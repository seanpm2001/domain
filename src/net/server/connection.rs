use crate::base::{Message, StreamTarget};
use crate::net::server::buf::BufSource;
use crate::net::server::message::MessageProcessor;
use crate::net::server::message::{ContextAwareMessage, MsgProvider};
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::middleware::chain::MiddlewareChain;
use crate::net::server::service::{
    CallResult, Service, ServiceCommand, ServiceError,
};

use chrono::{DateTime, Utc};
use core::ops::ControlFlow;
use core::sync::atomic::Ordering;
use core::time::Duration;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf,
};
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error};

//------------ Connection -----------------------------------------------

pub struct Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    buf_source: Buf,
    metrics: Arc<ServerMetrics>,
    service: Svc,
    middleware_chain: Option<MiddlewareChain<Buf::Output, Svc::Target>>,
    stream: Option<Stream>,
    addr: SocketAddr,
}

/// Creation
///
impl<Stream, Buf, Svc> Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    #[must_use]
    pub fn new(
        service: Svc,
        middleware_chain: Option<MiddlewareChain<Buf::Output, Svc::Target>>,
        buf_source: Buf,
        metrics: Arc<ServerMetrics>,
        stream: Stream,
        addr: SocketAddr,
    ) -> Self {
        Self {
            buf_source,
            service,
            middleware_chain,
            metrics,
            stream: Some(stream),
            addr,
        }
    }
}

/// Control
///
impl<Stream, Buf, Svc> Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    /// Start reading requests and writing responses to the stream.
    ///
    /// # Shutdown behaviour
    ///
    /// When the parent server is shutdown (explicitly or via Drop) the child
    /// connections will also see the [`ServiceCommand::Shutdown`] signal and
    /// shutdown and flush any pending writes to the output stream.
    ///
    /// Any requests received after the shutdown signal or requests still
    /// in-flight will be abandoned.
    ///
    /// TODO: What does "abandoned" mean in practice here?
    pub async fn run(mut self, command_rx: watch::Receiver<ServiceCommand>)
    where
        Svc::Single: Send,
    {
        self.metrics
            .num_connections
            .as_ref()
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);

        // TODO: Why use an Option and then Option::take()?
        let stream = self.stream.take().unwrap();
        self.run_until_error(command_rx, stream).await;

        self.metrics
            .num_connections
            .as_ref()
            .unwrap()
            .fetch_sub(1, Ordering::Relaxed);
    }
}

//--- Internal details

impl<Stream, Buf, Svc> Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    async fn run_until_error(
        &self,
        mut command_rx: watch::Receiver<ServiceCommand>,
        stream: Stream,
    ) where
        Svc::Single: Send,
    {
        let (mut stream_rx, stream_tx) = tokio::io::split(stream);
        let (result_q_tx, mut result_q_rx) =
            mpsc::channel::<CallResult<Svc::Target>>(10); // TODO: Take from configuration
        let idle_timeout = chrono::Duration::seconds(3); // TODO: Take from configuration

        let mut state =
            StreamState::new(stream_tx, result_q_tx, idle_timeout);

        let mut msg_size_buf = self
            .buf_source
            .create_sized(Message::<Buf::Output>::MIN_HDR_BYTES);

        loop {
            if let Err(err) = self
                .transceive_one_request(
                    &mut command_rx,
                    &mut state,
                    &mut stream_rx,
                    &mut result_q_rx,
                    &mut msg_size_buf,
                )
                .await
            {
                match err {
                    ConnectionEvent::DisconnectWithoutFlush => {
                        break;
                    }
                    ConnectionEvent::DisconnectWithFlush => {
                        self.flush_write_queue(&mut state, &mut result_q_rx)
                            .await;
                        break;
                    }
                    ConnectionEvent::ReadSucceeded => {
                        // A success is not an error, this shouldn't happen.
                        unreachable!()
                    }
                    ConnectionEvent::ServiceError(err) => {
                        error!("Service error: {}", err);
                    }
                }
            }
        }
    }

    async fn transceive_one_request(
        &self,
        command_rx: &mut watch::Receiver<ServiceCommand>,
        state: &mut StreamState<Stream, Buf, Svc>,
        stream_rx: &mut ReadHalf<Stream>,
        result_q_rx: &mut mpsc::Receiver<CallResult<Svc::Target>>,
        msg_size_buf: &mut <Buf as BufSource>::Output,
    ) -> Result<(), ConnectionEvent<Svc::Error>>
    where
        Svc::Single: Send,
    {
        self.transceive_until(
            command_rx,
            state,
            stream_rx,
            result_q_rx,
            msg_size_buf,
        )
        .await?;

        let msg_len = Message::determine_msg_len(msg_size_buf);
        let mut msg_buf = self.buf_source.create_sized(msg_len);

        self.transceive_until(
            command_rx,
            state,
            stream_rx,
            result_q_rx,
            &mut msg_buf,
        )
        .await?;

        state.full_msg_received();

        self.process_request(
            msg_buf,
            self.addr,
            state.result_q_tx.clone(),
            self.middleware_chain.clone(),
            &self.service,
            self.metrics.clone(),
        )
        .map_err(ConnectionEvent::ServiceError)?;

        Ok(())
    }

    async fn transceive_until(
        &self,
        command_rx: &mut watch::Receiver<ServiceCommand>,
        state: &mut StreamState<Stream, Buf, Svc>,
        stream_rx: &mut ReadHalf<Stream>,
        result_q_rx: &mut mpsc::Receiver<CallResult<Svc::Target>>,
        buf: &mut <Buf as BufSource>::Output,
    ) -> Result<ConnectionEvent<Svc::Error>, ConnectionEvent<Svc::Error>>
    {
        // Note: The MPSC receiver used to receive finished service call
        // results can be read from safely even if the future is cancelled.
        // Thus we don't need to keep the future, we can just call recv()
        // again when we need to.
        //
        // The same is not true of reading an exact number of bytes from the
        // incoming data stream, the future cannot be cancelled safely as any
        // bytes already read will be written to the buffer but we will lose
        // the knowledge of how many bytes have been written to the buffer. So
        // we must keep using the same future until it finally resolves when
        // the read is complete or results in an error.
        'read: loop {
            let stream_read_fut = stream_rx.read_exact(buf.as_mut());
            let timeout_fut = tokio::time::sleep(state.timeout_as_std());

            tokio::pin!(stream_read_fut);
            tokio::pin!(timeout_fut);

            loop {
                tokio::select! {
                    biased;

                    res = command_rx.changed() => {
                        self.process_service_command(res, state, command_rx)?;
                    }

                    result_q_res = result_q_rx.recv() => {
                        // If we failed to read the results of requests
                        // processed by the service because the queue holding
                        // those results is empty and can no longer be read
                        // from, then there is no point continuing to read
                        // from the input stream because we will not be able
                        // to access the result of processing the request.
                        // TODO: Describe when this can occur.
                        let call_result = result_q_res
                            .ok_or(ConnectionEvent::DisconnectWithFlush)?;

                        self.process_queued_result(state, call_result).await;
                    }

                    stream_read_res = &mut stream_read_fut => {
                        match stream_read_res {
                            // The stream read succeeded. Return to the caller
                            // so that it can process the bytes written to the
                            // buffer.
                            Ok(_size) => {
                                return Ok(ConnectionEvent::ReadSucceeded);
                            }

                            Err(err) => {
                                match self.process_io_error(err) {
                                    ControlFlow::Continue(_) => continue 'read,
                                    ControlFlow::Break(err) => return Err(err),
                                }
                            }
                        }
                    }

                    _ = &mut timeout_fut => {
                        return Err(ConnectionEvent::DisconnectWithFlush);
                    }
                }
            }
        }
    }

    fn process_service_command(
        &self,
        res: Result<(), watch::error::RecvError>,
        state: &mut StreamState<Stream, Buf, Svc>,
        command_rx: &mut watch::Receiver<ServiceCommand>,
    ) -> Result<(), ConnectionEvent<Svc::Error>> {
        // If the parent server no longer exists but was not cleanly shutdown
        // then the command channel will be closed and attempting to check for
        // a new command will fail. Advise the caller to break the connection
        // and cleanup if such a problem occurs.
        res.map_err(|_err| ConnectionEvent::DisconnectWithFlush)?;

        // Get the changed command.
        let command = *command_rx.borrow_and_update();

        // And process it.
        match command {
            ServiceCommand::Reconfigure { idle_timeout } => {
                // Support RFC 7828 "The edns-tcp-keepalive EDNS0 Option".
                // This cannot be done by the caller as it requires knowing
                // (a) when the last message was received and (b) when all
                // pending messages have been sent, neither of which is known
                // to the caller. However we also don't want to parse and
                // understand DNS messages in this layer, it is left to the
                // caller to process received messages and construct
                // appropriate responses. If the caller detects an EDNS0
                // edns-tcp-keepalive option it can use this reconfigure
                // mechanism to signal to us that we should adjust the point
                // at which we will consider the connectin to be idle and thus
                // potentially worthy of timing out.
                debug!("Server connection timeout reconfigured to {idle_timeout:?}");
                if let Ok(timeout) = chrono::Duration::from_std(idle_timeout)
                {
                    state.idle_timeout = timeout;
                }

                // TODO: Support dynamic replacement of the middleware chain?
                // E.g. via ArcSwapOption<MiddlewareChain> instead of Option?
            }

            ServiceCommand::Shutdown => {
                // The parent server has been shutdown. Close this connection
                // but ensure that we write any pending responses to the
                // stream first.
                //
                // TODO: Should we also wait for any in-flight requests to
                // complete before shutting down? And if so how should we
                // respond to any requests received in the meantime? Should we
                // even stop reading from the stream?
                return Err(ConnectionEvent::DisconnectWithFlush);
            }

            ServiceCommand::Init => {
                // The initial "Init" value in the watch channel is never
                // actually seen because changed() is required to return true
                // before we call borrow_and_update() but the initial value in
                // the channel, Init, is not considered a "change". So the
                // only way to end up here would be if we somehow wrongly
                // placed another ServiceCommand::Init value into the watch
                // channel after the initial one.
                unreachable!()
            }

            ServiceCommand::CloseConnection => {
                // TODO: Should we flush in this case or not?
                return Err(ConnectionEvent::DisconnectWithFlush);
            }
        }

        Ok(())
    }

    #[must_use]
    fn process_io_error(
        &self,
        err: io::Error,
    ) -> ControlFlow<ConnectionEvent<Svc::Error>> {
        match err.kind() {
            io::ErrorKind::UnexpectedEof => {
                // The client disconnected. Per RFC 7766 6.2.4 pending
                // responses MUST NOT be sent to the client.
                ControlFlow::Break(ConnectionEvent::DisconnectWithoutFlush)
            }
            io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
                // These errors might be recoverable, try again.
                ControlFlow::Continue(())
            }
            _ => {
                // Everything else is either unrecoverable or unknown to us at
                // the time of writing and so we can't guess how to handle it,
                // so abort.
                ControlFlow::Break(ConnectionEvent::DisconnectWithoutFlush)
            }
        }
    }

    async fn flush_write_queue(
        &self,
        state: &mut StreamState<Stream, Buf, Svc>,
        result_q_rx: &mut mpsc::Receiver<CallResult<Svc::Target>>,
    ) {
        // Stop accepting new response messages (should we check for in-flight
        // messages that haven't generated a response yet but should be
        // allowed to do so?) so that we can flush the write queue and exit
        // this connection handler.
        result_q_rx.close();
        while let Some(call_result) = result_q_rx.recv().await {
            self.process_queued_result(state, call_result).await;
        }
    }

    async fn process_queued_result(
        &self,
        state: &mut StreamState<Stream, Buf, Svc>,
        call_result: CallResult<Svc::Target>,
    ) {
        let (response, command) = call_result.into_inner();

        if let Some(response) = response {
            self.write_result_to_stream(state, response.finish()).await;
        }

        if let Some(command) = command {
            self.act_on_queued_command(command, state).await;
        }
    }

    async fn write_result_to_stream(
        &self,
        state: &mut StreamState<Stream, Buf, Svc>,
        msg: StreamTarget<Svc::Target>,
    ) {
        // TODO: spawn this as a task and serialize access to write with a lock?
        if let Err(err) =
            state.stream_tx.write_all(msg.as_stream_slice()).await
        {
            error!("Write error: {err}");
            todo!()
        }
        if state.result_q_tx.capacity() == state.result_q_tx.max_capacity() {
            state.response_queue_emptied();
        }
        self.metrics
            .num_pending_writes
            .fetch_sub(1, Ordering::Relaxed);
    }

    async fn act_on_queued_command(
        &self,
        cmd: ServiceCommand,
        state: &mut StreamState<Stream, Buf, Svc>,
    ) {
        match cmd {
            ServiceCommand::CloseConnection { .. } => todo!(),
            ServiceCommand::Init => todo!(),
            ServiceCommand::Reconfigure { idle_timeout } => {
                debug!("Reconfigured connection timeout to {idle_timeout:?}");
                state.idle_timeout =
                    chrono::Duration::from_std(idle_timeout).unwrap();
                // TODO: Check this unwrap()
            }
            ServiceCommand::Shutdown => {
                state.stream_tx.shutdown().await.unwrap()
            }
        }
    }
}

//--- MessageProcessor

impl<Stream, Buf, Svc> MessageProcessor<Buf, Svc>
    for Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    type State = Sender<CallResult<Svc::Target>>;

    fn add_context_to_request(
        &self,
        request: Message<Buf::Output>,
        addr: SocketAddr,
    ) -> ContextAwareMessage<Message<Buf::Output>> {
        ContextAwareMessage::new(request, true, addr)
    }

    fn handle_final_call_result(
        call_result: CallResult<Svc::Target>,
        _addr: SocketAddr,
        tx: Self::State,
        metrics: Arc<ServerMetrics>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(err) = tx.send(call_result).await {
                // TODO: How should we properly communicate this to the operator?
                error!("StreamServer: Error while queuing response: {err}");
            }

            metrics
                .num_pending_writes
                .store(tx.max_capacity() - tx.capacity(), Ordering::Relaxed);
        })
    }
}

//------------ ConnectionEvent -----------------------------------------------

enum ConnectionEvent<T> {
    /// RFC 7766 6.2.4 "Under normal operation DNS clients typically initiate
    /// connection closing on idle connections; however, DNS servers can close
    /// the connection if the idle timeout set by local policy is exceeded.
    /// Also, connections can be closed by either end under unusual conditions
    /// such as defending against an attack or system failure reboot."
    ///
    /// And: RFC 7766 3 "A DNS server considers an established DNS-over-TCP
    /// session to be idle when it has sent responses to all the queries it
    /// has received on that connection."
    DisconnectWithoutFlush,

    /// RFC 7766 6.2.3 "If a DNS server finds that a DNS client has closed a
    /// TCP session (or if the session has been otherwise interrupted) before
    /// all pending responses have been sent, then the server MUST NOT attempt
    /// to send those responses.  Of course, the DNS server MAY cache those
    /// responses."
    DisconnectWithFlush,

    ReadSucceeded,

    ServiceError(ServiceError<T>),
}

//------------ StreamState ---------------------------------------------------

pub struct StreamState<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    stream_tx: WriteHalf<Stream>,

    result_q_tx: mpsc::Sender<CallResult<Svc::Target>>,

    // RFC 1035 7.1: "Since a resolver must be able to multiplex multiple
    // requests if it is to perform its function efficiently, each pending
    // request is usually represented in some block of state information.
    // This state block will typically contain:
    //
    //   - A timestamp indicating the time the request began.
    //     The timestamp is used to decide whether RRs in the database
    //     can be used or are out of date.  This timestamp uses the
    //     absolute time format previously discussed for RR storage in
    //     zones and caches.  Note that when an RRs TTL indicates a
    //     relative time, the RR must be timely, since it is part of a
    //     zone.  When the RR has an absolute time, it is part of a
    //     cache, and the TTL of the RR is compared against the timestamp
    //     for the start of the request.

    //     Note that using the timestamp is superior to using a current
    //     time, since it allows RRs with TTLs of zero to be entered in
    //     the cache in the usual manner, but still used by the current
    //     request, even after intervals of many seconds due to system
    //     load, query retransmission timeouts, etc."
    //
    //
    idle_timer_reset_at: DateTime<Utc>,

    idle_timeout: chrono::Duration,
}

impl<Stream, Buf, Svc> StreamState<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    #[must_use]
    fn new(
        stream_tx: WriteHalf<Stream>,
        result_q_tx: mpsc::Sender<CallResult<Svc::Target>>,
        idle_timeout: chrono::Duration,
    ) -> Self {
        Self {
            stream_tx,
            result_q_tx,
            idle_timer_reset_at: Utc::now(),
            idle_timeout,
        }
    }

    /// How long from now should this connection be timed out?
    ///
    /// When we (will) have been sat idle for longer than the configured idle
    /// timeout for this connection.
    #[must_use]
    pub fn timeout_at(&self) -> chrono::Duration {
        self.idle_timeout
            .checked_sub(&self.idle_time())
            .unwrap_or(chrono::Duration::zero())
    }

    #[must_use]
    pub fn timeout_as_std(&self) -> Duration {
        self.timeout_at().to_std().unwrap_or_default()
    }

    /// How long has this connection been sat idle?
    #[must_use]
    pub fn idle_time(&self) -> chrono::Duration {
        Utc::now().signed_duration_since(self.idle_timer_reset_at)
    }

    fn reset_idle_timer(&mut self) {
        self.idle_timer_reset_at = Utc::now()
    }

    fn full_msg_received(&mut self) {
        // RFC 7766 6.2.3: "DNS messages delivered over TCP might arrive in
        // multiple segments.  A DNS server that resets its idle timeout after
        // receiving a single segment might be vulnerable to a "slow-read
        // attack". For this reason, servers SHOULD reset the idle timeout on
        // the receipt of a full DNS message, rather than on receipt of any
        // part of a DNS message."
        self.reset_idle_timer()
    }

    fn response_queue_emptied(&mut self) {
        // RFC 7766 3: "A DNS server considers an established DNS-over-TCP
        // session to be idle when it has sent responses to all the queries it
        // has received on that connection."
        self.reset_idle_timer()
    }
}