//! A transport that multiplexes requests over multiple redundant transports.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use bytes::Bytes;

use futures::stream::FuturesUnordered;
use futures::StreamExt;

use octseq::{Octets, OctetsBuilder};

use rand::random;

use std::boxed::Box;
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;

use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{sleep_until, Duration, Instant};

use crate::base::iana::OptRcode;
use crate::base::wire::Composer;
use crate::base::Message;
use crate::net::client::error::Error;
use crate::net::client::query::{GetResult, QueryMessage3};

/*
Basic algorithm:
- keep track of expected response time for every upstream
- start with the upstream with the lowest expected response time
- set a timer to the expect response time.
- if the timer expires before reply arrives, send the query to the next lowest
  and set a timer
- when a reply arrives update the expected response time for the relevant
  upstream and for the ones that failed.

Based on a random number generator:
- pick a different upstream rather then the best but set the timer to the
  expected response time of the best.
*/

/// Capacity of the channel that transports [ChanReq].
const DEF_CHAN_CAP: usize = 8;

/// Time in milliseconds for the initial response time estimate.
const DEFAULT_RT_MS: u64 = 300;

/// The initial response time estimate for unused connections.
const DEFAULT_RT: Duration = Duration::from_millis(DEFAULT_RT_MS);

/// Maintain a moving average for the measured response time and the
/// square of that. The window is SMOOTH_N.
const SMOOTH_N: f64 = 8.;

/// Chance to probe a worse connection.
const PROBE_P: f64 = 0.05;

/// Avoid sending two requests at the same time.
///
/// When a worse connection is probed, give it a slight head start.
const PROBE_RT: Duration = Duration::from_millis(1);

//------------ Config ---------------------------------------------------------

/// User configuration variables.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Defer transport errors.
    pub defer_transport_error: bool,

    /// Defer replies that report Refused.
    pub defer_refused: bool,

    /// Defer replies that report ServFail.
    pub defer_servfail: bool,
}

//------------ Connection -----------------------------------------------------

/// This type represents a transport connection.
#[derive(Clone)]
pub struct Connection<Octs: Send> {
    /// Reference to the actual implementation of the connection.
    inner: Arc<InnerConnection<Octs>>,
}

impl<'a, Octs: Clone + Composer + Debug + Send + Sync + 'static>
    Connection<Octs>
{
    /// Create a new connection.
    pub fn new(config: Option<Config>) -> Result<Connection<Octs>, Error> {
        let config = match config {
            Some(config) => {
                check_config(&config)?;
                config
            }
            None => Default::default(),
        };
        let connection = InnerConnection::new(config)?;
        //test_send(connection);
        Ok(Self {
            inner: Arc::new(connection),
        })
    }

    /// Runner function for a connection.
    pub async fn run(&self) {
        self.inner.run().await
    }

    /// Add a transport connection.
    pub async fn add(
        &self,
        conn: Box<dyn QueryMessage3<Octs> + Send + Sync>,
    ) -> Result<(), Error> {
        self.inner.add(conn).await
    }

    /// Implementation of the query function.
    async fn query_impl(
        &self,
        query_msg: &Message<Octs>,
    ) -> Result<Box<dyn GetResult + Send>, Error> {
        let query = self.inner.query(query_msg.clone()).await?;
        Ok(Box::new(query))
    }
}

impl<
        Octs: Clone + Composer + Debug + OctetsBuilder + Send + Sync + 'static,
    > QueryMessage3<Octs> for Connection<Octs>
{
    fn query<'a>(
        &'a self,
        query_msg: &'a Message<Octs>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn GetResult + Send>, Error>>
                + Send
                + '_,
        >,
    > {
        return Box::pin(self.query_impl(query_msg));
    }
}

//------------ Query ----------------------------------------------------------

/// This type represents an active query request.
#[derive(Debug)]
pub struct Query<Octs: AsRef<[u8]> + Send> {
    /// User configuration.
    config: Config,

    /// The state of the query
    state: QueryState,

    /// The query message
    query_msg: Message<Octs>,

    /// List of connections identifiers and estimated response times.
    conn_rt: Vec<ConnRT>,

    /// Channel to send requests to the run function.
    sender: mpsc::Sender<ChanReq<Octs>>,

    /// List of futures for outstanding requests.
    fut_list:
        FuturesUnordered<Pin<Box<dyn Future<Output = FutListOutput> + Send>>>,

    /// Transport error that should be reported if nothing better shows
    /// up.
    deferred_transport_error: Option<Error>,

    /// Reply that should be returned to the user if nothing better shows
    /// up.
    deferred_reply: Option<Message<Bytes>>,

    /// The result from one of the connectons.
    result: Option<Result<Message<Bytes>, Error>>,

    /// Index of the connection that returned a result.
    res_index: usize,
}

/// The various states a query can be in.
#[derive(Debug)]
enum QueryState {
    /// The initial state
    Init,

    /// Start a request on a specific connection.
    Probe(usize),

    /// Report the response time for a specific index in the list.
    Report(usize),

    /// Wait for one of the requests to finish.
    Wait,
}

/// The commands that can be sent to the run function.
enum ChanReq<Octs: Send> {
    /// Add a connection
    Add(AddReq<Octs>),

    /// Get the list of estimated response times for all connections
    GetRT(RTReq),

    /// Start a query
    Query(QueryReq<Octs>),

    /// Report how long it took to get a response
    Report(TimeReport),

    /// Report that a connection failed to provide a timely response
    Failure(TimeReport),
}

impl<Octs: Debug + Send> Debug for ChanReq<Octs> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("ChanReq").finish()
    }
}

/// Request to add a new connection
struct AddReq<Octs> {
    /// New connection to add
    conn: Box<dyn QueryMessage3<Octs> + Send + Sync>,

    /// Channel to send the reply to
    tx: oneshot::Sender<AddReply>,
}

/// Reply to an Add request
type AddReply = Result<(), Error>;

/// Request to give the estimated response times for all connections
struct RTReq /*<Octs>*/ {
    /// Channel to send the reply to
    tx: oneshot::Sender<RTReply>,
}

/// Reply to a RT request
type RTReply = Result<Vec<ConnRT>, Error>;

/// Request to start a query
struct QueryReq<Octs: Send> {
    /// Identifier of connection
    id: u64,

    /// Request message
    query_msg: Message<Octs>,

    /// Channel to send the reply to
    tx: oneshot::Sender<QueryReply>,
}

impl<Octs: AsRef<[u8]> + Debug + Send> Debug for QueryReq<Octs> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("QueryReq")
            .field("id", &self.id)
            .field("query_msg", &self.query_msg)
            .finish()
    }
}

/// Reply to a query request.
type QueryReply = Result<Box<dyn GetResult + Send>, Error>;

/// Report the amount of time until success or failure.
#[derive(Debug)]
struct TimeReport {
    /// Identifier of the transport connection.
    id: u64,

    /// Time spend waiting for a reply.
    elapsed: Duration,
}

/// Connection statistics to compute the estimated response time.
struct ConnStats {
    /// Aproximation of the windowed average of response times.
    mean: f64,

    /// Aproximation of the windowed average of the square of response times.
    mean_sq: f64,
}

/// Data required to schedule requests and report timing results.
#[derive(Clone, Debug)]
struct ConnRT {
    /// Estimated response time.
    est_rt: Duration,

    /// Identifier of the connection.
    id: u64,

    /// Start of a request using this connection.
    start: Option<Instant>,
}

/// Result of the futures in fut_list.
type FutListOutput = (usize, Result<Message<Bytes>, Error>);

impl<Octs: AsRef<[u8]> + Clone + Debug + Send + Sync + 'static> Query<Octs> {
    /// Create a new query object.
    fn new(
        config: Config,
        query_msg: Message<Octs>,
        mut conn_rt: Vec<ConnRT>,
        sender: mpsc::Sender<ChanReq<Octs>>,
    ) -> Query<Octs> {
        let conn_rt_len = conn_rt.len();
        conn_rt.sort_unstable_by(conn_rt_cmp);

        // Do we want to probe a less performant upstream?
        if conn_rt_len > 1 && random::<f64>() < PROBE_P {
            let index: usize = 1 + random::<usize>() % (conn_rt_len - 1);
            conn_rt[index].est_rt = PROBE_RT;

            // Sort again
            conn_rt.sort_unstable_by(conn_rt_cmp);
        }

        Query {
            config,
            query_msg,
            //conns,
            conn_rt,
            sender,
            state: QueryState::Init,
            fut_list: FuturesUnordered::new(),
            deferred_transport_error: None,
            deferred_reply: None,
            result: None,
            res_index: 0,
        }
    }

    /// Implementation of get_result.
    async fn get_result_impl(&mut self) -> Result<Message<Bytes>, Error> {
        loop {
            match self.state {
                QueryState::Init => {
                    if self.conn_rt.is_empty() {
                        return Err(Error::NoTransportAvailable);
                    }
                    self.state = QueryState::Probe(0);
                    continue;
                }
                QueryState::Probe(ind) => {
                    self.conn_rt[ind].start = Some(Instant::now());
                    let fut = start_request(
                        ind,
                        self.conn_rt[ind].id,
                        self.sender.clone(),
                        self.query_msg.clone(),
                    );
                    self.fut_list.push(Box::pin(fut));
                    let timeout = Instant::now() + self.conn_rt[ind].est_rt;
                    loop {
                        tokio::select! {
                            res = self.fut_list.next() => {
                            let res = res.expect("res should not be empty");
                            match res.1 {
                                Err(ref err) => {
                                    if self.config.defer_transport_error {
                                    if self.deferred_transport_error.is_none() {
                                        self.deferred_transport_error = Some(err.clone());
                                    }
                                    if res.0 == ind {
                                        // The current upstream finished,
                                        // try the next one, if any.
                                        self.state =
                                        if ind+1 < self.conn_rt.len() {
                                            QueryState::Probe(ind+1)
                                        }
                                        else
                                        {
                                            QueryState::Wait
                                        };
                                        // Break out of receive loop
                                        break;
                                    }
                                    // Just continue receiving
                                    continue;
                                    }
                                    // Return error to the user.
                                }
                                Ok(ref msg) => {
                                if skip(msg, &self.config) {
                                    if self.deferred_reply.is_none() {
                                        self.deferred_reply = Some(msg.clone());
                                    }
                                    if res.0 == ind {
                                    // The current upstream finished,
                                    // try the next one, if any.
                                    self.state =
                                    if ind+1 < self.conn_rt.len() {
                                        QueryState::Probe(ind+1)
                                    }
                                    else
                                    {
                                        QueryState::Wait
                                    };
                                    // Break out of receive loop
                                    break;
                                    }
                                    // Just continue receiving
                                    continue;
                                }
                                // Now we have a reply that can be
                                // returned to the user.
                                }
                            }
                            self.result = Some(res.1);
                            self.res_index= res.0;

                            self.state = QueryState::Report(0);
                            // Break out of receive loop
                            break;
                            }
                            _ = sleep_until(timeout) => {
                            // Move to the next Probe state if there
                            // are more upstreams to try, otherwise
                            // move to the Wait state.
                            self.state =
                            if ind+1 < self.conn_rt.len() {
                                QueryState::Probe(ind+1)
                            }
                            else
                            {
                                QueryState::Wait
                            };
                            // Break out of receive loop
                            break;
                            }
                        }
                    }
                    // Continue with state machine loop
                    continue;
                }
                QueryState::Report(ind) => {
                    if ind >= self.conn_rt.len()
                        || self.conn_rt[ind].start.is_none()
                    {
                        // Nothing more to report. Return result.
                        let res = self
                            .result
                            .take()
                            .expect("result should not be empty");
                        return res;
                    }

                    let start = self.conn_rt[ind]
                        .start
                        .expect("start time should not be empty");
                    let elapsed = start.elapsed();
                    let time_report = TimeReport {
                        id: self.conn_rt[ind].id,
                        elapsed,
                    };
                    let report = if ind == self.res_index {
                        // Succesfull entry
                        ChanReq::Report(time_report)
                    } else {
                        // Failed entry
                        ChanReq::Failure(time_report)
                    };

                    // Send could fail but we don't care.
                    let _ = self.sender.send(report).await;

                    self.state = QueryState::Report(ind + 1);
                    continue;
                }
                QueryState::Wait => {
                    loop {
                        if self.fut_list.is_empty() {
                            // We have nothing left. There should be a reply or
                            // an error. Prefer a reply over an error.
                            if self.deferred_reply.is_some() {
                                let msg = self
                                    .deferred_reply
                                    .take()
                                    .expect("just checked for Some");
                                return Ok(msg);
                            }
                            if self.deferred_transport_error.is_some() {
                                let err = self
                                    .deferred_transport_error
                                    .take()
                                    .expect("just checked for Some");
                                return Err(err);
                            }
                            panic!("either deferred_reply or deferred_error should be present");
                        }
                        let res = self.fut_list.next().await;
                        let res = res.expect("res should not be empty");
                        match res.1 {
                            Err(ref err) => {
                                if self.config.defer_transport_error {
                                    if self.deferred_transport_error.is_none()
                                    {
                                        self.deferred_transport_error =
                                            Some(err.clone());
                                    }
                                    // Just continue with the next future, or
                                    // finish if fut_list is empty.
                                    continue;
                                }
                                // Return error to the user.
                            }
                            Ok(ref msg) => {
                                if skip(msg, &self.config) {
                                    if self.deferred_reply.is_none() {
                                        self.deferred_reply =
                                            Some(msg.clone());
                                    }
                                    // Just continue with the next future, or
                                    // finish if fut_list is empty.
                                    continue;
                                }
                                // Return reply to user.
                            }
                        }
                        self.result = Some(res.1);
                        self.res_index = res.0;
                        self.state = QueryState::Report(0);
                        // Break out of loop to continue with the state machine
                        break;
                    }
                    continue;
                }
            }
        }
    }
}

impl<
        Octs: AsMut<[u8]>
            + AsRef<[u8]>
            + Clone
            + Composer
            + Debug
            + OctetsBuilder
            + Send
            + Sync
            + 'static,
    > GetResult for Query<Octs>
{
    fn get_result(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_result_impl())
    }
}

//------------ InnerConnection ------------------------------------------------

/// Type that actually implements the connection.
struct InnerConnection<Octs: Send> {
    /// User configuation.
    config: Config,

    /// Receive side of the channel used by the runner.
    receiver: Mutex<Option<mpsc::Receiver<ChanReq<Octs>>>>,

    /// To send a request to the runner.
    sender: mpsc::Sender<ChanReq<Octs>>,
}

impl<'a, Octs: AsRef<[u8]> + Clone + Debug + Send + Sync + 'static>
    InnerConnection<Octs>
{
    /// Implementation of the new method.
    fn new(config: Config) -> Result<InnerConnection<Octs>, Error> {
        let (tx, rx) = mpsc::channel(DEF_CHAN_CAP);
        Ok(Self {
            config,
            receiver: Mutex::new(Some(rx)),
            sender: tx,
        })
    }

    /// Implementation of the run method.
    async fn run(&self) {
        let mut next_id: u64 = 10;
        let mut conn_stats: Vec<ConnStats> = Vec::new();
        let mut conn_rt: Vec<ConnRT> = Vec::new();
        let mut conns: Vec<Box<dyn QueryMessage3<Octs> + Send + Sync>> =
            Vec::new();

        let mut receiver = self.receiver.lock().await;
        let opt_receiver = receiver.take();
        drop(receiver);
        let mut receiver =
            opt_receiver.expect("receiver should not be empty");
        loop {
            let req =
                receiver.recv().await.expect("receiver should not fail");
            match req {
                ChanReq::Add(add_req) => {
                    let id = next_id;
                    next_id += 1;
                    conn_stats.push(ConnStats {
                        mean: (DEFAULT_RT_MS as f64) / 1000.,
                        mean_sq: 0.,
                    });
                    conn_rt.push(ConnRT {
                        id,
                        est_rt: DEFAULT_RT,
                        start: None,
                    });
                    conns.push(add_req.conn);

                    // Don't care if send fails
                    let _ = add_req.tx.send(Ok(()));
                }
                ChanReq::GetRT(rt_req) => {
                    // Don't care if send fails
                    let _ = rt_req.tx.send(Ok(conn_rt.clone()));
                }
                ChanReq::Query(query_req) => {
                    let opt_ind =
                        conn_rt.iter().position(|e| e.id == query_req.id);
                    match opt_ind {
                        Some(ind) => {
                            let query =
                                conns[ind].query(&query_req.query_msg).await;
                            // Don't care if send fails
                            let _ = query_req.tx.send(query);
                        }
                        None => {
                            // Don't care if send fails
                            let _ = query_req
                                .tx
                                .send(Err(Error::RedundantTransportNotFound));
                        }
                    }
                }
                ChanReq::Report(time_report) => {
                    let opt_ind =
                        conn_rt.iter().position(|e| e.id == time_report.id);
                    if let Some(ind) = opt_ind {
                        let elapsed = time_report.elapsed.as_secs_f64();
                        conn_stats[ind].mean +=
                            (elapsed - conn_stats[ind].mean) / SMOOTH_N;
                        let elapsed_sq = elapsed * elapsed;
                        conn_stats[ind].mean_sq +=
                            (elapsed_sq - conn_stats[ind].mean_sq) / SMOOTH_N;
                        let mean = conn_stats[ind].mean;
                        let var = conn_stats[ind].mean_sq - mean * mean;
                        let std_dev =
                            if var < 0. { 0. } else { f64::sqrt(var) };
                        let est_rt = mean + 3. * std_dev;
                        conn_rt[ind].est_rt = Duration::from_secs_f64(est_rt);
                    }
                }
                ChanReq::Failure(time_report) => {
                    let opt_ind =
                        conn_rt.iter().position(|e| e.id == time_report.id);
                    if let Some(ind) = opt_ind {
                        let elapsed = time_report.elapsed.as_secs_f64();
                        if elapsed < conn_stats[ind].mean {
                            // Do not update the mean if a
                            // failure took less time than the
                            // current mean.
                            continue;
                        }
                        conn_stats[ind].mean +=
                            (elapsed - conn_stats[ind].mean) / SMOOTH_N;
                        let elapsed_sq = elapsed * elapsed;
                        conn_stats[ind].mean_sq +=
                            (elapsed_sq - conn_stats[ind].mean_sq) / SMOOTH_N;
                        let mean = conn_stats[ind].mean;
                        let var = conn_stats[ind].mean_sq - mean * mean;
                        let std_dev =
                            if var < 0. { 0. } else { f64::sqrt(var) };
                        let est_rt = mean + 3. * std_dev;
                        conn_rt[ind].est_rt = Duration::from_secs_f64(est_rt);
                    }
                }
            }
        }
    }

    /// Implementation of the add method.
    async fn add(
        &self,
        conn: Box<dyn QueryMessage3<Octs> + Send + Sync>,
    ) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(ChanReq::Add(AddReq { conn, tx }))
            .await
            .expect("send should not fail");
        rx.await.expect("receive should not fail")
    }

    /// Implementation of the query method.
    async fn query(
        &'a self,
        query_msg: Message<Octs>,
    ) -> Result<Query<Octs>, Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(ChanReq::GetRT(RTReq { tx }))
            .await
            .expect("send should not fail");
        let conn_rt = rx.await.expect("receive should not fail")?;
        Ok(Query::new(
            self.config.clone(),
            query_msg,
            conn_rt,
            self.sender.clone(),
        ))
    }
}

//------------ Utility --------------------------------------------------------

/// Async function to send a request and wait for the reply.
///
/// This gives a single future that we can put in a list.
async fn start_request<Octs: Clone + Debug + Send>(
    index: usize,
    id: u64,
    sender: mpsc::Sender<ChanReq<Octs>>,
    query_msg: Message<Octs>,
) -> (usize, Result<Message<Bytes>, Error>) {
    let (tx, rx) = oneshot::channel();
    sender
        .send(ChanReq::Query(QueryReq {
            id,
            query_msg: query_msg.clone(),
            tx,
        }))
        .await
        .expect("send is expected to work");
    let mut query = match rx.await.expect("receive is expected to work") {
        Err(err) => return (index, Err(err)),
        Ok(query) => query,
    };
    let reply = query.get_result().await;

    (index, reply)
}

/// Compare ConnRT elements based on estimated response time.
fn conn_rt_cmp(e1: &ConnRT, e2: &ConnRT) -> Ordering {
    e1.est_rt.cmp(&e2.est_rt)
}

/// Return if this reply should be skipped or not.
fn skip<Octs: Octets>(msg: &Message<Octs>, config: &Config) -> bool {
    // Check if we actually need to check.
    if !config.defer_refused && !config.defer_servfail {
        return false;
    }

    let opt_rcode = get_opt_rcode(msg);
    // OptRcode needs PartialEq
    if let OptRcode::Refused = opt_rcode {
        if config.defer_refused {
            return true;
        }
    }
    if let OptRcode::ServFail = opt_rcode {
        if config.defer_servfail {
            return true;
        }
    }

    false
}

/// Get the extended rcode of a message.
fn get_opt_rcode<Octs: Octets>(msg: &Message<Octs>) -> OptRcode {
    let opt = msg.opt();
    match opt {
        Some(opt) => opt.rcode(msg.header()),
        None => {
            // Convert Rcode to OptRcode, this should be part of
            // OptRcode
            OptRcode::from_int(msg.header().rcode().to_int() as u16)
        }
    }
}

/// Check if config is valid.
fn check_config(_config: &Config) -> Result<(), Error> {
    // Nothing to check at the moment.
    Ok(())
}
