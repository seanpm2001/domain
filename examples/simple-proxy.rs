//! Simple DNS proxy

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use clap::Parser;
use domain::base::iana::Rtype;
use domain::base::message_builder::PushError;
use domain::base::opt::{Opt, OptRecord};
use domain::base::{
    Message, MessageBuilder, ParsedDname, StaticCompressor, StreamTarget,
};
use domain::net::client::multi_stream;
use domain::net::client::tcp_factory::TcpConnFactory;
use domain::net::client::tls_factory::TlsConnFactory;
use domain::net::client::udp_tcp;
use domain::rdata::AllRecordData;
use domain::serve::buf::BufSource;
use domain::serve::dgram::DgramServer;
use domain::serve::service::{
    CallResult, Service, ServiceError, Transaction,
};
use futures::Stream;
use octseq::octets::OctetsFrom;
use octseq::Octets;
use rustls::ClientConfig;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::UdpSocket;

/// Arguments parser.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP address of remote server.
    #[arg(short = 's', long, value_name = "IP_ADDRESS")]
    server: Option<IpAddr>,

    /// Option for the destination TCP port.
    #[arg(short = 'p', long = "port", value_parser = clap::value_parser!(u16))]
    port: Option<u16>,

    /// Option for the local port.
    #[arg(long = "locport", value_parser = clap::value_parser!(u16))]
    locport: Option<u16>,

    /// Argument to enable TLS upstream connections.
    #[arg(long = "tls", requires = "tls-params-group")]
    do_tls: bool,

    /// Server name for TLS.
    #[arg(long = "servername", group = "tls-params-group")]
    servername: Option<String>,

    /// Flag to use UDP+TCP for upstream connections.
    #[arg(long = "udp")]
    do_udp: bool,
}

/// Convert a Message into a MessageBuilder.
fn to_builder<Octs1: Octets>(
    source: &Message<Octs1>,
) -> Result<MessageBuilder<StaticCompressor<StreamTarget<Vec<u8>>>>, PushError>
{
    let mut target = MessageBuilder::from_target(StaticCompressor::new(
        StreamTarget::new_vec(),
    ))
    .unwrap();

    let header = source.header();
    *target.header_mut() = header;

    let source = source.question();
    let mut target = target.additional().builder().question();
    for rr in source {
        let rr = rr.unwrap();
        target.push(rr)?;
    }
    let mut source = source.answer().unwrap();
    let mut target = target.answer();
    for rr in &mut source {
        let rr = rr.unwrap();
        let rr = rr
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .unwrap();
        target.push(rr)?;
    }

    let mut source = source.next_section().unwrap().unwrap();
    let mut target = target.authority();
    for rr in &mut source {
        let rr = rr.unwrap();
        let rr = rr
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .unwrap();
        target.push(rr)?;
    }

    let source = source.next_section().unwrap().unwrap();
    let mut target = target.additional();
    for rr in source {
        let rr = rr.unwrap();
        if rr.rtype() == Rtype::Opt {
            let rr = rr.into_record::<Opt<_>>().unwrap().unwrap();
            let opt_record = OptRecord::from_record(rr);
            target
                .opt(|newopt| {
                    newopt
                        .set_udp_payload_size(opt_record.udp_payload_size());
                    newopt.set_version(opt_record.version());
                    newopt.set_dnssec_ok(opt_record.dnssec_ok());

                    // Copy the transitive options that we support. Nothing
                    // at the moment.
                    /*
                                for option in opt_record.opt().iter::<AllOptData<_, _>>()
                                {
                                let option = option.unwrap();
                                if let AllOptData::TcpKeepalive(_) = option {
                                    panic!("handle keepalive");
                                } else {
                                    newopt.push(&option).unwrap();
                                }
                                }
                    */
                    Ok(())
                })
                .unwrap();
        } else {
            let rr = rr
                .into_record::<AllRecordData<_, ParsedDname<_>>>()
                .unwrap()
                .unwrap();
            target.push(rr)?;
        }
    }

    // It would be nice to use .builder() here. But that one deletes all
    // section. We have to resort to .as_builder() which gives a
    // reference and then .clone()
    Ok(target.as_builder().clone())
}

/// Convert a Message into a StreamTarget.
fn to_stream_target<Octs1: Octets, OctsOut>(
    source: &Message<Octs1>,
) -> Result<StreamTarget<Vec<u8>>, PushError> {
    let builder = to_builder(source).unwrap();
    Ok(builder.as_target().as_target().clone())
}

// We need a query trait to merge these into one service function.

/// Function that returns a Service trait.
///
/// This is a trick to capture the Future by an async block into a type.
fn stream_service<
    RequestOctets: AsRef<[u8]> + Octets + Send + Sync + 'static,
>(
    conn: multi_stream::Connection<Vec<u8>>,
) -> impl Service<RequestOctets>
where
    for<'a> &'a RequestOctets: AsRef<[u8]>,
{
    /// Basic query function for Service.
    fn query<RequestOctets: AsRef<[u8]> + Octets, ReplyOcts>(
        message: Message<RequestOctets>,
        conn: multi_stream::Connection<Vec<u8>>,
    ) -> Transaction<
        impl Future<Output = Result<CallResult<Vec<u8>>, ServiceError<()>>>,
        impl Stream<Item = Result<CallResult<Vec<u8>>, ServiceError<()>>>,
    >
    where
        for<'a> &'a RequestOctets: AsRef<[u8]>,
    {
        Transaction::<_, NoStream<Vec<u8>>>::Single(async move {
            // Extract the ID. We need to set it in the reply.
            let id = message.header().id();
            // We get a Message, but the client transport needs a
            // MessageBuilder. Convert.
            println!("request {:?}", message);
            let mut msg_builder = to_builder(&message).unwrap();
            println!("request {:?}", msg_builder);
            let mut query = conn.query(&mut msg_builder).await.unwrap();
            let reply = query.get_result().await.unwrap();
            println!("got reply {:?}", reply);

            // Set the ID
            let mut reply: Message<Vec<u8>> = OctetsFrom::octets_from(reply);
            reply.header_mut().set_id(id);

            // We get the reply as Message from the client transport but
            // we need to return a StreamTarget. Convert.
            let stream = to_stream_target::<_, Vec<u8>>(&reply).unwrap();
            Ok(CallResult::new(stream))
        })
    }

    move |message| Ok(query::<RequestOctets, Vec<u8>>(message, conn.clone()))
}

/// Function that returns a Service trait.
///
/// This is a trick to capture the Future by an async block into a type.
fn udptcp_service<
    RequestOctets: AsRef<[u8]> + Octets + Send + Sync + 'static,
>(
    conn: udp_tcp::Connection<Vec<u8>>,
) -> impl Service<RequestOctets>
where
    for<'a> &'a RequestOctets: AsRef<[u8]>,
{
    /// Basic query function for Service.
    fn query<RequestOctets: AsRef<[u8]> + Octets, ReplyOcts>(
        message: Message<RequestOctets>,
        conn: udp_tcp::Connection<Vec<u8>>,
    ) -> Transaction<
        impl Future<Output = Result<CallResult<Vec<u8>>, ServiceError<()>>>,
        impl Stream<Item = Result<CallResult<Vec<u8>>, ServiceError<()>>>,
    >
    where
        for<'a> &'a RequestOctets: AsRef<[u8]>,
    {
        Transaction::<_, NoStream<Vec<u8>>>::Single(async move {
            // Extract the ID. We need to set it in the reply.
            let id = message.header().id();
            // We get a Message, but the client transport needs a
            // MessageBuilder. Convert.
            println!("request {:?}", message);
            let mut msg_builder = to_builder(&message).unwrap();
            println!("request {:?}", msg_builder);
            let mut query = conn.query(&mut msg_builder).await.unwrap();
            let reply = query.get_result().await.unwrap();
            println!("got reply {:?}", reply);

            // Set the ID
            let mut reply: Message<Vec<u8>> = OctetsFrom::octets_from(reply);
            reply.header_mut().set_id(id);

            // We get the reply as Message from the client transport but
            // we need to return a StreamTarget. Convert.
            let stream = to_stream_target::<_, Vec<u8>>(&reply).unwrap();
            Ok(CallResult::new(stream))
        })
    }

    move |message| Ok(query::<RequestOctets, Vec<u8>>(message, conn.clone()))
}

/// Dummy stream
struct NoStream<Octs> {
    /// This is needed to handle the Octs type parameter.
    phantom: PhantomData<Octs>,
}

impl<Octs> Stream for NoStream<Octs> {
    type Item = Result<CallResult<Octs>, ServiceError<()>>;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        todo!()
    }
}

/// A buffer based on Vec.
struct VecBufSource;

impl BufSource for VecBufSource {
    type Output = Vec<u8>;

    fn create_buf(&self) -> Self::Output {
        vec![0; 1024]
    }

    fn create_sized(&self, size: usize) -> Self::Output {
        vec![0; size]
    }
}

/// A single optional call result based on a Vector.
struct VecSingle(Option<CallResult<Vec<u8>>>);

impl Future for VecSingle {
    type Output = Result<CallResult<Vec<u8>>, ServiceError<()>>;

    fn poll(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        Poll::Ready(Ok(self.0.take().unwrap()))
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let server = args.server.unwrap_or_else(|| "9.9.9.9".parse().unwrap());

    let locport = args.locport.unwrap_or_else(|| "8053".parse().unwrap());

    let udpsocket = UdpSocket::bind(SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        locport,
    ))
    .await
    .unwrap();

    if args.do_udp {
        let port = args.port.unwrap_or_else(|| "53".parse().unwrap());

        let conn =
            udp_tcp::Connection::new(SocketAddr::new(server, port)).unwrap();
        let conn_run = conn.clone();

        tokio::spawn(async move {
            conn_run.run().await;
            println!("run terminated");
        });

        let svc = udptcp_service(conn);

        let buf_source = Arc::new(VecBufSource);
        let srv = Arc::new(DgramServer::new(
            udpsocket,
            buf_source.clone(),
            Arc::new(svc),
        ));
        let udp_join_handle = tokio::spawn(srv.run());

        udp_join_handle.await.unwrap().unwrap();
    } else if args.do_tls {
        let port = args.port.unwrap_or_else(|| "853".parse().unwrap());

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
        );
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        let tls_factory = TlsConnFactory::new(
            client_config,
            &args.servername.unwrap(),
            SocketAddr::new(server, port),
        );

        let conn = multi_stream::Connection::new().unwrap();
        let conn_run = conn.clone();

        tokio::spawn(async move {
            conn_run.run(tls_factory).await;
            println!("run terminated");
        });

        let svc = stream_service(conn);

        let buf_source = Arc::new(VecBufSource);
        let srv = Arc::new(DgramServer::new(
            udpsocket,
            buf_source.clone(),
            Arc::new(svc),
        ));
        let udp_join_handle = tokio::spawn(srv.run());

        udp_join_handle.await.unwrap().unwrap();
    } else {
        let port = args.port.unwrap_or_else(|| "53".parse().unwrap());
        let tcp_factory = TcpConnFactory::new(SocketAddr::new(server, port));

        let conn = multi_stream::Connection::new().unwrap();
        let conn_run = conn.clone();

        tokio::spawn(async move {
            conn_run.run(tcp_factory).await;
            println!("run terminated");
        });

        let svc = stream_service(conn);

        let buf_source = Arc::new(VecBufSource);
        let srv = Arc::new(DgramServer::new(
            udpsocket,
            buf_source.clone(),
            Arc::new(svc),
        ));
        let udp_join_handle = tokio::spawn(srv.run());

        udp_join_handle.await.unwrap().unwrap();
    }
}
