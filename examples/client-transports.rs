/// Using the `domain::net::client` module for sending a query.
use domain::base::Dname;
use domain::base::MessageBuilder;
use domain::base::Rtype::Aaaa;
use domain::net::client::dgram;
use domain::net::client::dgram_stream;
use domain::net::client::multi_stream;
use domain::net::client::octet_stream;
use domain::net::client::protocol::{TcpConnect, TlsConnect, UdpConnect};
use domain::net::client::redundant;
use domain::net::client::request::{RequestMessage, SendRequest};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

#[tokio::main]
async fn main() {
    // Create DNS request message.
    //
    // Transports currently take a `RequestMessage` as their input to be able
    // to add options along the way.
    //
    // In the future, it will also be possible to pass in a message or message
    // builder directly as input but for now it needs to be converted into a
    // `RequestMessage` manually.
    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_rd(true);
    let mut msg = msg.question();
    msg.push((Dname::vec_from_str("example.com").unwrap(), Aaaa))
        .unwrap();
    let req = RequestMessage::new(msg);

    // Destination for UDP and TCP
    let server_addr = SocketAddr::new(IpAddr::from_str("::1").unwrap(), 53);

    let multi_stream_config = multi_stream::Config {
        octet_stream: Some(octet_stream::Config {
            response_timeout: Duration::from_millis(100),
        }),
    };

    // Create a new UDP+TCP transport connection. Pass the destination address
    // and port as parameter.
    let dgram_config = dgram::Config {
        max_parallel: 1,
        read_timeout: Duration::from_millis(1000),
        max_retries: 1,
        udp_payload_size: Some(1400),
    };
    let dgram_stream_config = dgram_stream::Config {
        dgram: Some(dgram_config.clone()),
        multi_stream: Some(multi_stream_config.clone()),
    };
    let udp_connect = UdpConnect::new(server_addr);
    let tcp_connect = TcpConnect::new(server_addr);
    let udptcp_conn =
        dgram_stream::Connection::new(Some(dgram_stream_config), udp_connect)
            .unwrap();

    // Start the run function in a separate task. The run function will
    // terminate when all references to the connection have been dropped.
    // Make sure that the task does not accidentally get a reference to the
    // connection.
    let run_fut = udptcp_conn.run(tcp_connect);
    tokio::spawn(async move {
        let res = run_fut.await;
        println!("UDP+TCP run exited with {:?}", res);
    });

    // Send a query message.
    let mut request = udptcp_conn.send_request(&req).await.unwrap();

    // Get the reply
    println!("Wating for UDP+TCP reply");
    let reply = request.get_response().await;
    println!("UDP+TCP reply: {:?}", reply);

    // The query may have a reference to the connection. Drop the query
    // when it is no longer needed.
    drop(request);

    // Create a new TCP connections object. Pass the destination address and
    // port as parameter.
    let tcp_connect = TcpConnect::new(server_addr);

    // A muli_stream transport connection sets up new TCP connections when
    // needed.
    let tcp_conn =
        multi_stream::Connection::new(Some(multi_stream_config.clone()))
            .unwrap();

    // Get a future for the run function. The run function receives
    // the connection stream as a parameter.
    let run_fut = tcp_conn.run(tcp_connect);
    tokio::spawn(async move {
        let res = run_fut.await;
        println!("multi TCP run exited with {:?}", res);
    });

    // Send a query message.
    let mut request = tcp_conn.send_request(&req).await.unwrap();

    // Get the reply. A multi_stream connection does not have any timeout.
    // Wrap get_result in a timeout.
    println!("Wating for multi TCP reply");
    let reply =
        timeout(Duration::from_millis(500), request.get_response()).await;
    println!("multi TCP reply: {:?}", reply);

    drop(request);

    // Some TLS boiler plate for the root certificates.
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(
        |ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        },
    ));

    // TLS config
    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Currently the only support TLS connections are the ones that have a
    // valid certificate. Use a well known public resolver.
    let google_server_addr =
        SocketAddr::new(IpAddr::from_str("8.8.8.8").unwrap(), 853);

    // Create a new TLS connections object. We pass the TLS config, the name of
    // the remote server and the destination address and port.
    let tls_connect = TlsConnect::new(
        client_config,
        "dns.google".try_into().unwrap(),
        google_server_addr,
    );

    // Again create a multi_stream transport connection.
    let tls_conn =
        multi_stream::Connection::new(Some(multi_stream_config)).unwrap();

    // Start the run function.
    let run_fut = tls_conn.run(tls_connect);
    tokio::spawn(async move {
        let res = run_fut.await;
        println!("TLS run exited with {:?}", res);
    });

    let mut request = tls_conn.send_request(&req).await.unwrap();
    println!("Wating for TLS reply");
    let reply =
        timeout(Duration::from_millis(500), request.get_response()).await;
    println!("TLS reply: {:?}", reply);

    drop(request);

    // Create a transport connection for redundant connections.
    let redun = redundant::Connection::new(None).unwrap();

    // Start the run function on a separate task.
    let run_fut = redun.run();
    tokio::spawn(async move {
        run_fut.await;
        println!("redundant run terminated");
    });

    // Add the previously created transports.
    redun.add(Box::new(udptcp_conn)).await.unwrap();
    redun.add(Box::new(tcp_conn)).await.unwrap();
    redun.add(Box::new(tls_conn)).await.unwrap();

    // Start a few queries.
    for i in 1..10 {
        let mut request = redun.send_request(&req).await.unwrap();
        let reply = request.get_response().await;
        if i == 2 {
            println!("redundant connection reply: {:?}", reply);
        }
    }

    drop(redun);

    // Create a new datagram transport connection. Pass the destination address
    // and port as parameter. This transport does not retry over TCP if the
    // reply is truncated. This transport does not have a separate run
    // function.
    let udp_connect = UdpConnect::new(server_addr);
    let dgram_conn =
        dgram::Connection::new(Some(dgram_config), udp_connect).unwrap();

    // Send a query message.
    let mut request = dgram_conn.send_request(&req).await.unwrap();

    // Get the reply
    let reply = request.get_response().await;
    println!("Dgram reply: {:?}", reply);

    // Create a single TCP transport connection. This is usefull for a
    // single request or a small burst of requests.
    let tcp_conn = match TcpStream::connect(server_addr).await {
        Ok(conn) => conn,
        Err(err) => {
            println!(
                "TCP Connection to {} failed: {}, exiting",
                server_addr, err
            );
            return;
        }
    };

    let tcp = octet_stream::Connection::new(None).unwrap();
    let run_fut = tcp.run(tcp_conn);
    tokio::spawn(async move {
        run_fut.await;
        println!("single TCP run terminated");
    });

    // Send a request message.
    let mut request = tcp.send_request(&req).await.unwrap();

    // Get the reply
    let reply = request.get_response().await;
    println!("TCP reply: {:?}", reply);

    drop(tcp);
}
