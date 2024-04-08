#![cfg(feature = "net")]
mod net;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use domain::zonetree::{Answer, ZoneTree};
use octseq::Octets;
use rstest::rstest;
use tracing::instrument;
use tracing::{trace, warn};

use domain::base::iana::Rcode;
use domain::base::wire::Composer;
use domain::base::{Dname, ToDname};
use domain::net::client::{dgram, stream};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::middleware::builder::MiddlewareBuilder;
#[cfg(feature = "siphasher")]
use domain::net::server::middleware::processors::cookies::CookiesMiddlewareProcessor;
use domain::net::server::middleware::processors::edns::EdnsMiddlewareProcessor;
use domain::net::server::service::{
    CallResult, Service, ServiceError, Transaction,
};
use domain::net::server::stream::StreamServer;
use domain::net::server::util::{mk_builder_for_target, service_fn};
use domain::zonefile::inplace::Zonefile;

use net::stelline::channel::ClientServerChannel;
use net::stelline::client::do_client;
use net::stelline::client::ClientFactory;
use net::stelline::client::{
    CurrStepValue, PerClientAddressClientFactory, QueryTailoredClientFactory,
};
use net::stelline::parse_stelline;
use net::stelline::parse_stelline::parse_file;
use net::stelline::parse_stelline::Config;
use net::stelline::parse_stelline::Matches;

//----------- Tests ----------------------------------------------------------

/// Stelline test cases for which the .rpl file defines a server: config block.
///
/// Note: Adding or removing .rpl files on disk won't be detected until the
/// test is re-compiled.
// #[cfg(feature = "mock-time")] # Needed for the cookies test but that is
// currently disabled by renaming it to .rpl.not.
#[instrument(skip_all, fields(rpl = rpl_file.file_name().unwrap().to_str()))]
#[rstest]
#[tokio::test(start_paused = true)]
async fn server_tests(#[files("test-data/server/*.rpl")] rpl_file: PathBuf) {
    // Load the test .rpl file that determines which queries will be sent
    // and which responses will be expected, and how the server that
    // answers them should be configured.

    use domain::zonetree::{Zone, ZoneTree};

    let file = File::open(&rpl_file).unwrap();
    let stelline = parse_file(&file, rpl_file.to_str().unwrap());
    let server_config = parse_server_config(&stelline.config);

    // Create a zonetree from the zones defined by the config
    let mut zones = ZoneTree::new();
    // TODO: get rid of zonefiles.clone()
    for reader in server_config.zonefiles.clone() {
        let zone = Zone::try_from(reader).unwrap();
        zones.insert_zone(zone).unwrap();
    }
    let zones = Arc::new(zones);

    // Create a service to answer queries received by the DNS servers.
    let service: Arc<_> = service_fn(test_service, zones).into();

    // Create dgram and stream servers for answering requests
    let (dgram_srv, dgram_conn, stream_srv, stream_conn) =
        mk_servers(service, &server_config);

    // Create a client factory for sending requests
    let client_factory = mk_client_factory(dgram_conn, stream_conn);

    // Run the Stelline test!
    let step_value = Arc::new(CurrStepValue::new());
    do_client(&stelline, &step_value, client_factory).await;

    // Await shutdown
    if !dgram_srv.await_shutdown(Duration::from_secs(5)).await {
        warn!("Datagram server did not shutdown on time.");
    }

    if !stream_srv.await_shutdown(Duration::from_secs(5)).await {
        warn!("Stream server did not shutdown on time.");
    }
}

//----------- test helpers ---------------------------------------------------

#[allow(clippy::type_complexity)]
fn mk_servers<Svc>(
    service: Arc<Svc>,
    server_config: &ServerConfig,
) -> (
    Arc<DgramServer<ClientServerChannel, VecBufSource, Arc<Svc>>>,
    ClientServerChannel,
    Arc<StreamServer<ClientServerChannel, VecBufSource, Arc<Svc>>>,
    ClientServerChannel,
)
where
    Svc: Service + Send + Sync + 'static,
    Svc::Future: Send,
    Svc::Target: Composer + Default + Send + Sync,
{
    // Prepare middleware to be used by the DNS servers to pre-process
    // received requests and post-process created responses.
    let (dgram_config, stream_config) = mk_server_configs(server_config);

    // Create a dgram server for handling UDP requests.
    let dgram_server_conn = ClientServerChannel::new_dgram();
    let dgram_server = DgramServer::with_config(
        dgram_server_conn.clone(),
        VecBufSource,
        service.clone(),
        dgram_config,
    );
    let dgram_server = Arc::new(dgram_server);
    let cloned_dgram_server = dgram_server.clone();
    tokio::spawn(async move { cloned_dgram_server.run().await });

    // Create a stream server for handling TCP requests, i.e. Stelline queries
    // with "MATCH TCP".
    let stream_server_conn = ClientServerChannel::new_stream();
    let stream_server = StreamServer::with_config(
        stream_server_conn.clone(),
        VecBufSource,
        service,
        stream_config,
    );
    let stream_server = Arc::new(stream_server);
    let cloned_stream_server = stream_server.clone();
    tokio::spawn(async move { cloned_stream_server.run().await });

    (
        dgram_server,
        dgram_server_conn,
        stream_server,
        stream_server_conn,
    )
}

fn mk_client_factory(
    dgram_server_conn: ClientServerChannel,
    stream_server_conn: ClientServerChannel,
) -> impl ClientFactory {
    // Create a TCP client factory that only creates a client if (a) no
    // existing TCP client exists for the source address of the Stelline query,
    // and (b) if the query specifies "MATCHES TCP". Clients created by this
    // factory connect to the TCP server created above.
    let only_for_tcp_queries = |entry: &parse_stelline::Entry| {
        matches!(entry.matches, Some(Matches { tcp: true, .. }))
    };

    let tcp_client_factory = PerClientAddressClientFactory::new(
        move |_source_addr| {
            let stream = stream_server_conn.connect();
            let (conn, transport) = stream::Connection::new(stream);
            tokio::spawn(transport.run());
            Box::new(conn)
        },
        only_for_tcp_queries,
    );

    // Create a UDP client factory that only creates a client if (a) no
    // existing UDP client exists for the source address of the Stelline query.
    let for_all_other_queries = |_: &_| true;

    let udp_client_factory = PerClientAddressClientFactory::new(
        move |_| Box::new(dgram::Connection::new(dgram_server_conn.clone())),
        for_all_other_queries,
    );

    // Create a combined client factory that will allow the Stelline runner to
    // use existing or create new client connections as appropriate for the
    // Stelline query being evaluated.
    QueryTailoredClientFactory::new(vec![
        Box::new(tcp_client_factory),
        Box::new(udp_client_factory),
    ])
}

fn mk_server_configs<RequestOctets, Target>(
    config: &ServerConfig,
) -> (
    domain::net::server::dgram::Config<RequestOctets, Target>,
    domain::net::server::stream::Config<RequestOctets, Target>,
)
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    let mut middleware = MiddlewareBuilder::minimal();

    if config.cookies.enabled {
        #[cfg(feature = "siphasher")]
        if let Some(secret) = config.cookies.secret {
            let secret = hex::decode(secret).unwrap();
            let secret = <[u8; 16]>::try_from(secret).unwrap();
            let processor = CookiesMiddlewareProcessor::new(secret);
            let processor = processor
                .with_denied_ips(config.cookies.ip_deny_list.clone());
            middleware.push(processor.into());
        }

        #[cfg(not(feature = "siphasher"))]
        panic!("The test uses cookies but the required 'siphasher' feature is not enabled.");
    }

    if config.edns_tcp_keepalive {
        let processor = EdnsMiddlewareProcessor::new();
        middleware.push(processor.into());
    }

    let middleware = middleware.build();

    let mut dgram_config = domain::net::server::dgram::Config::default();
    dgram_config.set_middleware_chain(middleware.clone());

    let mut stream_config = domain::net::server::stream::Config::default();
    if let Some(idle_timeout) = config.idle_timeout {
        let mut connection_config =
            domain::net::server::ConnectionConfig::default();
        connection_config.set_idle_timeout(idle_timeout);
        connection_config.set_middleware_chain(middleware);
        stream_config.set_connection_config(connection_config);
    }

    (dgram_config, stream_config)
}

// A test `Service` impl.
//
// This function can be used with `service_fn()` to create a `Service`
// instance designed to respond to test queries.
//
// The functionality provided is the mininum common set of behaviour needed
// by the tests that use it.
//
// It's behaviour should be influenced to match the conditions under test by:
//   - Using different `MiddlewareChain` setups with the server(s) to which
//     the `Service` will be passed.
//   - Controlling the content of the `Zonefile` passed to instances of
//     this `Service` impl.
#[allow(clippy::type_complexity)]
fn test_service(
    request: Request<Vec<u8>>,
    zones: Arc<ZoneTree>,
) -> Result<
    Transaction<
        Vec<u8>,
        impl Future<Output = Result<CallResult<Vec<u8>>, ServiceError>> + Send,
    >,
    ServiceError,
> {
    trace!("Service received request");
    Ok(Transaction::single(async move {
        trace!("Service is constructing a single response");
        // If given a single question:
        let question = request.message().sole_question().unwrap();
        let zone = zones
            .find_zone(question.qname(), question.qclass())
            .map(|zone| zone.read());
        let answer = match zone {
            Some(zone) => {
                let qname = question.qname().to_bytes();
                let qtype = question.qtype();
                zone.query(qname, qtype).unwrap()
            }
            None => Answer::new(Rcode::NXDOMAIN),
        };

        trace!("Service answer: {:#?}", &answer);

        let builder = mk_builder_for_target();
        let additional = answer.to_message(request.message(), builder);
        Ok(CallResult::new(additional))
    }))
}

//----------- Stelline config block parsing -----------------------------------

#[derive(Default)]
struct ServerConfig<'a> {
    cookies: CookieConfig<'a>,
    edns_tcp_keepalive: bool,
    idle_timeout: Option<Duration>,
    zonefiles: Vec<Zonefile>,
}

#[derive(Default)]
struct CookieConfig<'a> {
    enabled: bool,
    secret: Option<&'a str>,
    ip_deny_list: Vec<IpAddr>,
}

#[derive(Debug, Eq, PartialEq)]
enum ConfigSection {
    None,
    Server,
    AuthZone,
    AuthZoneZonefile,
    StubZone,
    Unknown,
}

impl ConfigSection {
    fn is_indented(&self) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match &self {
            ConfigSection::None => false,
            ConfigSection::AuthZoneZonefile => false,
            _ => true,
        }
    }
}

fn parse_server_config(config: &Config) -> ServerConfig {
    let mut parsed_config = ServerConfig::default();
    let mut zone_file_bytes = VecDeque::<u8>::new();
    let mut tempfiles: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut zone_tempfiles: HashSet<&str> = HashSet::new();
    let mut cur_tempfile_name: Option<&str> = None;
    let mut cur_tempfile_lines = Vec::new();
    let mut cur_section = ConfigSection::None;

    for line in config.lines() {
        if cur_section.is_indented()
            && !line.starts_with(|c: char| c.is_whitespace())
        {
            cur_section = ConfigSection::None;
        } else if line.trim_start().starts_with('#') {
            // Skip comment line
            continue;
        }

        if matches!(cur_section, ConfigSection::None|ConfigSection::AuthZoneZonefile) {
            if line.starts_with("server:") {
                cur_section = ConfigSection::Server;
                continue;
            } else if line.starts_with("auth-zone:") {
                cur_section = ConfigSection::AuthZone;
                continue;
            } else if line.starts_with("stub-zone") {
                cur_section = ConfigSection::StubZone;
                continue;
            } else if cur_section == ConfigSection::None {
                eprintln!("Ignoring unknown section: {line}");
                cur_section = ConfigSection::Unknown;
                continue;
            }
        }

        match cur_section {
            ConfigSection::Server => {
                if let Some((setting, value)) = line.trim().split_once(':') {
                    // Trim off whitespace and trailing comments.
                    let setting = setting.trim();
                    let value = value
                        .split_once('#')
                        .map_or(value, |(value, _rest)| value)
                        .trim();

                    match (setting, value) {
                        ("answer-cookie", "yes") => {
                            parsed_config.cookies.enabled = true
                        }
                        ("cookie-secret", v) => {
                            parsed_config.cookies.secret =
                                Some(v.trim_matches('"'));
                        }
                        ("access-control", v) => {
                            // TODO: Strictly speaking the "ip" is a netblock
                            // "given as an IPv4 or IPv6 address /size appended
                            // for a classless network block", but we only handle
                            // an IP address here for now.
                            // See: https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html?highlight=edns-tcp-keepalive#unbound-conf-access-control
                            if let Some((ip, action)) =
                                v.split_once(|c: char| c.is_whitespace())
                            {
                                match action {
                                    "allow_cookie" => {
                                        if let Ok(ip) = ip.parse() {
                                            parsed_config
                                                .cookies
                                                .ip_deny_list
                                                .push(ip);
                                        } else {
                                            eprintln!("Ignoring malformed IP address '{ip}' in 'access-control' setting");
                                        }
                                    }

                                    _ => {
                                        eprintln!("Ignoring unknown action '{action}' for 'access-control' setting");
                                    }
                                }
                            }
                        }
                        ("local-data", v) => {
                            if zone_file_bytes.is_empty() {
                                zone_file_bytes.extend(
                                    r#"test.	3600	IN	SOA	test. hostmaster.test. (
                                    1379078166 28800 7200 604800 7200 )"#
                                        .as_bytes(),
                                );
                            }
                            zone_file_bytes.push_back(b'\n');
                            zone_file_bytes.extend(
                                v.trim_matches('"').as_bytes().iter(),
                            );
                            zone_file_bytes.push_back(b'\n');
                        }
                        ("edns-tcp-keepalive", "yes") => {
                            parsed_config.edns_tcp_keepalive = true;
                        }
                        ("edns-tcp-keepalive-timeout", v) => {
                            if parsed_config.edns_tcp_keepalive {
                                parsed_config.idle_timeout = Some(
                                    Duration::from_millis(v.parse().unwrap()),
                                );
                            }
                        }
                        _ => {
                            eprintln!("Ignoring unknown server setting '{setting}' with value: {value}");
                        }
                    }
                }
            }

            ConfigSection::AuthZone => {
                if let Some((setting, value)) = line.trim().split_once(':') {
                    // Trim off whitespace and trailing comments.
                    let setting = setting.trim();
                    let value = value
                        .split_once('#')
                        .map_or(value, |(value, _rest)| value)
                        .trim();

                    match (setting, value) {
                        ("zonefile", _v) => {
                            cur_section = ConfigSection::AuthZoneZonefile;
                        }
                        (comment, _) if comment.starts_with('#') => {
                            // Nothing to do
                        }
                        _ => {
                            eprintln!("Ignoring unknown auth-zone setting '{setting}' with value: {value}");
                        }
                    }
                }
            }

            ConfigSection::AuthZoneZonefile => {
                if let Some((directive, value)) = line.trim().split_once(' ') {
                    let mut is_known_directive_with_value = true;

                    // Trim off whitespace and trailing comments.
                    let value = value
                        .split_once('#')
                        .map_or(value, |(value, _rest)| value)
                        .trim();

                    match (directive, value) {
                        ("TEMPFILE_NAME", tempfile_name) => {
                            // We don't write a tempfile by this name to disk, we
                            // instead read the contents directly into a zone tree,
                            // but we still need to pay attention to this line because
                            // it tells us which of the "TEMPFILE_CONTENTS" blocks are
                            // actually zones rather than just fragments included by
                            // "$INCLUDE_TEMPFILE" directives.
                            zone_tempfiles.insert(tempfile_name);
                        }
                        ("TEMPFILE_CONTENTS", tempfile_name) => {
                            if cur_tempfile_name.is_some() {
                                panic!("'TEMPFILE_CONTENTS {tempfile_name}' without 'TEMPFILE_END'");
                            }
                            cur_tempfile_name = Some(tempfile_name);
                            cur_tempfile_lines.clear();
                        }
                        _ => {
                            // Treat this line as zone file content.
                            is_known_directive_with_value = false;
                        }
                    }

                    if is_known_directive_with_value {
                        continue;
                    }
                }

                if line.starts_with("TEMPFILE_END") {
                    let tempfile_lines = cur_tempfile_lines;
                    cur_tempfile_lines = Vec::new();
                    tempfiles
                        .insert(cur_tempfile_name.unwrap(), tempfile_lines);
                    cur_tempfile_name = None;
                } else if line.trim().is_empty() {
                    // Note: We don't actually ever reach this branch because
                    // the Stelline config block parsing code discards empty
                    // lines.
                    cur_section = ConfigSection::None;
                } else {
                    cur_tempfile_lines.push(line);
                }
            }

            ConfigSection::StubZone => {
                eprintln!("Ignoring 'stub-zone': not implemented yet");
            }

            _ => {
                // skip
            }
        }
    }

    fn zonefile_str_from_tempfile(
        tempfile_name: &str,
        tempfiles: &HashMap<&str, Vec<&str>>,
    ) -> String {
        let mut zonefile_str = String::new();

        let tempfile_lines = tempfiles
            .get(tempfile_name)
            .expect("TEMPFILE not found: '{tempfile_name}'");

        for line in tempfile_lines {
            if line.starts_with("$INCLUDE_TEMPFILE ") {
                if let Some((_setting, value)) = line.trim().split_once(' ') {
                    // Trim off whitespace and trailing comments.
                    let include_tempfile_name = value
                        .split_once('#')
                        .map_or(value, |(value, _rest)| value)
                        .trim();

                    // Don't attempt a circular include
                    if include_tempfile_name == tempfile_name {
                        panic!(
                            r#"Circular include: "$INCLUDE_TEMPFILE {include_tempfile_name}" from tempfile "{tempfile_name}""#
                        );
                    }

                    if !tempfiles.contains_key(include_tempfile_name) {
                        panic!(
                            r#"TEMPFILE not found for "$INCLUDE_TEMPFILE {include_tempfile_name}"#
                        );
                    }

                    let included_str = zonefile_str_from_tempfile(
                        include_tempfile_name,
                        tempfiles,
                    );
                    zonefile_str.push_str(&included_str);
                }
            } else {
                zonefile_str.push_str(line);
                zonefile_str.push('\n');
            }
        }

        zonefile_str
    }

    // Process tempfiles
    // Note: An earlier one can refer to a later one via $INCLUDE_TEMPFILE.
    for tempfile_name in zone_tempfiles {
        let zonefile_str =
            zonefile_str_from_tempfile(tempfile_name, &tempfiles);
        let mut reader = BufReader::new(zonefile_str.as_bytes());
        let mut zonefile = Zonefile::load(&mut reader)
            .expect("Error while parsing zone TEMPFILE '{tempfile_name}'");
        zonefile.set_origin(Dname::bytes_from_str(tempfile_name).unwrap());
        parsed_config.zonefiles.push(zonefile);
    }

    if !zone_file_bytes.is_empty() {
        let mut zonefile = Zonefile::load(&mut zone_file_bytes).unwrap();
        zonefile.set_origin(Dname::bytes_from_str("test").unwrap());
        parsed_config.zonefiles.push(zonefile);
    }

    parsed_config
}
