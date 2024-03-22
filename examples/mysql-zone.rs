//! MySQL backed zone serving minimal proof of concept.
//
// This example extends `domain` with a new `ZoneData` impl adding support for
// MySQL backed zones. This demonstration only implements the `ReadableZone`
// trait, it doesn't implement the `WritableZone` trait, so database access is
// read-only. Write access could be implemented, it just isn't in this
// example. The same approach can be used to implement access for any kind of
// backed, e.g. invoking shell commands to get the answers even ;-)
//
// Warning: This example needs a lot of setup and has several prerequisites.
//
// ===========================================================================
// A big shout out to PowerDNS as this example uses their MySQL database
// schema and their zone2sql tool. And also to the sqlx project for making
// database access via Rust so easy.
//
// For more information about the PowerDNS MySQL support see:
//   https://doc.powerdns.com/authoritative/backends/generic-mysql.html
//
// For more information about SQLX see:
//   https://github.com/launchbadge/sqlx
// ===========================================================================
//
// # Prerequisites
//
// You need:
//   - A Linux machine (the instructions below have only been tested on Fedora
//     39).
//   - A MySQL server (tested with "Ver 8.0.35 for Linux on x86_64).
//   - A MySQL user with the right to create a database.
//     Note: You may also need sufficient rights to disable restrictions
//     concerning maximum column length.
//   - The PowerDNS zone2sql command line tool for converting a zone file to
//     SQL insert operations compatible with the PowerDNS MySQL schema.
//   - The sqlx-cli command line tool, for automating database and table
//     creation and data import.
//
// # Database access
//
// Connecting to the database users settings provided in an environment
// variable called DATABASE_URL. When using a connection URL the password has
// to be URL encoded. The environment variable value must have the following
// format.
//
//   DATABASE_URL='mysql://<user>:<pass>>@<host>[:<port>]/<dbname>'
//
// Note: The PowerDNS MySQL schema uses large column sizes. If you see an
// error like "Column length too big for column" when running the initial sqlx
// database migration step to create the schema, disable the default MySQL
// restrictions with a command similar to the following in the MySQL shell:
//
//   $ mysql -u root -p mysql> SET GLOBAL sql_mode = '';
//
// A quick tip for viewing the MySQL queries issued by this example:
//
//   $ mysql -u root -p
//   mysql> SET GLOBAL log_output = 'table';
//   mysql> SET GLOBAL general_log = 'on';
//   mysql> SELECT CONVERT(argument USING utf8) FROM mysql.general_log;
//
// # Preparation
//
//   Note: dnf is the Fedora package manager, and pdns is the name of the
//   Fedora PowerDNS package. Adjust the commands and values below to match
//   your O/S.
//
//   - cargo install sqlx-cli
//
//   - sudo dnf install -y pdns
//
//   - export DATABASE_URL='.....'
//     Make sure the user specified in
//     DATABASE_URL has the right to create databases.
//
//   - cargo sqlx database create
//
//   - cargo sqlx migrate add make_tables
//     Note: This will output a migrations/..._make_tables.sql path. We will
//     refer to this below as MAKE_TABLES_PATH
//
//   - wget -O${MAKE_TABLES_PATH}
//     https://raw.githubusercontent.com/PowerDNS/pdns/master/modules/gmysqlbackend/schema.mysql.sql
//
//   - cargo sqlx migrate run
//
//   - cargo sqlx migrate add import_data
//     Note: This will output a migrations/..._import_data.sql path. We will
//     refer to this below as IMPORT_DATA_PATH
//
//   - zone2sql --gmysql --zone=test-data/zonefiles/nsd-example.txt >
//     ${IMPORT_DATA_PATH}
//
//   - cargo sqlx migrate run
//
//   - cargo sqlx prepare -- --example mysql-zone --features
//     zonefile,net,unstable-server-transport
//
// # Running the example
//
// Now you can run the example with the following command and should see
// output similar to that shown below:
//
//  $ cargo run --example mysql-zone --features zonefile,net,unstable-server-transport
//  ...
//  ; (1 server found)
//  ;; global options:
//  ;; Got answer:
//  ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 0
//  ;; flags: qr ; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
//  ;; QUESTION SECTION:
//  ;example.com IN A
//
//  ;; ANSWER SECTION:
//  example.com. 86400 IN A 192.0.2.1

use std::{future::Future, pin::Pin, str::FromStr, sync::Arc};

use bytes::Bytes;
use domain::base::iana::{Class, Rcode};
use domain::base::scan::IterScanner;
use domain::base::{Dname, Rtype, Ttl};
use domain::rdata::ZoneRecordData;
use domain::zonetree::{
    Answer, OutOfZone, ReadableZone, Rrset, SharedRrset, StoredDname,
    Version, VersionMarker, WalkOp, WriteableZone, Zone, ZoneData, ZoneSet,
};
use parking_lot::RwLock;
use sqlx::{mysql::MySqlConnectOptions, MySqlPool};

#[path = "common/serve-utils.rs"]
mod common;

#[tokio::main]
async fn main() {
    // Create a zone whose queries will be satisfied by querying the database
    // defined by the DATABASE_URL environment variable.
    let mut zones = ZoneSet::new();
    let db_zone = DatabaseZoneBuilder::mk_test_zone("example.com").await;
    zones.insert_zone(db_zone).unwrap();

    // Setup a mock query.
    let qname = Dname::bytes_from_str("example.com").unwrap();
    let qclass = Class::In;
    let qtype = Rtype::A;

    // Execute the query. The steps we take are:
    //   1. Find the zone in the zone set that matches the query name.
    //   2. Get a read interface to it via `.read()`.
    //   3. Query the zone, synchronously or asynchronously, based on what
    //      the zone says it supports. For stock `domain` zones the
    //      `.is_async()` call will return false, but for our MySQL backed
    //      zone it returns true, as the DB calls are asynchronous.
    let zone = zones.find_zone(&qname, qclass).unwrap().read();
    let zone_answer = match zone.is_async() {
        true => zone.query_async(qname.clone(), qtype).await.unwrap(),
        false => zone.query(qname.clone(), qtype).unwrap(),
    };

    // Render the response in dig style output.
    let wire_query = common::generate_wire_query(&qname, qtype);
    let wire_response =
        common::generate_wire_response(&wire_query, zone_answer);
    common::print_dig_style_response(&wire_query, &wire_response, false);
}

//----------- DatbaseZoneBuilder ---------------------------------------------

pub struct DatabaseZoneBuilder;

impl DatabaseZoneBuilder {
    pub async fn mk_test_zone(apex_name: &str) -> Zone {
        let opts: MySqlConnectOptions =
            std::env::var("DATABASE_URL").unwrap().parse().unwrap();
        let pool = MySqlPool::connect_with(opts).await.unwrap();
        let apex_name = StoredDname::from_str(apex_name).unwrap();
        let node = DatabaseNode::new(pool, apex_name);
        Zone::new(node)
    }
}

//----------- DatbaseNode ----------------------------------------------------

#[derive(Debug)]
struct DatabaseNode {
    db_pool: sqlx::MySqlPool,
    apex_name: StoredDname,
}

impl DatabaseNode {
    fn new(db_pool: sqlx::MySqlPool, apex_name: StoredDname) -> Self {
        Self { db_pool, apex_name }
    }
}

//--- impl ZoneData

impl ZoneData for DatabaseNode {
    fn class(&self) -> Class {
        Class::In
    }

    fn apex_name(&self) -> &StoredDname {
        &self.apex_name
    }

    fn read(
        self: Arc<Self>,
        _current: (Version, Arc<VersionMarker>),
    ) -> Box<dyn ReadableZone> {
        Box::new(DatabaseReadZone::new(
            self.db_pool.clone(),
            self.apex_name.clone(),
        ))
    }

    fn write(
        self: Arc<Self>,
        _version: Version,
        _zone_versions: Arc<RwLock<domain::zonetree::ZoneVersions>>,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WriteableZone>>>> {
        todo!()
    }
}

//----------- DatbaseReadZone ------------------------------------------------

struct DatabaseReadZone {
    db_pool: sqlx::MySqlPool,
    apex_name: StoredDname,
}

impl DatabaseReadZone {
    fn new(db_pool: sqlx::MySqlPool, apex_name: StoredDname) -> Self {
        Self { db_pool, apex_name }
    }
}

//--- impl ReadableZone

impl ReadableZone for DatabaseReadZone {
    fn is_async(&self) -> bool {
        true
    }

    fn query_async(
        &self,
        qname: Dname<Bytes>,
        qtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<Answer, OutOfZone>> + Send>> {
        let db_pool = self.db_pool.clone();
        let apex_name = self.apex_name.to_string();
        let fut = async move {
            let answer = if let Ok(row) = sqlx::query!(
                r#"SELECT R.content, R.ttl FROM domains D, records R WHERE D.name = ? AND D.id = R.domain_id AND R.name = ? AND R.type = ? LIMIT 1"#,
                apex_name,
                qname.to_string(),
                qtype.to_string(),
            )
            .fetch_one(&db_pool)
            .await
            {
                let mut answer = Answer::new(Rcode::NoError);
                let mut rrset = Rrset::new(qtype, Ttl::from_secs(row.ttl.unwrap() as u32));
                let content = &row.content.unwrap();
                let content_strings = content.split_ascii_whitespace().collect::<std::vec::Vec<&str>>();
                let mut scanner = IterScanner::new(&content_strings);
                match ZoneRecordData::scan(qtype, &mut scanner) {
                    Ok(data) => {
                        rrset.push_data(data);
                        let rrset = SharedRrset::new(rrset);
                        answer.add_answer(rrset);
                        answer
                    }
                    Err(err) => {
                        eprintln!("Unable to parse DB record of type {qtype}: {err}");
                        Answer::new(Rcode::ServFail)
                    }
                }
            } else {
                Answer::new(Rcode::NXDomain)
            };
            Ok(answer)
        };
        Box::pin(fut)
    }

    fn walk_async(
        &self,
        op: WalkOp,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let db_pool = self.db_pool.clone();
        let apex_name = self.apex_name.to_string();
        let fut = async move {
            for row in sqlx::query!(
                r#"SELECT R.name, R.type AS rtype, R.content, R.ttl FROM domains D, records R WHERE D.name = ? AND D.id = R.domain_id"#,
                apex_name,
            )
            .fetch_all(&db_pool)
            .await
            .unwrap() {
                let owner = Dname::bytes_from_str(&row.name.unwrap()).unwrap();
                let rtype = Rtype::from_str(&row.rtype.unwrap()).unwrap();
                let mut rrset = Rrset::new(rtype, Ttl::from_secs(row.ttl.unwrap() as u32));
                let content = &row.content.unwrap();
                let content_strings = content.split_ascii_whitespace().collect::<std::vec::Vec<&str>>();
                // eprintln!("Scanning {rtype} content: {:?}", content_strings);
                let mut scanner = IterScanner::new(&content_strings);
                match ZoneRecordData::scan(rtype, &mut scanner) {
                    Ok(data) => {
                        rrset.push_data(data);
                        op(owner, &rrset);
                    }
                    Err(err) => {
                        eprintln!("Unable to parse DB record of type {rtype}: {err}");
                    }
                }
            };
        };
        Box::pin(fut)
    }

    fn query(
        &self,
        _qname: Dname<Bytes>,
        _qtype: Rtype,
    ) -> Result<Answer, OutOfZone> {
        unimplemented!()
    }

    fn walk(&self, _walkop: WalkOp) {
        unimplemented!()
    }
}
