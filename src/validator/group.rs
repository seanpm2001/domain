// Group of resource records and associated signatures.

// For lack of a better term we call this a group. RR set refers to just
// the resource records without the signatures.

// Name suggested by Yorgos: SignedRrset. Problem, sometimes there are no
// signatures, sometimes there is a signature but no RRset.

use crate::base::Name;
use crate::base::ParsedName;
use crate::base::ParsedRecord;
use crate::base::Ttl;
use bytes::Bytes;
//use crate::base::ParseRecordData;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::class::Class;
use crate::base::iana::ExtendedErrorCode;
use crate::base::name::ToName;
use crate::base::opt::exterr::ExtendedError;
use crate::base::rdata::ComposeRecordData;
use crate::base::Record;
use crate::base::Rtype;
//use crate::base::UnknownRecordData;
//use crate::dep::octseq::OctetsFrom;
//use crate::dep::octseq::OctetsInto;
use crate::dep::octseq::builder::with_infallible;
use crate::net::client::request::RequestMessage;
use crate::net::client::request::SendRequest;
use crate::rdata::dnssec::Timestamp;
use crate::rdata::AllRecordData;
use crate::rdata::Dnskey;
use crate::rdata::Rrsig;
use crate::validate::RrsigExt;
use moka::future::Cache;
use ring::digest;
use std::fmt::Debug;
//use std::marker::PhantomData;
use std::slice::Iter;
//use std::slice::IterMut;
use super::context::Node;
use super::context::ValidationContext;
use super::types::ValidationState;
use super::utilities::map_dname;
use super::utilities::ttl_for_sig;
//use std::sync::Mutex;
use std::cmp::min;
//use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

type RrType = Record<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>;
type SigType = Record<Name<Bytes>, Rrsig<Bytes, Name<Bytes>>>;

#[derive(Debug)]
pub struct Group {
    rr_set: Vec<RrType>,
    sig_set: Vec<SigType>,
}

impl Group {
    fn new(rr: ParsedRecord<'_, Bytes>) -> Self {
        if rr.rtype() != Rtype::RRSIG {
            return Self {
                rr_set: vec![to_bytes_record(&rr)],
                sig_set: Vec::new(),
            };
        }
        let record = rr.to_record::<Rrsig<_, _>>().unwrap().unwrap();
        let rrsig = record.data();

        let rrsig: Rrsig<Bytes, Name<Bytes>> =
            Rrsig::<Bytes, Name<Bytes>>::new(
                rrsig.type_covered(),
                rrsig.algorithm(),
                rrsig.labels(),
                rrsig.original_ttl(),
                rrsig.expiration(),
                rrsig.inception(),
                rrsig.key_tag(),
                rrsig.signer_name().try_to_name::<Bytes>().unwrap(),
                Bytes::copy_from_slice(rrsig.signature().as_ref()),
            )
            .unwrap();

        let record: Record<Name<Bytes>, _> = Record::new(
            record.owner().try_to_name::<Bytes>().unwrap(),
            record.class(),
            record.ttl(),
            rrsig,
        );

        return Self {
            rr_set: Vec::new(),
            sig_set: vec![record],
        };
    }

    fn add(&mut self, rr: &ParsedRecord<'_, Bytes>) -> Result<(), ()> {
        // First check owner.
        if !self.rr_set.is_empty() {
            if self.rr_set[0].owner()
                != &rr.owner().try_to_name::<Bytes>().unwrap()
            {
                return Err(());
            }
        } else {
            if self.sig_set[0].owner().try_to_name::<Bytes>()
                != rr.owner().try_to_name()
            {
                return Err(());
            }
        }

        let (curr_class, curr_rtype) = if !self.rr_set.is_empty() {
            (self.rr_set[0].class(), self.rr_set[0].rtype())
        } else {
            (
                self.sig_set[0].class(),
                self.sig_set[0].data().type_covered(),
            )
        };

        if rr.rtype() == Rtype::RRSIG {
            let record = rr.to_record::<Rrsig<_, _>>().unwrap().unwrap();
            let rrsig = record.data();

            if curr_class == rr.class() && curr_rtype == rrsig.type_covered()
            {
                let rrsig: Rrsig<Bytes, Name<Bytes>> =
                    Rrsig::<Bytes, Name<Bytes>>::new(
                        rrsig.type_covered(),
                        rrsig.algorithm(),
                        rrsig.labels(),
                        rrsig.original_ttl(),
                        rrsig.expiration(),
                        rrsig.inception(),
                        rrsig.key_tag(),
                        rrsig.signer_name().try_to_name::<Bytes>().unwrap(),
                        Bytes::copy_from_slice(rrsig.signature().as_ref()),
                    )
                    .unwrap();

                let record: Record<Name<Bytes>, _> = Record::new(
                    record.owner().try_to_name::<Bytes>().unwrap(),
                    curr_class,
                    record.ttl(),
                    rrsig,
                );
                self.sig_set.push(record);
                return Ok(());
            }
            return Err(());
        }

        // We can add rr if owner, class and rtype match.
        if curr_class == rr.class() && curr_rtype == rr.rtype() {
            let rr = to_bytes_record(rr);

            // Some recursors return deplicate records. Check.
            for r in &self.rr_set {
                if *r == rr {
                    // We already have this record.
                    return Ok(());
                }
            }

            self.rr_set.push(rr);
            return Ok(());
        }

        // No match.
        Err(())
    }

    pub fn validated(
        &self,
        state: ValidationState,
        signer_name: Name<Bytes>,
        wildcard: Option<Name<Bytes>>,
        ede: Option<ExtendedError<Bytes>>,
    ) -> ValidatedGroup {
        ValidatedGroup::new(
            self.rr_set.clone(),
            self.sig_set.clone(),
            state,
            signer_name,
            wildcard,
            ede,
        )
    }

    pub fn owner(&self) -> Name<Bytes> {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].owner().to_bytes();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        return self.sig_set[0].owner().to_bytes();
    }

    pub fn class(&self) -> Class {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].class();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        self.sig_set[0].class()
    }

    pub fn rtype(&self) -> Rtype {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].rtype();
        }

        // The type in sig_set is always Rrsig
        Rtype::RRSIG
    }

    pub fn rr_set(&self) -> Vec<RrType> {
        self.rr_set.clone()
    }

    pub fn rr_iter(&mut self) -> Iter<RrType> {
        self.rr_set.iter()
    }

    pub fn sig_set_len(&self) -> usize {
        self.sig_set.len()
    }

    pub fn sig_iter(&mut self) -> Iter<SigType> {
        self.sig_set.iter()
    }

    pub async fn validate_with_vc<Upstream>(
        &self,
        vc: &ValidationContext<Upstream>,
    ) -> (
        ValidationState,
        Name<Bytes>,
        Option<Name<Bytes>>,
        Option<ExtendedError<Bytes>>,
    )
    where
        Upstream: Clone + SendRequest<RequestMessage<Bytes>>,
    {
        // We have two cases, with an without RRSIGs. With RRSIGs we can
        // look at the signer_name. We need to find the DNSSEC status
        // of signer_name. If the status is secure, we can validate
        // the RRset against the keys in that zone. If the status is
        // insecure we can ignore the RRSIGs and return insecure.
        //
        // Without signatures we need to find the closest enclosing zone
        // that is insecure (and return the status insecure) or find that
        // the name is in a secure zone and return bogus.
        //
        // Note that the GetDNS validator issues a SOA query if there is
        // no signature. Is that better then just walking to the first
        // insecure delegation?
        //
        // Note that if the RRset is empty (and we only have RRSIG records)
        // then the status is insecure, because we cannot validate RRSIGs.
        // Is there an RFC that descibes this?
        if self.rr_set.is_empty() {
            return (
                ValidationState::Insecure,
                Name::root(),
                None,
                Some(
                    ExtendedError::new_with_str(
                        ExtendedErrorCode::DNSSEC_INDETERMINATE,
                        "RRSIG without RRset",
                    )
                    .unwrap(),
                ),
            );
        }

        let target = if !self.sig_set.is_empty() {
            self.sig_set[0].data().signer_name()
        } else {
            self.rr_set[0].owner()
        };
        let node = vc.get_node(target).await;
        let state = node.validation_state();
        match state {
            ValidationState::Secure => (), // Continue validating
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => {
                return (state, target.clone(), None, node.extended_error())
            }
        }
        let (state, wildcard, ede, _ttl) =
            self.validate_with_node(&node, &vc.usig_cache()).await;
        (state, target.clone(), wildcard, ede)
    }

    // Try to validate the signature using a node. Return the validation
    // state. Also return if the signature was expanded from a wildcard.
    // This is valid only if the validation state is secure.
    pub async fn validate_with_node(
        &self,
        node: &Node,
        sig_cache: &SigCache,
    ) -> (
        ValidationState,
        Option<Name<Bytes>>,
        Option<ExtendedError<Bytes>>,
        Duration,
    ) {
        // Check the validation state of node. We can return directly if the
        // state is anything other than Secure.
        let state = node.validation_state();
        match state {
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => {
                return (state, None, node.extended_error(), node.ttl())
            }
            ValidationState::Secure => (),
        }
        let keys = node.keys();
        let ttl = node.ttl();
        println!("validate_with_node: node ttl {ttl:?}");
        let group_ttl = self.min_ttl().into_duration();
        let ttl = min(ttl, group_ttl);
        println!("with group_ttl {group_ttl:?}, new ttl {ttl:?}");

        for sig_rec in self.clone().sig_iter() {
            let sig = sig_rec.data();
            for key in keys {
                // See if this key matches the sig.
                if key.algorithm() != sig.algorithm() {
                    continue;
                }
                let key_tag = key.key_tag();
                if key_tag != sig.key_tag() {
                    continue;
                }

                println!("validate_with_node: sig {sig_rec:?}");
                if self
                    .check_sig_cached(
                        sig_rec,
                        node.signer_name(),
                        key,
                        node.signer_name(),
                        key_tag,
                        sig_cache,
                    )
                    .await
                {
                    let wildcard =
                        sig.wildcard_closest_encloser(&self.rr_set[0]);

                    let sig_ttl = ttl_for_sig(sig_rec);
                    let ttl = min(ttl, sig_ttl);
                    println!("with sig_ttl {sig_ttl:?}, new ttl {ttl:?}");
                    return (ValidationState::Secure, wildcard, None, ttl);
                } else {
                    // To avoid CPU exhaustion attacks such as KeyTrap
                    // (CVE-2023-50387) it is good to limit signature
                    // validation as much as possible. To be as strict as
                    // possible, we can make the following assumptions:
                    // 1) A trust anchor contains at least one key with a
                    // supported algorithm, so at least one signature is
                    // expected to be verifiable.
                    // 2) A DNSKEY RRset plus associated RRSIG is self-
                    // contained. Every signature is made with a key in the
                    // RRset and it is the current contents of the RRset
                    // that is signed. So we expect that signature
                    // verification cannot fail.
                    // 3) With one exception: keytag collisions could create
                    // confusion about which key was used. Collisions are
                    // rare so we assume at most two keys in the RRset to be
                    // involved in a collision.
                    // For these reasons we can limit the number of failures
                    // we tolerate to one. And declare the DNSKEY RRset
                    // bogus if we get two failures.
                    todo!();
                }
            }
        }
        todo!(); // EDE
                 // (ValidationState::Bogus, None)
    }

    // Follow RFC 4035, Section 5.3.
    fn check_sig(
        &self,
        sig: &Record<Name<Bytes>, Rrsig<Bytes, Name<Bytes>>>,
        signer_name: &Name<Bytes>,
        key: &Dnskey<Bytes>,
        key_name: &Name<Bytes>,
        key_tag: u16,
    ) -> bool {
        let ts_now = Timestamp::now();
        let rtype = self.rtype();
        let owner = self.owner();
        let labels = owner.iter().count() - 1;
        let rrsig = sig.data();

        println!("check_sig for {rrsig:?} and {key:?}");

        println!("{:?} and {:?}", rrsig.type_covered(), rtype);
        println!(
            "{:?} and {:?}: {:?}",
            rrsig.expiration(),
            ts_now,
            rrsig.expiration().canonical_lt(&ts_now)
        );
        println!(
            "{:?} and {:?}: {:?}",
            rrsig.inception(),
            ts_now,
            rrsig.inception().canonical_gt(&ts_now)
        );
        println!("{:?} and {:?}", rrsig.algorithm(), key.algorithm());
        println!("{:?} and {:?}", rrsig.key_tag(), key_tag);

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR and the RRset MUST have the same owner name and the same
        //   class.
        if !sig.owner().name_eq(&owner) || sig.class() != self.class() {
            println!("failed at line {}", line!());
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR's Signer's Name field MUST be the name of the zone that
        //   contains the RRset.

        // We don't really know the name of the zone that contains an RRset. What
        // we can do is that the signer's name is a prefix of the owner name.
        // We assume that a zone will not sign things in space that is delegated
        // (except for the parent side of the delegation)
        if !owner.ends_with(&signer_name) {
            println!("failed at line {}", line!());
            println!(
                "check_sig: {:?} does not end with {signer_name:?}",
                owner
            );
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR's Type Covered field MUST equal the RRset's type.
        if rrsig.type_covered() != rtype {
            println!("failed at line {}", line!());
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The number of labels in the RRset owner name MUST be greater than
        //   or equal to the value in the RRSIG RR's Labels field.
        if labels < rrsig.labels() as usize {
            println!("failed at line {}", line!());
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The validator's notion of the current time MUST be less than or
        //   equal to the time listed in the RRSIG RR's Expiration field.
        // - The validator's notion of the current time MUST be greater than or
        //   equal to the time listed in the RRSIG RR's Inception field.
        if ts_now.canonical_gt(&rrsig.expiration())
            || ts_now.canonical_lt(&rrsig.inception())
        {
            println!("failed at line {}", line!());
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST
        //   match the owner name, algorithm, and key tag for some DNSKEY RR in
        //   the zone's apex DNSKEY RRset.
        if signer_name != key_name
            || rrsig.algorithm() != key.algorithm()
            || rrsig.key_tag() != key_tag
        {
            println!("failed at line {}", line!());
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The matching DNSKEY RR MUST be present in the zone's apex DNSKEY
        //   RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7)
        //   set.

        // We cannot check here if the key is in the zone's apex, that is up to
        // the caller. Just check the Zone Flag bit.
        if !key.is_zone_key() {
            println!("failed at line {}", line!());
            return false;
        }

        //signature
        let mut signed_data = Vec::<u8>::new();
        rrsig
            .signed_data(&mut signed_data, &mut self.rr_set())
            .unwrap();
        let res = rrsig.verify_signed_data(key, &signed_data);

        if !res.is_ok() {
            println!("failed at line {} with {res:?}", line!());
        }

        res.is_ok()
    }

    pub async fn check_sig_cached(
        &self,
        sig: &Record<Name<Bytes>, Rrsig<Bytes, Name<Bytes>>>,
        signer_name: &Name<Bytes>,
        key: &Dnskey<Bytes>,
        key_name: &Name<Bytes>,
        key_tag: u16,
        cache: &SigCache,
    ) -> bool {
        let mut signed_data = Vec::<u8>::new();
        sig.data()
            .signed_data(&mut signed_data, &mut self.rr_set())
            .unwrap();

        let mut buf: Vec<u8> = Vec::new();
        with_infallible(|| key.compose_canonical_rdata(&mut buf));
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(&buf);
        let key_hash = ctx.finish();

        let mut buf: Vec<u8> = Vec::new();
        with_infallible(|| sig.data().compose_canonical_rdata(&mut buf));
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(&buf);
        let sig_hash = ctx.finish();

        let cache_key = (
            signed_data,
            sig_hash.as_ref().to_vec(),
            key_hash.as_ref().to_vec(),
        );

        if let Some(ce) = cache.cache.get(&cache_key).await {
            println!("check_sig_cached: existing result");
            return ce;
        }
        println!("check_sig_cached: checking");
        let res = self.check_sig(sig, signer_name, key, key_name, key_tag);
        println!("check_sig_cached: inserting {res:?}");
        cache.cache.insert(cache_key, res).await;
        res
    }

    pub fn min_ttl(&self) -> Ttl {
        if self.rr_set.is_empty() {
            return Ttl::ZERO;
        }
        let mut ttl = self.rr_set[0].ttl();
        for rr in &self.rr_set[1..] {
            ttl = min(ttl, rr.ttl());
        }
        ttl
    }
}

impl Clone for Group {
    fn clone(&self) -> Self {
        Self {
            rr_set: self.rr_set.clone(),
            sig_set: self.sig_set.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GroupList(Vec<Group>);

impl GroupList {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, rr: ParsedRecord<'_, Bytes>) {
        // Very simplistic implementation of add. Assume resource records
        // are mostly in order. If this O(n^2) algorithm is not enough,
        // then we should use a small hash table or sort first.
        if self.0.is_empty() {
            self.0.push(Group::new(rr));
            return;
        }
        let len = self.0.len();
        let res = self.0[len - 1].add(&rr);
        if res.is_ok() {
            return;
        }

        // Try all existing groups except the last one
        for g in &mut self.0[..len - 1] {
            let res = g.add(&rr);
            if res.is_ok() {
                return;
            }
        }

        // Add a new group.
        self.0.push(Group::new(rr));
    }

    pub fn remove_redundant_cnames(&mut self) {
        let self_clone = self.clone();
        self.0.retain(|g| {
            if g.rtype() != Rtype::CNAME {
                return true;
            }
            let rr_set = g.rr_set();
            if rr_set.len() != 1 {
                return true; // Let it fail if it is in secure zone.
            }
            if g.sig_set_len() != 0 {
                // Signed CNAME, no need to check.
                return true;
            }

            if self_clone.matches_dname(&rr_set[0]) {
                // Courtesy CNAME, remove.
                return false;
            }

            // No match.
            return true;
        });
    }

    fn matches_dname(
        &self,
        cname_rr: &Record<
            Name<Bytes>,
            AllRecordData<Bytes, ParsedName<Bytes>>,
        >,
    ) -> bool {
        let cname_name = cname_rr.owner();
        for g in &self.0 {
            if g.rtype() != Rtype::DNAME {
                continue;
            }
            let rr_set = g.rr_set();
            for rr in rr_set {
                let owner = rr.owner();
                if !cname_name.ends_with(owner) {
                    continue;
                }
                if cname_name == owner {
                    // Weird, both a CNAME and a DNAME at the same name.
                    continue;
                }

                // Now check the target of the CNAME.
                let result_name =
                    if let AllRecordData::Dname(dname) = rr.data() {
                        map_dname(owner, dname, cname_name)
                    } else {
                        panic!("DNAME expected");
                    };
                println!("after applying DNAME: {result_name:?}");
                if let AllRecordData::Cname(cname) = cname_rr.data() {
                    if cname.cname().to_name::<Bytes>() == result_name {
                        println!("got match");
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn iter(&mut self) -> Iter<Group> {
        self.0.iter()
    }
}

#[derive(Debug)]
pub struct ValidatedGroup {
    rr_set: Vec<RrType>,
    sig_set: Vec<SigType>,
    state: ValidationState,
    signer_name: Name<Bytes>,
    closest_encloser: Option<Name<Bytes>>,
    ede: Option<ExtendedError<Bytes>>,
}

impl ValidatedGroup {
    fn new(
        rr_set: Vec<RrType>,
        sig_set: Vec<SigType>,
        state: ValidationState,
        signer_name: Name<Bytes>,
        closest_encloser: Option<Name<Bytes>>,
        ede: Option<ExtendedError<Bytes>>,
    ) -> ValidatedGroup {
        ValidatedGroup {
            rr_set,
            sig_set,
            state,
            signer_name,
            closest_encloser,
            ede,
        }
    }

    pub fn class(&self) -> Class {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].class();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        self.sig_set[0].class()
    }

    pub fn rtype(&self) -> Rtype {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].rtype();
        }

        // The type in sig_set is always Rrsig
        Rtype::RRSIG
    }

    pub fn owner(&self) -> Name<Bytes> {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].owner().to_bytes();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        return self.sig_set[0].owner().to_bytes();
    }

    pub fn state(&self) -> ValidationState {
        self.state
    }

    pub fn signer_name(&self) -> Name<Bytes> {
        self.signer_name.clone()
    }

    pub fn closest_encloser(&self) -> Option<Name<Bytes>> {
        self.closest_encloser.clone()
    }

    pub fn ede(&self) -> Option<ExtendedError<Bytes>> {
        self.ede.clone()
    }

    pub fn rr_set(&self) -> Vec<RrType> {
        self.rr_set.clone()
    }
}

fn to_bytes_record(
    rr: &ParsedRecord<'_, Bytes>,
) -> Record<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>> {
    let record = rr.to_record::<AllRecordData<_, _>>().unwrap().unwrap();
    Record::<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>::new(
        rr.owner().try_to_name::<Bytes>().unwrap(),
        rr.class(),
        rr.ttl(),
        record.data().clone(),
    )
}

pub struct SigCache {
    cache: Cache<(Vec<u8>, Vec<u8>, Vec<u8>), bool>,
}

impl SigCache {
    pub fn new(size: u64) -> Self {
        Self {
            cache: Cache::new(size),
        }
    }
}