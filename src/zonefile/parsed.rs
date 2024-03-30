//! Importing from and (in future) exporting to a zonefiles.

use core::convert::Infallible;
use std::collections::{BTreeMap, HashMap};
use std::vec::Vec;

use tracing::trace;

use super::error::{OwnerError, RecordError, ZoneErrors};
use super::inplace::{self, Entry};

use crate::base::iana::{Class, Rtype};
use crate::base::name::FlattenInto;
use crate::base::ToDname;
use crate::rdata::ZoneRecordData;
use crate::zonetree::ZoneBuilder;
use crate::zonetree::{Rrset, SharedRr, StoredDname, StoredRecord};

//------------ Zonefile ------------------------------------------------------

/// A parsed sanity checked representation of a zonefile.
///
/// This type eases creation of a [`ZoneBuilder`] from a collection of
/// [`StoredRecord`]s, e.g.  and accepts only records that are valid within
/// the zone.
///
/// The zone origin and class may be specified explicitly or be derived from
/// the SOA record when inserted. The relationship of each resource record
/// with the zone is classified on insert, similar to that described by [RFC
/// 1034 4.2.1].
///
/// Getter functions provide insight into the classification results.
///
/// When ready the [`Self::into_zone_builder()`] function can be used to
/// convert the parsed zonefile into a pre-populated [`ZoneBuilder`].
///
/// # Usage
///
/// See the [zonetree] module docs for example usage.
///
/// [RFC 1034 4.2.1]:
///     https://datatracker.ietf.org/doc/html/rfc1034#section-4.2.1
/// [zonetree]: crate::zonetree
#[derive(Clone, Default)]
pub struct Zonefile {
    /// The name of the apex of the zone.
    origin: Option<StoredDname>,

    /// The class of the zone.
    class: Option<Class>,

    /// The records for names that have regular RRsets attached to them.
    normal: Owners<Normal>,

    /// The records for names that are zone cuts.
    zone_cuts: Owners<ZoneCut>,

    /// The records for names that are CNAMEs.
    cnames: Owners<SharedRr>,

    /// Out of zone records.
    out_of_zone: Owners<Normal>,
}

impl Zonefile {
    pub fn new(apex: StoredDname, class: Class) -> Self {
        Zonefile {
            origin: Some(apex),
            class: Some(class),
            ..Default::default()
        }
    }
}

impl Zonefile {
    pub fn set_origin(&mut self, origin: StoredDname) {
        self.origin = Some(origin)
    }

    /// Inserts the record into the zone file.
    pub fn insert(
        &mut self,
        record: StoredRecord,
    ) -> Result<(), RecordError> {
        // If a zone apex and class were not provided via [`Self::new()`],
        // i.e. we were created by [`Self::default()`], require the first
        // record to be a SOA record and use its owner name and class as the
        // zone apex name and class.
        if self.origin.is_none() {
            if record.rtype() != Rtype::Soa {
                return Err(RecordError::MissingSoa);
            } else {
                let apex = record
                    .owner()
                    .to_dname()
                    .map_err(|_: Infallible| unreachable!())?;
                self.class = Some(record.class());
                self.origin = Some(apex);
            }
        }

        let (zone_apex, zone_class) =
            (self.origin().unwrap(), self.class().unwrap());

        if record.class() != zone_class {
            return Err(RecordError::ClassMismatch);
        }

        if !record.owner().ends_with(zone_apex) {
            self.out_of_zone
                .entry(record.owner().clone())
                .insert(record);
            Ok(())
        } else {
            match record.rtype() {
                // An Name Server (NS) record at the apex is a nameserver RR
                // that indicates a server for the zone. An NS record is only
                // an indication of a zone cut when it is NOT at the apex.
                //
                // A Delegation Signer (DS) record can only appear within the
                // parent zone and refer to a child zone, a DS record cannot
                // therefore appear at the apex.
                Rtype::Ns | Rtype::Ds if record.owner() != zone_apex => {
                    if self.normal.contains(record.owner())
                        || self.cnames.contains(record.owner())
                    {
                        return Err(RecordError::IllegalZoneCut);
                    }
                    self.zone_cuts
                        .entry(record.owner().clone())
                        .insert(record);
                    Ok(())
                }
                Rtype::Cname => {
                    if self.normal.contains(record.owner())
                        || self.zone_cuts.contains(record.owner())
                    {
                        return Err(RecordError::IllegalCname);
                    }
                    if self.cnames.contains(record.owner()) {
                        return Err(RecordError::MultipleCnames);
                    }
                    self.cnames.insert(record.owner().clone(), record.into());
                    Ok(())
                }
                _ => {
                    if self.zone_cuts.contains(record.owner())
                        || self.cnames.contains(record.owner())
                    {
                        return Err(RecordError::IllegalRecord);
                    }
                    self.normal.entry(record.owner().clone()).insert(record);
                    Ok(())
                }
            }
        }
    }
}

impl Zonefile {
    pub fn origin(&self) -> Option<&StoredDname> {
        self.origin.as_ref()
    }

    pub fn class(&self) -> Option<Class> {
        self.class
    }

    pub fn normal(&self) -> &Owners<Normal> {
        &self.normal
    }

    pub fn zone_cuts(&self) -> &Owners<ZoneCut> {
        &self.zone_cuts
    }

    pub fn cnames(&self) -> &Owners<SharedRr> {
        &self.cnames
    }

    pub fn out_of_zone(&self) -> &Owners<Normal> {
        &self.out_of_zone
    }
}

impl TryFrom<Zonefile> for ZoneBuilder {
    type Error = ZoneErrors;

    fn try_from(mut zonefile: Zonefile) -> Result<Self, Self::Error> {
        let mut builder = ZoneBuilder::new(
            zonefile.origin.unwrap(),
            zonefile.class.unwrap(),
        );
        let mut zone_err = ZoneErrors::default();

        // Insert all the zone cuts first. Fish out potential glue records
        // from the normal or out-of-zone records.
        for (name, cut) in zonefile.zone_cuts.into_iter() {
            let ns = match cut.ns {
                Some(ns) => ns.into_shared(),
                None => {
                    zone_err.add_error(name, OwnerError::MissingNs);
                    continue;
                }
            };
            let ds = cut.ds.map(Rrset::into_shared);
            let mut glue = vec![];
            for rdata in ns.data() {
                if let ZoneRecordData::Ns(ns) = rdata {
                    glue.append(
                        &mut zonefile.normal.collect_glue(ns.nsdname()),
                    );
                }
            }

            if let Err(err) = builder.insert_zone_cut(&name, ns, ds, glue) {
                zone_err.add_error(name, OwnerError::InvalidZonecut(err))
            }
        }

        // Now insert all the CNAMEs.
        for (name, rrset) in zonefile.cnames.into_iter() {
            if let Err(err) = builder.insert_cname(&name, rrset) {
                zone_err.add_error(name, OwnerError::InvalidCname(err))
            }
        }

        // Finally, all the normal records.
        for (name, rrsets) in zonefile.normal.into_iter() {
            for (rtype, rrset) in rrsets.into_iter() {
                if builder.insert_rrset(&name, rrset.into_shared()).is_err() {
                    zone_err.add_error(
                        name.clone(),
                        OwnerError::OutOfZone(rtype),
                    );
                }
            }
        }

        // If there are out-of-zone records left, we will error to avoid
        // surprises.
        for (name, rrsets) in zonefile.out_of_zone.into_iter() {
            for (rtype, _) in rrsets.into_iter() {
                zone_err
                    .add_error(name.clone(), OwnerError::OutOfZone(rtype));
            }
        }

        zone_err.into_result().map(|_| builder)
    }
}

//--- TryFrom<inplace::Zonefile>

impl TryFrom<inplace::Zonefile> for Zonefile {
    type Error = RecordError;

    fn try_from(source: inplace::Zonefile) -> Result<Self, Self::Error> {
        let mut zonefile = Zonefile::default();

        for res in source {
            match res.map_err(RecordError::MalformedRecord)? {
                Entry::Record(r) => zonefile.insert(r.flatten_into())?,
                entry => {
                    trace!("Skipping unsupported zone file entry: {entry:?}")
                }
            }
        }

        Ok(zonefile)
    }
}

//------------ Owners --------------------------------------------------------

#[derive(Clone)]
pub struct Owners<Content> {
    owners: BTreeMap<StoredDname, Content>,
}

impl<Content> Owners<Content> {
    fn contains(&self, name: &StoredDname) -> bool {
        self.owners.contains_key(name)
    }

    fn insert(&mut self, name: StoredDname, content: Content) -> bool {
        use std::collections::btree_map::Entry;

        match self.owners.entry(name) {
            Entry::Occupied(_) => false,
            Entry::Vacant(vacant) => {
                vacant.insert(content);
                true
            }
        }
    }

    fn entry(&mut self, name: StoredDname) -> &mut Content
    where
        Content: Default,
    {
        self.owners.entry(name).or_default()
    }

    fn into_iter(self) -> impl Iterator<Item = (StoredDname, Content)> {
        self.owners.into_iter()
    }
}

impl Owners<Normal> {
    fn collect_glue(&mut self, name: &StoredDname) -> Vec<StoredRecord> {
        let mut glue_records = vec![];

        // https://www.rfc-editor.org/rfc/rfc9471.html
        // 2.1. Glue for In-Domain Name Servers

        // For each NS delegation find the names of the nameservers the NS
        // records point to, and then see if the A/AAAA records for this names
        // are defined in the authoritative (normal) data for this zone, and
        // if so extract them.
        if let Some(normal) = self.owners.get(name) {
            // Now see if A/AAAA records exists for the name in
            // this zone.
            for (_rtype, rrset) in
                normal.records.iter().filter(|(&rtype, _)| {
                    rtype == Rtype::A || rtype == Rtype::Aaaa
                })
            {
                for rdata in rrset.data() {
                    let glue_record = StoredRecord::new(
                        name.clone(),
                        Class::In,
                        rrset.ttl(),
                        rdata.clone(),
                    );
                    glue_records.push(glue_record);
                }
            }
        }

        glue_records
    }
}

impl<Content> Default for Owners<Content> {
    fn default() -> Self {
        Owners {
            owners: Default::default(),
        }
    }
}

//------------ Normal --------------------------------------------------------

#[derive(Clone, Default)]
pub struct Normal {
    records: HashMap<Rtype, Rrset>,
}

impl Normal {
    fn insert(&mut self, record: StoredRecord) {
        use std::collections::hash_map::Entry;

        match self.records.entry(record.rtype()) {
            Entry::Occupied(mut occupied) => {
                occupied.get_mut().push_record(record)
            }
            Entry::Vacant(vacant) => {
                vacant.insert(record.into());
            }
        }
    }

    fn into_iter(self) -> impl Iterator<Item = (Rtype, Rrset)> {
        self.records.into_iter()
    }
}

//------------ ZoneCut -------------------------------------------------------

#[derive(Clone, Default)]
pub struct ZoneCut {
    ns: Option<Rrset>,
    ds: Option<Rrset>,
}

impl ZoneCut {
    fn insert(&mut self, record: StoredRecord) {
        match record.rtype() {
            Rtype::Ns => {
                if let Some(ns) = self.ns.as_mut() {
                    ns.push_record(record)
                } else {
                    self.ns = Some(record.into())
                }
            }
            Rtype::Ds => {
                if let Some(ds) = self.ds.as_mut() {
                    ds.push_record(record)
                } else {
                    self.ds = Some(record.into())
                }
            }
            _ => panic!("inserting wrong rtype to zone cut"),
        }
    }
}