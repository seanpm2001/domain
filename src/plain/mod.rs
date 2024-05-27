//! More convenient variations of the base types.
//!
//! This module provides variations of the fundamental types in the
//! [`base`] and [`rdata`] modules that are more
//! convenient to use but may result in less efficient code under some
//! circumstances or aren’t usable in all cases.
//!
//! First of all, all types herein use `Bytes` and `BytesMut` as their
//! octet sequence types. These types provide a good balance between being
//! owned and relatively cheaply shareable.
#![cfg(feature = "plain")]

//------------ Sub-modules ---------------------------------------------------

pub mod message;

//------------ Type Aliases --------------------------------------------------

use crate::{base, rdata};
use bytes::Bytes;

/// The content of a DNS character string.
pub type CharStr = base::charstr::CharStr<Bytes>;

/// An uncompressed, absolute domain name.
pub type Name = base::name::Name<Bytes>;

/// An uncompressed, relative domain name.
pub type RelativeName = base::name::RelativeName<Bytes>;

/// A domain name that may be absolute or relative.
pub type UncertainName = base::name::UncertainName<Bytes>;

/// A question in a DNS message.
pub type Question = base::question::Question<Name>;

/// Record data for all record types.
pub type AllRecordData = rdata::AllRecordData<Bytes, Name>;

/// Record data for all record types allowed in zonefiles.
pub type ZoneRecordData = rdata::ZoneRecordData<Bytes, Name>;

/// Generic record data.
pub type UnknownRecordData = base::rdata::UnknownRecordData<Bytes>;

/// A resource record covering all record types.
pub type Record = base::record::Record<Name, AllRecordData>;

/// A resource record covering all record types allowed in zonefiles.
pub type ZoneRecord = base::record::Record<Name, ZoneRecordData>;

/// Option data for all option types.
pub type AllOptData = base::opt::AllOptData<Bytes, Name>;
