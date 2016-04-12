//! Character strings.

use std::borrow::Borrow;
use std::cmp;
use std::fmt;
use std::hash;
use std::ops::Deref;
use std::str;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, FromStrError, FromStrResult, ParseResult};
use super::parse::ParseBytes;

//------------ CString ------------------------------------------------------

pub trait CString: fmt::Display + Sized {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()>;
}

//------------ CStringRef ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct CStringRef<'a> {
    inner: &'a [u8]
}

impl <'a> CStringRef<'a> {
    unsafe fn from_bytes(bytes: &'a [u8]) -> Self {
        CStringRef { inner: bytes }
    }

    pub fn to_owned(&self) -> OwnedCString {
        unsafe { OwnedCString::from_bytes(self.inner) }
    }

    pub fn parse<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        let len = try!(parser.parse_u8()) as usize;
        parser.parse_bytes(len)
              .map(|bytes| unsafe {CStringRef::from_bytes(bytes) })
    }
}


//--- CString

impl<'a> CString for CStringRef<'a> {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        assert!(self.inner.len() < 256);
        try!(target.push_u8(self.inner.len() as u8));
        try!(target.push_bytes(self.inner));
        Ok(())
    }
}


//--- Deref, Borrow, AsRef

impl<'a> Deref for CStringRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'a> Borrow<[u8]> for CStringRef<'a> {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl<'a> AsRef<[u8]> for CStringRef<'a> {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}


//--- PartialEq, Eq

impl<'a, T: AsRef<[u8]>> PartialEq<T> for CStringRef<'a> {
    fn eq(&self, other: &T) -> bool {
        self.deref().eq(other.as_ref())
    }
}

impl<'a> Eq for CStringRef<'a> { }


//--- PartialOrd, Ord

impl<'a, T: AsRef<[u8]>> PartialOrd<T> for CStringRef<'a> {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other.as_ref())
    }
}

impl<'a> Ord for CStringRef<'a> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}


//--- Hash

impl<'a> hash::Hash for CStringRef<'a> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


//--- Display

impl<'a> fmt::Display for CStringRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.inner.iter() {
            if ch == b' ' || ch == b'\\' {
                try!(write!(f, "\\{}", ch as char));
            }
            else if ch < b' ' || ch >= 0x7F {
                try!(write!(f, "\\{:03}", ch));
            }
            else {
                try!((ch as char).fmt(f));
            }
        }
        Ok(())
    }
}


//------------ OwnedCString -------------------------------------------------

#[derive(Clone, Debug)]
pub struct OwnedCString {
    inner: Vec<u8>
}


impl OwnedCString {
    unsafe fn from_bytes(bytes: &[u8]) -> Self {
        OwnedCString { inner: Vec::from(bytes) }
    }

    pub fn new() -> Self {
        OwnedCString { inner: Vec::new() }
    }

    pub fn from_str(s: &str) -> FromStrResult<Self> {
        let mut res = OwnedCString::new();
        let mut chars = s.chars();
        loop {
            match chars.next() {
                Some(c) => {
                    match c {
                        '\\' => res.push(try!(parse_escape(&mut chars))),
                        ' ' ... '[' | ']' ... '~' => {
                            res.push(c as u8);
                        }
                        _ => return Err(FromStrError::IllegalCharacter)
                    }
                }
                None => break
            }
        }
        if res.len() > 255 { Err(FromStrError::LongString) }
        else { Ok(res) }
    }

    pub fn parse<'a, P: ParseBytes<'a>>(parser: &mut P)
                                        -> ParseResult<Self> {
        Ok(try!(CStringRef::parse(parser)).to_owned())
    }

    pub fn as_slice(&self) -> &[u8] {
        self
    }
}


/// # Manipulations.
///
impl OwnedCString {
    pub fn push(&mut self, ch: u8) {
        self.inner.push(ch)
    }
}


//--- CString

impl CString for OwnedCString {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        assert!(self.inner.len() < 256);
        try!(target.push_u8(self.inner.len() as u8));
        try!(target.push_bytes(&self.inner));
        Ok(())
    }
}


//--- FromStr

// XXX TODO


//--- Deref, Borrow, AsRef

impl Deref for OwnedCString {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl Borrow<[u8]> for OwnedCString {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl AsRef<[u8]> for OwnedCString {
    fn as_ref(&self) -> &[u8] {
        self
    }
}


//--- PartialEq and Eq

impl<T: AsRef<[u8]>> PartialEq<T> for OwnedCString {
    fn eq(&self, other: &T) -> bool {
        self.deref().eq(other.as_ref())
    }
}

impl Eq for OwnedCString { }


//--- PartialOrd and Ord

impl<T: AsRef<[u8]>> PartialOrd<T> for OwnedCString {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other.as_ref())
    }
}

impl Ord for OwnedCString {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}


//--- Hash

impl hash::Hash for OwnedCString {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


//--- Display

impl fmt::Display for OwnedCString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe { CStringRef::from_bytes(&self.inner) }.fmt(f)
    }
}


//------------ Internal Helpers ---------------------------------------------

fn parse_escape(chars: &mut str::Chars) -> FromStrResult<u8> {
    let ch = try!(chars.next().ok_or(FromStrError::UnexpectedEnd));
    if ch == '0' || ch == '1' || ch == '2' {
        let v = ch.to_digit(10).unwrap() * 100
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)))
                     * 10
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)));
        Ok(v as u8)
    }
    else { Ok(ch as u8) }
}
