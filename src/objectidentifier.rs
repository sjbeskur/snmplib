
use std::fmt;
use std::mem;
use super::{SnmpResult, SnmpError};

/// Wrapper around raw bytes representing an ASN.1 OBJECT IDENTIFIER.
#[derive(PartialEq)]
pub struct ObjectIdentifier<'a> {
    inner: &'a [u8],
}

impl<'a> fmt::Debug for ObjectIdentifier<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.inner).finish()
    }
}

pub type ObjIdBuf = [u32; 128];

impl<'a> fmt::Display for ObjectIdentifier<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf: ObjIdBuf = unsafe { mem::uninitialized() };
        let mut first = true;
        match self.read_name(&mut buf) {
            Ok(name) => {
                for subid in name {
                    if first {
                        first = false;
                        f.write_fmt(format_args!("{}", subid))?;
                    } else {
                        f.write_fmt(format_args!(".{}", subid))?;
                    }
                }
                Ok(())
            }
            Err(err) => f.write_fmt(format_args!("Invalid OID: {:?}", err))
        }
    }
}

impl<'a> PartialEq<[u32]> for ObjectIdentifier<'a> {
    fn eq(&self, other: &[u32]) -> bool {
        let mut buf: ObjIdBuf = unsafe { mem::uninitialized() };
        if let Ok(name) = self.read_name(&mut buf) {
            name == other
        } else {
            false
        }
    }
}

impl<'a, 'b> PartialEq<&'b [u32]> for ObjectIdentifier<'a> {
    fn eq(&self, other: &&[u32]) -> bool {
        self == *other
    }
}

impl<'a> ObjectIdentifier<'a> {
    pub fn from_bytes(bytes: &[u8]) -> ObjectIdentifier {
        ObjectIdentifier {
            inner: bytes,
        }
    }

    /// Reads out the OBJECT IDENTIFIER sub-IDs as a slice of u32s.
    /// Caller must provide storage for 128 sub-IDs.
    pub fn read_name<'b>(&self, out: &'b mut ObjIdBuf) -> SnmpResult<&'b [u32]> {
        let input = self.inner;
        let output = &mut out[..];
        if input.len() < 2 {
            return Err(SnmpError::AsnInvalidLen);
        }
        let subid1 = (input[0] / 40) as u32;
        let subid2 = (input[0] % 40) as u32;
        output[0] = subid1;
        output[1] = subid2;
        let mut pos = 2;
        let mut cur_oid: u32 = 0;
        let mut is_done = false;
        for b in &input[1..] {
            if pos == output.len() {
                return Err(SnmpError::AsnEof);
            }
            is_done = b & 0b10000000 == 0;
            let val = b & 0b01111111;
            cur_oid = cur_oid.checked_shl(7).ok_or(SnmpError::AsnIntOverflow)?;
            cur_oid |= val as u32;
            if is_done {
                output[pos] = cur_oid;
                pos += 1;
                cur_oid = 0;
            }
        }
        if !is_done {
            Err(SnmpError::AsnParseError)
        } else {
            Ok(&output[..pos])
        }
    }

    pub fn raw(&self) -> &'a [u8] {
        self.inner
    }
}