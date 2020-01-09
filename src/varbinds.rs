use std::fmt;

use super::asnreader::*;
use super::objectidentifier::*;
use super::value::*;
use super::asn1;

#[derive(Clone)]
pub struct Varbinds<'a> {
    inner:  AsnReader<'a>,
}

impl<'a> fmt::Debug for Varbinds<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // f.debug_list().entries(self.clone()).finish()
        let mut ds = f.debug_struct("Varbinds");
        for (name, val) in self.clone() {
            ds.field(&format!("{}", name), &format!("{:?}", val));
        }
        ds.finish()
    }
}

impl<'a> Varbinds<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Varbinds<'a> {
        Varbinds {
            inner: AsnReader::from_bytes(bytes)
        }
    }
}

impl<'a> Iterator for Varbinds<'a> {
    type Item = (ObjectIdentifier<'a>, Value<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(seq) = self.inner.read_raw(asn1::TYPE_SEQUENCE) {
            let mut pair = AsnReader::from_bytes(seq);
            if let (Ok(name), Some(value)) = (pair.read_asn_objectidentifier(), pair.next()) {
                return Some((name, value));
            }
        }
        None
    }
}
