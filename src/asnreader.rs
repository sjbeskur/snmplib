use std::fmt;
use std::mem;
use std::ptr;

use super::{ SnmpError, SnmpResult, USIZE_LEN, decode_i64, asn1, snmp };
use super::objectidentifier::*;
use super::value::*;

/// ASN.1/DER decoder iterator.
///
/// Supports:
///
/// - types required by SNMP.
///
/// Does not support:
///
/// - extended tag IDs.
/// - indefinite lengths (disallowed by DER).
/// - INTEGER values not representable by i64.
pub struct AsnReader<'a> {
    inner: &'a [u8],
}

impl<'a> Clone for AsnReader<'a> {
    fn clone(&self) -> AsnReader<'a> {
        AsnReader {
            inner: self.inner,
        }
    }
}

impl<'a> fmt::Debug for AsnReader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a> AsnReader<'a> {

    pub fn from_bytes(bytes: &[u8]) -> AsnReader {
        AsnReader {inner: bytes}
    }

    pub fn peek_byte(&mut self) -> SnmpResult<u8> {
        if self.inner.is_empty() {
            Err(SnmpError::AsnEof)
        } else {
            Ok(self.inner[0])
        }
    }

    pub fn read_byte(&mut self) -> SnmpResult<u8> {
        match self.inner.split_first() {
            Some((head, tail)) => {
                self.inner = tail;
                Ok(*head)
            }
            _ => Err(SnmpError::AsnEof)
        }
    }

    pub fn read_length(&mut self) -> SnmpResult<usize> {
        if let Some((head, tail)) = self.inner.split_first() {
            let o: usize;
            if head < &128 {
                // short form
                o = *head as usize;
                self.inner = tail;
                Ok(o)
            } else if head == &0xff {
                Err(SnmpError::AsnInvalidLen) // reserved for future use
            } else {
                // long form
                let length_len = (*head & 0b01111111) as usize;
                if length_len == 0 {
                    // Indefinite length. Not allowed in DER.
                    return Err(SnmpError::AsnInvalidLen);
                }

                let mut bytes = [0u8; USIZE_LEN];
                bytes[(USIZE_LEN - length_len)..]
                    .copy_from_slice(&tail[..length_len]);

                o = unsafe { mem::transmute::<[u8; USIZE_LEN], usize>(bytes).to_be()};
                self.inner = &tail[length_len as usize..];
                Ok(o)
            }
        } else {
            Err(SnmpError::AsnEof)
        }
    }

    pub fn read_i64_type(&mut self, expected_ident: u8) -> SnmpResult<i64> {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (val, remaining) = self.inner.split_at(val_len);
        self.inner = remaining;
        decode_i64(val)
    }

    pub fn read_raw(&mut self, expected_ident: u8) -> SnmpResult<&'a [u8]> {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (val, remaining) = self.inner.split_at(val_len);
        self.inner = remaining;
        Ok(val)
    }

    pub fn read_constructed<F>(&mut self, expected_ident: u8, f: F) -> SnmpResult<()>
        where F: Fn(&mut AsnReader) -> SnmpResult<()>
    {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let seq_len = self.read_length()?;
        if seq_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (seq_bytes, remaining) = self.inner.split_at(seq_len);
        let mut reader = AsnReader::from_bytes(seq_bytes);
        self.inner = remaining;
        f(&mut reader)
    }

    //
    // ASN
    //

    pub fn read_asn_boolean(&mut self) -> SnmpResult<bool> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_NULL {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len != 1 {
            return Err(SnmpError::AsnInvalidLen);
        }
        match self.read_byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SnmpError::AsnParseError), // DER mandates 1/0 for booleans
        }
    }

    pub fn read_asn_integer(&mut self) -> SnmpResult<i64> {
        self.read_i64_type(asn1::TYPE_INTEGER)
    }

    pub fn read_asn_octetstring(&mut self) -> SnmpResult<&'a [u8]> {
        self.read_raw(asn1::TYPE_OCTETSTRING)
    }

    pub fn read_asn_null(&mut self) -> SnmpResult<()> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_NULL {
            return Err(SnmpError::AsnWrongType);
        }
        let null_len = self.read_length()?;
        if null_len != 0 {
            Err(SnmpError::AsnInvalidLen)
        } else {
            Ok(())
        }
    }

    pub fn read_asn_objectidentifier(&mut self) -> SnmpResult<ObjectIdentifier<'a>> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_OBJECTIDENTIFIER {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (input, remaining) = self.inner.split_at(val_len);
        self.inner = remaining;

        Ok(ObjectIdentifier::from_bytes(input))
    }

    pub fn read_asn_sequence<F>(&mut self, f: F) -> SnmpResult<()>
        where F: Fn(&mut AsnReader) -> SnmpResult<()>
    {
        self.read_constructed(asn1::TYPE_SEQUENCE, f)
    }

    // fn read_asn_set<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(asn1::TYPE_SET, f)
    // }

    //
    // SNMP
    //

    pub fn read_snmp_counter32(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_COUNTER32).map(|v| v as u32)
    }

    pub fn read_snmp_unsigned32(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_UNSIGNED32).map(|v| v as u32)
    }

    pub fn read_snmp_timeticks(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_TIMETICKS).map(|v| v as u32)
    }

    pub fn read_snmp_counter64(&mut self) -> SnmpResult<u64> {
        self.read_i64_type(snmp::TYPE_COUNTER64).map(|v| v as u64)
    }

    pub fn read_snmp_opaque(&mut self) -> SnmpResult<&'a [u8]> {
        self.read_raw(snmp::TYPE_OPAQUE)
    }

    pub fn read_snmp_ipaddress(&mut self) -> SnmpResult<[u8; 4]> {
        //let mut ip = [0u8; 4];
        let val = self.read_raw(snmp::TYPE_IPADDRESS)?;
        if val.len() != 4 {
            return Err(SnmpError::AsnInvalidLen);
        }
        //&mut ip[..].copy_from_slice(val);
        //Ok(ip)
        unsafe { Ok(ptr::read(val.as_ptr() as *const _)) }
    }

    // fn read_snmp_get<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_GET, f)
    // }

    // fn read_snmp_getnext<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_GET_NEXT, f)
    // }

    // fn read_snmp_getbulk<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_GET_BULK, f)
    // }

    // fn read_snmp_response<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_RESPONSE, f)
    // }

    // fn read_snmp_inform<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_INFORM, f)
    // }

    // fn read_snmp_report<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_REPORT, f)
    // }

    // fn read_snmp_set<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_SET, f)
    // }

    // fn read_snmp_trap<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_TRAP, f)
    // }

}



impl<'a> Iterator for AsnReader<'a> {
    type Item = Value<'a>;

    fn next(&mut self) -> Option<Value<'a>> {
        use Value::*;
        if let Ok(ident) = self.peek_byte() {
            let ret: SnmpResult<Value> = match ident {
                asn1::TYPE_BOOLEAN          => self.read_asn_boolean().map(Boolean),
                asn1::TYPE_NULL             => self.read_asn_null().map(|_| Null),
                asn1::TYPE_INTEGER          => self.read_asn_integer().map(Integer),
                asn1::TYPE_OCTETSTRING      => self.read_asn_octetstring().map(OctetString),
                asn1::TYPE_OBJECTIDENTIFIER => self.read_asn_objectidentifier().map(ObjectIdentifier),
                asn1::TYPE_SEQUENCE         => self.read_raw(ident).map(|v| Sequence(AsnReader::from_bytes(v))),
                asn1::TYPE_SET              => self.read_raw(ident).map(|v| Set(AsnReader::from_bytes(v))),
                snmp::TYPE_IPADDRESS        => self.read_snmp_ipaddress().map(IpAddress),
                snmp::TYPE_COUNTER32        => self.read_snmp_counter32().map(Counter32),
                snmp::TYPE_UNSIGNED32       => self.read_snmp_unsigned32().map(Unsigned32),
                snmp::TYPE_TIMETICKS        => self.read_snmp_timeticks().map(Timeticks),
                snmp::TYPE_OPAQUE           => self.read_snmp_opaque().map(Opaque),
                snmp::TYPE_COUNTER64        => self.read_snmp_counter64().map(Counter64),
                snmp::MSG_GET               => self.read_raw(ident).map(|v| SnmpGetRequest(AsnReader::from_bytes(v))),
                snmp::MSG_GET_NEXT          => self.read_raw(ident).map(|v| SnmpGetNextRequest(AsnReader::from_bytes(v))),
                snmp::MSG_GET_BULK          => self.read_raw(ident).map(|v| SnmpGetBulkRequest(AsnReader::from_bytes(v))),
                snmp::MSG_RESPONSE          => self.read_raw(ident).map(|v| SnmpResponse(AsnReader::from_bytes(v))),
                snmp::MSG_SET               => self.read_raw(ident).map(|v| SnmpSetRequest(AsnReader::from_bytes(v))),
                snmp::MSG_INFORM            => self.read_raw(ident).map(|v| SnmpInformRequest(AsnReader::from_bytes(v))),
                snmp::MSG_TRAP              => self.read_raw(ident).map(|v| SnmpTrap(AsnReader::from_bytes(v))),
                snmp::MSG_REPORT            => self.read_raw(ident).map(|v| SnmpReport(AsnReader::from_bytes(v))),
                ident if ident & asn1::CONSTRUCTED == asn1::CONSTRUCTED =>
                                              self.read_raw(ident).map(|v| Constructed(ident, AsnReader::from_bytes(v))),
                _ =>                          Err(SnmpError::AsnUnsupportedType),
            };
            ret.ok()
        } else {
            None
        }
    }
}