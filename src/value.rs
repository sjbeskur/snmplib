use std::fmt;

use super::asnreader::AsnReader;
use super::objectidentifier::*;

pub enum Value<'a> {
    Boolean(bool),
    Null,
    Integer(i64),
    OctetString(&'a [u8]),
    ObjectIdentifier(ObjectIdentifier<'a>),
    Sequence(AsnReader<'a>),
    Set(AsnReader<'a>),
    Constructed(u8, AsnReader<'a>),

    IpAddress([u8;4]),
    Counter32(u32),
    Unsigned32(u32),
    Timeticks(u32),
    Opaque(&'a [u8]),
    Counter64(u64),

    EndOfMibView,
    NoSuchObject,
    NoSuchInstance,

    SnmpGetRequest(AsnReader<'a>),
    SnmpGetNextRequest(AsnReader<'a>),
    SnmpGetBulkRequest(AsnReader<'a>),
    SnmpResponse(AsnReader<'a>),
    SnmpSetRequest(AsnReader<'a>),
    SnmpInformRequest(AsnReader<'a>),
    SnmpTrap(AsnReader<'a>),
    SnmpReport(AsnReader<'a>),
}

impl<'a> fmt::Debug for Value<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Value::*;
        match *self {
            Boolean(v)                   => write!(f, "BOOLEAN: {}", v),
            Integer(n)                   => write!(f, "INTEGER: {}", n),
            OctetString(slice)           => write!(f, "OCTET STRING: {}", String::from_utf8_lossy(slice)),
            ObjectIdentifier(ref obj_id) => write!(f, "OBJECT IDENTIFIER: {}", obj_id),
            Null                         => write!(f, "NULL"),
            Sequence(ref val)            => write!(f, "SEQUENCE: {:#?}", val),
            Set(ref val)                 => write!(f, "SET: {:?}", val),
            Constructed(ident, ref val)  => write!(f, "CONSTRUCTED-{}: {:#?}", ident, val),

            IpAddress(val)               => write!(f, "IP ADDRESS: {}.{}.{}.{}", val[0], val[1], val[2], val[3]),
            Counter32(val)               => write!(f, "COUNTER32: {}", val),
            Unsigned32(val)              => write!(f, "UNSIGNED32: {}", val),
            Timeticks(val)               => write!(f, "TIMETICKS: {}", val),
            Opaque(val)                  => write!(f, "OPAQUE: {:?}", val),
            Counter64(val)               => write!(f, "COUNTER64: {}", val),

            EndOfMibView                 => write!(f, "END OF MIB VIEW"),
            NoSuchObject                 => write!(f, "NO SUCH OBJECT"),
            NoSuchInstance               => write!(f, "NO SUCH INSTANCE"),

            SnmpGetRequest(ref val)      => write!(f, "SNMP GET REQUEST: {:#?}", val),
            SnmpGetNextRequest(ref val)  => write!(f, "SNMP GET NEXT REQUEST: {:#?}", val),
            SnmpGetBulkRequest(ref val)  => write!(f, "SNMP GET BULK REQUEST: {:#?}", val),
            SnmpResponse(ref val)        => write!(f, "SNMP RESPONSE: {:#?}", val),
            SnmpSetRequest(ref val)      => write!(f, "SNMP SET REQUEST: {:#?}", val),
            SnmpInformRequest(ref val)   => write!(f, "SNMP INFORM REQUEST: {:#?}", val),
            SnmpTrap(ref val)            => write!(f, "SNMP TRAP: {:#?}", val),
            SnmpReport(ref val)          => write!(f, "SNMP REPORT: {:#?}", val),
        }
    }
}
