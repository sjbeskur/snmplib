#![allow(dead_code)] //, identity_op, eq_op)]

use super::asn1;
use super::varbinds::*;
use super::asnreader::AsnReader;
use super::{ SnmpResult, SnmpError} ;

pub const VERSION_2:    i64 = 1;

pub const MSG_GET:      u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 0;
pub const MSG_GET_NEXT: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 1;
pub const MSG_RESPONSE: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 2;
pub const MSG_SET:      u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 3;
pub const MSG_GET_BULK: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 5;
pub const MSG_INFORM:   u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 6;
pub const MSG_TRAP:     u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 7;
pub const MSG_REPORT:   u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 8;

pub const TYPE_IPADDRESS:  u8 = asn1::CLASS_APPLICATION | 0;
pub const TYPE_COUNTER32:  u8 = asn1::CLASS_APPLICATION | 1;
pub const TYPE_UNSIGNED32: u8 = asn1::CLASS_APPLICATION | 2;
pub const TYPE_GAUGE32:    u8 = TYPE_UNSIGNED32;
pub const TYPE_TIMETICKS:  u8 = asn1::CLASS_APPLICATION | 3;
pub const TYPE_OPAQUE:     u8 = asn1::CLASS_APPLICATION | 4;
pub const TYPE_COUNTER64:  u8 = asn1::CLASS_APPLICATION | 6;

pub const SNMP_NOSUCHOBJECT:   u8 = (asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x0); /* 80=128 */
pub const SNMP_NOSUCHINSTANCE: u8 = (asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x1); /* 81=129 */
pub const SNMP_ENDOFMIBVIEW:   u8 = (asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x2); /* 82=130 */

pub const ERRSTATUS_NOERROR:             u32 =  0;
pub const ERRSTATUS_TOOBIG:              u32 =  1;
pub const ERRSTATUS_NOSUCHNAME:          u32 =  2;
pub const ERRSTATUS_BADVALUE:            u32 =  3;
pub const ERRSTATUS_READONLY:            u32 =  4;
pub const ERRSTATUS_GENERR:              u32 =  5;
pub const ERRSTATUS_NOACCESS:            u32 =  6;
pub const ERRSTATUS_WRONGTYPE:           u32 =  7;
pub const ERRSTATUS_WRONGLENGTH:         u32 =  8;
pub const ERRSTATUS_WRONGENCODING:       u32 =  9;
pub const ERRSTATUS_WRONGVALUE:          u32 = 10;
pub const ERRSTATUS_NOCREATION:          u32 = 11;
pub const ERRSTATUS_INCONSISTENTVALUE:   u32 = 12;
pub const ERRSTATUS_RESOURCEUNAVAILABLE: u32 = 13;
pub const ERRSTATUS_COMMITFAILED:        u32 = 14;
pub const ERRSTATUS_UNDOFAILED:          u32 = 15;
pub const ERRSTATUS_AUTHORIZATIONERROR:  u32 = 16;
pub const ERRSTATUS_NOTWRITABLE:         u32 = 17;
pub const ERRSTATUS_INCONSISTENTNAME:    u32 = 18;



#[derive(Debug, PartialEq)]
pub enum SnmpMessageType {
    GetRequest,
    GetNextRequest,
    GetBulkRequest,
    Response,
    SetRequest,
    InformRequest,
    Trap,
    Report,
}

impl SnmpMessageType {
    pub fn from_ident(ident: u8) -> SnmpResult<SnmpMessageType> {
        use SnmpMessageType::*;
        Ok(
            match ident {
                MSG_GET      => GetRequest,
                MSG_GET_NEXT => GetNextRequest,
                MSG_GET_BULK => GetBulkRequest,
                MSG_RESPONSE => Response,
                MSG_SET      => SetRequest,
                MSG_INFORM   => InformRequest,
                MSG_TRAP     => Trap,
                MSG_REPORT   => Report,
                _ => return Err(SnmpError::AsnWrongType),
            }
        )
    }
}

#[derive(Debug)]
pub struct SnmpPdu<'a> {
    version: i64,
    pub community: &'a [u8],
    pub message_type: SnmpMessageType,
    pub req_id: i32,
    pub error_status: u32,
    pub error_index: u32,
    pub varbinds: Varbinds<'a>,
}

impl<'a> SnmpPdu<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> SnmpResult<SnmpPdu<'a>> {
        let seq = AsnReader::from_bytes(bytes).read_raw(asn1::TYPE_SEQUENCE)?;
        let mut rdr = AsnReader::from_bytes(seq);
        let version = rdr.read_asn_integer()?;
        if version != VERSION_2 {
            return Err(SnmpError::UnsupportedVersion);
        }
        let community = rdr.read_asn_octetstring()?;
        let ident = rdr.peek_byte()?;
        let message_type = SnmpMessageType::from_ident(ident)?;

        let mut response_pdu = AsnReader::from_bytes(rdr.read_raw(ident)?);

        let req_id = response_pdu.read_asn_integer()?;
        if req_id < i32::min_value() as i64 || req_id > i32::max_value() as i64 {
            return Err(SnmpError::ValueOutOfRange);
        }

        let error_status = response_pdu.read_asn_integer()?;
        if error_status < 0 || error_status > i32::max_value() as i64 {
            return Err(SnmpError::ValueOutOfRange);
        }

        let error_index = response_pdu.read_asn_integer()?;
        if error_index < 0 || error_index > i32::max_value() as i64 {
            return Err(SnmpError::ValueOutOfRange);
        }

        let varbind_bytes = response_pdu.read_raw(asn1::TYPE_SEQUENCE)?;
        let varbinds = Varbinds::from_bytes(varbind_bytes);

        Ok(
            SnmpPdu {
                version: version,
                community: community,
                message_type: message_type,
                req_id: req_id as i32,
                error_status: error_status as u32,
                error_index: error_index as u32,
                varbinds: varbinds,
            }
        )
    }
}