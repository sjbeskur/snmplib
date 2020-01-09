use std::mem;

pub mod asn1;
mod snmp;
mod pdu;
mod value;
mod asnreader;
mod objectidentifier;
pub mod varbinds;
mod sync;
pub use sync::SyncSession;


const BUFFER_SIZE: usize = 4096;

#[cfg(target_pointer_width="32")]
const USIZE_LEN: usize = 4;
#[cfg(target_pointer_width="64")]
const USIZE_LEN: usize = 8;


#[derive(Debug, PartialEq)]
pub enum SnmpError {
    AsnParseError,
    AsnInvalidLen,
    AsnWrongType,
    AsnUnsupportedType,
    AsnEof,
    AsnIntOverflow,

    UnsupportedVersion,
    RequestIdMismatch,
    CommunityMismatch,
    ValueOutOfRange,

    SendError,
    ReceiveError,
}

type SnmpResult<T> = Result<T, SnmpError>;


fn decode_i64(i: &[u8]) -> SnmpResult<i64> {
    if i.len() > mem::size_of::<i64>() {
        return Err(SnmpError::AsnIntOverflow);
    }
    let mut bytes = [0u8; 8];
    bytes[(mem::size_of::<i64>() - i.len())..].copy_from_slice(i);

    let mut ret = unsafe { mem::transmute::<[u8; 8], i64>(bytes).to_be()};
    {
        //sign extend
        let shift_amount = (mem::size_of::<i64>() - i.len()) * 8;
        ret = (ret << shift_amount) >> shift_amount;
    }
    Ok(ret)
}




