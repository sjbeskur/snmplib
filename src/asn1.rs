#![allow(dead_code)] // TODO: , identity_op, eq_op)]

pub const PRIMITIVE:             u8 = 0b00000000;
pub const CONSTRUCTED:           u8 = 0b00100000;

pub const CLASS_UNIVERSAL:       u8 = 0b00000000;
pub const CLASS_APPLICATION:     u8 = 0b01000000;
pub const CLASS_CONTEXTSPECIFIC: u8 = 0b10000000;
pub const CLASS_PRIVATE:         u8 = 0b11000000;

pub const TYPE_BOOLEAN:          u8 = CLASS_UNIVERSAL | PRIMITIVE   |  1;
pub const TYPE_INTEGER:          u8 = CLASS_UNIVERSAL | PRIMITIVE   |  2;
pub const TYPE_OCTETSTRING:      u8 = CLASS_UNIVERSAL | PRIMITIVE   |  4;
pub const TYPE_NULL:             u8 = CLASS_UNIVERSAL | PRIMITIVE   |  5;
pub const TYPE_OBJECTIDENTIFIER: u8 = CLASS_UNIVERSAL | PRIMITIVE   |  6;
pub const TYPE_SEQUENCE:         u8 = CLASS_UNIVERSAL | CONSTRUCTED | 16;
pub const TYPE_SET:              u8 = CLASS_UNIVERSAL | CONSTRUCTED | 17;
