// use crate::{
//     err::{ValueTooBigError, ValueType},
//     *,
// };

use bitvec::{field::BitField, prelude::Msb0, slice::BitSlice};

use super::rcmp_header::{MessageClass, RmcpHeader};

pub struct RmcpHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> RmcpHeaderSlice<'a> {
    // creates a slice containing an rmcp header
    pub fn from_slice(slice: &'a [u8]) -> RmcpHeaderSlice<'a> {
        // todo: implement error checking

        RmcpHeaderSlice::<'a> {
            slice: unsafe { core::slice::from_raw_parts(slice.as_ptr(), 4) },
        }
    }

    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    pub fn version(&self) -> u8 {
        // must add error checking in constructor (check if len >= 4 bytes)
        unsafe { u8::from_be_bytes([*self.slice.as_ptr()]) }
    }

    pub fn reserved(&self) -> u8 {
        // must add error checking in constructor (check if len >= 4 bytes)
        unsafe { u8::from_be_bytes([*self.slice.as_ptr().add(1)]) }
    }

    pub fn sequence_number(&self) -> u8 {
        // must add error checking in constructor (check if len >= 4 bytes)
        unsafe { u8::from_be_bytes([*self.slice.as_ptr().add(2)]) }
    }

    pub fn ack(&self) -> bool {
        let message_class: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[3]);
        message_class[0]
    }

    pub fn message_class(&self) -> u8 {
        let message_class: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[3]);
        message_class[4..].load::<u8>()
    }

    pub fn to_header(&self) -> RmcpHeader {
        RmcpHeader {
            version: self.version(),
            reserved: self.reserved(),
            sequence_number: self.sequence_number(),
            rmcp_ack: self.ack(),
            message_class: MessageClass::from_u8(self.message_class()),
        }
    }
}
