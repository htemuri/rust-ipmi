use bitvec::prelude::*;

use crate::err::RMCPError;

use bitvec::{field::BitField, prelude::Msb0, slice::BitSlice};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RmcpHeader {
    pub version: u8,         // 0x06 for RMCP Version 1.0
    pub reserved: u8,        // 0x00
    pub sequence_number: u8, // 255 if no RMCP ACK; 0-254 if RMCP ACK desired
    pub rmcp_ack: bool,
    pub message_class: MessageClass,
}

impl TryFrom<&[u8]> for RmcpHeader {
    type Error = RMCPError;

    fn try_from(value: &[u8]) -> Result<Self, RMCPError> {
        if value.len() != 4 {
            Err(RMCPError::WrongLength)?
        }

        let third_byte_slice = BitSlice::<u8, Msb0>::from_element(&value[3]);

        Ok(RmcpHeader {
            version: value[0],
            reserved: value[1],
            sequence_number: value[2],
            rmcp_ack: third_byte_slice[0],
            message_class: third_byte_slice[4..].load::<u8>().try_into()?,
        })
    }
}

impl Into<Vec<u8>> for RmcpHeader {
    fn into(self) -> Vec<u8> {
        let result = [self.version, self.reserved, self.sequence_number, {
            let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
            bv[0..1].store::<u8>(self.rmcp_ack as u8);
            bv[4..].store::<u8>(self.message_class.into());
            let message_class = bv[..].load::<u8>();
            message_class
        }];
        let mut vec_result = Vec::new();
        vec_result.extend_from_slice(result.as_slice());
        vec_result
    }
}

impl RmcpHeader {
    pub fn new(version: u8, sequence_number: u8, message_class: MessageClass) -> RmcpHeader {
        RmcpHeader {
            version,
            reserved: 0x00,
            sequence_number,
            rmcp_ack: false,
            message_class,
        }
    }
}

impl Default for RmcpHeader {
    fn default() -> RmcpHeader {
        RmcpHeader {
            version: 0x06,
            reserved: 0,
            sequence_number: 0xff,
            rmcp_ack: false,
            message_class: MessageClass::IPMI,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MessageClass {
    ASF,
    IPMI,
    OEM,
}

impl TryFrom<u8> for MessageClass {
    type Error = RMCPError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x6 => Ok(MessageClass::ASF),
            0x7 => Ok(MessageClass::IPMI),
            0x8 => Ok(MessageClass::OEM),
            _ => Err(RMCPError::UnsupportedMessageClass(value)),
        }
    }
}

impl Into<u8> for MessageClass {
    fn into(self) -> u8 {
        match self {
            MessageClass::ASF => 6,
            MessageClass::IPMI => 7,
            MessageClass::OEM => 8,
        }
    }
}
