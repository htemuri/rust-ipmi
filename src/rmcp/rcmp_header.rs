use bitvec::prelude::*;

use super::rmcp_header_slice::RmcpHeaderSlice;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RmcpHeader {
    pub version: u8,         // 0x06 for RMCP Version 1.0
    pub reserved: u8,        // 0x00
    pub sequence_number: u8, // 255 if no RMCP ACK; 0-254 if RMCP ACK desired
    pub rmcp_ack: bool,
    pub message_class: MessageClass,
}

impl RmcpHeader {
    pub const MIN_LEN: usize = 4;

    pub const MAX_LEN: usize = 4;

    pub fn new(version: u8, sequence_number: u8, message_class: MessageClass) -> RmcpHeader {
        RmcpHeader {
            version,
            reserved: 0x00,
            sequence_number,
            rmcp_ack: false,
            message_class,
        }
    }

    pub fn from_slice(slice: &[u8]) -> RmcpHeader {
        let h = RmcpHeaderSlice::from_slice(slice);
        h.to_header()
    }

    pub fn to_bytes(&self) -> [u8; RmcpHeader::MAX_LEN] {
        let result = [self.version, self.reserved, self.sequence_number, {
            let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
            bv[0..1].store::<u8>(self.rmcp_ack as u8);
            bv[4..].store::<u8>(self.message_class.to_u8());
            let message_class = bv[..].load::<u8>();
            message_class
        }];
        result
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
    None,
}

impl MessageClass {
    pub fn from_u8(message_class: u8) -> MessageClass {
        match message_class {
            0x6 => MessageClass::ASF,
            0x7 => MessageClass::IPMI,
            0x8 => MessageClass::OEM,
            _ => MessageClass::None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match &self {
            MessageClass::ASF => 6,
            MessageClass::IPMI => 7,
            MessageClass::OEM => 8,
            MessageClass::None => 0,
        }
    }
}
