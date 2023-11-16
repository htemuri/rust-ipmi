// use crate::ipmi::data::data::Data;

use std::fmt::Debug;

use crate::ipmi::data::data::Data;

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct GetChannelAuthCapabilitiesRequest {
    pub channel_version: bool,
    pub channel_number: u8,
    pub max_privilege: Privilege,
}

impl GetChannelAuthCapabilitiesRequest {
    pub fn from_slice(_slice: &[u8]) -> GetChannelAuthCapabilitiesRequest {
        // todo: add error checking
        GetChannelAuthCapabilitiesRequest {
            channel_version: true,
            channel_number: 0x01,
            max_privilege: Privilege::User,
        }
    }
}

impl Data for GetChannelAuthCapabilitiesRequest {}

pub struct GetChannelAuthCapabilitiesResponse {}
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum Privilege {
    Reserved,
    Callback,
    User,
    Operator,
    Administrator,
    Oem,
    Unknown(u8),
}

impl Privilege {
    pub fn from_u8(privilege: u8) -> Privilege {
        match privilege {
            0x00 => Privilege::Reserved,
            0x01 => Privilege::Callback,
            0x02 => Privilege::User,
            0x03 => Privilege::Operator,
            0x04 => Privilege::Administrator,
            0x05 => Privilege::Oem,
            _ => Privilege::Unknown(privilege),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            Privilege::Reserved => 0x00,
            Privilege::Callback => 0x01,
            Privilege::User => 0x02,
            Privilege::Operator => 0x03,
            Privilege::Administrator => 0x04,
            Privilege::Oem => 0x05,
            Privilege::Unknown(privilege) => *privilege,
        }
    }
}
