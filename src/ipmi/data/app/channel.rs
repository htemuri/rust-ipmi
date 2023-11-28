// use crate::ipmi::data::data::Data;

use std::fmt::Debug;

use bitvec::prelude::*;

use crate::{
    connection::Connection,
    ipmi::{
        data::{self, commands::Command},
        ipmi_header::{AuthType, IpmiHeader},
        ipmi_v1_header::IpmiV1Header,
        payload::{
            ipmi_payload::{IpmiPayload, NetFn},
            ipmi_payload_request::IpmiPayloadRequest,
        },
    },
    packet::packet::Packet,
};

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct GetChannelAuthCapabilitiesRequest {
    pub channel_version: bool,
    pub channel_number: u8,
    pub max_privilege: Privilege,
}

impl GetChannelAuthCapabilitiesRequest {
    pub fn new(
        channel_version: bool,
        max_privilege: Privilege,
    ) -> GetChannelAuthCapabilitiesRequest {
        GetChannelAuthCapabilitiesRequest {
            channel_version,
            channel_number: 0xE,
            max_privilege,
        }
    }

    pub fn from_slice(_slice: &[u8]) -> GetChannelAuthCapabilitiesRequest {
        // todo: add error checking
        GetChannelAuthCapabilitiesRequest {
            channel_version: true,
            channel_number: 0x01,
            max_privilege: Privilege::User,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push({
            let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
            *bv.get_mut(0).unwrap() = self.channel_version;
            bv[4..].store::<u8>(self.channel_number);
            println!("{:?}", bv);
            let channel_number = bv[..].load::<u8>();
            channel_number
        });
        result.push(self.max_privilege.to_u8());
        result
    }

    pub fn create_packet(
        &self,
        con: &Connection,
        session_seq_number: u32,
        session_id: u32,
        auth_code: Option<u128>,
    ) -> Packet {
        let data_bytes = self.to_bytes();
        println!("{:x?}", data_bytes);
        let packet = Packet::new(
            IpmiHeader::V1_5(IpmiV1Header {
                auth_type: con.auth_type,
                session_seq_number,
                session_id,
                auth_code,
                payload_length: (data_bytes.len() as u8) + 7,
            }),
            IpmiPayload::Request(IpmiPayloadRequest::new(
                NetFn::App,
                Command::GetChannelAuthCapabilities,
                data_bytes,
            )),
        );
        packet
    }
}

pub struct GetChannelAuthCapabilitiesResponse {
    pub channel_number: u8,
    pub auth_version: AuthVersion,
    pub auth_type: [AuthType],
}

pub enum AuthVersion {
    IpmiV2,
    IpmiV1_5,
}

impl AuthVersion {
    pub fn to_bool(&self) -> bool {
        match self {
            AuthVersion::IpmiV1_5 => false,
            AuthVersion::IpmiV2 => true,
        }
    }

    pub fn from_bool(val: bool) -> AuthVersion {
        match val {
            true => AuthVersion::IpmiV2,
            false => AuthVersion::IpmiV1_5,
        }
    }
}

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
