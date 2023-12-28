use arrayvec::ArrayVec;
use bitvec::{field::BitField, order::Msb0, slice::BitSlice};

use super::{
    ipmi_v1_header::IpmiV1Header,
    ipmi_v2_header::{IpmiV2Header, PayloadType},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IpmiHeader {
    V1_5(IpmiV1Header),
    V2_0(IpmiV2Header),
}

pub enum Version {
    V1_5,
    V2_0,
}

impl IpmiHeader {
    pub const MAX_LEN: usize = 26;

    pub fn version_from_auth_type(auth_type: AuthType) -> Version {
        match auth_type {
            AuthType::RmcpPlus => Version::V2_0,
            _ => Version::V1_5,
        }
    }

    pub fn payload_type(&self) -> PayloadType {
        match self {
            IpmiHeader::V1_5(_header) => PayloadType::IPMI,
            IpmiHeader::V2_0(header) => header.payload_type,
        }
    }

    pub fn header_len(first_byte: u8, second_byte: u8) -> usize {
        let auth_type = AuthType::from_u8(first_byte);
        match auth_type {
            AuthType::RmcpPlus => {
                let length = 12;
                let payload_type = PayloadType::from_u8(
                    BitSlice::<u8, Msb0>::from_element(&second_byte)[3..].load::<u8>(),
                );
                match payload_type {
                    PayloadType::OEM => length + 6,
                    _ => length,
                }
            }
            AuthType::None => 10,
            _ => 26,
        }
    }

    pub fn payload_len(&self) -> usize {
        match self {
            IpmiHeader::V1_5(a) => a.payload_length.try_into().unwrap(),
            IpmiHeader::V2_0(a) => a.payload_length.try_into().unwrap(),
        }
    }

    pub fn from_slice(slice: &[u8]) -> IpmiHeader {
        let auth_type = AuthType::from_u8(u8::from_be_bytes([slice[0]]));

        match auth_type {
            AuthType::RmcpPlus => IpmiHeader::V2_0(IpmiV2Header::from_slice(&slice).unwrap().0),
            _ => IpmiHeader::V1_5(IpmiV1Header::from_slice(&slice).unwrap().0),
        }
    }

    pub fn to_bytes(&self) -> ArrayVec<u8, { IpmiHeader::MAX_LEN }> {
        match self {
            IpmiHeader::V1_5(header) => header.to_bytes(),
            IpmiHeader::V2_0(header) => header.to_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AuthType {
    None,
    MD2,
    MD5,
    Reserved,
    PasswordOrKey,
    OEM,
    RmcpPlus,
}

impl AuthType {
    pub fn from_u8(format: u8) -> AuthType {
        match format {
            0x00 => AuthType::None,
            0x01 => AuthType::MD2,
            0x02 => AuthType::MD5,
            0x04 => AuthType::PasswordOrKey,
            0x05 => AuthType::OEM,
            0x06 => AuthType::RmcpPlus,
            _ => AuthType::Reserved,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match &self {
            AuthType::None => 0x00,
            AuthType::MD2 => 0x01,
            AuthType::MD5 => 0x02,
            AuthType::PasswordOrKey => 0x04,
            AuthType::OEM => 0x05,
            AuthType::RmcpPlus => 0x06,
            AuthType::Reserved => 0x03,
        }
    }
}
