use bitvec::{field::BitField, order::Msb0, slice::BitSlice};

use crate::err::IpmiHeaderError;

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

impl TryFrom<&[u8]> for IpmiHeader {
    type Error = IpmiHeaderError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 10 {
            Err(IpmiHeaderError::WrongLength)?
        }

        let auth_type: AuthType = value[0].try_into()?;

        match auth_type {
            AuthType::RmcpPlus => Ok(IpmiHeader::V2_0(value.try_into()?)),
            _ => Ok(IpmiHeader::V1_5(value.try_into()?)),
        }
    }
}

impl Into<Vec<u8>> for IpmiHeader {
    fn into(self) -> Vec<u8> {
        match self {
            IpmiHeader::V1_5(header) => header.into(),
            IpmiHeader::V2_0(header) => header.into(),
        }
    }
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

    pub fn header_len(first_byte: u8, second_byte: u8) -> Result<usize, IpmiHeaderError> {
        let auth_type: AuthType = first_byte.try_into()?;
        match auth_type {
            AuthType::RmcpPlus => {
                let length = 12;
                let payload_type: PayloadType = BitSlice::<u8, Msb0>::from_element(&second_byte)
                    [3..]
                    .load::<u8>()
                    .try_into()?;
                match payload_type {
                    PayloadType::OEM => Ok(length + 6),
                    _ => Ok(length),
                }
            }
            AuthType::None => Ok(10),
            _ => Ok(26),
        }
    }

    pub fn payload_len(&self) -> usize {
        match self {
            IpmiHeader::V1_5(a) => a.payload_length.try_into().unwrap(),
            IpmiHeader::V2_0(a) => a.payload_length.try_into().unwrap(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AuthType {
    None,
    MD2,
    MD5,
    PasswordOrKey,
    OEM,
    RmcpPlus,
}

impl TryFrom<u8> for AuthType {
    type Error = IpmiHeaderError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(AuthType::None),
            0x01 => Ok(AuthType::MD2),
            0x02 => Ok(AuthType::MD5),
            0x04 => Ok(AuthType::PasswordOrKey),
            0x05 => Ok(AuthType::OEM),
            0x06 => Ok(AuthType::RmcpPlus),
            _ => Err(IpmiHeaderError::UnsupportedAuthType(value)),
        }
    }
}

impl Into<u8> for AuthType {
    fn into(self) -> u8 {
        match &self {
            AuthType::None => 0x00,
            AuthType::MD2 => 0x01,
            AuthType::MD5 => 0x02,
            AuthType::PasswordOrKey => 0x04,
            AuthType::OEM => 0x05,
            AuthType::RmcpPlus => 0x06,
        }
    }
}
