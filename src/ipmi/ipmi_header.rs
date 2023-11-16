use super::{ipmi_v1_header::IpmiV1Header, ipmi_v2_header::IpmiV2Header};

pub enum IpmiHeader {
    V1_5(IpmiV1Header),
    V2_0(IpmiV2Header),
}

impl IpmiHeader {
    pub const MAX_LEN: usize = 26;

    // fn to_bytes(&self) -> ArrayVec<u8, { IpmiHeader::MAX_LEN }> {
    //     match self {
    //         IpmiHeader::V1_5(header) => header.to_bytes(),
    //         IpmiHeader::V2_0(header) => header.to_bytes(),
    //     }
    // }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
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
