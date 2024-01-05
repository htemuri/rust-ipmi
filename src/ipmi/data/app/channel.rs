// use crate::ipmi::data::data::Data;
use std::fmt::Debug;

use bitvec::prelude::*;

use crate::{
    err::{IpmiPayloadError, ParseError, PrivilegeError},
    ipmi::data::commands::Command,
    parser::{
        ipmi_payload::IpmiPayload, ipmi_payload_request::IpmiPayloadRequest, AuthType, IpmiHeader,
        IpmiV1Header, Packet, Payload,
    },
    NetFn,
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
        channel_number: u8,
        max_privilege: Privilege,
    ) -> GetChannelAuthCapabilitiesRequest {
        GetChannelAuthCapabilitiesRequest {
            channel_version,
            channel_number,
            max_privilege,
        }
    }

    // pub fn from_slice(_slice: &[u8]) -> GetChannelAuthCapabilitiesRequest {
    //     // todo: add error checking
    //     GetChannelAuthCapabilitiesRequest {
    //         channel_version: true,
    //         channel_number: 0x01,
    //         max_privilege: Privilege::User,
    //     }
    // }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push({
            let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
            *bv.get_mut(0).unwrap() = self.channel_version;
            bv[4..].store::<u8>(self.channel_number);
            // println!("{:?}", bv);
            let channel_number = bv[..].load::<u8>();
            channel_number
        });
        result.push(self.max_privilege.clone().into());
        result
    }

    pub fn create_packet(
        &self,
        auth_type: AuthType,
        session_seq_number: u32,
        session_id: u32,
        auth_code: Option<u128>,
    ) -> Packet {
        let data_bytes = self.to_bytes();
        // println!("{:x?}", data_bytes);
        let packet = Packet::new(
            IpmiHeader::V1_5(IpmiV1Header {
                auth_type,
                session_seq_number,
                session_id,
                auth_code,
                payload_length: (data_bytes.len() as u8) + 7,
            }),
            Payload::Ipmi(IpmiPayload::Request(IpmiPayloadRequest::new(
                NetFn::App,
                Command::GetChannelAuthCapabilities,
                Some(data_bytes),
            ))),
        );
        packet
    }
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct GetChannelAuthCapabilitiesResponse {
    pub channel_number: u8,
    pub auth_version: AuthVersion,
    pub auth_type: Vec<AuthType>,
    pub kg_status: KG,
    pub per_message_auth: bool,
    pub user_level_auth: bool,
    pub anon_login: AnonLogin,
    pub channel_extended_cap: AuthVersion,
    pub oem_id: u32, // 3 bytes not 4
    pub oem_aux_data: u8,
}

impl From<&[u8]> for GetChannelAuthCapabilitiesResponse {
    fn from(value: &[u8]) -> Self {
        GetChannelAuthCapabilitiesResponse::from_slice(value)
    }
}
impl From<Vec<u8>> for GetChannelAuthCapabilitiesResponse {
    fn from(value: Vec<u8>) -> Self {
        GetChannelAuthCapabilitiesResponse::from_slice(value.as_slice())
    }
}

impl GetChannelAuthCapabilitiesResponse {
    fn from_slice(slice: &[u8]) -> GetChannelAuthCapabilitiesResponse {
        GetChannelAuthCapabilitiesResponse {
            channel_number: { slice[0] },
            auth_version: {
                let bv = BitSlice::<u8, Msb0>::from_element(&slice[1]);
                AuthVersion::from_bool(bv[0])
            },
            auth_type: {
                let bv = BitSlice::<u8, Msb0>::from_element(&slice[1]);
                let mut result = vec![];
                if bv[2] {
                    result.push(AuthType::OEM)
                }
                if bv[3] {
                    result.push(AuthType::PasswordOrKey)
                }
                if bv[5] {
                    result.push(AuthType::MD5)
                }
                if bv[6] {
                    result.push(AuthType::MD2)
                }
                if bv[7] {
                    result.push(AuthType::None)
                }
                result
            },
            kg_status: {
                let bv = BitSlice::<u8, Msb0>::from_element(&slice[2]);
                KG::from_bool(bv[2])
            },
            per_message_auth: {
                let bv = BitSlice::<u8, Msb0>::from_element(&slice[2]);
                !bv[3]
            },
            user_level_auth: {
                let bv = BitSlice::<u8, Msb0>::from_element(&slice[2]);
                !bv[4]
            },
            anon_login: {
                let bv = BitSlice::<u8, Msb0>::from_element(&slice[2]);
                AnonLogin::new(
                    AnonStatus::from_bool(bv[5]),
                    AnonStatus::from_bool(bv[6]),
                    AnonStatus::from_bool(bv[7]),
                )
            },
            channel_extended_cap: {
                let bv = BitSlice::<u8, Msb0>::from_element(&slice[3]);
                AuthVersion::from_bool(bv[6])
            },
            oem_id: u32::from_le_bytes([0, slice[4], slice[5], slice[6]]),
            oem_aux_data: slice[7],
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]

pub enum KG {
    /*
        0b = KG is set to default (all 0’s). User key KUID will be used in place of
        KG in RAKP. (Knowledge of KG not required for activating session.)
        1b = KG is set to non-zero value. (Knowledge of both KG and user
        password (if not anonymous login) required for activating session.)
    */
    Defualt,
    NonZero,
}
impl KG {
    // pub fn to_bool(&self) -> bool {
    //     match self {
    //         KG::Defualt => false,
    //         KG::NonZero => true,
    //     }
    // }
    pub fn from_bool(flag: bool) -> KG {
        match flag {
            false => KG::Defualt,
            true => KG::NonZero,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]

pub struct AnonLogin {
    /*
        1b = Non-null usernames enabled. (One or more users are enabled
        that have non-null usernames).
        1b = Null usernames enabled (One or more users that have a null
        username, but non-null password, are presently enabled)
        1b = Anonymous Login enabled (A user that has
    */
    pub non_null_username: AnonStatus,
    pub null_username: AnonStatus,
    pub anonymous_login: AnonStatus,
}

impl AnonLogin {
    pub fn new(
        non_null_username: AnonStatus,
        null_username: AnonStatus,
        anonymous_login: AnonStatus,
    ) -> AnonLogin {
        AnonLogin {
            non_null_username,
            null_username,
            anonymous_login,
        }
    }

    // pub fn to_bits(&self) -> [bool; 3] {
    //     return [
    //         self.non_null_username.to_bool(),
    //         self.null_username.to_bool(),
    //         self.anonymous_login.to_bool(),
    //     ];
    // }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]

pub enum AnonStatus {
    Enabled,
    Disabled,
}

impl AnonStatus {
    // pub fn to_bool(&self) -> bool {
    //     match self {
    //         AnonStatus::Enabled => true,
    //         AnonStatus::Disabled => false,
    //     }
    // }
    pub fn from_bool(flag: bool) -> AnonStatus {
        match flag {
            true => AnonStatus::Enabled,
            false => AnonStatus::Disabled,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]

pub enum AuthVersion {
    IpmiV2,
    IpmiV1_5,
}

impl AuthVersion {
    // pub fn to_bool(&self) -> bool {
    //     match self {
    //         AuthVersion::IpmiV1_5 => false,
    //         AuthVersion::IpmiV2 => true,
    //     }
    // }

    pub fn from_bool(val: bool) -> AuthVersion {
        match val {
            true => AuthVersion::IpmiV2,
            false => AuthVersion::IpmiV1_5,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Privilege {
    Reserved,
    Callback,
    User,
    Operator,
    Administrator,
    Oem,
    // Unknown(u8),
}

impl TryFrom<u8> for Privilege {
    type Error = IpmiPayloadError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Privilege::Reserved),
            0x01 => Ok(Privilege::Callback),
            0x02 => Ok(Privilege::User),
            0x03 => Ok(Privilege::Operator),
            0x04 => Ok(Privilege::Administrator),
            0x05 => Ok(Privilege::Oem),
            _ => Err(ParseError::Privilege(PrivilegeError::UnknownPrivilege(
                value,
            )))?,
        }
    }
}

impl Into<u8> for Privilege {
    fn into(self) -> u8 {
        match self {
            Privilege::Reserved => 0x00,
            Privilege::Callback => 0x01,
            Privilege::User => 0x02,
            Privilege::Operator => 0x03,
            Privilege::Administrator => 0x04,
            Privilege::Oem => 0x05,
        }
    }
}

// impl Privilege {
//     // pub fn from_u8(privilege: u8) -> Privilege {
//     //     match privilege {
//     //         0x00 => Privilege::Reserved,
//     //         0x01 => Privilege::Callback,
//     //         0x02 => Privilege::User,
//     //         0x03 => Privilege::Operator,
//     //         0x04 => Privilege::Administrator,
//     //         0x05 => Privilege::Oem,
//     //         _ => Privilege::Unknown(privilege),
//     //     }
//     // }

//     // pub fn to_u8(&self) -> u8 {
//     //     match self {
//     //         Privilege::Reserved => 0x00,
//     //         Privilege::Callback => 0x01,
//     //         Privilege::User => 0x02,
//     //         Privilege::Operator => 0x03,
//     //         Privilege::Administrator => 0x04,
//     //         Privilege::Oem => 0x05,
//     //         Privilege::Unknown(privilege) => *privilege,
//     //     }
//     // }
// }
