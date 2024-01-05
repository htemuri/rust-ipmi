use crate::{
    commands::Privilege,
    err::IpmiPayloadError,
    parser::{AuthType, IpmiHeader, IpmiV2Header, Packet, Payload, PayloadType},
};

use bitvec::prelude::*;

use super::rmcp_open_session::StatusCode;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum RAKP {
    Message1(RAKPMessage1),
    Message2(RAKPMessage2),
    Message3(RAKPMessage3),
    Message4(RAKPMessage4),
}

impl Into<Vec<u8>> for RAKP {
    fn into(self) -> Vec<u8> {
        match self {
            RAKP::Message1(payload) => payload.into(),
            RAKP::Message3(payload) => payload.into(),
            _ => todo!(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RAKPMessage1 {
    pub message_tag: u8,
    pub managed_system_session_id: u32,
    pub remote_console_random_number: u128,
    pub inherit_role: bool,
    pub requested_max_privilege: Privilege,
    pub username_length: u8,
    pub username: String,
}

impl Into<Vec<u8>> for RAKPMessage1 {
    fn into(self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.message_tag);
        result.extend([0x0, 0x0, 0x0]);
        result.extend(u32::to_le_bytes(self.managed_system_session_id));
        result.extend(u128::to_le_bytes(self.remote_console_random_number));
        result.push({
            let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
            *bv.get_mut(3).unwrap() = self.inherit_role;
            bv[4..].store::<u8>(self.requested_max_privilege.into());
            let max_priv = bv[..].load::<u8>();
            max_priv
        });
        result.extend([0x0, 0x0]);
        result.push(self.username_length);
        result.extend(self.username.into_bytes());
        result
    }
}

impl Into<Packet> for RAKPMessage1 {
    fn into(self) -> Packet {
        Packet::new(
            IpmiHeader::V2_0(IpmiV2Header::new(
                AuthType::RmcpPlus,
                false,
                false,
                PayloadType::RAKP1,
                0x0,
                0x0,
                (self.username_length + 28).try_into().unwrap(),
            )),
            Payload::RAKP(RAKP::Message1(self.clone())),
        )
    }
}

impl RAKPMessage1 {
    pub fn new(
        message_tag: u8,
        managed_system_session_id: u32,
        remote_console_random_number: u128,
        inherit_role: bool,
        requested_max_privilege: Privilege,
        username: String,
    ) -> RAKPMessage1 {
        RAKPMessage1 {
            message_tag,
            managed_system_session_id,
            remote_console_random_number,
            inherit_role,
            requested_max_privilege,
            username_length: { username.len().try_into().unwrap() },
            username,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RAKPMessage2 {
    pub message_tag: u8,
    pub rmcp_plus_status_code: StatusCode,
    pub remote_console_session_id: u32,
    pub managed_system_random_number: u128,
    pub managed_system_guid: u128,
    pub key_exchange_auth_code: Option<Vec<u8>>,
}

impl TryFrom<&[u8]> for RAKPMessage2 {
    type Error = IpmiPayloadError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 8 {
            Err(IpmiPayloadError::WrongLength)?
        }
        let message_tag = value[0];
        let rmcp_plus_status_code: StatusCode = value[1].into();
        let remote_console_session_id = u32::from_le_bytes(value[4..8].try_into().unwrap());
        let mut managed_system_random_number = 0;
        let mut managed_system_guid = 0;
        let mut key_exchange_auth_code = None;

        if value.len() >= 40 {
            managed_system_random_number = u128::from_le_bytes(value[8..24].try_into().unwrap());
            managed_system_guid = u128::from_le_bytes(value[24..40].try_into().unwrap());
            if value.len() > 40 {
                key_exchange_auth_code = Some(value[40..].to_vec())
            }
        };

        Ok(RAKPMessage2 {
            message_tag,
            rmcp_plus_status_code,
            remote_console_session_id,
            managed_system_random_number,
            managed_system_guid,
            key_exchange_auth_code,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RAKPMessage3 {
    pub message_tag: u8,
    pub rmcp_plus_status_code: StatusCode,
    pub managed_system_session_id: u32,
    pub key_exchange_auth_code: Option<Vec<u8>>,
}

impl Into<Vec<u8>> for RAKPMessage3 {
    fn into(self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.message_tag);
        result.push(self.rmcp_plus_status_code.into());
        result.extend([0x0, 0x0]);
        result.extend(u32::to_le_bytes(self.managed_system_session_id));
        if let Some(auth_code) = &self.key_exchange_auth_code {
            result.append(&mut auth_code.clone());
        }
        result
    }
}

impl Into<Packet> for RAKPMessage3 {
    fn into(self) -> Packet {
        Packet::new(
            IpmiHeader::V2_0(IpmiV2Header::new(
                AuthType::RmcpPlus,
                false,
                false,
                PayloadType::RAKP3,
                0x0,
                0x0,
                {
                    match &self.key_exchange_auth_code {
                        None => 8 as u16,
                        Some(auth_code) => (auth_code.len() + 8) as u16,
                    }
                },
            )),
            Payload::RAKP(RAKP::Message3(self.clone())),
        )
    }
}

impl RAKPMessage3 {
    pub fn new(
        message_tag: u8,
        rmcp_plus_status_code: StatusCode,
        managed_system_session_id: u32,
        key_exchange_auth_code: Option<Vec<u8>>,
    ) -> RAKPMessage3 {
        RAKPMessage3 {
            message_tag,
            rmcp_plus_status_code,
            managed_system_session_id,
            key_exchange_auth_code,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RAKPMessage4 {
    pub message_tag: u8,
    pub rmcp_plus_status_code: StatusCode,
    pub management_console_session_id: u32,
    pub integrity_check_value: Option<Vec<u8>>,
}

impl TryFrom<&[u8]> for RAKPMessage4 {
    type Error = IpmiPayloadError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 8 {
            Err(IpmiPayloadError::WrongLength)?
        }
        Ok(RAKPMessage4 {
            message_tag: value[0],
            rmcp_plus_status_code: value[1].into(),
            management_console_session_id: u32::from_le_bytes(value[4..8].try_into().unwrap()),
            integrity_check_value: {
                if value.len() > 8 {
                    Some(value[8..].to_vec())
                } else {
                    None
                }
            },
        })
    }
}
