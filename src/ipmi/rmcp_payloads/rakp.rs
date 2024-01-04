use crate::{
    ipmi::data::app::channel::Privilege,
    packet::packet::{Packet, Payload},
    parser::{AuthType, IpmiHeader, IpmiV2Header, PayloadType},
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

impl RAKP {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            RAKP::Message1(payload) => payload.to_bytes(),
            RAKP::Message3(payload) => payload.to_bytes(),
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.message_tag);
        [0x0, 0x0, 0x0].map(|x| result.push(x));
        u32::to_le_bytes(self.managed_system_session_id).map(|x| result.push(x));
        u128::to_le_bytes(self.remote_console_random_number).map(|x| result.push(x));
        result.push({
            let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
            *bv.get_mut(3).unwrap() = self.inherit_role;
            bv[4..].store::<u8>(self.requested_max_privilege.to_u8());
            let max_priv = bv[..].load::<u8>();
            max_priv
        });
        [0x0, 0x0].map(|x| result.push(x));
        result.push(self.username_length);
        self.username
            .clone()
            .into_bytes()
            .iter()
            .for_each(|character| result.push(*character));
        result
    }

    pub fn create_packet(&self) -> Packet {
        let packet = Packet::new(
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
        );
        packet
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

impl RAKPMessage2 {
    pub fn from_slice(slice: &[u8]) -> RAKPMessage2 {
        if slice.len() < 40 {
            RAKPMessage2 {
                message_tag: slice[0],
                rmcp_plus_status_code: StatusCode::from_u8(slice[1]),
                remote_console_session_id: u32::from_le_bytes([
                    slice[4], slice[5], slice[6], slice[7],
                ]),
                managed_system_random_number: 0,
                managed_system_guid: 0,
                key_exchange_auth_code: None,
            }
        } else {
            RAKPMessage2 {
                message_tag: slice[0],
                rmcp_plus_status_code: StatusCode::from_u8(slice[1]),
                remote_console_session_id: u32::from_le_bytes([
                    slice[4], slice[5], slice[6], slice[7],
                ]),
                managed_system_random_number: u128::from_le_bytes([
                    slice[8], slice[9], slice[10], slice[11], slice[12], slice[13], slice[14],
                    slice[15], slice[16], slice[17], slice[18], slice[19], slice[20], slice[21],
                    slice[22], slice[23],
                ]),
                managed_system_guid: u128::from_le_bytes([
                    slice[24], slice[25], slice[26], slice[27], slice[28], slice[29], slice[30],
                    slice[31], slice[32], slice[33], slice[34], slice[35], slice[36], slice[37],
                    slice[38], slice[39],
                ]),
                key_exchange_auth_code: {
                    if slice.len() > 40 {
                        let mut vec = Vec::new();
                        vec.extend_from_slice(&slice[40..]);
                        Some(vec)
                    } else {
                        None
                    }
                },
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RAKPMessage3 {
    pub message_tag: u8,
    pub rmcp_plus_status_code: StatusCode,
    pub managed_system_session_id: u32,
    pub key_exchange_auth_code: Option<Vec<u8>>,
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.message_tag);
        result.push(self.rmcp_plus_status_code.to_u8());
        [0x0, 0x0].map(|x| result.push(x));
        u32::to_le_bytes(self.managed_system_session_id).map(|x| result.push(x));
        if let Some(auth_code) = &self.key_exchange_auth_code {
            auth_code.into_iter().for_each(|x| result.push(x.clone()))
        }
        result
    }

    pub fn create_packet(&self) -> Packet {
        let packet = Packet::new(
            IpmiHeader::V2_0(IpmiV2Header::new(
                AuthType::RmcpPlus,
                false,
                false,
                PayloadType::RAKP3,
                0x0,
                0x0,
                {
                    match &self.key_exchange_auth_code {
                        None => 8.try_into().unwrap(),
                        Some(auth_code) => (auth_code.len() + 8).try_into().unwrap(),
                    }
                },
            )),
            Payload::RAKP(RAKP::Message3(self.clone())),
        );
        packet
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RAKPMessage4 {
    pub message_tag: u8,
    pub rmcp_plus_status_code: StatusCode,
    pub management_console_session_id: u32,
    pub integrity_check_value: Option<Vec<u8>>,
}

impl RAKPMessage4 {
    pub fn from_slice(slice: &[u8]) -> RAKPMessage4 {
        RAKPMessage4 {
            message_tag: slice[0],
            rmcp_plus_status_code: StatusCode::from_u8(slice[1]),
            management_console_session_id: u32::from_le_bytes([
                slice[4], slice[5], slice[6], slice[7],
            ]),
            integrity_check_value: {
                if slice.len() > 8 {
                    let mut vec = Vec::new();
                    vec.extend_from_slice(&slice[8..]);
                    Some(vec)
                } else {
                    None
                }
            },
        }
    }
}
