use crate::{
    connection::Connection,
    ipmi::{
        data::app::channel::Privilege,
        ipmi_header::IpmiHeader,
        ipmi_v2_header::{IpmiV2Header, PayloadType},
        payload,
    },
    packet::packet::{Packet, Payload},
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

    pub fn create_packet(&self, con: &Connection) -> Packet {
        let packet = Packet::new(
            IpmiHeader::V2_0(IpmiV2Header::new(
                con.auth_type,
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
        RAKPMessage2 {
            message_tag: slice[0],
            rmcp_plus_status_code: StatusCode::from_u8(slice[1]),
            remote_console_session_id: u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]),
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

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RAKPMessage3 {
    /*
    1 Message Tag - Selected by remote console. Used by remote console to help match
        responses up with requests. In this case, the corresponding RAKP Message 4 that is
        returned by the BMC. The BMC can use this value to help differentiate retried
        messages from new messages from the remote console.
    2 RMCP+ Status Code Identifies the status of the previous message. If the previous
        message generated an error, then only the Completion Code, Reserved, and
        Managed System Session ID fields are returned.
        If the BMC receives an error from the remote console, it will immediately terminate the
        RAKP exchange in progress, and will not respond with an RAKP Message 4, even if
        the remaining parameters and Key Exchange Authentication code (below) are valid.
        (Terminating the RAKP exchange in progress means that the BMC will require the
        remote console to restart the RAKP authentication process starting with RAKP
        Message 1.)
        See Table 13-15, RMCP+ and RAKP Message Status Codes for the status codes
        defined for this message.
    3:4 Reserved - write as 00_00h.
    5:8 Managed System Session ID
        The Managed System’s Session ID for this session, returned by the managed system
        on the previous RMCP+ Open Session Response message.
    9:N Key Exchange Authentication Code
        An integrity check value over the relevant items specified by the RAKP authentication
        algorithm identified in RAKP Message 1 . The size of this field depends on the
        specific Authentication Algorithm. This field may be 0 bytes (absent) for some
        algorithms (e.g. RAKP-none). Note that if the authentication algorithm for the given
        Requested Maximum Privilege Level/Role specifies (e.g. RAKP-none) specifies ‘no
        Authentication Code’ then this field must be absent to be considered a match for the
        algorithm.
     */
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

    pub fn create_packet(&self, con: &Connection) -> Packet {
        let packet = Packet::new(
            IpmiHeader::V2_0(IpmiV2Header::new(
                con.auth_type,
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
    /*
    1 Message Tag - The BMC returns the Message Tag value that was passed by the
        remote console in RAKP Message 3.
    2 RMCP+ Status Code - Identifies the status of the previous message. If the
        previous message generated an error, then only the Status Code,
        Reserved, and Management Console Session ID fields are returned. See
        2.1.3.6.1 for the status codes defined for this message.
    3:4 Reserved - Reserved for future definition by this specification set to
        000000h.
    5:8 Mgmt Console Session ID The Mgmt Console Session ID specified by the
        RMCP+ Open Session Request (83h) message associated with this
        response.
    9:N Integrity Check Value An integrity check value over the relevant items
        specified by the RAKP authentication algorithm that was identified in RAKP
        Message 1. The size of this field depends on the specific authentication
        algorithm. (For example, the RAKP-HMAC-SHA1 specifies that an HMACSHA1-96 algorithm be used for calculating this field. See Section 13.28,
        Authentication, Integrity, and Confidentiality Algorithm Numbers for info on
        the algorithm to be used for this field.) This field may be 0 bytes (absent) for
        some authentication algorithms (e.g. RAKP-none)
     */
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
