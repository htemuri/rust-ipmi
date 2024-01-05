use std::fmt::Display;

use crate::{
    err::PacketError,
    helpers::utils::{aes_128_cbc_decrypt, aes_128_cbc_encrypt, generate_iv, hash_hmac_sha_256},
    parser::{ipmi_payload::IpmiPayload, IpmiHeader, IpmiV1Header, PayloadType, RmcpHeader},
};

use super::{rakp::RAKP, rmcp_open_session::RMCPPlusOpenSession};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Packet {
    pub rmcp_header: RmcpHeader,
    pub ipmi_header: IpmiHeader,
    pub payload: Option<Payload>,
}

impl TryFrom<&[u8]> for Packet {
    type Error = PacketError;
    fn try_from(value: &[u8]) -> Result<Self, PacketError> {
        let nbytes: usize = value.len();
        if nbytes < 20 {
            Err(PacketError::WrongLength)?
        }
        let ipmi_header_len = IpmiHeader::header_len(value[4], value[5])?;
        let ipmi_header: IpmiHeader = value[4..(ipmi_header_len + 4)].try_into()?;
        // let ipmi_header = IpmiHeader::from_slice(&value[4..(ipmi_header_len + 4)]);
        let payload_length = ipmi_header.payload_len();
        let mut payload_vec = Vec::new();
        payload_vec.extend_from_slice(&value[(nbytes - payload_length)..nbytes]);
        // println!("Payload vec: {:x?}", payload_vec);
        Ok(Packet {
            rmcp_header: value[..4].try_into()?,
            ipmi_header,
            payload: {
                match payload_length {
                    0 => None,
                    _ => match ipmi_header.payload_type() {
                        PayloadType::IPMI => {
                            Some(Payload::Ipmi(payload_vec.as_slice().try_into()?))
                        }
                        PayloadType::RcmpOpenSessionRequest => todo!(),
                        PayloadType::RcmpOpenSessionResponse => {
                            Some(Payload::RMCP(RMCPPlusOpenSession::Response(
                                // RMCPPlusOpenSessionResponse::from_slice(
                                payload_vec.as_slice().try_into()?, // ),
                            )))
                        }
                        PayloadType::RAKP2 => Some(Payload::RAKP(RAKP::Message2(
                            // RAKPMessage2::from_slice(
                            payload_vec.as_slice().try_into()?, // ),
                        ))),
                        PayloadType::RAKP4 => Some(Payload::RAKP(RAKP::Message4(
                            // RAKPMessage4::from_slice(
                            payload_vec.as_slice().try_into()?, // ),
                        ))),
                        _ => todo!(),
                    },
                }
            },
        })
    }
}

impl TryFrom<(&[u8], &[u8; 32])> for Packet {
    type Error = PacketError;

    fn try_from(value: (&[u8], &[u8; 32])) -> Result<Self, PacketError> {
        let nbytes: usize = value.0.len();
        if nbytes < 20 {
            Err(PacketError::WrongLength)?
        }
        let ipmi_header_len = IpmiHeader::header_len(value.0[4], value.0[5])?;
        let ipmi_header: IpmiHeader = value.0[4..(ipmi_header_len + 4)].try_into()?;
        let payload_length = ipmi_header.payload_len();
        let mut payload_vec = Vec::new();
        if let IpmiHeader::V2_0(header) = ipmi_header {
            if header.payload_enc {
                // decrypt slice
                let iv = &value.0[16..32];
                let binding = aes_128_cbc_decrypt(
                    value.1[..16].try_into().unwrap(),
                    iv.try_into().unwrap(),
                    value.0[32..(32 + payload_length - 16)].to_vec(),
                );
                binding.iter().for_each(|byte| payload_vec.push(*byte))
            } else {
                payload_vec.extend_from_slice(&value.0[(nbytes - payload_length)..nbytes])
            }
        } else {
            payload_vec.extend_from_slice(&value.0[(nbytes - payload_length)..nbytes])
        }
        // println!("Payload vec: {:x?}", payload_vec);
        Ok(Packet {
            rmcp_header: value.0[..4].try_into()?,
            ipmi_header,
            payload: {
                match payload_length {
                    0 => None,
                    _ => match ipmi_header.payload_type() {
                        PayloadType::IPMI => {
                            Some(Payload::Ipmi(payload_vec.as_slice().try_into()?))
                        }
                        PayloadType::RcmpOpenSessionRequest => todo!(),
                        PayloadType::RcmpOpenSessionResponse => {
                            Some(Payload::RMCP(RMCPPlusOpenSession::Response(
                                // RMCPPlusOpenSessionResponse::from_slice(
                                payload_vec.as_slice().try_into()?, // ),
                            )))
                        }
                        PayloadType::RAKP2 => Some(Payload::RAKP(RAKP::Message2(
                            // RAKPMessage2::from_slice(
                            payload_vec.as_slice().try_into()?, // ),
                        ))),
                        PayloadType::RAKP4 => Some(Payload::RAKP(RAKP::Message4(
                            // RAKPMessage4::from_slice(
                            payload_vec.as_slice().try_into()?, // ),
                        ))),
                        _ => todo!(),
                    },
                }
            },
        })
    }
}

impl Into<Vec<u8>> for Packet {
    fn into(self) -> Vec<u8> {
        let mut result = Vec::new();
        result.append(&mut self.rmcp_header.into());
        result.append(&mut self.ipmi_header.clone().into());
        match &self.payload {
            None => {}
            Some(a) => result.append(&mut a.clone().into()),
        }
        result
    }
}

impl Packet {
    pub fn new(ipmi_header: IpmiHeader, payload: Payload) -> Packet {
        Packet {
            rmcp_header: RmcpHeader::default(),
            ipmi_header,
            payload: Some(payload),
        }
    }
    pub fn to_encrypted_bytes(&self, k1: &[u8; 32], k2: &[u8; 32]) -> Option<Vec<u8>> {
        if let IpmiHeader::V2_0(header) = self.ipmi_header {
            let mut encrypted_packet: Vec<u8> = Vec::new();
            let mut auth_code_input: Vec<u8> = header.into();
            let iv = generate_iv();
            auth_code_input.extend(&iv);

            let mut encrypted_payload = aes_128_cbc_encrypt(
                k2.clone()[..16].try_into().unwrap(), // aes 128 cbc wants the first 128 bits of k2 as the key
                iv,
                self.payload.clone().unwrap().into(),
            );
            auth_code_input.append(&mut encrypted_payload);

            // integrity padding
            let padding_needed = 4 - ((auth_code_input.len() + 2) % 4);
            for _ in 0..padding_needed {
                auth_code_input.push(0xff);
            }
            auth_code_input.push(padding_needed.try_into().unwrap());
            /*
            **Next Header**. Reserved in IPMI v2.0. Set
            to 07h for RMCP+ packets
            defined in this specification.
            */
            auth_code_input.push(0x7);
            // hmac sha256-128 using k1 as key and auth_code input as input buffer
            let auth_code = &hash_hmac_sha_256(k1.into(), auth_code_input.clone()); // choose first 128 bits for sha256_128

            encrypted_packet.append(&mut self.rmcp_header.into());
            encrypted_packet.append(&mut auth_code_input);
            encrypted_packet.extend(&auth_code[..16]);
            Some(encrypted_packet)
        } else {
            return None;
        }
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            rmcp_header: RmcpHeader::default(),
            ipmi_header: IpmiHeader::V1_5(IpmiV1Header::default()),
            payload: None,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Payload {
    Ipmi(IpmiPayload),
    RMCP(RMCPPlusOpenSession),
    RAKP(RAKP),
}

impl Into<Vec<u8>> for Payload {
    fn into(self) -> Vec<u8> {
        match self {
            Payload::Ipmi(payload) => payload.into(),
            Payload::RMCP(payload) => payload.into(),
            Payload::RAKP(payload) => payload.into(),
        }
    }
}
