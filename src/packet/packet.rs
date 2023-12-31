use crate::{
    helpers::utils::{aes_128_cbc_encrypt, generate_iv, hash_hmac_sha_256},
    ipmi::{
        ipmi_header::IpmiHeader,
        ipmi_v1_header::IpmiV1Header,
        ipmi_v2_header::PayloadType,
        payload::ipmi_payload::IpmiPayload,
        rmcp_payloads::{
            rakp::{RAKPMessage2, RAKPMessage4, RAKP},
            rmcp_open_session::{RMCPPlusOpenSession, RMCPPlusOpenSessionResponse},
        },
    },
    rmcp::rcmp_header::RmcpHeader,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Packet {
    pub rmcp_header: RmcpHeader,
    pub ipmi_header: IpmiHeader,
    pub payload: Option<Payload>,
}

impl Packet {
    pub fn new(ipmi_header: IpmiHeader, payload: Payload) -> Packet {
        Packet {
            rmcp_header: RmcpHeader::default(),
            ipmi_header,
            payload: Some(payload),
        }
    }

    pub fn from_slice(slice: &[u8]) -> Packet {
        let nbytes: usize = slice.len();
        let ipmi_header_len = IpmiHeader::header_len(slice[4], slice[5]);
        let ipmi_header = IpmiHeader::from_slice(&slice[4..(ipmi_header_len + 4)]);
        let payload_length = ipmi_header.payload_len();
        // println!("payload length: {:x?}", payload_length);

        Packet {
            rmcp_header: RmcpHeader::from_slice(&slice[..3]),
            ipmi_header: IpmiHeader::from_slice(&slice[4..(ipmi_header_len + 4)]),
            payload: {
                match payload_length {
                    0 => None,
                    _ => match ipmi_header.payload_type() {
                        PayloadType::IPMI => Some(Payload::Ipmi(IpmiPayload::from_slice(
                            &slice[(nbytes - payload_length)..nbytes],
                        ))),
                        PayloadType::RcmpOpenSessionRequest => todo!(),
                        PayloadType::RcmpOpenSessionResponse => Some(Payload::RMCP(
                            RMCPPlusOpenSession::Response(RMCPPlusOpenSessionResponse::from_slice(
                                &slice[(nbytes - payload_length)..nbytes],
                            )),
                        )),
                        PayloadType::RAKP2 => Some(Payload::RAKP(RAKP::Message2(
                            RAKPMessage2::from_slice(&slice[(nbytes - payload_length)..nbytes]),
                        ))),
                        PayloadType::RAKP4 => Some(Payload::RAKP(RAKP::Message4(
                            RAKPMessage4::from_slice(&slice[(nbytes - payload_length)..nbytes]),
                        ))),
                        _ => todo!(),
                    },
                }
            },
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for &byte in self.rmcp_header.to_bytes().iter() {
            result.push(byte);
        }
        for &byte in self.ipmi_header.to_bytes().iter() {
            result.push(byte);
        }
        match &self.payload {
            None => {}
            Some(a) => {
                for &byte in a.to_bytes().iter() {
                    result.push(byte);
                }
            }
        }
        result
    }

    pub fn to_encrypted_bytes(&self, k1: &[u8; 32], k2: &[u8; 32]) -> Option<Vec<u8>> {
        if let IpmiHeader::V2_0(header) = self.ipmi_header {
            let mut encrypted_packet: Vec<u8> = Vec::new();
            let mut auth_code_input = header.to_bytes();
            let iv = generate_iv();
            // println!("using this iv: {:x?}", iv);
            // println!("using this key for aes: {:x?}", &k2.clone()[..16]);
            iv.map(|x| auth_code_input.push(x));
            let encrypted_payload = aes_128_cbc_encrypt(
                k2.clone()[..16].try_into().unwrap(), // aes 128 cbc wants the first 128 bits of k2 as the key
                iv,
                self.payload.clone().unwrap().to_bytes(),
            );
            encrypted_payload
                .iter()
                .for_each(|x| auth_code_input.push(*x));

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
            // println!("auth_code input: {:x?}", auth_code_input);
            // println!("using this key for sha256: {:x?}", &k1);
            // hmac sha256-128 using k1 as key and auth_code input as input buffer
            let auth_code = &hash_hmac_sha_256(k1.into(), auth_code_input.clone()); // choose first 128 bits for sha256_128
                                                                                    // println!("auth_code output: {:x?}", &auth_code[..16]);
            self.rmcp_header
                .to_bytes()
                .map(|header_byte| encrypted_packet.push(header_byte));
            auth_code_input
                .iter()
                .for_each(|byte| encrypted_packet.push(*byte));
            auth_code[..16]
                .iter()
                .for_each(|byte| encrypted_packet.push(*byte));
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

impl Payload {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Payload::Ipmi(payload) => payload.to_bytes(),
            Payload::RMCP(payload) => payload.to_bytes(),
            Payload::RAKP(payload) => payload.to_bytes(),
        }
    }
}
