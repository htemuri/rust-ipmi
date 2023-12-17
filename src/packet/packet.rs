use crate::{
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
