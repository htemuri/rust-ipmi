use crate::{
    ipmi::{
        ipmi_header::IpmiHeader, ipmi_v1_header::IpmiV1Header, payload::ipmi_payload::IpmiPayload,
    },
    rmcp::rcmp_header::RmcpHeader,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Packet {
    pub rmcp_header: RmcpHeader,
    pub ipmi_header: IpmiHeader,
    pub ipmi_payload: Option<IpmiPayload>,
}

impl Packet {
    pub fn from_slice(slice: &[u8], nbytes: usize) -> Packet {
        let ipmi_header =
            IpmiHeader::from_slice(&slice[4..IpmiHeader::header_len(slice[0], slice[1])]);
        let payload_length = ipmi_header.payload_len();
        Packet {
            rmcp_header: RmcpHeader::from_slice(&slice[..3]),
            ipmi_header: IpmiHeader::from_slice(
                &slice[4..IpmiHeader::header_len(slice[0], slice[1])],
            ),
            ipmi_payload: {
                match payload_length {
                    0 => None,
                    _ => {
                        // println!("{:x?}", &slice[(&slice.len() - payload_length)..]);
                        // println!("{:?}", &slice.len());
                        // println!("{:?}", nbytes);
                        // println!("{:?}", payload_length);
                        Some(IpmiPayload::from_slice(
                            &slice[(nbytes - payload_length)..nbytes],
                        ))
                    }
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
        match &self.ipmi_payload {
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
            ipmi_payload: None,
        }
    }
}
