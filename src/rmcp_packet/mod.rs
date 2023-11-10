pub mod ipmi_payload1_5;

use ipmi_payload1_5::IpmiPayload1_5;

#[derive(Debug)]
pub struct Packet {
    pub rmcp_header: RmcpHeader,
    pub ipmi_header: IpmiSessionHeader1_5,
    pub ipmi_payload: IpmiPayload1_5,
}

impl Packet {
    pub fn get_bytes(&self) -> Vec<u8> {
        let rmcp_header_bytes = self.rmcp_header.get_bytes();
        let mut ipmi_header_bytes = self.ipmi_header.get_bytes(&self.ipmi_payload);
        let mut ipmi_payload_bytes = self.ipmi_payload.get_bytes();

        let mut result = Vec::from(rmcp_header_bytes);
        result.append(&mut ipmi_header_bytes);
        result.append(&mut ipmi_payload_bytes);
        result
    }

    pub fn from_slice(bytes: &[u8; 8092], size: &usize) -> Packet {
        // println!("{:x?}", &bytes[14..*size]);
        Packet {
            rmcp_header: RmcpHeader::from_slice(&bytes[..4]),
            ipmi_header: IpmiSessionHeader1_5::from_slice(&bytes[4..15]),
            ipmi_payload: IpmiPayload1_5::from_slice(&bytes[14..*size]),
        }
    }
}
#[derive(Debug)]
pub struct RmcpHeader {
    pub version: u8,
    pub reserved: u8,
    pub sequence_number: u8,
    pub message_class: u8,
}

impl RmcpHeader {
    pub fn get_bytes(&self) -> [u8; 4] {
        let final_bytes: [u8; 4] = [
            self.version,
            self.reserved,
            self.sequence_number,
            self.message_class,
        ];
        final_bytes
    }
    pub fn from_slice(bytes: &[u8]) -> RmcpHeader {
        RmcpHeader {
            version: bytes[0],
            reserved: bytes[1],
            sequence_number: bytes[2],
            message_class: bytes[3],
        }
    }
}

#[derive(Debug)]
pub struct IpmiSessionHeader1_5 {
    pub auth_type: u8,
    pub session_seq_number: u32,
    pub session_id: u32,
    pub auth_code: u64,
    pub payload_length: u8,
}

impl IpmiSessionHeader1_5 {
    pub fn get_bytes(&self, payload: &IpmiPayload1_5) -> Vec<u8> {
        let mut result = vec![];
        result.push(self.auth_type);
        result.append(&mut bincode::serialize(&self.session_seq_number).unwrap());
        result.append(&mut bincode::serialize(&self.session_id).unwrap());
        result.push(payload.get_bytes().len().try_into().unwrap());
        result
    }

    pub fn from_slice(bytes: &[u8]) -> IpmiSessionHeader1_5 {
        let session_seq_number: u32 = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let session_id: u32 = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        IpmiSessionHeader1_5 {
            auth_type: bytes[0],
            session_seq_number: session_seq_number,
            session_id: session_id,
            auth_code: 0,
            payload_length: bytes[9],
        }
    }
}
