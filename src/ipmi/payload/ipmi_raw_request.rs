use serde::de::IntoDeserializer;

use crate::{
    connection::Connection,
    ipmi::{
        data::commands::Command,
        ipmi_header::IpmiHeader,
        ipmi_v2_header::{IpmiV2Header, PayloadType},
    },
    packet::packet::{Packet, Payload},
};

use super::{
    ipmi_payload::{IpmiPayload, NetFn},
    ipmi_payload_request::IpmiPayloadRequest,
};

pub struct IpmiPayloadRawRequest {
    pub netfn: NetFn,
    pub command_code: Command,
    pub data: Option<Vec<u8>>,
}

impl IpmiPayloadRawRequest {
    pub fn new(
        netfn: NetFn,
        command_code: Command,
        data: Option<Vec<u8>>,
    ) -> IpmiPayloadRawRequest {
        IpmiPayloadRawRequest {
            netfn,
            command_code,
            data,
        }
    }

    pub fn create_packet(
        &self,
        con: &Connection,
        rmcp_plus_session_id: u32,
        session_seq_number: u32,
    ) -> Packet {
        let netfn = self.netfn.clone();
        let cmd = self.command_code.clone();
        let data = self.data.clone();
        Packet::new(
            IpmiHeader::V2_0(IpmiV2Header {
                auth_type: con.auth_type,
                payload_enc: true,
                payload_auth: true,
                payload_type: PayloadType::IPMI,
                oem_iana: None,
                oem_payload_id: None,
                rmcp_plus_session_id,
                session_seq_number,
                payload_length: 32,
            }),
            Payload::Ipmi(IpmiPayload::Request(IpmiPayloadRequest::new(
                netfn, cmd, data,
            ))),
        )
    }
}
