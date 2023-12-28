use crate::ipmi::data::commands::Command;
use crate::packet::packet::Payload;
use crate::{
    connection::Connection,
    helpers::utils::join_two_bits_to_byte,
    ipmi::{
        ipmi_header::IpmiHeader,
        ipmi_v2_header::{IpmiV2Header, PayloadType},
        payload::{
            ipmi_payload::{IpmiPayload, NetFn},
            ipmi_payload_request::IpmiPayloadRequest,
        },
    },
    packet::packet::Packet,
};
use bitvec::prelude::*;

pub struct GetChannelCipherSuitesRequest {
    pub channel_number: u8,
    pub payload_type: PayloadType,
    pub list_algo_cipher_suite: bool,
    pub list_index: u8,
}

impl GetChannelCipherSuitesRequest {
    pub fn new(
        channel_number: u8,
        payload_type: PayloadType,
        list_algo_cipher_suite: bool,
        list_index: u8,
    ) -> GetChannelCipherSuitesRequest {
        GetChannelCipherSuitesRequest {
            channel_number,
            payload_type,
            list_algo_cipher_suite,
            list_index,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(join_two_bits_to_byte(0, self.channel_number, 4));
        result.push(join_two_bits_to_byte(0, self.payload_type.to_u8(), 3));
        result.push({
            let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
            *bv.get_mut(0).unwrap() = self.list_algo_cipher_suite;
            bv[2..].store::<u8>(self.list_index);
            let list_index = bv[..].load::<u8>();
            list_index
        });
        result
    }

    pub fn create_packet(&self, con: &Connection) -> Packet {
        let data_bytes = self.to_bytes();
        // println!("{:x?}", data_bytes);
        let packet = Packet::new(
            IpmiHeader::V2_0(IpmiV2Header {
                auth_type: con.auth_type,
                payload_enc: false,
                payload_auth: false,
                payload_type: PayloadType::IPMI,
                oem_iana: None,
                oem_payload_id: None,
                rmcp_plus_session_id: 0x0,
                session_seq_number: 0x0,
                payload_length: ((data_bytes.len() as u8) + 7).try_into().unwrap(),
            }),
            Payload::Ipmi(IpmiPayload::Request(IpmiPayloadRequest::new(
                NetFn::App,
                Command::GetChannelCipherSuites,
                Some(data_bytes),
            ))),
        );
        packet
    }
}

impl Default for GetChannelCipherSuitesRequest {
    fn default() -> Self {
        GetChannelCipherSuitesRequest {
            channel_number: 0xe,
            payload_type: PayloadType::IPMI,
            list_algo_cipher_suite: true,
            list_index: 0x0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GetChannelCipherSuitesResponse {
    /*
    2 bytes Channel Number
    Channel number that the Authentication Algorithms are being returned
    for. If the channel number in the request was set to Eh, this will return
    the channel number for the channel that the request was received on.

    (3:18) bytes Cipher Suite Record data bytes, per Table 22-19, Cipher Suite Record
    Format. Record data is ‘packed’; there are no pad bytes between records. It is
    possible that record data will span across multiple List Index values.
    The BMC returns sixteen (16) bytes at a time per index, starting from index
    00h, until the list data is exhausted, at which point it will 0 bytes or <16 bytes
    of list data.
     */
    pub channel_number: u8,
    pub cypher_suite_record_data_bytes: Vec<u8>,
}

impl GetChannelCipherSuitesResponse {
    pub fn from_slice(slice: &[u8]) -> GetChannelCipherSuitesResponse {
        GetChannelCipherSuitesResponse {
            channel_number: slice[0],
            cypher_suite_record_data_bytes: {
                let mut vec = Vec::new();
                vec.extend_from_slice(&slice[1..]);
                vec
            },
        }
    }

    pub fn is_last(&self) -> bool {
        if self.cypher_suite_record_data_bytes.len() < 16 {
            return true;
        } else {
            return false;
        }
    }
}

//
