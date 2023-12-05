use crate::{
    connection::Connection, helpers::utils::join_two_bits_to_byte,
    ipmi::ipmi_v2_header::PayloadType, packet::packet::Packet,
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

    pub fn create_packet(
        &self,
        con: &Connection,
        session_seq_number: u32,
        session_id: u32,
        auth_code: Option<u128>,
    ) -> Packet {
        todo!();
        // let data_bytes = self.to_bytes();
        // println!("{:x?}", data_bytes);
        // let packet = Packet::new(
        //     IpmiHeader::V1_5(IpmiV1Header {
        //         auth_type: con.auth_type,
        //         session_seq_number,
        //         session_id,
        //         auth_code,
        //         payload_length: (data_bytes.len() as u8) + 7,
        //     }),
        //     IpmiPayload::Request(IpmiPayloadRequest::new(
        //         NetFn::App,
        //         Command::GetChannelAuthCapabilities,
        //         data_bytes,
        //     )),
        // );
        // packet
    }
}
