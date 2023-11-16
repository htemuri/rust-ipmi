use std::fmt::Debug;

// use bitvec::{bitvec, order::Msb0, vec::BitVec};
use bitvec::prelude::*;

use crate::ipmi::{
    data::{self, commands::Command},
    payload::ipmi_payload_request_slice::IpmiPayloadRequestSlice,
};

use super::ipmi_payload::{AddrType, CommandType, Lun, NetFn, SlaveAddress, SoftwareType};

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct IpmiPayloadRequest {
    pub rs_addr_type: AddrType,
    pub rs_slave_address_type: Option<SlaveAddress>,
    pub rs_software_type: Option<SoftwareType>,
    pub net_fn: NetFn,
    pub rs_lun: Lun,
    // checksum 1
    pub rq_addr_type: AddrType,
    pub rq_slave_address_type: Option<SlaveAddress>,
    pub rq_software_type: Option<SoftwareType>,
    pub rq_sequence: u8,
    pub rq_lun: Lun,
    pub command: Command,
    pub data: Vec<u8>,
    // checksum 2
}

impl IpmiPayloadRequest {
    pub const MAX_PAYLOAD_LENGTH: usize = 0xff;

    pub fn new(net_fn: NetFn, command: Command, data: Vec<u8>) -> IpmiPayloadRequest {
        IpmiPayloadRequest {
            rs_addr_type: AddrType::SlaveAddress,
            rs_slave_address_type: Some(SlaveAddress::Bmc),
            rs_software_type: None,
            net_fn,
            rs_lun: Lun::Bmc,
            rq_addr_type: AddrType::SoftwareId,
            rq_slave_address_type: None,
            rq_software_type: Some(SoftwareType::RemoteConsoleSoftware(1)),
            rq_sequence: 0x00,
            rq_lun: Lun::Bmc,
            command,
            data,
        }
    }

    fn join_two_bits_to_byte(first: u8, second: u8, split_index: usize) -> u8 {
        let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
        bv[..split_index].store::<u8>(first);
        bv[split_index..].store::<u8>(second);
        bv[..].load::<u8>()
    }

    fn get8bit_checksum(byte_array: &[u8]) -> u8 {
        let answer: u8 = byte_array.iter().fold(0, |a, &b| a.wrapping_add(b));
        255 - answer + 1
    }

    pub fn payload_length(&self) -> usize {
        self.data.len() + 7
    }

    // returns the payload as an object and the length of the payload
    pub fn from_slice(slice: &[u8]) -> Result<(IpmiPayloadRequest, &[u8]), std::io::ErrorKind> {
        let h = IpmiPayloadRequestSlice::from_slice(slice)?;
        // println!("{:x?}", h);
        // Ok(h.to_header())
        Ok((h.to_header(), &slice[h.slice().len()..]))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        let rs_addr = Self::join_two_bits_to_byte(
            self.rs_addr_type.to_u8(),
            {
                match &self.rs_slave_address_type {
                    Some(a) => a.to_u8(),
                    None => match &self.rs_software_type {
                        Some(a) => a.to_u8(),
                        _ => 0x00,
                    },
                }
            },
            1,
        );
        let net_fn_rs_lun = Self::join_two_bits_to_byte(
            self.net_fn.to_u8(CommandType::Request),
            self.rs_lun.to_u8(),
            6,
        );
        let checksum1 = Self::get8bit_checksum(&[rs_addr, net_fn_rs_lun]);
        let rq_addr = Self::join_two_bits_to_byte(
            self.rq_addr_type.to_u8(),
            {
                match &self.rq_slave_address_type {
                    Some(a) => a.to_u8(),
                    None => match &self.rq_software_type {
                        Some(a) => a.to_u8(),
                        _ => 0x00,
                    },
                }
            },
            1,
        );
        let rq_seq_rq_lun = Self::join_two_bits_to_byte(self.rq_sequence, self.rs_lun.to_u8(), 6);
        let command_code = self.command.to_u8();
        let data = self.data.as_slice();
        result.push(rs_addr);
        result.push(net_fn_rs_lun);
        result.push(checksum1);
        result.push(rq_addr);
        result.push(rq_seq_rq_lun);
        result.push(command_code);
        for &byte in data.iter() {
            result.push(byte);
        }
        result.push(Self::get8bit_checksum(&result[3..]));
        result
    }
}
