use std::fmt::Debug;

use arrayvec::ArrayVec;
use bitvec::vec;

use crate::ipmi::{
    data::commands::Command, payload::ipmi_payload_request_slice::IpmiPayloadRequestSlice,
};

use super::ipmi_payload::{AddrType, Lun, NetFn, SlaveAddress, SoftwareType};

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
    pub data: Vec<u8>, // pub data: Option<dyn Data>,
}

impl IpmiPayloadRequest {
    pub const MAX_PAYLOAD_LENGTH: usize = 0xff;

    pub fn new(net_fn: NetFn, command: Command) -> IpmiPayloadRequest {
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
            data: vec![], // data: None,
        }
    }

    // returns the payload as an object and the length of the payload
    pub fn from_slice(slice: &[u8]) -> Result<(IpmiPayloadRequest, &[u8]), std::io::ErrorKind> {
        let h = IpmiPayloadRequestSlice::from_slice(slice)?;
        // println!("{:x?}", h);
        // Ok(h.to_header())
        Ok((h.to_header(), &slice[h.slice().len()..]))
    }
}
