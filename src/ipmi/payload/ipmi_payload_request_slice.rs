use crate::ipmi::data::commands::Command;

use super::{
    ipmi_payload::{AddrType, Lun, NetFn, SlaveAddress, SoftwareType},
    ipmi_payload_request::IpmiPayloadRequest,
};

pub struct IpmiPayloadRequestSlice<'a> {
    slice: &'a [u8],
}

impl<'a> IpmiPayloadRequestSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<IpmiPayloadRequestSlice<'a>, std::io::ErrorKind> {
        // todo: implement error checking
        Ok(IpmiPayloadRequestSlice::<'a> {
            slice: unsafe { core::slice::from_raw_parts(slice.as_ptr(), slice.len()) },
        })
    }

    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    pub fn to_header(&self) -> IpmiPayloadRequest {
        IpmiPayloadRequest {
            rs_addr_type: AddrType::SlaveAddress,
            rs_slave_address_type: Some(SlaveAddress::Bmc),
            rs_software_type: None,
            net_fn: NetFn::App,
            rs_lun: Lun::Bmc,
            rq_addr_type: AddrType::SoftwareId,
            rq_slave_address_type: None,
            rq_software_type: Some(SoftwareType::RemoteConsoleSoftware(1)),
            rq_sequence: 0x00,
            rq_lun: Lun::Bmc,
            command: Command::GetChannelAuthCapabilities,
            data: None, //{ Comm },
        }
    }
}
