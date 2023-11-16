use bitvec::{field::BitField, order::Msb0, slice::BitSlice};

use crate::ipmi::data::commands::{self, Command};

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

    pub fn rs_addr_type(&self) -> AddrType {
        let rs_addr_byte: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[0]);
        AddrType::from_bool(rs_addr_byte[0])
    }

    pub fn rs_slave_address_type(&self) -> Option<SlaveAddress> {
        let rs_addr_byte = BitSlice::<u8, Msb0>::from_element(&self.slice[0]);
        let last_bits = rs_addr_byte[1..].load::<u8>();
        match self.rs_addr_type() {
            AddrType::SlaveAddress => Some(SlaveAddress::from_u8(last_bits)),
            AddrType::SoftwareId => None,
        }
    }

    pub fn rs_software_type(&self) -> Option<SoftwareType> {
        let rs_addr_byte = BitSlice::<u8, Msb0>::from_element(&self.slice[0]);
        let last_bits = rs_addr_byte[1..].load::<u8>();
        match self.rs_addr_type() {
            AddrType::SlaveAddress => None,
            AddrType::SoftwareId => Some(SoftwareType::from_u8(last_bits)),
        }
    }

    pub fn net_fn(&self) -> NetFn {
        let netfn_rqlun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[1]);
        let netfn_slice = &netfn_rqlun[0..6];
        let netfn = netfn_slice[..].load::<u8>();
        NetFn::from_u8(netfn)
    }

    pub fn rs_lun(&self) -> Lun {
        let rqseq_rslun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[1]);
        let rslun_slice = &rqseq_rslun[7..8];
        let rslun = rslun_slice[..].load::<u8>();
        Lun::from_u8(rslun)
    }

    pub fn rq_addr_type(&self) -> AddrType {
        let rq_addr_byte: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[3]);
        AddrType::from_bool(rq_addr_byte[0])
    }

    pub fn rq_slave_address_type(&self) -> Option<SlaveAddress> {
        let rq_addr_byte = BitSlice::<u8, Msb0>::from_element(&self.slice[3]);
        let last_bits = rq_addr_byte[1..].load::<u8>();
        match self.rq_addr_type() {
            AddrType::SlaveAddress => Some(SlaveAddress::from_u8(last_bits)),
            AddrType::SoftwareId => None,
        }
    }

    pub fn rq_software_type(&self) -> Option<SoftwareType> {
        let rq_addr_byte = BitSlice::<u8, Msb0>::from_element(&self.slice[3]);
        let last_bits = rq_addr_byte[1..].load::<u8>();
        match self.rq_addr_type() {
            AddrType::SlaveAddress => None,
            AddrType::SoftwareId => Some(SoftwareType::from_u8(last_bits)),
        }
    }

    pub fn rq_sequence(&self) -> u8 {
        let rqseq_rslun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[4]);
        let rqseq_slice = &rqseq_rslun[0..6];
        rqseq_slice[..].load::<u8>()
    }

    pub fn rq_lun(&self) -> Lun {
        let rqseq_rslun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[4]);
        let rslun_slice = &rqseq_rslun[7..8];
        let rslun = rslun_slice[..].load::<u8>();
        Lun::from_u8(rslun)
    }

    pub fn command(&self) -> Command {
        Command::from_u8_and_netfn(self.slice[5], self.net_fn())
    }

    // return the data slice as a vector
    pub fn data(&self) -> Vec<u8> {
        Vec::from(&self.slice()[7..&self.slice().len() - 1])
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
            data: self.data(),
        }
    }
}
