use bitvec::{field::BitField, order::Msb0, slice::BitSlice};

use crate::ipmi::data::commands::Command;

use super::{
    ipmi_payload::{AddrType, Lun, NetFn, SlaveAddress, SoftwareType},
    ipmi_payload_response::{CompletionCode, IpmiPayloadResponse},
};

pub struct IpmiPayloadResponseSlice<'a> {
    slice: &'a [u8],
}

impl<'a> IpmiPayloadResponseSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<IpmiPayloadResponseSlice<'a>, std::io::ErrorKind> {
        // todo: implement error checking
        Ok(IpmiPayloadResponseSlice::<'a> {
            slice: unsafe { core::slice::from_raw_parts(slice.as_ptr(), slice.len()) },
        })
    }

    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    pub fn rs_addr_type(&self) -> AddrType {
        let rs_addr_byte: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[3]);
        AddrType::from_bool(rs_addr_byte[0])
    }

    pub fn rs_slave_address_type(&self) -> Option<SlaveAddress> {
        let rs_addr_byte = BitSlice::<u8, Msb0>::from_element(&self.slice[3]);
        let last_bits = rs_addr_byte[1..].load::<u8>();
        match self.rs_addr_type() {
            AddrType::SlaveAddress => Some(SlaveAddress::from_u8(last_bits)),
            AddrType::SoftwareId => None,
        }
    }

    pub fn rs_software_type(&self) -> Option<SoftwareType> {
        let rs_addr_byte = BitSlice::<u8, Msb0>::from_element(&self.slice[3]);
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
        let rqseq_rslun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[3]);
        let rslun_slice = &rqseq_rslun[7..8];
        let rslun = rslun_slice[..].load::<u8>();
        Lun::from_u8(rslun)
    }

    pub fn rq_addr_type(&self) -> AddrType {
        let rq_addr_byte: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[0]);
        AddrType::from_bool(rq_addr_byte[0])
    }

    pub fn rq_slave_address_type(&self) -> Option<SlaveAddress> {
        let rq_addr_byte = BitSlice::<u8, Msb0>::from_element(&self.slice[0]);
        let last_bits = rq_addr_byte[1..].load::<u8>();
        match self.rq_addr_type() {
            AddrType::SlaveAddress => Some(SlaveAddress::from_u8(last_bits)),
            AddrType::SoftwareId => None,
        }
    }

    pub fn rq_software_type(&self) -> Option<SoftwareType> {
        let rq_addr_byte = BitSlice::<u8, Msb0>::from_element(&self.slice[0]);
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
        let rqseq_rslun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&self.slice[1]);
        let rslun_slice = &rqseq_rslun[7..8];
        let rslun = rslun_slice[..].load::<u8>();
        Lun::from_u8(rslun)
    }

    pub fn command(&self) -> Command {
        Command::from_u8_and_netfn(self.slice[5], self.net_fn())
    }
    pub fn completion_code(&self) -> CompletionCode {
        CompletionCode::from_u8(self.slice[6])
    }

    // return the data slice as a vector
    pub fn data(&self) -> Vec<u8> {
        let len = self.slice().len() - 1;
        // println!("{}", self.slice().len());
        Vec::from(&self.slice()[7..len])
    }

    pub fn to_header(&self) -> IpmiPayloadResponse {
        IpmiPayloadResponse {
            rq_addr_type: self.rq_addr_type(),
            rq_slave_address_type: self.rq_slave_address_type(),
            rq_software_type: self.rq_software_type(),
            net_fn: self.net_fn(),
            rq_lun: self.rq_lun(),
            rs_addr_type: self.rs_addr_type(),
            rs_slave_address_type: self.rs_slave_address_type(),
            rs_software_type: self.rs_software_type(),
            rq_sequence: self.rq_sequence(),
            rs_lun: self.rs_lun(),
            command: self.command(),
            completion_code: self.completion_code(),
            data: self.data(),
        }
    }
}
