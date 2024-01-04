use bitvec::{field::BitField, order::Msb0, slice::BitSlice};
use std::fmt::Debug;

use crate::{
    err::{IpmiPayloadError, IpmiPayloadRequestError},
    helpers::utils::{get8bit_checksum, join_two_bits_to_byte},
    ipmi::data::commands::Command,
};

use super::ipmi_payload::{AddrType, CommandType, Lun, NetFn, SlaveAddress, SoftwareType};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
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
    pub data: Option<Vec<u8>>,
    // checksum 2
}

impl TryFrom<&[u8]> for IpmiPayloadRequest {
    type Error = IpmiPayloadError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 7 {
            Err(IpmiPayloadRequestError::WrongLength)?
        }
        let rs_addr_byte = BitSlice::<u8, Msb0>::from_element(&value[0]);
        let rq_addr_byte = BitSlice::<u8, Msb0>::from_element(&value[3]);

        let rs_addr_type: AddrType = rs_addr_byte[0].into();
        let rq_addr_type: AddrType = rq_addr_byte[0].into();

        let netfn_rqlun = BitSlice::<u8, Msb0>::from_element(&value[1]);
        let rqseq_rslun = BitSlice::<u8, Msb0>::from_element(&value[4]);

        let net_fn: NetFn = netfn_rqlun[0..6].load::<u8>().try_into()?;

        Ok(IpmiPayloadRequest {
            rs_addr_type,
            rs_slave_address_type: match rs_addr_type {
                AddrType::SlaveAddress => Some(rs_addr_byte[1..].load::<u8>().into()),
                AddrType::SoftwareId => None,
            },
            rs_software_type: match rs_addr_type {
                AddrType::SoftwareId => Some(rs_addr_byte[1..].load::<u8>().into()),
                AddrType::SlaveAddress => None,
            },
            net_fn: net_fn.clone(),
            rs_lun: netfn_rqlun[7..8].load::<u8>().try_into()?,
            rq_addr_type,
            rq_slave_address_type: match rq_addr_type {
                AddrType::SlaveAddress => Some(rq_addr_byte[1..].load::<u8>().into()),
                AddrType::SoftwareId => None,
            },
            rq_software_type: match rq_addr_type {
                AddrType::SoftwareId => Some(rq_addr_byte[1..].load::<u8>().into()),
                AddrType::SlaveAddress => None,
            },
            rq_sequence: rqseq_rslun[0..6].load::<u8>(),
            rq_lun: rqseq_rslun[7..8].load::<u8>().try_into()?,
            command: (value[5], net_fn.into()).try_into()?,
            data: {
                let len = value.len() - 1;
                if len == 6 {
                    None
                } else {
                    Some(value[6..len].into())
                }
            },
        })
    }
}

impl Into<Vec<u8>> for IpmiPayloadRequest {
    fn into(self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        let rs_addr = join_two_bits_to_byte(
            self.rs_addr_type.into(),
            {
                match &self.rs_slave_address_type {
                    Some(a) => a.clone().into(),
                    None => match &self.rs_software_type {
                        Some(a) => a.clone().into(),
                        _ => 0x00,
                    },
                }
            },
            1,
        );
        let net_fn_rs_lun = join_two_bits_to_byte(
            self.net_fn.to_u8(CommandType::Request),
            self.rs_lun.clone().into(),
            6,
        );
        let checksum1 = get8bit_checksum(&[rs_addr, net_fn_rs_lun]);
        let rq_addr = join_two_bits_to_byte(
            self.rq_addr_type.into(),
            {
                match &self.rq_slave_address_type {
                    Some(a) => a.clone().into(),
                    None => match &self.rq_software_type {
                        Some(a) => a.clone().into(),
                        _ => 0x00,
                    },
                }
            },
            2,
        );
        let rq_seq_rq_lun = join_two_bits_to_byte(self.rq_sequence, self.rs_lun.into(), 6);
        let command_code = self.command.into();
        // let data = self.data.as_slice();
        result.push(rs_addr);
        result.push(net_fn_rs_lun);
        result.push(checksum1);
        result.push(rq_addr);
        result.push(rq_seq_rq_lun);
        result.push(command_code);
        if let Some(data) = &self.data {
            result.extend(data);
            // for &byte in data.iter() {
            //     result.push(byte);
            // }
        }
        // println!("bytes: {:x?}", &result);
        result.push(get8bit_checksum(&result[3..]));
        result
    }
}

impl IpmiPayloadRequest {
    pub fn new(net_fn: NetFn, command: Command, data: Option<Vec<u8>>) -> IpmiPayloadRequest {
        IpmiPayloadRequest {
            rs_addr_type: AddrType::SlaveAddress,
            rs_slave_address_type: Some(SlaveAddress::Bmc),
            rs_software_type: None,
            net_fn,
            rs_lun: Lun::Bmc,
            rq_addr_type: AddrType::SoftwareId,
            rq_slave_address_type: None,
            rq_software_type: Some(SoftwareType::RemoteConsoleSoftware(1)),
            rq_sequence: 0x8,
            rq_lun: Lun::Bmc,
            command,
            data,
        }
    }

    pub fn payload_length(&self) -> usize {
        match &self.data {
            Some(x) => 7 + x.len(),
            None => 7,
        }
    }
}

impl Default for IpmiPayloadRequest {
    fn default() -> Self {
        Self {
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
            data: None,
        }
    }
}
