use crate::{
    commands::Command,
    err::{IpmiPayloadError, IpmiPayloadRequestError},
    helpers::utils::{get8bit_checksum, join_two_bits_to_byte},
};
use bitvec::{field::BitField, order::Msb0, slice::BitSlice};

use super::{
    ipmi_payload::{CommandType, Lun, NetFn, SlaveAddress, SoftwareType},
    ipmi_payload_response::Address,
};

#[derive(Clone)]
pub struct IpmiPayloadRequest {
    pub rs_addr: Address,
    pub net_fn: NetFn,
    pub rs_lun: Lun,
    // checksum 1
    pub rq_addr: Address,
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
        let netfn_rqlun = BitSlice::<u8, Msb0>::from_element(&value[1]);
        let rqseq_rslun = BitSlice::<u8, Msb0>::from_element(&value[4]);

        let net_fn: NetFn = netfn_rqlun[0..6].load::<u8>().into();

        Ok(IpmiPayloadRequest {
            rs_addr: value[0].into(),
            net_fn: net_fn.clone(),
            rs_lun: netfn_rqlun[7..8].load::<u8>().try_into()?,
            rq_addr: value[3].into(),
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
        let rs_addr = self.rs_addr.into();
        let net_fn_rs_lun = join_two_bits_to_byte(
            self.net_fn.to_u8(CommandType::Request),
            self.rs_lun.clone().into(),
            6,
        );
        let checksum1 = get8bit_checksum(&[rs_addr, net_fn_rs_lun]);
        let rq_addr = self.rq_addr.into();
        let rq_seq_rq_lun = join_two_bits_to_byte(self.rq_sequence, self.rs_lun.into(), 6);
        let command_code = self.command.into();
        result.push(rs_addr);
        result.push(net_fn_rs_lun);
        result.push(checksum1);
        result.push(rq_addr);
        result.push(rq_seq_rq_lun);
        result.push(command_code);
        if let Some(data) = &self.data {
            result.extend(data);
        }
        result.push(get8bit_checksum(&result[3..]));
        result
    }
}

impl IpmiPayloadRequest {
    pub fn new(net_fn: NetFn, command: Command, data: Option<Vec<u8>>) -> IpmiPayloadRequest {
        IpmiPayloadRequest {
            rs_addr: Address::Slave(SlaveAddress::Bmc),
            net_fn,
            rs_lun: Lun::Bmc,
            rq_addr: Address::Software(SoftwareType::RemoteConsoleSoftware(1)),
            rq_sequence: 0x8,
            rq_lun: Lun::Bmc,
            command,
            data,
        }
    }

    // pub fn payload_length(&self) -> usize {
    //     match &self.data {
    //         Some(x) => 7 + x.len(),
    //         None => 7,
    //     }
    // }
}

impl Default for IpmiPayloadRequest {
    fn default() -> Self {
        Self {
            rs_addr: Address::Slave(SlaveAddress::Bmc),
            net_fn: NetFn::App,
            rs_lun: Lun::Bmc,
            rq_addr: Address::Software(SoftwareType::RemoteConsoleSoftware(1)),
            rq_sequence: 0x00,
            rq_lun: Lun::Bmc,
            command: Command::GetChannelAuthCapabilities,
            data: None,
        }
    }
}
