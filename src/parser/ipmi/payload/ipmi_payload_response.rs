// use bitvec::prelude::*;
use bitvec::{field::BitField, order::Msb0, slice::BitSlice};

use crate::{
    err::{IpmiPayloadError, IpmiPayloadRequestError},
    ipmi::data::commands::Command,
};

use super::ipmi_payload::{AddrType, Lun, NetFn, SlaveAddress, SoftwareType};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IpmiPayloadResponse {
    pub rq_addr_type: AddrType,
    pub rq_slave_address_type: Option<SlaveAddress>,
    pub rq_software_type: Option<SoftwareType>,
    pub net_fn: NetFn,
    pub rq_lun: Lun,
    // checksum 1
    pub rs_addr_type: AddrType,
    pub rs_slave_address_type: Option<SlaveAddress>,
    pub rs_software_type: Option<SoftwareType>,
    pub rq_sequence: u8,
    pub rs_lun: Lun,
    pub command: Command,
    pub completion_code: CompletionCode,
    pub data: Option<Vec<u8>>,
    // checksum 2
}

impl TryFrom<&[u8]> for IpmiPayloadResponse {
    type Error = IpmiPayloadError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 8 {
            Err(IpmiPayloadRequestError::WrongLength)?
        }
        let rq_addr_byte = BitSlice::<u8, Msb0>::from_element(&value[0]);
        let rs_addr_byte = BitSlice::<u8, Msb0>::from_element(&value[3]);

        let rs_addr_type: AddrType = rs_addr_byte[0].into();
        let rq_addr_type: AddrType = rq_addr_byte[0].into();

        let netfn_rqlun = BitSlice::<u8, Msb0>::from_element(&value[1]);
        let rqseq_rslun = BitSlice::<u8, Msb0>::from_element(&value[4]);

        let net_fn: NetFn = netfn_rqlun[0..6].load::<u8>().try_into()?;

        Ok(IpmiPayloadResponse {
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
            rq_lun: netfn_rqlun[7..8].load::<u8>().try_into()?,
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
            rs_lun: rqseq_rslun[7..8].load::<u8>().try_into()?,
            command: (value[5], net_fn.into()).try_into()?,
            completion_code: value[6].into(),
            data: {
                let len = value.len() - 1;
                if len == 7 {
                    None
                } else {
                    Some(value[7..len].into())
                }
            },
        })
    }
}

impl IpmiPayloadResponse {
    pub fn payload_length(&self) -> usize {
        match &self.data {
            Some(d) => d.len() + 8,
            None => 8,
        }
    }

    // returns the payload as an object and the length of the payload
    // pub fn from_slice(slice: &[u8]) -> IpmiPayloadResponse {
    //     let h = IpmiPayloadResponseSlice::from_slice(slice).unwrap();
    //     // println!("{:x?}", h.to_header());
    //     // Ok(h.to_header())
    //     h.to_header()
    // }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum CompletionCode {
    CompletedNormally,
    NodeBusy,
    InvalidCommand,
    InvalidCommandForLun,
    Timeout,
    OutOfSpace,
    ReservationCancelled,
    RequestDataTruncated,
    RequestDataLengthInvalid,
    RequestDataFieldLengthLimitExceeded,
    ParameterOutOfRange,
    CannotReturnNumberOfRqDataBytes,
    RqSensorDataRecordNotPresent,
    InvalidDataFieldInRequest,
    CommandIllegalForSensor,
    CommandResponseNotProvided,
    CantExecuteDuplicateRq,
    FailedSDRUpdateMode,
    FailedDevFirmwareMode,
    FailedInitInProgress,
    DestinationUnavailable,
    CannotExecuteCommandInsuffientPrivileges,
    CommandSubFunctionUnavailable,
    CannotExecuteCommandIllegalParam,
    UnspecifiedError,
    OEM(u8),
    CommandCode(u8),
    Reserved(u8),
}

impl From<u8> for CompletionCode {
    fn from(value: u8) -> Self {
        match value {
            0x0 => CompletionCode::CompletedNormally,
            0xc0 => CompletionCode::NodeBusy,
            0xc1 => CompletionCode::InvalidCommand,
            0xc2 => CompletionCode::InvalidCommandForLun,
            0xc3 => CompletionCode::Timeout,
            0xc4 => CompletionCode::OutOfSpace,
            0xc5 => CompletionCode::ReservationCancelled,
            0xc6 => CompletionCode::RequestDataTruncated,
            0xc7 => CompletionCode::RequestDataLengthInvalid,
            0xc8 => CompletionCode::RequestDataFieldLengthLimitExceeded,
            0xc9 => CompletionCode::ParameterOutOfRange,
            0xca => CompletionCode::CannotReturnNumberOfRqDataBytes,
            0xcb => CompletionCode::RqSensorDataRecordNotPresent,
            0xcc => CompletionCode::InvalidDataFieldInRequest,
            0xcd => CompletionCode::CommandIllegalForSensor,
            0xce => CompletionCode::CommandResponseNotProvided,
            0xcf => CompletionCode::CantExecuteDuplicateRq,
            0xd0 => CompletionCode::FailedSDRUpdateMode,
            0xd1 => CompletionCode::FailedDevFirmwareMode,
            0xd2 => CompletionCode::FailedInitInProgress,
            0xd3 => CompletionCode::DestinationUnavailable,
            0xd4 => CompletionCode::CannotExecuteCommandInsuffientPrivileges,
            0xd5 => CompletionCode::CommandSubFunctionUnavailable,
            0xd6 => CompletionCode::CannotExecuteCommandIllegalParam,
            0xff => CompletionCode::UnspecifiedError,
            0x01..=0x7e => CompletionCode::OEM(value),
            0x80..=0xbe => CompletionCode::CommandCode(value),
            _ => CompletionCode::Reserved(value),
        }
    }
}

impl CompletionCode {
    pub fn from_u8(code: u8) -> CompletionCode {
        match code {
            0x0 => CompletionCode::CompletedNormally,
            0xc0 => CompletionCode::NodeBusy,
            0xc1 => CompletionCode::InvalidCommand,
            0xc2 => CompletionCode::InvalidCommandForLun,
            0xc3 => CompletionCode::Timeout,
            0xc4 => CompletionCode::OutOfSpace,
            0xc5 => CompletionCode::ReservationCancelled,
            0xc6 => CompletionCode::RequestDataTruncated,
            0xc7 => CompletionCode::RequestDataLengthInvalid,
            0xc8 => CompletionCode::RequestDataFieldLengthLimitExceeded,
            0xc9 => CompletionCode::ParameterOutOfRange,
            0xca => CompletionCode::CannotReturnNumberOfRqDataBytes,
            0xcb => CompletionCode::RqSensorDataRecordNotPresent,
            0xcc => CompletionCode::InvalidDataFieldInRequest,
            0xcd => CompletionCode::CommandIllegalForSensor,
            0xce => CompletionCode::CommandResponseNotProvided,
            0xcf => CompletionCode::CantExecuteDuplicateRq,
            0xd0 => CompletionCode::FailedSDRUpdateMode,
            0xd1 => CompletionCode::FailedDevFirmwareMode,
            0xd2 => CompletionCode::FailedInitInProgress,
            0xd3 => CompletionCode::DestinationUnavailable,
            0xd4 => CompletionCode::CannotExecuteCommandInsuffientPrivileges,
            0xd5 => CompletionCode::CommandSubFunctionUnavailable,
            0xd6 => CompletionCode::CannotExecuteCommandIllegalParam,
            0xff => CompletionCode::UnspecifiedError,
            0x01..=0x7e => CompletionCode::OEM(code),
            0x80..=0xbe => CompletionCode::CommandCode(code),
            _ => CompletionCode::Reserved(code),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            CompletionCode::CompletedNormally => 0x00,
            CompletionCode::NodeBusy => 0xc0,
            CompletionCode::InvalidCommand => 0xc1,
            CompletionCode::InvalidCommandForLun => 0xc2,
            CompletionCode::Timeout => 0xc3,
            CompletionCode::OutOfSpace => 0xc4,
            CompletionCode::ReservationCancelled => 0xc5,
            CompletionCode::RequestDataTruncated => 0xc6,
            CompletionCode::RequestDataLengthInvalid => 0xc7,
            CompletionCode::RequestDataFieldLengthLimitExceeded => 0xc8,
            CompletionCode::ParameterOutOfRange => 0xc9,
            CompletionCode::CannotReturnNumberOfRqDataBytes => 0xca,
            CompletionCode::RqSensorDataRecordNotPresent => 0xcb,
            CompletionCode::InvalidDataFieldInRequest => 0xcc,
            CompletionCode::CommandIllegalForSensor => 0xcd,
            CompletionCode::CommandResponseNotProvided => 0xce,
            CompletionCode::CantExecuteDuplicateRq => 0xcf,
            CompletionCode::FailedSDRUpdateMode => 0xd0,
            CompletionCode::FailedDevFirmwareMode => 0xd1,
            CompletionCode::FailedInitInProgress => 0xd2,
            CompletionCode::DestinationUnavailable => 0xd3,
            CompletionCode::CannotExecuteCommandInsuffientPrivileges => 0xd4,
            CompletionCode::CommandSubFunctionUnavailable => 0xd5,
            CompletionCode::CannotExecuteCommandIllegalParam => 0xd6,
            CompletionCode::UnspecifiedError => 0xff,
            CompletionCode::OEM(code) => *code,
            CompletionCode::CommandCode(code) => *code,
            CompletionCode::Reserved(code) => *code,
        }
    }
}
