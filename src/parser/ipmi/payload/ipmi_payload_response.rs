use std::fmt;

// use bitvec::prelude::*;
use bitvec::{field::BitField, order::Msb0, slice::BitSlice};

use crate::{
    commands::Command,
    err::{IpmiPayloadError, IpmiPayloadRequestError},
};

use super::ipmi_payload::{AddrType, Lun, NetFn, SlaveAddress, SoftwareType};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IpmiPayloadResponse {
    pub rq_addr: Address,
    pub net_fn: NetFn,
    pub rq_lun: Lun,
    // checksum 1
    pub rs_addr: Address,
    pub rq_sequence: u8,
    pub rs_lun: Lun,
    pub command: Command,
    pub completion_code: CompletionCode,
    pub data: Option<Vec<u8>>,
    // checksum 2
}

impl fmt::Display for IpmiPayloadResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data: String = match self.data.clone() {
            Some(x) => format!("{:x?}", x),
            None => "None".to_string(),
        };
        write!(
            f,
            "IPMI Response:\n\tRequester Address: {}\n\tNetFn: {}\n\tRequester LUN: {}\n\tResponder Address: {}\n\tRequester Sequence Number: {}\n\tResponder LUN: {}\n\tCommand: {}\n\tCompletion Code: {}\n\tDate: {}",
            self.rq_addr,
            self.net_fn,
            self.rq_lun,
            self.rs_addr,
            self.rq_sequence,
            self.rs_lun,
            self.command,
            self.completion_code,
            data
        )
    }
}

impl TryFrom<&[u8]> for IpmiPayloadResponse {
    type Error = IpmiPayloadError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 8 {
            Err(IpmiPayloadRequestError::WrongLength)?
        }
        let netfn_rqlun = BitSlice::<u8, Msb0>::from_element(&value[1]);
        let rqseq_rslun = BitSlice::<u8, Msb0>::from_element(&value[4]);
        let net_fn: NetFn = netfn_rqlun[0..6].load::<u8>().into();

        Ok(IpmiPayloadResponse {
            rq_addr: value[0].into(),
            net_fn: net_fn.clone(),
            rq_lun: netfn_rqlun[7..8].load::<u8>().try_into()?,
            rs_addr: value[3].into(),
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
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Address {
    Slave(SlaveAddress),
    Software(SoftwareType),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Slave(x) => write!(f, "{}", x),
            Address::Software(x) => write!(f, "{}", x),
        }
    }
}

impl From<u8> for Address {
    fn from(value: u8) -> Self {
        let bitslice = BitSlice::<u8, Msb0>::from_element(&value);
        let rs_addr_type: AddrType = bitslice[0].into();
        match rs_addr_type {
            AddrType::SlaveAddress => Self::Slave(bitslice[1..].load::<u8>().into()),
            AddrType::SoftwareId => Self::Software(bitslice[1..].load::<u8>().into()),
        }
    }
}

impl Into<u8> for Address {
    fn into(self) -> u8 {
        match self {
            Self::Slave(s) => s.into(),
            Self::Software(s) => s.into(),
        }
    }
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

impl fmt::Display for CompletionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompletionCode::CompletedNormally => write!(f, "Command Completed Normally"),
            CompletionCode::NodeBusy => write!(f, "Node Busy. Command could not be processed because command processing resources are temporarily unavailable"),
            CompletionCode::InvalidCommand => write!(f, "Invalid Command. Used to indicate an unrecognized or unsupported command"),
            CompletionCode::InvalidCommandForLun => write!(f, "Command invalid for given LUN"),
            CompletionCode::Timeout => write!(f, "Timeout while processing command. Response unavailable"),
            CompletionCode::OutOfSpace => write!(f, "Out of space. Command could not be completed because of a lack of storage space required to execute the given command operation"),
            CompletionCode::ReservationCancelled => write!(f, "Reservation Canceled or Invalid Reservation ID"),
            CompletionCode::RequestDataTruncated => write!(f, "Request data truncated"),
            CompletionCode::RequestDataLengthInvalid => write!(f, "Request data length invalid"),
            CompletionCode::RequestDataFieldLengthLimitExceeded => write!(f, "Request data field length limit exceeded"),
            CompletionCode::ParameterOutOfRange => write!(f, "Parameter out of range. One or more parameters in the data field of the Request are out of range. This is different from ‘Invalid data field’ (CCh) code in that it indicates that the erroneous field(s) has a contiguous range of possible values"),
            CompletionCode::CannotReturnNumberOfRqDataBytes => write!(f, "Cannot return number of requested data bytes"),
            CompletionCode::RqSensorDataRecordNotPresent => write!(f, "Requested Sensor, data, or record not present"),
            CompletionCode::InvalidDataFieldInRequest => write!(f, "Invalid data field in Request"),
            CompletionCode::CommandIllegalForSensor => write!(f, "Command illegal for specified sensor or record type"),
            CompletionCode::CommandResponseNotProvided => write!(f, "Command response could not be provided"),
            CompletionCode::CantExecuteDuplicateRq => write!(f, "Cannot execute duplicated request"),
            CompletionCode::FailedSDRUpdateMode => write!(f, "Command response could not be provided. SDR Repository in update mode"),
            CompletionCode::FailedDevFirmwareMode => write!(f, "Command response could not be provided. Device in firmware update mode"),
            CompletionCode::FailedInitInProgress => write!(f, "Command response could not be provided. BMC initialization or initialization agent in progress"),
            CompletionCode::DestinationUnavailable => write!(f, "Destination unavailable"),
            CompletionCode::CannotExecuteCommandInsuffientPrivileges => write!(f, "Cannot execute command due to insufficient privilege level or other securitybased restriction (e.g. disabled for ‘firmware firewall’)."),
            CompletionCode::CommandSubFunctionUnavailable => write!(f, "Cannot execute command. Command, or request parameter(s), not supported in present state"),
            CompletionCode::CannotExecuteCommandIllegalParam => write!(f, "Cannot execute command. Parameter is illegal because command sub-function has been disabled or is unavailable (e.g. disabled for ‘firmware firewall’)"),
            CompletionCode::UnspecifiedError => write!(f, "Unspecified error"),
            CompletionCode::OEM(x) => write!(f, "Device specific (OEM) completion code: {}", x),
            CompletionCode::CommandCode(x) => write!(f, "Command specific code: {}", x),
            CompletionCode::Reserved(x) => write!(f, "Reserved code: {}", x),
        }
    }
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
