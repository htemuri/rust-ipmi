use std::num::TryFromIntError;

use bitvec::{field::BitField, order::Msb0, slice::BitSlice};
use hmac::digest::block_buffer::Error;

use crate::err::{IpmiPayloadError, LunError, NetFnError};

use super::ipmi_payload_request::IpmiPayloadRequest;
use super::ipmi_payload_response::IpmiPayloadResponse;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum IpmiPayload {
    Request(IpmiPayloadRequest),
    Response(IpmiPayloadResponse),
}

impl TryFrom<&[u8]> for IpmiPayload {
    type Error = IpmiPayloadError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 7 {
            Err(IpmiPayloadError::WrongLength)?
        }
        let netfn_rqlun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&value[1]);
        let netfn = netfn_rqlun[0..6].load::<u8>();
        let command_type: CommandType = netfn.into();

        match command_type {
            CommandType::Request => Ok(IpmiPayload::Request(value.try_into()?)),
            CommandType::Response => Ok(IpmiPayload::Response(value.try_into()?)),
        }
    }
}

impl Into<Vec<u8>> for IpmiPayload {
    fn into(self) -> Vec<u8> {
        match self {
            IpmiPayload::Request(payload) => payload.into(),
            _ => todo!(), // IpmiPayload::Response(header) => header.to_bytes(),
        }
    }
}

impl IpmiPayload {
    pub const PAYLOAD_MAX_LEN: usize = 0xff;

    // pub fn from_slice(slice: &[u8]) -> IpmiPayload {
    //     let netfn_rqlun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&slice[1]);
    //     let netfn_slice = &netfn_rqlun[0..6];
    //     let netfn = netfn_slice[..].load::<u8>();
    //     let command_type = netfn);

    //     match command_type {
    //         CommandType::Request => IpmiPayload::Request(slice.try_into()?),
    //         // _ => todo!(),
    //         CommandType::Response => IpmiPayload::Response(IpmiPayloadResponse::from_slice(slice)),
    //     }
    // }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            IpmiPayload::Request(payload) => payload.clone().into(),
            _ => todo!(), // IpmiPayload::Response(header) => header.to_bytes(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum NetFn {
    Chassis,
    Bridge,
    SensorEvent,
    App,
    Firmware,
    Storage,
    Transport,
    Reserved,
    Unknown(u8),
}

impl TryFrom<u8> for NetFn {
    type Error = NetFnError;
    fn try_from(value: u8) -> Result<Self, NetFnError> {
        match value {
            0x00..=0x01 => Ok(NetFn::Chassis),
            0x02..=0x03 => Ok(NetFn::Bridge),
            0x04..=0x05 => Ok(NetFn::SensorEvent),
            0x06..=0x07 => Ok(NetFn::App),
            0x08..=0x09 => Ok(NetFn::Firmware),
            0x0A..=0x0B => Ok(NetFn::Storage),
            0x0C..=0x0D => Ok(NetFn::Transport),
            0x0E..=0x2B => Ok(NetFn::Reserved),
            _ => Err(NetFnError::UnknownNetFn(value)),
        }
    }
}

impl NetFn {
    pub fn from_u8(fn_code: u8) -> NetFn {
        match fn_code {
            0x00..=0x01 => NetFn::Chassis,
            0x02..=0x03 => NetFn::Bridge,
            0x04..=0x05 => NetFn::SensorEvent,
            0x06..=0x07 => NetFn::App,
            0x08..=0x09 => NetFn::Firmware,
            0x0A..=0x0B => NetFn::Storage,
            0x0C..=0x0D => NetFn::Transport,
            0x0E..=0x2B => NetFn::Reserved,
            _ => NetFn::Unknown(fn_code),
        }
    }
    pub fn to_u8(&self, command_type: CommandType) -> u8 {
        match self {
            NetFn::Chassis => match command_type {
                CommandType::Request => 0x00,
                CommandType::Response => 0x01,
            },
            NetFn::Bridge => match command_type {
                CommandType::Request => 0x02,
                CommandType::Response => 0x03,
            },
            NetFn::SensorEvent => match command_type {
                CommandType::Request => 0x04,
                CommandType::Response => 0x05,
            },
            NetFn::App => match command_type {
                CommandType::Request => 0x06,
                CommandType::Response => 0x07,
            },
            NetFn::Firmware => match command_type {
                CommandType::Request => 0x08,
                CommandType::Response => 0x09,
            },
            NetFn::Storage => match command_type {
                CommandType::Request => 0x0A,
                CommandType::Response => 0x0B,
            },
            NetFn::Transport => match command_type {
                CommandType::Request => 0x0C,
                CommandType::Response => 0x0D,
            },
            NetFn::Reserved => match command_type {
                CommandType::Request => 0x0E,
                CommandType::Response => 0x2B,
            },
            NetFn::Unknown(fn_code) => match command_type {
                CommandType::Request => *fn_code,
                CommandType::Response => *fn_code,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum CommandType {
    Request,
    Response,
}

impl From<u8> for CommandType {
    fn from(value: u8) -> Self {
        if value % 2 == 0 {
            CommandType::Request
        } else {
            CommandType::Response
        }
    }
}

// impl CommandType {
//     pub fn from_u8(netfn: u8) -> CommandType {
//         match netfn % 2 {
//             0 => CommandType::Request,
//             1 => CommandType::Response,
//             _ => CommandType::Request,
//         }
//     }
// }

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Lun {
    Bmc,
    Oem1,
    Sms,
    Oem2,
}
impl TryFrom<u8> for Lun {
    type Error = LunError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(Lun::Bmc),
            0b01 => Ok(Lun::Oem1),
            0b10 => Ok(Lun::Sms),
            0b11 => Ok(Lun::Oem2),
            _ => Err(LunError::UnknownLun(value)),
        }
    }
}

impl Into<u8> for Lun {
    fn into(self) -> u8 {
        match self {
            Lun::Bmc => 0b00,
            Lun::Oem1 => 0b01,
            Lun::Sms => 0b10,
            Lun::Oem2 => 0b11,
        }
    }
}

// impl Lun {
//     pub fn from_u8(lun: u8) -> Lun {
//         match lun {
//             0b00 => Lun::Bmc,
//             0b01 => Lun::Oem1,
//             0b10 => Lun::Sms,
//             0b11 => Lun::Oem2,
//             _ => Lun::Error(lun),
//         }
//     }
//     pub fn to_u8(&self) -> u8 {
//         match self {
//             Lun::Bmc => 0b00,
//             Lun::Oem1 => 0b01,
//             Lun::Sms => 0b10,
//             Lun::Oem2 => 0b11,
//             Lun::Error(a) => *a,
//         }
//     }
// }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AddrType {
    SlaveAddress,
    SoftwareId,
}

impl From<bool> for AddrType {
    fn from(value: bool) -> Self {
        match value {
            false => AddrType::SlaveAddress,
            true => AddrType::SoftwareId,
        }
    }
}

impl Into<u8> for AddrType {
    fn into(self) -> u8 {
        match self {
            AddrType::SlaveAddress => 0,
            AddrType::SoftwareId => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SoftwareType {
    Bios,
    SmiHandler,
    SystemManagementSoftware,
    Oem,
    RemoteConsoleSoftware(u8),
    TerminalModeRemoteConsole,
    Reserved(u8),
}

impl From<u8> for SoftwareType {
    fn from(value: u8) -> Self {
        match value {
            0x00..=0x0F => SoftwareType::Bios,
            0x10..=0x1F => SoftwareType::SmiHandler,
            0x20..=0x2F => SoftwareType::SystemManagementSoftware,
            0x30..=0x3F => SoftwareType::Oem,
            0x40..=0x46 => SoftwareType::RemoteConsoleSoftware(value - 0x3F),
            0x47 => SoftwareType::TerminalModeRemoteConsole,
            _ => SoftwareType::Reserved(value),
        }
    }
}

impl Into<u8> for SoftwareType {
    fn into(self) -> u8 {
        match self {
            SoftwareType::Bios => 0x00,
            SoftwareType::SmiHandler => 0x10,
            SoftwareType::SystemManagementSoftware => 0x20,
            SoftwareType::Oem => 0x30,
            SoftwareType::RemoteConsoleSoftware(a) => a,
            SoftwareType::TerminalModeRemoteConsole => 0x47,
            SoftwareType::Reserved(a) => a,
        }
    }
}

// impl SoftwareType {
//     pub fn from_u8(software_id: u8) -> SoftwareType {
//         match software_id {
//             0x00..=0x0F => SoftwareType::Bios,
//             0x10..=0x1F => SoftwareType::SmiHandler,
//             0x20..=0x2F => SoftwareType::SystemManagementSoftware,
//             0x30..=0x3F => SoftwareType::Oem,
//             0x40..=0x46 => SoftwareType::RemoteConsoleSoftware(software_id - 0x3F),
//             0x47 => SoftwareType::TerminalModeRemoteConsole,
//             _ => SoftwareType::Reserved(software_id),
//         }
//     }

//     pub fn to_u8(&self) -> u8 {
//         match self {
//             SoftwareType::Bios => 0x00,
//             SoftwareType::SmiHandler => 0x10,
//             SoftwareType::SystemManagementSoftware => 0x20,
//             SoftwareType::Oem => 0x30,
//             SoftwareType::RemoteConsoleSoftware(a) => *a,
//             SoftwareType::TerminalModeRemoteConsole => 0x47,
//             SoftwareType::Reserved(a) => *a,
//         }
//     }
// }
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SlaveAddress {
    Bmc,
    Unknown(u8),
}

impl From<u8> for SlaveAddress {
    fn from(value: u8) -> Self {
        match value {
            0x20 => SlaveAddress::Bmc,
            _ => SlaveAddress::Unknown(value),
        }
    }
}

impl Into<u8> for SlaveAddress {
    fn into(self) -> u8 {
        match self {
            SlaveAddress::Bmc => 0x20,
            SlaveAddress::Unknown(a) => a,
        }
    }
}

// impl SlaveAddress {
//     pub fn from_u8(slave_address: u8) -> SlaveAddress {
//         match slave_address {
//             0x20 => SlaveAddress::Bmc,
//             _ => SlaveAddress::Unknown(slave_address),
//         }
//     }

//     pub fn to_u8(&self) -> u8 {
//         match self {
//             SlaveAddress::Bmc => 0x20,
//             SlaveAddress::Unknown(a) => *a,
//         }
//     }
// }
