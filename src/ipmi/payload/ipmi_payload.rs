// use super::ipmi_payload_request::IpmiV1Payload;

// pub enum IpmiPayload {
//     V1_5(Ip),
//     // V2_0(IpmiV2Payload),
// }

// impl IpmiPayload

// pub enum NetFn {
//     Chassis(CommandType),
//     Bridge(CommandType),
//     SensorEvent(CommandType),
//     App(CommandType),
//     Firmware(CommandType),
//     Storage(CommandType),
//     Transport(CommandType),
//     Reserved,
// }

// impl NetFn {
//     pub fn from_u8(fn_code: u8) -> NetFn {
//         if &fn_code % 2 == 0 {
//             match fn_code {
//                 0x06 => NetFn::App(CommandType::Request),
//                 _ => NetFn::App(CommandType::Request),
//             }
//         } else {
//             match fn_code {
//                 0x07 => NetFn::App(CommandType::Response),
//                 _ => NetFn::App(CommandType::Response),
//             }
//         }
//     }
// }

// use crate::ipmi::data::netfn::CommandType;
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
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Lun {
    Bmc,
    Oem1,
    Sms,
    Oem2,
    Error(u8),
}

impl Lun {
    pub fn from_u8(lun: u8) -> Lun {
        match lun {
            0b00 => Lun::Bmc,
            0b01 => Lun::Oem1,
            0b10 => Lun::Sms,
            0b11 => Lun::Oem2,
            _ => Lun::Error(lun),
        }
    }
    pub fn to_u8(&self) -> u8 {
        match self {
            Lun::Bmc => 0b00,
            Lun::Oem1 => 0b01,
            Lun::Sms => 0b10,
            Lun::Oem2 => 0b11,
            Lun::Error(a) => *a,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AddrType {
    SlaveAddress,
    SoftwareId,
}

impl AddrType {
    pub fn from_bool(bit_value: bool) -> AddrType {
        match bit_value {
            false => AddrType::SlaveAddress,
            true => AddrType::SoftwareId,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            AddrType::SlaveAddress => 0,
            AddrType::SoftwareId => 1,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SoftwareType {
    Bios,
    SmiHandler,
    SystemManagementSoftware,
    Oem,
    RemoteConsoleSoftware(u8),
    TerminalModeRemoteConsole,
    Reserved(u8),
}

impl SoftwareType {
    pub fn from_u8(software_id: u8) -> SoftwareType {
        match software_id {
            0x00..=0x0F => SoftwareType::Bios,
            0x10..=0x1F => SoftwareType::SmiHandler,
            0x20..=0x2F => SoftwareType::SystemManagementSoftware,
            0x30..=0x3F => SoftwareType::Oem,
            0x40..=0x46 => SoftwareType::RemoteConsoleSoftware(software_id - 0x3F),
            0x47 => SoftwareType::TerminalModeRemoteConsole,
            _ => SoftwareType::Reserved(software_id),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            SoftwareType::Bios => 0x00,
            SoftwareType::SmiHandler => 0x10,
            SoftwareType::SystemManagementSoftware => 0x20,
            SoftwareType::Oem => 0x30,
            SoftwareType::RemoteConsoleSoftware(a) => *a + 0x3F,
            SoftwareType::TerminalModeRemoteConsole => 0x47,
            SoftwareType::Reserved(a) => *a,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SlaveAddress {
    Bmc,
    Unknown(u8),
}

impl SlaveAddress {
    pub fn from_u8(slave_address: u8) -> SlaveAddress {
        match slave_address {
            0x20 => SlaveAddress::Bmc,
            _ => SlaveAddress::Unknown(slave_address),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            SlaveAddress::Bmc => 0x20,
            SlaveAddress::Unknown(a) => *a,
        }
    }
}
