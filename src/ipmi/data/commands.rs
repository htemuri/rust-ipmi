use arrayvec::ArrayVec;

use crate::ipmi::{
    data::app::channel::GetChannelAuthCapabilitiesRequest, payload::ipmi_payload::NetFn,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Command {
    /// APP Commands
    Reserved,
    // GetDeviceId,
    // ColdReset,
    // WarmReset,
    // GetSelfTestResults,
    // ManufacturingTestOn,
    // SetACPIPowerState,
    // GetACPIPowerState,
    // GetDeviceGUID,
    // GetNetFnSupport,
    // GetCommandSupport,
    // GetCommandSubfunctionSupport,
    // GetConfigurableCommandSubfunctions,
    // Unassigned,
    // SetCommandEnables,
    // GetCommandEnables,
    // SetCommandSubfunctionEnables,
    // GetCommandSubfunctionEnables,
    // GetOEMNetFnIANASupport,
    // ResetWatchdogTimer,
    // SetWatchdogTimer,
    // GetWatchdogTimer,
    // SetBMCGlobalEnables,
    // GetBMCGlobalEnables,
    // ClearMessageFlags,
    // GetMessageFlags,
    // EnableMessageChannelReceive,
    // GetMessage,
    // SendMessage,
    // ReadEventMessageBuffer,
    // GetBTInterfaceCapabilities,
    // GetSystemGUID,
    // SetSystemInfoParameters,
    // GetSystemInfoParameters,
    GetChannelAuthCapabilities,
    // GetSessionChallenge,
    // ActivateSession,
    // SetSessionPrivilegeLevel,
    // CloseSession,
    // GetAuthCode,
    // SetChannelAccess,
    // GetChannelAccess,
    // GetChannelInfoCommand,
    // SetUserAccessCommand,
    // GetUserAccessCommand,
    // SetUserName,
    // GetUserNameCommand,
    // SetUserPasswordCommand,
    // ActivatePayload,
    // DeactivatePayload,
    // GetPayloadActivationStatus,
    // GetPayloadInstanceInfo,
    // SetUserPayloadAccess,
    // GetUserPayloadAccess,
    // GetChannelPayloadSupport,
    // GetChannelPayloadVersion,
    // GetChannelOEMPayloadInfo,
    // MasterWriteRead,
    // GetChannelCipherSuites,
    // SuspendResumePayloadEncryption,
    // SetChannelSecurityKeys,
    // GetSystemInterfaceCapabilities,
    // FirmwareFirewallConfiguration,
}

impl Command {
    pub fn to_u8(&self) -> u8 {
        match self {
            Command::GetChannelAuthCapabilities => 0x38,
            Command::Reserved => 0x00,
        }
    }

    pub fn from_u8_and_netfn(command_code: u8, net_fn: NetFn) -> Command {
        match net_fn {
            NetFn::App => match command_code {
                0x38 => Command::GetChannelAuthCapabilities,
                _ => Command::Reserved,
            },
            _ => Command::Reserved,
        }
    }
}

// pub fn data_from_slice(command: Command, slice: &[u8]) -> Option<Box<dyn Data>> {
//     match command {
//         Command::GetChannelAuthCapabilities => Some(Box::new(
//             GetChannelAuthCapabilitiesRequest::from_slice(slice),
//         )),
//     }
// }

// //

// pub trait Data {
//     fn to_bytes(&self) -> ArrayVec<u8, 8092>;
//     fn from_slice<T>(slice: &[u8]) -> Result<T, std::io::ErrorKind>;
// }
