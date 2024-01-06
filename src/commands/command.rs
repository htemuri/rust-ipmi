use core::fmt;

use crate::{err::CommandError, NetFn};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Command {
    Unknown(u8),
    /// APP Commands
    // Reserved,
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
    SetSessionPrivilegeLevel,
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
    GetChannelCipherSuites,
    // SuspendResumePayloadEncryption,
    // SetChannelSecurityKeys,
    // GetSystemInterfaceCapabilities,
    // FirmwareFirewallConfiguration,
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Unknown(x) => write!(f, "Unknown: {}", x),
            Command::GetChannelAuthCapabilities => write!(f, "Get Channel Auth Capabilities"),
            Command::SetSessionPrivilegeLevel => write!(f, "Set Session Privilege Level"),
            Command::GetChannelCipherSuites => write!(f, "Get Channel Cipher Suites"),
        }
    }
}

type CommandAndNetfn = (u8, NetFn);

impl TryFrom<CommandAndNetfn> for Command {
    type Error = CommandError;

    fn try_from(value: CommandAndNetfn) -> Result<Self, CommandError> {
        let command_code = value.0;
        let netfn = value.1;
        match netfn {
            NetFn::App => match command_code {
                0x38 => Ok(Command::GetChannelAuthCapabilities),
                0x54 => Ok(Command::GetChannelCipherSuites),
                0x3b => Ok(Command::SetSessionPrivilegeLevel),
                _ => Ok(Command::Unknown(command_code)), // _ => Err(CommandError::UnknownCommandCode(command_code))?,
            },
            _ => Ok(Command::Unknown(command_code)),
        }
    }
}

impl Into<u8> for Command {
    fn into(self) -> u8 {
        match self {
            Command::GetChannelAuthCapabilities => 0x38,
            Command::GetChannelCipherSuites => 0x54,
            Command::SetSessionPrivilegeLevel => 0x3b,
            // Command::Reserved => 0x00,
            Command::Unknown(x) => x,
        }
    }
}

impl Into<CommandAndNetfn> for Command {
    fn into(self) -> CommandAndNetfn {
        match self {
            Command::GetChannelAuthCapabilities => (0x38, NetFn::App),
            Command::GetChannelCipherSuites => (0x54, NetFn::App),
            Command::SetSessionPrivilegeLevel => (0x3b, NetFn::App),
            // Command::Reserved => (0x00, NetFn::Unknown(0)),
            Command::Unknown(x) => (x, NetFn::Unknown(0)),
        }
    }
}
