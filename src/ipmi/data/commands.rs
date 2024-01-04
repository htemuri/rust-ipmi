use crate::{err::CommandError, NetFn};

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

impl TryFrom<(u8, NetFn)> for Command {
    type Error = CommandError;

    fn try_from(value: (u8, NetFn)) -> Result<Self, CommandError> {
        let command = Self::from_u8_and_netfn(value.0, value.1);
        if let Command::Reserved = command {
            Err(CommandError::UnknownCommandCode(value.0))
        } else {
            Ok(command)
        }
    }
}

impl Into<u8> for Command {
    fn into(self) -> u8 {
        match self {
            Command::GetChannelAuthCapabilities => 0x38,
            Command::GetChannelCipherSuites => 0x54,
            Command::SetSessionPrivilegeLevel => 0x3b,
            Command::Reserved => 0x00,
        }
    }
}

impl Command {
    pub fn to_u8(&self) -> u8 {
        match self {
            Command::GetChannelAuthCapabilities => 0x38,
            Command::GetChannelCipherSuites => 0x54,
            Command::SetSessionPrivilegeLevel => 0x3b,
            Command::Reserved => 0x00,
        }
    }

    pub fn from_u8_and_netfn(command_code: u8, net_fn: NetFn) -> Command {
        match net_fn {
            NetFn::App => match command_code {
                0x38 => Command::GetChannelAuthCapabilities,
                0x54 => Command::GetChannelCipherSuites,
                0x3b => Command::SetSessionPrivilegeLevel,
                _ => Command::Reserved,
            },
            _ => Command::Reserved,
        }
    }
}
