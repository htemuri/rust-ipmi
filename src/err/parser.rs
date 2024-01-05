use thiserror::Error;

use super::{
    AuthAlgorithmError, CommandError, ConfidentialityAlgorithmError, IntegrityAlgorithmError,
    LunError, NetFnError, PrivilegeError,
};

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Length of slice should be 4 bytes")]
    WrongLength,
    #[error("Failed to parse slice to rmcp header")]
    FailedToParse,
    #[error("Unsupported Message class {0}")]
    UnsupportedMessageClass(u8),
    #[error("Failed parsing IPMI payload {0:?}")]
    NetFn(#[from] NetFnError),
    #[error("Failed parsing IPMI payload {0:?}")]
    Lun(#[from] LunError),
    #[error("Failed parsing IPMI payload {0:?}")]
    Command(#[from] CommandError),
    #[error("Failed parsing IPMI payload {0:?}")]
    Privilege(#[from] PrivilegeError),
    #[error("Failed parsing IPMI payload {0:?}")]
    AuthAlgorithm(#[from] AuthAlgorithmError),
}

#[derive(Error, Debug)]
pub enum IpmiHeaderError {
    #[error("Length of slice should be at least 10 bytes")]
    WrongLength,
    #[error("Failed parsing IPMI v2 header {0:?}")]
    V2Error(#[from] IpmiV2HeaderError),
    #[error("Failed parsing IPMI v1.5 header {0:?}")]
    V1_5Error(#[from] IpmiV1HeaderError),
    #[error("Unsupported Auth Type {0}")]
    UnsupportedAuthType(u8),
}

#[derive(Error, Debug)]
pub enum IpmiPayloadError {
    #[error("Length of slice should be at least 7 bytes")]
    WrongLength,
    #[error("Failed parsing IPMI request payload {0:?}")]
    PayloadRequestError(#[from] IpmiPayloadRequestError),
    #[error("Unsupported Auth Type {0}")]
    UnsupportedAuthType(u8),
    #[error("Failed parsing IPMI payload {0:?}")]
    NetFn(#[from] NetFnError),
    #[error("Failed parsing IPMI payload {0:?}")]
    Lun(#[from] LunError),
    #[error("Failed parsing IPMI payload {0:?}")]
    Command(#[from] CommandError),
    #[error("Failed parsing IPMI payload {0:?}")]
    Privilege(#[from] PrivilegeError),
    #[error("Failed parsing payload")]
    Parse(#[from] ParseError),
    #[error("Failed parsing IPMI payload {0:?}")]
    AuthAlgorithm(#[from] AuthAlgorithmError),
    #[error("Failed parsing IPMI payload {0:?}")]
    IntegrityAlgorithm(#[from] IntegrityAlgorithmError),
    #[error("Failed parsing IPMI payload {0:?}")]
    ConfidentialityAlgorithm(#[from] ConfidentialityAlgorithmError),
}

#[derive(Error, Debug)]
pub enum IpmiV2HeaderError {
    #[error("Length of slice should be either 12 or 18 bytes")]
    WrongLength,
    #[error("Unsupported Payload Type {0}")]
    UnsupportedPayloadType(u8),
}

#[derive(Error, Debug)]
pub enum IpmiV1HeaderError {
    #[error("Length of slice should be either 10 or 26 bytes")]
    WrongLength,
}

#[derive(Error, Debug)]
pub enum IpmiPayloadRequestError {
    #[error("Length of slice should be at least 7 bytes")]
    WrongLength,
    #[error("Unsupported Payload Type {0}")]
    UnsupportedPayloadType(u8),
    #[error("Failed parsing payload")]
    Parse(#[from] ParseError),
}
