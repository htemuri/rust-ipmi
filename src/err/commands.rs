use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetFnError {
    #[error("Failed due to not supporting the following NetFn code: {0}")]
    UnknownNetFn(u8),
}

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("Failed due to not supporting the following Command code: {0}")]
    UnknownCommandCode(u8),
}

#[derive(Error, Debug)]
pub enum LunError {
    #[error("Failed due to not supporting the following Lun code: {0}")]
    UnknownLun(u8),
}

#[derive(Error, Debug)]
pub enum PrivilegeError {
    #[error("Failed due to not supporting the following Privilege code: {0}")]
    UnknownPrivilege(u8),
}

#[derive(Error, Debug)]
pub enum AuthAlgorithmError {
    #[error("Failed due to not supporting the following AuthAlgorithm code: {0}")]
    UnknownAuthAlgorithm(u8),
}

#[derive(Error, Debug)]
pub enum IntegrityAlgorithmError {
    #[error("Failed due to not supporting the following IntegrityAlgorithm code: {0}")]
    UnknownIntegrityAlgorithm(u8),
}

#[derive(Error, Debug)]
pub enum ConfidentialityAlgorithmError {
    #[error("Failed due to not supporting the following ConfidentialityAlgorithm code: {0}")]
    UnknownConfidentialityAlgorithm(u8),
}
