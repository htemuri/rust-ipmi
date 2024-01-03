use thiserror::Error;

#[derive(Error, Debug)]
pub enum RMCPError {
    #[error("Length of slice should be 4 bytes")]
    WrongLength,
    #[error("Failed to parse slice to rmcp header")]
    FailedToParse,
    #[error("Unsupported Message class {0}")]
    UnsupportedMessageClass(u8),
}
