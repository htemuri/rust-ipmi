use thiserror::Error;

use super::RMCPError;

#[derive(Error, Debug)]
pub enum PacketError {
    #[error("Failed to parse slice to Packet")]
    FailedToParse,
    #[error("Failed to parse slice to Packet")]
    RMCPHeaderError(#[from] RMCPError),
}
