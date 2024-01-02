use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketError {
    #[error("Failed to parse slice to Packet")]
    FailedToParse,
}
