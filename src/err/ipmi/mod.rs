use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum IPMIClientError {
    #[error("Failed to bind due to: {0}")]
    FailedBind(#[source] io::Error),
    #[error("Failed to connect to IPMI Server due to: {0}")]
    ConnectToIPMIServer(#[source] io::Error),
}
