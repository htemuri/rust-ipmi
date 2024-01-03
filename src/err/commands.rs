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
