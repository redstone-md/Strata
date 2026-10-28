use std::io;

/// Errors that mean "nothing usable could be produced".
/// Partial results are reported through [`crate::Damage`] instead.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    #[error("unrecognised format: {0}")]
    Format(String),
    #[error("out of range: offset {offset:#x} len {len}")]
    OutOfRange { offset: u64, len: u64 },
    #[error("cancelled")]
    Cancelled,
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn format(msg: impl Into<String>) -> Self {
        Self::Format(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
