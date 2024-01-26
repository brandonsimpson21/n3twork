use thiserror::Error;

#[derive(Error, Debug)]
pub enum N3tworkError {
    #[error("data store disconnected")]
    IOError(#[from] std::io::Error),
    #[error("Internal Error {0}")]
    InternalError(String),
    #[error("Unknown Error {0}")]
    UnknownError(String),
}

impl From<Box<dyn std::error::Error>> for N3tworkError {
    fn from(error: Box<dyn std::error::Error>) -> Self {
        N3tworkError::InternalError(error.to_string())
    }
}

impl From<anyhow::Error> for N3tworkError {
    fn from(error: anyhow::Error) -> Self {
        N3tworkError::InternalError(error.to_string())
    }
}