use thiserror::Error;

#[derive(Error, Debug)]
pub enum N3tworkError {
    #[error("data store disconnected")]
    IOError(#[from] std::io::Error),
    #[error("send error {0}")]
    SendError(String),
    #[error("recv error {0}")]
    RecvError(String),
    #[error("Internal Error {0}")]
    InternalError(String),
    #[error("Unknown Error {0}")]
    UnknownError(String),
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("signature error {0}")]
    SignatureError(String),
    #[error("internal error {0}")]
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

impl From<CryptoError> for N3tworkError {
    fn from(error: CryptoError) -> Self {
        N3tworkError::InternalError(error.to_string())
    }
}