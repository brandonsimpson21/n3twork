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
    #[error("encryption error {0}")]
    EncryptionError(String),
    #[error("decryption error {0}")]
    DecryptionError(String),
    #[error("cert error {0}")]
    CertError(String),
    #[error("key error {0}")]
    KeyError(String),
    #[error("invalid length error {0}")]
    InvalidLengthError(String),
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

impl From<std::array::TryFromSliceError> for CryptoError {
    fn from(error: std::array::TryFromSliceError) -> Self {
        CryptoError::InternalError(error.to_string())
    }
}

impl From<chacha20poly1305::Error> for CryptoError {
    fn from(e: chacha20poly1305::Error) -> Self {
        CryptoError::EncryptionError(e.to_string())
    }
}

impl From<ed25519_dalek::ed25519::Error> for CryptoError {
    fn from(e: ed25519_dalek::ed25519::Error) -> Self {
        CryptoError::EncryptionError(e.to_string())
    }
}

impl From<ring::error::Unspecified> for CryptoError {
    fn from(e: ring::error::Unspecified) -> Self {
        CryptoError::InvalidLengthError(e.to_string())
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for CryptoError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        CryptoError::InternalError(e.to_string())
    }
}
