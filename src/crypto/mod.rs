

pub mod core;
#[cfg(feature = "openssl")]
pub mod openssl_core;


pub const PREFIX_ENCRYPTION: [u8; 8] = [0x68, 0x65, 0x79, 0x67, 0x75, 0x72, 0x6c, 0x01]; //TODO
pub const PREFIX_COMMITMENT: [u8; 8] = [0x68, 0x65, 0x79, 0x67, 0x75, 0x72, 0x6c, 0xff]; // TODO

pub const X25519_SECRET_KEY_SIZE: usize = 32;
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

pub const XCHACHA20_POLY1305_NONCE_SIZE: usize = 24;
pub const XCHACHA20_POLY1305_KEY_SIZE: usize = 32;

pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SECRET_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

