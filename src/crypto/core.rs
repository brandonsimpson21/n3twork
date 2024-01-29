// use rand_core::OsRng;

use ring::{
    agreement::{self, Algorithm, EphemeralPrivateKey, PublicKey},
    hmac::{self, Algorithm as hmacAlgorithm, Tag},
    rand::{self, SecureRandom},
};

use crate::error::CryptoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use super::{
    ED25519_PUBLIC_KEY_SIZE, ED25519_SECRET_KEY_SIZE, PREFIX_ENCRYPTION, X25519_PUBLIC_KEY_SIZE,
    X25519_SECRET_KEY_SIZE, XCHACHA20_POLY1305_NONCE_SIZE,
};

pub const NONCE_SIZE: usize = XCHACHA20_POLY1305_NONCE_SIZE;

#[inline(always)]
pub fn get_random_bytes(size: usize) -> Vec<u8> {
    let rng = rand::SystemRandom::new();
    let mut bytes = vec![0u8; size];
    rng.fill(&mut bytes).expect("rng.fill failed");
    bytes
}

/// get new public and private x25519 keys
#[inline(always)]
pub fn new_x25519_keypair() -> ([u8; X25519_SECRET_KEY_SIZE], [u8; X25519_PUBLIC_KEY_SIZE]) {
    let rng = rand::SystemRandom::new();
    let mut sec_key = [0; X25519_SECRET_KEY_SIZE];
    rng.fill(&mut sec_key).expect("rng.fill failed");
    let pub_key = x25519(sec_key, X25519_BASEPOINT_BYTES);
    (sec_key, pub_key)
}

/// get new public and private ed25519 keys
#[inline(always)]
pub fn new_ed25519_keypair() -> ([u8; ED25519_SECRET_KEY_SIZE], [u8; ED25519_PUBLIC_KEY_SIZE]) {
    let sec_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pub_key = sec_key.verifying_key();
    (sec_key.to_bytes(), pub_key.to_bytes())
}

/// x5119 diffie-hellman
/// # Example.
/// ```rust
///     use ring::rand::{self, SecureRandom};
///     use n3twork::crypto::{
///        XCHACHA20_POLY1305_NONCE_SIZE,
///       core::{x25519_dh, new_x25519_keypair}
///     };
///     let rng = rand::SystemRandom::new();
///     let mut nonce = [0u8; XCHACHA20_POLY1305_NONCE_SIZE];
///     rng.fill(&mut nonce).expect("rng.fill failed");
///     let (alice_sec, alice_pub) = new_x25519_keypair();
///     let (bob_sec, bob_pub) = new_x25519_keypair();
///     assert_ne!(alice_sec, bob_sec);
///     let alice_shared = x25519_dh(alice_sec, bob_pub, &nonce).unwrap();
///     let bob_shared = x25519_dh(bob_sec, alice_pub, &nonce).unwrap();
///     assert_eq!(alice_shared, bob_shared);
/// ```
#[inline(always)]
pub fn x25519_dh<B>(
    sec_key: B,
    pub_key: B,
    nonce: &[u8],
) -> Result<[u8; X25519_SECRET_KEY_SIZE], CryptoError>
where
    B: AsRef<[u8]>,
{
    let sec_key: [u8; X25519_SECRET_KEY_SIZE] = sec_key.as_ref().try_into()?;
    let pub_key: [u8; X25519_PUBLIC_KEY_SIZE] = pub_key.as_ref().try_into()?;
    let key_material = x25519(sec_key, pub_key);
    let nonce: [u8; XCHACHA20_POLY1305_NONCE_SIZE] = nonce.try_into()?;
    Ok(kdf_with_nonce(&key_material, &nonce)?)
}

/// new ephemeral keypair
/// supported algorithms: X25519, ECDH_P256 (TODO) ECDH_P256
#[inline(always)]
pub fn new_ephemeral_keypair(algo: &'static Algorithm) -> (EphemeralPrivateKey, PublicKey) {
    let rng = rand::SystemRandom::new();
    let eph_sec = agreement::EphemeralPrivateKey::generate(algo, &rng)
        .expect("ephemeral key generation failed");
    let eph_pub = eph_sec
        .compute_public_key()
        .expect("ephemeral key generation failed");
    (eph_sec, eph_pub)
}

#[inline(always)]
pub fn kdf(key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let rng = rand::SystemRandom::new();
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill(&mut nonce).expect("rng.fill failed");
    let mut kdf = blake3::Hasher::new_keyed(&key.try_into()?);
    let mut input = Vec::from(PREFIX_ENCRYPTION); // TODO
    input.extend_from_slice(&nonce);
    let shared_key = kdf.update(&input).finalize();
    Ok((nonce.to_vec(), shared_key.as_bytes().to_vec()))
}

#[inline(always)]
pub fn kdf_with_nonce(
    key: &[u8],
    nonce: &[u8; NONCE_SIZE],
) -> Result<[u8; X25519_SECRET_KEY_SIZE], CryptoError> {
    let mut kdf = blake3::Hasher::new_keyed(&key.try_into()?);
    let mut input = Vec::from(PREFIX_ENCRYPTION); //TODO
    input.extend_from_slice(nonce);
    let key_hash = kdf.update(&input).finalize();
    Ok(*key_hash.as_bytes())
}

/// encrypt data with xchacha20poly1305
/// # Example.
/// ```rust
///     use n3twork::crypto::{
///         XCHACHA20_POLY1305_NONCE_SIZE, XCHACHA20_POLY1305_KEY_SIZE,
///         core::{xchacha_decrypt_data, xchacha_encrypt_data, get_random_bytes}
///         };
///     use ring::rand::{self, SecureRandom};
///     let rng = rand::SystemRandom::new();
///     let mut nonce = [0u8; XCHACHA20_POLY1305_NONCE_SIZE];
///     rng.fill(&mut nonce).expect("rng.fill failed");
///     let shared_key = get_random_bytes(XCHACHA20_POLY1305_KEY_SIZE);
///     let plaintext = b"hello world";
///     let aad = Some(b"some aad".as_ref());
///     let ciphertext = xchacha_encrypt_data(&shared_key, plaintext, aad, &nonce).unwrap();
///     let decrypted = xchacha_decrypt_data(&shared_key, &ciphertext, aad, &nonce).unwrap();
///     assert_eq!(plaintext, decrypted.as_slice());
/// ```
pub fn xchacha_encrypt_data(
    key: &[u8],
    message: &[u8],
    aad: Option<&[u8]>,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    let payload = Payload {
        msg: message,
        aad: aad.unwrap_or(&[]),
    };
    let cipher = XChaCha20Poly1305::new(key.into());
    Ok(cipher.encrypt(nonce.into(), payload)?)
}

/// decrypt data with xchacha20poly1305
/// # Example.
/// ```rust
///     use n3twork::crypto::{
///         XCHACHA20_POLY1305_NONCE_SIZE, XCHACHA20_POLY1305_KEY_SIZE,
///         core::{
///         xchacha_decrypt_data, xchacha_encrypt_data, get_random_bytes
///         }
///     };
///     use ring::rand::{self, SecureRandom};
///     let rng = rand::SystemRandom::new();
///     let mut nonce = [0u8; XCHACHA20_POLY1305_NONCE_SIZE];
///     rng.fill(&mut nonce).expect("rng.fill failed");
///     let shared_key = get_random_bytes(XCHACHA20_POLY1305_KEY_SIZE);
///     let plaintext = b"hello world";
///     let aad = Some(b"some aad".as_ref());
///     let ciphertext = xchacha_encrypt_data(&shared_key, plaintext, aad, &nonce).unwrap();
///     let decrypted = xchacha_decrypt_data(&shared_key, &ciphertext, aad, &nonce).unwrap();
///     assert_eq!(plaintext, decrypted.as_slice());
/// ```
pub fn xchacha_decrypt_data(
    key: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    let payload = Payload {
        msg: ciphertext,
        aad: aad.unwrap_or(&[]),
    };
    let cipher = XChaCha20Poly1305::new(key.into());
    Ok(cipher.decrypt(nonce.into(), payload)?)
}

/// hmac
/// # Example.
/// ```rust
///     use n3twork::crypto::{
///         XCHACHA20_POLY1305_NONCE_SIZE,
///         core::{
///             hmac, verify_hmac, get_random_bytes
///         }
///     };
///     use ring::hmac;
///     let algo = hmac::HMAC_SHA256;
///     let msg = b"hello world";
///     let key = get_random_bytes(32);
///     let nonce = get_random_bytes(XCHACHA20_POLY1305_NONCE_SIZE);
///     let tag = hmac(&key, msg.clone(), algo);
///     assert!(verify_hmac(&key, msg.clone(), tag, algo));
/// ```
#[inline(always)]
pub fn hmac<B, D>(key: B, msg: D, algo: hmacAlgorithm) -> Tag
where
    B: AsRef<[u8]>,
    D: AsRef<[u8]>,
{
    let s_key = hmac::Key::new(algo, key.as_ref());
    hmac::sign(&s_key, msg.as_ref())
}

/// verify hmac
/// # Example.
/// ```rust
///     use n3twork::crypto::{
///         XCHACHA20_POLY1305_NONCE_SIZE,
///         core::{
///             hmac, verify_hmac, get_random_bytes
///         }
///     };
///     use ring::hmac;
///     let algo = hmac::HMAC_SHA256;
///     let msg = b"hello world";
///     let key = get_random_bytes(32);
///     let nonce = get_random_bytes(XCHACHA20_POLY1305_NONCE_SIZE);
///     let tag = hmac(&key, msg.clone(), algo);
///     assert!(verify_hmac(&key, msg.clone(), tag, algo));
/// ```
#[inline(always)]
pub fn verify_hmac<B, D>(key: B, msg: D, tag: Tag, algo: hmacAlgorithm) -> bool
where
    B: AsRef<[u8]>,
    D: AsRef<[u8]>,
{
    let s_key = hmac::Key::new(algo, key.as_ref());
    hmac::verify(&s_key, msg.as_ref(), tag.as_ref()).is_ok()
}

#[cfg(test)]
mod test_utils {

    use crate::crypto::XCHACHA20_POLY1305_KEY_SIZE;

    use super::*;

    #[test]
    fn test_25519_gen() {
        let (xsk, xpk) = new_x25519_keypair();
        let (esk, epk) = new_ed25519_keypair();
        assert!(xsk.len() == X25519_SECRET_KEY_SIZE);
        assert!(xpk.len() == X25519_PUBLIC_KEY_SIZE);
        assert!(esk.len() == ED25519_SECRET_KEY_SIZE);
        assert!(epk.len() == ED25519_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_get_random_bytes() -> Result<(), CryptoError> {
        let n = 10;
        let bits = get_random_bytes(n);
        assert!(bits.len() == n);
        Ok(())
    }

    #[test]
    fn test_x25519dh() {
        let rng = rand::SystemRandom::new();
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce).expect("rng.fill failed");
        let (alice_sec, alice_pub) = new_x25519_keypair();
        let (bob_sec, bob_pub) = new_x25519_keypair();
        assert_ne!(alice_sec, bob_sec);
        let alice_shared = x25519_dh(alice_sec, bob_pub, &nonce).unwrap();
        let bob_shared = x25519_dh(bob_sec, alice_pub, &nonce).unwrap();
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_dh() {
        let rng = rand::SystemRandom::new();
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce).expect("rng.fill failed");

        for algo in vec![&agreement::X25519, &agreement::ECDH_P256] {
            let (alice_sec, alice_pub) = new_ephemeral_keypair(algo);
            let (bob_sec, bob_pub) = new_ephemeral_keypair(algo);

            let alice_shared = agreement::agree_ephemeral(
                alice_sec,
                &agreement::UnparsedPublicKey::new(algo, bob_pub.clone()),
                |key_mat| kdf_with_nonce(key_mat, &nonce),
            )
            .expect("alice_shared failed");
            let bob_shared = agreement::agree_ephemeral(
                bob_sec,
                &agreement::UnparsedPublicKey::new(algo, alice_pub.clone()),
                |key_mat| kdf_with_nonce(key_mat, &nonce),
            )
            .expect("bob_shared failed");
            assert!(alice_shared.is_ok());
            assert!(bob_shared.is_ok());

            assert_eq!(alice_shared.unwrap(), bob_shared.unwrap());
        }
    }

    #[test]
    fn test_encrypt_decrypt() -> Result<(), CryptoError> {
        let rng = rand::SystemRandom::new();
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce).expect("rng.fill failed");
        let shared_key = get_random_bytes(XCHACHA20_POLY1305_KEY_SIZE);
        let plaintext = b"hello world";
        let aad = Some(b"some aad".as_ref());
        let ciphertext = xchacha_encrypt_data(&shared_key, plaintext, aad, &nonce)?;
        let decrypted = xchacha_decrypt_data(&shared_key, &ciphertext, aad, &nonce)?;
        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_hmac() {
        let algos = vec![hmac::HMAC_SHA256, hmac::HMAC_SHA384, hmac::HMAC_SHA512];
        let msg = b"hello world";
        let key = get_random_bytes(32);
        let nonce = get_random_bytes(NONCE_SIZE);
        let msg = xchacha_encrypt_data(&key, msg, None, &nonce.try_into().unwrap()).unwrap();
        for algo in algos {
            let tag = hmac(&key, msg.clone(), algo);
            assert!(verify_hmac(&key, msg.clone(), tag, algo));
        }
    }
}
