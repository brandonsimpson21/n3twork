use openssl::{
    ec::{EcGroup, EcKey},
    encrypt::{Decrypter, Encrypter},
    envelope::{Open, Seal},
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPrivate, HasPublic, Id, PKey, Private, Public},
    rsa::Rsa,
    sign::{Signer, Verifier},
    symm,
};

use crate::error::CryptoError;

/// New RSA private key
pub fn ossl_new_rsa_key(bits: Option<u32>) -> Result<PKey<Private>, CryptoError> {
    let rsa = Rsa::generate(bits.unwrap_or(2048))?;
    let sec_key = PKey::from_rsa(rsa)?;
    Ok(sec_key)
}

/// New elliptic curve keypair
/// if curve is None defaults to X9_62_PRIME256V1 IE NIST P-256
pub fn ossl_new_ec_key(curve: Option<Nid>) -> Result<(PKey<Private>, PKey<Public>), CryptoError> {
    let curve = curve.unwrap_or(Nid::X9_62_PRIME256V1);

    let group = EcGroup::from_curve_name(curve)?;
    let ec_sec_key = EcKey::generate(&group)?;

    let ec_pub_key = EcKey::from_public_key(&group, &ec_sec_key.public_key())?;

    let sec_key = PKey::from_ec_key(ec_sec_key)?;
    let pub_key = PKey::from_ec_key(ec_pub_key)?;

    Ok((sec_key, pub_key))
}

/// New ed25519 keypair
pub fn ossl_new_ed25519_keypair() -> Result<(PKey<Private>, PKey<Public>), CryptoError> {
    let sec_key = PKey::generate_ed25519()?;
    let pub_key = PKey::public_key_from_raw_bytes(&*sec_key.raw_public_key()?, Id::ED25519)?;
    Ok((sec_key, pub_key))
}

/// New x25519 keypair
pub fn ossl_new_x25519_keypair() -> Result<(PKey<Private>, PKey<Public>), CryptoError> {
    let sec_key = PKey::generate_x25519()?;
    let pub_key = PKey::public_key_from_raw_bytes(&*sec_key.raw_public_key()?, Id::X25519)?;
    Ok((sec_key, pub_key))
}

/// envelope encryption seal
pub fn ossl_seal<T, B>(
    pub_keys: &[PKey<T>],
    cipher: symm::Cipher,
    secret: B,
) -> Result<(Seal, Vec<u8>, usize), CryptoError>
where
    B: AsRef<[u8]>,
    T: HasPublic,
{
    let secret = secret.as_ref();
    let mut seal = Seal::new(cipher, pub_keys)?;
    let mut encrypted = vec![0; secret.len() + cipher.block_size()];
    let mut enc_len = seal.update(secret, &mut encrypted)?;
    enc_len += seal.finalize(&mut encrypted[enc_len..])?;
    Ok((seal, encrypted, enc_len))
}

/// Envelope encryption unseal
pub fn ossl_unseal<T, B>(
    sec_key: &PKey<T>,
    cipher: symm::Cipher,
    encrypted_key: B,
    encrypted: B,
    enc_len: usize,
    iv: Option<&[u8]>,
) -> Result<(Vec<u8>, usize), CryptoError>
where
    B: AsRef<[u8]>,
    T: HasPrivate,
{
    let encrypted = encrypted.as_ref();
    let encrypted_key = encrypted_key.as_ref();
    let mut open = Open::new(cipher, &sec_key, iv, encrypted_key).unwrap();
    let mut decrypted = vec![0; enc_len + cipher.block_size()];
    let mut dec_len = open.update(&encrypted[..enc_len], &mut decrypted).unwrap();
    dec_len += open.finalize(&mut decrypted[dec_len..]).unwrap();
    Ok((decrypted[..dec_len].to_vec(), dec_len))
}

pub fn ossl_sign<B>(
    key: &PKey<Private>,
    digest: MessageDigest,
    data: impl Iterator<Item = B>,
) -> Result<Vec<u8>, CryptoError>
where
    B: AsRef<[u8]>,
{
    let mut signer = Signer::new(digest, key)?;
    for d in data {
        signer.update(d.as_ref())?;
    }

    Ok(signer.sign_to_vec()?)
}

pub fn ossl_verify<B>(
    key: &PKey<Private>,
    digest: MessageDigest,
    data: impl Iterator<Item = B>,
    sig: &[u8],
) -> Result<bool, CryptoError>
where
    B: AsRef<[u8]>,
{
    let mut verifier = Verifier::new(digest, key)?;
    for d in data {
        verifier.update(d.as_ref())?;
    }
    Ok(verifier.verify(sig)?)
}

#[cfg(test)]
mod test_openssl_crypto {

    use super::*;

    fn load_test_public_private() -> (PKey<Private>, PKey<Public>) {
        let private_pem = include_bytes!("../../test/rsa.pem");
        let public_pem = include_bytes!("../../test/rsa.pub");
        let private_key = PKey::private_key_from_pem(private_pem).unwrap();
        let public_key = PKey::public_key_from_pem(public_pem).unwrap();
        (private_key, public_key)
    }

    #[test]
    fn test_seal() {
        let (private_key, public_key) = load_test_public_private();
        let cipher = symm::Cipher::aes_256_cbc();
        let secret = b"My secret message";
        let (seal, encrypted, enc_len) = ossl_seal(&[public_key], cipher, secret).unwrap();
        let encrypted_key = &seal.encrypted_keys()[0];
        let iv = seal.iv();
        let (decrypted, dec_len) =
            ossl_unseal(&private_key, cipher, encrypted_key, &encrypted, enc_len, iv).unwrap();
        assert_eq!(&secret[..], &decrypted[..dec_len]);
    }

    #[test]
    fn test_ossl_sign_verify() {
        let (keypair, _) = ossl_new_ec_key(None).unwrap();
        let digest_type = MessageDigest::sha256();
        let data = vec![b"data1", b"data2", b"data3"];
        let sig = ossl_sign(&keypair, digest_type, data.iter());
        assert!(sig.is_ok());
        let sig = sig.unwrap();
        let verify = ossl_verify(&keypair, digest_type, data.iter(), &sig);
        assert!(verify.is_ok());
        let verify = verify.unwrap();
        assert!(verify);
    }
}
