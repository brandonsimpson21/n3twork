use bytes::Bytes;
use chrono::{DateTime, FixedOffset, Utc};
use ipnet::{IpNet, IpSubnets};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use std::{
    fs::File,
    io::BufReader,
    path::Path,
};
use std::collections::{BTreeSet, HashSet};
use x509_parser::{certificate::X509Certificate, time::ASN1Time};

use crate::error::CryptoError;

#[derive(Debug, Clone)]
pub struct CertMetaData {
    pub name: String,
    pub ips: BTreeSet<IpNet>,
    pub subnets: BTreeSet<IpSubnets>,
    pub groups: HashSet<String>,
    pub not_before: DateTime<FixedOffset>,
    pub not_after: DateTime<FixedOffset>,
    pub pub_key: Bytes,
    pub is_ca: bool,
    pub issuer: String,
    pub curve: String,
}

impl Default for CertMetaData {
    fn default() -> Self {
        Self {
            name: String::new(),
            ips: BTreeSet::new(),
            subnets: BTreeSet::new(),
            groups: HashSet::new(),
            not_before: DateTime::from(Utc::now()),
            not_after: DateTime::from(Utc::now()),
            pub_key: Bytes::default(),
            is_ca: false,
            issuer: String::new(),
            curve: String::new(),
        }
    }
}

impl CertMetaData {
    pub fn new(
        name: &str,
        ips: BTreeSet<IpNet>,
        subnet: BTreeSet<IpSubnets>,
        groups: HashSet<String>,
        not_before: DateTime<FixedOffset>,
        not_after: DateTime<FixedOffset>,
        pub_key: Bytes,
        is_ca: bool,
        issuer: &str,
        curve: &str,
    ) -> Self {
        Self {
            name: name.to_string(),
            ips: ips,
            subnets: subnet,
            groups: groups,
            not_before: not_before,
            not_after: not_after,
            pub_key: pub_key,
            is_ca: is_ca,
            issuer: issuer.to_string(),
            curve: curve.to_string(),
        }
    }

    pub fn from_x509_cert<'d>(cert: &X509Certificate<'d>) -> Result<Self, CryptoError> {
        let validity = cert.validity();
        let not_before = parse_asn1_to_datetime(validity.not_before)?;
        let not_after = parse_asn1_to_datetime(validity.not_after)?;
        let issuer = cert.issuer.to_string();
        let is_ca = cert.is_ca();
        let pk = cert.public_key();
        let pk_bytes = pk.raw.iter().cloned().collect::<Bytes>();
        let name = cert.subject().to_string();
        let ips = BTreeSet::new(); //TODO
        let subnet = BTreeSet::new(); //TODO
        let groups = HashSet::new(); // TODO
        let curve = cert.signature_algorithm.oid().to_id_string();
        Ok(Self::new(
            &name, ips, subnet, groups, not_before, not_after, pk_bytes, is_ca, &issuer, &curve,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct N3tworkCertificate {
    pub metadata: CertMetaData,
    pub signature: Bytes,
    pub checksum: [u8; 32],
}

impl Default for N3tworkCertificate {
    fn default() -> Self {
        Self {
            metadata: CertMetaData::default(),
            signature: Bytes::default(),
            checksum: [0; 32],
        }
    }
}

impl N3tworkCertificate {
    pub fn new(metadata: CertMetaData, signature: &[u8], checksum: [u8; 32]) -> Self {
        Self {
            metadata: metadata,
            signature: Bytes::from_iter(signature.iter().cloned()),
            checksum,
        }
    }

    pub fn parse_cert_der<'d>(der: &CertificateDer<'d>) -> Result<Self, CryptoError> {
        let cert_bytes = der.to_vec();
        let checksum = crate::crypto::core::hash_sha256(&cert_bytes);
        let (_remaining_data, cert) = x509_parser::parse_x509_certificate(&*cert_bytes)
            .map_err(|e| CryptoError::CertError(e.to_string()))?;
        let metadata = CertMetaData::from_x509_cert(&cert)?;
        let signature = cert.signature_value.data.to_vec();

        if let Err(e) = cert.verify_signature(Some(cert.public_key())) {
            tracing::error!("Failed to verify signature: {}", e);
            return Err(CryptoError::CertError(
                "Failed to verify signature".to_string(),
            ));
        }
        Ok(Self::new(metadata, &signature, checksum))
    }

    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<Self>, CryptoError> {
        read_certs(path)?
            .iter()
            .map(|c| Self::parse_cert_der(c))
            .collect()
    }
}

pub fn read_certs<'c, T: AsRef<Path>>(path: T) -> Result<Vec<CertificateDer<'c>>, CryptoError> {
    let file = File::open(path.as_ref())
        .map_err(|_| CryptoError::CertError("Failed to open cert file".to_string()))?;
    let mut buf = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut buf)
        .filter_map(|c| c.ok())
        .collect::<Vec<CertificateDer<'_>>>();
    Ok(certs)
}

pub fn read_ecc_key<'c, T: AsRef<Path>>(
    path: T,
) -> Result<Vec<PrivateSec1KeyDer<'c>>, CryptoError> {
    let file = File::open(path.as_ref())
        .map_err(|_| CryptoError::KeyError("Failed to open key file".to_string()))?;
    let mut buf = BufReader::new(file);
    let keys = rustls_pemfile::ec_private_keys(&mut buf)
        .filter_map(|c| c.ok())
        .collect::<Vec<_>>();
    Ok(keys)
}

pub fn read_pks8_key<'c, T: AsRef<Path>>(
    path: T,
) -> Result<Vec<PrivatePkcs8KeyDer<'c>>, CryptoError> {
    let file = File::open(path.as_ref())
        .map_err(|_| CryptoError::KeyError("Failed to open key file".to_string()))?;
    let mut buf = BufReader::new(file);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut buf)
        .filter_map(|c| c.ok())
        .collect::<Vec<_>>();
    Ok(keys)
}

pub fn read_all(path: &str) -> Result<Vec<rustls_pemfile::Item>, CryptoError> {
    let file = File::open(path)
        .map_err(|_| CryptoError::KeyError("Failed to open key file".to_string()))?;
    let mut buf = BufReader::new(file);
    Ok(rustls_pemfile::read_all(&mut buf)
        .filter_map(|c| c.ok())
        .collect::<Vec<_>>())
}

fn parse_asn1_to_datetime(asn1_time: ASN1Time) -> Result<DateTime<FixedOffset>, CryptoError> {
    let time_rfc2822 = asn1_time
        .to_rfc2822()
        .map_err(|e| CryptoError::InternalError(e.to_string()))?;
    Ok(chrono::DateTime::parse_from_rfc2822(&*time_rfc2822)
        .map_err(|e| CryptoError::InternalError(e.to_string()))?)
}

#[cfg(test)]
mod test_pki {
    use super::*;

    #[test]
    fn test_read_cert_key() {
        let key = read_ecc_key("test/certs/RootCA.key");
        assert!(key.is_ok());
        let key = read_all("test/certs/RootCA.key");
        assert!(key.is_ok());
        let key = read_pks8_key("test/certs/RootCA.key");
        assert!(key.is_ok());
        let cert = N3tworkCertificate::read_from_file("test/certs/RootCA.pem");
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        assert_eq!(cert.len(), 1);
        let cert_default = N3tworkCertificate::default();
        assert!(cert_default.metadata.ips.is_empty());
    }
}
