use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub fn write_self_signed_cert(dir: &Path, dns_name: &str) -> Result<(PathBuf, PathBuf)> {
    let mut params = rcgen::CertificateParams::new(vec![dns_name.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns_name);
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let cert_path = dir.join(format!("{dns_name}.crt.pem"));
    let key_path = dir.join(format!("{dns_name}.key.pem"));
    fs::write(&cert_path, cert_pem).context("write cert")?;
    fs::write(&key_path, key_pem).context("write key")?;
    Ok((cert_path, key_path))
}
