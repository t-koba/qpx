use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

#[derive(Debug, Clone, Default)]
pub(crate) struct UpstreamCertificateInfo {
    pub(crate) present: bool,
    pub(crate) subject: Option<String>,
    pub(crate) issuer: Option<String>,
    pub(crate) san_dns: Vec<String>,
    pub(crate) san_uri: Vec<String>,
    pub(crate) fingerprint_sha256: Option<String>,
}

pub(crate) fn extract_upstream_certificate_info(raw_der: Option<&[u8]>) -> UpstreamCertificateInfo {
    let Some(raw_der) = raw_der else {
        return UpstreamCertificateInfo::default();
    };
    let Ok((_, cert)) = X509Certificate::from_der(raw_der) else {
        return UpstreamCertificateInfo {
            present: true,
            ..Default::default()
        };
    };
    let fingerprint = Sha256::digest(raw_der);
    let fingerprint_sha256 = Some(
        fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let mut san_dns = Vec::new();
    let mut san_uri = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(value) => san_dns.push(value.to_string()),
                GeneralName::URI(value) => san_uri.push(value.to_string()),
                _ => {}
            }
        }
    }
    UpstreamCertificateInfo {
        present: true,
        subject: Some(cert.subject().to_string()),
        issuer: Some(cert.issuer().to_string()),
        san_dns,
        san_uri,
        fingerprint_sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;

    #[test]
    fn extract_upstream_certificate_info_parses_dns_and_fingerprint() {
        let certified =
            generate_simple_self_signed(vec!["example.com".to_string()]).expect("self-signed cert");
        let info = extract_upstream_certificate_info(Some(certified.cert.der().as_ref()));
        assert!(info.present);
        assert_eq!(info.san_dns, vec!["example.com".to_string()]);
        assert!(info.san_uri.is_empty());
        assert_eq!(info.fingerprint_sha256.as_deref().map(str::len), Some(64));
    }
}
