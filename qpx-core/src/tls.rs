#[cfg(feature = "tls-rustls")]
mod imp {

    use anyhow::{anyhow, Context, Result};
    use chrono::Datelike as _;
    use lru::LruCache;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    };
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::ring::sign::any_supported_type;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
    use std::fs;
    use std::io::BufReader;
    use std::num::NonZeroUsize;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use webpki_roots::TLS_SERVER_ROOTS;

    #[derive(Clone)]
    pub struct CaStore {
        issuer: Arc<Issuer<'static, KeyPair>>,
        ca_pem: String,
        ca_key_pem: String,
        ca_der: Vec<u8>,
        state_dir: PathBuf,
    }

    #[derive(Clone)]
    pub struct MitmConfig {
        pub ca: CaStore,
        pub resolver: Arc<DynamicCertResolver>,
        pub server_config: Arc<ServerConfig>,
    }

    pub fn load_or_generate_ca(state_dir: &Path) -> Result<CaStore> {
        ensure_path_not_symlink(state_dir, "state dir")?;
        fs::create_dir_all(state_dir)
            .with_context(|| format!("failed to create state dir {}", state_dir.display()))?;
        let cert_path = state_dir.join("ca.crt");
        let key_path = state_dir.join("ca.key");
        if cert_path.exists() && key_path.exists() {
            ensure_path_not_symlink(&cert_path, "ca cert")?;
            ensure_path_not_symlink(&key_path, "ca key")?;
            enforce_private_key_permissions(&key_path)?;
            let ca_pem = fs::read_to_string(&cert_path)?;
            let ca_key_pem = fs::read_to_string(&key_path)?;
            let key_pair = KeyPair::from_pem(&ca_key_pem)?;
            let issuer = Issuer::from_ca_cert_pem(&ca_pem, key_pair)?;
            let ca_der = {
                let mut reader = BufReader::new(ca_pem.as_bytes());
                let mut certs = certs(&mut reader)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|_| anyhow!("invalid CA pem"))?;
                certs.pop().ok_or_else(|| anyhow!("no CA cert found"))?
            };
            return Ok(CaStore {
                issuer: Arc::new(issuer),
                ca_pem,
                ca_key_pem,
                ca_der: ca_der.to_vec(),
                state_dir: state_dir.to_path_buf(),
            });
        }

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "qpx Proxy CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let now = chrono::Utc::now();
        let not_before = now.date_naive();
        let not_after = (now + chrono::Duration::days(365 * 10)).date_naive();
        params.not_before = rcgen::date_time_ymd(
            not_before.year(),
            not_before.month() as u8,
            not_before.day() as u8,
        );
        params.not_after = rcgen::date_time_ymd(
            not_after.year(),
            not_after.month() as u8,
            not_after.day() as u8,
        );

        let key_pair = KeyPair::generate()?;
        let ca_cert = params.self_signed(&key_pair)?;
        let ca_pem = ca_cert.pem();
        let ca_key_pem = key_pair.serialize_pem();
        write_cert_file(&cert_path, &ca_pem)?;
        write_private_key_file(&key_path, &ca_key_pem)?;
        let ca_der = ca_cert.der().to_vec();
        let issuer = Issuer::new(params, key_pair);
        Ok(CaStore {
            issuer: Arc::new(issuer),
            ca_pem,
            ca_key_pem,
            ca_der,
            state_dir: state_dir.to_path_buf(),
        })
    }

    pub fn write_ca_files(state_dir: &Path) -> Result<(PathBuf, PathBuf)> {
        let ca = load_or_generate_ca(state_dir)?;
        let cert_path = ca.cert_path();
        let key_path = ca.key_path();
        write_cert_file(&cert_path, &ca.ca_pem)?;
        write_private_key_file(&key_path, &ca.ca_key_pem)?;
        Ok((cert_path, key_path))
    }

    #[cfg(unix)]
    fn write_cert_file(path: &Path, contents: &str) -> Result<()> {
        write_text_file(path, contents, 0o644)
    }

    #[cfg(not(unix))]
    fn write_cert_file(path: &Path, contents: &str) -> Result<()> {
        write_text_file(path, contents)
    }

    #[cfg(unix)]
    fn write_private_key_file(path: &Path, contents: &str) -> Result<()> {
        write_text_file(path, contents, 0o600)?;
        enforce_private_key_permissions(path)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn write_private_key_file(path: &Path, contents: &str) -> Result<()> {
        write_text_file(path, contents)?;
        enforce_private_key_permissions(path)?;
        Ok(())
    }

    #[cfg(unix)]
    fn write_text_file(path: &Path, contents: &str, mode: u32) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn write_text_file(path: &Path, contents: &str) -> Result<()> {
        // Best-effort protection: do not write through a symlink on platforms without O_NOFOLLOW.
        ensure_path_not_symlink(path, "output file")?;
        fs::write(path, contents)?;
        Ok(())
    }

    #[cfg(unix)]
    fn enforce_private_key_permissions(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::metadata(path)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn enforce_private_key_permissions(path: &Path) -> Result<()> {
        // Best-effort: ensure we didn't resolve a symlink path for sensitive key material.
        ensure_path_not_symlink(path, "private key")?;
        Ok(())
    }

    fn ensure_path_not_symlink(path: &Path, label: &str) -> Result<()> {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(anyhow!(
                    "{label} path must not be a symlink: {}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    impl CaStore {
        pub fn state_dir(&self) -> &Path {
            &self.state_dir
        }

        pub fn cert_path(&self) -> PathBuf {
            self.state_dir().join("ca.crt")
        }

        pub fn key_path(&self) -> PathBuf {
            self.state_dir().join("ca.key")
        }

        pub fn mitm_config(&self) -> Result<MitmConfig> {
            let resolver = Arc::new(DynamicCertResolver::new(self.clone()));
            let mut config = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver.clone());
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Ok(MitmConfig {
                ca: self.clone(),
                resolver,
                server_config: Arc::new(config),
            })
        }

        pub fn client_config(&self, verify: bool) -> Result<Arc<ClientConfig>> {
            let mut root = RootCertStore::empty();
            root.extend(TLS_SERVER_ROOTS.iter().cloned());
            let mut config = ClientConfig::builder()
                .with_root_certificates(root)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            if verify {
                Ok(Arc::new(config))
            } else {
                config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(NoVerifier));
                Ok(Arc::new(config))
            }
        }

        pub fn ca_pem(&self) -> &str {
            &self.ca_pem
        }

        pub fn issue_server_cert(
            &self,
            subject_alt_names: &[String],
        ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
            let mut sans: Vec<String> = subject_alt_names
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            if sans.is_empty() {
                sans.push("localhost".to_string());
            }

            let mut params = CertificateParams::new(sans.clone())?;
            params.distinguished_name = DistinguishedName::new();
            params
                .distinguished_name
                .push(DnType::CommonName, sans[0].clone());
            let key_pair = KeyPair::generate()?;
            let leaf = params.signed_by(&key_pair, self.issuer.as_ref())?;
            let chain = vec![
                leaf.der().clone(),
                CertificateDer::from(self.ca_der.clone()),
            ];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
            Ok((chain, key))
        }
    }

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    #[derive(Clone)]
    pub struct DynamicCertResolver {
        ca: CaStore,
        cache: Arc<Mutex<LruCache<String, Arc<CertifiedKey>>>>,
    }

    impl std::fmt::Debug for DynamicCertResolver {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DynamicCertResolver").finish()
        }
    }

    impl DynamicCertResolver {
        fn new(ca: CaStore) -> Self {
            Self {
                ca,
                cache: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(256).unwrap()))),
            }
        }

        fn issue_cert(&self, host: &str) -> Result<Arc<CertifiedKey>> {
            let mut params = CertificateParams::new(vec![host.to_string()])?;
            params.distinguished_name = DistinguishedName::new();
            params.distinguished_name.push(DnType::CommonName, host);
            let key_pair = KeyPair::generate()?;
            let leaf = params.signed_by(&key_pair, self.ca.issuer.as_ref())?;

            let cert_chain = vec![
                leaf.der().clone(),
                CertificateDer::from(self.ca.ca_der.clone()),
            ];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
            let signing_key =
                any_supported_type(&key).map_err(|_| anyhow!("failed to create signing key"))?;
            Ok(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
        }
    }

    impl ResolvesServerCert for DynamicCertResolver {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            let server_name = client_hello
                .server_name()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            if let Ok(mut cache) = self.cache.lock() {
                if let Some(entry) = cache.get(&server_name) {
                    return Some(entry.clone());
                }
            }
            let issued = self.issue_cert(&server_name).ok()?;
            if let Ok(mut cache) = self.cache.lock() {
                cache.put(server_name, issued.clone());
            }
            Some(issued)
        }
    }

    pub fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
        let data =
            fs::read(path).with_context(|| format!("failed to read cert {}", path.display()))?;
        let mut reader = BufReader::new(&data[..]);
        let certs = certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| anyhow!("invalid cert {}", path.display()))?;
        Ok(certs)
    }

    pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
        let data =
            fs::read(path).with_context(|| format!("failed to read key {}", path.display()))?;
        let mut reader = BufReader::new(&data[..]);
        if let Ok(mut keys) =
            pkcs8_private_keys(&mut reader).collect::<std::result::Result<Vec<_>, _>>()
        {
            if let Some(key) = keys.pop() {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
        }
        let mut reader = BufReader::new(&data[..]);
        if let Ok(mut keys) =
            rsa_private_keys(&mut reader).collect::<std::result::Result<Vec<_>, _>>()
        {
            if let Some(key) = keys.pop() {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
        }
        Err(anyhow!("no private key found in {}", path.display()))
    }

    pub fn build_server_config(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Arc<ServerConfig>> {
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    pub fn build_client_config(
        ca_cert: Option<&Path>,
        client_cert_chain: Option<Vec<CertificateDer<'static>>>,
        client_key: Option<PrivateKeyDer<'static>>,
        insecure_skip_verify: bool,
    ) -> Result<Arc<ClientConfig>> {
        let mut root = RootCertStore::empty();
        if let Some(path) = ca_cert {
            let certs = load_cert_chain(path)?;
            let (added, _) = root.add_parsable_certificates(certs);
            if added == 0 {
                return Err(anyhow!("no CA certs loaded from {}", path.display()));
            }
        } else {
            root.extend(TLS_SERVER_ROOTS.iter().cloned());
        }

        let builder = ClientConfig::builder().with_root_certificates(root);
        let mut config = match (client_cert_chain, client_key) {
            (Some(chain), Some(key)) => builder
                .with_client_auth_cert(chain, key)
                .map_err(|_| anyhow!("invalid client certificate/key"))?,
            (None, None) => builder.with_no_client_auth(),
            _ => {
                return Err(anyhow!(
                    "client_cert_chain and client_key must be set together"
                ))
            }
        };
        if insecure_skip_verify {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));
        }
        Ok(Arc::new(config))
    }
} // mod imp

#[cfg(feature = "tls-rustls")]
pub use imp::*;

// --- Stub implementation when tls-rustls is not enabled ---

#[cfg(not(feature = "tls-rustls"))]
use anyhow::{anyhow, Result};
#[cfg(not(feature = "tls-rustls"))]
use std::path::{Path, PathBuf};

#[cfg(not(feature = "tls-rustls"))]
#[derive(Clone)]
pub struct CaStore {
    state_dir: PathBuf,
}

#[cfg(not(feature = "tls-rustls"))]
#[derive(Clone)]
pub struct MitmConfig;

#[cfg(not(feature = "tls-rustls"))]
pub fn load_or_generate_ca(state_dir: &Path) -> Result<CaStore> {
    Err(anyhow!(
        "TLS (rustls) support is not enabled in this build (enable feature tls-rustls); state_dir={}",
        state_dir.display()
    ))
}

#[cfg(not(feature = "tls-rustls"))]
pub fn write_ca_files(state_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    Err(anyhow!(
        "TLS (rustls) support is not enabled in this build (enable feature tls-rustls); state_dir={}",
        state_dir.display()
    ))
}

#[cfg(not(feature = "tls-rustls"))]
impl CaStore {
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn cert_path(&self) -> PathBuf {
        self.state_dir().join("ca.crt")
    }

    pub fn key_path(&self) -> PathBuf {
        self.state_dir().join("ca.key")
    }

    pub fn mitm_config(&self) -> Result<MitmConfig> {
        Err(anyhow!(
            "TLS MITM is not available without the rustls backend (enable feature tls-rustls)"
        ))
    }
}
