/// Parsed metadata from a TLS ClientHello.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsClientHelloInfo {
    /// Server Name Indication value.
    pub sni: Option<String>,
    /// First advertised ALPN protocol when available.
    pub alpn: Option<String>,
    /// Parsed TLS version label.
    pub tls_version: Option<String>,
    /// JA3 fingerprint.
    pub ja3: Option<String>,
    /// JA4 fingerprint.
    pub ja4: Option<String>,
}
