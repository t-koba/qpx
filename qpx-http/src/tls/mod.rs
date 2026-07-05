//! Shared upstream TLS connection builder. Cryptographic primitives
//! (CA, cert info, trust) live in `qpx-core::tls`; this module assembles client
//! connections (rustls / native-tls backends) over the shared `BoxTlsStream`.

pub mod builder;
