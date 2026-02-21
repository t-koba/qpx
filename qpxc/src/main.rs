use anyhow::{Context, Result};
use clap::Parser;
use pcap_file::pcapng::{Block, PcapNgReader};
use qpx_core::exporter::STREAM_PREFACE_LINE;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

#[cfg(all(feature = "tls-rustls", feature = "tls-native"))]
compile_error!("qpxc: features tls-rustls and tls-native are mutually exclusive");

#[cfg(feature = "tls-rustls")]
use qpx_core::tls::{build_client_config, load_cert_chain, load_private_key};
#[cfg(feature = "tls-rustls")]
use rustls::pki_types::ServerName;
#[cfg(feature = "tls-rustls")]
use std::net::IpAddr;

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
use std::fs;

#[derive(Parser)]
#[command(name = "qpxc", about = "qpx stream client")]
struct Cli {
    #[arg(short = 'e', long, default_value = "127.0.0.1:19101")]
    endpoint: String,
    #[arg(short = 'm', long, default_value = "live", value_parser = ["live", "history", "follow"])]
    mode: String,
    #[arg(short = 's', long)]
    save: Option<PathBuf>,
    #[arg(short = 'v', long)]
    view: bool,
    #[arg(long)]
    extcap_interfaces: bool,
    #[arg(long)]
    extcap_dlts: bool,
    #[arg(long)]
    extcap_interface: Option<String>,
    #[arg(short = 'c', long)]
    capture: bool,
    #[arg(short = 'f', long)]
    fifo: Option<PathBuf>,

    #[arg(short = 't', long)]
    token_env: Option<String>,

    #[arg(short = 'T', long)]
    tls: bool,
    #[arg(short = 'a', long)]
    tls_ca_cert: Option<PathBuf>,
    #[cfg(feature = "tls-rustls")]
    #[arg(long)]
    tls_client_cert: Option<PathBuf>,
    #[cfg(feature = "tls-rustls")]
    #[arg(long)]
    tls_client_key: Option<PathBuf>,
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    #[arg(long)]
    tls_client_pkcs12: Option<PathBuf>,
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    #[arg(long)]
    tls_client_pkcs12_password_env: Option<String>,
    #[arg(short = 'n', long)]
    tls_server_name: Option<String>,
    #[arg(long)]
    tls_insecure_skip_verify: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let tls_args = TlsClientArgs {
        enabled: cli.tls,
        ca_cert: cli.tls_ca_cert.clone(),
        #[cfg(feature = "tls-rustls")]
        client_cert: cli.tls_client_cert.clone(),
        #[cfg(feature = "tls-rustls")]
        client_key: cli.tls_client_key.clone(),
        #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
        client_pkcs12: cli.tls_client_pkcs12.clone(),
        #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
        client_pkcs12_password_env: cli.tls_client_pkcs12_password_env.clone(),
        server_name: cli.tls_server_name.clone(),
        insecure_skip_verify: cli.tls_insecure_skip_verify,
    };

    if cli.extcap_interfaces {
        print_extcap_interfaces();
        return Ok(());
    }
    if cli.extcap_dlts {
        print_extcap_dlts();
        return Ok(());
    }
    if cli.view {
        return run_view(
            cli.endpoint.as_str(),
            cli.mode.as_str(),
            cli.token_env.as_deref(),
            &tls_args,
        );
    }

    let _ = cli.extcap_interface.as_deref();
    let _ = cli.capture;
    run_stream(
        cli.endpoint.as_str(),
        cli.mode.as_str(),
        cli.fifo.as_ref(),
        cli.save.as_ref(),
        cli.token_env.as_deref(),
        tls_args,
    )
}

fn print_extcap_interfaces() {
    println!("extcap {{version=1.0}}{{display=QPX Exporter extcap}}");
    println!("interface {{value=qpxc}}{{display=QPX Exporter Stream}}");
}

fn print_extcap_dlts() {
    println!("dlt {{number=101}}{{name=RAW}}{{display=Raw IP}}");
}

fn run_stream(
    endpoint: &str,
    mode: &str,
    fifo: Option<&PathBuf>,
    save: Option<&PathBuf>,
    token_env: Option<&str>,
    tls: TlsClientArgs,
) -> Result<()> {
    let token = token_env.map(load_required_env).transpose()?;
    let mut stream = connect_with_mode(endpoint, mode, token.as_deref(), &tls)?;
    let mut output: Box<dyn Write> = match fifo {
        Some(path) => Box::new(
            OpenOptions::new()
                .write(true)
                .open(path)
                .with_context(|| format!("failed to open fifo: {}", path.display()))?,
        ),
        None => Box::new(io::stdout()),
    };
    let mut save_file = match save {
        Some(path) => Some(
            File::create(path)
                .with_context(|| format!("failed to open save file: {}", path.display()))?,
        ),
        None => None,
    };

    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
        if let Some(file) = save_file.as_mut() {
            file.write_all(&buf[..n])?;
        }
    }
    output.flush()?;
    if let Some(file) = save_file.as_mut() {
        file.flush()?;
    }
    Ok(())
}

fn run_view(
    endpoint: &str,
    mode: &str,
    token_env: Option<&str>,
    tls: &TlsClientArgs,
) -> Result<()> {
    let token = token_env.map(load_required_env).transpose()?;
    let stream = connect_with_mode(endpoint, mode, token.as_deref(), tls)?;
    let mut reader = PcapNgReader::new(stream).context("failed to initialize pcapng reader")?;
    while let Some(block) = reader.next_block() {
        if let Block::EnhancedPacket(packet) = block? {
            println!(
                "iface={} ts_ns={} len={}",
                packet.interface_id,
                packet.timestamp.as_nanos(),
                packet.original_len
            );
        }
    }
    Ok(())
}

#[derive(Default)]
struct TlsClientArgs {
    enabled: bool,
    ca_cert: Option<PathBuf>,
    #[cfg(feature = "tls-rustls")]
    client_cert: Option<PathBuf>,
    #[cfg(feature = "tls-rustls")]
    client_key: Option<PathBuf>,
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    client_pkcs12: Option<PathBuf>,
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    client_pkcs12_password_env: Option<String>,
    server_name: Option<String>,
    insecure_skip_verify: bool,
}

enum ClientStream {
    Tcp(TcpStream),
    #[cfg(feature = "tls-rustls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    Tls(Box<native_tls::TlsStream<TcpStream>>),
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            Self::Tls(s) => s.flush(),
        }
    }
}

fn connect_with_mode(
    endpoint: &str,
    mode: &str,
    token: Option<&str>,
    tls: &TlsClientArgs,
) -> Result<ClientStream> {
    let tcp =
        TcpStream::connect(endpoint).with_context(|| format!("failed to connect: {}", endpoint))?;
    let mut stream = if tls.enabled {
        #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
        let server_name = tls
            .server_name
            .clone()
            .or_else(|| parse_host_from_endpoint(endpoint))
            .unwrap_or_else(|| "localhost".to_string());

        #[cfg(feature = "tls-rustls")]
        {
            let server_name = server_name_for_host(server_name.as_str())?;
            let ca_path = tls.ca_cert.as_deref();
            let client_chain = tls
                .client_cert
                .as_deref()
                .map(load_cert_chain)
                .transpose()?;
            let client_key = tls
                .client_key
                .as_deref()
                .map(load_private_key)
                .transpose()?;
            let config =
                build_client_config(ca_path, client_chain, client_key, tls.insecure_skip_verify)?;
            let conn = rustls::ClientConnection::new(config, server_name)?;
            ClientStream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
        }

        #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
        {
            let mut builder = native_tls::TlsConnector::builder();
            if tls.insecure_skip_verify {
                builder.danger_accept_invalid_certs(true);
                builder.danger_accept_invalid_hostnames(true);
            }
            if let Some(ca_path) = tls.ca_cert.as_deref() {
                let pem = fs::read(ca_path).with_context(|| {
                    format!("failed to read tls_ca_cert: {}", ca_path.display())
                })?;
                let cert = native_tls::Certificate::from_pem(&pem)
                    .map_err(|_| anyhow::anyhow!("invalid tls_ca_cert: {}", ca_path.display()))?;
                builder.add_root_certificate(cert);
            }
            if let Some(pkcs12_path) = tls.client_pkcs12.as_deref() {
                let password = match tls.client_pkcs12_password_env.as_deref() {
                    Some(env) => load_required_env(env)?,
                    None => String::new(),
                };
                let der = fs::read(pkcs12_path).with_context(|| {
                    format!(
                        "failed to read tls_client_pkcs12: {}",
                        pkcs12_path.display()
                    )
                })?;
                let identity =
                    native_tls::Identity::from_pkcs12(&der, password.as_str()).map_err(|_| {
                        anyhow::anyhow!("invalid pkcs12 identity: {}", pkcs12_path.display())
                    })?;
                builder.identity(identity);
            } else if let Some(env) = tls.client_pkcs12_password_env.as_deref() {
                return Err(anyhow::anyhow!(
                    "--tls-client-pkcs12-password-env ({env}) requires --tls-client-pkcs12"
                ));
            }

            let connector = builder.build().context("failed to build TLS connector")?;
            let tls_stream = connector
                .connect(server_name.as_str(), tcp)
                .with_context(|| format!("tls connect failed to {}", server_name))?;
            ClientStream::Tls(Box::new(tls_stream))
        }

        #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
        {
            // Keep CLI options consistent (they may be provided) and avoid dead_code lints in
            // no-TLS builds.
            let _ = tls.ca_cert.as_deref();
            let _ = tls.server_name.as_deref();
            let _ = tls.insecure_skip_verify;
            return Err(anyhow::anyhow!(
                "TLS requested but qpxc was built without TLS support"
            ));
        }
    } else {
        ClientStream::Tcp(tcp)
    };

    stream.write_all(format!("{STREAM_PREFACE_LINE}\n").as_bytes())?;
    if let Some(token) = token {
        stream.write_all(format!("AUTH {token}\n").as_bytes())?;
    }
    stream.write_all(format!("MODE {}\n", mode.to_ascii_uppercase()).as_bytes())?;
    Ok(stream)
}

fn load_required_env(name: &str) -> Result<String> {
    let value = std::env::var(name)
        .with_context(|| format!("{name} is required but not set"))?
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(anyhow::Error::msg(format!("{name} is set but empty")));
    }
    Ok(value)
}

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
fn parse_host_from_endpoint(endpoint: &str) -> Option<String> {
    let authority: http::uri::Authority = endpoint.parse().ok()?;
    Some(authority.host().to_string())
}

#[cfg(feature = "tls-rustls")]
fn server_name_for_host(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name for TLS: {}", host))
}
