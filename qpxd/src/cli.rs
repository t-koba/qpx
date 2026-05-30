use clap::{Parser, Subcommand, ValueEnum};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "qpxd", about = "qpx proxy daemon")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Run {
        #[arg(short, long, required = true, num_args = 1..)]
        config: Vec<PathBuf>,
    },
    Check {
        #[arg(short, long, required = true, num_args = 1..)]
        config: Vec<PathBuf>,
    },
    Init {
        #[arg(value_enum)]
        template: InitTemplate,
    },
    Schema {
        #[arg(long, value_enum, default_value_t = SchemaFormat::Json)]
        format: SchemaFormat,
    },
    Explain {
        #[arg(short, long, required = true, num_args = 1..)]
        config: Vec<PathBuf>,
        #[arg(long)]
        edge: Option<String>,
        #[arg(long)]
        route: Option<String>,
    },
    Match {
        #[arg(short, long, required = true, num_args = 1..)]
        config: Vec<PathBuf>,
        #[arg(long)]
        edge: String,
        #[arg(long)]
        src_ip: Option<IpAddr>,
        #[arg(long)]
        dst_port: Option<u16>,
        #[arg(long)]
        sni: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        path: Option<String>,
    },
    #[cfg(feature = "tls-rustls")]
    GenCa {
        #[arg(short = 'd', long)]
        state_dir: PathBuf,
    },
    Upgrade {
        #[arg(long)]
        pid: u32,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum InitTemplate {
    ReverseBasic,
    ForwardEgress,
    TransparentLinux,
    IpcGateway,
    TrustedIdentityExtAuthz,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum SchemaFormat {
    Json,
    Yaml,
}

pub(crate) struct MatchConfigRequest {
    pub(crate) edge: String,
    pub(crate) src_ip: Option<IpAddr>,
    pub(crate) dst_port: Option<u16>,
    pub(crate) sni: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) method: Option<String>,
    pub(crate) path: Option<String>,
}

#[cfg(test)]
mod tests;
