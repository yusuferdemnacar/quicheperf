use parse_size::parse_size;
use quiche::PathStatus;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::PathBuf;

use clap::ArgAction;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

#[derive(Debug, Clone, ValueEnum)]
pub enum SchedulerOpts {
    Blest,
    MinRTT,
    RoundRobin,
}

// Inspired by https://github.com/clap-rs/clap/blob/dd5e6b23131f16ef8b090a8482f1b97c6a693498/clap_derive/examples/true_or_false.rs
fn parse_bool(s: &str) -> Result<bool, &'static str> {
    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("expected `true` or `false`"),
    }
}

fn parse_bitrate(s: &str) -> Result<u64, String> {
    match parse_size(s) {
        Ok(v) => Ok(v / 8),
        Err(_) => Err(format!("failed parsing {}", s)),
    }
}

fn resolve_addr(s: &str) -> Result<SocketAddr, String> {
    match s.to_socket_addrs() {
        Ok(mut it) => it.next().ok_or(format!("failed to resolve {}", s)),
        Err(e) => Err(format!("failed to resolve {}: {}", s, e)),
    }
}

fn parse_path_status(s: &str) -> Result<(std::time::Duration, usize, PathStatus), String> {
    let s = s.split(',').collect::<Vec<_>>();
    if s.len() != 3 {
        return Err("Failed to split status into three parts".into());
    }
    let secs = match s[0].parse::<u64>() {
        Ok(s) => s,
        Err(_) => return Err("Failed to parse seconds".into()),
    };
    let pid = match s[1].parse::<usize>() {
        Ok(v) => v,
        Err(_) => return Err("Failed to path path id".into()),
    };
    let status = match s[2].parse::<u64>() {
        Ok(v) => v,
        Err(e) => return Err(format!("Failed to parse status integer: {}", e)),
    };
    let status = PathStatus::from(status);
    Ok((std::time::Duration::from_secs(secs), pid, status))
}

#[derive(Parser, Debug)]
#[command(author, about, long_about = None, version = super::version())]
pub struct Args {
    /// Password required to start test
    #[arg(short, long, global = true)]
    pub password: Option<String>,

    /// Set congestion control algorithm of this peer: Reno, CUBIC, or BBR
    #[arg(long = "cc", default_value = "cubic", global = true)]
    pub congestion: String,

    /// Enable or disable multipath (Automatically enabled if more than one
    /// local_addr is present)
    #[arg(long = "mp", global = true, default_value = "false", value_parser=parse_bool, action = ArgAction::Set)]
    pub multipath: bool,

    /// Set the multipath scheduler of this peer
    #[arg(long, value_enum, global = true)]
    pub scheduler: Option<SchedulerOpts>,

    /// The local address(es) or interface names to connect from
    #[arg(short, default_value = "0.0.0.0:0", global = true)]
    pub local_addrs: Vec<String>,

    /// Initial connection-wide flow control limit
    #[arg(long, global = true, default_value = "25165824")]
    pub max_data: u64,
    /// Initial per-stream flow control limit
    #[arg(long, global = true, default_value = "1000000")]
    pub max_stream_data: u64,

    /// The initial connection window
    #[arg(long, global = true, default_value = "49152")]
    pub fc_initial_connection_window: u64,

    /// The initial stream window
    #[arg(long, global = true, default_value = "32768")]
    pub fc_initial_stream_window: u64,

    /// Set the flow control window update threshold in percent (0-100)
    #[arg(long, global = true, default_value = "50")]
    pub fc_window_update_threshold: u64,

    /// Set the flow control autotuning strategy
    #[arg(long, global = true, default_value = "reactive")]
    pub fc_autotune_strategy: String,

    /// When autotuning, increase the window by this factor
    #[arg(long, global = true, default_value = "2")]
    pub fc_autotune_increase_factor: u64,

    /// Reactive autotune if last update within factor * RTT
    #[arg(long, global = true, default_value = "2")]
    pub fc_reactive_rtt_trigger_factor: u32,

    ///  Enable hystart (instead of slow start)
    #[arg(long, global = true, default_value = "true", value_parser=parse_bool, action = ArgAction::Set)]
    pub hystart: bool,

    #[command(subcommand)]
    pub commands: Subcommands,
}

#[derive(Subcommand, Debug)]
pub enum Subcommands {
    /// Run quicheperf client
    Client {
        /// The remote address(es) to connect to
        #[arg(short = 'c', required = true, value_parser=resolve_addr)]
        peer_addrs: Vec<SocketAddr>,

        /// Time in seconds to run test for
        #[arg(short, long, default_value = "10")]
        duration: u64,

        /// Send data from server to client
        #[arg(short, long)]
        reverse: bool,

        /// Send data at the specified bitrate (can contain unit, e.g., 1MB, 1MiB, etc.)
        #[arg(short, long, value_parser=parse_bitrate)]
        bitrate: Option<u64>,

        /// Set the multipath status of a path: (after sec, path id, status as uint)
        /// 1 => Standby
        /// 2 => Available
        /// 7 => Broken
        #[arg(long = "status", value_parser=parse_path_status)]
        path_statuses: Vec<(std::time::Duration, usize, PathStatus)>,
    },
    /// Run quicheperf server
    Server {
        /// Path to the server certificate
        #[arg(long)]
        cert: PathBuf,

        /// Path to the certificate's private key
        #[arg(long)]
        key: PathBuf,

        /// quit after one run
        #[arg(long, short = '1')]
        oneshot: bool,
    },
}
