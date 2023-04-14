use std::net::SocketAddr;
use std::path::PathBuf;

use clap::ArgAction;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

#[derive(Debug, Clone, ValueEnum)]
pub enum SchedulerOpts {
    Blest,
    MinRTT,
}

// Inspired by https://github.com/clap-rs/clap/blob/dd5e6b23131f16ef8b090a8482f1b97c6a693498/clap_derive/examples/true_or_false.rs
fn parse_bool(s: &str) -> Result<bool, &'static str> {
    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("expected `true` or `false`"),
    }
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

    /// The local address(es) to connect from
    #[arg(short, default_value = "0.0.0.0:0", global = true)]
    pub local_addrs: Vec<SocketAddr>,

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
        #[arg(short = 'c', required = true)]
        peer_addrs: Vec<SocketAddr>,

        /// Time in seconds to run test for
        #[arg(short, long, default_value = "10")]
        duration: u64,

        /// Send data from server to client
        #[arg(short, long)]
        reverse: bool,
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
