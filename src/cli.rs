use parse_size::parse_size;
use quiche::PathStatus;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::PathBuf;

use clap::ArgAction;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

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

fn parse_data_size(s: &str) -> Result<u64, String> {
    match parse_size(s) {
        Ok(v) => Ok(v),
        Err(_) => Err(format!("failed parsing {}", s)),
    }
}

fn parse_duration_seconds(s: &str) -> Result<std::time::Duration, String> {
    match s.parse::<f64>() {
        Ok(secs) => Ok(std::time::Duration::from_secs_f64(secs)),
        Err(e) => Err(format!("failed to parse duration {}: {}", s, e)),
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

#[derive(Debug, Clone, ValueEnum)]
pub enum SchedulerOpts {
    Blest,
    MinRTT,
    RoundRobin,
    BestPath,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum FlowHandlerOpts {
    Noop,
    Reordering,
}

const FC_HEADING: &str = "Flow Control Options";
const CC_HEADING: &str = "Congestion Control Options";
const LOG_HEADING: &str = "Logging Options";
const MP_HEADING: &str = "Multipath Options";

#[derive(Parser, Debug)]
#[command(author, about, long_about = None, version = super::version())]
pub struct Args {
    // --- Ungrouped Options ---
    /// Password required to start test
    #[arg(short, long, global = true)]
    pub password: Option<String>,

    /// The local address(es) to connect from. Must include a port (port 0 -> free port chosen automatically).
    /// Also accepts the name of a network interface (with or without port) to infer the address from.
    #[arg(short, default_value = "[::]:0", global = true)]
    pub local_addrs: Vec<String>,

    /// Bind the UDP sockets to an interface (SO_BINDTODEVICE).
    #[arg(long = "bind", default_value = "true", global = true, value_parser=parse_bool, action = ArgAction::Set)]
    pub bind_to_intf: bool,

    // --- LOG_HEADING ---
    /// Log to file with level trace
    #[arg(long, global = true, help_heading = LOG_HEADING)]
    pub logfile: Option<String>,

    /// Set the console logging level: default -> info, -v -> debug, -vv -> trace
    #[arg(short = 'v', action = ArgAction::Count, global = true, help_heading = LOG_HEADING)]
    pub verbose: u8,

    /// Write qlogs to this directory
    #[arg(long, global = true, env = "QLOGDIR", help_heading = LOG_HEADING)]
    pub qlogdir: Option<String>,

    /// Compress qlogs with zstandard
    #[arg(long, global = true, default_value = "true", value_parser=parse_bool, action = ArgAction::Set, help_heading = LOG_HEADING)]
    pub compress_qlogs: bool,

    // --- MP_HEADING ---
    /// Enable or disable multipath (Automatically enabled if more than one
    /// local_addr is present)
    #[arg(long = "mp", global = true, default_value = "false", value_parser=parse_bool, action = ArgAction::Set, help_heading = MP_HEADING)]
    pub multipath: bool,

    /// Set the packet multipath scheduler of this peer
    #[arg(long, value_enum, global = true, help_heading = MP_HEADING)]
    pub pscheduler: Option<quiche::scheduler::PacketSchedulerAlgo>,

    /// Set the frame multipath scheduler of this peer. Accepts a comma-separated list of schedulers.
    #[arg(long, value_enum, global = true, value_delimiter = ',', conflicts_with = "pscheduler", help_heading = MP_HEADING)]
    pub fscheduler: Option<Vec<quiche::scheduler::FrameSchedulerAlgo>>,

    /// Prefer usage of this path
    #[arg(long, global = true, help_heading = MP_HEADING)]
    pub prefer_path: Option<usize>,

    // --- CC_HEADING ---
    ///  Enable hystart (instead of slow start)
    #[arg(long, global = true, default_value = "true", value_parser=parse_bool, action = ArgAction::Set, help_heading = CC_HEADING)]
    pub hystart: bool,
    /// Set congestion control algorithm of this peer: Reno, CUBIC, or BBR
    #[arg(long = "cc", default_value = "cubic", global = true, help_heading = CC_HEADING)]
    pub congestion: String,

    // --- FC_HEADING ---
    /// Initial connection-wide flow control limit
    #[arg(long, global = true, default_value = "25165824", help_heading = FC_HEADING)]
    pub max_data: u64,
    /// Initial per-stream flow control limit
    #[arg(long, global = true, default_value = "1000000", help_heading = FC_HEADING)]
    pub max_stream_data: u64,

    /// The initial connection window
    #[arg(long, global = true, default_value = "49152", help_heading = FC_HEADING)]
    pub fc_initial_connection_window: u64,

    /// The initial stream window
    #[arg(long, global = true, default_value = "32768", help_heading = FC_HEADING)]
    pub fc_initial_stream_window: u64,

    /// Set the flow control window update threshold in percent (0-100)
    #[arg(long, global = true, default_value = "50", help_heading = FC_HEADING)]
    pub fc_window_update_threshold: u64,

    /// Set the flow control autotuning strategy
    #[arg(long, global = true, default_value = "reactive", help_heading = FC_HEADING)]
    pub fc_autotune_strategy: String,

    /// When autotuning, increase the window by this factor
    #[arg(long, global = true, default_value = "2", help_heading = FC_HEADING)]
    pub fc_autotune_increase_factor: u64,

    /// Reactive autotune if last update within factor * RTT
    #[arg(long, global = true, default_value = "2", help_heading = FC_HEADING)]
    pub fc_reactive_rtt_trigger_factor: u32,

    /// Set the length of the datagram send queue (unit: number of packets)
    #[arg(long, global = true, default_value = "100", help_heading = FC_HEADING)]
    pub dgram_send_queue_len: usize,

    /// Largest UDP payload to send or accept, in bytes. 1200 keeps a QUIC packet unfragmented inside the proxy tunnel.
    #[arg(long, global = true, default_value = "1350", value_parser = clap::value_parser!(u64).range(1200..=1350))]
    pub max_udp_payload: u64,

    // --- Subcommands ---
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

        /// Time in seconds to run test for. Is exclusive with --size.
        /// If neither --duration nor --size is specified, the default is 10s.
        #[arg(short, long, conflicts_with = "sizes", value_parser = parse_duration_seconds)]
        duration: Option<std::time::Duration>,

        /// How much data to send on a stream. Is exclusive with --duration.
        ///
        /// Can either take a single argument (in which case the same number of bytes are sent on all streams)
        /// or a list; the list must have the same number of elements as there are streams and each
        /// list element is the number of bytes that are supposed to be sent on that stream
        /// (identified by position). Can parse human-readable sizes, e.g. 10MB.
        #[arg(long, value_parser=parse_data_size, num_args = 1..)]
        sizes: Option<Vec<u64>>,

        /// Send data from server to client
        #[arg(short, long)]
        reverse: bool,

        /// Send data at the specified bitrate (can contain unit, e.g., 1MB, 1MiB, etc.)
        #[arg(short, long, value_parser=parse_bitrate)]
        bitrate: Option<u64>,

        /// Specifies the number of parallel uni-directional QUIC streams to open.
        #[arg(short, long, default_value = "1")]
        streams: usize,

        /// Set the multipath status of a path: (after sec, path id, status as uint)
        /// 1 => Standby
        /// 2 => Available
        /// 7 => Broken
        #[arg(long = "status", value_parser=parse_path_status)]
        path_statuses: Vec<(std::time::Duration, usize, PathStatus)>,
    },

    /// Run quicheperf server
    Server {
        /// Path to a server certificate. If omitted, a default certificate will be used.
        #[arg(long, requires = "key")]
        cert: Option<PathBuf>,

        /// Path to the certificate's private key. If omitted, a default key will be used.
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,

        /// quit after one run
        #[arg(long, short = '1')]
        oneshot: bool,
    },

    /// Run proxy client
    ProxyClient {
        /// The remote address(es) to connect to
        #[arg(short = 'c', required = true, value_parser=resolve_addr)]
        peer_addrs: Vec<SocketAddr>,

        /// Name of the tun interface. Create with:
        /// ip tuntap add mode tun multi_queue name mp0
        #[arg(long, default_value = "mp0")]
        tun: String,

        /// Set the multipath scheduler of this peer
        #[arg(long, value_enum, default_value = "reordering")]
        flow_handler: FlowHandlerOpts,

        /// Set the multipath status of a path: (after sec, path id, status as uint)
        /// 1 => Standby
        /// 2 => Available
        /// 7 => Broken
        #[arg(long = "status", value_parser=parse_path_status)]
        path_statuses: Vec<(std::time::Duration, usize, PathStatus)>,
    },

    /// Run proxy server
    ProxyServer {
        /// Path to the server certificate
        #[arg(long, requires = "key")]
        cert: Option<PathBuf>,

        /// Path to the certificate's private key
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,

        /// Name of the tun interface. Create with:
        /// ip tuntap add mode tun multi_queue name mp0
        #[arg(long, default_value = "mp0")]
        tun: String,

        /// quit after one run
        #[arg(long, short = '1')]
        oneshot: bool,

        /// Set the multipath scheduler of this peer
        #[arg(long, value_enum, default_value = "reordering")]
        flow_handler: FlowHandlerOpts,

        #[command(flatten)]
        path_log: crate::pathlog::PathLogArgs,
    },
}
