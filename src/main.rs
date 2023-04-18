// Copyright (C) 2020, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;
extern crate serde;

mod cli;
mod client;
mod common;
mod protocol;
mod sendto;
mod server;
mod ui;

use std::process::ExitCode;
use std::time::Duration;

use crate::protocol::TestConfig;
use cli::Args;
use git_testament::git_testament_macros;

use clap::Parser;
use quiche::scheduler;

fn main() -> ExitCode {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    // Parse CLI parameters.
    let args = cli::Args::parse();

    let mut config = match make_quiche_config(&args) {
        Ok(v) => v,
        Err(exitcode) => return exitcode,
    };

    match args.commands {
        cli::Subcommands::Client {
            peer_addrs,
            duration,
            reverse,
        } => {
            if args.local_addrs.len() != peer_addrs.len() {
                eprintln!(
                "Same number of local and peer addresses expected. One path will be created per pair.\n\
                local_addrs={:?}, peer_addrs={:?}",
                args.local_addrs, peer_addrs
            );
                return ExitCode::FAILURE;
            }

            let tc = TestConfig {
                local_addrs: args.local_addrs.iter().map(|s| s.to_string()).collect(),
                peer_addrs: peer_addrs.iter().map(|s| s.to_string()).collect(),
                password: args.password,
                client_sending: !reverse,
                duration: Duration::from_secs(duration),
            };

            let res = match args.scheduler.unwrap_or(cli::SchedulerOpts::MinRTT) {
                cli::SchedulerOpts::Blest => client::connect(
                    args.local_addrs,
                    peer_addrs,
                    tc,
                    config,
                    scheduler::Blest::new(),
                ),
                cli::SchedulerOpts::MinRTT => client::connect(
                    args.local_addrs,
                    peer_addrs,
                    tc,
                    config,
                    scheduler::MinRTT::new(),
                ),
            };

            return match res {
                Err(client::ClientError::HandshakeFail) => ExitCode::FAILURE,

                // Err(client::ClientError::HttpFail) => std::process::exit(-2),
                Err(client::ClientError::Other(e)) => {
                    eprintln!("{}", e);
                    ExitCode::FAILURE
                }

                Ok(_) => ExitCode::SUCCESS,
            };
        }
        cli::Subcommands::Server {
            cert,
            key,
            oneshot: _,
        } => {
            if let Err(e) = config.load_cert_chain_from_pem_file(cert.to_str().unwrap()) {
                eprintln!("Error loading certificate from {:?}: {}", cert, e);
                return ExitCode::FAILURE;
            };

            if let Err(e) = config.load_priv_key_from_pem_file(key.to_str().unwrap()) {
                eprintln!("Error loading private key from {:?}: {}", key, e);
                return ExitCode::FAILURE;
            };

            server::listen(args.local_addrs, args.password, config);
        }
    }

    ExitCode::FAILURE
}

pub fn make_quiche_config(args: &Args) -> Result<quiche::Config, ExitCode> {
    let mut config = match quiche::Config::new(quiche::PROTOCOL_VERSION) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Could not create quiche config: {}", e);
            return Err(ExitCode::FAILURE);
        }
    };

    config
        .set_application_protos(&common::QUICHEPERF_ALPN)
        .unwrap();

    config.set_max_idle_timeout(30_000); // in ms
    config.set_max_recv_udp_payload_size(common::MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(common::MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(args.max_data);

    config.set_initial_max_stream_data_bidi_local(args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(args.max_stream_data);
    config.set_initial_max_stream_data_uni(args.max_stream_data);

    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_ack_delay_exponent(3); // quiche default
    config.set_max_ack_delay(25); // quiche default
    config.set_active_connection_id_limit(5);
    config.set_disable_active_migration(false);

    // get_bool(--mp) -> is the flag present?
    let implicitely_mp = !args.multipath && args.local_addrs.len() > 1;
    let explicitly_mp = args.multipath;
    if implicitely_mp || explicitly_mp {
        config.set_multipath(true);
        info!("Enabled multipath");
    } else {
        config.set_multipath(false);
    }

    if let Ok(cwnd) = args.congestion.parse::<usize>() {
        config.set_cc_algorithm_name("constant").unwrap();
        config.set_constant_cwnd(cwnd);
        info!("Set constant cwnd={}B", cwnd);
    } else if let Err(e) = config.set_cc_algorithm_name(args.congestion.as_ref()) {
        eprintln!("Could not set CCA {}: {}", args.congestion, e);
        return Err(ExitCode::FAILURE);
    };

    config.enable_hystart(args.hystart);
    config.enable_pacing(true);

    config.enable_dgram(false, 1000, 1000);

    config.set_max_connection_window(25_165_824);
    config.set_max_stream_window(16_777_216);

    // config.set_stateless_reset_token
    // config.set_disable_dcid_reuse

    config.flow_control_config.initial_connection_window = args.fc_initial_connection_window;
    config.flow_control_config.initial_stream_window = args.fc_initial_stream_window;
    config.flow_control_config.window_update_threshold = args.fc_window_update_threshold;
    config.flow_control_config.autotune_increase_factor = args.fc_autotune_increase_factor;
    config.flow_control_config.reactive_rtt_trigger_factor = args.fc_reactive_rtt_trigger_factor;

    if let Err(e) = config.set_fc_autotune_strategy(&args.fc_autotune_strategy) {
        eprintln!(
            "Error setting flow control autotune strategy {}: {}",
            args.fc_autotune_strategy, e
        );
        return Err(ExitCode::FAILURE);
    }

    Ok(config)
}

git_testament_macros!(version);
pub const fn version() -> &'static str {
    if cfg!(debug_assertions) {
        concat!(env!("CARGO_PKG_VERSION"), " (debug) ", version_testament!())
    } else {
        concat!(
            env!("CARGO_PKG_VERSION"),
            " (release) ",
            version_testament!()
        )
    }
}
