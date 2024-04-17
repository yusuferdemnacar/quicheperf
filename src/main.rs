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
mod perf;
mod perf_ui;
mod proxy;
mod proxy_ui;
mod sendto;
mod server;

use std::cmp::min;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::perf::TestConfig;
use cli::Args;
use client::{Client, ClientError};
use common::PathStatusUpdater;
use git_testament::git_testament_macros;

use clap::Parser;
use perf::Perf;
use quiche::scheduler::{self, MultipathScheduler};
use server::Server;
use std::net::SocketAddr;

use lazy_static::lazy_static;

lazy_static! {
    // time panics when trying to fetch the local time offset in a multi-threaded program.
    // We therefore store it when the program is initialized.
    pub static ref UTC_OFFSET: time::UtcOffset = time::UtcOffset::current_local_offset().unwrap_or_else(|_| {
        warn!("Failed to retrieve the local UTC offset");
        time::UtcOffset::UTC
    });
}

pub fn make_quiche_config(args: &Args) -> Result<quiche::Config, ExitCode> {
    let mut config = match quiche::Config::new(quiche::PROTOCOL_VERSION) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Could not create quiche config: {}", e);
            return Err(ExitCode::FAILURE);
        }
    };

    // config.set_application_protos(&perf::ALPN).unwrap();

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

    config.enable_dgram(true, 1000, 1000);

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

fn main() -> ExitCode {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    lazy_static::initialize(&UTC_OFFSET);

    // Parse CLI parameters.
    let args = cli::Args::parse();

    let mut quiche_config = match make_quiche_config(&args) {
        Ok(v) => v,
        Err(exitcode) => return exitcode,
    };

    let terminate = Arc::new(AtomicBool::new(false));
    let t = terminate.clone();

    ctrlc::set_handler(move || {
        debug!("SIGINT received, set terminate=true");
        t.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let local_addrs: Vec<SocketAddr> = args
        .local_addrs
        .iter()
        .map(|local_addr| {
            let socket_parse_err = match local_addr.parse::<SocketAddr>() {
                Ok(v) => return Some(v),
                Err(e) => e,
            };

            match common::get_ip_from_ifname(local_addr) {
                Some(v) => {
                    info!("{}: use local IP {}", local_addr, v);
                    Some(v)
                }
                None => {
                    eprintln!(
                        "Could neither convert {} to IP nor find interface IP address: {}",
                        local_addr, socket_parse_err
                    );
                    None
                }
            }
        })
        .filter(|v| v.is_some())
        .map(|v| v.unwrap())
        .collect();

    let scheduler: Box<dyn scheduler::MultipathScheduler> =
        match args.scheduler.unwrap_or(cli::SchedulerOpts::MinRTT) {
            cli::SchedulerOpts::Blest => Box::new(scheduler::Blest::new()),
            cli::SchedulerOpts::MinRTT => Box::new(scheduler::MinRTT::new()),
            cli::SchedulerOpts::RoundRobin => Box::new(scheduler::RoundRobin::new()),
        };

    match args.commands {
        cli::Subcommands::Client {
            peer_addrs,
            duration,
            reverse,
            bitrate: bitrate_target,
            path_statuses,
        } => {
            if args.local_addrs.len() != peer_addrs.len() {
                eprintln!(
                "Same number of local and peer addresses expected. One path will be created per pair.\n\
                local_addrs={:?}, peer_addrs={:?}",
                args.local_addrs, peer_addrs
            );
                return ExitCode::FAILURE;
            }

            let psu = match common::PathStatusUpdater::new(
                Instant::now(),
                local_addrs.clone(),
                peer_addrs.clone(),
                path_statuses,
            ) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Path status updater: {}", e);
                    return ExitCode::FAILURE;
                }
            };

            let tc = TestConfig {
                local_addrs: local_addrs.iter().map(|s| s.to_string()).collect(),
                peer_addrs: peer_addrs.iter().map(|s| s.to_string()).collect(),
                password: args.password,
                client_sending: !reverse,
                duration: Duration::from_secs(duration),
                bitrate_target: bitrate_target,
            };

            quiche_config.set_application_protos(&perf::ALPN).unwrap();

            let client = client::Client::new(local_addrs, peer_addrs, quiche_config).unwrap();

            return match perf_client(client, scheduler, tc, psu, terminate) {
                Err(client::ClientError::HandshakeFail) => ExitCode::FAILURE,

                Err(client::ClientError::IOFail(e)) | Err(client::ClientError::Other(e)) => {
                    eprintln!("{}", e);
                    ExitCode::FAILURE
                }

                Ok(_) => ExitCode::SUCCESS,
            };
        }
        cli::Subcommands::Server { cert, key, oneshot } => {
            if let Err(e) = quiche_config.load_cert_chain_from_pem_file(cert.to_str().unwrap()) {
                eprintln!("Error loading certificate from {:?}: {}", cert, e);
                return ExitCode::FAILURE;
            };

            if let Err(e) = quiche_config.load_priv_key_from_pem_file(key.to_str().unwrap()) {
                eprintln!("Error loading private key from {:?}: {}", key, e);
                return ExitCode::FAILURE;
            };

            quiche_config.set_application_protos(&perf::ALPN).unwrap();

            let server =
                match server::Server::new(local_addrs, args.password, quiche_config, scheduler) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Failed to set up server: {:?}", e);
                        return ExitCode::FAILURE;
                    }
                };

            return match perf_server(server, oneshot, terminate) {
                Ok(_) => ExitCode::SUCCESS,
                Err(server::ServerError::FatalSocket(e)) => {
                    eprintln!("Fatal: {}", e);
                    ExitCode::FAILURE
                }
                Err(server::ServerError::Unexpected(e)) => {
                    eprintln!("Unexpected: {}", e);
                    ExitCode::FAILURE
                }
            };
        }
        cli::Subcommands::ProxyClient { peer_addrs } => {
            if args.local_addrs.len() != peer_addrs.len() {
                eprintln!(
                "Same number of local and peer addresses expected. One path will be created per pair.\n\
                local_addrs={:?}, peer_addrs={:?}",
                args.local_addrs, peer_addrs
            );
                return ExitCode::FAILURE;
            }

            quiche_config.set_application_protos(&proxy::ALPN).unwrap();

            let client = client::Client::new(local_addrs, peer_addrs, quiche_config).unwrap();

            return match proxy_client(client, scheduler, terminate) {
                Err(client::ClientError::HandshakeFail) => ExitCode::FAILURE,

                Err(client::ClientError::IOFail(e)) | Err(client::ClientError::Other(e)) => {
                    eprintln!("{}", e);
                    ExitCode::FAILURE
                }

                Ok(_) => ExitCode::SUCCESS,
            };
        }
        cli::Subcommands::ProxyServer { cert, key } => {
            if let Err(e) = quiche_config.load_cert_chain_from_pem_file(cert.to_str().unwrap()) {
                eprintln!("Error loading certificate from {:?}: {}", cert, e);
                return ExitCode::FAILURE;
            };

            if let Err(e) = quiche_config.load_priv_key_from_pem_file(key.to_str().unwrap()) {
                eprintln!("Error loading private key from {:?}: {}", key, e);
                return ExitCode::FAILURE;
            };

            quiche_config.set_application_protos(&proxy::ALPN).unwrap();

            let server =
                match server::Server::new(local_addrs, args.password, quiche_config, scheduler) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Failed to set up server: {:?}", e);
                        return ExitCode::FAILURE;
                    }
                };

            return match proxy_server(server, terminate) {
                Ok(_) => ExitCode::SUCCESS,
                Err(server::ServerError::FatalSocket(e)) => {
                    eprintln!("Fatal: {}", e);
                    ExitCode::FAILURE
                }
                Err(server::ServerError::Unexpected(e)) => {
                    eprintln!("Unexpected: {}", e);
                    ExitCode::FAILURE
                }
            };
        }
    }
}

fn perf_client(
    mut client: Client,
    mut scheduler: Box<dyn MultipathScheduler>,
    tc: TestConfig,
    mut psu: PathStatusUpdater,
    terminate: Arc<AtomicBool>,
) -> Result<(), ClientError> {
    let mut ui = perf_ui::PerfUI::new(tc.client_sending);
    ui.new_test(&tc).ok();

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);
    client.register(&poll);

    let mut protocol: Option<Perf> = None;

    client.connect(&mut scheduler)?;

    loop {
        if terminate.load(Ordering::SeqCst) && client.conn.local_error().is_none() {
            debug!("Close conn due to SIGINT [0]");
            client.conn.close(true, 0x1, b"user terminated").ok();
        }

        if let Some(ref p) = protocol {
            ui.update(&client.conn, &mut scheduler, p.test_duration_elapsed())
                .ok();
        }

        let ui_timeout = ui.timeout();
        let protocol_timeout = if let Some(protocol) = protocol.as_ref() {
            protocol.timeout()
        } else {
            Duration::MAX
        };
        let early_data_timeout = if client.conn.is_in_early_data() {
            Duration::ZERO
        } else {
            Duration::MAX
        };
        let conn_timeout = client.conn.timeout().unwrap_or(Duration::ZERO);
        let timeout = min(
            min(min(ui_timeout, protocol_timeout), early_data_timeout),
            conn_timeout,
        );

        let poll_start = Instant::now();
        if let Err(e) = poll.poll(&mut events, Some(timeout)) {
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(ClientError::Other(format!("Poll returned error: {}", e)));
            }
        }
        let poll_duration = poll_start.elapsed();
        let conn_timeout_expired = events.is_empty()
            && conn_timeout.saturating_sub(poll_duration) == std::time::Duration::ZERO;

        if conn_timeout_expired {
            // Running this if a timeout has not actually occured has no adverse effect.
            client.conn.on_timeout();
        }

        log::trace!(
            "timeout (ms) {}, slept {}, conn_expired={}: early={}, conn={}, ui={}, perf={}",
            timeout.as_millis(),
            poll_duration.as_millis(),
            conn_timeout_expired,
            common::duration_as_millis(early_data_timeout),
            common::duration_as_millis(conn_timeout),
            common::duration_as_millis(ui_timeout),
            common::duration_as_millis(protocol_timeout),
        );

        if terminate.load(Ordering::SeqCst) && client.conn.local_error().is_none() {
            debug!("Close conn due to SIGINT [1]");
            client.conn.close(true, 0x1, b"user terminated").ok();
        }

        for event in &events {
            client.read(event)?;
        }

        if client.conn.is_closed() {
            break;
        }

        // Create a new application protocol session once the QUIC connection is established.
        if (client.conn.is_established() || client.conn.is_in_early_data()) && protocol.is_none() {
            let app_proto = client.conn.application_proto();

            if perf::ALPN.contains(&app_proto) {
                info!("Connection established. Selecting QUICHEPERF protocol.");
                protocol = Some(perf::Perf::new_with_tc(tc.clone()));
            } else {
                warn!("No ALPN matched");
            }
        }

        psu.check(&mut client.conn);

        client.handle_cids();
        client.handle_path_events();
        client.probe_paths_if_necessary()?;

        if let Some(protocol) = protocol.as_mut() {
            protocol.client_dispatch(&mut client.conn);
        }

        client.send(&mut scheduler)?;
    }

    client.on_close()?;

    if let Some(p) = protocol {
        ui.print_summary(&client.conn, p.test_duration_elapsed())
            .ok();
    }

    Ok(())
}

fn perf_server(
    mut server: Server,
    oneshot: bool,
    terminate: Arc<AtomicBool>,
) -> Result<(), server::ServerError> {
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);
    server.register(&poll);

    loop {
        if terminate.load(Ordering::SeqCst) {
            info!("Termination signal received, closing connection");
            for c in server.clients.values_mut().into_iter() {
                c.conn.close(true, 0x1, b"user terminated").ok();
            }
            // TODO: Send out connection close messages and wait for a few seconds
            return Ok(());
        }

        //server.poll(&mut events)?;
        let timeout = server
            .clients
            .values()
            .filter_map(|c| c.conn.timeout())
            .min();
        let poll_start = std::time::Instant::now();
        if let Err(e) = poll.poll(&mut events, timeout) {
            if e.kind() != std::io::ErrorKind::Interrupted {
                error!("Poll returned error: {}", e);
                // break;
            }
        }
        let poll_duration = poll_start.elapsed();
        let conn_timeout_expired = events.is_empty()
            && timeout.map_or(false, |t| {
                t.saturating_sub(poll_duration) == std::time::Duration::ZERO
            });
        if conn_timeout_expired {
            server
                .clients
                .values_mut()
                .for_each(|c| c.conn.on_timeout());
        }
        log::trace!(
            "timeout {:?}, slept {}, expired={}",
            timeout,
            poll_duration.as_millis(),
            conn_timeout_expired,
        );

        for event in events.iter() {
            let token = event.token().into();

            // Writable mio notifications disabled for now
            // if event.is_writable() {
            server.on_writable(token)?;
            // }
            if let Err(e) = server.on_readable(token) {
                match e {
                    server::ServerError::FatalSocket(e) => {
                        error!("{}", e);
                        break;
                    }
                    server::ServerError::Unexpected(e) => {
                        trace!("{}", e);
                        continue;
                    }
                }
            }
        }
        server.send()?;

        let client_collected = server.garbage_collect();
        if oneshot && client_collected {
            info!("oneshot mode, exit");
            break;
        }
    }

    Ok(())
}

fn proxy_client(
    mut client: Client,
    mut scheduler: Box<dyn MultipathScheduler>,
    terminate: Arc<AtomicBool>,
) -> Result<(), ClientError> {
    let ui = proxy_ui::ProxyUI {};
    // ui.new_test(&tc).ok();

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);
    client.register(&poll);

    let proxy_token = 128;
    let mut proxy_client = proxy::Proxy::new("mp0".to_string());
    proxy_client.register(proxy_token, &mut poll);

    let keep_alive = common::KeepAlive::new(Duration::from_millis(5000));

    let mut alpn_negotiated: bool = false;

    // Setup proxy protocol
    client.connect(&mut scheduler)?;

    loop {
        if terminate.load(Ordering::SeqCst) && client.conn.local_error().is_none() {
            debug!("Close conn due to SIGINT [0]");
            client.conn.close(true, 0x1, b"user terminated").ok();
        }

        // if alpn_negotiated {
        //     ui.update(&client.conn, &mut scheduler).ok();
        // }

        let ui_timeout = ui.timeout();
        let keep_alive_timeout = keep_alive.timeout(&client.conn);
        let early_data_timeout = if client.conn.is_in_early_data() {
            Duration::ZERO
        } else {
            Duration::MAX
        };
        let conn_timeout = client.conn.timeout().unwrap_or(Duration::ZERO);
        let timeout = *[
            ui_timeout,
            keep_alive_timeout,
            early_data_timeout,
            conn_timeout,
        ]
        .iter()
        .min()
        .unwrap();

        let poll_start = Instant::now();
        if let Err(e) = poll.poll(&mut events, Some(timeout)) {
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(ClientError::Other(format!("Poll returned error: {}", e)));
            }
        }
        let poll_duration = poll_start.elapsed();
        let conn_timeout_expired = events.is_empty()
            && conn_timeout.saturating_sub(poll_duration) == std::time::Duration::ZERO;
        if conn_timeout_expired {
            // Running this if a timeout has not actually occured has no adverse effect.
            client.conn.on_timeout();
        }
        let keep_alive_expired = events.is_empty()
            && keep_alive_timeout.saturating_sub(poll_duration) == std::time::Duration::ZERO;
        if keep_alive_expired {
            keep_alive.check(&mut client.conn);
        }

        log::trace!(
            "timeout (ms) {}, slept {}, conn_expired={}, events={}: ui={}, ka={}, early={}, conn={}",
            timeout.as_millis(),
            poll_duration.as_millis(),
            conn_timeout_expired,
            !events.is_empty(),
            common::duration_as_millis(ui_timeout),
            common::duration_as_millis(keep_alive_timeout),
            common::duration_as_millis(early_data_timeout),
            common::duration_as_millis(conn_timeout),
        );

        if terminate.load(Ordering::SeqCst) && client.conn.local_error().is_none() {
            debug!("Close conn due to SIGINT [1]");
            client.conn.close(true, 0x1, b"user terminated").ok();
        }

        for event in &events {
            let token: usize = event.token().into();
            if token == proxy_token {
                proxy_client.read_tun(&mut client.conn);
            } else {
                client.read(event)?;
            }
        }

        if client.conn.is_closed() {
            break;
        }

        // Create a new application protocol session once the QUIC connection is established.
        if (client.conn.is_established() || client.conn.is_in_early_data()) && !alpn_negotiated {
            let app_proto = client.conn.application_proto();
            if proxy::ALPN.contains(&app_proto) {
                info!("Connection established. Selecting PROXY protocol.");
                // protocol = Some(proxy::Proxy {});
                alpn_negotiated = true;
            } else {
                warn!("ALPN did not match");
                client.conn.close(false, 0x1, b"No ALPN match").ok();
            }
        }

        // psu.check(&mut client.conn);

        client.handle_cids();
        client.handle_path_events();
        client.probe_paths_if_necessary()?;

        if alpn_negotiated {
            proxy_client.write_tun(&mut client.conn);
        }

        client.send(&mut scheduler)?;
    }

    client.on_close()?;

    // if protocol.is_some() {
    //     ui.print_summary(&client.conn).ok();
    // }

    // If the QUIC connection was closed
    terminate.store(true, Ordering::SeqCst);

    Ok(())
}

fn proxy_server(mut server: Server, terminate: Arc<AtomicBool>) -> Result<(), server::ServerError> {
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);
    server.register(&poll);

    let proxy_token = 128;
    let mut proxy = proxy::Proxy::new("mp0".to_string());
    proxy.register(proxy_token, &mut poll);

    loop {
        if terminate.load(Ordering::SeqCst) {
            info!("Termination signal received, closing connection");
            for c in server.clients.values_mut().into_iter() {
                c.conn.close(true, 0x1, b"user terminated").ok();
            }
            // TODO: Send out connection close messages and wait for a few seconds
            return Ok(());
        }

        // server.poll(&mut events)?;
        let mut timeout = server
            .clients
            .values()
            .filter_map(|c| c.conn.timeout())
            .min();
        if let Some(t) = timeout {
            timeout = Some(min(Duration::from_secs(5), t));
        }
        let poll_start = std::time::Instant::now();
        if let Err(e) = poll.poll(&mut events, timeout) {
            if e.kind() != std::io::ErrorKind::Interrupted {
                error!("Poll returned error: {}", e);
            }
        }
        let poll_duration = poll_start.elapsed();
        let conn_timeout_expired = events.is_empty()
            && timeout.map_or(false, |t| {
                t.saturating_sub(poll_duration) == std::time::Duration::ZERO
            });
        if conn_timeout_expired {
            server
                .clients
                .values_mut()
                .for_each(|c| c.conn.on_timeout());
        }

        let timeout_str = match timeout {
            Some(v) => v.as_millis().to_string(),
            None => "None".to_string(),
        };
        log::trace!(
            "timeout (ms) {}: slept {}, expired={}",
            timeout_str,
            poll_duration.as_millis(),
            conn_timeout_expired,
        );

        for event in events.iter() {
            let token = event.token().into();
            if token == proxy_token {
                // TODO: sent the packet to the first client, improve this
                for (_, client) in server.clients.iter_mut() {
                    proxy.read_tun(&mut client.conn);
                }
            } else {
                // Writable mio notifications disabled for now
                // if event.is_writable() {
                server.on_writable(token)?;
                // }
                if let Err(e) = server.on_readable(token) {
                    match e {
                        server::ServerError::FatalSocket(e) => {
                            error!("{}", e);
                            break;
                        }
                        server::ServerError::Unexpected(e) => {
                            trace!("{}", e);
                            continue;
                        }
                    }
                }

                for (_, client) in server.clients.iter_mut() {
                    proxy.write_tun(&mut client.conn);
                }
            }
        }
        server.send()?;
        server.garbage_collect();
    }
}
