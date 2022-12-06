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

mod client;
mod common;
mod protocol;
mod sendto;
mod server;
mod ui;

use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::process::ExitCode;
use std::time::Duration;

use crate::protocol::TestConfig;

const USAGE: &'static str = "
Usage: quicperf server [-p <password> --cc <cc>] --cert <cert> --key <key> [-l <local_addr>]...
       quicperf client [-d <duration> -p <password> --reverse --cc <cc>] [-l <local_addr>]... (-c <peer_addr>)...
       quicperf -h | --help

-l <local_addr>                         The local address(es) to connect from [default: 0.0.0.0:0]
-c <peer_addr>                          The remote address(es) to connect to
--cert <cert>                           Path to the server certificate
--key <key>                             Path to the certificate's private key
-d <duration>, --duration=<duration>    Time in seconds to run test for [default: 10]
-p <password>, --password=<password>    Password required to start test
-r, --reverse                           Send data from server to client
--cc=<cc>                               Set congestion control algorithm of this peer: Reno, CUBIC, or BBR. [default: cubic]
";

fn main() -> ExitCode {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(USAGE).unwrap();
    let args = docopt.parse().unwrap_or_else(|e| e.exit());

    let local_addrs =
        match args.get_vec("-l").into_iter().map(|a| a.parse()).collect() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed parsing local addresses: {e}");
                return ExitCode::FAILURE;
            },
        };

    let peer_addrs = match args
        .get_vec("-c")
        .into_iter()
        .map(|a| match a.to_socket_addrs() {
            Err(e) => Err(format!("Failed to resolve {}: {:?}", a, e)),
            Ok(it) => {
                let resolved: Vec<SocketAddr> = it.collect();
                info!("Resolved {} to {:?}", a, resolved);
                match resolved.iter().filter(|a| a.is_ipv4()).nth(0) {
                    Some(v) => Ok(v.to_owned()),
                    None => Err(format!("No IPv4 address of {}", a)),
                }
            },
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "Failed to process peer_addr: {:?}\nPort number missing?",
                e
            );
            return ExitCode::FAILURE;
        },
    };

    let password = match args.get_str("--password") {
        "" => None,
        s => Some(s.to_string()),
    };

    let mut config = make_quiche_config();
    if let Err(e) =
        config.set_cc_algorithm_name(args.get_str("--cc").to_lowercase().as_ref())
    {
        eprintln!("Could not set CCA {}: {}", args.get_str("--cc"), e);
        return ExitCode::FAILURE;
    };

    if args.get_bool("server") {
        let cert = args.get_str("--cert");
        if let Err(e) = config.load_cert_chain_from_pem_file(cert) {
            eprintln!("Error loading certificate from {}: {}", cert, e);
            return ExitCode::FAILURE;
        };

        let key = args.get_str("--key");
        if let Err(e) = config.load_priv_key_from_pem_file(key) {
            eprintln!("Error loading private key from {}: {}", key, e);
            return ExitCode::FAILURE;
        };

        server::listen(local_addrs, password, config);
    } else if args.get_bool("client") {
        if local_addrs.len() != peer_addrs.len() {
            eprintln!(
                "Same number of local and peer addresses expected. One path will be created per pair.\n\
                local_addrs={:?}, peer_addrs={:?}",
                args.get_vec("-l"), args.get_vec("-c")
            );
            return ExitCode::FAILURE;
        }

        let duration = args.get_str("--duration").parse::<u64>().unwrap();

        let tc = TestConfig {
            local_addrs: args
                .get_vec("-l")
                .iter()
                .map(|s| s.to_string())
                .collect(),
            peer_addrs: args
                .get_vec("-c")
                .iter()
                .map(|s| s.to_string())
                .collect(),
            password,
            client_sending: !args.get_bool("--reverse"),
            duration: Duration::from_secs(duration),
        };

        return match client::connect(local_addrs, peer_addrs, tc, config) {
            Err(client::ClientError::HandshakeFail) => ExitCode::FAILURE,

            // Err(client::ClientError::HttpFail) => std::process::exit(-2),
            Err(client::ClientError::Other(e)) => {
                eprintln!("{}", e);
                ExitCode::FAILURE
            },

            Ok(_) => ExitCode::SUCCESS,
        };
    }

    ExitCode::FAILURE
}

pub fn make_quiche_config() -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // config
    //         "/home/cech/Research/MPQUIC/quiche/quicperf/src/cert.crt",
    //     )
    //     .unwrap();
    // config
    //     .load_priv_key_from_pem_file(
    //         "/home/cech/Research/MPQUIC/quiche/quicperf/src/cert.key",
    //     )
    //     .unwrap();

    config
        .set_application_protos(&common::QUICPERF_ALPN)
        .unwrap();

    config.set_max_idle_timeout(30_000); // in ms
    config.set_max_recv_udp_payload_size(common::MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(common::MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(100 * 10_000_000);
    let max_stream_data = 10 * 16_777_216;
    config.set_initial_max_stream_data_bidi_local(max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(max_stream_data);
    config.set_initial_max_stream_data_uni(max_stream_data);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_ack_delay_exponent(3); // quiche default
    config.set_max_ack_delay(25); // quiche default
    config.set_active_connection_id_limit(5);
    config.set_disable_active_migration(false);
    config.set_multipath(true);

    config.set_cc_algorithm_name("cubic").unwrap();

    config.enable_hystart(true);
    config.enable_pacing(true);

    config.enable_dgram(false, 1000, 1000);

    config.set_max_connection_window(25_165_824);
    config.set_max_stream_window(16_777_216);

    // config.set_stateless_reset_token
    // config.set_disable_dcid_reuse

    config
}
