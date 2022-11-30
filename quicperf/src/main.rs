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

// use quiche_apps::args::*;

// use quiche_apps::common::*;

// use quiche_apps::client::*;

#[macro_use]
extern crate log;
extern crate serde;

mod server;
mod client;
mod common;
mod sendto;
mod protocol;

use std::{net::SocketAddr, time::Duration};

use crate::protocol::TestConfig;

const USAGE: &'static str = "
Usage: quicperf server (-l <local_addr>)...
       quicperf client (-l <local_addr>)... (-c <peer_addr>)...
       quicperf -h | --help

-d <duration>, --duration=<duration>     Time in seconds to run test for [default: 10]
";

fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(USAGE).unwrap();
    let args = docopt.parse().unwrap_or_else(|e| e.exit());

    let local_addrs: Vec<SocketAddr> = args
        .get_vec("<local_addr>")
        .into_iter()
        .filter_map(|a| a.parse().ok())
        .collect();

    let peer_addrs: Vec<SocketAddr> = args
        .get_vec("<peer_addr>")
        .into_iter()
        .filter_map(|a| a.parse().ok())
        .collect();

    info!("local_addrs={:?}", local_addrs);
    info!("peer_addrs={:?}", peer_addrs);

    if args.get_bool("server") {
        info!("is server");
        server::listen(local_addrs);
    } else if args.get_bool("client") {
        info!("is client");

        let duration = args.get_str("--duration").parse::<u64>().unwrap();

        let tc = TestConfig{
            client_sending: true,
            duration: Duration::from_secs(duration),
        };
        
        match client::connect(local_addrs, peer_addrs, tc) {
            Err(client::ClientError::HandshakeFail) => std::process::exit(-1),

            // Err(client::ClientError::HttpFail) => std::process::exit(-2),

            Err(client::ClientError::Other(e)) => panic!("{}", e),

            Ok(_) => (),
        }
    }
}