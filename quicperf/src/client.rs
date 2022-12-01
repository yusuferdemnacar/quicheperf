use crate::common::*;
use crate::protocol::Protocol;
use crate::protocol::TestConfig;
use crate::ui;

use ring::rand::*;
use slab::Slab;
use std::collections::HashMap;
use std::net::SocketAddr;

pub fn connect(
    local_addrs: Vec<SocketAddr>, peer_addrs: Vec<SocketAddr>, tc: TestConfig, mut config: quiche::Config
) -> Result<(), ClientError> {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut ui = ui::UI::new();
    ui.new_test(&local_addrs, &peer_addrs, &tc);

    let mut sockets = Slab::with_capacity(std::cmp::max(local_addrs.len(), 1));
    let mut src_addrs = HashMap::new();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop. Either we provided addresses, or we rely on the default
    // INADDR_IN or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let mut addrs = Vec::new();
    for src_addr in local_addrs {
        let socket = mio::net::UdpSocket::bind(src_addr).unwrap();
        let local_addr = socket.local_addr().unwrap();
        let token = sockets.insert(socket);
        src_addrs.insert(local_addr, token);
        addrs.push(local_addr);
        poll.registry()
            .register(
                &mut sockets[token],
                mio::Token(token),
                mio::Interest::READABLE,
            )
            .unwrap();
    }
    let local_addr = *addrs.first().unwrap();

    let mut keylog = configure_keylog();
    config.log_keys();

    let mut protocol: Option<Protocol> = None;

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    let rng = SystemRandom::new();
    rng.fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(None, &scid, local_addr, peer_addrs[0], &mut config)
            .unwrap();

    if let Some(keylog) = &mut keylog {
        if let Ok(keylog) = keylog.try_clone() {
            conn.set_keylog(Box::new(keylog));
        }
    }

    // Only bother with qlog if the user specified it.
    #[cfg(feature = "qlog")]
    {
        if let Some(dir) = std::env::var_os("QLOGDIR") {
            let id = format!("{:?}", scid);
            let writer = make_qlog_writer(&dir, "client", &id);

            conn.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-client qlog".to_string(),
                format!("{} id={}", "quiche-client qlog", id),
            );
        }
    }

    info!(
        "connecting to {:} from {:} with scid {:?}",
        peer_addrs[0], local_addr, scid
    );

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");
    let token = src_addrs[&send_info.from];

    while let Err(e) = sockets[token].send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            trace!(
                "{} -> {}: send() would block",
                sockets[token].local_addr().unwrap(),
                send_info.to
            );
            continue;
        }

        return Err(ClientError::Other(format!("send() failed: {:?}", e)));
    }

    trace!(
        "init write: written {} bytes from {:} to {:}",
        write,
        send_info.from,
        send_info.to
    );

    let app_data_start = std::time::Instant::now();

    // consider the first path as already probed, as we established the
    // connection over it.
    let mut probed_paths = 1;

    loop {
        if !conn.is_in_early_data() || protocol.is_some() {
            let timeout = std::cmp::min(conn.timeout(), ui.timeout());
            poll.poll(&mut events, timeout).unwrap();
        }

        ui.update(&conn);

        // If the event loop reported no events, it means that the timeout
        // has expired, so handle it without attempting to read packets. We
        // will then proceed with the send loop.
        if events.is_empty() {
            trace!("timed out");
            conn.on_timeout();
        }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        for event in &events {
            let token = event.token().into();
            let socket = &sockets[token];
            let local_addr = socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read on this socket.
                        // Process subsequent events.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("{}: recv() would block", local_addr);
                            break 'read;
                        }

                        return Err(ClientError::Other(format!(
                            "{}: recv() failed: {:?}",
                            local_addr, e
                        )));
                    },
                };

                trace!("{}->{}: got {} bytes", from, local_addr, len);

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process potentially coalesced packets.
                let read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("{}: recv failed: {:?}", local_addr, e);
                        continue 'read;
                    },
                };

                trace!("{}: processed {} bytes", local_addr, read);
            }
        }

        trace!("done reading");

        if conn.is_closed() {
            info!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                error!(
                    "connection timed out after {:?}",
                    app_data_start.elapsed(),
                );

                return Err(ClientError::HandshakeFail);
            }

            // TODO: close custom connection
            // if let Some(si_conn) = siduck_conn {
            //     si_conn.report_incomplete(&app_data_start);
            // }

            break;
        }

        // Create a new application protocol session once the QUIC connection is
        // established.
        if (conn.is_established() || conn.is_in_early_data()) &&
            protocol.is_none()
        {
            let app_proto = conn.application_proto();

            if QUICPERF_ALPN.contains(&app_proto) {
                info!("Connection established. Selecting QUICPERF protocol.");
                protocol = Some(Protocol::new());
            } else {
                warn!("No ALPN matched");
            }
        }

        if let Some(protocol) = protocol.as_mut() {
            protocol.check_duration(&mut conn);
            if !protocol.config_sent {
                if protocol.send_config(&mut conn, &tc).is_err() {
                    continue;
                }
            } else if !protocol.config_acked {
                if protocol.recv_config_ack(&mut conn, &mut buf).is_err() {
                    continue;
                }
            }
            if protocol.config_acked {
                if protocol.send_data(&mut conn).is_err() {
                    continue;
                }
            }
        }

        client_handle_path_events(&mut conn);

        // See whether source Connection IDs have been retired.
        while let Some(retired_scid) = conn.retired_scid_next() {
            info!("Retiring source CID {:?}", retired_scid);
        }

        // Provides as many CIDs as possible.
        while conn.source_cids_left() > 0 {
            let (scid, reset_token) = generate_cid_and_reset_token(&rng);

            if conn.new_source_cid(&scid, reset_token, false).is_err() {
                break;
            }
        }

        if probed_paths < addrs.len() {
            trace!("probed_path={}, addrs={:?}", probed_paths, addrs);
            let local_probe_addr = addrs[probed_paths];
            let peer_probe_addr = peer_addrs[probed_paths];
            if conn.available_dcids() > 0 {
                match conn.probe_path(local_probe_addr, peer_probe_addr) {
                    Ok(v) => {
                        info!("{:}->{:} Successfully started probing for path with dcid {}",
                        local_probe_addr, peer_probe_addr, v);
                        probed_paths += 1;
                    },
                    Err(e) => error!(
                        "{:}->{:} Failed probing path from: {}",
                        local_probe_addr, peer_probe_addr, e
                    ),
                }
            } else {
                warn!(
                    "{:}->{:} Failed to probe path: No DCID available.",
                    local_probe_addr, peer_probe_addr
                );
            }
        }

        // Determine in which order we are going to iterate over paths.
        let scheduled_tuples = lowest_latency_scheduler(&conn);

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        for (local_addr, peer_addr) in scheduled_tuples {
            let token = src_addrs[&local_addr];
            let socket = &sockets[token];
            loop {
                let (write, send_info) = match conn.send_on_path(
                    &mut out,
                    Some(local_addr),
                    Some(peer_addr),
                ) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!(
                            "{} -> {}: done writing to conn",
                            local_addr,
                            peer_addr
                        );
                        break;
                    },

                    Err(e) => {
                        error!(
                            "{} -> {}: conn.send failed: {:?}",
                            local_addr, peer_addr, e
                        );

                        conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!(
                            "{} -> {}: socket.send() would block",
                            local_addr,
                            send_info.to
                        );
                        break;
                    }

                    return Err(ClientError::Other(format!(
                        "{} -> {}: send() failed: {:?}",
                        local_addr, send_info.to, e
                    )));
                } else {
                    trace!(
                        "{} -> {}: {} bytes written to socket",
                        local_addr,
                        send_info.to,
                        write
                    );
                }
            }
        }

        if conn.is_closed() {
            info!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                error!(
                    "connection timed out after {:?}",
                    app_data_start.elapsed(),
                );

                return Err(ClientError::HandshakeFail);
            }

            // TODO
            // if let Some(si_conn) = siduck_conn {
            //     si_conn.report_incomplete(&app_data_start);
            // }

            break;
        }
    }

    Ok(())
}

// Handle path events on client
fn client_handle_path_events(conn: &mut quiche::Connection) {
    while let Some(qe) = conn.path_event_next() {
        match qe {
            quiche::PathEvent::New(..) => unreachable!(),

            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                info!("Path ({}, {}) is now validated", local_addr, peer_addr);
                // if conn_args.multipath {
                conn.set_active(local_addr, peer_addr, true).ok();
            },

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!("Path ({}, {}) failed validation", local_addr, peer_addr);
            },

            quiche::PathEvent::Closed(local_addr, peer_addr, e, reason) => {
                info!(
                    "Path ({}, {}) is now closed and unusable; err = {}, reason = {:?}",
                    local_addr, peer_addr, e, reason
                );
            },

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "Peer reused cid seq {} (initially {:?}) on {:?}",
                    cid_seq, old, new
                );
            },

            quiche::PathEvent::PeerMigrated(..) => unreachable!(),

            quiche::PathEvent::PeerPathStatus(..) => {},
        }
    }
}

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    // HttpFail,
    Other(String),
}
