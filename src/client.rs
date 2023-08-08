use crate::common;
use crate::common::*;
use crate::protocol::Protocol;
use crate::protocol::TestConfig;
use crate::ui;
use itertools::Itertools;
use quiche::scheduler::MultipathScheduler;
use ring::rand::*;
use slab::Slab;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

struct SocketState {
    socket: mio::net::UdpSocket,
    buf: [u8; MAX_DATAGRAM_SIZE],
    until: usize,
    to: Option<SocketAddr>,
    would_block_cntr: u64,
}

impl SocketState {
    fn new(socket: mio::net::UdpSocket) -> SocketState {
        SocketState {
            socket: socket,
            buf: [0; MAX_DATAGRAM_SIZE],
            until: 0,
            to: None,
            would_block_cntr: 0,
        }
    }

    /// Returns whether a buffer is currently waiting to be written to the socket.
    fn send_pending(&self) -> bool {
        self.to.is_some()
    }

    /// Schedule a buffer for sending on the socket.
    /// If `buf` is not None, its copied to the internal send buffer `buf`. If not, the internal
    /// send buffer `buf` will be sent.
    fn schedule_send(
        &mut self,
        buf: Option<&[u8; MAX_DATAGRAM_SIZE]>,
        until: usize,
        to: SocketAddr,
    ) {
        if self.to.is_some() {
            panic!("Socket schedule_send: still had data to sent");
        }
        buf.map(|v| self.buf.clone_from_slice(v));
        self.until = until;
        self.to = Some(to);
        trace!("try_send: schedule {} bytes to {}", self.until, to);
    }

    /// Try to send the scheduled buffer, if it exists.
    /// Returns Ok(0) if the socket returned WouldBlock.
    fn try_send(&mut self) -> Result<usize, ClientError> {
        if self.to.is_none() {
            return Ok(0);
        }
        let write_buf = &self.buf[..self.until];
        let local_addr = self.socket.local_addr().unwrap();
        let peer_addr = self.to.unwrap();

        match self.socket.send_to(write_buf, peer_addr) {
            Ok(n) => {
                self.to = None;
                trace!(
                    "try_send: {} -> {}: {} bytes written to socket",
                    local_addr,
                    peer_addr,
                    self.until
                );
                Ok(n)
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!(
                        "try_send: {} -> {}: socket.send would block",
                        local_addr, peer_addr
                    );
                    self.would_block_cntr += 1;
                    return Ok(0);
                }

                return Err(ClientError::Other(format!(
                    "try_send: {} -> {}: send() failed: {:?}",
                    local_addr, peer_addr, e
                )));
            }
        }
    }
}

pub fn connect(
    local_addrs: Vec<SocketAddr>,
    peer_addrs: Vec<SocketAddr>,
    tc: TestConfig,
    mut config: quiche::Config,
    mut scheduler: impl MultipathScheduler,
) -> Result<(), ClientError> {
    let mut recv_buf = [0; 65535];

    let mut ui = ui::UI::new(tc.client_sending);
    ui.new_test(&local_addrs, &peer_addrs, &tc);

    let mut sockets: Slab<SocketState> = Slab::with_capacity(std::cmp::max(local_addrs.len(), 1));
    let mut src_addr_tokens = HashMap::new();

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
        let socket = mio::net::UdpSocket::bind(src_addr)
            .map_err(|e| ClientError::Other(format!("Failed binding to {}: {}", src_addr, e)))?;
        let local_addr = socket.local_addr().unwrap();

        #[cfg(target_os = "linux")]
        {
            let ifname = common::get_ifname_from_ip(local_addr);
            if let Some(ifname) = ifname {
                if let Err(e) = common::bind_socket_to_if(&socket, &ifname) {
                    eprintln!("{}: unable to bind {}: {}", ifname, local_addr, e);
                } else {
                    println!("{}: bind {}", ifname, local_addr);
                }
            }

            match common::set_socket_buf_size(&socket, common::UDPBufType::Rcv) {
                Ok(v) => info!("Set the UDP rcv buf size to {}", v),
                Err(e) => warn!("{}", e),
            };
            match common::set_socket_buf_size(&socket, common::UDPBufType::Snd) {
                Ok(v) => info!("Set the UDP snd buf size to {}", v),
                Err(e) => warn!("{}", e),
            };
        }

        let socket_state = SocketState::new(socket);
        let token = sockets.insert(socket_state);
        src_addr_tokens.insert(local_addr, token);
        addrs.push(local_addr);
        poll.registry()
            .register(
                &mut sockets[token].socket,
                mio::Token(token),
                mio::Interest::READABLE.add(mio::Interest::WRITABLE),
            )
            .unwrap();
    }
    let local_addr = *addrs.first().unwrap();

    let mut keylog = configure_keylog();
    config.log_keys();

    let mut protocol: Option<Protocol> = None;

    let rng = SystemRandom::new();
    let scid = gen_scid(&rng);

    info!(
        "connecting to {:} from {:} with scid {:?}",
        peer_addrs[0], local_addr, scid
    );

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(None, &scid, local_addr, peer_addrs[0], &mut config).unwrap();

    if let Some(keylog) = &mut keylog {
        if let Ok(keylog) = keylog.try_clone() {
            conn.set_keylog(Box::new(keylog));
        }
    }

    // Only bother with qlog if the user specified it.
    #[cfg(feature = "qlog")]
    {
        #![allow(unstable_name_collisions)]
        let peer_addrs_str = Some(
            peer_addrs
                .iter()
                .map(|a| a.to_string())
                .intersperse(",".to_string())
                .collect(),
        );
        common::set_qlog(&mut conn, format!("{:?}", scid), "client", peer_addrs_str);

        common::qlog_metadata(&mut conn, &tc, &config);
    }

    // Send initial message to server
    let mut write_buf = [0; MAX_DATAGRAM_SIZE];
    let (write, send_info) = conn.send(&mut write_buf).expect("initial send failed");
    let token = src_addr_tokens[&send_info.from];
    let socket = &mut sockets[token];
    socket.schedule_send(Some(&write_buf), write, send_info.to);
    socket.try_send()?;

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

    'outer: loop {
        let mut is_conn_timeout = false;
        let mut timeout_duration = Duration::ZERO;
        if !conn.is_in_early_data() || protocol.is_some() {
            let conn_timeout = conn.timeout().unwrap_or(Duration::ZERO);
            let ui_timeout = ui.timeout();
            let protocol_timeout = if let Some(protocol) = protocol.as_ref() {
                protocol.timeout()
            } else {
                Duration::MAX
            };
            let timeout = std::cmp::min(std::cmp::min(conn_timeout, ui_timeout), protocol_timeout);
            is_conn_timeout = conn_timeout == timeout;
            let poll_wait = Instant::now();
            log::trace!(
                "poll_timeout={:?}: conn={:?}, ui={:?}, protocol={:?}",
                timeout,
                conn_timeout,
                ui_timeout,
                protocol_timeout,
            );
            poll.poll(&mut events, Some(timeout)).unwrap();
            timeout_duration = poll_wait.elapsed();
            log::trace!(
                "poll duration was {:?} events_empty={}",
                timeout_duration,
                events.is_empty()
            );
        }

        if protocol.is_some() {
            ui.update(&conn);
        }

        // If the event loop reported no events, it means that the timeout
        // has expired, so handle it without attempting to read packets. We
        // will then proceed with the send loop.
        if events.is_empty() && is_conn_timeout {
            trace!("timed out after {:?}", timeout_duration);
            conn.on_timeout();
        }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        for event in &events {
            let token = event.token().into();
            let socket = &mut sockets[token];

            if event.is_writable() && socket.send_pending() {
                socket.try_send()?;
            }

            if event.is_readable() {
                let local_addr = socket.socket.local_addr().unwrap();
                'read: loop {
                    let (len, from) = match socket.socket.recv_from(&mut recv_buf) {
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
                        }
                    };

                    trace!("{}->{}: got {} bytes", from, local_addr, len);

                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };

                    // Process potentially coalesced packets.
                    let read = match conn.recv(&mut recv_buf[..len], recv_info) {
                        Ok(v) => v,

                        Err(e) => {
                            error!("{}: recv failed: {:?}", local_addr, e);
                            continue 'read;
                        }
                    };

                    trace!("{}: processed {} bytes", local_addr, read);
                }
            }
        }

        // trace!("done reading");

        // Skip draining on the client
        // if conn.is_draining() || conn.is_closed() {
        if conn.is_closed() {
            break 'outer;
        }

        // Create a new application protocol session once the QUIC connection is
        // established.
        if (conn.is_established() || conn.is_in_early_data()) && protocol.is_none() {
            let app_proto = conn.application_proto();

            if QUICHEPERF_ALPN.contains(&app_proto) {
                info!("Connection established. Selecting QUICHEPERF protocol.");
                protocol = Some(Protocol::new());
            } else {
                warn!("No ALPN matched");
            }
        }

        if let Some(protocol) = protocol.as_mut() {
            if !conn.is_closed() && !conn.is_draining() && !protocol.close_after_duration(&mut conn)
            {
                if !protocol.config_sent {
                    protocol.send_config(&mut conn, &tc).ok();
                } else if !protocol.config_acked {
                    protocol.recv_config_ack(&mut conn, &mut recv_buf).ok();
                }
                if protocol.config_acked {
                    protocol.work(&mut conn, &mut recv_buf).ok();
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
                        info!(
                            "{:}->{:} Successfully started probing for path with dcid {}",
                            local_probe_addr, peer_probe_addr, v
                        );
                        probed_paths += 1;
                    }
                    Err(e) => error!(
                        "{:}->{:} Failed probing path from: {}",
                        local_probe_addr, peer_probe_addr, e
                    ),
                }
            }
            // else if app_data_start.elapsed() > Duration::from_secs(3) {
            //     warn!(
            //         "{:}->{:} Failed to probe path: No DCID available.",
            //         local_probe_addr, peer_probe_addr
            //     );
            // }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket.
        while let Some((local_addr, peer_addr)) = scheduler.get_best_path(&conn) {
            let token = src_addr_tokens[&local_addr];
            let socket = &mut sockets[token];
            if socket.send_pending() {
                // The scheduler will probably return this same path over and over again. Break to exit (potential) infinite loop.
                // In most cases, socket.try_send() would block now. We wait for a writable event.
                trace!("outgoing packet on socket {} pending", local_addr);
                break;
            }

            let (write, send_info) =
                match conn.send_on_path(&mut socket.buf, Some(local_addr), Some(peer_addr)) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("{} -> {}: done writing to conn", local_addr, peer_addr);
                        break;
                    }
                    Err(e) => {
                        error!("{} -> {}: conn.send failed: {:?}", local_addr, peer_addr, e);

                        conn.close(false, 0x1, b"fail").ok();
                        break;
                    }
                };

            socket.schedule_send(None, write, send_info.to);
            socket.try_send()?;
        }

        // let path_stats: Vec<_> = conn
        //     .path_stats()
        //     .map(|p| (p.local_addr, p.peer_addr))
        //     .collect();
        // Only execute this for multipath
        // Enabling this leads to error messages on the receiver, looking like:
        // 74850c9a211749cc8b0a8933ead48b74043d1b1d dropped invalid packet: CryptoFail
        // if path_stats.len() > 1 {
        //     for (l, p) in path_stats {
        //         let token = src_addr_tokens[&local_addr];
        //         let socket = &mut sockets[token];
        //         if socket.send_pending() {
        //             continue;
        //         }

        //         let (write, send_info) = match conn.send_on_path(&mut write_buf, Some(l), Some(p)) {
        //             Ok(v) => v,
        //             Err(quiche::Error::Done) => break,
        //             Err(_) => {
        //                 conn.close(false, 0x1, b"fail").ok();
        //                 break;
        //             }
        //         };

        //         socket.schedule_send(None, write, send_info.to);
        //         socket.try_send()?;
        //     }

        //     if conn.is_closed() {
        //         break 'outer;
        //     }
        // }
    }

    info!(
        "connection closed, {:?} {:?}",
        conn.stats(),
        conn.path_stats().collect::<Vec<quiche::PathStats>>()
    );

    if !conn.is_established() {
        error!("connection timed out after {:?}", app_data_start.elapsed(),);

        return Err(ClientError::HandshakeFail);
    }

    for (local_addr, token) in src_addr_tokens.iter() {
        let socket = &mut sockets[*token];
        if socket.would_block_cntr > 0 {
            let msg = format!(
                "{}: socket snd buf was full {} times. Consider increasing the send buffer size.",
                local_addr, socket.would_block_cntr
            );
            warn!("{}", msg);
            println!("{}", msg);
        }
    }

    if protocol.is_some() {
        ui.print_summary(&conn);
    }

    #[cfg(feature = "qlog")]
    {
        if !conn.qlog_writer_drained() {
            println!("Waiting for the qlog event queue to be drained");
        }
        conn.await_qlog_writer_drained();
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
            }

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!("Path ({}, {}) failed validation", local_addr, peer_addr);
            }

            quiche::PathEvent::Closed(local_addr, peer_addr, e, reason) => {
                info!(
                    "Path ({}, {}) is now closed and unusable; err = {}, reason = {:?}",
                    local_addr, peer_addr, e, reason
                );
            }

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "Peer reused cid seq {} (initially {:?}) on {:?}",
                    cid_seq, old, new
                );
            }

            quiche::PathEvent::PeerMigrated(..) => unreachable!(),

            quiche::PathEvent::PeerPathStatus(..) => {}
        }
    }
}

// Generate a random source connection ID for the connection.
fn gen_scid<T: SecureRandom>(rng: &T) -> quiche::ConnectionId<'static> {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid[..]).unwrap();
    quiche::ConnectionId::from_vec(scid.to_vec())
}

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    // HttpFail,
    Other(String),
}
