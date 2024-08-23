use std::net::SocketAddr;

use crate::common;

use super::common::*;
use super::sendto;
use quiche::scheduler::MultipathScheduler;
use quiche::RecvInfo;
use quiche::SendInfo;
use ring::rand::*;
use slab::Slab;
use std::collections::HashMap;

use quiche::ConnectionId;

type ClientId = u64;

#[derive(Debug)]
pub enum ServerError {
    FatalSocket(String),
    Unexpected(String),
}

enum PacketRecvAction {
    NotInitial,
    VersionNegotiation,
    IOFail(String),
}

/// See `SocketState` in client.rs
struct SocketState {
    // Constant, set with new()
    socket: mio::net::UdpSocket,
    pacing: bool,
    enable_gso: bool,

    // Changed for each send
    buf: [u8; MAX_BUF_SIZE],
    until: usize,
    send_info: Option<SendInfo>,
    max_datagram_size: usize,
}

impl SocketState {
    fn new(socket: mio::net::UdpSocket, pacing: bool, enable_gso: bool) -> SocketState {
        SocketState {
            socket: socket,
            pacing,
            enable_gso,
            buf: [0; MAX_BUF_SIZE],
            until: 0,
            send_info: None,
            max_datagram_size: 0,
        }
    }

    fn reset(&mut self) {
        self.until = 0;
        self.send_info = None;
        self.max_datagram_size = 0;
    }

    /// Returns whether a buffer is currently waiting to be written to the socket.
    #[allow(dead_code)]
    fn send_pending(&self) -> bool {
        self.send_info.is_some()
    }

    fn writable_for_dest(&self, peer_addr: &SocketAddr) -> bool {
        match self.send_info {
            Some(si) => si.to == *peer_addr,
            None => true,
        }
    }

    /// Try to send the scheduled buffer, if it exists.
    /// Returns `Ok(0)` if the socket returned `WouldBlock`.
    fn try_send(&mut self) -> Result<usize, ServerError> {
        let send_info = match self.send_info {
            Some(v) => v,
            None => return Ok(0),
        };
        match sendto::send_to(
            &self.socket,
            &self.buf[..self.until],
            &send_info,
            self.max_datagram_size,
            self.pacing,
            self.enable_gso,
        ) {
            Ok(n) => {
                let to = self.send_info.unwrap();
                trace!("{:}->{:} written {} bytes", to.from, to.to, self.until);
                self.reset();
                Ok(n)
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // TODO: The data of "out" is thrown away, right? Should I handle this?
                    // Is this assertion correct? It isn't, right?
                    trace!("send() would block, will try_send again alter");
                    return Ok(0);
                }

                return Err(ServerError::FatalSocket(format!(
                    "send_to() failed: {:?}",
                    e
                )));
            }
        }
    }
}

/// Holds state of one QUIC connection.
pub struct Client {
    pub conn: quiche::Connection,
    client_id: ClientId,
    protocol: Option<Protocols>,
    password: Option<String>,
    max_datagram_size: usize,
    max_send_burst: usize,
}

impl Client {
    pub fn recv(&mut self, pkt_buf: &mut [u8], recv_info: RecvInfo) -> Result<(), ServerError> {
        // Process potentially coalesced packets.
        let _read = match self.conn.recv(pkt_buf, recv_info) {
            Ok(v) => v,

            Err(e) => {
                return Err(ServerError::Unexpected(format!(
                    "{} recv failed: {:?}",
                    self.conn.trace_id(),
                    e
                )));
            }
        };

        // Create a new application protocol session as soon as the QUIC
        // connection is established.
        if self.protocol.is_none() && (self.conn.is_in_early_data() || self.conn.is_established()) {
            let app_proto = self.conn.application_proto();

            if crate::perf::ALPN.contains(&app_proto) {
                info!("Connection established. Selecting PERF protocol.");
                let perf = crate::perf::Perf::new_with_password(self.password.clone());
                self.protocol = Some(Protocols::Perf(perf));
            } else if crate::proxy::ALPN.contains(&app_proto) {
                info!("Connection established. Selecting PROXY protocol.");
                // self.protocol = Some(Protocols::Proxy(crate::proxy::Proxy::new(
                //     "mp0".to_string(),
                // )));
                self.protocol = Some(Protocols::Proxy(()));
            } else {
                warn!("ALPN did not match");
                self.conn.close(false, 0x1, b"No ALPN match").ok();
            }
        }

        // Update max_datagram_size after connection established.
        self.max_datagram_size = self.conn.max_send_udp_payload_size();

        if let Some(protocol) = self.protocol.as_mut() {
            match protocol {
                Protocols::Perf(perf) => perf.server_dispatch(&mut self.conn),
                Protocols::Proxy(()) => (), //proxy.write_tun(&mut self.conn),
            };
        }

        self.handle_path_events();

        Ok(())
    }

    fn handle_path_events(&mut self) {
        while let Some(qe) = self.conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(local_addr, peer_addr) => {
                    info!(
                        "{} Seen new path ({}, {})",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );

                    // Directly probe the new path.
                    self.conn
                        .probe_path(local_addr, peer_addr)
                        .map_err(|e| error!("cannot probe: {}", e))
                        .ok();
                }

                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!(
                        "{} Path ({}, {}) is now validated",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                    if self.conn.is_multipath_enabled() {
                        self.conn
                            .set_active(local_addr, peer_addr, true)
                            .map_err(|e| error!("cannot set path active: {}", e))
                            .ok();
                    }
                }

                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    info!(
                        "{} Path ({}, {}) failed validation",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                }

                quiche::PathEvent::Closed(local_addr, peer_addr, err, reason) => {
                    info!(
                        "{} Path ({}, {}) is now closed and unusable; err = {} reason = {:?}",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr,
                        err,
                        reason,
                    );
                }

                quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                    info!(
                        "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                        self.conn.trace_id(),
                        cid_seq,
                        old,
                        new
                    );
                }

                quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                    info!(
                        "{} Connection migrated to ({}, {})",
                        self.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                }

                quiche::PathEvent::PeerPathStatus(addr, path_status) => {
                    info!("Peer asks status {:?} for {:?}", path_status, addr,);
                    self.conn
                        .set_path_status(addr.0, addr.1, path_status, false)
                        .map_err(|e| error!("cannot follow status request: {}", e))
                        .ok();
                }
            }
        }
    }
}

type ClientIdMap = HashMap<ConnectionId<'static>, ClientId>;
type ClientMap = HashMap<ClientId, Client>;

pub struct Server {
    password: Option<String>,
    config: quiche::Config,
    scheduler: Box<dyn MultipathScheduler>,

    sockets: Slab<SocketState>,
    src_addr_tokens: HashMap<SocketAddr, usize>,

    keylog: Option<std::fs::File>,

    rng: SystemRandom,
    conn_id_seed: ring::hmac::Key,

    next_client_id: u64,
    clients_ids: ClientIdMap,
    pub clients: HashMap<u64, Client>,

    buf: [u8; MAX_BUF_SIZE],
    out: [u8; MAX_BUF_SIZE],
}

impl Server {
    pub fn new(
        local_addrs: Vec<SocketAddr>,
        password: Option<String>,
        config: quiche::Config,
        scheduler: Box<dyn MultipathScheduler>,
    ) -> Result<Server, ServerError> {
        let mut sockets: Slab<SocketState> =
            Slab::with_capacity(std::cmp::max(local_addrs.len(), 1));
        let mut src_addr_tokens = HashMap::new();

        // Set SO_TXTIME socket option on the listening UDP socket for pacing
        // outgoing packets.
        let pacing = true;
        let mut enable_gso = false;

        let mut addrs = Vec::new();
        for src_addr in local_addrs {
            let socket = match mio::net::UdpSocket::bind(src_addr) {
                Ok(v) => v,
                Err(e) => {
                    return Err(ServerError::FatalSocket(format!(
                        "failed binding UDP socket to {}: {}",
                        src_addr, e
                    )))
                }
            };
            let local_addr = socket.local_addr().unwrap();

            match set_txtime_sockopt(&socket) {
                Ok(_) => debug!("successfully set SO_TXTIME socket option"),
                Err(e) => error!("set SO_TXTIME socket option failed {:?}", e),
            };
            enable_gso &= sendto::detect_gso(&socket, MAX_DATAGRAM_SIZE);
            info!("{} GSO", if enable_gso { "Enable" } else { "Disable" });

            #[cfg(target_os = "linux")]
            {
                match common::set_socket_buf_size(&socket, common::UDPBufType::Rcv) {
                    Ok(v) => trace!("Set the UDP rcv buf size to {}", v),
                    Err(e) => warn!("{}", e),
                };
                match common::set_socket_buf_size(&socket, common::UDPBufType::Snd) {
                    Ok(v) => trace!("Set the UDP snd buf size to {}", v),
                    Err(e) => warn!("{}", e),
                };
            }

            let socket_state = SocketState::new(socket, pacing, enable_gso);
            let token = sockets.insert(socket_state);
            src_addr_tokens.insert(local_addr, token);
            addrs.push(local_addr);

            info!("listening on {:}", local_addr);
        }

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        Ok(Server {
            password,
            config,
            scheduler,

            sockets,
            src_addr_tokens,

            keylog: configure_keylog(),

            conn_id_seed,
            rng,

            next_client_id: 0,
            clients_ids: ClientIdMap::new(),
            clients: ClientMap::new(),
            buf: [0; MAX_BUF_SIZE],
            out: [0; MAX_BUF_SIZE],
        })
    }

    pub fn register(&mut self, poll: &mio::Poll) {
        for (token, socket) in self.sockets.iter_mut() {
            // Disabled WRITABLE for now. See client.rs for details on the implications.
            poll.registry()
                .register(
                    &mut socket.socket,
                    mio::Token(token),
                    mio::Interest::READABLE, // .add(mio::Interest::WRITABLE),
                )
                .unwrap();
        }
    }

    // pub fn poll(&mut self, events: &mut mio::Events) -> Result<(), ServerError> {
    //     // Find the shorter timeout from all the active connections.
    //     let timeout = self.clients.values().filter_map(|c| c.conn.timeout()).min();

    //     // let send_pending = self.sockets.iter().fold(false, |acc, (_, s)| acc || s.send_pending());

    //     let poll_start = std::time::Instant::now();
    //     if let Err(e) = self.poll.poll(events, timeout) {
    //         if e.kind() != std::io::ErrorKind::Interrupted {
    //             return Err(ServerError::Unexpected(format!(
    //                 "Poll returned error: {}",
    //                 e
    //             )));
    //         }
    //     }
    //     let poll_duration = poll_start.elapsed();
    //     // let (readable, writable) = events.iter().fold(
    //     //     (false, false),
    //     //     |(readable, writable), e| (readable || e.is_readable(), writable || e.is_writable()));

    //     trace!(
    //         "timeout {:?}, slept {} ms, ev={} (r={}, w={})",
    //         timeout,
    //         poll_duration.as_millis(),
    //         !events.is_empty(),
    //         "?", // readable,
    //         "?", // writable,
    //     );

    //     let conn_timeout_expired = timeout.map_or(false, |t| {
    //         t.saturating_sub(poll_duration) == std::time::Duration::ZERO
    //     });

    //     if events.is_empty() && conn_timeout_expired {
    //         trace!(
    //             "timed out after {} ms, events_empty={}",
    //             poll_duration.as_millis(),
    //             events.is_empty()
    //         );
    //         self.clients.values_mut().for_each(|c| c.conn.on_timeout());
    //     }

    //     Ok(())
    // }

    /// If a send is pending, this will try sending. If not, nothing is done.
    pub fn on_writable(&mut self, token: usize) -> Result<(), ServerError> {
        let socket = &mut self.sockets[token];
        if let Err(e) = socket.try_send() {
            return Err(ServerError::FatalSocket(format!(
                "socket.try_send failed: {:?}",
                e
            )));
        };
        Ok(())
    }

    /// Read incoming UDP packets from the socket and feed them to quiche,
    /// until there are no more packets to read.
    pub fn on_readable(&mut self, token: usize) -> Result<(), ServerError> {
        // let socket = &self.sockets[token].socket;
        let local_addr = self.sockets[token].socket.local_addr().unwrap();
        loop {
            let socket_recv = self.sockets[token].socket.recv_from(&mut self.buf);
            let (len, from) = match socket_recv {
                Ok(v) => v,
                Err(e) => {
                    // There are no more UDP packets to read, so end the read loop
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        // trace!("recv() from {:} would block", local_addr);
                        return Ok(());
                    }
                    return Err(ServerError::FatalSocket(format!(
                        "recv() from {:} failed: {:?}",
                        local_addr, e
                    )));
                }
            };

            // Parse the QUIC packet's header.
            let hdr = {
                let mut pkt_buf = &mut self.buf[..len];
                match quiche::Header::from_slice(&mut pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(ServerError::Unexpected(format!(
                            "Parsing packet header failed: {:?}",
                            e
                        )));
                    }
                }
            };

            // trace!("{:}->{:}: reveived {} bytes, {:?}", from, local_addr, len, hdr);

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            let conn_id = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            let client_id = match self.get_client_id(&recv_info, &hdr, conn_id) {
                Ok(v) => v,
                Err(e) => match e {
                    PacketRecvAction::NotInitial => {
                        return Err(ServerError::Unexpected("Expected initial packet".into()))
                    }
                    PacketRecvAction::VersionNegotiation => {
                        warn!("Doing version negotiation");
                        let len =
                            quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut self.out).unwrap();
                        let out = &self.out[..len];
                        // TODO: refactor
                        if let Err(e) = self.sockets[token].socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                return Err(ServerError::Unexpected(
                                    "send() would block in connection establishment".into(),
                                ));
                            }
                            return Err(ServerError::FatalSocket(format!(
                                "send() failed: {:?}",
                                e
                            )));
                        }
                        return Ok(());
                    }
                    PacketRecvAction::IOFail(e) => return Err(ServerError::FatalSocket(e)),
                },
            };

            let client = match self.clients.get_mut(&client_id) {
                Some(v) => v,
                None => {
                    return Err(ServerError::Unexpected(format!(
                        "No client in map for client_id={}",
                        client_id
                    )))
                }
            };

            let mut pkt_buf = &mut self.buf[..len];
            client.recv(&mut pkt_buf, recv_info)?;

            // See whether source Connection IDs have been retired.
            while let Some(retired_scid) = client.conn.retired_scid_next() {
                info!("Retiring source CID {:?}", retired_scid);
                self.clients_ids.remove(&retired_scid);
            }

            // Provides as many CIDs as possible.
            while client.conn.source_cids_left() > 0 {
                let (scid, reset_token) = generate_cid_and_reset_token(&self.rng);
                if client
                    .conn
                    .new_source_cid(&scid, reset_token, false)
                    .is_err()
                {
                    break;
                }

                self.clients_ids.insert(scid, client.client_id);
            }
        }
    }

    fn get_client_id(
        &mut self,
        recv_info: &RecvInfo,
        hdr: &quiche::Header,
        conn_id: ConnectionId<'_>,
    ) -> Result<ClientId, PacketRecvAction> {
        // Lookup a connection based on the packet's connection ID. If there is no connection
        // matching, create a new one.
        let client_unknown =
            !self.clients_ids.contains_key(&hdr.dcid) && !self.clients_ids.contains_key(&conn_id);

        if client_unknown {
            if hdr.ty != quiche::Type::Initial {
                return Err(PacketRecvAction::NotInitial);
            }

            if !quiche::version_is_supported(hdr.version) {
                return Err(PacketRecvAction::VersionNegotiation);
            }

            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
            scid.copy_from_slice(&conn_id);
            let scid = quiche::ConnectionId::from_vec(scid.to_vec());

            debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

            #[allow(unused_mut)]
            let mut conn =
                quiche::accept(&scid, None, recv_info.to, recv_info.from, &mut self.config)
                    .unwrap();

            if let Some(keylog) = &mut self.keylog {
                if let Ok(keylog) = keylog.try_clone() {
                    conn.set_keylog(Box::new(keylog));
                }
            }

            // Only bother with qlog if the user specified it.
            #[cfg(feature = "qlog")]
            if let Err(e) = common::set_qlog(&mut conn, format!("{:?}", &hdr.scid), "server", None)
            {
                return Err(PacketRecvAction::IOFail(e));
            };

            let client_id = self.next_client_id;

            let client = Client {
                conn,
                client_id,
                protocol: None,
                password: self.password.clone(),
                // partial_requests: HashMap::new(),
                // partial_responses: HashMap::new(),
                // siduck_conn: None,
                max_datagram_size: MAX_DATAGRAM_SIZE,
                // loss_rate: 0.0,
                max_send_burst: MAX_BUF_SIZE,
            };

            self.clients.insert(client_id, client);
            self.clients_ids.insert(scid.clone(), client_id);
            self.next_client_id += 1;

            Ok(client_id)
        } else {
            let cid = match self.clients_ids.get(&hdr.dcid) {
                Some(v) => v,
                None => self.clients_ids.get(&conn_id).unwrap(),
            };
            Ok(*cid)
        }
    }

    /// Generate outgoing QUIC packets for all active connections and send
    /// them on the UDP socket, until quiche reports that there are no more
    /// packets to be sent.
    pub fn send(&mut self) -> Result<(), ServerError> {
        for client in self.clients.values_mut() {
            // Reduce max_send_burst by 25% if loss is increasing more than 0.1%.
            // let loss_rate = client.conn.stats().lost as f64 / client.conn.stats().sent as f64;
            // if loss_rate > client.loss_rate + 0.001 {
            //     let prev_max_send_burst = client.max_send_burst;
            //     let prev_loss_rate = client.loss_rate;
            //     client.max_send_burst = client.max_send_burst / 4 * 3;
            //     // Minimun bound of 10xMSS.
            //     client.max_send_burst = client.max_send_burst.max(client.max_datagram_size * 10);
            //     client.loss_rate = loss_rate;
            //     debug!("Decreased max_send_burst of {} from {} to {} since loss increased from {} to {}",
            //             client.conn.trace_id(),
            //             prev_max_send_burst, client.max_send_burst, prev_loss_rate, loss_rate);
            // }

            let mut continue_write = true;
            while continue_write {
                continue_write = false;

                // The maximum amount of data that should be written in one burst with GSO.
                // Explanation division and multiplication: https://github.com/cloudflare/quiche/pull/1213
                // Applies to each socket individually.
                let max_send_burst = client.conn.send_quantum().min(client.max_send_burst)
                    / client.max_datagram_size
                    * client.max_datagram_size;

                let mut it = 0;
                while let Some((local_addr, peer_addr, send_instr)) =
                    self.scheduler.get_best_path(&mut client.conn)
                {
                    it += 1;

                    let token = self.src_addr_tokens[&local_addr];
                    let socket = &mut self.sockets[token];

                    if !socket.writable_for_dest(&peer_addr) {
                        // The socket has already data queued for sending. Only more packets toward the same
                        // destination can be queued.
                        break;
                    }

                    // TODO: get send quantum for that specific path

                    if socket.until >= max_send_burst {
                        // The QUIC connection might have more data to write than max_send_burst.
                        // Write data to the socket and try to generate more packets.
                        continue_write = true;
                        break;
                    }

                    let (written, send_info) = match client.conn.send_on_path_with_instructions(
                        &mut socket.buf[socket.until..max_send_burst],
                        Some(local_addr),
                        Some(peer_addr),
                        Some(send_instr),
                    ) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            trace!(
                                "{}->{} {}, [{}], conn.send returned Done",
                                local_addr,
                                peer_addr,
                                it,
                                client.conn.trace_id()
                            );
                            break;
                        }

                        Err(e) => {
                            error!("{} conn.send failed: {:?}", client.conn.trace_id(), e);
                            client.conn.close(false, 0x1, b"fail").ok();
                            // Not sure what's correct in this situation.
                            break;
                        }
                    };

                    socket.until += written;
                    let _ = socket.send_info.get_or_insert(send_info);
                    socket.max_datagram_size = client.max_datagram_size;

                    trace!(
                        "{:}->{:} conn.send [{}] returned {} bytes, max_datagram_size={}",
                        send_info.from,
                        send_info.to,
                        it,
                        written,
                        client.max_datagram_size,
                    );

                    if !client.conn.is_established() {
                        trace!("Disabled GSO packet assembly during connection establishment");
                        continue_write = true;
                        break;
                    }

                    if written < client.max_datagram_size {
                        // https://github.com/cloudflare/quiche/commit/eac98fae15ce67ee774125c90db0d59c4deda5da
                        // The QUIC connection might has more data to write.
                        continue_write = true;

                        // No full-sized packet has been written; only the last packet can be less than
                        // max_datagram_size if we want to use GSO.
                        break;
                    }
                }

                // Try to send the queued data
                for (_, token) in self.src_addr_tokens.iter() {
                    let socket = &mut self.sockets[*token];
                    if let Err(e) = socket.try_send() {
                        return Err(ServerError::FatalSocket(format!(
                            "socket.try_send failed: {:?}",
                            e
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns true if at least one client connection was cleaned up.
    pub fn garbage_collect(&mut self) -> bool {
        let closed_cids: Vec<u64> = self
            .clients
            .iter()
            .filter(|(_, client)| client.conn.is_closed())
            .map(|(cid, client)| {
                info!(
                    "{} connection collected {:?} {:?}",
                    client.conn.trace_id(),
                    client.conn.stats(),
                    client.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );
                (cid, client)
            })
            .map(|(cid, _)| *cid)
            .collect();

        self.clients_ids
            .retain(|_, client_id| !closed_cids.contains(client_id));

        for cid in closed_cids.iter() {
            self.clients.remove(&cid);
        }

        !closed_cids.is_empty()
    }
}
