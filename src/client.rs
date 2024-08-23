use crate::common;
use crate::common::*;
use itertools::Itertools;
use quiche::scheduler::MultipathScheduler;
use ring::rand::*;
use slab::Slab;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    IOFail(String),
    Other(String),
}

/// SocketState manages one UDP socket and the buffer that holds the packets that will
/// eventually be written to that socket.
///
/// The client will either directly write data to `self.socket` or use `schedule_send()`.
/// Then, `try_send()` will try to actually write the buffer to the UDP socket. That
/// operation can fail under heavy load with `WouldBlock`, indicating that the OS buffers
/// are filled and that the write operation should be retried later.
///
/// Could be improved to support GSO (see the server equivalent).
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
    }

    /// Try to send the scheduled buffer, if it exists. Returns `Ok(0)` if the
    /// socket returns `WouldBlock`.
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

                return Err(ClientError::IOFail(format!(
                    "try_send: {} -> {}: send() failed: {:?}",
                    local_addr, peer_addr, e
                )));
            }
        }
    }
}

pub struct Client {
    pub local_addrs: Vec<SocketAddr>,
    peer_addrs: Vec<SocketAddr>,

    pub conn: quiche::Connection,
    sockets: Slab<SocketState>,
    src_addr_tokens: HashMap<SocketAddr, usize>,
    app_data_start: Option<Instant>,
    recv_buf: [u8; 65535],
    rng: SystemRandom,
    probed_paths: usize,
}

impl Client {
    pub fn new(
        local_addrs: Vec<SocketAddr>,
        peer_addrs: Vec<SocketAddr>,
        mut config: quiche::Config,
    ) -> Result<Client, ClientError> {
        let mut sockets = Slab::with_capacity(std::cmp::max(local_addrs.len(), 1));
        let mut src_addr_tokens = HashMap::new();

        let mut addrs: Vec<std::net::SocketAddr> = Vec::new();
        for src_addr in local_addrs.into_iter() {
            let socket = mio::net::UdpSocket::bind(src_addr).map_err(|e| {
                ClientError::Other(format!("Failed binding to {}: {}", src_addr, e))
            })?;
            let local_addr = socket.local_addr().unwrap().into();

            #[cfg(target_os = "linux")]
            {
                let ifname = common::get_ifname_from_ip(local_addr);
                if let Some(ifname) = ifname {
                    if let Err(e) = common::bind_socket_to_if(&socket, &ifname) {
                        error!("{}: unable to bind {}: {}", ifname, local_addr, e);
                    } else {
                        trace!("{}: bind {}", ifname, local_addr);
                    }
                }

                match common::set_socket_buf_size(&socket, common::UDPBufType::Rcv) {
                    Ok(v) => trace!("Set the UDP rcv buf size to {}", v),
                    Err(e) => warn!("{}", e),
                };
                match common::set_socket_buf_size(&socket, common::UDPBufType::Snd) {
                    Ok(v) => trace!("Set the UDP snd buf size to {}", v),
                    Err(e) => warn!("{}", e),
                };
            }

            let socket_state = SocketState::new(socket);
            let token = sockets.insert(socket_state);
            src_addr_tokens.insert(local_addr, token);
            addrs.push(local_addr);

            // Disabled notifications on WRITABLE to stop poll.poll being waken up unnecessarily.
            // This will lead to problems under heavy load, more specifically if writing to the UDP
            // socket in `SocketState` returns WouldBlock. In these cases, the application should retry
            // writing to that socket as soon as it's writable again.
            // TODO: find a good solution to this problem
            // poll.registry()
            //     .register(
            //         &mut sockets[token].socket,
            //         mio::Token(token),
            //         mio::Interest::READABLE, // .add(mio::Interest::WRITABLE),
            //     )
            //     .expect("Failed registering socket with mio");
        }

        let (local_addr, peer_addr) = common::match_local_peer_ip_version(
            *addrs.first().unwrap(),
            *peer_addrs.first().unwrap(),
        )
        .map_err(|e| ClientError::Other(e))?;

        config.log_keys();

        // Create a QUIC connection and initiate handshake.
        let rng = SystemRandom::new();
        let scid = gen_scid(&rng);
        let mut conn = quiche::connect(None, &scid, local_addr, peer_addr, &mut config).unwrap();

        let mut keylog = configure_keylog();
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
            if let Err(e) =
                common::set_qlog(&mut conn, format!("{:?}", scid), "client", peer_addrs_str)
            {
                return Err(ClientError::IOFail(e));
            };
            // common::qlog_metadata(&mut conn, &tc, &config);
        }

        Ok(Client {
            local_addrs: addrs,
            peer_addrs,

            conn,
            sockets,
            src_addr_tokens,
            app_data_start: None,
            recv_buf: [0; 65535],
            rng: rng,

            // consider the first path as already probed, as we established the
            // connection over it.
            probed_paths: 1,
        })
    }

    pub fn register(&mut self, poll: &mio::Poll) {
        // Disabled notifications on WRITABLE to stop poll.poll being waken up unnecessarily.
        // This will lead to problems under heavy load, more specifically if writing to the UDP
        // socket in `SocketState` returns WouldBlock. In these cases, the application should retry
        // writing to that socket as soon as it's writable again.
        // TODO: find a good solution to this problem
        for (token, socket) in self.sockets.iter_mut() {
            poll.registry()
                .register(
                    &mut socket.socket,
                    mio::Token(token),
                    mio::Interest::READABLE, // .add(mio::Interest::WRITABLE),
                )
                .expect("Failed registering socket with mio");
        }
    }

    pub fn connect(
        &mut self,
        scheduler: &mut Box<dyn MultipathScheduler>,
    ) -> Result<(), ClientError> {
        info!(
            "Connecting to {:} from {:}", // with scid {:?}",
            self.peer_addrs[0],
            self.local_addrs[0], // scid
        );

        // Send initial message to server
        self.send(scheduler)?;

        self.app_data_start = Some(std::time::Instant::now());

        Ok(())
    }

    // pub fn poll(
    //     &mut self,
    //     ui_timeout: Duration,
    //     protocol_timeout: Duration,
    // ) -> Result<(), ClientError> {
    //     let mut conn_timeout_expired = false;
    //     let mut poll_duration = Duration::ZERO;

    //     if !self.conn.is_in_early_data() || protocol_timeout < Duration::MAX {
    //         let conn_timeout = self.conn.timeout().unwrap_or(Duration::ZERO);
    //         let timeout = std::cmp::min(std::cmp::min(conn_timeout, ui_timeout), protocol_timeout);

    //         let poll_start = Instant::now();
    //         if let Err(e) = self.poll.poll(&mut self.events, Some(timeout)) {
    //             if e.kind() != std::io::ErrorKind::Interrupted {
    //                 return Err(ClientError::Other(format!("Poll returned error: {}", e)));
    //             }
    //         }
    //         poll_duration = poll_start.elapsed();

    //         conn_timeout_expired =
    //             conn_timeout.saturating_sub(poll_duration) == std::time::Duration::ZERO;

    //         // let (readable, writable) = self.events.iter().fold(
    //         //     (false, false),
    //         //     |(r, w), e| (r || e.is_readable(), w || e.is_writable()));

    //         log::trace!(
    //             "timeout (ms) {}, slept {}, ev={} (r={}, w={}): conn={}, ui={}, protocol={}",
    //             timeout.as_millis(),
    //             poll_duration.as_millis(),
    //             !self.events.is_empty(),
    //             "?",
    //             "?",
    //             // readable,
    //             // writable,
    //             conn_timeout.as_millis(),
    //             ui_timeout.as_millis(),
    //             protocol_timeout.as_millis(),
    //         );
    //     }

    //     if self.events.is_empty() && conn_timeout_expired {
    //         trace!(
    //             "timed out after {:?}, events_empty={}",
    //             poll_duration,
    //             self.events.is_empty()
    //         );
    //         // Running this if a timeout has not actually occured has no adverse effect.
    //         self.conn.on_timeout();
    //     }

    //     Ok(())
    // }

    /// Read incoming UDP packets from the socket and feed them to quiche,
    /// until there are no more packets to read.
    pub fn read(&mut self, event: &mio::event::Event) -> Result<(), ClientError> {
        let token = event.token().into();
        let socket = &mut self.sockets[token];

        // if event.is_writable() && socket.send_pending() {
        if socket.send_pending() {
            socket.try_send()?;
        }

        if event.is_readable() {
            let local_addr = socket.socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.socket.recv_from(&mut self.recv_buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read on this socket.
                        // Process subsequent events.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            // trace!("{}: recv() would block", local_addr);
                            break 'read;
                        }

                        return Err(ClientError::IOFail(format!(
                            "{}: recv() failed: {:?}",
                            local_addr, e
                        )));
                    }
                };

                // trace!("{}->{}: got {} bytes", from, local_addr, len);

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process potentially coalesced packets.
                let _read = match self.conn.recv(&mut self.recv_buf[..len], recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("{}: recv failed: {:?}", local_addr, e);
                        continue 'read;
                    }
                };

                // trace!("{}: processed {} bytes", local_addr, read);
            }
        }

        Ok(())
    }

    pub fn handle_cids(&mut self) {
        // See whether source Connection IDs have been retired.
        while let Some(retired_scid) = self.conn.retired_scid_next() {
            info!("Retiring source CID {:?}", retired_scid);
        }

        // Provides as many CIDs as possible.
        while self.conn.source_cids_left() > 0 {
            let (scid, reset_token) = generate_cid_and_reset_token(&self.rng);

            if self.conn.new_source_cid(&scid, reset_token, false).is_err() {
                break;
            }
        }
    }

    // Handle path events on client
    pub fn handle_path_events(&mut self) {
        while let Some(qe) = self.conn.path_event_next() {
            match qe {
                // Only called server-side
                quiche::PathEvent::New(..) => unreachable!(),

                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!("Path ({}, {}) is now validated", local_addr, peer_addr);
                    // if conn_args.multipath {
                    self.conn.set_active(local_addr, peer_addr, true).ok();
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

    pub fn probe_paths_if_necessary(&mut self) -> Result<(), ClientError> {
        if self.probed_paths < self.local_addrs.len() {
            let (local_addr, peer_addr) = common::match_local_peer_ip_version(
                self.local_addrs[self.probed_paths],
                self.peer_addrs[self.probed_paths],
            )
            .map_err(|e| ClientError::Other(e))?;

            trace!(
                "probed_path={}, addrs={:?}",
                self.probed_paths,
                self.local_addrs
            );

            if self.conn.available_dcids() > 0 {
                match self.conn.probe_path(local_addr, peer_addr) {
                    Ok(v) => {
                        info!(
                            "{:}->{:} Successfully started probing for path with dcid {}",
                            local_addr, peer_addr, v
                        );
                        self.probed_paths += 1;
                    }
                    Err(e) => error!(
                        "{:}->{:} Failed probing path from: {}",
                        local_addr, peer_addr, e
                    ),
                }
            }
            // else if app_data_start.elapsed() > Duration::from_secs(3) {
            //     warn!(
            //         "{:}->{:} Failed to probe path: No DCID available.",
            //         local_addr, peer_addr
            //     );
            // }
        }

        Ok(())
    }

    /// Generate outgoing QUIC packets and send them on the UDP socket.
    pub fn send(&mut self, scheduler: &mut Box<dyn MultipathScheduler>) -> Result<(), ClientError> {
        while let Some((local_addr, peer_addr, send_instr)) =
            scheduler.get_best_path(&mut self.conn)
        {
            let token = self.src_addr_tokens[&local_addr];
            let socket = &mut self.sockets[token];
            if socket.send_pending() {
                // The scheduler will probably return this same path over and over again. Break
                // to exit (potential) infinite loop. In most cases, socket.try_send() would
                // block now. We wait for a writable event.
                trace!("outgoing packet on socket {} pending", local_addr);
                break;
            }

            let (write, send_info) = match self.conn.send_on_path_with_instructions(
                &mut socket.buf,
                Some(local_addr),
                Some(peer_addr),
                Some(send_instr),
            ) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    // trace!("{} -> {}: done writing to conn", local_addr, peer_addr);
                    break;
                }
                Err(e) => {
                    error!("{} -> {}: conn.send failed: {:?}", local_addr, peer_addr, e);
                    self.conn.close(false, 0x1, b"fail").ok();
                    break;
                }
            };

            socket.schedule_send(None, write, send_info.to);
            socket.try_send()?;
        }

        Ok(())
    }

    pub fn on_close(&mut self) -> Result<(), ClientError> {
        info!(
            "connection closed, {:?} {:?}",
            self.conn.stats(),
            self.conn.path_stats().collect::<Vec<quiche::PathStats>>()
        );

        if !self.conn.is_established() {
            error!(
                "connection timed out after {:?}",
                self.app_data_start.unwrap().elapsed()
            );

            return Err(ClientError::HandshakeFail);
        }

        for (local_addr, token) in self.src_addr_tokens.iter() {
            let socket = &mut self.sockets[*token];
            if socket.would_block_cntr > 0 {
                let msg = format!(
                    "{}: socket snd buf was full {} times. Consider increasing the send buffer size.",
                    local_addr, socket.would_block_cntr
                );
                warn!("{}", msg);
            }
        }

        #[cfg(feature = "qlog")]
        {
            // if !self.conn.qlog_writer_drained() {
            //     println!("Waiting for the qlog event queue to be drained");
            // }
            // Sleep until all qlog events have been written to disk
            self.conn.await_qlog_writer_drained();
        }

        Ok(())
    }
}

// Generate a random source connection ID for the connection.
fn gen_scid<T: SecureRandom>(rng: &T) -> quiche::ConnectionId<'static> {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid[..]).unwrap();
    quiche::ConnectionId::from_vec(scid.to_vec())
}
