use crate::common;
use crate::socket;
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

pub struct Client {
    pub local_addrs: Vec<SocketAddr>,
    peer_addrs: Vec<SocketAddr>,

    pub conn: quiche::Connection,
    sockets: Slab<socket::SocketState>,
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
        qlog_setter: common::QlogSetter,
        mut config: quiche::Config,
    ) -> Result<Client, ClientError> {
        let enable_gso = true;
        let (addrs, sockets, src_addr_tokens) =
            match socket::configure_local_sockets(local_addrs, true, enable_gso) {
                Ok(v) => v,
                Err(e) => return Err(ClientError::Other(e)),
            };

        let (local_addr, peer_addr) = socket::match_local_peer_ip_version(
            *addrs.first().unwrap(),
            *peer_addrs.first().unwrap(),
        )
        .map_err(|e| ClientError::Other(e))?;

        config.log_keys();

        // Create a QUIC connection and initiate handshake.
        let rng = SystemRandom::new();
        let scid = gen_scid(&rng);
        let mut conn = quiche::connect(None, &scid, local_addr, peer_addr, &mut config).unwrap();

        let mut keylog = common::configure_keylog();
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
            qlog_setter
                .set_qlog(&mut conn, format!("{:?}", scid), "client", peer_addrs_str)
                .map_err(ClientError::IOFail)?;
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

    /// Read incoming UDP packets from the socket and feed them to quiche,
    /// until there are no more packets to read.
    pub fn read(&mut self, event: &mio::event::Event) -> Result<(), ClientError> {
        let token = event.token().into();
        let socket = &mut self.sockets[token];

        // if event.is_writable() && socket.send_pending() {
        if socket.send_pending() {
            socket.try_send().map_err(|e| ClientError::Other(e))?;
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
            let (scid, reset_token) = common::generate_cid_and_reset_token(&self.rng);

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
            let (local_addr, peer_addr) = socket::match_local_peer_ip_version(
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
        socket::send_on_socket(
            &mut self.conn,
            common::MAX_BUF_SIZE,
            common::MAX_DATAGRAM_SIZE,
            scheduler,
            &self.src_addr_tokens,
            &mut self.sockets,
        )
        .map_err(|e| ClientError::IOFail(e))
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
