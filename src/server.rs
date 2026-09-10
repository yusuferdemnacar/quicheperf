use std::net::SocketAddr;
use std::time::Duration;

use crate::socket::SocketState;
use crate::{common, socket};

use super::common::*;
use quiche::scheduler::{SchedulerAlgo, SchedulerImpl};
use quiche::RecvInfo;
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

/// Holds state of one QUIC connection.
pub struct Client {
    pub conn: quiche::Connection,
    schedulers: Option<Vec<SchedulerImpl>>,
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

    sockets: Slab<SocketState>,
    src_addr_tokens: HashMap<SocketAddr, usize>,

    keylog: Option<std::fs::File>,
    qlog_setter: QlogSetter,

    rng: SystemRandom,
    conn_id_seed: ring::hmac::Key,

    next_client_id: u64,
    clients_ids: ClientIdMap,
    pub clients: HashMap<u64, Client>,

    buf: [u8; MAX_BUF_SIZE],
    out: [u8; MAX_BUF_SIZE],

    // prefer_path: Option<usize>,
    scheduler_algo: Option<Vec<SchedulerAlgo>>,
}

impl Server {
    pub fn new(
        local_addrs: Vec<SocketAddr>,
        password: Option<String>,
        bind_to_intf: bool,
        config: quiche::Config,
        qlog_setter: common::QlogSetter,
        // prefer_path: Option<usize>,
        scheduler_algo: Option<Vec<SchedulerAlgo>>,
    ) -> Result<Server, ServerError> {
        let enable_gso = true;
        let enable_pacing = true;
        let (_addrs, sockets, src_addr_tokens) = match socket::configure_local_sockets(
            local_addrs,
            enable_pacing,
            enable_gso,
            bind_to_intf,
        ) {
            Ok(v) => v,
            Err(e) => return Err(ServerError::FatalSocket(e)),
        };

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        Ok(Server {
            password,
            config,

            sockets,
            src_addr_tokens,

            keylog: configure_keylog(),
            qlog_setter,

            conn_id_seed,
            rng,

            next_client_id: 0,
            clients_ids: ClientIdMap::new(),
            clients: ClientMap::new(),
            buf: [0; MAX_BUF_SIZE],
            out: [0; MAX_BUF_SIZE],

            // prefer_path,
            scheduler_algo,
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
            let (read, from) = match socket_recv {
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

            trace!("{}->{}: read {}B from socket", from, local_addr, read);

            // Parse the QUIC packet's header.
            let hdr = {
                let pkt_buf = &mut self.buf[..read];
                match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(ServerError::Unexpected(format!(
                            "Parsing packet header failed: {:?}",
                            e
                        )));
                    }
                }
            };

            // trace!("{from}->{local_addr}: got/processed {read}/{processed}B");
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

            let pkt_buf = &mut self.buf[..read];
            client.recv(pkt_buf, recv_info)?;

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

            // TODO: reenable
            // if let Some(pid) = self.prefer_path {
            //     info!("Prefer path {pid}");
            //     conn.scheduler
            //         .set_preferred_path(pid)
            //         .expect("setting preferred path");
            // }

            // Only bother with qlog if the user specified it.
            #[cfg(feature = "qlog")]
            self.qlog_setter
                .set_qlog(&mut conn, format!("{:?}", &hdr.scid), "server", None)
                .map_err(PacketRecvAction::IOFail)?;

            let client_id = self.next_client_id;

            let schedulers = self
                .scheduler_algo
                .as_ref()
                .map(|algos| algos.iter().map(|a| (*a).into()).collect());
            trace!("Using schedulers {schedulers:?}");

            let client = Client {
                conn,
                schedulers,
                client_id,
                protocol: None,
                password: self.password.clone(),
                max_datagram_size: MAX_DATAGRAM_SIZE,
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

            socket::send_multipath(
                &mut client.conn,
                client.schedulers.as_mut(),
                client.max_send_burst,
                client.max_datagram_size,
                &self.src_addr_tokens,
                &mut self.sockets,
            )
            .map_err(ServerError::FatalSocket)?;
        }
        Ok(())
    }

    /// The soonest any client's `Perf` protocol wants to run again to keep pacing a bitrate
    /// target, independent of `quiche::Connection::timeout()` (loss recovery / idle timeout).
    ///
    /// `perf_server`'s poll loop must bound its wait by this in addition to the connection
    /// timeout, or a client whose own traffic has quieted down never wakes the server up to
    /// keep sending. That happens for every reverse ("-r") test: the client only acknowledges,
    /// it does not send test data, so once the server's own sends stop giving it anything new
    /// to acknowledge, nothing schedules another wakeup and the transfer stalls.
    pub fn perf_timeout(&self) -> Duration {
        self.clients
            .values()
            .filter_map(|c| match &c.protocol {
                Some(common::Protocols::Perf(perf)) => Some(perf.timeout()),
                _ => None,
            })
            .min()
            .unwrap_or(Duration::MAX)
    }

    /// Re-drives every client's `Perf` protocol on a timer, independent of whether a packet was
    /// actually received this iteration.
    ///
    /// `Client::recv` only calls `server_dispatch` in response to a socket event. The client
    /// loop's equivalent call to `client_dispatch` runs unconditionally every iteration instead
    /// (see the `client` subcommand's loop in main.rs), which is what lets a sender keep pacing
    /// a bitrate target purely on `Perf::timeout()`. The server needs the same unconditional
    /// call, paired with `perf_timeout` above, for the same reason.
    pub fn perf_tick(&mut self) {
        for c in self.clients.values_mut() {
            if let Some(common::Protocols::Perf(perf)) = c.protocol.as_mut() {
                perf.server_dispatch(&mut c.conn);
            }
        }
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
            self.clients.remove(cid);
        }

        !closed_cids.is_empty()
    }
}
