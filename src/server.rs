use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::common;
use crate::protocol::Protocol;

use super::common::*;
use super::sendto;
use quiche::scheduler::MultipathScheduler;
use quiche::SendInfo;
use ring::rand::*;
use slab::Slab;
use std::collections::HashMap;

use quiche::ConnectionId;

type ClientId = u64;

#[derive(Debug)]
pub enum ServerError {
    SocketError(String),
}

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
    // fn send_pending(&self) -> bool {
    //     self.send_info.is_some()
    // }

    fn writable_for_dest(&self, peer_addr: &SocketAddr) -> bool {
        match self.send_info {
            Some(si) => si.to == *peer_addr,
            None => true,
        }
    }

    /// Schedule a buffer for sending on the socket.
    /// If `buf` is not None, its copied to the internal send buffer `buf`. If not, the internal
    /// send buffer `buf` will be sent.
    // fn schedule_send(
    //     &mut self,
    //     buf: Option<&[u8; MAX_BUF_SIZE]>,
    //     until: usize,
    //     to: SendInfo,
    //     max_datagram_size: usize,
    // ) {
    //     if self.send_info.is_some() {
    //         panic!("Socket schedule_send: still had data to sent");
    //     }
    //     buf.map(|v| self.buf.clone_from_slice(v));
    //     self.until = until;
    //     self.send_info = Some(to);
    //     self.max_datagram_size = max_datagram_size;
    // }

    /// Try to send the scheduled buffer, if it exists.
    /// Returns Ok(0) if the socket returned WouldBlock.
    fn try_send(&mut self) -> Result<usize, ServerError> {
        let send_info = match self.send_info {
            Some(v) => v,
            None => return Ok(0),
        };
        trace!(
            "{:}->{:} try sending scheduled {} bytes",
            send_info.from,
            send_info.to,
            self.until
        );
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
                trace!("{:}->{:} written {} bytes", to.from, to.to, self.until,);
                self.reset();
                Ok(n)
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // TODO: The data of "out" is thrown away, right? Should I handle this?
                    trace!("send() would block");
                    return Ok(0);
                }

                return Err(ServerError::SocketError(format!(
                    "send_to() failed: {:?}",
                    e
                )));
            }
        }
    }
}

struct Client {
    conn: quiche::Connection,

    client_id: ClientId,

    protocol: Option<Protocol>,

    // partial_requests: std::collections::HashMap<u64, PartialRequest>,

    // partial_responses: std::collections::HashMap<u64, PartialResponse>,
    max_datagram_size: usize,

    // loss_rate: f64,
    max_send_burst: usize,
}

type ClientIdMap = HashMap<ConnectionId<'static>, ClientId>;
type ClientMap = HashMap<ClientId, Client>;

pub fn listen(
    local_addrs: Vec<SocketAddr>,
    password: Option<String>,
    mut config: quiche::Config,
    mut scheduler: impl MultipathScheduler,
    terminate: Arc<AtomicBool>,
) -> ! {
    let mut buf = [0; MAX_BUF_SIZE];
    let mut out = [0; MAX_BUF_SIZE];

    let mut sockets: Slab<SocketState> = Slab::with_capacity(std::cmp::max(local_addrs.len(), 1));
    let mut src_addr_tokens = HashMap::new();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let mut enable_gso = true;
    // Set SO_TXTIME socket option on the listening UDP socket for pacing
    // outgoing packets.
    let pacing = true;

    let mut addrs = Vec::new();
    for src_addr in local_addrs {
        println!("listening on {:?}", src_addr);
        let socket = mio::net::UdpSocket::bind(src_addr).unwrap();
        let local_addr = socket.local_addr().unwrap();

        match set_txtime_sockopt(&socket) {
            Ok(_) => debug!("successfully set SO_TXTIME socket option"),
            Err(e) => error!("set SO_TXTIME socket option failed {:?}", e),
        };
        enable_gso &= sendto::detect_gso(&socket, MAX_DATAGRAM_SIZE);

        #[cfg(target_os = "linux")]
        {
            match common::set_socket_buf_size(&socket, common::UDPBufType::Rcv) {
                Ok(v) => info!("Set the UDP rcv buf size to {}", v),
                Err(e) => warn!("{}", e),
            };
            match common::set_socket_buf_size(&socket, common::UDPBufType::Snd) {
                Ok(v) => info!("Set the UDP snd buf size to {}", v),
                Err(e) => warn!("{}", e),
            };
        }

        let socket_state = SocketState::new(socket, pacing, enable_gso);
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

        info!("listening on {:}", local_addr);
    }

    let mut keylog = configure_keylog();

    let rng = SystemRandom::new();
    let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut next_client_id = 0;
    let mut clients_ids = ClientIdMap::new();
    let mut clients = ClientMap::new();

    // Indicates if the poll sleep should return immediately so that the write part of
    // the loop is ran again.
    let mut continue_write = false;

    loop {
        if terminate.load(Ordering::SeqCst) {
            info!("Termination signal received, closing connection");
            for c in clients.values_mut().into_iter() {
                c.conn.close(true, 0x1, b"user terminated").ok();
            }
        }

        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = match continue_write {
            true => Some(std::time::Duration::from_secs(0)),
            false => clients.values().filter_map(|c| c.conn.timeout()).min(),
        };

        let poll_wait = std::time::Instant::now();
        poll.poll(&mut events, timeout).unwrap();
        trace!(
            "poll_timeout was {:?} ms, slept for {:?} ms, events_empty={}, continue_write={}",
            timeout,
            poll_wait.elapsed(),
            events.is_empty(),
            continue_write,
        );

        // If the event loop reported no events, it means that the timeout
        // has expired, so handle it without attempting to read packets. We
        // will then proceed with the send loop.
        if events.is_empty() && !continue_write {
            trace!("timed out");
            clients.values_mut().for_each(|c| c.conn.on_timeout());
        }

        for event in &events {
            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            let token = event.token().into();
            let socket = &mut sockets[token];
            let local_addr = socket.socket.local_addr().unwrap();

            if event.is_writable() {
                // If a send is pending, this will try sending. If not, nothing is done.
                if let Err(e) = socket.try_send() {
                    panic!("socket.try_send failed: {:?}", e);
                };
            }

            if !event.is_readable() {
                continue;
            }
            'read: loop {
                let (len, from) = match socket.socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("recv() from {:} would block", local_addr);
                            break 'read;
                        }

                        panic!("recv() from {:} failed: {:?}", local_addr, e);
                    }
                };

                trace!("{:}->{:}: got {} bytes", from, local_addr, len);

                let pkt_buf = &mut buf[..len];

                // Parse the QUIC packet's header.
                let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Parsing packet header failed: {:?}", e);
                        continue 'read;
                    }
                };

                trace!("got packet {:?}", hdr);

                let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                let conn_id = conn_id.to_vec().into();

                // Lookup a connection based on the packet's connection ID. If
                // there is no connection matching, create a new
                // one.
                let client = if !clients_ids.contains_key(&hdr.dcid)
                    && !clients_ids.contains_key(&conn_id)
                {
                    if hdr.ty != quiche::Type::Initial {
                        error!("Packet is not Initial");
                        continue 'read;
                    }

                    if !quiche::version_is_supported(hdr.version) {
                        warn!("Doing version negotiation");

                        let len =
                            quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();

                        let out = &out[..len];

                        // TODO: refactor
                        if let Err(e) = socket.socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                trace!("send() would block in connection establishment");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    scid.copy_from_slice(&conn_id);

                    let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                    debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                    #[allow(unused_mut)]
                    let mut conn =
                        quiche::accept(&scid, None, local_addr, from, &mut config).unwrap();

                    if let Some(keylog) = &mut keylog {
                        if let Ok(keylog) = keylog.try_clone() {
                            conn.set_keylog(Box::new(keylog));
                        }
                    }

                    // Only bother with qlog if the user specified it.
                    #[cfg(feature = "qlog")]
                    common::set_qlog(&mut conn, format!("{:?}", &hdr.scid), "server", None);

                    let client_id = next_client_id;

                    let client = Client {
                        conn,
                        client_id,
                        protocol: None,
                        // partial_requests: HashMap::new(),
                        // partial_responses: HashMap::new(),
                        // siduck_conn: None,
                        max_datagram_size: MAX_DATAGRAM_SIZE,
                        // loss_rate: 0.0,
                        max_send_burst: MAX_BUF_SIZE,
                    };

                    clients.insert(client_id, client);
                    clients_ids.insert(scid.clone(), client_id);

                    next_client_id += 1;

                    clients.get_mut(&client_id).unwrap()
                } else {
                    let cid = match clients_ids.get(&hdr.dcid) {
                        Some(v) => v,

                        None => clients_ids.get(&conn_id).unwrap(),
                    };

                    clients.get_mut(cid).unwrap()
                };

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process potentially coalesced packets.
                let read = match client.conn.recv(pkt_buf, recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                        continue 'read;
                    }
                };

                trace!("{} processed {} bytes", client.conn.trace_id(), read);

                // Create a new application protocol session as soon as the QUIC
                // connection is established.
                if client.protocol.is_none()
                    && (client.conn.is_in_early_data() || client.conn.is_established())
                {
                    // At this stage the ALPN negotiation succeeded and selected a
                    // single application protocol name. We'll use this to
                    // construct the correct type of HttpConn
                    // but `application_proto()`
                    // returns a slice, so we have to convert it to a str in order
                    // to compare to our lists of protocols. We `unwrap()` because
                    // we need the value and if something fails at this stage,
                    // there is not much anyone can do to
                    // recover.
                    let app_proto = client.conn.application_proto();

                    if QUICHEPERF_ALPN.contains(&app_proto) {
                        info!("Connection established. Selecting QUICHEPERF protocol.");
                        client.protocol = Some(Protocol::new());
                    } else {
                        warn!("ALPN did not match {:?}: {:?}", QUICHEPERF_ALPN, app_proto);
                        client.conn.close(false, 0x1, b"No ALPN match").ok();
                    }
                }

                // Update max_datagram_size after connection established.
                client.max_datagram_size = client.conn.max_send_udp_payload_size();

                if let Some(protocol) = client.protocol.as_mut() {
                    if !protocol.config_acked {
                        protocol
                            .recv_config(&mut client.conn, &mut buf, &password)
                            .ok();
                        #[cfg(feature = "qlog")]
                        if let Some(tc) = &protocol.tc {
                            common::qlog_metadata(&mut client.conn, tc, &config);
                        }
                    } else {
                        protocol.work(&mut client.conn).ok();
                    }
                }

                handle_path_events(client);

                // See whether source Connection IDs have been retired.
                while let Some(retired_scid) = client.conn.retired_scid_next() {
                    info!("Retiring source CID {:?}", retired_scid);
                    clients_ids.remove(&retired_scid);
                }

                // Provides as many CIDs as possible.
                while client.conn.source_cids_left() > 0 {
                    let (scid, reset_token) = generate_cid_and_reset_token(&rng);
                    if client
                        .conn
                        .new_source_cid(&scid, reset_token, false)
                        .is_err()
                    {
                        break;
                    }

                    clients_ids.insert(scid, client.client_id);
                }
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        continue_write = false;
        for client in clients.values_mut() {
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

            let max_send_burst = client.conn.send_quantum().min(client.max_send_burst)
                / client.max_datagram_size
                * client.max_datagram_size;

            while let Some((local_addr, peer_addr)) = scheduler.get_best_path(&client.conn) {
                let token = src_addr_tokens[&local_addr];
                let socket = &mut sockets[token];
                if !socket.writable_for_dest(&peer_addr) {
                    // Ideally we would check the second-best path but this is not currently possible
                    continue;
                }

                if socket.until >= max_send_burst {
                    // The QUIC connection might have more data to write than max_send_burst.
                    // Set continue_write to immediately exit the event poll.
                    continue_write = true;
                    break;
                }

                let (write, send_info) = match client.conn.send_on_path(
                    &mut socket.buf[socket.until..max_send_burst],
                    Some(local_addr),
                    Some(peer_addr),
                ) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("conn.send: {} done writing", client.conn.trace_id());
                        break;
                    }

                    Err(e) => {
                        error!("{} conn.send failed: {:?}", client.conn.trace_id(), e);
                        client.conn.close(false, 0x1, b"fail").ok();
                        // Not sure what's correct in this situation.
                        break;
                    }
                };

                socket.until += write;
                let _ = socket.send_info.get_or_insert(send_info);
                socket.max_datagram_size = client.max_datagram_size;

                trace!(
                    "{:}->{:} conn.send: wrote {} bytes",
                    send_info.from,
                    send_info.to,
                    write
                );

                if write < client.max_datagram_size {
                    // https://github.com/cloudflare/quiche/commit/eac98fae15ce67ee774125c90db0d59c4deda5da
                    // The QUIC connection might has more data to write than this it did not fill.
                    // Set continue_write to immediately exit the event poll.
                    continue_write = true;

                    // We can not continue appending packets to this send buffer. Immediately break to
                    // sending the buffer.
                    break;
                }
            }

            // Pass the buffer packet data to the UDP socket.
            for (_local_addr, token) in src_addr_tokens.iter() {
                let socket = &mut sockets[*token];
                if let Err(e) = socket.try_send() {
                    panic!("socket.try_send failed: {:?}", e);
                }
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            if c.conn.is_closed() {
                println!(
                    "{} connection collected {:?} {:?}",
                    c.conn.trace_id(),
                    c.conn.stats(),
                    c.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );

                if !c.conn.qlog_writer_drained() {
                    println!("{} qlog event queue not yet drained", c.conn.trace_id());
                }
            }

            !c.conn.is_closed()
        });

        clients_ids.retain(|_, client_id| clients.contains_key(client_id));
    }
}

fn handle_path_events(client: &mut Client) {
    while let Some(qe) = client.conn.path_event_next() {
        match qe {
            quiche::PathEvent::New(local_addr, peer_addr) => {
                info!(
                    "{} Seen new path ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );

                // Directly probe the new path.
                client
                    .conn
                    .probe_path(local_addr, peer_addr)
                    .map_err(|e| error!("cannot probe: {}", e))
                    .ok();
            }

            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now validated",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
                if client.conn.is_multipath_enabled() {
                    client
                        .conn
                        .set_active(local_addr, peer_addr, true)
                        .map_err(|e| error!("cannot set path active: {}", e))
                        .ok();
                }
            }

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) failed validation",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            }

            quiche::PathEvent::Closed(local_addr, peer_addr, err, reason) => {
                info!(
                    "{} Path ({}, {}) is now closed and unusable; err = {} reason = {:?}",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr,
                    err,
                    reason,
                );
            }

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                    client.conn.trace_id(),
                    cid_seq,
                    old,
                    new
                );
            }

            quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                info!(
                    "{} Connection migrated to ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            }

            quiche::PathEvent::PeerPathStatus(addr, path_status) => {
                info!("Peer asks status {:?} for {:?}", path_status, addr,);
                client
                    .conn
                    .set_path_status(addr.0, addr.1, path_status, false)
                    .map_err(|e| error!("cannot follow status request: {}", e))
                    .ok();
            }
        }
    }
}
