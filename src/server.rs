use std::net::SocketAddr;

use crate::common;
use crate::protocol::Protocol;

use super::common::*;
use super::sendto;
use ring::rand::*;
use slab::Slab;
use std::collections::HashMap;

use quiche::ConnectionId;

type ClientId = u64;

struct Client {
    conn: quiche::Connection,

    client_id: ClientId,

    protocol: Option<Protocol>,

    // partial_requests: std::collections::HashMap<u64, PartialRequest>,

    // partial_responses: std::collections::HashMap<u64, PartialResponse>,
    max_datagram_size: usize,

    loss_rate: f64,

    max_send_burst: usize,
}

type ClientIdMap = HashMap<ConnectionId<'static>, ClientId>;
type ClientMap = HashMap<ClientId, Client>;

pub fn listen(
    local_addrs: Vec<SocketAddr>, password: Option<String>,
    mut config: quiche::Config,
) {
    let mut buf = [0; MAX_BUF_SIZE];
    let mut out = [0; MAX_BUF_SIZE];

    let mut sockets = Slab::with_capacity(std::cmp::max(local_addrs.len(), 1));
    let mut src_addrs = HashMap::new();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let mut enable_gso = true;

    let mut addrs = Vec::new();
    for src_addr in local_addrs {
        let socket = mio::net::UdpSocket::bind(src_addr).unwrap();
        let local_addr = socket.local_addr().unwrap();

        match set_txtime_sockopt(&socket) {
            Ok(_) => debug!("successfully set SO_TXTIME socket option"),
            Err(e) => error!("set SO_TXTIME socket option failed {:?}", e),
        };
        enable_gso &= sendto::detect_gso(&socket, MAX_DATAGRAM_SIZE);

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

        info!("listening on {:}", local_addr);
    }

    // Set SO_TXTIME socket option on the listening UDP socket for pacing
    // outgoing packets.
    let pacing = true;

    let mut keylog = configure_keylog();

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut next_client_id = 0;
    let mut clients_ids = ClientIdMap::new();
    let mut clients = ClientMap::new();

    let mut continue_write = false;

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = match continue_write {
            true => Some(std::time::Duration::from_secs(0)),
            false => clients.values().filter_map(|c| c.conn.timeout()).min(),
        };
        poll.poll(&mut events, timeout).unwrap();

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
            let socket = &sockets[token];
            let local_addr = socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("recv() from {:} would block", local_addr);
                            break 'read;
                        }

                        panic!("recv() from {:} failed: {:?}", local_addr, e);
                    },
                };

                trace!("{:}->{:}: got {} bytes", from, local_addr, len);

                let pkt_buf = &mut buf[..len];

                // Parse the QUIC packet's header.
                let hdr = match quiche::Header::from_slice(
                    pkt_buf,
                    quiche::MAX_CONN_ID_LEN,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Parsing packet header failed: {:?}", e);
                        continue 'read;
                    },
                };

                trace!("got packet {:?}", hdr);

                let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                let conn_id = conn_id.to_vec().into();

                // Lookup a connection based on the packet's connection ID. If
                // there is no connection matching, create a new
                // one.
                let client = if !clients_ids.contains_key(&hdr.dcid) &&
                    !clients_ids.contains_key(&conn_id)
                {
                    if hdr.ty != quiche::Type::Initial {
                        error!("Packet is not Initial");
                        continue 'read;
                    }

                    if !quiche::version_is_supported(hdr.version) {
                        warn!("Doing version negotiation");

                        let len = quiche::negotiate_version(
                            &hdr.scid, &hdr.dcid, &mut out,
                        )
                        .unwrap();

                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                trace!("send() would block");
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
                    let mut conn = quiche::accept(
                        &scid,
                        None,
                        local_addr,
                        from,
                        &mut config,
                    )
                    .unwrap();

                    if let Some(keylog) = &mut keylog {
                        if let Ok(keylog) = keylog.try_clone() {
                            conn.set_keylog(Box::new(keylog));
                        }
                    }

                    // Only bother with qlog if the user specified it.
                    #[cfg(feature = "qlog")]
                    common::set_qlog(
                        &mut conn,
                        format!("{:?}", &hdr.scid),
                        "server",
                        None,
                    );

                    let client_id = next_client_id;

                    let client = Client {
                        conn,
                        client_id,
                        protocol: None,
                        // partial_requests: HashMap::new(),
                        // partial_responses: HashMap::new(),
                        // siduck_conn: None,
                        max_datagram_size: MAX_DATAGRAM_SIZE,
                        loss_rate: 0.0,
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
                    },
                };

                trace!("{} processed {} bytes", client.conn.trace_id(), read);

                // Create a new application protocol session as soon as the QUIC
                // connection is established.
                if client.protocol.is_none() &&
                    (client.conn.is_in_early_data() ||
                        client.conn.is_established())
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

                    if QUICPERF_ALPN.contains(&app_proto) {
                        info!("Connection established. Selecting QUICPERF protocol.");
                        client.protocol = Some(Protocol::new())
                    } else {
                        warn!("No ALPN matched")
                    }
                }

                // Update max_datagram_size after connection established.
                client.max_datagram_size =
                    client.conn.max_send_udp_payload_size();

                if let Some(protocol) = client.protocol.as_mut() {
                    if !protocol.config_acked {
                        protocol
                            .recv_config(&mut client.conn, &mut buf, &password)
                            .ok();
                        if let Some(tc) = &protocol.tc {
                            common::qlog_metadata(&mut client.conn, tc, &config);
                        }
                    } else {
                        protocol.work(&mut client.conn, &mut buf).ok();
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
            let loss_rate =
                client.conn.stats().lost as f64 / client.conn.stats().sent as f64;
            if loss_rate > client.loss_rate + 0.001 {
                client.max_send_burst = client.max_send_burst / 4 * 3;
                // Minimun bound of 10xMSS.
                client.max_send_burst =
                    client.max_send_burst.max(client.max_datagram_size * 10);
                client.loss_rate = loss_rate;
            }

            let max_send_burst =
                client.conn.send_quantum().min(client.max_send_burst) /
                    client.max_datagram_size *
                    client.max_datagram_size;
            let mut total_write = 0;
            let mut dst_info: Option<quiche::SendInfo> = None;

            while total_write < max_send_burst {
                let res = match dst_info {
                    Some(info) => client.conn.send_on_path(
                        &mut out[total_write..max_send_burst],
                        Some(info.from),
                        Some(info.to),
                    ),
                    None =>
                        client.conn.send(&mut out[total_write..max_send_burst]),
                };

                let (write, send_info) = match res {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        continue_write = dst_info.is_some();
                        trace!(
                            "conn.send: {} done writing",
                            client.conn.trace_id()
                        );
                        break;
                    },

                    Err(e) => {
                        error!(
                            "{} conn.send failed: {:?}",
                            client.conn.trace_id(),
                            e
                        );

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                trace!(
                    "{:}->{:} conn.send: wrote {} bytes",
                    send_info.from,
                    send_info.to,
                    write
                );

                total_write += write;

                // Use the first packet time to send, not the last.
                let _ = dst_info.get_or_insert(send_info);

                if write < client.max_datagram_size {
                    break;
                }
            }

            if total_write == 0 || dst_info.is_none() {
                break;
            }
            let dst_info = dst_info.unwrap();

            let token = src_addrs[&dst_info.from];
            let socket = &sockets[token];

            if let Err(e) = sendto::send_to(
                &socket,
                &out[..total_write],
                &dst_info,
                client.max_datagram_size,
                pacing,
                enable_gso,
            ) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("send() would block");
                    break;
                }

                panic!("send_to() failed: {:?}", e);
            }

            trace!(
                "{:}->{:} written {} bytes",
                dst_info.from,
                dst_info.to,
                total_write
            );

            if continue_write {
                trace!(
                    "{} pause writing and consider another path",
                    client.conn.trace_id()
                );
                break;
            }

            if total_write >= max_send_burst {
                trace!("{} pause writing", client.conn.trace_id(),);
                continue_write = true;
                break;
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?} {:?}",
                    c.conn.trace_id(),
                    c.conn.stats(),
                    c.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );
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
            },

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
            },

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) failed validation",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::Closed(local_addr, peer_addr, err, reason) => {
                info!(
                    "{} Path ({}, {}) is now closed and unusable; err = {} reason = {:?}",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr,
                    err,
                    reason,
                );
            },

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                    client.conn.trace_id(),
                    cid_seq,
                    old,
                    new
                );
            },

            quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                info!(
                    "{} Connection migrated to ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::PeerPathStatus(addr, path_status) => {
                info!("Peer asks status {:?} for {:?}", path_status, addr,);
                client
                    .conn
                    .set_path_status(addr.0, addr.1, path_status, false)
                    .map_err(|e| error!("cannot follow status request: {}", e))
                    .ok();
            },
        }
    }
}
