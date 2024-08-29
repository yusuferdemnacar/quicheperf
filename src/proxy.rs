use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    hash::{DefaultHasher, Hasher},
    io::Write,
    time::{Duration, Instant},
};

use etherparse::PacketHeaders;
use riptun::{Queue, Tun};

use crate::cli::FlowHandlerOpts;

pub const ALPN: [&[u8]; 2] = [b"quicheproxy", b"quicheproxy-00"];

type FlowId = u64;

pub struct Proxy {
    queue: Queue,

    flow_handler_opts: FlowHandlerOpts,

    flows: HashMap<FlowId, Box<dyn FlowHandler>>,

    /// Contains flows with queued packets (optimization to avoid iterating over
    /// all of self.flows each time).
    active_flows: HashSet<FlowId>,
}

impl Proxy {
    pub fn new(name: String, flow_handler_opts: FlowHandlerOpts) -> Result<Proxy, String> {
        let mut tun =
            Tun::new(&name, 1).map_err(|e| format!("Failed creating tun {}: {}", name, e))?;
        info!(
            "Opened {}; using flow handler {:?}",
            tun.name(),
            flow_handler_opts
        );

        let queue = tun
            .drain(..)
            .next()
            .ok_or_else(|| "Failed tun drain".to_string())?;
        queue.set_non_blocking(true).map_err(|e| format!("{}", e))?;

        Ok(Proxy {
            queue,
            flow_handler_opts,
            flows: HashMap::new(),
            active_flows: HashSet::new(),
        })
    }

    pub fn register(&mut self, token: usize, poll: &mut mio::Poll) {
        trace!("Registered tun with token {} with mio", token);
        poll.registry()
            .register(&mut self.queue, mio::Token(token), mio::Interest::READABLE)
            .unwrap();
    }

    /// Returns the time until a buffered packet must be forwarded
    pub fn timeout(&self) -> Duration {
        let now = Instant::now();
        self.flows
            .values()
            .map(|fh| fh.timeout(now))
            .min()
            .unwrap_or(Duration::MAX)
    }

    /// Return a new FlowHandler according to the choice made by the user
    fn new_flow_handler(&self) -> Box<dyn FlowHandler> {
        match self.flow_handler_opts {
            FlowHandlerOpts::Noop => Box::new(NoopFlowHandler::new()),
            FlowHandlerOpts::Reordering => Box::new(ReorderingFlowHandler::new()),
        }
    }

    /// Read packet from the tun interface if quiche can queue another datagram
    pub fn forward_tun_to_conn(&mut self, conn: &mut quiche::Connection) {
        let mut buf: [u8; 1500] = [0x00; 1500];
        loop {
            if conn.is_dgram_send_queue_full() {
                trace!("read_tun: not reading since dgram_send_queue is full");
                return;
            }

            // TODO: use read_vectored?
            let mut read = match self.queue.recv(&mut buf[8..]) {
                Ok(read) if read == 0 => return,
                Ok(read) => read,
                // If its a WouldBlock simply short circuit, and re-poll the Queues.
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    // If we error simply log the issue, and continue on business as usual.
                    error!("Reading from tun: {}", err);
                    break;
                }
            };

            let flow_id = map_packet_to_flow(&buf[..read]).unwrap_or_else(|e| {
                warn!("Failed parsing packet: {}", e);
                None
            });

            let fh = if let Some(flow_id) = flow_id {
                match self.flows.get_mut(&flow_id) {
                    Some(v) => Some(v),
                    None => {
                        // New flow
                        let fh = self.new_flow_handler();
                        self.flows.insert(flow_id, fh);
                        self.flows.get_mut(&flow_id)
                    }
                }
            } else {
                None
            };

            // Write packet id
            let flow_id = match fh {
                Some(ref fh) => &fh.next_send_id().to_le_bytes(),
                None => &[0; 8],
            };
            buf[..8].copy_from_slice(flow_id);
            read += 8;

            debug!(
                "Sending dgram {} with {}B, max={:?}B",
                u64::from_le_bytes(*flow_id),
                read,
                conn.dgram_max_writable_len()
            );
            if let Err(e) = conn.dgram_send(&buf[..read]) {
                match e {
                    quiche::Error::Done => (),
                    quiche::Error::BufferTooShort => error!("Trying dgram_send but {}", e),
                    quiche::Error::InvalidState => error!("Trying dgram_send but {}", e),
                    _ => panic!("Unexpected dgram error: {}", e),
                }
            } else if let Some(fh) = fh {
                fh.incr_send_id();
            }
        }
    }

    /// Process received datagrams and write them to the tun interface
    pub fn forward_conn_to_tun(&mut self, conn: &mut quiche::Connection) -> Result<(), String> {
        let now = Instant::now();

        while let Ok(data) = conn.dgram_recv_vec() {
            let id = u64::from_le_bytes(data[..8].try_into().unwrap());
            let packet = &data[8..];

            debug!(
                "{} received packet with {}B from dgram {}",
                conn.trace_id(),
                packet.len(),
                id,
            );

            let flow_id = map_packet_to_flow(packet).unwrap_or_else(|e| {
                warn!("Failed parsing packet: {}", e);
                None
            });

            if let Some(flow_id) = flow_id {
                let fh = match self.flows.get_mut(&flow_id) {
                    Some(v) => v,
                    None => {
                        // New flow
                        let fh = self.new_flow_handler();
                        self.flows.insert(flow_id, fh);
                        self.flows.get_mut(&flow_id).unwrap()
                    }
                };

                fh.recv(id, packet.to_vec(), now);
                self.active_flows.insert(id);
            } else {
                let _written = self
                    .queue
                    .write(&packet)
                    .map_err(|e| format!("Failed writing to tun: {}", e))?;
            };
        }

        self.active_flows.retain(|flow_id| {
            let fh = self
                .flows
                .get_mut(flow_id)
                .expect("flow_id {} in HashSet but not in HashMap");
            while let Some((id, packet)) = fh.emit(now) {
                match self.queue.write(&packet) {
                    Ok(written) => trace!("Emitted packet {} with {}B", id, written),
                    Err(e) => error!("Failed writing to tun: {}", e),
                }
            }
            fh.packets_queued()
        });

        Ok(())
    }
}

/// Returns Some(flow_id) for TCP and UDP flows. Returns None for ICMP.
fn map_packet_to_flow(packet: &[u8]) -> Result<Option<FlowId>, String> {
    let headers = PacketHeaders::from_ip_slice(packet).map_err(|e| format!("{}", e))?;

    match headers.transport.as_ref().ok_or("No transport header")? {
        etherparse::TransportHeader::Icmpv4(_) | etherparse::TransportHeader::Icmpv6(_) => {
            return Ok(None)
        }
        _ => {}
    };

    let mut s = DefaultHasher::new();

    match headers.net.ok_or("No net header")? {
        etherparse::NetHeaders::Ipv4(ip, _) => {
            s.write(&ip.source);
            s.write(&ip.destination);
        }
        etherparse::NetHeaders::Ipv6(ip, _) => {
            s.write(&ip.source);
            s.write(&ip.destination);
        }
    };

    match headers.transport.ok_or("No transport header")? {
        etherparse::TransportHeader::Udp(h) => {
            s.write_u16(h.source_port);
            s.write_u16(h.destination_port);
        }
        etherparse::TransportHeader::Tcp(h) => {
            s.write_u16(h.source_port);
            s.write_u16(h.destination_port);
        }
        etherparse::TransportHeader::Icmpv4(_) => unreachable!(),
        etherparse::TransportHeader::Icmpv6(_) => unreachable!(),
    };

    // TODO: parse the connection ID from QUIC packets?

    Ok(Some(s.finish()))
}

pub trait FlowHandler {
    fn recv(&mut self, id: u64, packet: Vec<u8>, now: Instant);

    fn timeout(&self, now: Instant) -> Duration;

    fn emit(&mut self, now: Instant) -> Option<(u64, Vec<u8>)>;

    fn packets_queued(&self) -> bool;

    fn next_send_id(&self) -> u64;

    fn incr_send_id(&mut self) -> u64;
}

struct NoopFlowHandler {
    packets: VecDeque<(u64, Vec<u8>)>,

    // The id of the next outgoing packet
    next_send_id: u64,
}

impl NoopFlowHandler {
    #[allow(dead_code)]
    fn new() -> Self {
        NoopFlowHandler {
            packets: VecDeque::with_capacity(100),
            next_send_id: 0,
        }
    }
}

impl FlowHandler for NoopFlowHandler {
    fn recv(&mut self, id: u64, packet: Vec<u8>, _now: Instant) {
        self.packets.push_back((id, packet))
    }

    fn timeout(&self, _now: Instant) -> Duration {
        if self.packets.is_empty() {
            Duration::MAX
        } else {
            Duration::ZERO
        }
    }

    fn emit(&mut self, _now: Instant) -> Option<(u64, Vec<u8>)> {
        self.packets.pop_front()
    }

    fn packets_queued(&self) -> bool {
        !self.packets.is_empty()
    }

    fn next_send_id(&self) -> u64 {
        self.next_send_id
    }

    fn incr_send_id(&mut self) -> u64 {
        self.next_send_id += 1;
        self.next_send_id
    }
}

/// Holds packets until all preceeding packets have been received or a
/// packet-specific timeout expires.
struct ReorderingFlowHandler {
    // All packets up to this id have been forwarded
    low_id: u64,

    // Maps packet id to packet data and its release timeout
    packets: BTreeMap<u64, (Instant, Vec<u8>)>,

    // The id of the next outgoing packet
    next_send_id: u64,
}

impl ReorderingFlowHandler {
    const TIMEOUT: std::time::Duration = Duration::from_millis(30);

    fn new() -> Self {
        Self {
            low_id: 0,
            packets: BTreeMap::new(),
            next_send_id: 0,
        }
    }
}

impl FlowHandler for ReorderingFlowHandler {
    fn recv(&mut self, id: u64, packet: Vec<u8>, now: Instant) {
        let mut timeout = now + Self::TIMEOUT;

        if let Some((_, (next_timeout, _))) = self.packets.range(id..).next() {
            if *next_timeout <= timeout {
                timeout = *next_timeout;
            }
        }

        self.packets.insert(id, (timeout, packet));
    }

    fn timeout(&self, now: Instant) -> Duration {
        match self.packets.first_key_value() {
            Some((_, (timeout, _))) => timeout
                .checked_duration_since(now)
                .unwrap_or(Duration::ZERO),
            None => Duration::MAX,
        }
    }

    fn emit(&mut self, now: Instant) -> Option<(u64, Vec<u8>)> {
        let (id, (timeout, _packet)) = self.packets.first_key_value()?;

        if now > *timeout {
            trace!(
                "emit: {:?} until timeout; low_id would {} -> {}; {} packets queued",
                timeout.saturating_duration_since(now),
                self.low_id,
                id,
                self.packets.len()
            );
            self.low_id = *id;
        }

        // Check if the next packet (without a gap) is buffered
        if *id <= self.low_id + 1 {
            if *id == self.low_id + 1 {
                self.low_id = *id;
            }
            return self
                .packets
                .pop_first()
                .and_then(|(k, (_, v))| Some((k, v)));
        }

        None
    }

    fn packets_queued(&self) -> bool {
        !self.packets.is_empty()
    }

    fn next_send_id(&self) -> u64 {
        self.next_send_id
    }

    fn incr_send_id(&mut self) -> u64 {
        self.next_send_id += 1;
        self.next_send_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use etherparse::{IcmpEchoHeader, PacketBuilder};

    fn build_packet_udp(sport: u16) -> Vec<u8> {
        let builder = PacketBuilder::ipv4([192, 168, 1, 1], [192, 168, 1, 2], 20).udp(sport, 1234);
        let payload = [0; 8];
        let mut packet = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, &payload).unwrap();
        packet
    }

    fn build_packet_icmp(sport: u16) -> Vec<u8> {
        let icmp = etherparse::Icmpv4Type::EchoRequest(IcmpEchoHeader { id: 0, seq: 0 });
        let builder = PacketBuilder::ipv4([192, 168, 1, 1], [192, 168, 1, 2], 20).icmpv4(icmp);
        let payload = [0; 8];
        let mut packet = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, &payload).unwrap();
        packet
    }

    #[test]
    fn no_loss() {
        let mut fh = ReorderingFlowHandler::new();
        let packet = build_packet_udp(100);
        let now = Instant::now();

        fh.recv(0, packet.clone(), now);
        fh.recv(1, packet.clone(), now);
        fh.recv(2, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(2));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        fh.recv(3, packet.clone(), now);
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(3));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        assert!(fh.packets.is_empty())
    }

    #[test]
    fn dup_is_dropped() {
        let mut fh = ReorderingFlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(0, packet.clone(), now);
        fh.recv(1, packet.clone(), now);
        fh.recv(1, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        assert!(fh.packets.is_empty())
    }

    #[test]
    fn loss_single_range() {
        let mut fh = ReorderingFlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(0, packet.clone(), now);
        fh.recv(1, packet.clone(), now);
        fh.recv(5, packet.clone(), now);
        fh.recv(6, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        let timeout = now + ReorderingFlowHandler::TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(5));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(6));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);

        assert!(fh.packets.is_empty())
    }

    #[ignore]
    #[test]
    // The loss of the first packet is not detected since the the default value of low_id is 0
    fn loss_first_packet() {
        let mut fh = ReorderingFlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(1, packet.clone(), now);
        fh.recv(2, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        let timeout = now + ReorderingFlowHandler::TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(2));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);

        assert!(fh.packets.is_empty())
    }

    #[test]
    fn loss_multiple_ranges() {
        let mut fh = ReorderingFlowHandler::new();
        let packet = Vec::new();

        let now_a = Instant::now();
        fh.recv(0, packet.clone(), now_a);
        fh.recv(1, packet.clone(), now_a);
        fh.recv(5, packet.clone(), now_a);
        fh.recv(6, packet.clone(), now_a);

        let now_b = now_a + Duration::from_millis(10);
        fh.recv(8, packet.clone(), now_b);

        assert_eq!(fh.emit(now_a).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now_a).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now_a).map(|(k, _)| k), None);

        let timeout_a = now_a + ReorderingFlowHandler::TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout_a).map(|(k, _)| k), Some(5));
        assert_eq!(fh.emit(timeout_a).map(|(k, _)| k), Some(6));
        assert_eq!(fh.emit(timeout_a).map(|(k, _)| k), None);

        let timeout_b = now_b + ReorderingFlowHandler::TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout_b).map(|(k, _)| k), Some(8));
        assert_eq!(fh.emit(timeout_b).map(|(k, _)| k), None);

        assert!(fh.packets.is_empty())
    }

    #[test]
    fn reordering() {
        let mut fh = ReorderingFlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(0, packet.clone(), now);
        fh.recv(2, packet.clone(), now);
        fh.recv(1, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(2));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        assert!(fh.packets.is_empty())
    }

    #[test]
    fn late_arrival() {
        let mut fh = ReorderingFlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(0, packet.clone(), now);
        fh.recv(1, packet.clone(), now);
        fh.recv(5, packet.clone(), now);
        fh.recv(6, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        let timeout = now + ReorderingFlowHandler::TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(5));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(6));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);

        let late = now + ReorderingFlowHandler::TIMEOUT + Duration::from_millis(10);
        fh.recv(3, packet.clone(), late);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(3));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);

        fh.recv(7, packet.clone(), late);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(7));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);

        assert!(fh.packets.is_empty())
    }

    #[test]
    fn out_of_order() {
        let mut fh = ReorderingFlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(0, packet.clone(), now);
        fh.recv(1, packet.clone(), now);

        // Start loss timeout for 2, 3, and 4
        fh.recv(5, packet.clone(), now);
        fh.recv(6, packet.clone(), now);

        // Packet 4 arrives out-of-order
        let late = now + Duration::from_millis(10);
        fh.recv(4, packet.clone(), late);

        // Packets 0 and 1 are emitted and the timeout of packet 2 is respected
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        // The packets are released after the timeout
        let timeout = now + ReorderingFlowHandler::TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(4));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(5));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(6));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);

        assert!(fh.packets.is_empty())
    }
}
