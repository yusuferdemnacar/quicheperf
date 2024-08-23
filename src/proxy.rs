use std::{
    collections::{BTreeMap, VecDeque},
    io::Write,
    time::{Duration, Instant},
};

use riptun::{Queue, Tun};

pub const ALPN: [&[u8]; 2] = [b"quicheproxy", b"quicheproxy-00"];

pub struct Proxy {
    queue: Queue,

    flow_handler: FlowHandler,
}

impl Proxy {
    pub fn new(name: String) -> Result<Proxy, String> {
        let mut tun =
            Tun::new(&name, 1).map_err(|e| format!("Failed creating tun {}: {}", name, e))?;
        info!("Opened {}", tun.name());

        let queue = tun
            .drain(..)
            .next()
            .ok_or_else(|| "Failed tun drain".to_string())?;
        queue.set_non_blocking(true).map_err(|e| format!("{}", e))?;

        Ok(Proxy {
            queue,
            flow_handler: FlowHandler::new(),
        })
    }

    pub fn register(&mut self, token: usize, poll: &mut mio::Poll) {
        trace!("Registered tun with token {} with mio", token);
        poll.registry()
            .register(&mut self.queue, mio::Token(token), mio::Interest::READABLE)
            .unwrap();
    }

    /// Read packet from the tun interface if quiche can queue another datagram
    pub fn read_tun(&mut self, conn: &mut quiche::Connection) {
        let mut buf: [u8; 1500] = [0x00; 1500];
        loop {
            if conn.is_dgram_send_queue_full() {
                trace!("read_tun: not reading since dgram_send_queue is full");
                return;
            }

            // TODO: use read_vectored?
            let mut read = match self.queue.recv(&mut buf[8..]) {
                Ok(read) => read,
                // If its a WouldBlock simply short circuit, and re-poll the Queues.
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    // If we error simply log the issue, and continue on business as usual.
                    error!("Reading from tun: {}", err);
                    break;
                }
            };

            if read == 0 {
                return;
            }

            // TODO: get FlowHandler for the specific flow
            let fh = &mut self.flow_handler;

            // Write packet id
            buf[..8].copy_from_slice(&fh.next_send_id.to_le_bytes());
            read += 8;

            debug!(
                "Sending dgram {} with {}B, max={:?}B",
                fh.next_send_id,
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
            } else {
                fh.next_send_id += 1
            }
        }
    }

    /// Process received datagrams and write them to the tun interface
    pub fn write_tun(&mut self, conn: &mut quiche::Connection) -> Result<(), String> {
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

            // TODO: get a sensible FlowHander or iterate over all
            let fh = &mut self.flow_handler;
            fh.recv(id, packet.to_vec(), now);
        }

        // TODO: get a sensible FlowHander or iterate over all
        let fh = &mut self.flow_handler;
        while let Some((_id, packet)) = fh.emit(now) {
            trace!("Emit packet");
            let _written = self
                .queue
                .write(&packet)
                .map_err(|e| format!("Failed writing to tun: {}", e))?;
        }
        Ok(())
    }
}

const TIMEOUT: std::time::Duration = Duration::from_millis(30);

struct FlowHandler {
    // The id of the next outgoing packet
    next_send_id: u64,

    // All packets up to this id will be forwarded immediately
    low_id: u64,

    // The highest packet id received
    high_id: u64,

    timeouts: VecDeque<(u64, Instant)>,

    // Maps packet id to the packet
    packets: BTreeMap<u64, Vec<u8>>,
}

impl FlowHandler {
    fn new() -> Self {
        Self {
            next_send_id: 0,
            low_id: 0,
            high_id: 0,
            packets: BTreeMap::new(),
            timeouts: VecDeque::new(),
        }
    }

    fn recv(&mut self, id: u64, packet: Vec<u8>, now: Instant) {
        // What if id < low_id?
        if id == self.high_id + 1 || id == 0 {
            // No gap, forward
            self.high_id = id;
        } else if id > self.high_id + 1 {
            // Packet loss / reordering occured
            let timeout = now + TIMEOUT;
            self.timeouts.push_back((id, timeout));
        } else if id < self.high_id {
            // Late arrival: fills gap?
        } else if id == self.high_id {
            // Packet duplication; drop the packet
            return;
        } else {
            unreachable!()
        };

        self.packets.insert(id, packet);
    }

    fn emit(&mut self, now: Instant) -> Option<(u64, Vec<u8>)> {
        // Check if a timeout expired
        if let Some((id, timeout)) = self.timeouts.front() {
            if now > *timeout {
                self.low_id = *id;
                self.timeouts.pop_front();
            }
        };

        let min_id_buffered = *self.packets.first_key_value().and_then(|(k, _)| Some(k))?;

        // Check if the next packet (without a gap) is buffered
        if min_id_buffered <= self.low_id + 1 {
            if min_id_buffered == self.low_id + 1 {
                self.low_id = min_id_buffered;
            }
            return self.packets.pop_first().and_then(|(k, v)| Some((k, v)));
        }

        None
    }

    /* TODO: how to implement the timoeut?
    Think about the cases where we have two loss ranges. What should happen in that case?

    Would it be easier to implement a jitter buffer from the get-go? Or use logic sketched
    in the paper draft?
    */
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_loss() {
        let mut fh = FlowHandler::new();
        let packet = Vec::new();
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
    }

    #[test]
    fn dup_is_dropped() {
        let mut fh = FlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(0, packet.clone(), now);
        fh.recv(1, packet.clone(), now);
        fh.recv(1, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);
    }

    #[test]
    fn loss_single_range() {
        let mut fh = FlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(0, packet.clone(), now);
        fh.recv(1, packet.clone(), now);
        fh.recv(5, packet.clone(), now);
        fh.recv(6, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        let timeout = now + TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(5));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(6));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);
    }

    #[ignore]
    #[test]
    // The loss of the first packet is not detected since the the default value of low_id is 0
    fn loss_first_packet() {
        let mut fh = FlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(1, packet.clone(), now);
        fh.recv(2, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        let timeout = now + TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(2));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);
    }

    #[test]
    fn loss_multiple_ranges() {
        let mut fh = FlowHandler::new();
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

        let timeout_a = now_a + TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout_a).map(|(k, _)| k), Some(5));
        assert_eq!(fh.emit(timeout_a).map(|(k, _)| k), Some(6));
        assert_eq!(fh.emit(timeout_a).map(|(k, _)| k), None);

        let timeout_b = now_b + TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout_b).map(|(k, _)| k), Some(8));
        assert_eq!(fh.emit(timeout_b).map(|(k, _)| k), None);
    }

    #[test]
    fn reordering() {
        let mut fh = FlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(0, packet.clone(), now);
        fh.recv(2, packet.clone(), now);
        fh.recv(1, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(2));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);
    }

    #[test]
    fn late_arrival() {
        let mut fh = FlowHandler::new();
        let packet = Vec::new();
        let now = Instant::now();

        fh.recv(0, packet.clone(), now);
        fh.recv(1, packet.clone(), now);
        fh.recv(5, packet.clone(), now);
        fh.recv(6, packet.clone(), now);

        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(0));
        assert_eq!(fh.emit(now).map(|(k, _)| k), Some(1));
        assert_eq!(fh.emit(now).map(|(k, _)| k), None);

        let timeout = now + TIMEOUT + Duration::from_millis(1);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(5));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(6));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);

        let late = now + TIMEOUT + Duration::from_millis(10);
        fh.recv(3, packet.clone(), late);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(3));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);

        fh.recv(7, packet.clone(), late);
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), Some(7));
        assert_eq!(fh.emit(timeout).map(|(k, _)| k), None);
    }
}
