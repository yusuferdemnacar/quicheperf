use std::io::Write;

use riptun::{Queue, Tun};

pub const ALPN: [&[u8]; 2] = [b"quicheproxy", b"quicheproxy-00"];

pub struct Proxy {
    queue: Queue,
}

impl Proxy {
    pub fn new(name: String) -> Proxy {
        let mut tun = Tun::new(&name, 1).unwrap();
        info!("[INFO] => Created new virtual device: {}", tun.name());

        let queue = tun.drain(..).next().unwrap();
        queue.set_non_blocking(true).unwrap();

        Proxy { queue }
    }

    pub fn register(&mut self, token: usize, poll: &mut mio::Poll) {
        poll.registry()
            .register(&mut self.queue, mio::Token(token), mio::Interest::READABLE)
            .unwrap();
    }

    // TODO: read all available packets not just one
    pub fn read_tun(&self, buf: &mut [u8; 1500]) -> usize {
        match self.queue.recv(buf) {
            Ok(read) => read,
            // If its a WouldBlock simply short circuit, and re-poll the Queues.
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(err) => {
                // If we error simply log the issue, and continue on business as usual.
                error!("Reading from tun: {}", err);
                0
            }
        }
    }

    pub fn write_tun(&mut self, conn: &mut quiche::Connection) {
        while let Ok(data) = conn.dgram_recv_vec() {
            trace!("{} received {} bytes", conn.trace_id(), data.len());

            self.queue.write(&data).unwrap();
        }
        // Ok(())
    }

    // pub fn run(&self, terminate: Arc<AtomicBool>) {
    //     let intf_name = "mp%d";
    //     let tun = match Tun::new(intf_name, 1) {
    //         Ok(tun) => tun,
    //         Err(err) => {
    //             error!("Failed opening tun device {}: {}", intf_name, err);
    //             return;
    //         }
    //     };

    //     // Lets make sure we print the real name of our new TUN device.
    //     info!("Openend TUN intf {}", tun.name());

    //     // Create a buffer to read packets into, and setup the queue to receive from.
    //     let mut buffer: [u8; 1500] = [0x00; 1500];
    //     let queue = 0;

    //     loop {
    //         // Will not break reliably if no packets arrive and thread get's stuck in recv_via
    //         if terminate.load(Ordering::SeqCst) {
    //             break;
    //         }

    //         // Receive the next packet from the specified queue.
    //         let read = match tun.recv_via(queue, &mut buffer) {
    //             Ok(read) => read,
    //             Err(err) => {
    //                 error!("Failed reading from tun: {}", err);
    //                 return;
    //             }
    //         };

    //         // Print out the amount of data received and the bytes read off the queue.
    //         info!(
    //             "Received tun data ({}B): {:?}",
    //             read,
    //             &buffer[..read]
    //         );
    //     }
    // }
}
