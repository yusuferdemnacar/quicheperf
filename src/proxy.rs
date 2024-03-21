use std::{
    io::{Read, Write},
    time::Duration,
};

use riptun::{Queue, Tun};

pub const ALPN: [&[u8]; 2] = [b"quicheproxy", b"quicheproxy-00"];

pub struct Proxy {}

impl Proxy {
    pub fn timeout(&self) -> Duration {
        Duration::MAX
    }
}

pub struct ProxyClient {
    token: usize,
    queue: Queue,
}

impl ProxyClient {
    pub fn new(name: String, token: usize, poll: &mut mio::Poll) -> ProxyClient {
        let mut tun = Tun::new(&name, 1).unwrap();
        info!("[INFO] => Created new virtual device: {}", tun.name());

        let mut queue = tun.drain(..).next().unwrap();
        // let mut queue: &mut Queue = tun.get_mut(0).unwrap();

        // Ensure the Queue's underlying file descriptor is in non-blocking mode.
        queue.set_non_blocking(true).unwrap();

        // Create this queue's token, register, and then map this queue to that generated token.
        poll.registry()
            .register(&mut queue, mio::Token(token), mio::Interest::READABLE)
            .unwrap();

        ProxyClient { token, queue }
    }

    // TODO: read all available packets not just one
    pub fn read_tun(&self, event: &mio::event::Event, buf: &mut [u8; 1500]) -> usize {
        let token: usize = event.token().into();
        if event.is_readable() && token == self.token {
            return match self.queue.recv(buf) {
                Ok(read) => read,
                // If its a WouldBlock simply short circuit, and re-poll the Queues.
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => 0,
                Err(err) => {
                    // If we error simply log the issue, and continue on business as usual.
                    error!("[ERROR][Queue: {:?}] => {}", event.token(), err);
                    0
                }
            };
        }
        0
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
