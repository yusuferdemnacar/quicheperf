// Copyright (C) 2021, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::cmp;

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use crate::common::MAX_BUF_SIZE;
use crate::common::MAX_DATAGRAM_SIZE;

/// For Linux, try to detect GSO is available.
#[cfg(target_os = "linux")]
pub fn detect_gso(socket: &mio::net::UdpSocket, segment_size: usize) -> bool {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::UdpGsoSegment;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::io::BorrowedFd;

    let fd = &unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
    setsockopt(fd, UdpGsoSegment, &(segment_size as i32)).is_ok()
}

/// For non-Linux, there is no GSO support.
#[cfg(not(target_os = "linux"))]
pub fn detect_gso(_socket: &mio::net::UdpSocket, _segment_size: usize) -> bool {
    false
}

/// Send packets using sendmsg() with GSO.
#[cfg(target_os = "linux")]
fn send_to_gso_pacing(
    socket: &mio::net::UdpSocket,
    buf: &[u8],
    dest: SocketAddr,
    tx_time: Instant,
    segment_size: usize,
) -> io::Result<usize> {
    use nix::sys::socket::sendmsg;
    use nix::sys::socket::ControlMessage;
    use nix::sys::socket::MsgFlags;
    use nix::sys::socket::SockaddrStorage;
    use std::io::IoSlice;
    use std::os::unix::io::AsRawFd;

    let iov = [IoSlice::new(buf)];
    let segment_size = segment_size as u16;
    let dst = SockaddrStorage::from(dest);
    let sockfd = socket.as_raw_fd();

    // GSO option.
    let cmsg_gso = ControlMessage::UdpGsoSegments(&segment_size);

    let now = std::time::Instant::now();
    let until_a = tx_time.checked_duration_since(now);
    let until_b = now.checked_duration_since(tx_time);
    // send_info.at

    // Pacing option.
    let send_time = std_time_to_u64(&tx_time);
    let cmsg_txtime = ControlMessage::TxTime(&send_time);

    trace!("Pace packet at {:?} / {:?} / {}", until_a, until_b, send_time);

    match sendmsg(
        sockfd,
        &iov,
        &[cmsg_gso, cmsg_txtime],
        MsgFlags::empty(),
        Some(&dst),
    ) {
        Ok(v) => Ok(v),
        Err(e) => Err(e.into()),
    }
}

/// For non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn send_to_gso_pacing(
    _socket: &mio::net::UdpSocket,
    _buf: &[u8],
    _send_info: &quiche::SendInfo,
    _segment_size: usize,
) -> io::Result<usize> {
    panic!("send_to_gso() should not be called on non-linux platforms");
}

/// Send packets using sendmsg() with GSO.
#[cfg(target_os = "linux")]
fn sendmsg_pacing(
    socket: &mio::net::UdpSocket,
    buf: &[u8],
    dest: SocketAddr,
    tx_time: Instant,
) -> io::Result<usize> {
    use nix::sys::socket::sendmsg;
    use nix::sys::socket::ControlMessage;
    use nix::sys::socket::MsgFlags;
    use nix::sys::socket::SockaddrStorage;
    use std::io::IoSlice;
    use std::os::unix::io::AsRawFd;

    let iov = [IoSlice::new(buf)];
    let dst = SockaddrStorage::from(dest);
    let sockfd = socket.as_raw_fd();

    let now = std::time::Instant::now();
    let until_a = tx_time.checked_duration_since(now);
    let until_b = now.checked_duration_since(tx_time);
    // send_info.at

    // Pacing option.
    let send_time = std_time_to_u64(&tx_time);
    let cmsg_txtime = ControlMessage::TxTime(&send_time);

    trace!("Pace packet (no gso) at {:?} / {:?} / {}", until_a, until_b, send_time);

    match sendmsg(
        sockfd,
        &iov,
        &[cmsg_txtime],
        MsgFlags::empty(),
        Some(&dst),
    ) {
        Ok(v) => Ok(v),
        Err(e) => Err(e.into()),
    }
}

/// A wrapper function of send_to().
/// - when GSO and SO_TXTIME enabled, send a packet using send_to_gso().
/// Otherwise, send packet using socket.send_to().
// pub fn send_to(
//     socket: &mio::net::UdpSocket,
//     buf: &[u8],
//     send_info: &quiche::SendInfo,
//     segment_size: usize,
//     pacing: bool,
//     enable_gso: bool,
// ) -> io::Result<usize> {
//     if pacing && enable_gso {
//         return send_to_gso_pacing(socket, buf, send_info, segment_size);
//     }

//     let mut off = 0;
//     let mut left = buf.len();
//     let mut written = 0;

//     while left > 0 {
//         let pkt_len = cmp::min(left, segment_size);

//         let result = if pacing {
//             sendmsg_pacing(socket, &buf[off..off + pkt_len], send_info)
//         } else {
//             socket.send_to(&buf[off..off + pkt_len], send_info.to)
//         };

//         match result {
//             Ok(v) => {
//                 written += v;
//             }
//             Err(e) => return Err(e),
//         }

//         off += pkt_len;
//         left -= pkt_len;
//     }

//     Ok(written)
// }

#[cfg(target_os = "linux")]
fn std_time_to_u64(time: &std::time::Instant) -> u64 {
    const NANOS_PER_SEC: u64 = 1_000_000_000;

    const INSTANT_ZERO: std::time::Instant = unsafe { std::mem::transmute(std::time::UNIX_EPOCH) };

    let raw_time = time.duration_since(INSTANT_ZERO);

    let sec = raw_time.as_secs();
    let nsec = raw_time.subsec_nanos();

    sec * NANOS_PER_SEC + nsec as u64
}

/// SocketState manages one UDP socket and the buffer that holds the packets that will
/// eventually be written to that socket.
///
/// The client will either directly write data to `self.socket` or use `schedule_send()`.
/// Then, `try_send()` will try to actually write the buffer to the UDP socket. That
/// operation can fail under heavy load with `WouldBlock`, indicating that the OS buffers
/// are filled and that the write operation should be retried later.
pub struct SocketState {
    // Constant, set with new()
    pub socket: mio::net::UdpSocket,
    pacing: bool,
    enable_gso: bool,

    // Changed for each send
    buf: [u8; crate::common::MAX_BUF_SIZE],
    until: usize,
    pub max_datagram_size: usize,

    dest: Option<SocketAddr>,
    tx_times: Vec<Instant>,

    // `true` if more full-sized packets (= `max_datagram_size`) can be queueud on this path.
    // With GSO, only the last packet can be tless than `max_datagram_size`.
    pub extendable: bool,

    pub would_block_cntr: u64,
}

impl SocketState {
    pub fn new(socket: mio::net::UdpSocket, pacing: bool, enable_gso: bool) -> SocketState {
        SocketState {
            socket,
            pacing,
            enable_gso,
            buf: [0; crate::common::MAX_BUF_SIZE],
            until: 0,
            max_datagram_size: 0,
            dest: None,
            tx_times: Vec::with_capacity(MAX_BUF_SIZE / MAX_DATAGRAM_SIZE),
            extendable: true,
            would_block_cntr: 0,
        }
    }

    fn reset(&mut self) {
        self.until = 0;
        self.dest = None;
        self.tx_times.clear();
        self.max_datagram_size = 0;
        self.extendable = true;
    }

    /// Returns whether a buffer is currently waiting to be written to the socket.
    pub fn send_pending(&self) -> bool {
        self.dest.is_some()    
    }

    // Returns whether more packets can be queued on this socket.
    pub fn writable_for_dest(&self, peer_addr: &SocketAddr) -> bool {
        let dest = match self.dest {
            Some(addr) => addr == *peer_addr,
            None => true,
        };
        dest && self.extendable
    }

    // Returns the part of the `self.buf` for the next packet.
    pub fn buf_until(&mut self, max_send_burst: usize) -> Option<&mut [u8]> {
        assert!(self.extendable);
        self.buf.get_mut(self.until..max_send_burst)
    }

    // Advance the buffer after a packet has been written to `buf_until()`.
    // Check if more packets can be queued.
    pub fn buf_advance(&mut self, written: usize, send_info: &quiche::SendInfo) {
        assert!(self.writable_for_dest(&send_info.to));
        self.until += written;
        self.extendable = written == self.max_datagram_size;
        self.dest = Some(send_info.to);
        self.tx_times.push(send_info.at);
    }

    /// Try to send the scheduled buffer, if it exists.
    /// Returns `Ok(0)` if the socket returned `WouldBlock`.
    // TODO: imporve error
    pub fn try_send(&mut self) -> Result<usize, String> {
        let dest = match self.dest {
            Some(v) => v,
            None => return Ok(0),
        };
        let buf = &self.buf[..self.until];

        if self.pacing && self.enable_gso {
            return send_to_gso_pacing(&self.socket, buf, dest, *self.tx_times.first().unwrap(), self.max_datagram_size).map_err(|e| e.to_string());
        }

        let mut off = 0;
        let mut left = buf.len();
        let mut written = 0;

        let mut it = 0;
        while left > 0 {
            let pkt_len = cmp::min(left, self.max_datagram_size);

            let result = if self.pacing {
                let tx_time = self.tx_times.get(it).unwrap();
                sendmsg_pacing(&self.socket, &buf[off..off + pkt_len], dest, *tx_time)
            } else {
                self.socket.send_to(&buf[off..off + pkt_len], dest)
            };

            match result {
                Ok(v) => {
                    written += v;
                    // TODO: save local_addr once?
                    trace!("{:}->{:} written {} bytes", self.socket.local_addr().unwrap(), dest, written);
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        // TODO: not correctly handled, already sent packets will be sent again
                        // TODO: The data of "out" is thrown away, right? Should I handle this?
                        // Is this assertion correct? It isn't, right?
                        trace!("send() would block, will try_send again alter");
                        self.would_block_cntr += 1;
                        return Ok(0);
                    }

                    return Err(format!("send_to() failed: {:?}", e));

                    // return Err(ServerError::FatalSocket(format!(
                    //     "send_to() failed: {:?}",
                    //     e
                    // )));
                }
            }

            off += pkt_len;
            left -= pkt_len;
            it += 1;
        }

        self.reset();

        Ok(written)
    }
}
