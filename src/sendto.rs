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
    send_info: &quiche::SendInfo,
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
    let dst = SockaddrStorage::from(send_info.to);
    let sockfd = socket.as_raw_fd();

    // GSO option.
    let cmsg_gso = ControlMessage::UdpGsoSegments(&segment_size);
    let nanos_per_sec: u64 = 1_000_000_000;

    // Pacing option.
    let mut time_spec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    unsafe {
        std::ptr::copy_nonoverlapping(
            &send_info.at as *const _ as *const libc::timespec,
            &mut time_spec,
            1,
        )
    };

    let send_time = time_spec.tv_sec as u64 * nanos_per_sec + time_spec.tv_nsec as u64;

    let cmsg_txtime = ControlMessage::TxTime(&send_time);

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

/// A wrapper function of send_to().
/// - when GSO and SO_TXTIME enabled, send a packet using send_to_gso().
/// Otherwise, send packet using socket.send_to().
pub fn send_to(
    socket: &mio::net::UdpSocket,
    buf: &[u8],
    send_info: &quiche::SendInfo,
    segment_size: usize,
    pacing: bool,
    enable_gso: bool,
) -> io::Result<usize> {
    if pacing && enable_gso {
        return send_to_gso_pacing(socket, buf, send_info, segment_size);
    }

    let mut off = 0;
    let mut left = buf.len();
    let mut written = 0;

    while left > 0 {
        let pkt_len = cmp::min(left, segment_size);

        match socket.send_to(&buf[off..off + pkt_len], send_info.to) {
            Ok(v) => {
                written += v;
            }
            Err(e) => return Err(e),
        }

        off += pkt_len;
        left -= pkt_len;
    }

    Ok(written)
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
    pub send_info: Option<quiche::SendInfo>,
    pub max_datagram_size: usize,

    // `true` if more full-sized packets (= `max_datagram_size`) can be queueud on this path.
    // With GSO, only the last packet can be tless than `max_datagram_size`.
    pub extendable: bool,

    pub would_block_cntr: u64,
}

impl SocketState {
    pub fn new(socket: mio::net::UdpSocket, pacing: bool, enable_gso: bool) -> SocketState {
        SocketState {
            socket: socket,
            pacing,
            enable_gso,
            buf: [0; crate::common::MAX_BUF_SIZE],
            until: 0,
            send_info: None,
            max_datagram_size: 0,
            extendable: true,
            would_block_cntr: 0,
        }
    }

    fn reset(&mut self) {
        self.until = 0;
        self.send_info = None;
        self.max_datagram_size = 0;
        self.extendable = true;
    }

    /// Returns whether a buffer is currently waiting to be written to the socket.
    pub fn send_pending(&self) -> bool {
        self.send_info.is_some()
    }

    // Returns whether more packets can be queued on this socket.
    pub fn writable_for_dest(&self, peer_addr: &SocketAddr) -> bool {
        let dest = match self.send_info {
            Some(si) => si.to == *peer_addr,
            None => true,
        };
        dest && self.extendable
    }

    // Returns the part of the `self.buf` for the next packet.
    pub fn buf_until(&mut self, max_send_burst: usize) -> Option<&mut [u8]> {
        // TODO: check self.extendable?
        self.buf.get_mut(self.until..max_send_burst)
        // &mut self.buf[self.until..max_send_burst]
    }

    // Advance the buffer after a packet has been written to `buf_until()`.
    // Check if more packets can be queued.
    pub fn buf_advance(&mut self, written: usize) {
        self.until += written;
        self.extendable = written == self.max_datagram_size;
    }

    /// Try to send the scheduled buffer, if it exists.
    /// Returns `Ok(0)` if the socket returned `WouldBlock`.
    // TODO: imporve error
    pub fn try_send(&mut self) -> Result<usize, String> {
        let send_info = match self.send_info {
            Some(v) => v,
            None => return Ok(0),
        };
        match send_to(
            &self.socket,
            &self.buf[..self.until],
            &send_info,
            self.max_datagram_size,
            self.pacing,
            self.enable_gso,
        ) {
            Ok(n) => {
                let to = self.send_info.unwrap();
                trace!("{:}->{:} written {} bytes", to.from, to.to, self.until);
                self.reset();
                Ok(n)
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
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
    }
}
