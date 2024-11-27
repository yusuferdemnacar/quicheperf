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

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use quiche::Connection;
use slab::Slab;

use crate::common::MAX_BUF_SIZE;
use crate::common::MAX_DATAGRAM_SIZE;

#[cfg(target_os = "linux")]
pub fn get_ifname_from_ip(addr: std::net::SocketAddr) -> Option<String> {
    let ifaddrs_iter = match nix::ifaddrs::getifaddrs() {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to getifaddrs: {}", e);
            return None;
        }
    };

    for ifaddr in ifaddrs_iter {
        if let Some(ifaddrstorage) = ifaddr.address {
            match addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    let ifaddr_ip = match ifaddrstorage.as_sockaddr_in() {
                        Some(v) => v,
                        None => continue,
                    };
                    if ifaddr_ip.ip().to_be_bytes() == ip.octets() {
                        return Some(ifaddr.interface_name);
                    }
                }
                std::net::IpAddr::V6(ip) => {
                    let ifaddr_ip = match ifaddrstorage.as_sockaddr_in6() {
                        Some(v) => v,
                        None => continue,
                    };
                    if ifaddr_ip.ip().octets() == ip.octets() {
                        return Some(ifaddr.interface_name);
                    }
                }
            };
        }
    }

    None
}

#[cfg(target_os = "linux")]
pub fn get_ip_from_ifname(ifname: String, port: u16) -> Option<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let ifaddrs_iter = match nix::ifaddrs::getifaddrs() {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to getifaddrs: {}", e);
            return None;
        }
    };

    for ifaddr in ifaddrs_iter {
        if ifaddr.interface_name != *ifname {
            continue;
        }

        if let Some(ifaddrstorage) = ifaddr.address {
            if let Some(sockaddr) = ifaddrstorage.as_sockaddr_in() {
                let ipaddr = Ipv4Addr::from(sockaddr.ip().to_be_bytes());
                return Some(SocketAddr::new(IpAddr::V4(ipaddr), port));
            }
            if let Some(sockaddr) = ifaddrstorage.as_sockaddr_in6() {
                let ipaddr = Ipv6Addr::from(sockaddr.ip().octets());
                return Some(SocketAddr::new(IpAddr::V6(ipaddr), port));
            }
        }
    }

    None
}

/// Set SO_TXTIME socket option.
///
/// This socket option is set to send to kernel the outgoing UDP
/// packet transmission time in the sendmsg syscall.
///
/// Note that this socket option is set only on linux platforms.
#[cfg(target_os = "linux")]
pub fn set_txtime_sockopt(sock: &mio::net::UdpSocket) -> io::Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::TxTime;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::io::BorrowedFd;

    let config = nix::libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    let fd = &unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) };
    setsockopt(fd, TxTime, &config)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_txtime_sockopt(_: &mio::net::UdpSocket) -> io::Result<()> {
    use std::io::Error;
    use std::io::ErrorKind;

    Err(Error::new(
        ErrorKind::Other,
        "Not supported on this platform",
    ))
}

const DESIRED_RCV_BUF_SIZE: usize = 10_000_000;
const DESIRED_SND_BUF_SIZE: usize = 10_000_000;

#[derive(Debug, Clone, Copy)]
pub enum UDPBufType {
    Rcv,
    Snd,
}

#[cfg(target_os = "linux")]
fn get_buffer_size(
    sock: &mio::net::UdpSocket,
    buf_type: UDPBufType,
) -> Result<usize, nix::errno::Errno> {
    use nix::sys::socket::sockopt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::io::BorrowedFd;

    let fd = &unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) };
    let doubled_size = match buf_type {
        UDPBufType::Rcv => nix::sys::socket::getsockopt(fd, sockopt::RcvBuf),
        UDPBufType::Snd => nix::sys::socket::getsockopt(fd, sockopt::SndBuf),
    };

    // https://stackoverflow.com/questions/21146955/getsockopt-so-recvbuf-after-doing-a-set-shows-double-the-value-in-linux
    doubled_size.map(|v| v / 2)
}

#[cfg(target_os = "linux")]
fn set_buffer_size(
    sock: &mio::net::UdpSocket,
    buf_type: UDPBufType,
    size: usize,
) -> Result<(), nix::errno::Errno> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::io::BorrowedFd;

    let fd = &unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) };
    match buf_type {
        UDPBufType::Rcv => setsockopt(fd, sockopt::RcvBuf, &size),
        UDPBufType::Snd => setsockopt(fd, sockopt::SndBuf, &size),
    }
}

#[cfg(target_os = "linux")]
pub fn set_socket_buf_size(
    sock: &mio::net::UdpSocket,
    buf_type: UDPBufType,
) -> Result<usize, String> {
    let prev = get_buffer_size(sock, buf_type)
        .map_err(|e| format!("Could not read {:?} buffer size: {}", buf_type, e).to_owned())?;
    let desired_size = match buf_type {
        UDPBufType::Rcv => DESIRED_RCV_BUF_SIZE,
        UDPBufType::Snd => DESIRED_SND_BUF_SIZE,
    };
    set_buffer_size(sock, buf_type, desired_size).ok();
    let now = get_buffer_size(sock, buf_type)
        .map_err(|e| format!("Could not read {:?} buffer size: {}", buf_type, e).to_owned())?;

    if now != desired_size {
        Err(format!(
            "Could not set the {:?} buf size to {}. It changed from {} to {}",
            buf_type, desired_size, prev, now
        ))
    } else {
        Ok(now)
    }
}

/// Convert peer address to IPv6 if necessary. It is necessary to match the address
/// returned from a socket that listens for IPv4 and IPv6 addresses.
pub fn match_local_peer_ip_version(
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<(SocketAddr, SocketAddr), String> {
    let local_v4 = local.is_ipv4();
    let peer_v4 = peer.is_ipv4();
    match (local_v4, peer_v4) {
        (true, true) => Ok((local, peer)),
        (false, false) => Ok((local, peer)),
        (true, false) => Err("Local IP is v4, remote is v6".into()),
        (false, true) => {
            let ipv6_mapped = match peer {
                SocketAddr::V4(v) => v.ip().to_ipv6_mapped(),
                SocketAddr::V6(_) => unreachable!(),
            };
            let p = SocketAddr::new(ipv6_mapped.into(), peer.port());
            Ok((local, p))
        }
    }
}

#[cfg(target_os = "linux")]
pub fn bind_socket_to_if(
    socket: &mio::net::UdpSocket,
    ifname: &String,
) -> Result<(), nix::errno::Errno> {
    use nix::sys::socket::{setsockopt, sockopt::BindToDevice};
    use std::{ffi::OsString, os::fd::AsRawFd, os::fd::BorrowedFd};

    let fd = &unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
    setsockopt(fd, BindToDevice, &OsString::from(ifname))
}

/// For Linux, try to detect GSO is available.
#[cfg(target_os = "linux")]
pub fn detect_gso(socket: &mio::net::UdpSocket, segment_size: usize) -> bool {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::UdpGsoSegment;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::io::BorrowedFd;

    let fd = &unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
    let availability = setsockopt(fd, UdpGsoSegment, &(segment_size as i32)).is_ok();
    // Reverse setsockopt to be able to choose if GSO should be used on each send call
    match setsockopt(fd, UdpGsoSegment, &0) {
        Ok(_) => {}
        Err(e) => error!("reversing sockopt UdpGsoSegment failed: {e}"),
    };
    availability
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

    // Pacing option.
    let send_time = std_time_to_u64(&tx_time);
    let cmsg_txtime = ControlMessage::TxTime(&send_time);

    trace!("Pace packet (with gso) to {dest} at {until_a:?} / {until_b:?} / {send_time}");

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
fn sendmsg_with_pacing(
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

    // Pacing option.
    let send_time = std_time_to_u64(&tx_time);
    let cmsg_txtime = ControlMessage::TxTime(&send_time);

    trace!("Pace packet (no gso) to {dest} at {until_a:?} / {until_b:?} / {send_time}");

    match sendmsg(sockfd, &iov, &[cmsg_txtime], MsgFlags::empty(), Some(&dst)) {
        Ok(v) => Ok(v),
        Err(e) => Err(e.into()),
    }
}

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
    local_addr: SocketAddr,
    pacing: bool,
    enable_gso: bool,

    // Changed for each send
    buf: [u8; crate::common::MAX_BUF_SIZE],
    until: usize,
    max_datagram_size: usize,

    dest: Option<SocketAddr>,
    tx_times: Vec<Instant>,

    // `true` if more full-sized packets (= `max_datagram_size`) can be queueud on this path.
    // With GSO, only the last packet can be tless than `max_datagram_size`.
    extendable: bool,

    pub would_block_cntr: u64,
}

impl SocketState {
    pub fn new(socket: mio::net::UdpSocket, pacing: bool, enable_gso: bool) -> SocketState {
        let local_addr = socket.local_addr().unwrap();
        SocketState {
            socket,
            local_addr,
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

    pub fn is_extendable(&self) -> bool {
        self.extendable
    }

    pub fn gso_enabled(&self) -> bool {
        self.enable_gso
    }

    /// Returns whether a buffer is currently waiting to be written to the socket.
    pub fn send_pending(&self) -> bool {
        self.dest.is_some()
    }

    // Returns whether more packets can be queued on this socket.
    pub fn writable_for_dest(&self, peer_addr: &SocketAddr, max_datagram_size: usize) -> bool {
        let dest = match self.dest {
            Some(addr) => addr == *peer_addr,
            None => true,
        };
        let size_match = self.max_datagram_size == 0 || self.max_datagram_size == max_datagram_size;
        dest && self.extendable && size_match
    }

    // Returns the part of the `self.buf` for the next packet.
    pub fn buf_until(&mut self, max_send_burst: usize) -> Option<&mut [u8]> {
        assert!(self.extendable);
        self.buf.get_mut(self.until..max_send_burst)
    }

    // Advance the buffer after a packet has been written to `buf_until()`.
    // Check if more packets can be queued.
    pub fn buf_advance(
        &mut self,
        written: usize,
        send_info: &quiche::SendInfo,
        max_datagram_size: usize,
    ) {
        assert!(self.writable_for_dest(&send_info.to, max_datagram_size));
        self.max_datagram_size = max_datagram_size;
        self.until += written;
        self.dest = Some(send_info.to);
        self.tx_times.push(send_info.at);
        self.extendable = written == self.max_datagram_size;
    }

    /// Try to send the scheduled buffer, if it exists.
    /// Returns `Ok(0)` if the socket returned `WouldBlock`.
    // TODO: improve error
    pub fn try_send(&mut self) -> Result<usize, String> {
        let dest = match self.dest {
            Some(v) => v,
            None => return Ok(0),
        };
        let buf = &self.buf[..self.until];

        let written = if self.pacing && self.enable_gso {
            match send_to_gso_pacing(
                &self.socket,
                buf,
                dest,
                *self.tx_times.first().unwrap(),
                self.max_datagram_size,
            ) {
                Ok(written) => {
                    trace!(
                        "{}->{dest} GSO+pacing written {written} bytes",
                        self.local_addr
                    );
                    Ok(written)
                }
                Err(e) => {
                    warn!("send_to_gso_pacing failed, trying again without: {:?}", e);
                    self.enable_gso = false;
                    self.try_send()
                }
            }
        } else {
            match self.send_individually(buf, dest) {
                Ok(v) => Ok(v),
                Err(e) => {
                    if self.pacing {
                        warn!("sendmsg with pacing failed, trying again without: {:?}", e);
                        self.pacing = false;
                        self.try_send()
                    } else {
                        Err(format!(
                            "send_individually failed from {:?} to {}: {:?}",
                            self.socket.local_addr(),
                            dest,
                            e
                        ))
                    }
                }
            }
        }?;

        self.reset();

        Ok(written)
    }

    fn send_individually(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        let mut off = 0;
        let mut left = buf.len();
        let mut written = 0;

        let mut it = 0;
        while left > 0 {
            let pkt_len = cmp::min(left, self.max_datagram_size);

            let result = if self.pacing {
                let tx_time = self.tx_times.get(it).unwrap();
                sendmsg_with_pacing(&self.socket, &buf[off..off + pkt_len], dest, *tx_time)
            } else {
                self.socket.send_to(&buf[off..off + pkt_len], dest)
            };

            match result {
                Ok(v) => {
                    written += v;
                    trace!("{:}->{:} written {} bytes", self.local_addr, dest, written);
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        // TODO: not correctly handled, already sent packets will be sent again
                        // TODO: The data of "out" is thrown away, right? Should I handle this?
                        // Is this assertion correct? It isn't, right?
                        // trace!("send() would block, will try_send again alter");
                        // self.would_block_cntr += 1;
                        return Ok(0);
                    }

                    return Err(e);

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

        Ok(written)
    }
}

pub fn configure_local_sockets(
    local_addrs: Vec<SocketAddr>,
    pacing: bool,
    enable_gso: bool,
    bind_to_intf: bool,
) -> Result<
    (
        Vec<SocketAddr>,
        Slab<SocketState>,
        HashMap<SocketAddr, usize>,
    ),
    String,
> {
    let mut sockets: Slab<SocketState> = Slab::with_capacity(std::cmp::max(local_addrs.len(), 1));
    let mut src_addr_tokens = HashMap::new();

    let mut addrs = Vec::new();
    for src_addr in local_addrs {
        let socket = match mio::net::UdpSocket::bind(src_addr) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("Failed binding UDP socket to {}: {}", src_addr, e));
                // return Err(ServerError::FatalSocket(format!(
                //     "failed binding UDP socket to {}: {}",
                //     src_addr, e
                // )))
            }
        };
        let local_addr = socket.local_addr().unwrap();

        if let Err(e) = set_txtime_sockopt(&socket) {
            error!("set SO_TXTIME socket option failed {:?}", e);
        }
        if enable_gso && !detect_gso(&socket, MAX_DATAGRAM_SIZE) {
            error!("GSO can not be used with socket {}", src_addr);
        }

        #[cfg(target_os = "linux")]
        {
            if bind_to_intf {
                if let Some(ifname) = get_ifname_from_ip(local_addr) {
                    if let Err(e) = bind_socket_to_if(&socket, &ifname) {
                        error!("{}: unable to bind {}: {}", ifname, local_addr, e);
                    } else {
                        trace!("{}: bind {}", ifname, local_addr);
                    }
                }
            } else {
                trace!("Not binding to interface");
            }

            match set_socket_buf_size(&socket, UDPBufType::Rcv) {
                Ok(v) => trace!("Set the UDP rcv buf size to {}", v),
                Err(e) => warn!("{}", e),
            };
            match set_socket_buf_size(&socket, UDPBufType::Snd) {
                Ok(v) => trace!("Set the UDP snd buf size to {}", v),
                Err(e) => warn!("{}", e),
            };
        }

        let socket_state = SocketState::new(socket, pacing, enable_gso);
        let token = sockets.insert(socket_state);
        src_addr_tokens.insert(local_addr, token);
        addrs.push(local_addr);

        info!(
            "Listening on {:}, GSO {}",
            local_addr,
            if enable_gso { "enabled" } else { "disabled" }
        );

        // Disabled notifications on WRITABLE to stop poll.poll being waken up unnecessarily.
        // This will lead to problems under heavy load, more specifically if writing to the UDP
        // socket in `SocketState` returns WouldBlock. In these cases, the application should retry
        // writing to that socket as soon as it's writable again.
        // TODO: find a good solution to this problem
        // poll.registry()
        //     .register(
        //         &mut sockets[token].socket,
        //         mio::Token(token),
        //         mio::Interest::READABLE, // .add(mio::Interest::WRITABLE),
        //     )
        //     .expect("Failed registering socket with mio");
    }

    Ok((addrs, sockets, src_addr_tokens))
}

pub fn send(
    conn: &mut Connection,
    src_addr_tokens: &HashMap<SocketAddr, usize>,
    sockets: &mut Slab<SocketState>,
) -> Result<(), String> {
    loop {
        let mut out = [0; MAX_DATAGRAM_SIZE];

        let (written, send_info) = match conn.send(&mut out) {
            Ok(v) => v,

            Err(quiche::Error::Done) => {
                trace!(
                    "[{}], simple send: conn.send returned Done",
                    conn.trace_id()
                );
                break;
            }

            Err(e) => {
                error!(
                    "{}: simple send: conn.send failed: {:?}",
                    conn.trace_id(),
                    e
                );
                conn.close(false, 0x1, b"fail").ok();
                // Not sure what's correct in this situation.
                break;
            }
        };

        let token = src_addr_tokens[&send_info.from];
        let socket = &mut sockets[token];

        match socket.socket.send_to(&out[..written], send_info.to) {
            Ok(sent) => trace!(
                "{:}->{:} simple send: conn.send returned {written} bytes, sent {sent} bytes",
                send_info.from,
                send_info.to
            ),
            Err(e) => return Err(format!("simple send: send_to failed: {}", e)),
        }
    }

    Ok(())
}

pub fn send_multipath(
    conn: &mut Connection,
    max_send_burst: usize,
    max_datagram_size: usize,
    src_addr_tokens: &HashMap<SocketAddr, usize>,
    sockets: &mut Slab<SocketState>,
) -> Result<(), String> {
    if conn.scheduler.is_packet_algo() {
        send_packet_scheduler(
            conn,
            max_send_burst,
            max_datagram_size,
            src_addr_tokens,
            sockets,
        )
    } else if conn.scheduler.is_frame_algo() {
        send_frame_scheduler(
            conn,
            max_send_burst,
            max_datagram_size,
            src_addr_tokens,
            sockets,
        )
    } else {
        panic!("Invalid state")
    }
}

fn send_packet_scheduler(
    conn: &mut Connection,
    max_send_burst: usize,
    max_datagram_size: usize,
    src_addr_tokens: &HashMap<SocketAddr, usize>,
    sockets: &mut Slab<SocketState>,
) -> Result<(), String> {
    let mut continue_write = true;
    while continue_write {
        continue_write = false;

        let mut it = 0;
        while let Some((local_addr, peer_addr, send_instr)) = conn.get_best_path() {
            it += 1;

            let token = src_addr_tokens[&local_addr];
            let socket = &mut sockets[token];

            if !socket.writable_for_dest(&peer_addr, max_datagram_size) {
                // The socket has already data queued for sending. Only more packets toward the same
                // destination can be queued.
                break;
            }

            // The maximum amount of data that should be written in one burst with GSO.
            // Explanation division and multiplication: https://github.com/cloudflare/quiche/pull/1213
            // Applies to each socket individually.
            let max_send_burst = conn
                .send_quantum_on_path(local_addr, peer_addr)
                .min(max_send_burst)
                / max_datagram_size
                * max_datagram_size;

            let buf = match socket.buf_until(max_send_burst) {
                Some(v) if v.len() > 0 => v,
                _ => {
                    // None or if buffer len is 0
                    // We already wrote data up to `max_send_burst`. Send queued packets now but
                    // continue to ask conn for more packets immediately afterwards before receiving
                    // new packets.
                    continue_write = true;
                    break;
                }
            };

            let (written, send_info) = match conn.send_on_path_with_instructions(
                buf,
                Some(local_addr),
                Some(peer_addr),
                Some(send_instr),
            ) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    trace!(
                        "{local_addr}->{peer_addr} [{it}], [{}], conn.send returned Done",
                        conn.trace_id()
                    );
                    break;
                }

                Err(e) => {
                    error!("{} conn.send failed: {:?}", conn.trace_id(), e);
                    conn.close(false, 0x1, b"fail").ok();
                    // Not sure what's correct in this situation.
                    break;
                }
            };

            socket.buf_advance(written, &send_info, max_datagram_size);

            trace!(
                "{:}->{:} conn.send [{it}] returned {written} bytes, max_datagram_size={max_datagram_size}",
                send_info.from,
                send_info.to,
            );

            if !conn.is_established() && socket.gso_enabled() {
                trace!("Disabled GSO packet assembly during connection establishment");
                continue_write = true;
                break;
            }

            if !socket.is_extendable() {
                // https://github.com/cloudflare/quiche/commit/eac98fae15ce67ee774125c90db0d59c4deda5da
                // The QUIC connection might has more data to write.
                continue_write = true;

                // No full-sized packet has been written; only the last packet can be less than
                // max_datagram_size if we want to use GSO.
                break;
            }
        }

        // Try to send the queued data
        for (_, token) in src_addr_tokens.iter() {
            let socket = &mut sockets[*token];
            if let Err(e) = socket.try_send() {
                return Err(format!("socket.try_send failed: {:?}", e));
                // return Err(ServerError::FatalSocket(format!(
                //     "socket.try_send failed: {:?}",
                //     e
                // )));
            }
        }
    }
    Ok(())
}

/// Schedules Data and Frames, generates outgoing QUIC packets and sends them on the UDP socket
fn send_frame_scheduler(
    conn: &mut Connection,
    max_send_burst: usize,
    max_datagram_size: usize,
    src_addr_tokens: &HashMap<SocketAddr, usize>,
    sockets: &mut Slab<SocketState>,
) -> Result<(), String> {
    let now = Instant::now();
    // call the scheduler to schedule data and frames
    let _ = conn
        .derive_scheduling_decision()
        .map_err(|e| warn!("Scheduling failed: {e}"));

    // iterate over paths in RR fashion until none have packets to send
    //let mut paths = self.local_addrs.iter().map(| s | self.conn.paths_iter(*s).map(|r| (*s,r)).collect::<VecDeque<(SocketAddr, SocketAddr)>>()).flatten().collect::<VecDeque<(SocketAddr, SocketAddr)>>();
    let mut paths = conn.get_all_usable_paths();
    while let Some((pid, local_addr, recv_addr)) = paths.pop_front() {
        let socket = {
            let token = src_addr_tokens[&local_addr];
            &mut sockets[token]
        };

        if socket.send_pending() {
            // The scheduler will probably return this same path over and over again. Break
            // to exit (potential) infinite loop. In most cases, socket.try_send() would
            // block now. We wait for a writable event.
            trace!(
                "outgoing packet on socket {} pending, try sending it",
                local_addr
            );
            if let Err(e) = socket.try_send() {
                return Err(format!("socket.try_send failed: {:?}", e));
            }
            if socket.send_pending() {
                continue;
            }
        }

        let buf = match socket.buf_until(max_send_burst) {
            Some(v) if v.len() > 0 => v,
            _ => {
                // Since we don't do GSO, this should not happen
                warn!("Couldn't get buf_until");
                break;
            }
        };

        //TODO: set has_initial
        let (ptype, written, send_info) = match conn.get_packet_for_path(buf, pid, false, now) {
            Ok(v) => v,
            Err(quiche::Error::Done) => {
                trace!("get_packet_for_path({pid}) -> Done");
                continue;
            }
            Err(e) => return Err(format!("Failed to get packet for path with error {e:?}")),
        };

        socket.buf_advance(written, &send_info, max_datagram_size);
        trace!(
            "{:}->{:} get_packet_for_path({pid}) -> {written} B, type={ptype:?}, max_dgram_size={max_datagram_size} B",
            send_info.from,
            send_info.to,
        );

        if let Err(e) = socket.try_send() {
            return Err(format!("socket.try_send failed: {:?}", e));
        }

        //append path back to end of queue
        paths.push_back((pid, local_addr, recv_addr));

        // decisions[pid] += 1;
    }

    Ok(())
}
