use quiche::Connection;
use quiche::PathStatus;
use ring::rand::SecureRandom;
use serde::Deserialize;
use serde::Serialize;
use slab::Slab;
use std::collections::HashMap;
use std::fs::File;
use std::io;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use synchronized_writer::SynchronizedWriter;
use time::format_description::well_known::Iso8601;
use time::macros::format_description;
use time::OffsetDateTime;
use zstd::stream::Encoder;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::common;
use crate::perf::TestConfig;
use crate::sendto;
use crate::sendto::SocketState;

pub const MAX_BUF_SIZE: usize = 65507;

pub const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TestMetadata {
    pub test_config: TestConfig,
    pub cc_algorithm: String,
    pub version: String,
}

pub enum Protocols {
    Perf(crate::perf::Perf),
    // Proxy(crate::proxy::Proxy),
    Proxy(()),
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

#[cfg(feature = "qlog")]
pub struct QlogSetter {
    qlogdir: Option<String>,
    compress_qlogs: bool,
}

impl QlogSetter {
    pub fn new(qlogdir: Option<String>, compress_qlogs: bool) -> Self {
        Self {
            qlogdir,
            compress_qlogs,
        }
    }
    pub fn set_qlog(
        &self,
        conn: &mut quiche::Connection,
        scid: String,
        role: &str,
        peer_addr: Option<String>,
    ) -> Result<(), String> {
        if let Some(qlogdir) = self.qlogdir.as_ref() {
            let now_utc = OffsetDateTime::now_utc();
            let compact_fmt =
                format_description!("[year repr:last_two][month][day]T[hour][minute][second]");
            let time_compact = now_utc.format(&compact_fmt).unwrap();
            let time_iso = now_utc.format(&Iso8601::DEFAULT).unwrap();

            let mut path = std::path::PathBuf::from(qlogdir);
            path.push(format!("{}-{}-{}", time_compact, scid, role));
            if self.compress_qlogs {
                path.set_extension("sqlog.zst");
            } else {
                path.set_extension("sqlog");
            }

            let writer = match std::fs::File::create(&path) {
                Ok(f) => Ok(std::io::BufWriter::new(f)),
                Err(e) => Err(format!(
                    "Error creating qlog file attempted path was {}: {}",
                    path.to_str().unwrap(),
                    e
                )),
            }?;
            info!("Writing qlog to {}", path.display());

            let writer: Box<dyn std::io::Write + Send + Sync> = if self.compress_qlogs {
                let mut writer = match Encoder::new(writer, 0) {
                    Ok(v) => v,
                    Err(e) => panic!("Error creating zstd qlog encoder: {}", e),
                };
                writer.multithread(1).unwrap();
                let writer = Encoder::auto_finish(writer);
                Box::new(SynchronizedWriter::new(Arc::new(Mutex::new(writer))))
            } else {
                Box::new(writer)
            };

            let peer_addr = match peer_addr {
                Some(s) => format!(" peer_addr={}", s),
                None => "".to_string(),
            };

            conn.set_qlog_with_level(
                std::boxed::Box::new(writer),
                "quicheperf".to_string(),
                format!(
                    "quicheperf id={} start_time={}{}",
                    scid, time_iso, peer_addr
                ),
                quiche::QlogLevel::Extra,
            );
        }

        Ok(())
    }
}

// pub fn qlog_metadata(conn: &mut quiche::Connection, tc: &TestConfig, config: &quiche::Config) {
//     let metadata = TestMetadata {
//         test_config: tc.clone(),
//         cc_algorithm: config.get_cc_algorithm_name(),
//         version: super::version().into(),
//     };
//     let metadata_str = serde_json::to_string(&metadata).unwrap();
//     conn.add_qlog_event(qlog::events::Event::with_time(
//         0.0,
//         qlog::events::EventData::Message {
//             message: metadata_str,
//         },
//     ));
//     info!("{:?}", metadata);
// }

/// Generate a new pair of Source Connection ID and reset token.
pub fn generate_cid_and_reset_token<T: SecureRandom>(
    rng: &T,
) -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rng.fill(&mut reset_token).unwrap();
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

pub fn configure_keylog() -> Option<File> {
    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();
        return Some(file);
    }
    None
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

/* /// Generate a ordered list of 4-tuples on which the host should send packets,
/// following a lowest-latency scheduling.
pub fn lowest_latency_scheduler(
    conn: &quiche::Connection,
) -> impl Iterator<Item = (std::net::SocketAddr, std::net::SocketAddr)> {
    use itertools::Itertools;
    conn.path_stats()
        .sorted_by_key(|p| p.rtt)
        .map(|p| (p.local_addr, p.peer_addr))
} */

#[inline]
pub fn duration_as_millis(d: Duration) -> String {
    if d < Duration::MAX {
        d.as_millis().to_string()
    } else {
        "MAX".to_string()
    }
}

pub struct PathStatusUpdater {
    start: Instant,
    local_addrs: Vec<SocketAddr>,
    peer_addrs: Vec<SocketAddr>,
    updates: Vec<(std::time::Duration, usize, PathStatus)>,
}

impl PathStatusUpdater {
    pub fn new(
        start: Instant,
        local_addrs: Vec<SocketAddr>,
        peer_addrs: Vec<SocketAddr>,
        updates: Vec<(std::time::Duration, usize, PathStatus)>,
    ) -> Result<PathStatusUpdater, String> {
        for (_d, pid, _status) in updates.iter() {
            if *pid >= local_addrs.len() {
                return Err(format!("Path with {pid} does not exist"));
            }
        }
        let psu = PathStatusUpdater {
            start,
            local_addrs,
            peer_addrs,
            updates,
        };

        Ok(psu)
    }

    pub fn check(&mut self, conn: &mut quiche::Connection) {
        let elapsed = self.start.elapsed();
        let local_addrs = &self.local_addrs;
        let peer_addrs = &self.peer_addrs;
        self.updates.retain(|(d, pid, status)| {
            if elapsed >= *d {
                let local_addr = local_addrs[*pid];
                let peer_addr = peer_addrs[*pid];
                info!("Advertising path status {status:?} from {local_addr} to {peer_addr}");
                conn.set_path_status(local_addr, peer_addr, *status, true)
                    .is_err()
            } else {
                true
            }
        });
    }
}

pub struct KeepAlive {
    threshold: Duration,
}

impl KeepAlive {
    pub fn new(threshold: Duration) -> Self {
        Self { threshold }
    }

    pub fn timeout(&self, conn: &quiche::Connection) -> Duration {
        match conn.max_idle_duration() {
            Some(d) => self.threshold.saturating_sub(d),
            None => Duration::MAX,
        }
    }

    pub fn check(&self, conn: &mut quiche::Connection) {
        if let Err(e) = conn.probe_idle_paths(self.threshold) {
            error!("Failed to probe idle paths: {}", e)
        }
    }
}

pub fn configure_local_sockets(
    local_addrs: Vec<SocketAddr>,
    pacing: bool,
    enable_gso: bool,
) -> Result<
    (
        Vec<SocketAddr>,
        Slab<SocketState>,
        HashMap<SocketAddr, usize>,
    ),
    String,
> {
    // TODO: replace Slab with Vec
    let mut sockets: Slab<SocketState> = Slab::with_capacity(std::cmp::max(local_addrs.len(), 1));
    let mut src_addr_tokens = HashMap::new();

    // Set SO_TXTIME socket option on the listening UDP socket for pacing
    // outgoing packets.

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
        if enable_gso && !sendto::detect_gso(&socket, MAX_DATAGRAM_SIZE) {
            error!("GSO can not be used with socket {}", src_addr);
        }

        #[cfg(target_os = "linux")]
        {
            // Was client-only
            if let Some(ifname) = common::get_ifname_from_ip(local_addr) {
                if let Err(e) = common::bind_socket_to_if(&socket, &ifname) {
                    error!("{}: unable to bind {}: {}", ifname, local_addr, e);
                } else {
                    trace!("{}: bind {}", ifname, local_addr);
                }
            }

            match common::set_socket_buf_size(&socket, common::UDPBufType::Rcv) {
                Ok(v) => trace!("Set the UDP rcv buf size to {}", v),
                Err(e) => warn!("{}", e),
            };
            match common::set_socket_buf_size(&socket, common::UDPBufType::Snd) {
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

pub fn send_on_sockets(
    conn: &mut Connection,
    max_send_burst: usize,
    max_datagram_size: usize,
    scheduler: &mut Box<dyn quiche::scheduler::MultipathScheduler>,
    src_addr_tokens: &HashMap<SocketAddr, usize>,
    sockets: &mut Slab<SocketState>,
) -> Result<(), String> {
    let mut continue_write = true;
    while continue_write {
        continue_write = false;

        // The maximum amount of data that should be written in one burst with GSO.
        // Explanation division and multiplication: https://github.com/cloudflare/quiche/pull/1213
        // Applies to each socket individually.
        let max_send_burst =
            conn.send_quantum().min(max_send_burst) / max_datagram_size * max_datagram_size;

        let mut it = 0;
        while let Some((local_addr, peer_addr, send_instr)) = scheduler.get_best_path(conn) {
            it += 1;

            let token = src_addr_tokens[&local_addr];
            let socket = &mut sockets[token];

            if !socket.writable_for_dest(&peer_addr) {
                // The socket has already data queued for sending. Only more packets toward the same
                // destination can be queued.
                break;
            }

            // TODO: get send quantum for that specific path

            let buf = match socket.buf_until(max_send_burst) {
                Some(v) => v,
                None => {
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
                        "{}->{} {}, [{}], conn.send returned Done",
                        local_addr,
                        peer_addr,
                        it,
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

            socket.buf_advance(written, &send_info);
            socket.max_datagram_size = max_datagram_size;

            trace!(
                "{:}->{:} conn.send [{}] returned {} bytes, max_datagram_size={}",
                send_info.from,
                send_info.to,
                it,
                written,
                max_datagram_size,
            );

            if !conn.is_established() {
                trace!("Disabled GSO packet assembly during connection establishment");
                continue_write = true;
                break;
            }

            if !socket.extendable {
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
