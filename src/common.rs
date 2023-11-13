use quiche::PathStatus;
use ring::rand::SecureRandom;
use serde::Deserialize;
use serde::Serialize;
use std::fs::File;
use std::io;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use synchronized_writer::SynchronizedWriter;
use zstd::stream::Encoder;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::protocol::TestConfig;

pub const MAX_BUF_SIZE: usize = 65507;

pub const MAX_DATAGRAM_SIZE: usize = 1350;

pub const QUICHEPERF_ALPN: [&[u8]; 2] = [b"quicheperf", b"quicheperf-00"];

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TestMetadata {
    pub test_config: TestConfig,
    pub cc_algorithm: String,
    pub version: String,
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

    let config = nix::libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    setsockopt(sock.as_raw_fd(), TxTime, &config)?;

    Ok(())
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

    let fd = sock.as_raw_fd();
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

    let fd = sock.as_raw_fd();
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
pub fn get_ip_from_ifname(ifname: &String) -> Option<SocketAddr> {
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
                return Some(SocketAddr::new(IpAddr::V4(ipaddr), 0));
            }
            if let Some(sockaddr) = ifaddrstorage.as_sockaddr_in6() {
                let ipaddr = Ipv6Addr::from(sockaddr.ip().octets());
                return Some(SocketAddr::new(IpAddr::V6(ipaddr), 0));
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
    use std::{ffi::OsString, os::fd::AsRawFd};

    setsockopt(socket.as_raw_fd(), BindToDevice, &OsString::from(ifname))
}

#[cfg(feature = "qlog")]
pub fn set_qlog(
    conn: &mut quiche::Connection,
    scid: String,
    role: &str,
    peer_addr: Option<String>,
) {
    if let Some(dir) = std::env::var_os("QLOGDIR") {
        let local_time = chrono::Local::now();
        let utc_time: chrono::DateTime<chrono::Utc> = chrono::DateTime::from(local_time);

        let mut path = std::path::PathBuf::from(dir);
        let day = utc_time.format("%y%m%dT%H%M%S");
        let filename = format!("{}-{}-{}.sqlog.zst", day, scid, role);
        path.push(filename);

        let writer = match std::fs::File::create(&path) {
            Ok(f) => std::io::BufWriter::new(f),
            Err(e) => panic!(
                "Error creating qlog file attempted path was {:?}: {}",
                path, e
            ),
        };
        println!("Writing qlog to {}", path.display());

        let mut writer = match Encoder::new(writer, 0) {
            Ok(v) => v,
            Err(e) => panic!("Error creating zstd qlog encoder: {}", e),
        };
        writer.multithread(1).unwrap();
        let writer = Encoder::auto_finish(writer);
        let writer = SynchronizedWriter::new(Arc::new(Mutex::new(writer)));

        let peer_addr = match peer_addr {
            Some(s) => format!(" peer_addr={}", s),
            None => "".to_string(),
        };

        conn.set_qlog_with_level(
            std::boxed::Box::new(writer),
            "quicheperf".to_string(),
            format!(
                "quicheperf id={} start_time={}{}",
                scid,
                local_time.to_rfc3339(),
                peer_addr
            ),
            quiche::QlogLevel::Extra,
        );
    }
}

pub fn qlog_metadata(conn: &mut quiche::Connection, tc: &TestConfig, config: &quiche::Config) {
    let metadata = TestMetadata {
        test_config: tc.clone(),
        cc_algorithm: config.get_cc_algorithm_name(),
        version: super::version().into(),
    };
    let metadata_str = serde_json::to_string(&metadata).unwrap();
    conn.add_qlog_event(qlog::events::Event::with_time(
        0.0,
        qlog::events::EventData::Message {
            message: metadata_str,
        },
    ));
    info!("{:?}", metadata);
}

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
