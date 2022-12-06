use ring::rand::SecureRandom;
use serde::Deserialize;
use serde::Serialize;
use std::fs::File;
use std::io;

use std::sync::Arc;
use std::sync::Mutex;
use synchronized_writer::SynchronizedWriter;
use zstd::stream::Encoder;

use crate::protocol::TestConfig;

pub const MAX_BUF_SIZE: usize = 65507;

pub const MAX_DATAGRAM_SIZE: usize = 1350;

pub const QUICPERF_ALPN: [&[u8]; 2] = [b"quicperf", b"quicperf-00"];

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TestMetadata {
    pub test_config: TestConfig,
    pub cc_algorithm: String,
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

#[cfg(feature = "qlog")]
pub fn set_qlog(
    conn: &mut quiche::Connection, scid: String, role: &str,
    peer_addr: Option<String>,
) {
    if let Some(dir) = std::env::var_os("QLOGDIR") {
        let start_time = chrono::Local::now();

        let mut path = std::path::PathBuf::from(dir);
        let filename = format!("{}-{}.sqlog.zstd", scid, role);
        path.push(filename);

        let writer = match std::fs::File::create(&path) {
            Ok(f) => std::io::BufWriter::new(f),
            Err(e) => panic!(
                "Error creating qlog file attempted path was {:?}: {}",
                path, e
            ),
        };

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

        conn.set_qlog(
            std::boxed::Box::new(writer),
            "quicperf".to_string(),
            format!(
                "quicperf id={} start_time={}{}",
                scid,
                start_time.to_rfc3339(),
                peer_addr
            ),
        );
    }
}

pub fn qlog_metadata(
    conn: &mut quiche::Connection, tc: &TestConfig, config: &quiche::Config,
) {
    let metadata = TestMetadata {
        test_config: tc.clone(),
        cc_algorithm: config.get_cc_algorithm_name(),
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

/// Generate a ordered list of 4-tuples on which the host should send packets,
/// following a lowest-latency scheduling.
pub fn lowest_latency_scheduler(
    conn: &quiche::Connection,
) -> impl Iterator<Item = (std::net::SocketAddr, std::net::SocketAddr)> {
    use itertools::Itertools;
    conn.path_stats()
        .sorted_by_key(|p| p.rtt)
        .map(|p| (p.local_addr, p.peer_addr))
}
