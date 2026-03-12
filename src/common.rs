use quiche::PathStatus;
use ring::rand::SecureRandom;
use std::fs::File;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use synchronized_writer::SynchronizedWriter;
use time::format_description::well_known::Iso8601;
use time::macros::format_description;
use time::OffsetDateTime;
use zstd::stream::Encoder;

use std::net::SocketAddr;

pub const MAX_BUF_SIZE: usize = 65507;

pub const MAX_DATAGRAM_SIZE: usize = 1350;

// #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
// pub struct TestMetadata {
//     pub test_config: TestConfig,
//     pub cc_algorithm: String,
//     pub version: String,
// }

#[allow(clippy::large_enum_variant)]
pub enum Protocols {
    Perf(crate::perf::Perf),
    // Proxy(crate::proxy::Proxy),
    Proxy(()),
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
