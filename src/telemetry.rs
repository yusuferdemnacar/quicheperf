//! Receiver for the RIC radio telemetry feed, and the CLI surface that turns it on.
//!
//! The `kpm-telemetry-xapp` sends one UDP datagram per E2SM-KPM indication. Each datagram is a
//! complete, self-contained picture of the 5G radio and supersedes the one before it, so this
//! module keeps exactly one sample: the newest. There is no queue and no history, because a
//! scheduler asking "what does the radio look like now" is never served by a stale answer.
//!
//! Nothing here reads from the QUIC connection or writes to it. The receive thread owns a socket
//! and a mutex, and that is the whole of its contact with the rest of quicheperf. Wiring the
//! stored sample into an actual scheduling decision is deliberately a separate step from proving
//! the feed arrives.
//!
//! Loss and staleness are detected from `seq` and the local arrival time rather than from the
//! transport, which is what makes an unreliable transport the right choice here. A gap in `seq`
//! is counted and otherwise ignored: the missing sample is already superseded by the one that
//! exposed the gap. Staleness is the property that matters, and `latest_fresh` is the accessor a
//! scheduler should use, so that a dead feed degrades into transport-only scheduling instead of
//! steering traffic on a picture of the radio from minutes ago.
//!
//! The CLI flags and `maybe_spawn` below are declared in this file rather than in `cli.rs`/
//! `main.rs`, so the feature's entire footprint on upstream is one `mod telemetry;`, one
//! `#[command(flatten)]` field, and the call to `maybe_spawn` at the one call site that needs it.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;
use log::{error, info, warn};
use serde::Deserialize;

const TELEMETRY_HEADING: &str = "Telemetry Options";

/// Global CLI flags for the RIC telemetry receiver, flattened into `cli::Args`.
#[derive(Args, Debug, Clone)]
pub struct TelemetryArgs {
    /// Listen for RIC radio telemetry on this UDP address. Absent leaves the receiver off.
    #[arg(long = "telemetry-listen", global = true, value_parser = resolve_addr, help_heading = TELEMETRY_HEADING)]
    pub listen: Option<SocketAddr>,

    /// Log every Nth telemetry sample. 0 silences per-sample logging.
    #[arg(long = "telemetry-log-every", global = true, default_value = "10", help_heading = TELEMETRY_HEADING)]
    pub log_every: u64,
}

/// Duplicated from `cli::resolve_addr` rather than made `pub(crate)` there, so this module's only
/// contact with `cli.rs` is the single `#[command(flatten)]` field: nothing here reaches back into
/// upstream's internals.
fn resolve_addr(s: &str) -> Result<SocketAddr, String> {
    match s.to_socket_addrs() {
        Ok(mut it) => it.next().ok_or(format!("failed to resolve {}", s)),
        Err(e) => Err(format!("failed to resolve {}: {}", s, e)),
    }
}

/// The wire schema version this build understands. A sample announcing anything else is dropped
/// rather than parsed leniently, because a scheduler acting on misread radio values is worse than
/// one acting on none.
pub const SCHEMA_VERSION: u32 = 1;

/// Bounds how long the thread can take to notice `terminate`.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

/// A full sample of all eighteen DU metrics as JSON is well under 1 kB. This leaves generous room
/// and still refuses anything absurd.
const MAX_DATAGRAM: usize = 8192;

/// The normalized radio sample, in the units the xApp publishes: milliseconds, kbit/s, kbit, and
/// plain counts.
///
/// Every field is `f64` even where the metric is a count. The KPM provider chooses `set_integer`
/// or `set_real` per metric and the choice is not consistent between them, so a narrower type
/// would fail the whole sample over one field's encoding.
///
/// Every field is `Option`. `None` means either that the metric was not subscribed to or that the
/// gNB had no measurement for it. Both cases must stay distinct from a real zero: a CQI of 0 or a
/// PUSCH SNR of 0 is the provider's way of saying "no report", and the xApp already turns those
/// into null so they never arrive here looking like a terrible radio.
///
/// Most fields are unread until a scheduler consumes them, which is the next task. They are
/// declared now because the set of metrics is the interface being agreed with the xApp, and
/// decoding a field is what proves it survived the trip.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Radio {
    #[serde(default)]
    pub cqi: Option<f64>,
    /// Uplink PUSCH SNR at the gNB receiver. The provider exposes this same value under both
    /// `RSRP` and `RSRQ`; the xApp collapses them, so there is one field here and it is uplink.
    #[serde(default)]
    pub ul_snr_db: Option<f64>,
    #[serde(default)]
    pub dl_thp_kbps: Option<f64>,
    #[serde(default)]
    pub ul_thp_kbps: Option<f64>,
    #[serde(default)]
    pub prb_used_dl: Option<f64>,
    #[serde(default)]
    pub prb_used_ul: Option<f64>,
    #[serde(default)]
    pub prb_avail_dl: Option<f64>,
    #[serde(default)]
    pub prb_avail_ul: Option<f64>,
    #[serde(default)]
    pub prb_util_dl_pct: Option<f64>,
    #[serde(default)]
    pub prb_util_ul_pct: Option<f64>,
    #[serde(default)]
    pub dl_rlc_delay_ms: Option<f64>,
    #[serde(default)]
    pub ul_rlc_delay_ms: Option<f64>,
    #[serde(default)]
    pub ul_air_delay_ms: Option<f64>,
    /// An integer percentage. The provider truncates a ratio into whole percent, so anything
    /// below one percent arrives as 0 and cannot be told apart from no loss.
    #[serde(default)]
    pub dl_drop_rate_pct: Option<f64>,
    #[serde(default)]
    pub dl_volume_kbit: Option<f64>,
    #[serde(default)]
    pub ul_volume_kbit: Option<f64>,
    #[serde(default)]
    pub rach_preambles: Option<f64>,
}

/// Unread fields are the agreed envelope, not leftovers: they carry the identity and provenance a
/// scheduler needs once it correlates a sample to a path.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Sample {
    pub v: u32,
    pub seq: u64,
    /// The xApp's clock, not the gNB's. ross runs roughly fourteen minutes skewed from the rest
    /// of the testbed, so a gNB-side timestamp would make freshness arithmetic nonsense. This is
    /// carried for logging and correlation only; `Received::at` is what staleness is computed
    /// from, because a local monotonic clock cannot be skewed or stepped.
    pub sent_unix_ns: u64,
    #[serde(default)]
    pub e2_node: Option<String>,
    /// Null while the xApp subscribes with Report Style 1, which reports cell-level or index-0
    /// values and identifies no UE. Binding a sample to a specific UE, and from there to a QUIC
    /// flow, is unsolved and out of scope for the feed itself.
    #[serde(default)]
    pub ue: Option<String>,
    #[serde(default)]
    pub period_ms: u64,
    #[serde(default)]
    pub radio: Radio,
}

#[derive(Debug, Clone)]
pub struct Received {
    pub sample: Sample,
    /// Monotonic arrival time, the basis for every staleness decision.
    pub at: Instant,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub received: u64,
    /// Samples the sender emitted that never arrived, counted from gaps in `seq`.
    pub lost: u64,
    /// Datagrams that did not decode, or announced an unknown schema version.
    pub malformed: u64,
}

struct Inner {
    latest: Option<Received>,
    stats: Stats,
}

/// The single slot the receive thread writes and the scheduler reads.
///
/// A mutex rather than a lock-free cell: contention is one write per report period against
/// however often a scheduler looks, which is nothing, and the naive thing that is obviously
/// correct is worth more here than the clever thing.
pub struct TelemetryStore {
    inner: Mutex<Inner>,
}

impl TelemetryStore {
    fn new() -> Self {
        TelemetryStore {
            inner: Mutex::new(Inner {
                latest: None,
                stats: Stats::default(),
            }),
        }
    }

    /// A poisoned mutex must not take the data plane down with it. The telemetry feed is an
    /// optimization; the proxy has to keep forwarding without it.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn store(&self, sample: Sample) {
        let mut inner = self.lock();
        if let Some(previous) = &inner.latest {
            // Sequence numbers restart when the xApp restarts, so only a forward gap counts.
            if sample.seq > previous.sample.seq + 1 {
                inner.stats.lost += sample.seq - previous.sample.seq - 1;
            }
        }
        inner.stats.received += 1;
        inner.latest = Some(Received {
            sample,
            at: Instant::now(),
        });
    }

    fn count_malformed(&self) {
        self.lock().stats.malformed += 1;
    }

    /// The newest sample regardless of age. Prefer `latest_fresh` for anything that steers
    /// traffic.
    #[allow(dead_code)]
    pub fn latest(&self) -> Option<Received> {
        self.lock().latest.clone()
    }

    /// The newest sample if it is recent enough to act on, otherwise `None`.
    ///
    /// This is the accessor the cross-layer scheduler should call. Returning `None` when the feed
    /// has gone quiet is the whole safety property: the scheduler falls back to its transport-only
    /// decision rather than steering on a picture of the radio that has stopped being true.
    #[allow(dead_code)]
    pub fn latest_fresh(&self, max_age: Duration) -> Option<Sample> {
        let inner = self.lock();
        let received = inner.latest.as_ref()?;
        if received.at.elapsed() <= max_age {
            Some(received.sample.clone())
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn stats(&self) -> Stats {
        self.lock().stats
    }
}

fn show(value: Option<f64>) -> String {
    match value {
        Some(v) => format!("{:.1}", v),
        None => "-".to_string(),
    }
}

/// Starts the receiver if the CLI enabled it.
///
/// `Ok(None)` means the flag was absent, which is stock quicheperf behaviour: the receiver never
/// starts and the caller has nothing to hold onto. An error means the bind failed, which the
/// caller should treat as a fatal startup failure — a run configured to steer on radio telemetry
/// should not silently proceed without it.
pub fn maybe_spawn(
    args: &TelemetryArgs,
    terminate: Arc<AtomicBool>,
) -> std::io::Result<Option<Arc<TelemetryStore>>> {
    match args.listen {
        Some(listen) => spawn(listen, args.log_every, terminate).map(Some),
        None => Ok(None),
    }
}

/// Bind the telemetry socket and start the receive thread.
///
/// Returns the store the scheduler reads from. The thread holds its own reference, so it keeps
/// running whether or not the caller retains the handle, and exits when `terminate` is set.
fn spawn(
    listen: SocketAddr,
    log_every: u64,
    terminate: Arc<AtomicBool>,
) -> std::io::Result<Arc<TelemetryStore>> {
    let socket = UdpSocket::bind(listen)?;
    // Without a read timeout the thread would block in recv_from forever and never observe
    // terminate, so a quiet feed would hang shutdown.
    socket.set_read_timeout(Some(RECV_TIMEOUT))?;

    let store = Arc::new(TelemetryStore::new());
    let thread_store = store.clone();

    thread::Builder::new()
        .name("ric-telemetry".into())
        .spawn(move || {
            info!("RIC telemetry receiver listening on {}", listen);
            let mut buf = [0u8; MAX_DATAGRAM];

            while !terminate.load(Ordering::SeqCst) {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        // The read timeout expiring is the idle path, not an error.
                        continue;
                    }
                    Err(e) => {
                        error!("RIC telemetry receive failed, stopping receiver: {}", e);
                        break;
                    }
                };

                let sample: Sample = match serde_json::from_slice(&buf[..len]) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                            "undecodable telemetry datagram from {} ({} bytes): {}",
                            from, len, e
                        );
                        thread_store.count_malformed();
                        continue;
                    }
                };

                if sample.v != SCHEMA_VERSION {
                    warn!(
                        "telemetry schema v{} from {}, this build speaks v{}; dropping",
                        sample.v, from, SCHEMA_VERSION
                    );
                    thread_store.count_malformed();
                    continue;
                }

                let seq = sample.seq;
                let radio = sample.radio.clone();
                thread_store.store(sample);

                if log_every > 0 && seq % log_every == 0 {
                    let stats = thread_store.stats();
                    info!(
                        "telemetry seq={} cqi={} ul_snr_db={} dl_thp_kbps={} ul_thp_kbps={} \
                         dl_rlc_delay_ms={} prb_util_dl_pct={} (received={} lost={} malformed={})",
                        seq,
                        show(radio.cqi),
                        show(radio.ul_snr_db),
                        show(radio.dl_thp_kbps),
                        show(radio.ul_thp_kbps),
                        show(radio.dl_rlc_delay_ms),
                        show(radio.prb_util_dl_pct),
                        stats.received,
                        stats.lost,
                        stats.malformed
                    );
                }
            }

            let stats = thread_store.stats();
            info!(
                "RIC telemetry receiver stopped (received={} lost={} malformed={})",
                stats.received, stats.lost, stats.malformed
            );
        })?;

    Ok(store)
}
