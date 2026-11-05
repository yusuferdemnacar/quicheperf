//! The proxy-server's own view of each path, written for experiments to collect.
//!
//! With `--path-log <file>`, every connection's path statistics are sampled on a fixed grid of times and every path event is written as it arrives, one JSON object per line stamped with the host's clock.

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Args;
use log::{info, warn};
use serde::Serialize;
use serde_json::{json, Value};

const PATH_LOG_HEADING: &str = "Path Log Options";

/// The proxy-server's flags for the path log, flattened into its subcommand.
#[derive(Args, Debug, Clone)]
pub struct PathLogArgs {
    /// Append every path's statistics and every path event to this file as JSON lines. Absent leaves the log off.
    #[arg(long = "path-log", help_heading = PATH_LOG_HEADING)]
    pub file: Option<PathBuf>,

    /// Seconds between two samples of the path statistics.
    #[arg(long = "path-log-interval", default_value = "0.2", value_parser = parse_interval, help_heading = PATH_LOG_HEADING)]
    pub interval: Duration,
}

/// A positive number of seconds, since an interval of zero would keep the sampler from ever finishing.
fn parse_interval(s: &str) -> Result<Duration, String> {
    s.parse::<f64>()
        .ok()
        .and_then(|secs| Duration::try_from_secs_f64(secs).ok())
        .filter(|interval| !interval.is_zero())
        .ok_or(format!("expected a positive number of seconds, got {}", s))
}

/// The open log, shared by the poll loop, which samples it, and by every connection, which reports its path events to it.
pub struct PathLog {
    file: File,
    interval: Duration,
    next_sample: Cell<Instant>,
}

#[derive(Serialize)]
struct Line<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    time: f64,
    conn: &'a str,
    #[serde(flatten)]
    fields: Value,
}

impl PathLog {
    /// Opens the log if `--path-log` is set.
    pub fn maybe_open(args: &PathLogArgs) -> std::io::Result<Option<Rc<PathLog>>> {
        let Some(path) = &args.file else {
            return Ok(None);
        };
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        info!(
            "Logging the path statistics every {:?} to {:?}",
            args.interval, path
        );
        Ok(Some(Rc::new(PathLog {
            file,
            interval: args.interval,
            next_sample: Cell::new(Instant::now()),
        })))
    }

    /// The time until the next sample is due.
    pub fn timeout(&self) -> Duration {
        self.next_sample
            .get()
            .saturating_duration_since(Instant::now())
    }

    /// Writes one line per connection, holding all its paths, if a sample is due.
    pub fn sample<'a>(&self, conns: impl Iterator<Item = &'a quiche::Connection>) {
        let now = Instant::now();
        if now < self.next_sample.get() {
            return;
        }
        self.next_sample
            .set(next_sample(self.next_sample.get(), now, self.interval));
        for conn in conns {
            let paths: Vec<Value> = conn
                .path_stats()
                .enumerate()
                .map(|(index, stats)| path_fields(index, &stats))
                .collect();
            self.write("sample", conn, json!({ "paths": paths }));
        }
    }

    pub fn event(&self, conn: &quiche::Connection, event: &quiche::PathEvent) {
        self.write("event", conn, event_fields(event));
    }

    fn write(&self, kind: &'static str, conn: &quiche::Connection, fields: Value) {
        let line = Line {
            kind,
            time: unix_time(),
            conn: conn.trace_id(),
            fields,
        };
        let mut text = serde_json::to_vec(&line).expect("a path log line always serializes");
        text.push(b'\n');
        // Unbuffered, so every line is in the file when an experiment copies it out.
        if let Err(e) = (&self.file).write_all(&text) {
            warn!("Failed writing the path log: {}", e);
        }
    }
}

/// The first time on the sampling grid after `now`, so a loop that falls behind skips samples rather than bunching them.
fn next_sample(due: Instant, now: Instant, interval: Duration) -> Instant {
    let mut next = due + interval;
    while next <= now {
        next += interval;
    }
    next
}

fn unix_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn path_fields(index: usize, stats: &quiche::PathStats) -> Value {
    json!({
        "index": index,
        "local": stats.local_addr,
        "peer": stats.peer_addr,
        "validation_state": format!("{:?}", stats.validation_state),
        "active": stats.active,
        "rtt_ms": ms(stats.rtt),
        "min_rtt_ms": stats.min_rtt.map(ms),
        "rttvar_ms": ms(stats.rttvar),
        "rtt_update": stats.rtt_update,
        "sent": stats.sent,
        "recv": stats.recv,
        "lost": stats.lost,
        "lost_spurious": stats.lost_spurious,
        "dgram_sent": stats.dgram_sent,
        "dgram_recv": stats.dgram_recv,
        "cwnd": stats.cwnd,
        "delivery_rate": stats.delivery_rate,
    })
}

fn event_fields(event: &quiche::PathEvent) -> Value {
    use quiche::PathEvent::*;
    match event {
        New(local, peer) => json!({ "event": "new", "local": local, "peer": peer }),
        Validated(local, peer) => json!({ "event": "validated", "local": local, "peer": peer }),
        FailedValidation(local, peer) => {
            json!({ "event": "failed_validation", "local": local, "peer": peer })
        }
        Closed(local, peer, error, reason) => json!({
            "event": "closed",
            "local": local,
            "peer": peer,
            "error": error,
            "reason": String::from_utf8_lossy(reason),
        }),
        ReusedSourceConnectionId(seq, _, (local, peer)) => json!({
            "event": "reused_source_connection_id",
            "local": local,
            "peer": peer,
            "seq": seq,
        }),
        PeerMigrated(local, peer) => {
            json!({ "event": "peer_migrated", "local": local, "peer": peer })
        }
        PeerPathStatus((local, peer), status) => json!({
            "event": "peer_path_status",
            "local": local,
            "peer": peer,
            "status": format!("{:?}", status),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_stay_on_the_grid() {
        let due = Instant::now();
        let interval = Duration::from_millis(200);
        assert_eq!(
            next_sample(due, due + Duration::from_millis(5), interval),
            due + interval
        );
        assert_eq!(
            next_sample(due, due + Duration::from_millis(450), interval),
            due + interval * 3
        );
    }
}
