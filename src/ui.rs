use crate::perf::TestConfig;
use itertools::Itertools;
use quiche::scheduler::{MultipathScheduler, SchedulingDecisions};
use std::collections::HashMap;
use std::io;
use std::io::{Result, Write};
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;
use time::format_description::well_known::Iso8601;
use time::macros::format_description;
use time::OffsetDateTime;

#[derive(Debug, Default)]
struct Stats {
    tput_sent: f32,
    tput_recv: f32,
    packets_sent: usize,
    packets_recv: usize,
    // sent_bytes: u64,
    // recv_bytes: u64,
    lost: usize,
    lost_spurious: usize,
    dgram_sent: usize,
    dgram_recv: usize,

    // Only suitable for Paths
    cwnd_available: usize,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Clone, Debug)]
struct PathKey {
    path_id: usize,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

#[derive(Debug, Default)]
struct PathStats {
    stats: Stats,

    sent: usize,
    recv: usize,
    sent_bytes: u64,
    recv_bytes: u64,
    lost: usize,
    lost_spurious: usize,
    dgram_sent: usize,
    dgram_recv: usize,
}

impl PathStats {
    fn update(&mut self, stats: quiche::PathStats) {
        let mut ps = Stats::default();

        ps.tput_sent = (stats.sent_bytes - self.sent_bytes) as f32 * 8.0 / 1e6;
        ps.tput_recv = (stats.recv_bytes - self.recv_bytes) as f32 * 8.0 / 1e6;

        ps.packets_sent = stats.sent - self.sent;
        ps.packets_recv = stats.recv - self.recv;

        ps.lost = stats.lost - self.lost;
        ps.lost_spurious = stats.lost_spurious - self.lost_spurious;

        ps.dgram_sent = stats.dgram_sent - self.dgram_sent;
        ps.dgram_recv = stats.dgram_recv - self.dgram_recv;

        ps.cwnd_available = stats.cwnd_available;

        self.sent_bytes = stats.sent_bytes;
        self.recv_bytes = stats.recv_bytes;
        self.sent = stats.sent;
        self.recv = stats.recv;
        self.lost = stats.lost;
        self.lost_spurious = stats.lost_spurious;
        self.dgram_sent = stats.dgram_sent;
        self.dgram_recv = stats.dgram_recv;

        // let pscheduled = if i < scheduled.len() { scheduled[i] } else { 0 };

        self.stats = ps;
    }
}

#[derive(Debug)]
struct StatsManager {
    paths: HashMap<PathKey, PathStats>,
    conn_stats: Stats,

    sent: usize,
    recv: usize,
    sent_bytes: u64,
    recv_bytes: u64,
    lost: usize,
    dgram_sent: usize,
    dgram_recv: usize,
}

impl StatsManager {
    fn new() -> Self {
        Self {
            paths: HashMap::new(),
            conn_stats: Stats::default(),

            sent: 0,
            recv: 0,
            sent_bytes: 0,
            recv_bytes: 0,
            lost: 0,
            dgram_sent: 0,
            dgram_recv: 0,
        }
    }

    /// Returns `true` if a new path was created since Stats last checked.
    fn new_path(&self, conn: &quiche::Connection) -> bool {
        self.paths.len() < conn.path_stats().count()
    }

    fn update_stats(&mut self, conn: &quiche::Connection) {
        let stats = conn.stats();
        self.update_conn_stats(stats);

        // Update path values
        for (i, pstats) in conn.path_stats().enumerate() {
            let key = PathKey {
                local_addr: pstats.local_addr,
                peer_addr: pstats.peer_addr,
                path_id: i,
            };
            let pstats_prev = match self.paths.get_mut(&key) {
                Some(v) => v,
                None => {
                    self.paths.insert(key, PathStats::default());
                    self.paths.get_mut(&key).unwrap()
                }
            };

            pstats_prev.update(pstats);
        }
    }

    fn update_conn_stats(&mut self, stats: quiche::Stats) {
        let mut cs = Stats::default();

        cs.tput_sent = (stats.sent_bytes - self.sent_bytes) as f32 * 8.0 / 1e6;
        cs.tput_recv = (stats.recv_bytes - self.recv_bytes) as f32 * 8.0 / 1e6;

        cs.packets_sent = stats.sent - self.sent;
        cs.packets_recv = stats.recv - self.recv;

        cs.dgram_sent = stats.dgram_sent - self.dgram_sent;
        cs.dgram_recv = stats.dgram_recv - self.dgram_recv;

        // TODO: lost, lost_spurious

        // Update connection-level values for next iteration
        self.sent_bytes = stats.sent_bytes;
        self.recv_bytes = stats.recv_bytes;
        self.lost = stats.lost;
        self.sent = stats.sent;
        self.recv = stats.recv;

        self.conn_stats = cs;
    }
}

const UPDATE_FREQ: Duration = Duration::from_secs(1);

fn now_hour_second() -> String {
    let format = format_description!("[minute]:[second]");
    let now = OffsetDateTime::now_utc().to_offset(*crate::UTC_OFFSET);
    now.format(&format).unwrap()
}

fn fmt_unit(v: u64) -> (u64, &'static str) {
    if v >= 1_000_000 {
        (v / (1e6 as u64), "M")
    } else if v >= 1_000 {
        (v / (1e3 as u64), "K")
    } else {
        (v, " ")
    }
}

pub struct UIExecutor<'a> {
    ui: Box<dyn UI + 'a>,
    last_update: Option<Instant>,
    draining_line_printed: bool,
}

impl<'a> UIExecutor<'a> {
    pub fn new(ui: Box<dyn UI + 'a>) -> Self {
        Self {
            ui: ui,
            last_update: None,
            draining_line_printed: false,
        }
    }

    /// Returns the duration until the next per second update needs to be printed.
    /// Only starts counting down once update() has been called once.
    pub fn timeout(&self) -> Duration {
        match self.last_update {
            Some(last_update) => UPDATE_FREQ
                .checked_sub(last_update.elapsed())
                .unwrap_or(Duration::ZERO),
            None => Duration::MAX,
        }
    }

    /// Called during the test and determines if an per-second update line should be printed.
    pub fn update(
        &mut self,
        conn: &quiche::Connection,
        scheduler: Option<&mut Box<dyn MultipathScheduler>>,
        elapsed: Duration,
    ) -> Result<()> {
        let update_due = self.last_update.map_or(true, |v| v.elapsed() > UPDATE_FREQ);
        if !update_due || conn.is_closed() {
            return Ok(());
        }

        let scheduled = if let Some(s) = scheduler {
            s.pop_scheduling_decisions()
        } else {
            SchedulingDecisions::default()
        };

        self.ui.print_update(conn, scheduled, elapsed)?;

        if conn.is_draining() && !self.draining_line_printed {
            writeln!(io::stdout(), "Connection is draining ...")?;
            self.draining_line_printed = true;
        }

        self.last_update = Some(Instant::now());

        Ok(())
    }

    pub fn print_summary(&self, conn: &quiche::Connection, elapsed: Duration) -> Result<()> {
        self.ui.print_summary(conn, elapsed)
    }

    pub fn reset(&mut self) {
        self.ui.reset();
    }
}

pub trait UI {
    fn print_header(&self, npaths: usize) -> Result<()>;

    fn print_update(
        &mut self,
        conn: &quiche::Connection,
        scheduled: SchedulingDecisions,
        elapsed: Duration,
    ) -> Result<()>;

    fn print_summary(&self, conn: &quiche::Connection, elapsed: Duration) -> Result<()>;

    fn reset(&mut self);
}

#[derive(Debug)]
pub struct PerfUI {
    client_sending: bool,
    stats: StatsManager,
}

impl PerfUI {
    pub fn new(client_sending: bool) -> Self {
        PerfUI {
            client_sending,
            stats: StatsManager::new(),
            // last_update: None,
            // draining_line_printed: false,
        }
    }

    pub fn new_test(&self, tc: &TestConfig) -> Result<()> {
        let test_type = if tc.local_addrs.len() > 1 { "MP" } else { "SP" };

        let arrow = if tc.client_sending { "->" } else { "<-" };
        let addr_pairs = tc
            .local_addrs
            .iter()
            .zip(tc.peer_addrs.iter())
            .enumerate()
            .map(|(path_id, (l, p))| format!("- P{}: {}\t{} {}", path_id, l, arrow, p))
            .join("\n");

        let local_time = OffsetDateTime::now_utc().to_offset(*crate::UTC_OFFSET);

        writeln!(
            io::stdout(),
            "{direction} {test_type} test for {duration:?} at {time}\n{addr_pairs}",
            direction = if tc.client_sending {
                "uplink"
            } else {
                "downlink"
            },
            test_type = test_type,
            addr_pairs = addr_pairs,
            duration = tc.duration,
            time = local_time.format(&Iso8601::DEFAULT).unwrap(),
        )?;

        Ok(())
    }
}

impl UI for PerfUI {
    fn print_header(&self, npaths: usize) -> Result<()> {
        if npaths < 2 {
            writeln!(
                io::stdout(),
                "| {:<3} | {:<5} | {:<5} ‖ {:<13} | {:<24} |",
                "sec",
                "time",
                "FC_av",
                "P0 Mbps",
                "P0 Lost/Sched/Total (sp)",
            )?;
        } else {
            let mut pstr = String::new();
            for i in 0..npaths {
                pstr.push_str(&format!(
                    "‖ P{} Mbps, cwnd | P{} Lost/Sched/Total (sp) ",
                    i, i
                ));
            }

            writeln!(
                io::stdout(),
                "| {:<3} | {:<5} | {:<5} | {:<5} {}|",
                "sec",
                "time",
                "Mbps",
                "FC_av",
                pstr,
            )?;
        }

        Ok(())
    }

    fn print_update(
        &mut self,
        conn: &quiche::Connection,
        scheduled: SchedulingDecisions,
        elapsed: Duration,
    ) -> Result<()> {
        let npaths = conn.path_stats().count();
        if self.stats.new_path(conn) {
            self.print_header(npaths)?;
        }
        self.stats.update_stats(conn);

        let mut pstr = String::new();

        let tput = if self.client_sending {
            self.stats.conn_stats.tput_sent
        } else {
            self.stats.conn_stats.tput_recv
        };
        // let lost_total = stats.lost - self.lost;

        // let _packets = if self.client_sending {
        //     packets_sent
        // } else {
        //     packets_recv
        // };

        for (key, path_stats) in self.stats.paths.iter().sorted_by_key(|x| x.0) {
            let pstats = &path_stats.stats;

            let ptput = if self.client_sending {
                pstats.tput_sent
            } else {
                pstats.tput_recv
            };

            let (pcwndav_value, pcwndav_unit) = fmt_unit(pstats.cwnd_available as u64);
            // If PTO loss probes are sent, cwnd_available == max value.
            let pcwndav_value = std::cmp::min(pcwndav_value, 999);

            let packets = if self.client_sending {
                pstats.packets_sent
            } else {
                pstats.packets_recv
            };

            let plost = pstats.lost;
            let plost_spurious = pstats.lost_spurious;

            let pscheduled = if key.path_id < scheduled.len() {
                scheduled[key.path_id]
            } else {
                0
            };

            pstr.push_str(&format!(
                "‖ {:>7.2}, {:>3}{} | {:>5} /{:>5}/{:>6} ({:>2}) ",
                ptput, pcwndav_value, pcwndav_unit, plost, pscheduled, packets, plost_spurious
            ));
        }

        let stream_0_capacity = conn.stream_stats(0).map_or(0, |s| s.send_capacity);
        let (fc_value, fc_unit) = fmt_unit(stream_0_capacity);

        let time = now_hour_second();
        let elapsed = elapsed.as_secs();

        if npaths < 2 {
            writeln!(
                io::stdout(),
                "| {:>3} | {:>5} | {:>4}{} {}|",
                elapsed,
                time,
                fc_value,
                fc_unit,
                pstr
            )?;
        } else {
            writeln!(
                io::stdout(),
                "| {:>3} | {:>5} | {:>5.2} | {:>4}{} {}|",
                elapsed,
                time,
                tput,
                fc_value,
                fc_unit,
                pstr
            )?;
        }

        Ok(())
    }

    /// Called at the end of a test to print a final line.
    /// `finished_at` is Some if the test ended after the desired timeout. Otherwise it is None (e.g., on SIGINT).
    fn print_summary(&self, conn: &quiche::Connection, elapsed: Duration) -> Result<()> {
        let stats = conn.stats();

        let test_duration = elapsed.as_secs_f64();

        let tput_total = match (self.client_sending, test_duration != 0.0) {
            (true, true) => (stats.sent_bytes as f64 / test_duration) * 8.0 / 1e6,
            (false, true) => (stats.recv_bytes as f64 / test_duration) * 8.0 / 1e6,
            (_, false) => 0.0,
        };

        let lost_perc = (stats.lost as f64 / stats.sent as f64) * 100.0;

        let mut pstr = String::new();
        for (_i, pstats) in conn.path_stats().enumerate() {
            let ptput = match (self.client_sending, test_duration != 0.0) {
                (true, true) => (pstats.sent_bytes as f64 / test_duration) * 8.0 / 1e6,
                (false, true) => (pstats.recv_bytes as f64 / test_duration) * 8.0 / 1e6,
                (_, false) => 0.0,
            };

            let plost_perc = (pstats.lost as f64 / pstats.sent as f64) * 100.0;

            pstr.push_str(&format!("| {:>10.2} | {:>17.4}% ", ptput, plost_perc));
        }

        writeln!(io::stdout(), "{:->66}", "")?;

        let first_col = if self.client_sending { "Snt" } else { "Rcv" };
        if conn.path_stats().count() < 2 {
            writeln!(
                io::stdout(),
                "| {:>3} | {:>13} ‖ {:>7.2}       | {:>5} {:>17.4}% |",
                first_col,
                "",
                tput_total,
                stats.lost,
                lost_perc
            )?;
        } else {
            writeln!(
                io::stdout(),
                "| {:>3} | {:>5.2} {}|",
                first_col,
                tput_total,
                pstr
            )?;
        }

        Ok(())
    }

    fn reset(&mut self) {
        self.stats = StatsManager::new();
    }
}

pub struct ProxyUI {
    stats: StatsManager,
}

impl ProxyUI {
    pub fn new() -> Self {
        ProxyUI {
            stats: StatsManager::new(),
        }
    }
}

impl UI for ProxyUI {
    fn print_header(&self, npaths: usize) -> Result<()> {
        let mut pstr = String::new();
        for i in 0..npaths {
            pstr.push_str(&format!("‖ P{} Mbps / Pkts ", i));
        }

        writeln!(
            io::stdout(),
            "| {:<5}/{:<5} {:<2} {}|",
            "sec",
            "time",
            "",
            pstr,
        )?;

        Ok(())
    }

    fn print_update(
        &mut self,
        conn: &quiche::Connection,
        _scheduled: SchedulingDecisions,
        elapsed: Duration,
    ) -> Result<()> {
        let npaths = conn.path_stats().count();
        if self.stats.new_path(conn) {
            self.print_header(npaths)?;
        }
        self.stats.update_stats(conn);

        let mut pstr_sent = String::new();
        let mut pstr_recv = String::new();

        for (_key, path_stats) in self.stats.paths.iter().sorted_by_key(|x| x.0) {
            let pstats = &path_stats.stats;

            pstr_sent.push_str(&format!(
                "‖ {:>7.2} {:>6} ",
                pstats.tput_sent, pstats.dgram_sent,
            ));
            pstr_recv.push_str(&format!(
                "‖ {:>7.2} {:>6} ",
                pstats.tput_recv, pstats.dgram_recv,
            ));
        }

        let time = now_hour_second();
        let elapsed = elapsed.as_secs();

        writeln!(
            io::stdout(),
            "| {:>5}/{:>5} out {}|\n| {:>5} {:>5} in  {}|",
            elapsed,
            time,
            pstr_sent,
            "",
            "",
            pstr_recv,
        )?;

        Ok(())
    }

    fn print_summary(&self, _conn: &quiche::Connection, _elapsed: Duration) -> Result<()> {
        Ok(())
    }

    fn reset(&mut self) {
        self.stats = StatsManager::new();
    }
}
