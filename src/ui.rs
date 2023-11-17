use std::collections::HashMap;
use std::io;
use std::io::{Result, Write};
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use itertools::Itertools;
use quiche::scheduler::{MultipathScheduler, SchedulingDecisions};

use crate::protocol::TestConfig;

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
struct FourTuple {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

#[derive(Debug)]
struct PathStats {
    sent: usize,
    recv: usize,
    sent_bytes: u64,
    recv_bytes: u64,
    lost: usize,
    lost_spurious: usize,
}

impl PathStats {
    fn new() -> Self {
        PathStats {
            sent: 0,
            recv: 0,
            sent_bytes: 0,
            recv_bytes: 0,
            lost: 0,
            lost_spurious: 0,
        }
    }
}

const UPDATE_FREQ: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct UI {
    client_sending: bool,
    start: Instant,
    last_update: Option<Instant>,
    draining_line_printed: bool,

    sent: usize,
    recv: usize,
    sent_bytes: u64,
    recv_bytes: u64,
    lost: usize,

    paths: HashMap<FourTuple, PathStats>,
}

impl UI {
    pub fn new(client_sending: bool) -> Self {
        UI {
            client_sending,
            start: Instant::now(),
            last_update: None,
            draining_line_printed: false,

            sent: 0,
            recv: 0,
            sent_bytes: 0,
            recv_bytes: 0,
            lost: 0,

            paths: HashMap::new(),
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

        let local_time = chrono::Local::now();

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
            time = local_time.format("%y-%m-%dT%H:%M:%S")
        )?;

        Ok(())
    }

    /// Returns the duration until the next per second update needs to be printed. Only starts counting down once update() has been called once.
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
        scheduler: &mut Box<dyn MultipathScheduler>,
    ) -> Result<()> {
        let update_due = self.last_update.map_or(true, |v| v.elapsed() > UPDATE_FREQ);
        if !update_due || conn.is_closed() {
            return Ok(());
        }
        let scheduled = scheduler.pop_scheduling_decisions();
        self.print_per_second_update(conn, scheduled)?;

        if conn.is_draining() && !self.draining_line_printed {
            writeln!(io::stdout(), "Connection is draining ...")?;
            self.draining_line_printed = true;
        }

        self.last_update = Some(Instant::now());

        Ok(())
    }

    fn print_per_second_update(
        &mut self,
        conn: &quiche::Connection,
        scheduled: SchedulingDecisions,
    ) -> Result<()> {
        let npaths = conn.path_stats().count();
        if self.last_update.is_none() || self.paths.len() < npaths {
            if npaths < 2 {
                writeln!(
                    io::stdout(),
                    "| {:<3} | {:<5} | {:<5} | {:<10} | {:<18} |",
                    "sec",
                    "time",
                    "FC_av",
                    "P0 Mbps",
                    "P0 Lost/Total (sp)",
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
                    "| {:<3} | {:<5} | {:<10} | {:<5} {}|",
                    "sec",
                    "time",
                    "Total Mbps",
                    "FC_av",
                    pstr,
                )?;
            }
        }

        let mut pstr = String::new();

        let stats = conn.stats();
        let tput = if self.client_sending {
            (stats.sent_bytes - self.sent_bytes) as f32 * 8.0 / 1e6
        } else {
            (stats.recv_bytes - self.recv_bytes) as f32 * 8.0 / 1e6
        };
        // let lost_total = stats.lost - self.lost;

        let packets_sent = stats.sent - self.sent;
        let packets_recv = stats.recv - self.recv;
        let _packets = if self.client_sending {
            packets_sent
        } else {
            packets_recv
        };

        for (i, pstats) in conn.path_stats().enumerate() {
            let key = FourTuple {
                local_addr: pstats.local_addr,
                peer_addr: pstats.peer_addr,
            };
            let pstats_prev = match self.paths.get_mut(&key) {
                Some(v) => v,
                None => {
                    self.paths.insert(key, PathStats::new());
                    self.paths.get_mut(&key).unwrap()
                }
            };

            let ptput = if self.client_sending {
                (pstats.sent_bytes - pstats_prev.sent_bytes) as f32 * 8.0 / 1e6
            } else {
                (pstats.recv_bytes - pstats_prev.recv_bytes) as f32 * 8.0 / 1e6
            };

            let (pcwndav_value, pcwndav_unit) = fmt_unit(pstats.cwnd_available as u64);
            // If PTO loss probes are sent, cwnd_available == max value.
            let pcwndav_value = std::cmp::min(pcwndav_value, 999);

            let packets_sent = pstats.sent - pstats_prev.sent;
            let packets_recv = pstats.recv - pstats_prev.recv;
            let packets = if self.client_sending {
                packets_sent
            } else {
                packets_recv
            };

            let plost = pstats.lost - pstats_prev.lost;
            let plost_spurious = pstats.lost_spurious - pstats_prev.lost_spurious;

            let pscheduled = if i < scheduled.len() { scheduled[i] } else { 0 };

            pstr.push_str(&format!(
                "‖ {:>7.2}, {:>3}{} | {:>5} /{:>5}/{:>6} ({:>2}) ",
                ptput, pcwndav_value, pcwndav_unit, plost, pscheduled, packets, plost_spurious
            ));

            pstats_prev.sent_bytes = pstats.sent_bytes;
            pstats_prev.recv_bytes = pstats.recv_bytes;
            pstats_prev.lost = pstats.lost;
            pstats_prev.lost_spurious = pstats.lost_spurious;
            pstats_prev.sent = pstats.sent;
            pstats_prev.recv = pstats.recv;
        }

        let stream_0_capacity = conn.stream_stats(0).map_or(0, |s| s.send_capacity);
        let (fc_value, fc_unit) = fmt_unit(stream_0_capacity);

        let time = chrono::Local::now().format("%M:%S");
        let elapsed = self.start.elapsed().as_secs();

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
                "| {:>3} | {:>5} | {:>10.2} | {:>4}{} {}|",
                elapsed,
                time,
                tput,
                fc_value,
                fc_unit,
                pstr
            )?;
        }

        self.sent_bytes = stats.sent_bytes;
        self.recv_bytes = stats.recv_bytes;
        self.lost = stats.lost;
        self.sent = stats.sent;
        self.recv = stats.recv;

        Ok(())
    }

    pub fn print_summary(&mut self, conn: &quiche::Connection) -> Result<()> {
        let stats = conn.stats();

        let tput_total = if self.client_sending {
            (stats.sent_bytes as f32 / self.start.elapsed().as_secs_f32()) * 8.0 / 1e6
        } else {
            (stats.recv_bytes as f32 / self.start.elapsed().as_secs_f32()) * 8.0 / 1e6
        };
        let lost_perc = (stats.lost as f32 / stats.sent as f32) * 100.0;

        let mut pstr = String::new();
        for (_i, pstats) in conn.path_stats().enumerate() {
            let ptput = if self.client_sending {
                (pstats.sent_bytes as f32 / self.start.elapsed().as_secs_f32()) * 8.0 / 1e6
            } else {
                (pstats.recv_bytes as f32 / self.start.elapsed().as_secs_f32()) * 8.0 / 1e6
            };

            let plost_perc = (pstats.lost as f32 / pstats.sent as f32) * 100.0;

            pstr.push_str(&format!("| {:>10.2} | {:>17.4}% ", ptput, plost_perc));
        }

        writeln!(io::stdout(), "{:->88}", "")?;

        let first_col = if self.client_sending { "Snt" } else { "Rcv" };
        if conn.path_stats().count() < 2 {
            writeln!(
                io::stdout(),
                "| {:>3} | {:>10.2} | {:>5} {:>11.4}% |",
                first_col,
                tput_total,
                stats.lost,
                lost_perc
            )?;
        } else {
            writeln!(
                io::stdout(),
                "| {:>3} | {:>10.2} {}|",
                first_col,
                tput_total,
                pstr
            )?;
        }

        Ok(())
    }
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
