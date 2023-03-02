use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use itertools::Itertools;

use crate::protocol::TestConfig;

#[derive(PartialEq, Eq, Hash, Copy, Clone)]
struct FourTuple {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}
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

pub struct UI {
    client_sending: bool,
    start: Instant,
    last_update: Option<Instant>,

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

            sent: 0,
            recv: 0,
            sent_bytes: 0,
            recv_bytes: 0,
            lost: 0,

            paths: HashMap::new(),
        }
    }

    pub fn new_test(
        &self, local_addrs: &Vec<SocketAddr>, peer_addrs: &Vec<SocketAddr>,
        tc: &TestConfig,
    ) {
        let test_type = if local_addrs.len() > 1 { "MP" } else { "SP" };

        let addr_it = local_addrs.iter().zip(peer_addrs.iter());
        let addr_pairs = addr_it
            .map(|(l, p)| l.to_string() + "->" + &p.to_string())
            .join(", ");

        println!(
            "{test_type} test for {duration:?} from {addr_pairs}",
            test_type = test_type,
            addr_pairs = addr_pairs,
            duration = tc.duration
        );
    }

    pub fn timeout(&self) -> Option<Duration> {
        let last_update = self.last_update?;
        Duration::from_secs(1)
            .checked_sub(last_update.elapsed())
            .or_else(|| Some(std::time::Duration::ZERO))
    }

    pub fn update(&mut self, conn: &quiche::Connection) {
        if self.last_update.is_some() &&
            self.last_update.unwrap().elapsed() <= Duration::from_secs(1)
        {
            return;
        }

        let npaths = conn.path_stats().count();
        if self.last_update.is_none() || self.paths.len() < npaths {
            info!("{}, {}", self.paths.len(), npaths);
            if npaths < 2 {
                println!(
                    "| {:<3} | {:<10} | {:<18} |",
                    "sec", "P0 Mbps", "P0 Lost/Total (sp)",
                );
            } else {
                let mut pstr = String::new();
                for i in 0..npaths {
                    pstr.push_str(&format!(
                        "| P{}  Mbps   | P{} Lost/Total (sp) ",
                        i, i));
                }

                println!(
                    "| {:<3} | {:<10} {}|",
                    "sec", "Total Mbps", pstr,
                );
            }
        }

        let mut pstr = String::new();

        let stats = conn.stats();
        let tput_sent = (stats.sent_bytes - self.sent_bytes) as f32 * 8.0 / 1e6;
        let tput_recv = (stats.recv_bytes - self.recv_bytes) as f32 * 8.0 / 1e6;
        let tput = if self.client_sending {
            tput_sent
        } else {
            tput_recv
        };
        // let lost_total = stats.lost - self.lost;

        let packets_sent = stats.sent - self.sent;
        let packets_recv = stats.recv - self.recv;
        let _packets = if self.client_sending {
            packets_sent
        } else {
            packets_recv
        };

        for (_i, pstats) in conn.path_stats().enumerate() {
            let key = FourTuple {
                local_addr: pstats.local_addr,
                peer_addr: pstats.peer_addr,
            };
            let pstats_prev = match self.paths.get_mut(&key) {
                Some(v) => v,
                None => {
                    self.paths.insert(key, PathStats::new());
                    self.paths.get_mut(&key).unwrap()
                },
            };

            let ptput = if self.client_sending {
                (pstats.sent_bytes - pstats_prev.sent_bytes) as f32 * 8.0 / 1e6
            } else {
                (pstats.recv_bytes - pstats_prev.recv_bytes) as f32 * 8.0 / 1e6
            };

            let packets_sent = pstats.sent - pstats_prev.sent;
            let packets_recv = pstats.recv - pstats_prev.recv;
            let packets = if self.client_sending {
                packets_sent
            } else {
                packets_recv
            };

            let plost = pstats.lost - pstats_prev.lost;
            let plost_spurious = pstats.lost_spurious - pstats_prev.lost_spurious;

            pstr.push_str(&format!(
                "| {:>10.2} | {:>5} /{:>6} ({:>2}) ",
                ptput, plost, packets, plost_spurious
            ));

            pstats_prev.sent_bytes = pstats.sent_bytes;
            pstats_prev.recv_bytes = pstats.recv_bytes;
            pstats_prev.lost = pstats.lost;
            pstats_prev.lost_spurious = pstats.lost_spurious;
            pstats_prev.sent = pstats.sent;
            pstats_prev.recv = pstats.recv;
        }

        if npaths < 2 {
            println!("| {:>3} {}|", self.start.elapsed().as_secs(), pstr);
        } else {
            println!(
                "| {:>3} | {:>10.2} {}|",
                self.start.elapsed().as_secs(),
                tput,
                pstr
            );
        }

        self.last_update = Some(Instant::now());
        self.sent_bytes = stats.sent_bytes;
        self.recv_bytes = stats.recv_bytes;
        self.lost = stats.lost;
        self.sent = stats.sent;
        self.recv = stats.recv;
    }

    pub fn print_summary(&mut self, conn: &quiche::Connection) {
        let stats = conn.stats();

        let tput_total = (stats.sent_bytes as f32 / self.start.elapsed().as_secs_f32()) * 8.0 / 1e6;
        let lost_perc = (stats.lost as f32 / stats.sent as f32) * 100.0;

        let mut pstr = String::new();
        for (_i, pstats) in conn.path_stats().enumerate() {

            let ptput = if self.client_sending {
                (pstats.sent_bytes as f32 / self.start.elapsed().as_secs_f32()) * 8.0 / 1e6
            } else {
                (pstats.recv_bytes as f32 / self.start.elapsed().as_secs_f32()) * 8.0 / 1e6
            };

            let plost_perc = (pstats.lost as f32 / pstats.sent as f32) * 100.0;

            pstr.push_str(&format!(
                "| {:>10.2} | {:>17.4}% ",
                ptput, plost_perc
            ));
        }

        if conn.path_stats().count() < 2 {
            println!(
                "| {:>3} | {:>10.2} | {:>5} {:>11.4}% |",
                "Avg", tput_total, stats.lost, lost_perc
            );
        } else {
            println!(
                "| {:>3} | {:>10.2} {}|",
                "Avg", tput_total, pstr
            );

        }
    }
}
