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
    sent_bytes: u64,
    recv_bytes: u64,
    lost: usize,
    lost_spurious: usize,
}

impl PathStats {
    fn new() -> Self {
        PathStats {
            sent_bytes: 0,
            recv_bytes: 0,
            lost: 0,
            lost_spurious: 0,
        }
    }
}

pub struct UI {
    start: Instant,
    last_update: Option<Instant>,

    sent_bytes_prev: u64,
    lost_prev: usize,

    paths: HashMap<FourTuple, PathStats>,
}

impl UI {
    pub fn new() -> Self {
        UI {
            start: Instant::now(),
            last_update: None,

            sent_bytes_prev: 0,
            lost_prev: 0,

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
        if self.last_update.is_none() {
            println!(
                "{:<5} | {:<10} | {:<10} | {:<10}",
                "sec", "Mbps", "P0 Mbps", "P0 Lost",
            )
        }
        if self.last_update.is_some() &&
            self.last_update.unwrap().elapsed() <= Duration::from_secs(1)
        {
            return;
        }

        let mut pstr = String::new();

        let stats = conn.stats();
        let tput_total =
            (stats.sent_bytes - self.sent_bytes_prev) as f32 * 8.0 / 1e6;
        // let lost_total = stats.lost - self.lost_prev;

        for (_i, pstat) in conn.path_stats().enumerate() {
            let key = FourTuple{local_addr: pstat.local_addr, peer_addr:pstat.peer_addr};
            let pstat_prev = match self.paths.get_mut(&key) {
                Some(v) => v,
                None => {
                    self.paths.insert(key, PathStats::new());
                    self.paths.get_mut(&key).unwrap()
                },
            };

            // let ptput = pstat.delivery_rate as f32 * 8.0 / 1e6;
            let ptput = (pstat.sent_bytes - pstat_prev.sent_bytes) as f32 * 8.0 / 1e6;
            let plost = pstat.lost - pstat_prev.lost;

            pstr.push_str(&format!(
                "| {:<10.2} | {:<10}",
                ptput, plost
            ));

            pstat_prev.sent_bytes = pstat.sent_bytes;
            pstat_prev.lost = pstat.lost;
        }

        println!(
            "{:<5} | {:<10.2} {}",
            self.start.elapsed().as_secs(), tput_total, pstr
        );

        self.last_update = Some(Instant::now());
        self.sent_bytes_prev = stats.sent_bytes;
        self.lost_prev = stats.lost;
    }

    pub fn print_summary(&mut self, conn: &quiche::Connection) {
        let stats = conn.stats();


        let tput_total = (stats.sent_bytes as f32 / self.start.elapsed().as_secs_f32()) * 8.0 / 1e6;
        let lost_perc = (stats.lost as f32 / stats.sent as f32) * 100.0;

        println!(
            "{:<5} | {:<10.2} | {:.4}% packet loss",
            "Avg", tput_total, lost_perc
        );
    }
}
