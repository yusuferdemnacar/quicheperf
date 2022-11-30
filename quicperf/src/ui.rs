use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use itertools::Itertools;

use crate::protocol::TestConfig;

pub struct UI {
    start: Instant,
    last_update: Option<Instant>,

    sent_bytes_prev: u64,
    lost_prev: usize,
}

impl UI {
    pub fn new() -> Self {
        UI {
            start: Instant::now(),
            last_update: None,

            sent_bytes_prev: 0,
            lost_prev: 0,
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

        let stats = conn.stats();
        let tput_total =
            (stats.sent_bytes - self.sent_bytes_prev) as f32 * 8.0 / 1e6;
        let lost_total = stats.lost - self.lost_prev;

        let mut pstr = String::new();
        for (i, pstat) in conn.path_stats().enumerate() {
            let ptput = pstat.delivery_rate as f32 * 8.0 / 1e6;
            pstr.push_str(&format!(", path {}={:.2} Mbps", i, ptput));
        }

        println!("[{sec}] throughput={tput_total:.2} Mbps, lost={lost_total} packets{pstr}",
            sec=self.start.elapsed().as_secs(),
            tput_total=tput_total,
            lost_total=lost_total,
            pstr=pstr);

        self.last_update = Some(Instant::now());
        self.sent_bytes_prev = stats.sent_bytes;
        self.lost_prev = stats.lost;
    }
}
