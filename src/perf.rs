use std::cmp::min;
use std::time;
use std::time::Duration;
use std::time::Instant;

use quiche::Connection;
use serde::Deserialize;
use serde::Serialize;

pub const ALPN: [&[u8]; 2] = [b"quicheperf", b"quicheperf-00"];

pub static SEND_DATA: [u8; 65507] = [0; 65507];

const BITRATE_TIMER: Duration = Duration::from_millis(10);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TestConfig {
    pub local_addrs: Vec<String>,
    pub peer_addrs: Vec<String>,

    pub password: Option<String>,
    pub client_sending: bool,
    pub duration: Option<Duration>,

    // If None, send as much data as possible. If Some(v), try to send v bits per second.
    pub bitrate_target: Option<u64>,

    pub streams: Vec<PerfStream>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestConfigAck {
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PerfStream {
    pub stream_id: u64,
    // Point in time when data was last sent on this stream
    #[serde(with = "instant_none")]
    pub last_send: Option<Instant>,
    pub bytes_left: Option<u64>,
}

impl PerfStream {
    /// Returns how many bytes to send right now if a target bitrate was configured. If not, None is returned.
    fn bitrate_target_quantum(&mut self, bitrate_target: u64) -> u64 {
        let bytes_per_round = bitrate_target
            / (Duration::from_secs(1).as_millis() / BITRATE_TIMER.as_millis()) as u64;
        let quantum = match self.last_send {
            Some(last_send) => {
                // Clamp value to prevent excessive bursts
                let rounds_elapsed = (last_send.elapsed().as_micros() as f64
                    / BITRATE_TIMER.as_micros() as f64)
                    .clamp(0.0, 3.0);
                if rounds_elapsed < 1.0 {
                    // Not a whole round yet, so nothing is owed. Return without touching
                    // last_send: credit accrues against the last time data actually went out.
                    // Updating it here would restart the round on every early call, and early
                    // calls are the common case rather than the exception - every arriving ack
                    // wakes the poll loop and the sender is asked again then. Discarding the
                    // credit each time costs more the faster the test runs, because a faster
                    // test draws more acks per round.
                    return 0;
                }
                (bytes_per_round as f64 * rounds_elapsed) as u64
            }
            None => bytes_per_round,
        };
        self.last_send = Some(Instant::now());
        quantum
    }
}

#[derive(Debug, Clone)]
pub struct Perf {
    config_sent: bool,
    config_acked: bool,
    tc: Option<TestConfig>,
    password: Option<String>,

    // Set after TestConfig was ACKed
    started_at: Option<Instant>,
    // Set after test duration expired
    finished_at: Option<Instant>,

    buf: [u8; 65535],
    buf_config_offset: usize,

    prev_streams_idx: usize,

    // Stream IDs close_if_finished has observed with capacity at least once. conn.stream_capacity
    // reports the same error for "this stream does not exist yet" and "this stream is done and has
    // been dropped from the map", and only the second means finished. A reverse ("-r") test's
    // streams are server-initiated and absent from the client's map until the sender's first
    // packet lands, which is one or more dispatch calls after the config is acked.
    streams_seen: std::collections::HashSet<u64>,
}

impl Perf {
    /// Used by the client.
    pub fn new_with_tc(tc: TestConfig) -> Self {
        let password = tc.password.clone();
        Self {
            config_sent: false,
            config_acked: false,
            tc: Some(tc),
            password,
            started_at: None,
            finished_at: None,
            buf: [0; 65535],
            buf_config_offset: 0,
            prev_streams_idx: 0,
            streams_seen: std::collections::HashSet::new(),
        }
    }

    /// Used by the server.
    pub fn new_with_password(password: Option<String>) -> Self {
        Self {
            config_sent: false,
            config_acked: false,
            tc: None,
            password,
            started_at: None,
            finished_at: None,
            buf: [0; 65535],
            buf_config_offset: 0,
            prev_streams_idx: 0,
            streams_seen: std::collections::HashSet::new(),
        }
    }

    /// How soon this `Perf` wants to run again to keep pacing its bitrate target, for whichever
    /// peer is asking. `Duration::MAX` means "nothing to do", and the caller's poll loop is then
    /// bounded only by the connection's own timers.
    ///
    /// Two of the gates are subtle and both are load-bearing:
    ///
    /// - `is_sending()`, not `config_sent`. A receiver has no pacing to do, and every stream's
    ///   `last_send` stays `None` on it, which the arm below would turn into `ZERO` — a poll
    ///   timeout of zero, i.e. a peer that never sleeps.
    /// - `config_acked`, not `config_sent`. Only the client ever sets `config_sent`
    ///   (`send_config` is called exclusively from `client_dispatch`), so gating on it would
    ///   return `MAX` on every server-side `Perf` and deny the server its pacing wakeups
    ///   entirely. `config_acked` is set on both ends, by `recv_config_ack` and `recv_config`.
    #[allow(clippy::unnecessary_unwrap)]
    pub fn timeout(&self) -> time::Duration {
        if self.finished_at.is_some()
            || self.tc.is_none() // Wait for tc to arrive from client
            || self.tc.as_ref().unwrap().bitrate_target.is_none() // Wait for ACKs that trigger calling dispatch
            || !self.config_acked
            || !self.is_sending()
        {
            // Nothing to do
            time::Duration::MAX
        } else {
            self.tc
                .as_ref()
                .unwrap()
                .streams
                .iter()
                .map(|stream| {
                    if let Some(last_send) = stream.last_send {
                        BITRATE_TIMER.saturating_sub(last_send.elapsed())
                    } else {
                        Duration::ZERO
                    }
                })
                .min()
                .unwrap_or(time::Duration::ZERO)
        }
    }

    /// Drive the quicheperf client test execution forward: Send/receive configurations and
    /// data depending on the test direction.
    pub fn client_dispatch(&mut self, conn: &mut Connection) {
        if !conn.is_closed() && !conn.is_draining() && !self.close_if_finished(conn) {
            if !self.config_sent {
                self.send_config(conn).ok();
            } else if !self.config_acked {
                self.recv_config_ack(conn).ok();
            }
            if self.config_acked {
                if self.started_at.is_none() {
                    self.started_at = Some(Instant::now());
                }
                if let Err(e) = self.work(conn) {
                    error!("client_dispatch: {e}");
                }
            }
        }
    }

    /// Drive the quicheperf server test execution forward.
    pub fn server_dispatch(&mut self, conn: &mut Connection) {
        if !self.config_acked {
            self.recv_config(conn).ok();
            // #[cfg(feature = "qlog")]
            // if let Some(tc) = &protocol.tc {
            //     common::qlog_metadata(&mut self.conn, tc, &self.config);
            // }
        } else if let Err(e) = self.work(conn) {
            error!("server_dispatch: {e}");
        }
    }

    /// Returns how much of the test duration has elapsed. Stops increasing once the test has finished.
    pub fn test_duration_elapsed(&self) -> Duration {
        match (self.started_at, self.finished_at) {
            (None, None) => Duration::ZERO,
            (None, Some(_)) => unreachable!(),
            (Some(s), None) => s.elapsed(),
            (Some(s), Some(e)) => e - s,
        }
    }

    /// Whether this peer is the one sending test data.
    ///
    /// It depends on the test direction and on which end of the connection this `Perf` is, and
    /// `config_sent` is what distinguishes the ends: only the client ever sets it, because
    /// `send_config` is called exclusively from `client_dispatch`. So a forward test sends from
    /// the peer that sent the config, and a reverse test from the peer that did not.
    fn is_sending(&self) -> bool {
        match self.tc.as_ref() {
            Some(tc) => {
                (tc.client_sending && self.config_sent)
                    || (!tc.client_sending && !self.config_sent)
            }
            None => false,
        }
    }

    fn work(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        if !self.config_acked {
            return Err(quiche::Error::Done);
        }
        if self.is_sending() {
            self.send_data(conn)
        } else {
            self.recv_data(conn)
        }
    }

    /// Check if the test duration expired or all data has been sent and close connection if applicable.
    fn close_if_finished(&mut self, conn: &mut Connection) -> bool {
        if self.finished_at.is_some() {
            return true;
        }
        if self.tc.is_none() {
            return false;
        }
        let duration_remaining = match (&self.tc, self.started_at) {
            (Some(tc), Some(start)) => tc
                .duration
                .unwrap_or(Duration::MAX)
                .saturating_sub(start.elapsed()),
            _ => return false,
        };

        let duration_not_elapsed = duration_remaining > std::time::Duration::ZERO;
        if !duration_not_elapsed {
            debug!(
                "Closing connection after {:?} because --duration={:?} passssssed",
                self.started_at.unwrap().elapsed(),
                self.tc.as_ref().unwrap().duration
            );
        }

        // let streams_not_finished = self.tc.as_ref().unwrap().streams.iter().find(|stream| stream.bytes_left.unwrap_or(u64::MAX) > 0).is_some();
        //
        // conn.stream_capacity errors identically for "this stream does not exist yet" and "this
        // stream existed and is now fully consumed", but only the second means the stream is
        // finished. streams_seen disambiguates them: a stream that has never had capacity is still
        // awaited, not finished, so it must not count toward closing the connection.
        let streams_not_finished = self.tc.as_ref().unwrap().streams.iter().any(|stream| {
            if conn.stream_capacity(stream.stream_id).is_ok() {
                self.streams_seen.insert(stream.stream_id);
                true
            } else {
                !self.streams_seen.contains(&stream.stream_id)
            }
        });
        if !streams_not_finished {
            debug!(
                "Closing connection after {:?} because streams sent all data",
                self.started_at.unwrap().elapsed(),
            );
        }

        if duration_not_elapsed && streams_not_finished {
            return false;
        }

        self.finished_at = Some(Instant::now());
        match conn.close(true, 0x00, b"test finished") {
            // Already closed.
            Ok(_) | Err(quiche::Error::Done) => true,
            Err(e) => panic!("error closing conn: {:?}", e),
        }
    }

    /// Called by client to kick off test
    fn send_config(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        trace!("Trying to send test configuration request");

        let tc = match self.tc.as_ref() {
            Some(v) => v,
            None => unreachable!(),
        };

        let msg = serde_json::to_string(tc).unwrap();
        let written = match conn.stream_send(0, msg.as_bytes(), true) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return Err(e);
            }
        };

        trace!("Wrote {} bytes while sending config", written);
        if written < msg.len() {
            trace!("Not all bytes written, try again");
        } else {
            trace!("config_sent = true");
            self.config_sent = true;
        }

        self.tc = Some(tc.clone());

        Ok(())
    }

    // Called by client after sending TestConfig
    fn recv_config_ack(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        while let Ok((read, _fin)) = conn.stream_recv(0, &mut self.buf) {
            trace!(
                "recv_config_ack: {} received {} bytes from stream {}",
                conn.trace_id(),
                read,
                0
            );

            let tca: TestConfigAck = match serde_json::from_slice(&self.buf[..read]) {
                Ok(tca) => tca,
                Err(e) => {
                    error!("recv_config_ack: Serde error: {}", e);
                    return Err(quiche::Error::Done);
                }
            };

            if let Some(e) = tca.error {
                info!("recv_config_ack: Server returned TestConfig error: {}", e);
                // TODO: close connection
                return Err(quiche::Error::Done);
            }

            self.config_acked = true;
        }
        trace!("recv_config_ack: config_acked = {}", self.config_acked);
        Ok(())
    }

    fn send_data(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        // for streams_idx in 0..self.tc.as_ref().unwrap().streams.len() {
        let streams_len = self.tc.as_ref().unwrap().streams.len();
        // Write data to each stream until the connection can not buffer any more data
        // Each call to send_data_on_stream will only queue data correponding to 5 packets.
        // This is done to make sure that data can be queued on all streams, if we send
        // on more than one stream
        let mut wrote_data = true;
        while wrote_data {
            wrote_data = false;
            let prev_streams_idx = self.prev_streams_idx;
            for i in 0..streams_len {
                self.prev_streams_idx = (prev_streams_idx + i) % streams_len;
                match self.send_data_on_stream(conn, self.prev_streams_idx) {
                    Ok(_) => wrote_data = true,
                    Err(quiche::Error::Done) => continue, // no more data can be queued
                    Err(e) => return Err(e),
                };
            }
        }
        Ok(())
    }

    // TODO: look into FinalSize error: keep track of fin and don't call send dat_on_stream anymore

    fn send_data_on_stream(
        &mut self,
        conn: &mut Connection,
        streams_idx: usize,
    ) -> quiche::Result<()> {
        let bitrate_target = self.tc.as_ref().unwrap().bitrate_target;
        let stream = &mut self.tc.as_mut().unwrap().streams[streams_idx];
        let send_quantum = bitrate_target.map(|target| stream.bitrate_target_quantum(target));
        // A zero quantum means the round's allowance is already spent, not that the stream is
        // idle, so it has to read as "no progress". Ok(()) would tell send_data's
        // `while wrote_data` loop the opposite, and it would call straight back in - still inside
        // the same round, so still zero, with nothing to break the cycle but the clock. Done maps
        // onto the loop's existing no-progress arm and yields to the poll loop, which waits out
        // the rest of the round.
        if send_quantum == Some(0) {
            return Err(quiche::Error::Done);
        }
        // let mut bytes_to_send = send_quantum.unwrap_or(SEND_DATA.len() as u64 * 1000);
        // Only queue 5 packets on a stream at once to push data to all available streams
        let mut bytes_to_send = send_quantum.unwrap_or(conn.max_send_udp_payload_size() as u64 * 5);

        // FIN already set
        if stream.bytes_left.map(|left| left == 0).unwrap_or(false) {
            return Err(quiche::Error::Done);
        }

        let mut offset = bytes_to_send;
        while offset > 0 && stream.bytes_left.map(|left| left > 0).unwrap_or(true) {
            // Terminate also if all bytes of the stream have been written
            let bytes_left = stream.bytes_left.unwrap_or(u64::MAX);
            offset = min(min(bytes_to_send, SEND_DATA.len() as u64), bytes_left);
            let send_buf = &SEND_DATA[..offset as usize];
            let fin = stream
                .bytes_left
                .map(|left| offset == left)
                .unwrap_or(false);
            if fin {
                trace!("Setting fin: stream={stream:?} offset=")
            }
            let written = match conn.stream_send(stream.stream_id, send_buf, fin) {
                Ok(v) => v,

                Err(quiche::Error::Done) => return Err(quiche::Error::Done),

                Err(e) => {
                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return Err(e);
                }
            };

            trace!(
                "Wrote {written}/{offset} bytes on stream {}, {:?} B left, fin={}",
                stream.stream_id,
                stream.bytes_left,
                bytes_left == 0
            );
            bytes_to_send = bytes_to_send.saturating_sub(written as u64);
            stream.bytes_left = stream
                .bytes_left
                .map(|left| left.saturating_sub(written as u64));
        }

        Ok(())
    }

    fn recv_data(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        for stream_id in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut self.buf) {
                trace!(
                    "{} received {} bytes from stream {}, fin={}",
                    conn.trace_id(),
                    read,
                    0,
                    fin
                );

                let _stream_buf = &self.buf[..read];

                // Drop received data
            }
        }
        Ok(())
    }

    fn recv_config(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        debug!("receiving test config");
        match conn.stream_recv(0, &mut self.buf[self.buf_config_offset..]) {
            Ok((read, fin)) => {
                if !fin {
                    // Wait for the full config
                    self.buf_config_offset = read;
                    return Ok(());
                }
                let raw_config = &self.buf[..self.buf_config_offset + read];
                debug!(
                    "Test config: {}",
                    String::from_utf8(raw_config.to_vec()).unwrap_or("decoding error".into())
                );
                let tc: TestConfig = match serde_json::from_slice(raw_config) {
                    Ok(tc) => tc,
                    Err(e) => {
                        error!("Serde test config error: {}", e);
                        conn.close(true, 0x1, b"failed parsing test config")
                            .unwrap();
                        return Err(quiche::Error::Done);
                    }
                };

                debug!("Parsed test config: client_sending={}", tc.client_sending);

                fn pw_eq<T>(expected: &Option<T>, received: &Option<T>) -> bool
                where
                    T: PartialEq,
                {
                    match (expected, received) {
                        (None, _) => true,
                        (Some(v1), Some(v2)) => v1 == v2,
                        _ => false,
                    }
                }

                if !pw_eq(&self.password, &tc.password) {
                    info!("Authentication failed, closing connection");
                    match conn.close(true, 0x10, b"authentication failed") {
                        Ok(_) | Err(quiche::Error::Done) => return Ok(()),
                        Err(e) => panic!("error closing conn: {:?}", e),
                    };
                }

                let ack = TestConfigAck { error: None };
                let resp = serde_json::to_string(&ack).unwrap();

                let written = match conn.stream_send(0, resp.as_bytes(), true) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => 0,

                    Err(e) => {
                        error!("{} stream send failed {:?}", conn.trace_id(), e);
                        return Err(e);
                    }
                };

                debug!("{} wrote TestConfigAck: {} bytes", conn.trace_id(), written);
                self.config_acked = true;

                self.tc = Some(tc);
            }
            Err(e) => {
                debug!("stream_recv error: {}", e)
            }
        }

        Ok(())
    }
}

mod instant_none {
    use serde::{de::IgnoredAny, Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Instant;

    pub fn serialize<S>(_instant: &Option<Instant>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let v: Option<usize> = None;
        v.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Instant>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Consume whatever token is there (e.g., the `null`) and discard it
        let _ = IgnoredAny::deserialize(deserializer)?;
        Ok(None)
    }
}
