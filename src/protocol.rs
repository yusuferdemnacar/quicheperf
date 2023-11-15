use std::time;
use std::time::Duration;
use std::time::Instant;

use quiche::Connection;
use serde::Deserialize;
use serde::Serialize;

pub const SEND_DATA: [u8; 65507] = [0; 65507];

const BITRATE_TIMER: Duration = Duration::from_millis(10);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TestConfig {
    pub local_addrs: Vec<String>,
    pub peer_addrs: Vec<String>,

    pub password: Option<String>,
    pub client_sending: bool,
    pub duration: Duration,

    // If None, send as much data as possible. If Some(v), try to send v bits per second.
    pub bitrate_target: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestConfigAck {
    error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Protocol {
    pub config_sent: bool,
    pub config_acked: bool,
    pub tc: Option<TestConfig>,
    password: Option<String>,
    start: Option<Instant>,

    // Set after test duration expired
    finished: bool,

    // Point in time when data was last sent
    last_send: Option<Instant>,

    buf: [u8; 65535],
}

impl Protocol {
    /// Used by the client.
    pub fn new_with_tc(tc: TestConfig) -> Self {
        let password = tc.password.clone();
        Self {
            config_sent: false,
            config_acked: false,
            tc: Some(tc),
            password,
            start: None,
            finished: false,
            last_send: None,
            buf: [0; 65535],
        }
    }

    /// Used by the server.
    pub fn new_with_password(password: Option<String>) -> Self {
        Self {
            config_sent: false,
            config_acked: false,
            tc: None,
            password,
            start: None,
            finished: false,
            last_send: None,
            buf: [0; 65535],
        }
    }

    pub fn timeout(&self) -> time::Duration {
        if self.finished
            || self.tc.is_none()
            || self.tc.as_ref().unwrap().bitrate_target.is_none()
            || !self.config_sent
            || !self.config_acked
        {
            time::Duration::MAX
        } else if let Some(last_send) = self.last_send {
            BITRATE_TIMER
                .checked_sub(last_send.elapsed())
                .unwrap_or(time::Duration::ZERO)
        } else {
            time::Duration::ZERO
        }
    }

    /// Drive the quicheperf client test execution forward: Send/receive configurations and
    /// data depending on the test direction.
    pub fn client_dispatch(&mut self, conn: &mut Connection) {
        if !conn.is_closed() && !conn.is_draining() && !self.close_after_duration(conn) {
            if !self.config_sent {
                self.send_config(conn).ok();
            } else if !self.config_acked {
                self.recv_config_ack(conn).ok();
            }
            if self.config_acked {
                self.work(conn).ok();
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
        } else {
            self.work(conn).ok();
        }
    }

    // TODO: Merge into dispatch
    pub fn work(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        if !self.config_acked {
            return Err(quiche::Error::Done);
        }
        let tc = self.tc.as_ref().unwrap();
        let send_data =
            (tc.client_sending && self.config_sent) || (!tc.client_sending && !self.config_sent);
        if send_data {
            self.send_data(conn)
        } else {
            self.recv_data(conn)
        }
    }

    /// Check if the test duration expired and close connection if applicable
    pub fn close_after_duration(&mut self, conn: &mut Connection) -> bool {
        if self.finished {
            return true;
        }
        let duration_remaining = match (&self.tc, self.start) {
            (Some(tc), Some(start)) => tc
                .duration
                .checked_sub(start.elapsed())
                .unwrap_or(std::time::Duration::ZERO),
            _ => return false,
        };
        if duration_remaining > std::time::Duration::ZERO {
            return false;
        }
        debug!(
            "Closing connection after {:?} because --duration={:?} passed",
            self.start.unwrap().elapsed(),
            self.tc.as_ref().unwrap().duration
        );
        self.finished = true;
        match conn.close(true, 0x00, b"kthxbye") {
            // Already closed.
            Ok(_) | Err(quiche::Error::Done) => true,
            Err(e) => panic!("error closing conn: {:?}", e),
        }
    }

    /// Called by client to kick off test
    pub fn send_config(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        trace!("Trying to send test configuration request");

        let tc = match self.tc.as_ref() {
            Some(v) => v,
            None => unreachable!(),
        };

        let msg = serde_json::to_string(tc).unwrap();
        let written = match conn.stream_send(0, msg.as_bytes(), false) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return Err(From::from(e));
            }
        };

        trace!("Wrote {} bytes", written);
        if written < msg.as_bytes().len() {
            trace!("Not all bytes written, try again");
        } else {
            trace!("config_sent = true");
            self.config_sent = true;
        }

        self.tc = Some(tc.clone());
        self.start = Some(Instant::now());

        Ok(())
    }

    // Called by client after sending TestConfig
    pub fn recv_config_ack(&mut self, conn: &mut Connection) -> quiche::Result<()> {
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

    /// Returns how many bytes to send right now if a target bitrate was configured. If not, None is returned.
    fn bitrate_target_quantum(&self) -> Option<u64> {
        let bitrate_target = self.tc.as_ref()?.bitrate_target?;
        let bytes_per_round = bitrate_target
            / (Duration::from_secs(1).as_millis() / BITRATE_TIMER.as_millis()) as u64;
        match self.last_send {
            Some(last_send) => {
                // Clamp value to prevent excessive bursts
                let rounds_elapsed = (last_send.elapsed().as_micros() as f64
                    / BITRATE_TIMER.as_micros() as f64)
                    .clamp(0.0, 3.0);
                if rounds_elapsed < 1.0 {
                    Some(0)
                } else {
                    let send_bytes = (bytes_per_round as f64 * rounds_elapsed) as u64;
                    Some(send_bytes)
                }
            }
            None => Some(bytes_per_round),
        }
    }

    pub fn send_data(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        let send_quantum = self.bitrate_target_quantum();
        let mut bytes_to_send = send_quantum.unwrap_or(SEND_DATA.len() as u64 * 1000);

        while bytes_to_send > 0 {
            let offset = std::cmp::min(bytes_to_send, SEND_DATA.len() as u64);
            let send_buf = &SEND_DATA[..offset as usize];
            bytes_to_send -= offset;
            let written = match conn.stream_send(0, send_buf, false) {
                Ok(v) => v,

                Err(quiche::Error::Done) => break,

                Err(e) => {
                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return Err(From::from(e));
                }
            };

            self.last_send = Some(Instant::now());
            trace!("Wrote {} bytes", written);
        }

        Ok(())
    }

    pub fn recv_data(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        trace!("receiving data");
        while let Ok((read, fin)) = conn.stream_recv(0, &mut self.buf) {
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
        Ok(())
    }

    pub fn recv_config(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        debug!("receiving test config");
        let s = 0;
        match conn.stream_recv(s, &mut self.buf) {
            Ok((read, _fin)) => {
                let tc: TestConfig = match serde_json::from_slice(&self.buf[..read]) {
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

                let written = match conn.stream_send(s, resp.as_bytes(), false) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => 0,

                    Err(e) => {
                        error!("{} stream send failed {:?}", conn.trace_id(), e);
                        return Err(From::from(e));
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
