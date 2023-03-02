use std::time::Duration;
use std::time::Instant;

use quiche::Connection;
use serde::Deserialize;
use serde::Serialize;

pub const SEND_DATA: [u8; 65507] = [0; 65507];

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TestConfig {
    pub local_addrs: Vec<String>,
    pub peer_addrs: Vec<String>,

    pub password: Option<String>,
    pub client_sending: bool,
    pub duration: Duration,
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
    start: Option<Instant>,
}

impl Protocol {
    pub fn new() -> Self {
        Self {
            config_sent: false,
            config_acked: false,
            tc: None,
            start: None,
        }
    }

    pub fn work(
        &mut self, conn: &mut Connection, buf: &mut [u8],
    ) -> quiche::Result<()> {
        if !self.config_acked {
            return Err(quiche::Error::Done);
        }
        let tc = self.tc.as_ref().unwrap();
        let send_data = (tc.client_sending && self.config_sent) ||
            (!tc.client_sending && !self.config_sent);
        if send_data {
            self.send_data(conn)
        } else {
            self.recv_data(conn, buf)
        }
    }

    pub fn close_after_duration(&self, conn: &mut Connection) -> bool {
        let duration = match (&self.tc, self.start) {
            (Some(tc), Some(start)) => tc
                .duration
                .checked_sub(start.elapsed())
                .unwrap_or(std::time::Duration::ZERO),
            _ => return false,
        };
        if duration > std::time::Duration::ZERO {
            return false;
        }
        debug!(
            "Closing connection after {:?} because --duration={:?} passed",
            self.start.unwrap().elapsed(),
            self.tc.as_ref().unwrap().duration
        );
        match conn.close(true, 0x00, b"kthxbye") {
            // Already closed.
            Ok(_) | Err(quiche::Error::Done) => true,
            Err(e) => panic!("error closing conn: {:?}", e),
        }
    }

    // Called by client to kick off test
    pub fn send_config(
        &mut self, conn: &mut Connection, tc: &TestConfig,
    ) -> quiche::Result<()> {
        trace!("Trying to send test configuration request");

        let msg = serde_json::to_string(&tc).unwrap();
        let written = match conn.stream_send(0, msg.as_bytes(), false) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return Err(From::from(e));
            },
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
    pub fn recv_config_ack(
        &mut self, conn: &mut Connection, buf: &mut [u8],
    ) -> quiche::Result<()> {
        info!("receiving test config ack");

        while let Ok((read, _fin)) = conn.stream_recv(0, buf) {
            trace!(
                "{} received {} bytes from stream {}",
                conn.trace_id(),
                read,
                0
            );

            let tca: TestConfigAck = match serde_json::from_slice(&buf[..read]) {
                Ok(tca) => tca,
                Err(e) => {
                    error!("Serde error: {}", e);
                    return Err(quiche::Error::Done);
                },
            };

            if let Some(e) = tca.error {
                info!("Server returned TestConfig error: {}", e);
                // TODO: close connection
                return Err(quiche::Error::Done);
            }

            self.config_acked = true;
            trace!("config_acked = truconfig_acked = truee")
        }
        Ok(())
    }

    pub fn send_data(&mut self, conn: &mut Connection) -> quiche::Result<()> {
        trace!("sending data");
        loop {
            let written = match conn.stream_send(0, &SEND_DATA, false) {
                Ok(v) => v,

                Err(quiche::Error::Done) => break,

                Err(e) => {
                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return Err(From::from(e));
                },
            };

            trace!("Wrote {} bytes", written);
        }
        Ok(())
    }

    pub fn recv_data(
        &mut self, conn: &mut Connection, buf: &mut [u8],
    ) -> quiche::Result<()> {
        trace!("receiving data");
        while let Ok((read, fin)) = conn.stream_recv(0, buf) {
            trace!(
                "{} received {} bytes from stream {}",
                conn.trace_id(),
                read,
                0
            );

            let stream_buf = &buf[..read];

            trace!(
                "{} stream {} has {} bytes (fin? {})",
                conn.trace_id(),
                0,
                stream_buf.len(),
                fin
            );

            // Drop received data
        }
        Ok(())
    }

    pub fn recv_config(
        &mut self, conn: &mut Connection, buf: &mut [u8],
        password: &Option<String>,
    ) -> quiche::Result<()> {
        debug!("receiving test config");
        let s = 0;
        trace!("Reading from stream {}", s);
        match conn.stream_recv(s, buf) {
            Ok((read, _fin)) => {
                let tc: TestConfig = match serde_json::from_slice(&buf[..read]) {
                    Ok(tc) => tc,
                    Err(e) => {
                        error!("Serde test config error: {}", e);
                        conn.close(true, 0x1, b"failed parsing test config")
                            .unwrap();
                        return Err(quiche::Error::Done);
                    },
                };

                debug!(
                    "Parsed test config: client_sending={}",
                    tc.client_sending
                );

                if !match (password, &tc.password) {
                    (Some(exp), Some(rcvd)) => exp == rcvd,
                    (Some(_), None) => false,
                    (None, _) => true,
                } {
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
                    },
                };

                debug!(
                    "{} wrote TestConfigAck: {} bytes",
                    conn.trace_id(),
                    written
                );
                self.config_acked = true;

                self.tc = Some(tc);
            },
            Err(e) => {
                debug!("stream_recv error: {}", e)
            },
        }

        Ok(())
    }
}
