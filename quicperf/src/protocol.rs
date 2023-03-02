use serde::{Serialize, Deserialize};

pub const SEND_DATA: [u8; 65507] = [0; 65507];

#[derive(Serialize, Deserialize, Debug)]
pub struct TestConfig {
    client_sending: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestConfigAck {
    error: Option<String>,
}

pub struct Protocol {
    pub config_sent: bool,
    pub config_acked: bool,
}

impl Protocol {
    pub fn new() -> Self {
        Self { config_sent: false, config_acked: false }
    }

    // Called by client to kick off test
    pub fn send_config(&mut self, conn: &mut quiche::Connection) -> quiche::Result<()> {
        trace!("Trying to send test configuration request");

        let tc = TestConfig { client_sending: true };
        let msg = serde_json::to_string(&tc).unwrap();
        let written = match conn.stream_send(0,msg.as_bytes(), false) {
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

        Ok(())
    }

    // Called by client after sending TestConfig
    pub fn recv_config_ack(&mut self, conn: &mut quiche::Connection, buf: &mut [u8]) -> quiche::Result<()> {
        warn!("receiving test config ack");

        while let Ok((read, fin)) = conn.stream_recv(0, buf) {
            trace!("{} received {} bytes from stream {}", conn.trace_id(), read, 0);

            let tca: TestConfigAck = match serde_json::from_slice(&buf[..read]) {
                Ok(tca) => tca,
                Err(e) => {
                    error!("Serde error: {}", e);
                    return Err(quiche::Error::Done);
                }
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

    pub fn send_data(&mut self, conn: &mut quiche::Connection) -> quiche::Result<()> {
        warn!("sending data");
        loop { 
            let written = match conn.stream_send(0,&SEND_DATA, false) {
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

    pub fn recv_data(&mut self, conn: &mut quiche::Connection, buf: &mut [u8]) -> quiche::Result<()> {
        warn!("receiving data");
        while let Ok((read, fin)) = conn.stream_recv(0, buf) {
            trace!("{} received {} bytes from stream {}", conn.trace_id(), read, 0);

            let stream_buf = &buf[..read];

            trace!("{} stream {} has {} bytes (fin? {})", conn.trace_id(), 0, stream_buf.len(), fin);

            // Drop received data
        }
        Ok(())
    }

    pub fn recv_config(&mut self, conn: &mut quiche::Connection, buf: &mut [u8]) -> quiche::Result<()> {
        debug!("receiving test config");

        for s in conn.readable() {
            trace!("Reading from stream {}", s);
            match conn.stream_recv(s, buf) {
                Ok((read, fin)) => {
                    let tc: TestConfig = match serde_json::from_slice(&buf[..read]) {
                        Ok(tc) => tc,
                        Err(e) => {
                            error!("Serde test config error: {}", e);
                            conn.close(true, 0x1, b"failed parsing test config").unwrap();
                            return Err(quiche::Error::Done);
                        }
                    };

                    debug!("Parsed test config: client_sending={}", tc.client_sending);

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

                    debug!("{} wrote TestConfigAck: {} bytes", conn.trace_id(), written);
                    self.config_acked = true;
                },
                Err(e) => { debug!("stream_recv error: {}", e) }
            }
        }

        Ok(())
    }
}