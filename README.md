quicheperf
----------

QUIC performance testing tool based on [our fork of quiche](https://gitlab.lrz.de/cm/quiche), a QUIC Rust implementation from Cloudflare.

# Setup
Both quiche and quicheperf need to be cloned
```
git clone git@gitlab.lrz.de:cm/quiche.git
git clone git@gitlab.lrz.de:ge36xuy/quicheperf.git
cd quicheperf
cargo build --release --bin quicheperf
```


# Usage
```
Usage: quicheperf [OPTIONS] <COMMAND>

Commands:
  client  Run quicheperf client
  server  Run quicheperf server
  help    Print this message or the help of the given subcommand(s)

Options:
  -p, --password <PASSWORD>
          Password required to start test
      --cc <CONGESTION>
          Set congestion control algorithm of this peer: Reno, CUBIC, or BBR [default: cubic]
      --mp <MULTIPATH>
          Enable or disable multipath (Automatically enabled if more than one local_addr is present) [default: false]
      --scheduler <SCHEDULER>
          Set the multipath scheduler of this peer [possible values: blest, min-rtt]
  -l <LOCAL_ADDRS>
          The local address(es) to connect from [default: 0.0.0.0:0]
      --max-data <MAX_DATA>
          Initial connection-wide flow control limit [default: 25165824]
      --max-stream-data <MAX_STREAM_DATA>
          Initial per-stream flow control limit [default: 1000000]
      --fc-initial-connection-window <FC_INITIAL_CONNECTION_WINDOW>
          The initial connection window [default: 49152]
      --fc-initial-stream-window <FC_INITIAL_STREAM_WINDOW>
          The initial stream window [default: 32768]
      --fc-window-update-threshold <FC_WINDOW_UPDATE_THRESHOLD>
          Set the flow control window update threshold in percent (0-100) [default: 50]
      --fc-autotune-strategy <FC_AUTOTUNE_STRATEGY>
          Set the flow control autotuning strategy [default: reactive]
      --fc-autotune-increase-factor <FC_AUTOTUNE_INCREASE_FACTOR>
          When autotuning, increase the window by this factor [default: 2]
      --fc-reactive-rtt-trigger-factor <FC_REACTIVE_RTT_TRIGGER_FACTOR>
          Reactive autotune if last update within factor * RTT [default: 2]
      --hystart <HYSTART>
          Enable hystart (instead of slow start) [default: true]
  -h, --help
          Print help
  -V, --version
          Print version
```

# Example Usage
```
# Build quicheperf with `cargo build --release --bin quicheperf` and run `./target/release/quicheperf`
# or use cargo wrapper: `cargo run --release --bin quicheperf`

$ cargo run --release --bin quicheperf -- server --cert src/cert.crt --key src/cert.key -l 0.0.0.0:9999 &

$ cargo run --release --bin quicheperf -- client -c 127.0.0.1:9999
SP test for 10s from 0.0.0.0:0->127.0.0.1:9999
| sec | P0 Mbps    | P0 Lost/Total (sp) |
|   0 |       0.01 |     0 /     4 ( 0) |
|   1 |    3643.75 |   590 /338103 ( 0) |
|   2 |    3622.74 |   149 /335461 ( 0) |
|   3 |    3535.78 |     0 /327718 ( 0) |
|   4 |    3442.11 |     0 /319386 ( 0) |
|   5 |    2702.12 |     0 /250840 ( 0) |
|   6 |    2735.19 |    53 /253745 ( 0) |
|   7 |    2627.27 |     0 /243677 ( 0) |
|   8 |    2669.50 |     0 /247587 ( 0) |
|   9 |    2640.25 |   400 /244858 ( 0) |
| Avg |    3011.69 |  1192      0.0426% |
```
