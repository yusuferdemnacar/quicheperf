quicheperf
----------

QUIC performance testing tool based on [our fork of quiche](https://github.com/hendrikcech/quiche), a QUIC Rust implementation from Cloudflare.

# Building

quicheperf is built on a custom fork of quiche, Cloudflare's QUIC implementation in Rust, hosted at [github.com/hendrikcech/quiche](https://github.com/hendrikcech/quiche) (branch `frame-scheduler`).
`Cargo.toml` declares `quiche` and `qlog` as git dependencies of that repository, so a plain build fetches the fork from GitHub automatically; you do **not** need to clone quiche yourself:

```
git clone git@github.com:hendrikcech/quicheperf.git
cd quicheperf
cargo build --release      # ./target/release/quicheperf
```

## Building against a local quiche checkout

If you want to change quiche and have quicheperf pick up those changes, build against a **local** clone of quiche instead of the GitHub version.
Clone it next to quicheperf (the paths below assume this sibling layout).
The `--recurse-submodules` argument also pulls the vendored BoringSSL quiche dependency:

```
git clone --recurse-submodules git@github.com:hendrikcech/quiche.git
# working-copy/
#   quiche/       <- your checkout; may contain uncommitted changes
#   quicheperf/
```

Your uncommitted changes in `../quiche` are picked up by both methods below.

### With cargo (no Nix)

Create `quicheperf/.cargo/config.toml` with a `[patch]` that redirects the quiche and qlog dependencies to your local checkout:

```toml
[patch."https://github.com/hendrikcech/quiche"]
quiche = { path = "../quiche/quiche" }
qlog = { path = "../quiche/qlog" }
```

Then build as usual:

```
cargo build --release
```

Cargo now compiles against `../quiche` (this file is gitignored, so it stays a local override).
Delete it to go back to building the GitHub version.

### With `nix build`

`nix build` uses the GitHub quiche by default.
To build against your local checkout instead, override the `quiche` flake input for that invocation:

```
nix build --override-input quiche 'git+file:../quiche?submodules=1'   # -> ./result/bin/quicheperf
```

Please note:
- **New** files in quiche must be `git add`-ed to be visible (untracked files are excluded). Existing files do not need to be staged to be picked up.
- Do **not** use `path:../quiche`: it ignores `.gitignore` and copies `target/` into the store on every build.

To make the local checkout the default (no flag needed), edit the `quiche` input in `flake.nix` to `url = "git+file:../quiche?submodules=1"`.


# Usage
```
Usage: quicheperf [OPTIONS] <COMMAND>

Commands:
  client        Run quicheperf client
  server        Run quicheperf server
  proxy-client  Run proxy client
  proxy-server  Run proxy server
  help          Print this message or the help of the given subcommand(s)

Options:
  -p, --password <PASSWORD>
          Password required to start test
      --cc <CONGESTION>
          Set congestion control algorithm of this peer: Reno, CUBIC, or BBR [default: cubic]
      --mp <MULTIPATH>
          Enable or disable multipath (Automatically enabled if more than one local_addr is present) [default: false]
      --scheduler <SCHEDULER>
          Set the multipath scheduler of this peer [possible values: blest, min-rtt, round-robin]
  -l <LOCAL_ADDRS>
          The local address(es) to connect from. Must include a port (port 0 -> free port chosen automatically). Also accepts the name of a network interface (with or without port) to infer the address from [default: [::]:0]
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

# Environment Variables
- `QLOGDIR`: specify a path where each QUIC connection will be logged to a file in the [qlog](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/) format.
- `SSLKEYLOGFILE`: if this variable is set, the TLS secrets are logged this file; useful for debugging with Wireshark.

# Example Usage: Throughput Test

```
# Build quicheperf with `cargo build --release --bin quicheperf` and run `./target/release/quicheperf`
# or use cargo wrapper: `cargo run --release --bin quicheperf`

$ cargo run --release  -- server --cert src/cert.crt --key src/cert.key -l 0.0.0.0:9999 &

$ cargo run --release -- client -c 127.0.0.1:9999
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
