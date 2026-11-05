# ==============================================================================
# - Original Source: https://github.com/hendrikcech/quicheperf/blob/17bc74ce3593492f568543e03c7cc9e229fca6c7/Dockerfile
# - Modified By:     Yusuf Erdem Nacar
# - Changes:
#   - Builds from this repository alone, with quiche fetched at the commit `Cargo.toml` pins, in `rust:1.98.1-trixie` instead of `rust:1.81.0` with both repositories copied in.
#   - Builds with `--locked` and a pinned `cmake`.
#   - Runs on `debian:trixie-slim` instead of `debian:latest`, with pinned packages: adds iperf3, drops jq, traceroute and netcat-openbsd.
#   - Drops the maintainer label, the PATH override, the generated certificate, the `/qlogs` volume and `QLOGDIR`.
#   - Adds OCI labels from build arguments.
#   - Runs `docker_entrypoint.sh` from `/usr/local/bin` with `proxy-server` as the default role.
# ==============================================================================

FROM rust:1.98.1-trixie AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
      cmake=3.31.6-2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cargo build --release --locked

FROM debian:trixie-slim

ARG IMAGE_VERSION=dev
ARG QUICHEPERF_REVISION=unknown
ARG PROTOTYPE=true

LABEL org.opencontainers.image.title="quicheperf" \
      org.opencontainers.image.description="quicheperf for the 5G testbed's MPQUIC proxy pair, built from the fork's testbed branch: a fixed offered rate (--bitrate), a QUIC packet size cap (--max-udp-payload), the proxy-server's per-path log (--path-log), path statuses from the proxy-client (--status) and the RIC radio feed receiver (--telemetry-listen). One image serves the qp-server, proxy-server and proxy-client roles." \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${QUICHEPERF_REVISION}" \
      org.opencontainers.image.source="https://github.com/yusuferdemnacar/quicheperf" \
      org.opencontainers.image.base.name="debian:trixie-slim" \
      io.github.yusuferdemnacar.5g-testbed.prototype="${PROTOTYPE}" \
      io.github.yusuferdemnacar.5g-testbed.upstream="hendrikcech/quicheperf@17bc74c"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates=20250419+deb13u1 \
      iperf3=3.18-2+deb13u2 \
      iproute2=6.15.0-1 \
      iptables=1.8.11-2 \
      iputils-ping=3:20240905-3 \
      tcpdump=4.99.5-2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/target/release/quicheperf /usr/local/bin/quicheperf
COPY --chmod=0755 docker_entrypoint.sh /usr/local/bin/docker_entrypoint.sh

ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/docker_entrypoint.sh"]
CMD ["proxy-server"]
