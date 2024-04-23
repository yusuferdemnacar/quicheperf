# Build from parent folder:
# docker build -t quicheperf . -f quicheperf/Dockerfile

FROM rust:1.77.0 as build

WORKDIR /build

RUN apt-get update && apt-get install -y cmake && \
    rm -rf /var/lib/apt/lists/*

COPY ./quicheperf ./quicheperf/
COPY ./quiche ./quiche/

RUN cargo build --release --manifest-path quicheperf/Cargo.toml

##
## quiche-base: quiche image for apps
##
FROM debian:latest

LABEL org.opencontainers.image.authors="Hendrik Cech <hendrik.cech@tum.de>"

RUN apt-get update && apt-get install -y ca-certificates iproute2 iptables jq iputils-ping traceroute tcpdump && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build \
     /build/quicheperf/target/release/quicheperf \
     /usr/local/bin/
ENV PATH="/usr/local/bin/:${PATH}"

COPY --from=build \
     /build/quicheperf/docker_entrypoint.sh \
     /
RUN chmod +x /docker_entrypoint.sh

# Create a TLS key for the server
RUN openssl req -x509 -newkey rsa:4096 -keyout /key.pem -out /cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"

# Create volume for qlogs
VOLUME ["/qlogs"]

ENV RUST_LOG=info
ENV QLOGDIR=/qlogs

ENTRYPOINT [ "./docker_entrypoint.sh" ]
CMD ["proxy-server", "--cert", "/cert.pem", "--key", "/key.pem", "--tun", "mp0", "--mp", "true", "-l", "0.0.0.0:8000"]
