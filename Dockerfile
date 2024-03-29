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

RUN apt-get update && apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build \
     /build/quicheperf/target/release/quicheperf \
     /usr/local/bin/

RUN openssl req -x509 -newkey rsa:4096 -keyout /key.pem -out /cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"

ENV PATH="/usr/local/bin/:${PATH}"
ENV RUST_LOG=info

ENTRYPOINT [ "quicheperf" ]
