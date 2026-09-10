# GHOST relay image: the relay binary plus a Tor daemon exposing it as a v3 onion service (ADR-01).
# The relay listens on loopback only; the only way in is the onion address printed at first start.
# Build from the repository root:  docker build -f ghost/infra/relay/Dockerfile -t ghost-relay ghost

FROM rust:1.98.1-bookworm AS build
RUN apt-get update -q && apt-get install -y -q --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p ghost-relay-node --locked

FROM debian:bookworm-slim
RUN apt-get update -q && apt-get install -y -q --no-install-recommends tor ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /var/lib/ghost --create-home ghost
COPY --from=build /src/target/release/ghost-relay /usr/local/bin/ghost-relay
COPY infra/relay/torrc /etc/tor/torrc
COPY infra/relay/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && mkdir -p /var/lib/tor/ghost-relay && chown -R debian-tor:debian-tor /var/lib/tor
VOLUME ["/var/lib/ghost", "/var/lib/tor/ghost-relay"]
USER root
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
