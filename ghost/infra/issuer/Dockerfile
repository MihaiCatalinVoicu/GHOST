# GHOST issuer image (Phase 8 design §6.7, §7.1; ADR-26): the ghost-issuer binary, Tor (the
# issuer's v3 onion service, and the SOCKS proxy that carries monerod's peer-to-peer traffic) and
# the pinned Monero release: monerod, monero-wallet-rpc (the view-only wallet) and
# monero-wallet-cli (runbook R5 step 1). docker-compose.stagenet.yml runs this one image as four
# containers, each started by entrypoint.sh with its role; nothing listens outside loopback.
#
# The Monero archive is the linux-x64 entry of infra/issuer/monero-release.pin, the one place of its
# name, URL and SHA-256 (scripts/gates/monero-pin.sh): it is downloaded, checked with sha256sum -c,
# and only then extracted.
#
# Build from the repository root:
#   docker build -f ghost/infra/issuer/Dockerfile -t ghost-issuer-stagenet:local ghost
# The operator tools the issuer host needs (runbooks B1 and R2: reconcile-check and counters-export
# on a database copy) are a separate target and never part of the issuer image:
#   docker build -f ghost/infra/issuer/Dockerfile --target ops -t ghost-issuer-ops:local ghost

FROM rust:1.98.1-bookworm AS build
RUN apt-get update -q && apt-get install -y -q --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p ghost-issuer --bin ghost-issuer --locked

FROM build AS ops-build
RUN cargo build --release -p ghost-issuer-ops --bin ghost-issuer-ops --locked

FROM debian:bookworm-slim AS monero-release
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update -q && apt-get install -y -q --no-install-recommends ca-certificates curl bzip2 && rm -rf /var/lib/apt/lists/*
WORKDIR /monero
COPY infra/issuer/monero-release.pin monero-release.pin
RUN read -r _ platform file sha dir < <(awk '$1 == "archive" && $2 == "linux-x64"' monero-release.pin) \
 && url="$(awk '$1 == "url" {print $2}' monero-release.pin)" \
 && [ "$platform" = linux-x64 ] && [ -n "$file" ] && [ -n "$sha" ] && [ -n "$dir" ] && [ -n "$url" ] \
 && curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$file" "$url$file" \
 && echo "$sha  $file" | sha256sum -c - \
 && mkdir bin \
 && tar -xjf "$file" -C bin --strip-components=1 "$dir/monerod" "$dir/monero-wallet-rpc" "$dir/monero-wallet-cli" \
 && rm "$file"

# The ops service of docker-compose.stagenet.yml runs it without network, capabilities or a
# writable root file system.
FROM debian:bookworm-slim AS ops
COPY --from=ops-build /src/target/release/ghost-issuer-ops /usr/local/bin/ghost-issuer-ops
ENTRYPOINT ["/usr/local/bin/ghost-issuer-ops"]

FROM debian:bookworm-slim
RUN apt-get update -q && apt-get install -y -q --no-install-recommends tor && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ghost-issuer \
    && useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin monero
COPY --from=build /src/target/release/ghost-issuer /usr/local/bin/ghost-issuer
COPY --from=monero-release /monero/bin/ /usr/local/bin/
COPY infra/issuer/torrc /etc/tor/torrc
COPY infra/issuer/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
    && mkdir -p /var/lib/tor/state /var/lib/tor/ghost-issuer /var/lib/monerod /var/lib/monero-wallet \
       /var/lib/ghost-issuer/data /var/lib/ghost-issuer/export /var/lib/ghost-issuer/sealed-keys \
       /etc/ghost /etc/ghost-issuer
USER root
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
