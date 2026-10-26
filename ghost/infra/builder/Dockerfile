# ghost-builder — the pinned build environment for release ceremonies
# (docs/design/faza14-distribution.md §6, gate G-D2). Every recipe-A build — environments
# A/B/C and the owner's independent rebuild (RK1 step 2) — runs inside this image so the
# toolchain bytes are identical, not merely version-compatible. The repo's rust-toolchain.toml
# pins the Rust channel; this file pins everything underneath it.
#
# Bump policy: never retag in place. A toolchain change is a new pins.txt entry, a new image
# tag (24.04-<n+1>), and a re-measurement of the A/B equality before any ceremony uses it.
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac

ENV DEBIAN_FRONTEND=noninteractive
# Exact apt versions as of the base-image snapshot; pins.txt records them and the digests
# of every layer (docker image inspect). gcc/glibc versions are part of the release
# environment exactly like rustc's.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential=12.10ubuntu1 \
      ca-certificates=20260816ubuntu0.24.04.1 \
      curl=8.5.0-2ubuntu10.16 \
      git=1:2.43.0-1ubuntu7.4 \
      pkg-config=1.8.1-2build1 \
      protobuf-compiler=3.21.12-8.2ubuntu0.4 \
    && rm -rf /var/lib/apt/lists/*

# Rust is installed for channel "none" here; the checkout's rust-toolchain.toml pins the
# channel (1.98.1) and components, so a build of any tag gets exactly that tag's toolchain.
# The registry is populated at run time: run-in-image.sh mounts a seed cache and
# build-release.sh sets CARGO_NET_OFFLINE=true, so no build step reaches the network and
# no dependency can resolve differently than the tag's Cargo.lock.
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain none --profile minimal \
    && chmod -R a+w /opt/cargo /opt/rustup
ENV PATH=/opt/cargo/bin:$PATH

WORKDIR /src
