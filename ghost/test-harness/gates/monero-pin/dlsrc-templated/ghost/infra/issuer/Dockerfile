FROM debian:bookworm-slim
ARG MONERO_VERSION=v0.18.4.0
ARG MONERO_SHA=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
RUN curl -fsSLO "https://dlsrc.getmonero.org/cli/monero-linux-x64-${MONERO_VERSION}.tar.bz2" \
 && echo "${MONERO_SHA}  monero-linux-x64-${MONERO_VERSION}.tar.bz2" | sha256sum -c -
