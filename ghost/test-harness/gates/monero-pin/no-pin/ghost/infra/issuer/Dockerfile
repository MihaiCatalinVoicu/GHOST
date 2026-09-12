FROM debian:bookworm-slim
COPY infra/issuer/monero-release.pin /tmp/monero-release.pin
RUN read -r _ _ file sha dir < <(awk '$1 == "archive" && $2 == "linux-x64"' /tmp/monero-release.pin) \
 && curl -fsSL -o "/tmp/$file" "https://downloads.getmonero.org/cli/$file" \
 && echo "$sha  /tmp/$file" | sha256sum -c -
