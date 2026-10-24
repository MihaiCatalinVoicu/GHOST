# Staging update mirrors

The two static onion services of the staging deployment, built for Phase 13's close-out so the
update channel can be tested end to end. Each mirror is one container: Tor (a v3 onion service,
key persisted in `/srv/mirrors/{a,b}/tor`) in front of nginx with two listeners on loopback: plain
**HTTP/1.1 on the onion's port 80** (browsers and `ghost-verify`; the design's first-install path —
browsers do not speak HTTP/2 without TLS, D1) and **h2c with prior knowledge on port 443** (the
app's fetch path, D14 — the onion transport is the confidentiality layer).

This is **not** the Phase 14 mirror: real root/release keys, the GHRM format, the transparency log
and the ceremonies are ADR-48…52. Staging serves an equivalent-shaped fixture (versioned directory
with a manifest, a detached signature and an artifact) signed by a throwaway ed25519 key generated
per deployment, so the channel — onion reachability, static serving, manifest fetch, hash/length
binding — is real while the trust root is not.

## Run (on the staging host, ghost-runner)

```sh
mkdir -p /srv/mirrors/{a,b}/{www,tor}
ghost/infra/mirror/make-fixture.sh /srv/mirrors/a/www mirror-a
ghost/infra/mirror/make-fixture.sh /srv/mirrors/b/www mirror-b
docker compose -f ghost/infra/mirror/docker-compose.staging.yml up -d --build
# each container logs its onion hostname; the hostname file is /srv/mirrors/{a,b}/tor/mirror/hostname
```

Verify over Tor from anywhere with a SOCKS proxy (e.g. Tor Browser):

```
curl --socks5-hostname 127.0.0.1:9050 http://<onion>/v1/manifest.json
```
