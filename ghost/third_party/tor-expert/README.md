# GHOST Phase 12 — the loopback harness's Tor (expert bundle)

The §12.3 loopback harness (`ghost-client-core/net/tests/pt_loopback.rs`, slice S3) drives a
real Tor daemon as the loopback relay (ORPort + one throwaway v3 onion service). This
directory pins that daemon the way `ghost/infra/issuer/monero-release.pin` pins Monero and
`ghost/third_party/lyrebird/` pins lyrebird: one recorded artifact, hash-verified before use.

## Why the expert bundle and not the WSL tor

The harness runs where the Rust test runs (the Windows host for the S3 measurement, a Linux
self-hosted runner in CI). Shelling out to a WSL distro from a cargo test would make the test
depend on a distro name, WSL's localhost forwarding and a second pinned environment. The
expert bundle is self-contained: `tor.exe` plus its data files, no installer. The pinned
build's tor reports **0.4.9.11**, the same version the S0 evidence measured in WSL
Ubuntu-24.04, so the loopback numbers stay comparable across the two hosts.

## Layout

- `pins.env` — the only file a bump edits: the bundle version, both per-OS tarball names and
  SHA-256 pins (cross-checked against torproject.org's `sha256sums-unsigned-build.txt` at pin
  time), and the daemon version the harness asserts before trusting a fixture.
- `FETCH.sh` — downloads the pinned tarball for the current OS, `sha256sum -c` against the
  pin **before** extraction, unpacks under `.cache/` (git-ignored), and refuses a fixture
  whose `tor --version` does not report the pinned version. Idempotent.
- `.cache/` — fetch output, never committed (G-T1 fails on a committed copy).

## Use

```sh
bash ghost/third_party/tor-expert/FETCH.sh     # once per host; the harness needs it
```

The harness resolves the daemon from `$GHOST_PT_TOR`, else from this directory's `.cache/`.
It is a **test fixture**: the expert bundle ships under Tor's licence (GPL-3.0 for tor
itself; see the bundle's `docs/`), it is never linked into, embedded in, or shipped with the
APK, and the shipped app has no Tor binary of its own (arti is the Tor client).
