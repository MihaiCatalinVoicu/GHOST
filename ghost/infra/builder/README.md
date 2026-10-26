# ghost-builder

The pinned build environment for release ceremonies (docs/design/faza14-distribution.md §6,
gate G-D2). Recipe A (`scripts/release/build-release.sh`) must run inside this image so
every environment — A, B, C and the owner's independent rebuild (RK1) — shares identical
toolchain bytes, not just version numbers.

- `Dockerfile` — ubuntu 24.04 pinned by digest; apt versions pinned; rustup bootstrap
  (channel comes from the checkout's `rust-toolchain.toml`, i.e. from the tag being built).
- `pins.txt` — the pin list a ceremony verifies before building; each built image appends
  its image ID.
- `run-in-image.sh` — runs recipe A inside the image: repo mounted read-only, output dir
  on the host, cargo registry mounted as an offline seed (`CARGO_NET_OFFLINE=true` in
  build-release.sh).

Build the image:

```sh
docker build -t ghost-builder:24.04-1 infra/builder
docker image inspect ghost-builder:24.04-1 --format '{{.Id}}' >> infra/builder/pins.txt
```

Offline seed: `build-release.sh` sets `CARGO_NET_OFFLINE=true`, so the registry mounted at
`/opt/cargo/registry` must already contain every `.crate` the tag's `Cargo.lock` pins
(`cache/` + `src/`) and a current index. A partial seed fails loudly at the first missing
crate rather than resolving differently — that is the point. On a fresh machine, populate
the seed once from a machine that has built the same lock (merge `cache/`, `src/`, `index/`
of the two registries; the S4 verification used exactly such a merged seed).

The S4 self-check (`selfcheck.sh`) builds the current tag twice inside the image and compares
`SHA256SUMS`; it needs the seed above plus a `builder-selfcheck` tag in the mounted repo.

Bump policy: a toolchain change is a new image tag (`24.04-<n+1>`), a new pins.txt entry,
and a re-measured A/B equality before any ceremony uses it. Never retag in place.
