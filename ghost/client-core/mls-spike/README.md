# Phase 10 slice S0: OpenMLS evidence spike

**Evidence tooling, not product code.** Nothing here is linked into a shipped or host library,
and nothing here is a source for `ghost-client-mls`: slice S2 re-implements what it needs under
review with the pins of design §3.2. The results are in
[`docs/design/faza10-s0-evidence.md`](../../../docs/design/faza10-s0-evidence.md) (checks V10-1 …
V10-14 of `docs/design/faza10-forum.md` §14, row S0).

This is a virtual workspace of its own (`[workspace]`, own `Cargo.lock`), outside the ghost
workspace — the precedent of `client-core/dm-spike` — so the product lock, the client allowlist,
the crypto pins and `cargo deny` of the ghost workspace are untouched. Its `core/src` passes the
production-path gates that scan `client-core/**/src` (`anti-placeholder.sh`, `no-logging.sh`);
printing happens only in `core/tests`, `core/examples` and `kat/tests`.

| Path | What |
|---|---|
| `core/` (`ghost-mls-spike`) | `GhostKv` (the value-semantics storage adapter of §3.4: change-set, scopes, wrapping, `added_at` day rewrite, an optional split of past epochs), the provider composition and pseudonym signer (§3.3), GHOST's extensions and AAD formats (§5.3–§5.5, §19.2), a channel harness over the real OpenMLS 0.9.0, the seal's size rule, the seeded getrandom backend (feature `det`) |
| `core/tests/` | V10-4 sizes, V10-5 adapter cost, V10-8 bootstrap, V10-10 host timings, V10-11 lifetimes, V10-13 extensions and AAD, V10-9 PQ suites (feature `pq`) |
| `core/examples/det_world.rs` | V10-6: a scripted world under the process-global seeded stream |
| `core/examples/device_probe.rs` | V10-10/R-9: a native executable for Android, run with `adb` |
| `kat/` (`ghost-mls-spike-kat`) | V10-12: the MLS WG passive-client vectors through `GhostKv`; the only crate here with `openmls/test-utils` |
| `size-probe/size-probe.patch` | V10-1, V10-3, V10-7: links a probe crate (the spike's sources by `#[path]`) into `ghost-client-net`, plus a stub for openmls's optional `openmls_sqlite_storage` without which the ghost lock does not resolve (evidence §1) |
| `scripts/` | the build, fetch and crawl scripts named below |
| `vectors/` | fetched test vectors (not committed; `.gitignore`) |

## Commands

From this directory (`ghost/client-core/mls-spike`), Git Bash, with a target directory outside
`D:` (the evidence used `C:\Users\mihai\AppData\Local\Temp\ghost-target-p10-s0`):

```
export CARGO_TARGET_DIR='C:\Users\mihai\AppData\Local\Temp\ghost-target-p10-s0'

# V10-4, V10-5, V10-8, V10-10, V10-11, V10-13 (host, release)
cargo test --release -p ghost-mls-spike -- --nocapture --test-threads=1
#   the 100-member tests take ~20 min (value semantics at every call); run one with e.g.
cargo test --release -p ghost-mls-spike --test v10_04_sizes v10_04_small_class_cap_32 -- --nocapture

# V10-9 (OpenMLS's X-Wing suites; Q2 evidence only)
cargo test --release -p ghost-mls-spike --features pq --test v10_09_pq -- --nocapture --test-threads=1

# V10-6 (determinism): two processes per configuration, compare the output
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\det" RUSTFLAGS='--cfg getrandom_backend="custom"' \
  cargo build --release --example det_world --features det -p ghost-mls-spike
"$CARGO_TARGET_DIR\\det\\release\\examples\\det_world.exe" 01 1   # 1 rayon worker; twice, diff
"$CARGO_TARGET_DIR\\det\\release\\examples\\det_world.exe" 01 0   # rayon default pool; twice, diff
GHOST_SPIKE_NO_DAY_REWRITE=1 "$CARGO_TARGET_DIR\\det\\release\\examples\\det_world.exe" 01 1   # twice, diff

# V10-12 (needs network once: the vectors at openmls commit 3a3e35de…, verified by git blob id)
bash scripts/v10-12-fetch-vectors.sh
cargo test --release -p ghost-mls-spike-kat -- --nocapture

# V10-1, V10-3, V10-7 (Android; needs ANDROID_NDK_HOME, cargo-ndk 4.1.2, both Android targets)
git -C ../../.. apply ghost/client-core/mls-spike/size-probe/size-probe.patch   # from the repo root
cargo tree --offline -p ghost-client-net -e normal --target aarch64-linux-android --features mls-probe  # (in ghost/)
cargo deny --offline check                                                                          # (in ghost/)
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out> mls-probe
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out> ""          # probe without MLS
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out> mls-probe-pq
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out> mls-probe --unstripped
git -C ../../.. apply -R ghost/client-core/mls-spike/size-probe/size-probe.patch && git -C ../.. checkout Cargo.lock
rm -rf ../mls-probe
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out> ""          # baseline (unpatched)

# V10-2: a fresh RustSec database outside the shared cache
git clone --depth 1 https://github.com/rustsec/advisory-db <db>
cargo audit --db <db> --no-fetch --file ../../Cargo.lock    # with the patch applied

# V10-10 on the x86_64 emulator (AVD ghost-dm-api29 on port 5574)
cargo ndk -t x86_64 -t arm64-v8a build --release --example device_probe -p ghost-mls-spike
adb -s emulator-5574 push <target>/x86_64-linux-android/release/examples/device_probe /data/local/tmp/
adb -s emulator-5574 shell /data/local/tmp/device_probe 20    # and 100

# V10-14: scheduled-run job history (gh authenticated)
bash scripts/v10-14-nightly.sh 14 > jobs.tsv
```

Fate: deleted when `ghost-client-mls` and `ghost-client-mls-kat` land (slice S2), except what the
S2 gates take over (the size probe method, the nightly crawl), which moves to `ghost/scripts/`.
