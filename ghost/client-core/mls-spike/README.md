# Phase 10 slice S0: OpenMLS evidence spike

**Evidence tooling, not product code.** Nothing here is linked into a shipped or host library,
and nothing here is a source for `ghost-client-mls`: slice S2 re-implements what it needs under
review with the pins of design §3.2. The results are in
[`docs/design/faza10-s0-evidence.md`](../../../docs/design/faza10-s0-evidence.md) (checks V10-1 …
V10-14 of `docs/design/faza10-forum.md` §14, row S0; the review pass is its Appendix C, and the
corrections S0-1 … S0-18 are folded into the design's §19.26).

This is a virtual workspace of its own (`[workspace]`, own `Cargo.lock`), outside the ghost
workspace — the precedent of `client-core/dm-spike` — so the product lock, the client allowlist,
the crypto pins and `cargo deny` of the ghost workspace are untouched. Its `core/src` passes the
production-path gates that scan `client-core/**/src` (`anti-placeholder.sh`, `no-logging.sh`);
printing happens only in `core/tests`, `core/examples` and `kat/tests`. Since the review pass the
tests **assert** the numbers the evidence quotes (golden sizes, outcomes, replay totals); only
V10-10's timings, which bound nothing, are printed without assertion.

| Path | What |
|---|---|
| `core/` (`ghost-mls-spike`) | `GhostKv` (the value-semantics storage adapter of §3.4: change-set, scopes, wrapping, `added_at` day rewrite, an optional split of past epochs into one row each), the provider composition and pseudonym signer (§3.3), GHOST's extensions and AAD formats (§5.3–§5.5, §19.2), a channel harness over the real OpenMLS 0.9.0, the seal's size rule, the seeded getrandom backend (feature `det`) |
| `core/tests/v10_04_sizes.rs` | V10-4: commit, Welcome and post sizes at both caps; blank, populated, 64- and 128-leaf trees; thresholds; the canonical KeyPackage (395 B); worst Welcomes (batch and one joiner); leaf inflation by self-updates |
| `core/tests/v10_05_adapter.rs` | V10-5: rows, change-sets and medians of 9 per call at 0/2/8/64 retained past epochs, unsplit and split; the 53 scoped methods; split = unsplit on late posts |
| `core/tests/v10_08_bootstrap.rs` | V10-8: the bootstrap in the Welcome's GroupInfo, signature corruption, exported GroupInfos, a forged Welcome and the committers anchor |
| `core/tests/v10_09_pq.rs` | V10-9 (feature `pq`): 0x004D/0x004E/0x004F with the libcrux provider |
| `core/tests/v10_10_timings.rs` | V10-10: host timings (medians of 15), the retention effect |
| `core/tests/v10_11_lifetimes.rs` | V10-11: KeyPackage lifetimes on the host clock, received Adds, error ordering, the span, joins |
| `core/tests/v10_13_ext_aad.rs` | V10-13: `refresh_epoch`, `GhostKpBind`, AAD round trips |
| `core/examples/det_world.rs` | V10-6: a scripted world under the process-global seeded stream (`GHOST_SPIKE_DAY` sets the virtual day) |
| `core/examples/device_probe.rs` | V10-10/R-9: a native executable for Android, run with `adb` |
| `kat/` (`ghost-mls-spike-kat`) | V10-12: the MLS WG passive-client vectors through `GhostKv` (configurations: OpenMLS's default join retention of no past epoch, as in the first run; 16 past epochs unsplit; 16 split); the only crate here with `openmls/test-utils` |
| `size-probe/size-probe.patch` | V10-1, V10-3, V10-7: links a probe crate (the spike's sources by `#[path]`) into `ghost-client-net`, plus a stub for openmls's optional `openmls_sqlite_storage` without which the ghost lock does not resolve (evidence §1) |
| `scripts/` | the build, symbol, determinism, fetch, crawl and aggregation scripts named below |
| `vectors/` | fetched test vectors (not committed; `.gitignore`) |
| `core/tests/r10d_s0_12_lifetimes.rs` | round 10d (design §19.27): the lifetime **refusal branch** hides the sender and the proposals; the **constant lifetime** `[0, 2⁶⁴ − 1]` (still 395 B) is never refused |
| `core/tests/r10d_s0_15_anchor.rs` | round 10d (design §19.27): a removed committer's fresh-group forgery passes the anchor comparison (and, round 10e, fails §5.3's leaf rule); the **set** vs ordered committers digest; the anchor **pre-check** cost before `JoinBuilder::build()` |
| `core/tests/r10d_password.rs` | round 10d (design §19.28, as corrected by §19.29): the RFC 9106 §5.3 Argon2id vector, host timings per profile (p = 1 and p = 4), and `ChannelInviteV2` **exactly as specified** (`core/tests/support/invite_v2.rs`: 335 B for every kind and name, what a leaked link shows, the refusals); adds `argon2` 0.6.0 as a **dev-dependency** of this workspace only |
| `core/tests/r10e_protocol.rs` | round 10e (design §19.29): round 10d's lifetime rule forks honest members and lets any member freeze a channel, the constant-lifetime rule converges; a removed committer's fork of the real group passes the anchor and §5.3 and stays live (join and rejoin); the rejoin anchor is the signature only |
| `core/tests/r10e_password.rs` | round 10e (design §19.29): the `pw_version` admission check (round 10d's vs the corrected one), a sponsor that never knew the password, Argon2id floors as OWASP pairs, the offline guessing rate of a leaked link |
| `core/tests/support/invite_v2.rs` | the `ChannelInviteV2` construction shared by the two password probes (a `#[path]` module, not a test target) |

## Commands

From this directory (`ghost/client-core/mls-spike`), Git Bash, with a target directory outside
`D:` (the evidence used `C:\Users\mihai\AppData\Local\Temp\ghost-target-p10-s0`):

```
export CARGO_TARGET_DIR='C:\Users\mihai\AppData\Local\Temp\ghost-target-p10-s0'

# V10-4, V10-5, V10-8, V10-10, V10-11, V10-13 (host, release)
cargo test --release -p ghost-mls-spike -- --nocapture --test-threads=1
#   the 100-member populated tests take ~20 min (value semantics at every call); run one with e.g.
cargo test --release -p ghost-mls-spike --test v10_04_sizes v10_04_wide_trees_at_the_small_cap -- --nocapture

# V10-9 (OpenMLS's X-Wing suites; Q2 evidence only)
cargo test --release -p ghost-mls-spike --features pq --test v10_09_pq -- --nocapture --test-threads=1

# V10-6 (determinism): builds det_world with the custom getrandom backend, two processes per
# configuration (1 worker, a second seed, rayon's pool, no day rewrite), prints identical/differ
bash scripts/v10-06-determinism.sh <out-dir>

# V10-12 (needs network once: the vectors at openmls commit 3a3e35de…, verified by git blob id)
bash scripts/v10-12-fetch-vectors.sh
cargo test --release -p ghost-mls-spike-kat -- --nocapture

# V10-1, V10-3, V10-7 (Android; needs ANDROID_NDK_HOME, cargo-ndk 4.1.2, both Android targets).
# Build in a scratch copy of the committed tree (git archive), never in a working tree with
# uncommitted spike edits: the probe compiles the spike's sources (evidence §3, finding H5).
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out-base> ""                   # baseline (unpatched)
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out-base-u> "" --unstripped    # baseline, unstripped
git apply ghost/client-core/mls-spike/size-probe/size-probe.patch                                              # (in the copy's root)
cargo tree --offline -p ghost-client-net -e normal --target aarch64-linux-android --features mls-probe          # (in ghost/)
cargo deny --offline check                                                                                      # (in ghost/)
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out-nofeat> ""                  # probe without MLS
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out-mls> mls-probe
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out-pq> mls-probe-pq
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android" bash scripts/v10-03-size-build.sh <out-mls-u> mls-probe --unstripped
CARGO_TARGET_DIR="$CARGO_TARGET_DIR\\android2" bash scripts/v10-03-size-build.sh <out-t12> mls-probe            # T12: fresh target dir, compare SHA-256
bash scripts/v10-03-symbols.sh <out-base-u> <out-mls-u> 25                                                      # size delta by crate, both ABIs

# V10-2: a fresh RustSec database outside the shared cache
git clone --depth 1 https://github.com/rustsec/advisory-db <db>
cargo audit --db <db> --no-fetch --file ../../Cargo.lock    # with the patch applied
gh api repos/openmls/openmls/security-advisories            # OpenMLS is not in RustSec; also celabshq/hpke-rs, celabshq/libcrux

# V10-10 on the x86_64 emulator (AVD ghost-dm-api29 on port 5574)
cargo ndk -t x86_64 -t arm64-v8a build --release --example device_probe -p ghost-mls-spike
adb -s emulator-5574 push <target>/x86_64-linux-android/release/examples/device_probe /data/local/tmp/
adb -s emulator-5574 shell /data/local/tmp/device_probe 20    # and 100

# V10-14: every run of every trigger since a date, then the aggregation (gh authenticated; crawl
# only after the last night of interest has ended). v10-14-nightly.sh is the first run's
# schedule-only crawl, kept to reproduce its table.
bash scripts/v10-14-crawl.sh 2026-09-14 > jobs-all.tsv
gawk -f scripts/v10-14-aggregate.awk -v FROM=2026-09-17 -v TO=2026-09-26 jobs-all.tsv
```

Fate: deleted when `ghost-client-mls` and `ghost-client-mls-kat` land (slice S2), except what the
S2 gates take over (the size probe method, the occupancy crawl), which moves to `ghost/scripts/`.
