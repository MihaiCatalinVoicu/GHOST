# `saturating-time` 0.4.0 — GHOST vendored patch (compiled into every target)

**Why this exists (design `docs/design/faza12-transports.md` §12.3, S3-T6 → S3-T7).** `tor-netdoc`
0.46 and `tor-netdir` 0.46 (Arti's directory stack, in every GHOST build) depend on
`saturating-time` 0.4.0. Its lazy `SystemTime`/`Instant` limit discovery (`find_limit` in
`src/internal.rs`) assumes `checked_add`/`checked_sub` return `None` when the result would pass
the representable boundary. **Since Rust 1.98, `SystemTime`'s Windows implementation returns
`Some(unchanged)` for sub-100ns steps at the FILETIME boundary** (100ns granularity; measured on
rustc 1.98.1 windows-msvc: `UNIX_EPOCH - 11644473600s` (intervals 0) `.checked_sub(1..99ns) ==
Some(0)`, `>=100ns == None`). `find_limit` halves its probe down to a sub-100ns step (measured
stuck at 51ns against `res = intervals 0`), never sees `None`, and **spins forever at 100% CPU**.

Because `SaturatingTime::saturating_sub` uses eager `unwrap_or(min_value())`, *every* saturating
op on a `SystemTime` pays that lazy computation — so on Windows every arti consensus parse hangs
inside `Preamble::validity_time_range` → `MdConsensus::parse`, i.e. **arti cannot bootstrap at
all on Windows hosts** (the S3-T6 silence: the bootstrap state machine never advances past the
first successfully downloaded consensus, with and without the PT). On Linux/Android (1ns
granularity divides every `Duration`) the upstream algorithm terminates normally, which is why
the pinned upstream's own unit tests pass in its CI and why the shipped Android client is
unaffected.

**The patch** (marked `GHOST patch (S3-T7)` in `src/internal.rs`, the only functional change):
`find_limit` halves its step whenever `f` reports no movement (`Some(st) == res`), returning at a
stagnant 1ns probe. Termination is provable: every iteration either moves `res` strictly (a
strictly monotone sequence over a finite representable range) or shrinks `step` geometrically
toward 1ns. Behaviour on Linux/Android is byte-for-byte identical to upstream 0.4.0
(`Some(st) == res` never occurs where the granularity divides every `Duration`), so the shipped
path is untouched; on Windows the only change is that the computation terminates with the same
limit value the algorithm was converging to.

## Provenance and pins

| Item | Value |
|---|---|
| Upstream | `saturating-time` 0.4.0, crates.io, MIT OR Apache-2.0 (both license texts verbatim in this directory) |
| crates.io checksum (the pinned baseline's `Cargo.lock` entry) | `802bdbfcca9a239cb46eeaaedea507e37bb13ba1a673762d2e2ef7a9dac63144` |
| GHOST change surface | `src/internal.rs` only — the `find_limit` stagnation arm + `PartialEq` bounds on the two private `find_*` helpers and `find_limit` |
| Measured environment of the bug | rustc 1.98.1 (48a229cea 2026-09-01), x86_64-pc-windows-msvc |
| Upstream status | 0.5.0 carries the identical algorithm (checked) — unfixed upstream at vendoring time; the Rust std Windows behaviour is the recent change |
| Removal condition | drop this patch when the workspace moves to an arti stack whose `saturating-time` no longer has this algorithm, or when std's Windows `checked_sub`/`checked_add` restore the `None` boundary behaviour (re-run the S3-T7 probe in `D:\Forum\.claude\s3\`) |

The upstream README is preserved as `README.upstream.md`. The upstream crate checksum above must
equal the `saturating-time` entry the un-patched lock records; G-T1-style pin checks belong to
the gate slice that adopts this record.
