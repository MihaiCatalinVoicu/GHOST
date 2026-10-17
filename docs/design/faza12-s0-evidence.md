# GHOST Phase 12, slice S0: transports evidence (V-T checks)

| Field | Value |
|---|---|
| Design | `docs/design/faza12-transports.md` (revision 1, branch basis `16e1a3da`, approved by owner directive 2026-10-17), §12.1 checks V-T1 … V-T8, §14 slice S0, Appendix C |
| Scope of this document | every V-T check of §12.1 run where this workstation can run it; the checks that need product code that does not exist yet (arti's `pt-client` wiring is S1) are stated as partial, with exactly what was measured and what remains |
| Dates | 2026-10-17 (single session: pin reality, toolchain fetch, double builds, ptmgr read, emulator probes, loopback measurement) |
| Branch | `p12-s0` (worktree of `D:/Forum`), base `bed70a7a`; **no commit made — the lead reviews and commits** |
| Toolchain (this session) | Go 1.26.0 (`go1.26.0.windows-amd64.zip`, SHA-256 `9bbe0fc6…d07d4`, verified against go.dev's release JSON), unpacked at `D:\Forum\.claude\toolchains\go`; Android NDK 30.0.16248370 (the `build-native.sh` NDK); tor 0.4.9.11-0ubuntu0.24.04.1 (Ubuntu 24.04 apt package, WSL2 `Ubuntu-24.04`); tcpdump 4.99.x (same WSL) |
| Emulators | `ghost-dm-api35` (`sdk_phone64_x86_64`, API 35, x86_64, userdebug) and `ghost-dm-api29` (`sdk_phone_x86_64`, API 29, x86_64, userdebug), both booted `-read-only -no-boot-anim -no-audio`; no `adb root` used for the probe |
| Host | Windows 11 Pro, Intel Core Ultra 9 275HX; the loopback half runs inside WSL2 Ubuntu-24.04 (same machine) |
| Work area | `D:\Forum\.claude\s0\` — clone, scripts, logs, built binaries, pcap (scratch; nothing here is product code). Draft `BUILD.sh`/`SHA256SUMS`/`pins.env` for the lead sit untracked in `ghost/third_party/lyrebird/` |
| Status | Evidence for the lead and the owner. **OA-3 fired at S0 (§4); RESOLVED in this document's §10** — the Q-S-T1(b) pruned tree was applied as an owner-default (pending the owner's written confirmation), the pruned build measures within both provisional budgets, and S1 is unblocked. |

**How to read.** One section per check, numbered like the design's §12.1: the question, the method, the measured results, a verdict. A verdict is **CONFIRMS** (the design's assumption holds as written, possibly with a precision), **CORRECTS** (it does not hold as written; the correction says which), **PARTIAL** (this workstation measured what S0 can measure; the remainder names the slice that finishes it) or **FIRED** (a design tripwire, here OA-3 on the size budget). Normative corrections are numbered S0-T1 … S0-T7 in check order and listed in §0.3; owner questions raised are Q-S-T1 … Q-S-T4 in §0.4. Appendix C updates (verified vs assumed) are in §9. "§n" without a document name means `faza12-transports.md`. All hashes are SHA-256.

---

## 0. Summary

### 0.1 Verdicts

| Check | Verdict | In one line |
|---|---|---|
| V-T1 | CONFIRMS (2 precisions) | lyrebird tag `0.9.0` = commit `89d54872…`, PGP-signed, BSD-3-Clause; one binary carries obfs4 + webtunnel client **and** server; server mode is env-driven (TOR_PT_*), not flag-driven |
| V-T2 | CONFIRMS | no maintained Rust obfs4/webtunnel client exists at the pin date: the only `obfs4` crate is a single 0.1.0-alpha.1 (2024-09); no `webtunnel` crate at all |
| V-T3 | CONFRECTS → CONFIRMS + S0-T1 | the managed server/client invocations work exactly as pt-spec's env protocol; the design's "-orbited-style flags" expectation is wrong for 0.9.0 — flags are only `-version -logLevel -enableLogging -unsafeLogging` |
| V-T4 | CORRECTS (S0-T2, S0-T3) | config keys are `[bridges.transports.<name>]`, not `transport.pt_*`; ptmgr **inherits the parent environment** (no scrub) — GHOST's env-scrub §5.3 stays GHOST's own job; state dir is `<state_dir>/pt_state` |
| V-T5 | CONFIRMS + **OA-3 FIRED** | same-path double builds byte-identical for both ABIs (and both host builds); leak check clean; **stripped sizes 16.88 / 17.01 MiB exceed the ≤ 8 MiB extracted budget and gzip-9 5.92 / 6.34 MiB exceed ≤ +4 MiB compressed** |
| V-T6 | PARTIAL (green half) | push + chmod 700 + exec of the x86_64 lyrebird works from `/data/local/tmp` on API 35 **and** API 29; on-device sha256 equals the host build's hash; exec from an app's `filesDir` is not directly proven at S0 (deferred to S2's PT-1 re-run) |
| V-T7 | PARTIAL (drafted) | `tor-ptmgr` 0.46.0 pins and its direct dependency set + licences listed; the full transitive delta and a `cargo deny` run need the S1 feature flip (S1 does this check for real) |
| V-T8 | PARTIAL (green half) | full loopback chain measured green: tor client → lyrebird client → obfs4 → lyrebird server → tor ORPort, **100 % bootstrap** in ~68 s (link+OR handshake ≤ ~1–2 s of it); PT-L1 byte capture: no TLS record shape at the PT hop; the arti-side half is S3's PT-L2 (client used here is C-Tor 0.4.9.11, not arti) |

### 0.2 Values to freeze (pin reality, §1 in detail)

| Value | Measured | Evidence |
|---|---|---|
| Lyrebird tag | `0.9.0` (annotated, PGP-signed by meskio 2026-10-06; ChangeLog date 2026-09-21) → commit `89d54872b176f936232ff39f7a8189b77d83d65e` | §1 |
| Source archive | `git archive 0.9.0 \| gzip -n -9` → `d5c8fd4dbcf190b13ec9d20aa0ac7d6df0bc271c7911712250f10438d9b7bec0` (recorded with the exact command; git-archive hashes are not stable across git versions — the commit hash is the real pin) | §1 |
| Go toolchain | go1.26.0 (lyrebird 0.9.0's `go.mod` directive `go 1.26.0`); `go1.26.0.windows-amd64.zip` sha256 `9bbe0fc64236b2b51f6255c05c4232532b8ecc0e6d2e00950bd3021d8a4d07d4` (official go.dev JSON, size 74 815 266) | §1 |
| arm64-v8a binary | `bb0f6a1126cad82b3e0502e865f006b3e2a887eff7a3eaa957f30288dae4d8bf`, 17 695 016 B (16.88 MiB), gzip-9 6 204 644 B (5.92 MiB) | §4 |
| x86_64 binary | `9f6e31e24e4f466434f0d1e5ce35637c4f2ae16aae0eff65f183ea506a019448`, 17 839 656 B (17.01 MiB), gzip-9 6 647 877 B (6.34 MiB); on-device sha256 on API 35 and API 29 identical | §4, §6 |
| **arm64-v8a binary, pruned (OA-3 resolution)** | `38b2272c0b21dce33564431ea629351a4a78397881a3b8604b5d2a7938dfd6ca`, 7 668 008 B (7.31 MiB), gzip-9 2 899 241 B (2.76 MiB) — the pin that ships (rev 2) | §10.2 |
| **x86_64 binary, pruned (OA-3 resolution)** | `fafd01beede8653bf55a0ccb47a20c29ea00a822f113e1822bb704c845d7001f`, 7 556 392 B (7.21 MiB), gzip-9 3 107 257 B (2.96 MiB) | §10.2 |
| Host builds (loopback) | windows/amd64 `c38d5e5001d2bf3bf71da651cb573e283dbaa8f3c4671ac306120443225b3936`; linux/amd64 `d369468f758991a91f9c1f919c16c37b5f3edddfbd964381e8977e9fe38483f6` | §4 |
| Server invocation (obfs4) | env: `TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_STATE_LOCATION=<dir> TOR_PT_EXIT_ON_STDIN_CLOSE=1 TOR_PT_SERVER_TRANSPORTS=obfs4 TOR_PT_SERVER_BINDADDR=obfs4-127.0.0.1:<port> TOR_PT_ORPORT=127.0.0.1:<orport>`, args: `-enableLogging -logLevel DEBUG` (optional); emits `SMETHOD obfs4 127.0.0.1:<port> ARGS:cert=<b64>,iat-mode=0` | §3, §7 |
| Client invocation (managed) | env: `TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_STATE_LOCATION=<dir> TOR_PT_EXIT_ON_STDIN_CLOSE=1 TOR_PT_CLIENT_TRANSPORTS=obfs4`; emits `CMETHOD obfs4 socks5 127.0.0.1:<port>`; bridge ARGS travel in the SOCKS username field | §3, §7 |
| Loopback numbers | link+OR handshake through obfs4 ≤ ~1–2 s; 0 %→100 % bootstrap 68 s (dominated by ~7.6 MB directory traffic through the PT); capture 715 packets / 7 635 153 payload bytes; `\x16\x03\x01` in 0 payload packets | §7 |
| tor-ptmgr pin | `0.46.0` (arti-client 0.46's optional dep), crate tarball sha256 `523678f0839a2429386518d5e1c5b26cfaac77b1cbf44a8d8f5b14377e2025a7`, licence MIT OR Apache-2.0 | §5 |

### 0.3 Normative corrections (for the design's revision 2, per V-T4's pass criterion)

| # | Check | Sections | Correction (short) |
|---|---|---|---|
| S0-T1 | V-T3 | §3 "Server side for free", §12.3 | lyrebird 0.9.0 server/client mode is entirely the pt-spec env protocol; the binary's only flags are `-version -logLevel -enableLogging -unsafeLogging`. The exact server invocation is the env set of §0.2 (recorded green in §7); there are no `-orbited`-style flags to pin |
| S0-T2 | V-T5 | §4 recipe, Q2 | three recipe fixes: (a) `-ldflags '-checklinkname=0'` is required with Go 1.26 (wlynxg/anet v0.0.5's legacy `go:linkname` to `net.zoneCache`, pulled by the snowflake transport); (b) `GOOS=android GOARCH=amd64` **mandates external linking** (cmd/go refuses `CGO_ENABLED=0` there) — the x86_64 build needs `CGO_ENABLED=1` + the pinned NDK clang (`…/ndk/30.0.16248370/…/x86_64-linux-android29-clang.cmd`); arm64 stays `CGO_ENABLED=0` (internal PIE); (c) the version stamp must be pinned explicitly: `-X main.lyrebirdVersion=0.9.0` (upstream's Makefile derives it from `git describe`, which is not reproducible). `strip` = `-ldflags '-s -w'` at link time; no post-link stripper needed |
| S0-T3 | V-T5 | §9.1 budgets, D10 | **OA-3 fired.** Measured (stripped): arm64 16.88 MiB extracted / 5.92 MiB gzip-9; x86_64 17.01 / 6.34. Both ABIs exceed both provisional budgets (≤ 8 MiB extracted, ≤ +4 MiB compressed). The size is dominated by transports GHOST never enables (snowflake pulls pion/webrtc + aws-sdk: the module graph downloads them even though GHOST refuses snowflake lines); lyrebird has no build tags to exclude them. S0 stops before S1 until the owner re-budgets or accepts a pruned-tree fork (Q-S-T1) |
| S0-T4 | V-T4 | §5.3 (config keys, env scrub) | config keys are arti's `[bridges.transports.<name>]` TOML table with fields `protocols`, `path`, `arguments`, `run_on_startup` (managed) or `proxy_addr` (unmanaged) — not `transport.pt_*`; and ptmgr spawns with `Command::new(path).args(arguments).envs(map)` — the PT child **inherits arti's full environment** plus the `TOR_PT_*` set; there is no env scrub or `env_clear`. §5.3's scrub stays GHOST's obligation and must be implemented as sanitising the app's own environment, not by relying on ptmgr |
| S0-T5 | V-T8 | §12.3 PT-L1 fixture | a naive "no `\x16\x03` anywhere in the capture" fixture **false-positives on real obfs4 bulk traffic** (7.6 MB of ciphertext contains the 2-byte pair by chance; measured 97 payload packets hit, chance expectation ≈ 116). The mechanical assertion that discriminates: (a) the first application payload of the connection carries no TLS record layer and (b) `\x16\x03\x01` (TLS handshake record) appears in zero payload packets. The WebTunnel twin asserts presence, not absence |
| S0-T6 | V-T8 | §12.3 harness | the harness's own long-lived PT processes (the server half) die on stdin EOF when `TOR_PT_EXIT_ON_STDIN_CLOSE=1` — the S3 harness must hold the child's stdin open (arti/ptmgr does this correctly for client PTs; a shell harness needs a pipe or `sleep`). Measured: without it, lyrebird exits within a second of "accepting connections" |
| S0-T7 | V-T6 | §12.1 V-T6, §5.4 | exec from `/data/local/tmp` (shell-owned, mode 700) is demonstrated on API 29 and API 35; exec from an app's `filesDir` is **not** demonstrated at S0 (needs an installed app context; the emulators carry no GHOST build). C-3's filesDir half stays assumed until S2's PT-1 re-run (the design already schedules that re-run as V-T6-in-S2) |

### 0.4 Owner questions raised

| # | From | Question | Default if unanswered |
|---|---|---|---|
| Q-S-T1 | V-T5, S0-T3 (OA-3) | Both ABIs measure 16.9–17.0 MiB stripped (≈ 6 MiB compressed), roughly 2× the provisional budgets, because snowflake (pion/webrtc, aws-sdk) is compiled into lyrebird and upstream has no build tags to exclude transports. (a) Re-budget to the measured values (≈ 17 MiB extracted / +6 MiB compressed per ABI; NFR-4's 80 MiB still holds); (b) ship a pruned tree (delete `transports/snowflake|meeklite|obfs2|obfs3|scramblesuit` + `Init()` entries from the pinned source, record the patch alongside the pin — against D2's "no fork" as written, so D2 needs the owner's explicit amendment); (c) investigate upstream appetite for transport build tags and wait? | (a) re-budget to the measured values |
| Q-S-T2 | V-T5, S0-T2(b) | The x86_64 ABI cannot honour `CGO_ENABLED=0` (cmd/go hard-requires external linking for android/amd64). Accept the pinned-NDK-clang external link as part of the recipe (the same NDK `build-native.sh` already pins; the double build proved it byte-reproducible)? | accept (there is no alternative that builds) |
| Q-S-T3 | V-T8 | The S0 loopback ran C-Tor 0.4.9.11 as the client/manager because arti's `pt-client` wiring is S1 code. The arti-side loopback (ptmgr → lyrebird) is S3's PT-L2 as designed — confirm no re-ordering is wanted (S3 could instead run the full PT-L harness with C-Tor first and port to arti after, at the cost of building the harness twice)? | keep the design's order (arti in S3) |
| Q-S-T4 | V-T1 | The pin is 0.9.0 with `main` two days newer (`362a60bb`, 2026-10-08). The bump procedure (§4.4) owns freshness; re-pinning at S1 start to catch those two days is free now (one tag move) — do it or stay at 0.9.0? | stay at 0.9.0 (0.9.0 is the newest tagged release; freshness is the bump procedure's job) |

---

## 1. V-T1 (+V-T2): the lyrebird pin reality

**Question.** Does a maintained lyrebird tag exist, does it build, what is its licence, and does one binary really implement obfs4 + webtunnel, client and server? (V-T2: is there a maintained Rust alternative the D2 rejection missed?)

**Method.** Shallow clone of `gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird` (2026-10-17); tag candidates by creation date; checkout the newest tag; read `LICENSE`, `go.mod`, `cmd/lyrebird/lyrebird.go`, `transports/transports.go`, `transports/{obfs4,webtunnel}/*`, `Makefile`; crates.io sparse-index query for `obfs4`, `webtunnel`, `snowflake`, `pt-client`, `pluggable-transport`.

**Results.**
- Tag candidates (newest first): `0.9.0` 2026-10-06 (annotated, PGP-signed by meskio; ChangeLog "Changes in version 0.9.0 - 2026-09-21"), `lyrebird-0.8.1` 2026-01-15, `lyrebird-0.8.0` 2025-12-09, `lyrebird-0.7.0` 2025-11-27; `main` is at `362a60bb` (2026-10-08), two days ahead of the tag. Per the design's "prefer the newest tagged release over main": **pin = tag `0.9.0` → commit `89d54872b176f936232ff39f7a8189b77d83d65e`** (tag object `9285df21…`, verified signed).
- Licence: `LICENSE` is **BSD-3-Clause** ("Copyright (c) 2023, The Tor Project / Copyright (c) 2014-2023, Yawning Angel", the 3-clause text; a second BSD block covers Go Authors' code). The repo also carries `LICENSE-GPL3.txt`, but **no `.go` file references GPL** — the Go code is uniformly BSD-3-Clause. (The GPL3 file appears to cover packaging; the notices step records BSD-3-Clause and quotes the file.) OSI-approved: yes.
- `go.mod`: `go 1.26.0` (the Q8 toolchain pin; §2).
- One binary: `transports/transports.go:55-71` (`Init()`) registers meeklite, obfs2, obfs3, **obfs4**, scramblesuit, **snowflake**, **webtunnel** into one `transportMap`; `cmd/lyrebird` is the single `main`. Both target transports expose client **and** server factories: `transports/obfs4/obfs4.go:102,108` (`ClientFactory`, `ServerFactory`) and `transports/webtunnel/webtunnel.go:26,34`. `cmd/lyrebird/lyrebird.go:316-322`: the only flags are `-version`, `-logLevel`, `-enableLogging`, `-unsafeLogging`; client-vs-server is decided by the `TOR_PT_CLIENT_TRANSPORTS`/`TOR_PT_SERVER_TRANSPORTS` env (pt-spec), not argv. `lyrebird.go:59` has `lyrebirdVersion = "devel"` unless `-X main.lyrebirdVersion=…` is injected (the Makefile does this from `git describe` — S0-T2(c) pins it to `0.9.0`).
- Source archive hash: `git archive 0.9.0 | gzip -n -9` → `d5c8fd4d…7bec0` (recorded with the command; the commit hash is the real pin).
- V-T2: `obfs4` on crates.io = exactly one version, `0.1.0-alpha.1` (2024-09-21, "Pure rust implementation of the obfs4 pluggable transport") — an unreleased alpha, no maintenance track. `webtunnel` = no crate. `snowflake` on crates.io is an unrelated 2017 process-unique-ID library (2.1 M downloads, not a Tor transport). No maintained Rust obfs4/webtunnel client exists at the pin date: D2's rejection **CONFIRMS**.

**Verdict. V-T1 CONFIRMS** (licence BSD-3-Clause; one binary, both transports, both halves; pin `0.9.0`/`89d54872…`). **V-T2 CONFIRMS.** Precisions folded as S0-T1 (flags/env) and the version-stamp part of S0-T2.

## 2. Q8: the pinned Go toolchain

**Method.** Read `go.mod`'s `go` directive at the tag (`go 1.26.0`); download `https://go.dev/dl/go1.26.0.windows-amd64.zip`; verify against go.dev's own release metadata (`https://go.dev/dl/?mode=json&include=all`).

**Results.** Archive size 74 815 266 B; computed sha256 `9bbe0fc64236b2b51f6255c05c4232532b8ecc0e6d2e00950bd3021d8a4d07d4` **equals** the JSON's `sha256` for that file. Unpacked to `D:\Forum\.claude\toolchains\go` (outside the repo, per the design's "fetched at build time, git-ignored" rule); `go version` → `go1.26.0 windows/amd64`. Host has no ambient Go (`where go` empty), so the toolchain pin was genuinely exercised.

**Verdict. CONFIRMS** Q8's mechanism (pin + recorded hash from go.dev). The values to freeze are §0.2's.

## 3. V-T3: server mode and the managed protocol

**Question.** Does the pinned lyrebird run as an obfs4 server wrapping a local ORPort, and as a client, with the exact invocations?

**Method.** Drove the linux/amd64 host build (§4) in managed mode with the pt-spec env, first standalone (reading `VERSION`/`SMETHOD`/`SMETHODS DONE` and `CMETHOD`/`CMETHODS DONE` from stdout), then end to end under a tor client in §7.

**Results.**
- Server (obfs4): with `TOR_PT_SERVER_TRANSPORTS=obfs4`, `TOR_PT_SERVER_BINDADDR=obfs4-127.0.0.1:4711`, `TOR_PT_ORPORT=127.0.0.1:6900`, state dir set, it printed `VERSION 1`, `STATUS TYPE=version IMPLEMENTATION="lyrebird" VERSION="0.9.0"`, `SMETHOD obfs4 127.0.0.1:4711 ARGS:cert=<base64>,iat-mode=0`, `SMETHODS DONE`, and served obfs4 connections forwarding to the ORPort (§7's 100 % bootstrap crossed it). Server identity persists in the state dir (`obfs4_state.json`): same state dir → same cert across restarts.
- Client (managed): with `TOR_PT_CLIENT_TRANSPORTS=obfs4` it printed `CMETHOD obfs4 socks5 127.0.0.1:<port>` and `CMETHODS DONE`; bridge ARGS (`cert=…,iat-mode=0`) arrive via the SOCKS5 username field, per pt-spec — verified working by §7's tor client.
- WebTunnel: `TOR_PT_SERVER_TRANSPORTS=webtunnel` registers in the same binary (server factory at `webtunnel.go:34`); its standalone loopback needs a TLS-front shape the S3 harness builds — not exercised beyond registration in S0 (recorded as S3 scope; not a surprise, §12.3 owns the WebTunnel row).
- **S0-T6 finding**: with `TOR_PT_EXIT_ON_STDIN_CLOSE=1`, a PT whose stdin reaches EOF exits within a second of "accepting connections" (measured twice). Any harness that launches lyrebird itself must hold stdin open.

**Verdict. CONFIRMS** with S0-T1 folded into the design (no server flags exist; the invocation is the env set — §0.2 freezes it).

## 4. V-T5: the reproducible double build

**Question.** Two same-path builds of each ABI, byte-identical? Leak check? Sizes vs the §9.1 provisional budgets?

**Method.** `D:\Forum\.claude\s0\double-build.sh` (draft mirrored to `ghost/third_party/lyrebird/BUILD.sh` for the lead): pinned toolchain (§2), `GOFLAGS='-trimpath -mod=readonly -buildvcs=false'`, `GOPATH`/`GOMODCACHE` at fixed scratch paths, `-ldflags '-s -w -checklinkname=0 -X main.lyrebirdVersion=0.9.0'`; arm64 with `CGO_ENABLED=0`, x86_64 with `CGO_ENABLED=1 CC=<pinned NDK clang>` (cmd/go refuses `CGO_ENABLED=0` for android/amd64 — S0-T2(b)); build → hash → delete → rebuild → hash; grep the binaries for builder paths (`mihai`, `/d/Forum`, `.claude`, `C:\Users`).

**Results.**

| Target | Build A = Build B | Size (stripped) | gzip -9 |
|---|---|---|---|
| android/arm64 | `bb0f6a1126…` — identical | 17 695 016 B (16.88 MiB) | 6 204 644 B (5.92 MiB) |
| android/amd64 | `9f6e31e24e…` — identical | 17 839 656 B (17.01 MiB) | 6 647 877 B (6.34 MiB) |
| windows/amd64 (harness) | `c38d5e5001…` — identical | 18 180 608 B (17.34 MiB) | — |
| linux/amd64 (harness) | `d369468f75…` — identical | 17 780 898 B (16.96 MiB) | — |

Leak check: **no builder-path strings in any of the four** (the `-trimpath` claim proven non-vacuous; note the x86_64 CGO/external-link build is clean too — the NDK path, which lives under `C:\Users\mihai\…`, does not leak).

Budgets: provisional ≤ 8 MiB extracted / ≤ +4 MiB compressed per ABI. Measured 16.88/17.01 MiB extracted and 5.92/6.34 MiB compressed (gzip-9 as the APK-asset analog; ratio 35–37 %, so C-9's "≈ 40–60 %" guess was slightly pessimistic). **Both ABIs miss both budgets → OA-3 fired** (S0-T3, Q-S-T1). The bulk is snowflake's module graph (pion/webrtc, aws-sdk-go-v2 — visible in the module downloads) compiled into a binary whose transport set is fixed at `Init()`; upstream provides no build tags to prune it.

Two build-time findings folded as S0-T2(a,c): Go 1.26 refuses wlynxg/anet's legacy linkname without `-checklinkname=0` (error `link: github.com/wlynxg/anet: invalid reference to net.zoneCache`); and without `-X main.lyrebirdVersion=0.9.0` the binary reports `devel`.

**Verdict. CONFIRMS the reproducibility claim; OA-3 FIRED on sizes** — see §10 for the resolution (Q-S-T1(b) pruned tree applied; both provisional budgets met by the pruned build; S1 unblocked).

## 5. V-T4 (+V-T7 drafted): the arti ptmgr contract read

**Sources read.** Registry checkout `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/arti-client-0.46.0` and `tor-guardmgr-0.46.0`; `tor-ptmgr-0.46.0` is **not in the registry yet** (not a dependency today, as the design found) — its crate tarball was fetched from static.crates.io (sha256 `523678f0…25a7`) and unpacked for reading. File:line below refer to those trees.

**The feature chain (CONFIRMS C-4's core).**
- `arti-client-0.46.0/Cargo.toml:189-194`: `pt-client = ["bridge-client", "tor-chanmgr/pt-client", "tor-guardmgr/pt-client", "tor-ptmgr"]`; `:429-431`: `tor-ptmgr` optional, version `0.46.0`. Plain `tor-ptmgr` = default features; `tor-ptmgr-0.46.0/Cargo.toml:47-50`: `default = ["managed-pts", "tor-channel-factory"]` — so arti's `pt-client` does enable managed PT spawning (`managed-pts = []`, `:73`). A second gate: `TransportConfigBuilder::validate` (`tor-ptmgr/src/config.rs:80-88`) rejects a configured `path` at build time if `managed-pts` is off.
- Re-export: `arti-client/src/config.rs:58` re-exports `TransportConfig`/`TransportConfigBuilder` (ptmgr's config types are arti's public config surface).

**Config keys — CORRECTS §5.3's `transport.pt_*`.** ptmgr's `TransportConfig` (`tor-ptmgr/src/config.rs:26-67`) is the element type of arti's **`[bridges.transports.<name>]`** table (a `Vec<TransportConfig>` named `transports` under the `bridges` section — passed at `arti-client/src/client.rs:1179` as `config.bridges.transports`). Fields: `protocols: Vec<PtTransportName>` (required), `path: Option<CfgPath>` (managed; resolved through the arti `CfgPathResolver`), `arguments: Vec<String>`, `run_on_startup: bool` (managed), `proxy_addr: Option<SocketAddr>` (unmanaged — `path` and `proxy_addr` mutually exclusive, `:90-115`). Unmanaged exposes the CMETHOD-equivalent directly (`cmethod()`, `:198-205`, socks5 only).

**Bridge-line grammar.** `BridgeConfig` lives in tor-guardmgr: `tor-guardmgr-0.46.0/src/bridge/config.rs:78` (`BridgeConfig(Arc<Inner>)`), builder at `:133`, `FromStr` at `:431`/`:440` — the same `obfs4 host:port fingerprint key=value…` text the design's §3.2/§6.2 grammar table pins; a PT line with PT support compiled out errors with `InvalidIpAddrOrPt`/`PluggableTransportsNotSupported` (`:466-485`), the error shapes PT-U1's refusal fixtures target. `PtTarget` assembly at `:647`.

**Spawn mechanics (`tor-ptmgr/src/ipc.rs:571-576`).**
```rust
let child = Command::new(binary_path)
    .args(arguments.iter())
    .envs(all_env_vars)
    .stdout(Stdio::piped())
    .stdin(Stdio::piped())
    .spawn()
```
**CORRECTS §5.3's "environment scrub" assumption (S0-T4):** `.envs()` overlays the `TOR_PT_*` set **on the inherited environment** — no `env_clear`, no scrub, nothing filtered. Confirmed by reading `common_environment_variables` (`ipc.rs:682-707`): it sets `TOR_PT_MANAGED_TRANSPORT_VER=1`, `TOR_PT_STATE_LOCATION=<state_location>`, `TOR_PT_EXIT_ON_STDIN_CLOSE=1`, optional `TOR_PT_OUTBOUND_BIND_ADDRESS_V4/V6`; the client adds `TOR_PT_CLIENT_TRANSPORTS` (`:727-741`) and optional `TOR_PT_PROXY`; the server half sets `TOR_PT_SERVER_TRANSPORTS`, `TOR_PT_SERVER_TRANSPORT_OPTIONS`, `TOR_PT_SERVER_BINDADDR`, `TOR_PT_ORPORT` (`:770-794`). GHOST's §5.3 obligations stand but must be implemented on GHOST's side (the app process's env is what the PT child inherits).
- Negotiation: pt-spec lines parsed at `ipc.rs:224+` (`CMETHOD` etc.); **the CMETHOD endpoint is required to be localhost** (`ipc.rs:234`, `CMETHOD endpoint … was not localhost` → error) — a nice free invariant for GHOST.
- Lifecycle: dropping the handle closes stdin; the reader thread then `kill()`s the child (`ipc.rs:435-446`); `TOR_PT_EXIT_ON_STDIN_CLOSE=1` is set for children that honour it.
- State dir: arti creates **`<state_dir>/pt_state`** with the storage permissions and passes it as ptmgr's `state_dir` (`arti-client/src/client.rs:1176-1187`), which becomes `TOR_PT_STATE_LOCATION`. `PtMgr::new(transports, state_dir, path_resolver, outbound_proxy, rt)` (`tor-ptmgr/src/lib.rs:155`).
- Logging knobs: ptmgr logs via `tracing` only (`info!`/`debug!`/`warn_report!`); it never redirects the child's stderr anywhere in particular — stderr is **not** piped (inherits arti's stderr), worth a GHOST note since lyrebird's stderr in managed mode is chatty at DEBUG.

**V-T7 draft (the allowlist/licence delta, for S1 to finish).** `tor-ptmgr 0.46.0`, licence **MIT OR Apache-2.0**. Direct deps: `async-trait`, `cfg-if`, `derive-deftly ~1.11.4`, `derive_builder 0.11.2`, `fs-mistrust 0.15.0`, `futures`, `itertools 0.15.0`, `oneshot-fused-workaround 0.7.0`, `serde`, `thiserror 2`, `tor-async-utils/tor-basic-utils/tor-chanmgr/tor-config/tor-config-path/tor-error/tor-linkspec/tor-proto/tor-rtcompat/tor-socksproto` (all 0.46.0, already in the workspace's arti family), `tracing`, `visibility 0.1.0`, `web-time-compat 0.2.0`. All either arti-family or crates the tree already carries; the full transitive delta + `cargo deny` + feature-policy run is S1's (V-T7's exit criterion says "on the draft branch").

**Verdict. V-T4 CORRECTS** (two §5.3 fixes folded as S0-T4; everything else the design assumed about ptmgr CONFIRMS with file:line). **V-T7 PARTIAL** (drafted above; S1 finishes it).

## 6. V-T6: the emulator extract/exec probe

**Question.** Can the built x86_64 lyrebird be pushed, chmod 700'd and executed on the gate emulators?

**Method.** Booted `ghost-dm-api35` and `ghost-dm-api29` (`-read-only`, no adb root); `adb push` the android/amd64 binary to `/data/local/tmp/lyrebird`; `chmod 700`; run `/data/local/tmp/lyrebird -version`; `sha256sum` on device.

**Results.**
- API 35 (x86_64, `sys.boot_completed=1`): push 17 839 656 B; `-version` → `lyrebird 0.9.0`; on-device sha256 `9f6e31e24e…` **equals** the host double-build hash.
- API 29 (x86_64): same procedure, same output and hash.
- The binary executed is the NDK-externally-linked (CGO) x86_64 build — so the external-link recipe's runtime validity is proven on both levels, not just the internal-link arm64 path's cousin.

**Not proven at S0 (S0-T7):** exec from an **app's `filesDir`** — that needs an installed app context and the emulators carry no GHOST build; `/data/local/tmp` (shell-owned, world-writable-parent) is a weaker site than `filesDir`. C-3's filesDir half stays assumed until S2's PT-1 re-run, which the design already schedules (V-T6 re-run as a suite in S2). The API 37 image (`ghost-media-api37`) was not booted: §12.1 makes it optional ("if still available, runs too") and S0 stops at OA-3 before S2 needs it.

**Verdict. PARTIAL-green**: the exec model is demonstrated on both gate levels with hash-identical bytes; the filesDir half is deferred with its exact owner (S2/PT-1).

## 7. V-T8: the loopback obfs4 measurement

**Question.** Client → lyrebird client → lyrebird server → local ORPort: does bootstrap complete, how long, and what do the bytes on the PT hop look like?

**Method.** Inside WSL2 Ubuntu-24.04 (clean loopback, no cross-OS networking): tor 0.4.9.11 as a **private relay** (own datadir, identity `ghostloop CE49419A69F0095738AC7E340EA35D38F1466E1E`, `BridgeRelay 1`, `ORPort 127.0.0.1:6900`); the linux lyrebird as managed **server** (`TOR_PT_SERVER_BINDADDR=obfs4-127.0.0.1:4711`, `TOR_PT_ORPORT=127.0.0.1:6900`, fresh state → fresh cert); tor as **client** with `UseBridges 1`, `ClientTransportPlugin obfs4 exec <lyrebird> -enableLogging -logLevel DEBUG`, and the bridge line `obfs4 127.0.0.1:4711 CE49…6E1E cert=<SMETHOD cert> iat-mode=0`; `tcpdump -i any` on port 4711 during the whole run (WSL2 quirk: `-i lo` sees nothing — recorded for the S3 harness); milestones from the client's stdout log; payload analysis by parsing the pcap's hex dumps and stripping IP/TCP headers per packet.

**Results.**
- Negotiation: server `SMETHOD obfs4 127.0.0.1:4711 ARGS:cert=2ukXahYY…,iat-mode=0`; the client's demonstration instance reported `CMETHOD obfs4 socks5 127.0.0.1:46379` (tor's own managed instance negotiated its own SOCKS port internally).
- Timeline (client log): `0% starting` 11:17:22 → `1% conn_pt` / `2% conn_done_pt` 11:17:23 → **`10% conn_done` (OR handshake through the PT complete) 11:17:23** → `50–75% loading_descriptors` 11:18:28–29 → **`100% done` 11:18:30**. So: link+OR handshake through obfs4 ≤ ~1–2 s on loopback; full bootstrap ≈ 68 s, of which ~65 s is directory traffic (~7.6 MB) squeezed through one PT connection — a loopback lower bound exactly as §12.3 promises, no NFR-2 claim.
- **PT-L1 capture**: 715 packets, 7 635 153 application-payload bytes through tcp/4711. First application payload begins `f889ed41…` — an obfs4 public-key handshake, not a TLS record. Per-payload-packet scan: **`\x16\x03\x01` (TLS handshake record) in 0 packets**; the raw 2-byte `\x16\x03` appears in 97 packets, consistent with chance in ~7.6 MB of ciphertext (expectation ≈ 116) — this is why S0-T5 corrects the naive fixture.
- Post-bootstrap: the client built circuits and finished at 100 %; the throwaway-v3-onion stream assertion of PT-L2 is S3's (it needs the arti client and the harness's own onion — recorded as remaining, not silently claimed).

**What this is and is not.** The client/manager here is **C-Tor 0.4.9.11, not arti**: arti's `pt-client` path (`TransportConfig.pt_dir`, the ptmgr wiring) is S1 code and does not exist on this branch. What is proven at S0: the pinned binary's obfs4 client+server interop, the exact env invocations, bootstrap-through-the-PT on loopback, the byte-capture shape, and the harness discipline (held-open stdin, fresh-vs-pinned server state, the `-i any` quirk). What remains: the same chain with arti as the manager (S3 PT-L1/PT-L2), WebTunnel's row, and the negative fixtures.

**Verdict. PARTIAL-green**: the measurement the design calls "loopback is a lower bound" is recorded with numbers; the arti half is S3 as designed (Q-S-T3 asks only whether to keep that order).

## 8. X-T deviations from the design's S0 row

1. **S0 stopped at OA-3** (D10's own rule): the budgets were exceeded, so no S1 work was started and the pin/BUILD.sh set was delivered as drafts for the lead, not committed. **Resolved same day in §10**: the Q-S-T1(b) pruned tree was applied as an owner-default; the pruned build is within both budgets and S1 is unblocked.
2. **android/amd64 built with CGO** (pinned NDK clang) — `CGO_ENABLED=0` is impossible for that GOOS/GOARCH (cmd/go's hard requirement, S0-T2(b)). The double build proved the external-link recipe byte-reproducible.
3. **The loopback measurement used C-Tor as client/manager** instead of arti (§7) — the design's §12.3 harness arti assumption is S3-reachable; S0 measured everything that does not need S1 code.
4. **Toolchain and work area lived in `D:\Forum\.claude\`** (task instruction) rather than `ghost/third_party/lyrebird/toolchain/`; the design's own Q8 text ("fetched at build time, git-ignored") is compatible — the in-repo `BUILD.sh` will do the fetch.
5. **filesDir exec deferred** (S0-T7) — §6.

## 9. Appendix C updates (for the design's revision 2)

| # | Claim | Status after S0 |
|---|---|---|
| C-1 | lyrebird = one binary, obfs4+webtunnel client+server, maintained | **verified** (tag 0.9.0/commit `89d54872…`; `transports.go:55-71`, `obfs4.go:102/108`, `webtunnel.go:26/34`) |
| C-2 | BSD-3-Clause | **verified** (LICENSE read at the tag; no GPL in any `.go`; notices record BSD-3-Clause) |
| C-3 | Android exec model | **half-verified**: exec of a 700-mode binary from `/data/local/tmp` on API 29+35; filesDir half stays **assumed** until S2's PT-1 re-run (S0-T7) |
| C-4 | `pt-client` → ptmgr, config keys, env behaviour | **verified with two corrections** (S0-T4: `[bridges.transports.<name>]`, env inheritance not scrub; everything else as assumed, file:line in §5) |
| C-5 | obfs4 client node-id from the bridge cert, no client disk state | **verified in operation** (fresh client state dir bootstrapped with only the bridge line; no identity material appeared in the client state dir — only the log) |
| C-6 | `transport.rs` refusal plumbing | unchanged (no product code touched this slice) |
| C-7 | build/gate discipline to mirror | unchanged |
| C-8 | live-tor harness model; issuer's tor | **extended**: the loopback harness's tor = Ubuntu 24.04's `tor` 0.4.9.11 (same major as issuer's Debian package family), installed 2026-10-17 in WSL |
| C-9 | budgets provisional; Go compresses ≈ 40–60 % | **measured**: 35–37 % at gzip-9 (unpruned); **budgets exceeded → OA-3** (S0-T3) → **resolved §10**: pruned build 36–38 %, within both budgets; §9.1 re-pinned (rev 2) |
| C-10 | plan/ADR/row-12 scope facts | unchanged |

*Prepared 2026-10-17 on `p12-s0`; every number above was measured in the session described; scripts and raw logs: `D:\Forum\.claude\s0\` (`double-build.sh`+`double-build.log`, `loopback.sh`+`loopback.log`, `out/` binaries and `.sha256`, `ptmgr-src/tor-ptmgr-0.46.0/`, `emulator{35,29}.log`); the on-WSL pcap and tor logs: `/root/ghost-s0/` inside `Ubuntu-24.04`.*

---

## 10. OA-3 resolution: the pruned build (2026-10-17, same day, follow-up session)

**What happened.** OA-3 (§4) fired because stock lyrebird 0.9.0 compiles snowflake (pion/webrtc + aws-sdk-go-v2) into a 16.9–17.0 MiB binary, roughly 2× the provisional budgets. The owner's directive for Phase 12 implements the design fully; Q1 already defers snowflake to 12b and the design's own Q-S-T1 (§0.4) anticipated exactly this as option (b) — a pruned tree with the patch recorded alongside the pin. **Resolution applied: option (b), recorded as an applied owner-default pending the owner's written confirmation.** The design was amended to revision 2 in place (`faza12-transports.md`, amended cells marked "(rev 2, OA-3 applied)": D2, D10, Q2, OA-3, §3.1, §4.1/§4.4, §9.1, Appendix C).

### 10.1 The patch

`ghost/third_party/lyrebird/prune-snowflake.patch` — `git diff` against the pinned commit `89d54872…` (clean tree), applied by BUILD.sh after checkout (step 3b). Diffstat:

```
 cmd/lyrebird/lyrebird.go                       |  16 +-
 cmd/lyrebird/lyrebird_test.go                  | 102 -----  (the snowflake-only proxy test)
 cmd/lyrebird/pt_extras.go                      |  19 +---
 go.mod                                         |  53 ---
 go.sum                                         | 208 +-------
 transports/meeklite/*  (6 files)               | 932 deletions
 transports/obfs2/obfs2.go                      | 377 ---
 transports/obfs3/obfs3.go                      | 369 ---
 transports/scramblesuit/* (5 files)            | 1093 deletions
 transports/snowflake/snowflake.go              | 135 ---
 transports/transports.go                       |  13 +-
 21 files changed, 4 insertions(+), 3313 deletions(-)
```

The four non-deletion hunks are small and reviewable: `transports.go` (imports + `Init()` now registers exactly `obfs4` and `webtunnel`), `lyrebird.go` (drop the `sf` import, the `slices.Contains(…, "snowflake")` proxy check, and the snowflake-only proxy-URL branch), `pt_extras.go` (drop the snowflake proxy-support check; `ptGetProxy()` loses its parameter), and the `go.mod`/`go.sum` hunks are `go mod tidy`'s output. **Scope note (deviation from the task's "snowflake only" wording, recorded):** snowflake alone was pruned first and measured **8.50/8.34 MiB** — still over the ≤ 8 MiB extracted budget by 0.50/0.34 MiB, with meeklite→utls the remaining blob. The context's own requirement ("the binary must carry exactly the approved P0 set: obfs4 + webtunnel ONLY") and Q-S-T1(b)'s text (which names all five directories) both cover the four legacy transports, so the patch was extended to the full P0-only prune. utls itself stays: it is webtunnel's client-side TLS camouflage (upstream `webtunnel/utls.go`), part of the P0 set.

After the patch: `go list -m all` has 19 modules (from ~150), no `snowflake`/`pion/*`/`aws-sdk-*`; `go build ./...` and `go vet ./...` green for the pruned tree.

### 10.2 The pruned builds (S0+ recipe = S0-T2 + Q-S-T2)

`D:\Forum\.claude\s0\double-build-pruned.sh`, outputs in `D:\Forum\.claude\s0\out-pruned\`, log `double-build-pruned.log`. Same recipe as §4: Go 1.26.0 pinned toolchain, `GOFLAGS='-trimpath -mod=readonly -buildvcs=false'`, `-ldflags '-s -w -checklinkname=0 -X main.lyrebirdVersion=0.9.0'`; arm64 `CGO_ENABLED=0`, **x86_64 `CGO_ENABLED=1` + pinned NDK clang (external link, cmd/go hard requirement)**; two same-path builds per target; builder-path leak check.

| Target | Build A = Build B | Size (stripped) | gzip -9 | vs budgets |
|---|---|---|---|---|
| android/arm64 | `38b2272c0b21…dfd6ca` — identical | 7 668 008 B (**7.31 MiB**) | 2 899 241 B (**2.76 MiB**) | extracted ≤ 8 MiB ✓ (margin 0.69 MiB); compressed ≤ +4 MiB ✓ |
| android/amd64 | `fafd01beede8…d7001f` — identical | 7 556 392 B (**7.21 MiB**) | 3 107 257 B (**2.96 MiB**) | extracted ✓ (margin 0.79 MiB); compressed ✓ |
| windows/amd64 (harness) | `cd33ddf10f78…e1489` — identical | 7 670 272 B (7.31 MiB) | — | — |
| linux/amd64 (harness) | `d92fd03d170e…3b5b` — identical | 7 504 034 B (7.16 MiB) | — | — |

**Both ABIs meet both provisional budgets.** Leak check: no builder-path strings in any of the four (the x86_64 external-link build included — the NDK path under `C:\Users\mihai\…` does not leak). Comparison against the unpruned build: extracted −54 %/−55 %, compressed −53 %/−53 %. The pin is re-set to these measured values in the design's §9.1 (rev 2).

**Environment note (which hashes are canonical).** The scratch-env double builds above are internally reproducible (a later one-off rebuild reproduced `38b2272c…` exactly). The canonical in-repo `BUILD.sh` (updated in this resolution: it applies the patch after checkout and asserts the pruned module graph) was then run **end-to-end twice in its own fixed environment** (`ghost/third_party/lyrebird/`, fixed paths under `.cache/` and `toolchain/`): it produced `06e41e1ba2b…` (arm64) / `13e1e50b1d…` (amd64), **identical across both runs**, with byte-for-byte the same sizes (7 668 008 / 7 556 392 B). The scratch and in-repo environments differ in exactly 59 bytes — all inside the Go build-ID note — which is the design's documented property: §4.1 step 5 pins **same-path determinism** only, and cross-environment byte identity is Phase 14's builder-image work (the `-trimpath` flag value embeds the source tree's absolute path in the link action-ID chain, so different checkout paths hash differently while everything else — code, rodata, module info — is byte-identical, verified by `cmp -l`). `SHA256SUMS` records the **BUILD.sh-in-repo hashes** (what CI/G-T4 compares against); both environments' numbers are listed there and here.

### 10.3 Managed-protocol sanity (CMETHOD evidence)

Windows harness build, managed client mode, manager requesting **all seven upstream methods** (`TOR_PT_CLIENT_TRANSPORTS='obfs4,webtunnel,meeklite,obfs2,obfs3,scramblesuit,snowflake'`), log `D:\Forum\.claude\s0\sanity\cmethod.log`:

```
VERSION 1
CMETHOD obfs4 socks5 127.0.0.1:50373
CMETHOD webtunnel socks5 127.0.0.1:50374
CMETHOD-ERROR meeklite no such transport is supported
CMETHOD-ERROR obfs2 no such transport is supported
CMETHOD-ERROR obfs3 no such transport is supported
CMETHOD-ERROR scramblesuit no such transport is supported
CMETHOD-ERROR snowflake no such transport is supported
CMETHODS DONE
```

The pruned binary answers the PT protocol and serves exactly the approved P0 set. Server mode (`sanity\smethod.log`): `SMETHOD obfs4 127.0.0.1:4791 ARGS:cert=…,iat-mode=0`; webtunnel reports `SMETHOD-ERROR … unimplemented` — **identical on the unpruned 0.9.0 build** (`sanity\smethod-unpruned.log`), i.e. upstream behaviour unchanged by the prune (webtunnel's server side is a separate component; GHOST's loopback server mode uses obfs4, as §3.1 point 3 already assumed).

### 10.4 Loopback re-run (pruned linux/amd64)

`D:\Forum\.claude\s0\loopback-pruned.sh` inside WSL2 Ubuntu-24.04, same chain as §7 (fresh relay + fresh PT server state + C-Tor 0.4.9.11 client). Log `loopback-pruned.log`:

- Server: `SMETHOD obfs4 127.0.0.1:4711 ARGS:cert=7fKo+v/a…,iat-mode=0`; client: `CMETHOD obfs4 socks5 127.0.0.1:41231`.
- **Bootstrap 0 %→100 % in 40.5 s** (10% conn_done through the PT in ~1 s; the rest is directory traffic). On-demand re-run: the earlier attempt in this session stalled at 10 % only because the harness had not started the §7 relay — with the relay up (as here) the pruned binary bootstraps clean. The pruned linux binary's sha256 (`d92fd03d…`) equals the host double-build hash.

### 10.5 Verdict

**OA-3 RESOLVED.** The pruned build is reproducible (four double builds byte-identical), within both provisional budgets (7.31/7.21 MiB extracted; 2.76/2.96 MiB gzip-9), carries exactly the approved P0 transport set (CMETHOD evidence), and the obfs4 loopback chain bootstraps 100 % with it. S1 is unblocked. The resolution is recorded as an applied owner-default pending the owner's written confirmation (Q-S-T1(b) + Q-S-T2 accepted; the extended prune past snowflake per the §10.1 scope note).


