# GHOST Phase 12 (transports slice): Pluggable transports — obfs4 and WebTunnel via lyrebird — Design (proposed)

| Field | Value |
|---|---|
| Status | **Proposed** 2026-10-17, awaiting the owner (the owner's rule: an approved design before implementation). Owner questions **Q1 … Q11** carry proposed defaults (§0.5). **ADR-61 and ADR-62** (Appendix A, Romanian) are drafts at "Propus"; nothing in this document is a UI claim (CP-10; `docs/STATUS.md`, row "Afirmații permise în marketing/UI": "niciuna"). |
| Revision | **1** (branch basis `main` at `16e1a3da`). No adversarial review rounds yet; §15 item 7 schedules the phase's review, and §0.6 lists the owner actions this design needs (OA-1 … OA-3). |
| Date | 2026-10-17 |
| Phase | 12 (plan §6.2 row 12, the authoritative scope): "Hardening metadate: tuning jitter/batch, **bridges (P1)**, review independent al capturii de metadate" (`docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md:316`). **This design covers the bridges/pluggable-transports clause only.** The jitter/batch tuning clause and the independent metadata-capture review clause are excluded by **Q7** with a pointer to the findings (§16, F-T1) — the row's remainder needs its own small design. ADR-16 (approved) names Phase 12 as the phase of `pt-client` and the lyrebird binaries; its "Stare la 2026-09-11" is the normative starting point this design lands on |
| Exit gate | Plan row 12, the transports clause: PT bridges live end to end (localhost obfs4 bootstrap through lyrebird green in the S0/S3 harness; one recorded live public-bridge run), **capture ⊆ set permis** extended with the PT fixtures (T1), the PT-binary gates G-T1 … G-T8 green with fixtures, and the privacy invariants T58 … T60 evidenced. The row's other two clauses (tuning, independent review) are not claimed by this design (Q7) |
| Depends on | **Phase 6** code on `main` (`ghost/client-core/net`, ADR-19; reviewed 2026-09-11, `docs/reviews/2026-09-11-faza6-security-review.md`): Arti 0.46 with `bridge-client` + `vanguards`, the plain-bridge plumbing, the bootstrap/deadline/spent semantics this design extends. **Coordination (no code dependency):** Phase 13's paste/QR bridge-lines UI (`docs/design/faza13-ux.md:209` leaves "Bridges and pluggable transports UI" to this phase — the UI entry points are Phase 13's; Phase 12 ships the plumbing and a host-side test entry, Q4); Phase 14's bridge-line distribution (Q5); ADR-16's auto mode (Q6's reduced form is implemented here) |
| ADR impact | New: **ADR-61** (pluggable transports: the PT set, lyrebird provenance and reproducible build, the tor-ptmgr process model), **ADR-62** (bridge lines: user-provided only, wrapped storage, no built-in list). Deviations from approved documents, each recorded: **X-T1** (ADR-16's forward note "binarele lyrebird … livrate ca `lib*.so` în `jniLibs`" is replaced by APK assets + extraction to `filesDir/pt/` — Android's W^X/exec model, §5.4), **X-T2** (ADR-16's full auto mode with a shipped bridge list becomes the reduced auto mode until Phase 14, §6.5), **X-T3** (plan row 12's other two clauses excluded, Q7). New invariants **T58 … T60** (Appendix B.1), THREAT_MODEL AD-4 row update (Appendix B.2), new LIMITE section **L12** (Appendix B.3), STATUS row and ADR index entries (Appendix B.4). **Numbering:** ADR-61 … 62 are the next free numbers after ADR-60; T58 … T60 the next free invariants after Phase 13's T53 … T57 and Phase 14's T48 … T52; L12 the next free LIMITE section after Phase 14's L10 and Phase 13's L11 (reserved now rather than renumbered at merge, the Phase 11 rule) |
| Sources | Master plan v2.1 (§6.2 row 12, §6.2 row 6); ADR-01, ADR-07, ADR-16, ADR-19; `docs/THREAT_MODEL_v2.1.md` (AD-4, row 52); `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` §L4; `docs/STATUS.md` (Phase 6 row); `ghost/client-core/net/src/transport.rs` (the refusal and the plain-bridge plumbing, read at `16e1a3da`); `ghost/client-core/net/Cargo.toml` and `ghost/Cargo.toml` (arti-client 0.46.0, features `tokio`, `rustls`, `compression`, `onion-service-client`, `bridge-client`, `vanguards`; `pt-client` off, `tor-ptmgr` absent from `Cargo.lock` — verified in this worktree); `ghost/scripts/build-native.sh` and `ghost/scripts/gates/apk-native-libs.sh` (the build/gate discipline mirrored); `ghost/client-core/net/tests/live_tor.rs` (the live harness this phase extends); the Phase 10 design (`docs/design/faza10-forum.md`, Appendix A/B shape); the Phase 11 and Phase 13 designs (language and identifier conventions); `docs/design/faza13-ux.md` (the Phase 12 UI row and coordination). External sources are listed in Appendix D with what each was used for; load-bearing claims about lyrebird, Go, Android's exec model and Arti's ptmgr are marked **assumed** in Appendix C and are S0 checks (V-T1 … V-T8), not verified facts this draft relies on silently |

**How to read this document.** §0 is the summary: decisions, guarantees, deviations, non-goals, the owner questions with proposed defaults, owner actions. §1 fixes scope and terminology. §2 states what the local observer sees (AD-4) and the declared PT leakage LT. §3–§9 are normative: the PT set (§3), binary provenance and build (§4), the process model (§5), bridge lines and storage (§6), state and privacy (§7), the config/API/JNI surface (§8), size and timing budgets (§9). §10 lists the new invariants, §11 the schema and merge coordination. §12 is the test plan and the exit-gate argument, §13 the gates, §14 the slices and effort, §15 the exit checklist, §16 risks and findings outside the phase. Appendix A holds the ADR drafts (Romanian), Appendix B the text changes in other documents (Romanian), Appendix C the evidence table (verified vs assumed), Appendix D the sources. A section marked "(normative)" wins over a summary table.

**Identifier conventions.** Decisions `D1…D12`; owner questions `Q1…Q11`; owner actions `OA-1…OA-3`; S0 checks `V-T1…V-T8`; invariants `T58…T60`; gates `G-T1…G-T8` (plus the listed extensions to existing gates); guarantees `P-T1…P-T3` (privacy) and `CS-T1…CS-T3` (correctness); deviations `X-T1…X-T3`; declared PT leakage `LT-1…LT-4`; residues `L12-C1…L12-C7` (new LIMITE section L12); risks `R-T1…R-T8`; findings `F-T1…F-T4`; JNI functions `PT-1…PT-5`; test ids `PT-U1…`, `PT-L1…`, `PT-P1…`. Slices `S0…S4`. Citations `path:line` are relative to the worktree root (`ghost/…` for the monorepo), read at `16e1a3da` unless stated; `F6` = the Phase 6 review; `TM` = `docs/THREAT_MODEL_v2.1.md`; `LIM` = `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`; `INV` = `ghost/test-harness/privacy/INVARIANTS.md`.

---

## 0. Summary

### 0.1 Decisions

| # | Decision | Rejected alternatives (why) | Plan / ADR alignment |
|---|---|---|---|
| D1 | **Scope: the bridges/pluggable-transports clause of plan row 12 only.** P0: obfs4 and WebTunnel bridge lines end to end (config → storage → arti ptmgr → lyrebird → bootstrap), the reduced auto mode (Q6), the PT-binary build/provenance pipeline, the gates. **Excluded (Q7):** jitter/batch tuning and the independent metadata-capture review — the row's other two clauses; the Phase 11 design deferred "decuplarea" items to "Faza 12" (L9-M2, L9-M4) which land with the tuning slice, not this one (F-T1) | absorbing the tuning review into this design (it is a capture-and-shaping exercise over the whole traffic surface with its own evidence needs, not a transport feature) | plan:316 (X-T3); §16 F-T1 |
| D2 | **The PT set (Q1): obfs4 + WebTunnel, both from lyrebird** — the Tor Project's maintained Go PT bundle; one binary implements both transports. P0 ships exactly these two | shipping obfs4proxy and webtunnel as separate binaries (two provenance/build tracks for one purpose); a fork or a Rust PT (no maintained Rust obfs4/webtunnel client exists at the pin date — an S0 re-check, V-T2) | ADR-16 ("WebTunnel/obfs4/Snowflake"); §3 |
| D3 | **Snowflake is deferred to a Phase 12b.** Its client is a separate, heavy WebRTC Go binary (multi-MiB, its own dependency surface), it needs the broker/distribution machinery, and its threat model (DTLS/WebRTC fingerprinting) is a separate review | bundling snowflake-client now (doubles the binary surface for a transport whose distribution question — Q5 — is unanswered until Phase 14); dropping it silently (ADR-16 names it; deferral is explicit, not silent) | ADR-16 (named); §3.4 |
| D4 | **Binary provenance and build (Q2, §4 normative):** lyrebird built from a **pinned Tor git tag** (commit hash + recorded source-tarball SHA-256 in-repo) with a **pinned Go toolchain** (version + recorded toolchain SHA-256, fetched from go.dev at build time), `GOFLAGS=-trimpath -mod=readonly -buildvcs=false`, `CGO_ENABLED=0`, stripped, two ABIs (`arm64-v8a`, `x86_64`). The recipe, pins and output hashes live in **`ghost/third_party/lyrebird/`** (a `BUILD.sh` mirroring `scripts/build-native.sh`'s discipline); CI builds twice at the same path and **compares hashes** (the native library's double-build rule); the app verifies the binary's SHA-256 after extraction, before exec | prebuilt binaries from any source (unverifiable provenance, against ADR-07/ADR-38 direction); building lyrebird inside the Gradle build (non-reproducible, toolchain drift); pinning only a branch (mutable) | ADR-07 (reproducibility), ADR-16's plan note; §4 |
| D5 | **Process model (Q3, §5 normative): Arti's ptmgr** — `arti-client` gains the **`pt-client` feature** (`tor-ptmgr` enters the shipped graph with its own allowlist/licence/size checks, §5.2). The Android side extracts the lyrebird binary from APK assets to **`filesDir/pt/<abi>/lyrebird`**, verifies its SHA-256 against the in-repo sums, `chmod 700`, and hands the path to arti; each bootstrap attempt gets a private state dir `filesDir/pt/run-<n>/` which is deleted when the attempt ends | a hand-rolled PT launcher (re-implements the pluggable-transports stdio protocol, its version negotiation and its isolation, badly); embedding lyrebird as a `lib*.so` and dlopening it (it is a `main()` program, not a library; and APK-native code cannot `exec` from the mount — X-T1) | ADR-16's "feature `pt-client`"; §5 |
| D6 | **Bridge lines (Q4, Q5, §6 normative): user-provided only in P0.** Phase 12 ships the config plumbing (parsing, validation, storage), the refusal relaxations (obfs4/WebTunnel accepted when PT is enabled; snowflake still refused with its own error), and a **host-side test entry** that injects lines for tests. **No built-in bridge list.** Paste/QR is Phase 13's UI; distribution is Phase 14's question | a built-in list in P0 (the distribution question — who operates the bridges, how lines rotate, what a seized list costs — is Phase 14's design space; a half-answer now would be redesigned); generating lines at first run (needs distribution) | ADR-16 (mod auto assumes a list — deferred, X-T2); §6 |
| D7 | **Storage (§6.4, §7 normative):** bridge lines (plain and PT) live in SQLCipher, wrapped under the existing database key — no new Keystore key, no new table family beyond one table. Arti's state/cache dirs and `filesDir` are canary-scanned so no line ever lands outside wrapped storage; no bridge line in any log (T58) | a separate wrapped file per line (a second custody story for no gain); letting arti persist lines into its state dir uncontrolled (canary T58 catches it if it tries) | T3/T20 discipline extended |
| D8 | **Relay-facing shape unchanged (§7 normative):** the PT hop is **client → bridge only**. From the bridge onward the client is an ordinary Tor client; relays, onion services and the issuer see exactly today's shape. Vanguards-lite, isolation and the onion-only API are untouched | PT-wrapping relay-facing connections (pointless — the local observer is the target, and the relay path already runs over Tor) | ADR-01, ADR-19 |
| D9 | **Testing (§12 normative): localhost integration is the gate.** lyrebird **runs a server**: an obfs4 server wrapping a local Tor daemon's ORPort (the issuer staging infra already runs Tor, `infra/issuer`), with the arti client bootstrapping through it — the live-tor harness (`tests/live_tor.rs`) is the model. The gate harness runs fully on loopback; the live public-bridge run is manual and recorded (OA-1) | testing only against live public bridges (flaky, unbounded, needs lines in CI — refused); unit tests alone (they prove parsing, not a bootstrap) | §12.3 |
| D10 | **Size budgets (Q2, §9 normative):** provisional **≤ 8 MiB extracted per ABI** and **≤ +4 MiB per ABI in the compressed APK**, pinned to measured values by S0; if S0's measurement exceeds the provisional budget, S0 stops and the owner re-budgets before S1 (OA-3) | no budget (the repo's lesson: unmeasured size claims are how NFR-4 dies quietly); a hard guess written now (unverified until measured — the NFR rule) | §9 |
| D11 | **Bootstrap semantics unchanged (Q10):** `BOOTSTRAP_DEADLINE` stays 180 s **per attempt**; direct and PT attempts are separate clients with separate deadlines (the Phase 6 "spent client" rule applies to each); connections never bootstrap implicitly; fail-closed, no non-Tor fallback | one shared 180 s budget for direct+PT (a slow direct attempt eats the PT attempt's time; ADR-16's auto mode needs both) | `transport.rs:22-24,46-56`; ADR-16 |
| D12 | **Gates (§13 normative): G-T1 … G-T8** — source pin, double-build reproducibility, size budget, APK-asset hash equality, runtime hash check, the PT-exec-site textual gate (G-DM1-class: no module spawns processes except the net crate's ptmgr wiring), the bridge-line log gate, and the refusal-relaxation pinning — each with a negative fixture and a self-test, the Phase 9 gate practice | line greps without fixtures (the §22.33 evasion review broke 27 of 27) | ADR-10; the Phase 9 gate practice |

### 0.2 Guarantees claimed (each has a test in §12; none is a UI claim before the gate is met, CP-10)

| # | Guarantee | Evidence |
|---|---|---|
| P-T1 | On a PT bridge path, the local network observer (AD-4) sees a TCP connection to the bridge whose byte stream carries **no Tor fingerprint**: obfs4 looks like uniformly random bytes; WebTunnel looks like HTTPS to a web cover. The observer learns "a connection to that IP:port, its volume and timing" — not Tor-ness | PT-L1 capture of the loopback obfs4/webtunnel handshake (bytes), the T1 fixtures, and the structural argument of §2.2; the live run's capture recorded (OA-1) |
| P-T2 | **No bridge line (plain or PT) in logs, crash dumps, Arti state/cache, or `filesDir` outside wrapped storage** (T58 canaries: a synthetic line injected by the test never appears in any scanned sink) | PT-P1 canary scans; G-T7 |
| P-T3 | The app `exec`s **only** the lyrebird binary it extracted from its own APK assets and SHA-256-verified (T59); no other process is ever spawned by any module | G-T5 (runtime check), G-T6 (textual gate over every module), T59 |
| CS-T1 | Refusals are deliberate and pinned: malformed lines, unsupported parameters, and snowflake lines are rejected with distinct config errors; PT lines are accepted **only** when PT support is compiled in and a PT binary is installed (G-T8) | PT-U unit suite; the existing refusal test relaxed exactly as specified |
| CS-T2 | Bootstrap semantics of Phase 6 are unchanged: manual bootstrap, 180 s deadline per attempt, spent-client rule per attempt, no implicit bootstrap, fail-closed | the existing `transport.rs` tests keep passing unmodified; PT-U3 |
| CS-T3 | A bootstrap through a PT bridge reaches the same post-bootstrap state as a direct bootstrap: directory, guards, vanguards-lite, onion connectivity, empty keystore | PT-L2 loopback bootstrap assertions (the live_tor.rs assertion set) |

### 0.3 Deviations from approved or proposed documents (each recorded in an ADR draft or a finding)

| # | Deviation | Source | Recorded |
|---|---|---|---|
| X-T1 | ADR-16's forward note says the lyrebird binaries are "livrate ca `lib*.so` în `jniLibs`". The shipping shape is **APK assets + extraction to `filesDir/pt/<abi>/`**: Android executes only app-private files (W^X; the APK mount and the native-library directory are not an exec source), which is why Tor's own Android services (Orbot, Tor Browser for Android) ship PT binaries as extracted executables, not `.so`s. The `lib*.so` idea cannot work as written | ADR-16 "Stare la 2026-09-11" | ADR-61 point 5; §5.4 |
| X-T2 | ADR-16's **mod auto** assumes a shipped, rotated bridge list. With no built-in list in P0 (Q5), Phase 12 ships the **reduced auto mode** (Q6): direct first, bridges on failure/timeout, only over user-provided lines. Full auto with a shipped list is Phase 14's distribution question | ADR-16 ("Decizie propusă") | ADR-62 point 6; §6.5 |
| X-T3 | Plan row 12 has three clauses; this design implements one (bridges). The tuning clause and the independent-review clause are excluded (Q7) and flagged (F-T1) | plan:316 | §16 F-T1 |

### 0.4 What this design deliberately does not do

No snowflake client (12b, D3). No built-in bridge list, no bridge-line distribution, no bridge rotation service (Phase 14, Q5). No paste/QR/settings UI (Phase 13; §8.5 defines the facade seam the UI will call). No changes to jitter/batch traffic shaping (row 12's tuning clause, Q7). No changes to the relay-facing or onion-facing protocol, to vanguards, to circuit isolation, or to the JNI surfaces of Phases 9–11. No PT on non-Tor paths — there are none (ADR-01: onion-only). No Conjure, no Shadowsocks, no meek (not named by ADR-16; each would be its own ADR). No changes to `BOOTSTRAP_DEADLINE` (Q10). No 32-bit ABIs (armeabi-v7a/x86 are not shipped today; `build-native.sh:17` names exactly the two ABIs). No in-process obfs4 (a Rust obfs4 would be unaudited new crypto-protocol code — refused).

### 0.5 Owner questions (the proposed default applies unless the owner objects)

| # | Question | Proposed default | Răspunsul pentru proprietar (română) |
|---|---|---|---|
| Q1 | **The PT set:** obfs4 + WebTunnel via lyrebird (one maintained Go binary, both transports) as P0, snowflake deferred to an explicit Phase 12b? | **yes** (D2, D3) | Transporturile pluggable P0 sunt obfs4 și WebTunnel din lyrebird (un singur binar, întreținut de Tor Project); snowflake vine într-o faza 12b separată (binar WebRTC mare, propria distribuție) |
| Q2 | **Binary provenance and build:** pinned lyrebird git tag (commit + tarball hash in-repo), pinned Go toolchain (version + toolchain hash, fetched from go.dev), `-trimpath -mod=readonly -buildvcs=false`, `CGO_ENABLED=0`, stripped, ABIs arm64-v8a + x86_64; recipe and hashes in `ghost/third_party/lyrebird/`; CI double-build hash-compare; app verifies the hash after extraction; budgets **≤ 8 MiB extracted and ≤ +4 MiB compressed per ABI, provisional**, pinned to measured values in S0 (OA-3 if exceeded)? | **yes** (D4, D10) | Lyrebird se construiește dintr-un tag git fixat, cu un toolchain Go fixat, reproductibil, hash-uri în repo; aplicația verifică hash-ul binarului înainte de execuție; bugetul de dimensiune e provizoriu și se fixează din măsurători în S0 |
| Q3 | **Process model:** enable arti's `pt-client` feature (`tor-ptmgr` enters the shipped graph with its own allowlist/licence checks); Android extracts lyrebird to `filesDir/pt/<abi>/lyrebird`, chmod 700, per-attempt state dirs deleted after the attempt? | **yes** (D5) | Clientul Tor pornește transporturile pluggable prin mecanismul propriu Arti (ptmgr); binarul se extrage în spațiul privat al aplicației, se verifică și se execută de acolo |
| Q4 | **Bridge lines user-provided only in P0:** config plumbing + storage + host-side test entry ship in Phase 12; paste/QR stays in Phase 13 (which already owns scanning and secure text entry)? | **yes** (D6) | Liniile de bridge vin doar de la utilizator; Faza 12 livrează mecanismul, interfața de lipire/QR vine în Faza 13 |
| Q5 | **No built-in bridge list** in Phase 12 (bridge distribution, rotation and the seized-list cost are Phase 14's design question)? | **none** (D6) | Nicio listă de bridge-uri încorporată; distribuția lor e întrebarea Fazei 14 |
| Q6 | **Reduced auto mode:** direct bootstrap first; if it fails or times out and PT bridge lines are configured, retry with bridges (ADR-16's direction, limited to user-provided lines); full auto with a shipped list awaits Phase 14 (X-T2)? | **yes** (D11, §6.5) | Mai întâi Tor direct; dacă eșuează și există linii de bridge, se reîncearcă cu ele; modul auto complet, cu listă livrată, vine cu distribuția (Faza 14) |
| Q7 | **Scope:** the rest of plan row 12 (jitter/batch tuning, independent metadata-capture review) is excluded from this design and gets its own follow-up? | **excluded** (D1, X-T3) | Designul acoperă doar transporturile pluggable; reglajul de trafic și review-ul independent al capturii de metadate rămân pentru o lucrare separată |
| Q8 | **Go toolchain fetch:** the build downloads the pinned Go toolchain tarball from go.dev at build time and verifies its recorded SHA-256 (mirroring `build-native.sh`'s pinned cargo-ndk), rather than using whatever Go is on the host? | **yes** (§4.3) | Toolchain-ul Go e fixat prin versiune și hash, ca la cargo-ndk |
| Q9 | **Both ABIs ship PT binaries** (x86_64 included, so the emulator exercises the real PT path, not a stub)? | **yes** (§4.2) | Ambele ABI-uri (arm64-v8a și x86_64) primesc binarul PT, ca biblioteca nativă |
| Q10 | **Bootstrap deadline unchanged:** 180 s per attempt, direct and PT attempts are separate clients; S0/S3 measure the loopback PT bootstrap time and the exit checklist records it? | **yes** (D11) | Fiecare încercare de bootstrap are termenul propriu de 180 s; timpul real prin obfs4 se măsoară și se consemnează |
| Q11 | Approve ADR-61 and ADR-62 (Appendix A) as "Propus", and this design as the basis for Phase 12 code? | **yes** | Aprobarea ADR-61, ADR-62 și a designului |

### 0.6 Owner actions

| # | Action | Needed by |
|---|---|---|
| OA-1 | Provide (or approve fetching at run time from Tor's bridge endpoints) one live public obfs4 line and one WebTunnel line for the manual live run, **or** accept loopback-only evidence plus one recorded manual run before distribution | S3 exit (the gate is loopback-only by default; the live run is the distribution-day evidence) |
| OA-2 | Run the PT path on two arm64 reference phones (device step, restated from Phase 10/13's standing action): extraction, chmod, exec, bootstrap timing on real hardware | before distribution (not before S4) |
| OA-3 | If S0's measured size exceeds the provisional budget (Q2), re-budget before S1 starts | S0 exit |

---

## 1. Scope, requirements, terminology

### 1.1 Scope (normative)

**In scope (P0).** (a) The pluggable transports obfs4 and WebTunnel, client side, via lyrebird, integrated into `ghost/client-core/net` through arti's `pt-client` feature. (b) The lyrebird build/provenance pipeline in `ghost/third_party/lyrebird/` and its gates. (c) Bridge-line configuration plumbing: parsing, validation, storage, the relaxed refusals, and a host-side test entry. (d) The Android extraction/exec plumbing in the `:network` module. (e) The reduced auto mode (Q6). (f) The test plan, gates and invariants of this document.

**Out of scope.** Everything in §0.4. In particular this design changes **no wire format, no relay protocol, no schema beyond §6.4's one table, and no existing JNI surface** — the PT work sits entirely inside the network layer Phase 6 built (ADR-19: the Arti client is not exposed outside `ghost-client-net`, `transport.rs:1-8`).

### 1.2 Requirements (IDs R12-n; sources verified in the worktree at `16e1a3da`)

| # | Requirement | Source |
|---|---|---|
| R12-1 | Bridges/pluggable transports configurable | plan:258, FR-2.9 (P1) |
| R12-2 | Liniile `obfs4`/`webtunnel`/`snowflake` sunt refuzate explicit azi; activarea lor trebuie să fie o schimbare deliberată | STATUS Phase 6 row; ADR-16; `transport.rs:31-34,290-298` |
| R12-3 | PT binaries from a pinned source, reproducibly, with hashes recorded in-repo (the native library's discipline) | ADR-07/ADR-38 direction; `scripts/build-native.sh`; `apk-native-libs.sh` |
| R12-4 | The local observer must not see Tor-ness on a PT path (AD-4's "cu bridges cu transport pluggable: nici Tor") | TM:52 |
| R12-5 | No privacy claim before the gate (CP-10); nothing in UI until Phase 13 | STATUS row "Afirmații permise"; `docs/design/faza13-ux.md` |
| R12-6 | Fail-closed: no non-Tor mode; a PT failure never falls back to clearnet | ADR-01; `transport.rs:6-8` |
| R12-7 | The bridge-line UI (paste/QR) is Phase 13's; Phase 12 ships the engine plumbing | `faza13-ux.md:209` (the row names Phase 12 — resolved in §16 F-T2) |
| R12-8 | CI runs locally (ADR-58); every gate is a local script with fixtures | STATUS CI row; `docs/CI_LOCAL.md` |
| R12-9 | One Rust runtime in the APK (no second native library, no new runtime) | ADR-19; the DM/MLS crates link into `libghost_client_net.so` (`net/Cargo.toml:10-21`); lyrebird is a *separate process*, not a linked library — this is the one deliberate exception and it is what ADR-16's plan already assumed |

### 1.3 Terminology (normative)

- **Bridge line:** one line of Tor bridge configuration. *Plain*: `IP:PORT FINGERPRINT`. *PT*: `obfs4 IP:PORT FINGERPRINT cert=… iat-mode=…` or `webtunnel IP:PORT FINGERPRINT url=… ver=…`. GHOST accepts exactly the arti-parsable grammars of these three shapes and nothing else.
- **PT / pluggable transport:** an obfuscating proxy protocol run in a separate process, spoken between the Tor client and the bridge over the pluggable-transports stdio management protocol (tor-spec's `pt-spec.txt`).
- **lyrebird:** the Tor Project's maintained Go bundle of PT clients and servers, successor of obfs4proxy, implementing obfs4 and WebTunnel (client and server sides) in one binary (`lyrebird`).
- **ptmgr:** arti's pluggable-transport manager (`tor-ptmgr` crate), enabled by arti-client's `pt-client` feature; spawns and supervises PT processes.
- **Local observer:** AD-4 (ISP, hostile Wi-Fi, employer): sees the user's IP, the peer IP:port, byte streams, volume, timing.
- **Reduced auto mode:** Q6's direct-then-bridges bootstrap strategy.
- **Attempt:** one bootstrap try of one client (direct or PT), bounded by `BOOTSTRAP_DEADLINE` (180 s), subject to the spent-client rule.

---

## 2. Adversary view: AD-4 and the declared PT leakage

### 2.1 Effective view of the local observer (normative)

TM:52 defines AD-4's today-view: "vede IP-ul utilizatorului și că vorbește cu Tor/bridge; volum și timing", and states the goal: "cu bridges cu transport pluggable: nici Tor". This design delivers exactly that delta and nothing more:

| Path | What AD-4 sees today (plain bridge) | What AD-4 sees with a PT bridge (this design) |
|---|---|---|
| Connection open | TCP to bridge IP:443 (or any port); the **Tor TLS handshake fingerprint** follows within the first kilobytes | TCP to bridge IP:port. **obfs4:** a random-looking byte stream — the obfs4 handshake has no fixed prefix, no certificate, no distinguishable structure (the obfs4 spec's design goal is resistance to known-tor-fingerprint DPI). **WebTunnel:** a TLS handshake and HTTP semantics indistinguishable from HTTPS to the cover web server (uTLS browser parrot; the bridge answers as the web server and upgrades to the tunnel) |
| Steady state | Relay cells inside Tor TLS: packet sizes and timing with the Tor cell signature | obfs4: uniformly random bytes, cell boundaries hidden. WebTunnel: TLS records of web-like shapes |
| Everything else | Volume, timing, the peer's IP:port, up/down ratio | **Unchanged:** volume, timing, the peer's IP:port, up/down ratio. A PT does not hide that you talk *to that IP* or *how much* |

**LT (declared PT leakage — the only information a PT path adds or leaves):**

| # | Leak | Bound / note |
|---|---|---|
| LT-1 | The bridge's IP:port is visible, and "this user talks to that IP:port" is itself a signal if the bridge is a known/enumerated one | bridges are enumerable in principle; bridge-line secrecy (T58) and distribution (Phase 14) are the mitigations |
| LT-2 | Volume and timing are visible end to end at the observer | PTs pad the *handshake* and hide the cell structure; they do not pad the bulk (that is row 12's tuning clause, Q7) |
| LT-3 | Active probing: an active adversary can probe the bridge IP and learn it speaks obfs4/WebTunnel (obfs4 requires a correct `cert=` to answer; WebTunnel answers as a web server) — a *bridge-enumeration* risk, not a client-side one | bridge-side; noted for Phase 14's operator guidance |
| LT-4 | The PT binary's network shapes: WebTunnel's parroted ClientHello reveals *a browser-like TLS*; an observer comparing against real browsers can measure drift | uTLS parrots age; this is upstream lyrebird/uTLS maintenance, flagged R-T4 |

The relay-facing half of the world is untouched (D8): from the bridge inward the client is an ordinary Tor client, and GHOST's circuits still end at relay onion services with vanguards-lite (`transport.rs:111-115`).

### 2.2 What P-T1 does and does not claim (normative wording for L12)

Wording for the LIMITE rows (Appendix B.3), so no future text overclaims: a PT bridge path hides **Tor-ness from the local observer** — not the existence of a connection, not its volume or timing, not the bridge's IP:port, and nothing from the bridge operator (the bridge knows it is a Tor bridge and sees the traffic it carries; it is trusted no more than a guard is, which is why the path beyond it stays ordinary Tor). obfs4's node-id/certificate authenticates the bridge to the client; the client authenticates with the keys in the line. **No claim is made against a global passive adversary** (AD-2's row is unchanged: GPA sees "calea Tor", TM:52).

---

## 3. The PT set (normative; Q1)

### 3.1 Choice: lyrebird, one binary, two transports

**D2.** P0 ships exactly two pluggable transports — **obfs4** and **WebTunnel** — both implemented by the Tor Project's **lyrebird** Go bundle, from one pinned source tag, built once per ABI into one stripped binary.

Justification, on the repo's evidence rules:

1. **Maintenance.** lyrebird is the successor of obfs4proxy under the Tor Project's anti-censorship team, the same organisation that runs the bridge authority and the bridges GHOST users will paste lines from. WebTunnel is its current answer to DPI-heavy networks (HTTPS cover). One maintained upstream for both transports is the smallest provenance surface that satisfies ADR-16's set.
2. **One binary.** lyrebird implements obfs4, WebTunnel (client and server) and the legacy transports in a single executable; the transport is selected per bridge line by the PT management protocol. One binary = one provenance track, one build, one hash set, one size budget — the same economy the repo chose with `libghost_client_net.so`.
3. **Server side for free.** The same binary runs in **server mode** (`lyrebird -enableLogging … -orbited …` style flags; the exact server invocation is pinned in S0, V-T3). That is what makes the loopback gate of §12.3 possible without any third-party test dependency: GHOST runs its own obfs4 server around a local Tor ORPort.
4. **ADR-16's list.** obfs4 and WebTunnel are ADR-16's named P1 transports; snowflake is named too — its deferral is explicit (D3), not a silent cut.

### 3.2 What is enabled client-side

The bridge-line grammars accepted in P0 (the complete list; anything else is `TransportError::Config`, §6.2):

- `obfs4 <ip:port> <fingerprint> cert=<base64> iat-mode=<0|1|2>` — iat-mode 0 default; all three iat-modes accepted (they trade padding for latency; the choice is the line's, i.e. the operator's).
- `webtunnel <ip:port> <fingerprint> url=<https://…> ver=<hex>` — the ver parameter pins the webtunnel protocol version from the line.
- plain lines stay accepted, unchanged (`transport.rs:31-34`).

### 3.3 What is refused (and stays refused)

- `snowflake …` — refused with a **distinct** config error naming the 12b deferral (CS-T1); the refusal test stays, renamed, not deleted.
- Any other transport name, any unknown parameter, malformed base64/hex, a fingerprint that is not 40 hex chars, an IP:port that does not parse — refused as today.
- Lines are validated **before** any client is created (as today, in `build_config`), so a bad line is a config error, never a runtime surprise.

### 3.4 Snowflake deferral (12b) — the explicit boundary (normative)

Snowflake's client is a **separate Go binary** with a WebRTC stack (multi-MiB, its own dependency and licence surface), needs **brokers and a bridge distribution story** to be usable (its whole point is reachability to blocked bridges, which is the Phase 14 question), and its fingerprinting surface (DTLS/WebRTC) deserves its own review. Deferral boundary: **no snowflake grammar accepted, no snowflake binary shipped, no broker config** — a 12b design will pick up the ADR-16 line, reusing this phase's build/gates/extraction machinery (the pipeline of §4 is transport-agnostic).

---

## 4. Binary provenance and build (normative; Q2, Q8, Q9)

### 4.1 Layout: `ghost/third_party/lyrebird/`

New directory, mirroring the discipline of `ghost/scripts/build-native.sh` (pinned tools, fixed paths, recorded hashes, a leak check):

```
ghost/third_party/lyrebird/
  README.md          what this is, provenance statement, licence note, bump procedure
  pins.env           LYREBIRD_TAG, LYREBIRD_COMMIT, GO_VERSION, GO_TARBALL_SHA256,
                     LYREBIRD_TARBALL_SHA256   (the only files a bump edits)
  BUILD.sh           the build recipe (below)
  SHA256SUMS         "<sha256>  <abi>/lyrebird" lines, written by BUILD.sh, committed
```

`BUILD.sh` (the recipe, normative):

1. Read `pins.env`; fail if any pin is missing.
2. Fetch the Go toolchain **only if the pinned version is not already installed**: download `go<GO_VERSION>.<os>-<arch>.tar.gz` from `go.dev` (Q8), verify against `GO_TARBALL_SHA256`, unpack under a fixed path inside the workspace (`ghost/third_party/lyrebird/toolchain/`, git-ignored). The host's ambient Go is never used.
3. Fetch the lyrebird source at `LYREBIRD_COMMIT` (the tag's commit) from `gitlab.torproject.org` (or the GitHub mirror as fallback, same commit hash), verify the tree against `LYREBIRD_TARBALL_SHA256` (the tarball is reproducible-from-git; the hash pins what was reviewed).
4. Build, per ABI: `CGO_ENABLED=0 GOFLAGS=-trimpath -mod=readonly -buildvcs=false GOOS=android GOARCH=<arm64|amd64>` → `go build ./cmd/lyrebird` (the main package path is pinned in S0, V-T1), then `strip` (llvm-strip from the pinned NDK, the same one `build-native.sh` requires).
5. Reproducibility check: build **twice** into two directories at the **same path** (the native rule: same-path determinism is what CI checks; cross-environment byte identity is Phase 14's builder-image work, `build-native.sh:9-11`) and `cmp` the outputs; on difference, fail.
6. Leak check: grep each binary for the builder's home, workspace and toolchain paths (the `spellings()` idea, `build-native.sh:36-45`); on a hit, fail. `-trimpath` should make this vacuous — the check proves it.
7. Write `SHA256SUMS` ("`<sha256>  <abi>/lyrebird`") and print the measured sizes for the size gate.

Output: `ghost/third_party/lyrebird/out/<abi>/lyrebird` for `arm64-v8a` and `x86_64` (Q9).

### 4.2 The licence check (S0 exit)

Lyrebird's licence (expected BSD-3-Clause by obfs4 lineage, **assumed — verified, not remembered**: V-T1 records the licence file at the pinned tag into `ghost/licenses/THIRD_PARTY_NOTICES-*` and `deny.toml` gets whatever the verification finds; if the pin-date licence is not OSI-approved, S0 stops and the owner decides). The Go toolchain is a build-time tool (not shipped; its licence is recorded in the README only). The shipped APK gains exactly one new native executable — `apk-native-libs.sh`'s allowlist gains `assets/pt/*/lyrebird` (checked by hash, G-T4), not a new `.so`.

### 4.3 Why not the host's Go (Q8)

Reproducibility is a property of the *recipe*, not the machine: a host Go of any version silently changes the bytes. The toolchain pin + recorded hash is the same discipline as cargo-ndk 4.1.2 in `build-native.sh:16,30-34`.

### 4.4 Version policy

Bumps edit `pins.env` + the two recorded hashes, re-run BUILD.sh, and re-pin `SHA256SUMS`. Like G-R7's rule for Rust, a PT bump re-runs the whole §12 suite (the localhost bootstrap proves the new binary actually speaks to a Tor ORPort). No floating tags, ever: the tag is documentation; the **commit hash** is the pin.

---

## 5. Process model (normative; Q3)

### 5.1 arti's ptmgr

**D5.** `arti-client` gains the **`pt-client` feature** (one line in `ghost/Cargo.toml:76`). This pulls `tor-ptmgr` into the shipped graph — a **new external crate family**, which triggers, in S1, the standing checks: `rust-dependency-allowlist.txt`, `dependency-allowlist.sh`, `deny.toml` licences, `rust-feature-policy.sh`, and a **size re-measure** of `libghost_client_net.so` (the +3 MiB arm64 / +3.5 MiB x86_64 budgets of the Phase 10 owner decision — ptmgr is small, but the re-measure is mandatory and recorded). The PT code path is **compiled in but inert without bridge lines and without a PT binary**: no PT process ever spawns for direct clients, and the existing direct/bootstrap tests must pass byte-for-byte unchanged (CS-T2).

ptmgr's contract (normative expectations, verified against the crate source in S0, V-T4): it locates PT binaries from the client's config (`transport.pt_*` settings), spawns one process per transport with the pluggable-transports stdio protocol (version negotiation, `CMETHOD`/`SMETHOD` lines, per-connection `CMDOC`… over stdin/stdout), and kills the process tree when the client drops. GHOST's obligations: give it the binary path, a state dir, and a scrubbed environment (§5.3).

### 5.2 Wiring in `ghost-client-net`

`TransportConfig` (today: `state_dir`, `cache_dir`, `bridge_lines`, `transport.rs:27-35`) gains exactly:

```rust
pub struct TransportConfig {
    // … unchanged fields …
    /// Directory holding the extracted, hash-verified PT binaries
    /// (`<abi>/lyrebird` under the app's filesDir/pt). None = PT unavailable:
    /// PT bridge lines are then rejected with a distinct config error.
    pub pt_dir: Option<PathBuf>,
}
```

`build_config` (today `transport.rs:104-128`) relaxes exactly one branch: PT lines parse through arti's own bridge-line parser (with `pt-client` enabled, `BridgeConfigBuilder::parse` accepts obfs4/webtunnel), and when any PT line is present it additionally requires `pt_dir` to be `Some` and the binary to exist — checked up front, because a missing binary must be a config error at create time, not a bootstrap-time hang. The snowflake branch of the parser never runs: snowflake lines are rejected by GHOST's own pre-validation before arti sees them (§3.3). The `TransportError` enum gains `PtBinaryMissing` (config class). No other public type changes; `TorTransport`'s bootstrap/connect/isolation API is untouched.

### 5.3 Child-process hygiene (normative)

- **One spawn site.** The only code in the repository that spawns a process is the ptmgr wiring inside `ghost-client-net`. G-T6 enforces this textually over every module (G-DM1-class), in Rust (`std::process::Command`, `tokio::process`) and Kotlin (`ProcessBuilder`, `Runtime.exec`).
- **Environment scrub.** GHOST sets the PT child's environment explicitly (ptmgr's env plus nothing inherited that names the user): no proxy variables, no `HOME` pointing at readable storage, `TMPDIR` redirected to the attempt dir. What ptmgr passes verbatim is read from the crate source in S0 (V-T4) and recorded here in revision 2.
- **State isolation per attempt.** Each bootstrap attempt gets `filesDir/pt/run-<monotonic-n>/` as the PT state dir; the attempt's deletion (on success, failure, timeout, abort, process death) removes it. obfs4's client-side state is derived from the bridge line (its node id comes from the line's `cert=`), so PT statelessness holds (§7.1) — the per-attempt dir is defence in depth, not a requirement of the protocol.
- **No PT logging.** lyrebird's logging is disabled by configuration (and its stdout/stderr are the management protocol, consumed by ptmgr). A PT process must never write a log file; G-T7's textual gate covers the code that touches the PT path.

### 5.4 The Android exec model (normative; X-T1)

Facts the design relies on (checked against AOSP/primary sources in S0 where marked; the two load-bearing ones are Appendix C items):

1. **W^X and noexec.** Android does not permit executing from the APK archive (it is not mounted executable) and modern Android mounts the app's native-library directory `noexec` — a `.so` can be `dlopen`ed but not `exec`ed. Executing a separate program file requires it to live in **app-private storage** (`/data/data/<pkg>/…`, i.e. `filesDir`), whose filesystem is exec-able for the app's own uid. (This is why Orbot and Tor Browser for Android extract `obfs4proxy`/`lyrebird` into their filesDir and exec it from there — Appendix D, Appendix C C-3.)
2. **`extractNativeLibs="false"`** (AGP default for minSdk≥23) means `.so`s are mmap'd from the APK — reinforcing that the PT binary cannot be a `.so` executed in place. X-T1 records the correction to ADR-16's forward note.
3. **Shipping shape.** The built `lyrebird` binaries ship in the APK as **assets**: `assets/pt/arm64-v8a/lyrebird`, `assets/pt/x86_64/lyrebird` (Gradle `sourceSets { main.assets.srcDir … }` pointing at `ghost/third_party/lyrebird/out`, copied only when present — the host/JVM test build that has no binaries must compile and run, with PT config rejected, §8.4). Assets are per-ABI picks at extraction time via the app's `ApplicationInfo`/abi-split logic (the same logic that selects `libghost_client_net.so`; one helper, one allowlisted site).
4. **Extraction (idempotent, verified).** At first PT use, `:network` extracts the right ABI's asset to `filesDir/pt/<abi>/lyrebird.tmp`, verifies its SHA-256 against `SHA256SUMS` compiled into the app (the same sums `apk-native-libs.sh` checks — G-T4's APK-side twin), renames to `filesDir/pt/<abi>/lyrebird`, `chmod 700`. A failed hash deletes the temp file and fails closed (PT lines become config errors — bootstrap never starts half-trusted). On every app update the asset hash changes → the recorded hash mismatch forces re-extraction (store the asset's hash, not a flag).
5. **SELinux/seccomp.** An app executing its own filesDir binary is a normal, allowed operation (this is how Termux and the Tor services run); no privilege, no `android:extractNativeLibs` games, no `exec` permission exists to request. The S0 emulator check (V-T6) demonstrates extraction+exec on the API 29 and API 35 gate emulators.

---

## 6. Bridge lines (normative; Q4, Q5, Q6)

### 6.1 Source of lines in P0

User-provided only (D6). The only in-app writers of bridge lines are: the host-side test entry (§8.5), restore (lines travel inside the encrypted database backup like everything else), and the Phase 13 UI (later, through the same facade call). There is **no built-in list, no fetch, no update mechanism** (Q5); the APK contains zero bridge lines and a canary proves it (G-T8's fixture scans the APK for the test line and finds nothing but the fixture).

### 6.2 Validation (normative)

One validator in Rust, one grammar table (§3.2), run at write time and again at config-build time (a line stored by an older version is re-validated before use; a line that no longer parses is a config error naming the line index, never a panic):

1. Split the line; the first token must be `obfs4`, `webtunnel`, or a plain `IP:PORT` + 40-hex fingerprint shape — anything else (including `snowflake`) is refused with a distinct error.
2. Each grammar's parameters are checked structurally (fingerprint hex, base64 `cert=`, iat-mode range, URL scheme https for webtunnel, ver hex length). **Semantically opaque parameters are never interpreted by GHOST** — arti/ptmgr owns the protocol.
3. Line length cap 1 024 chars; at most 8 lines (a bootstrap tries them in order; more is a misconfiguration, and each line is a distinct observable contact).
4. Duplicate lines deduped by exact string (a duplicated line is a misconfiguration, not an attack).
5. The validator is total: property test with seeded random inputs (10⁶ per CI run, the repo's parser rule) — never panics, never over-reads.

### 6.3 Storage (normative)

- One new table, one migration (the next free schema version at merge — Phase 14's X-D12 rule applies; reservation recorded so Phase 13's `migration UX` and Phase 11's later merges don't collide): `transport_bridge(line TEXT PRIMARY KEY, added_day INTEGER NOT NULL)` — day granularity (T33 discipline), no time column, `WITHOUT ROWID`.
- Lines are stored **in the SQLCipher database like everything else**: encrypted at rest by the database key, excluded from backup by the existing `dataExtractionRules`/`allowBackup="false"` posture (T4's world already proves the plumbing). No wrapping key of their own — the threat model for lines equals the threat model for the rest of the config (D7).
- The order of lines is the insertion order (rowid-free: `added_day` then the line; ties broken by line — deterministic, no time).
- Deletion is a user action through the future UI; the host entry deletes by exact line. Nothing else writes the table (G-DM2-class enqueue gate extension is **not** needed: the table has no foreign keys into engines; the textual no-PT-writes gate of §13 covers the write sites).

### 6.4 Canary rule (T58's storage half)

The bridge-line set never appears outside the database: PT-P1 injects a synthetic line (`192.0.2.99:443 …` test-net shaped, unique per run), runs create/bootstrap/teardown, and scans (a) arti's state dir and cache dir, (b) `filesDir` recursively, (c) any log output — the line must appear **only** inside SQLCipher pages. This catches arti persisting bridge config (which GHOST would then re-derive rather than allow), a PT process writing state, and any accidental log (the T3 canary discipline extended with the line).

### 6.5 Reduced auto mode (normative; Q6, X-T2)

ADR-16's auto mode is "Tor direct → bridges, niciodată clearnet". With no built-in list, Phase 12 implements the reduction honestly:

1. If no bridge lines are configured: single direct attempt (today's behaviour, unchanged).
2. If bridge lines are configured: **direct attempt first**; on failure/timeout (the spent-client rule ends it), a fresh client attempts through the bridges, in line order, one client per attempt, each with its own 180 s deadline (D11).
3. If only bridge lines are configured (user deleted none but disabled direct — a Phase 13 setting; in Phase 12 the host entry sets the flag): bridges only.
4. Never clearnet, never a non-Tor fallback (R12-6); the sequence ends in `BootstrapSpent` chains until the caller (the sync runtime's session owner) gives up and surfaces the transport state.

What is **not** implemented in P0 (recorded, not implicit): list rotation, bridge health scoring, per-country defaults, the shipped list. Phase 14's distribution design decides whether ADR-16's full auto mode is reachable and what it costs (L12-C6).

### 6.6 Where lines never go

Not in `TransportConfig`'s error strings at INFO+ (errors name indices, §6.2), not in JNI strings returned to Kotlin beyond the validated grammar (the facade returns counts and indices; §8.5), not in the `native-libs.sha256`-style build outputs, not in CI logs (a gate fixture fails if any test log contains the injected line — G-T7).

---

## 7. State and privacy (normative)

### 7.1 PT statelessness

obfs4's client identity per bridge is **derived from the line** (the node id is a function of the bridge's `cert=`); the client writes no persistent state. WebTunnel's client keeps connection-local state only. Therefore: no PT key material is ever generated or stored by GHOST (the RUSTSEC-2023-0071 acceptance pattern, `transport.rs:405-422`, extends — the PT keystore check: after a PT bootstrap, `keystore_files(state_dir)` is still empty, and `filesDir/pt/run-*` holds nothing). The per-attempt dir of §5.3 exists only to give a reckless PT child a place to die in; it is deleted with the attempt.

### 7.2 The observer's view, per transport (summary of §2)

obfs4: random-looking stream; WebTunnel: HTTPS cover. Neither leaks Tor-ness to AD-4 on the client↔bridge hop (P-T1). Volume/timing/peer-IP remain (LT-1, LT-2). The bridge operator sees a Tor client (like a guard operator does — no new trust class).

### 7.3 The relay-facing shape (D8)

Relays, onion services and the issuer see the identical client as today: ordinary Tor cells from a normal-looking Tor IP (the bridge's exit), vanguards-lite pinned, onion-only API, per-scope isolation. No relay-side change, no protocol change, no new observable. The T1 capture set gains PT fixtures (§12.5) proving the relay-visible byte stream is byte-class-identical to the direct client's.

### 7.4 Logs

The no-logging rule (G-R4) extends to the PT path: ptmgr's own diagnostics never carry a bridge line (a canary PT-L run asserts the string never appears in captured logs at any level, G-T7). Arti/ptmgr are configured so PT protocol chatter is not surfaced into GHOST's log plumbing at all (V-T4 records the exact knobs).

---

## 8. Config, API and JNI surface (normative)

### 8.1 Module ownership

- Rust: all PT logic in `ghost/client-core/net` (parsing, config, ptmgr wiring). No new crate.
- Kotlin: extraction, storage and wiring in `ghost/android/network` (the module that already owns the Tor transport's Android side — `android/network` per the monorepo layout); the bridge-line table's DAO beside the other transport config in `:storage`'s schema, written through `:network`'s repository class. No other module gains PT imports (G-T6's import side).
- The auto-mode sequence of §6.5 lives where bootstrap orchestration already lives (the sync runtime's session owner calls `create`+`bootstrap` in sequence today; the sequence gains a second client — no new thread ownership).

### 8.2 JNI: the closed `PtConfig` surface (PT-1 … PT-5)

Five functions on the existing net JNI class (no new class — the Phase 9 rule: one handle registry; G-R6-class listing extended):

| # | Function | Contract |
|---|---|---|
| PT-1 | `ptInstall(contextFields) → Unit` | Extract+verify+chmod (§5.4.4); idempotent; throws `PT_HASH_MISMATCH`/`PT_UNSUPPORTED_ABI` |
| PT-2 | `ptAvailable() → Boolean` | True iff the verified binary exists and `pt_dir` is set |
| PT-3 | `bridgeLinesSet(lines: Array<String>) → Unit` | Validate (§6.2), store (§6.3); throws with the failing index; never logs a line |
| PT-4 | `bridgeLinesList() → Array<String>` | Returns the stored lines (they are config, not secrets, at the JNI boundary — but they never enter logs; the Phase 13 paste screen is `FLAG_SECURE`) |
| PT-5 | `transportConfigFields() → TransportConfigFields` | The existing transport-creation fields, now including `pt_dir` and the direct/bridges preference |

Host tests drive PT-3/PT-4 over the host library like today's JVM suites; PT-1 is exercised only where assets exist (emulator/device — V-T6) and is a no-op-with-false on the host build (§8.4).

### 8.3 Error taxonomy (normative)

`TransportError` gains `PtBinaryMissing` (config class). JNI error categories gain constants: `PT_HASH_MISMATCH`, `PT_UNSUPPORTED_ABI`, `BRIDGE_LINE_INVALID(index)`, `BRIDGE_LINE_UNSUPPORTED_TRANSPORT` — the same documented-and-tested category discipline as Phase 6 (`jni_error_canaries.rs` extended).

### 8.4 Host/JVM build behaviour

The host library and JVM tests have no APK assets: `pt_dir` is absent, PT-1 reports unavailable, PT bridge lines are rejected with `PtBinaryMissing`-class errors, and every non-PT test runs exactly as today. This is deliberate: the JVM suites stay hermetic; PT behaviour on the JVM is limited to parsing/storage/validation. PT *process* behaviour is proven on loopback in Rust (`§12.3`, no Android needed — lyrebird runs on the host too) and on the emulator in V-T6.

### 8.5 The Phase 13 seam

Phase 13's settings screen calls `bridgeLinesList`/`bridgeLinesSet` (PT-3/PT-4) and nothing deeper; the paste box and QR scanner are Phase 13's components (`faza13-ux.md` owns secure text entry and scanning). Phase 12 ships no UI and no strings.

---

## 9. Size and timing budgets (normative; Q2, Q10)

### 9.1 Size

| Budget | Value | Status |
|---|---|---|
| Extracted lyrebird per ABI (on disk, both ABIs shipped) | **≤ 8 MiB**, provisional | pinned to the S0 measurement; G-T3 enforces the pinned value; OA-3 if S0 exceeds the provisional budget |
| APK size delta per ABI (compressed; Go binaries compress ≈ 40–60 %) | **≤ +4 MiB**, provisional | same pinning rule |
| `libghost_client_net.so` growth from `pt-client` | within the existing Phase 10 budgets (arm64 ≤ +3 MiB strict is the *library* budget; the re-measure is S1's exit evidence) | re-measured, not assumed |

NFR-4 (< 80 MiB) is not at risk on these numbers, but the honest statement is the S0 measurement, not this table (D10).

### 9.2 Timing

- `BOOTSTRAP_DEADLINE` stays 180 s per attempt (D11, Q10).
- S0/S3 measure on loopback: client→obfs4-server→ORPort bootstrap time (host), recorded in the exit checklist. Loopback is a lower bound for the real network; the live run (OA-1) records the real number. **No NFR-2 claim is made from loopback numbers** — the record exists to catch regressions (a PT bootstrap that takes 10× longer after a bump fails S3's re-run) and to size the onboarding copy Phase 13 will write.

---

## 10. Invariants

Three new invariants, T58 … T60 (Romanian rows for INVARIANTS.md in Appendix B.1). Existing invariants are **unchanged** — T1's capture set gains the PT fixtures (§12.5), T3's canaries gain the bridge line, T20's introspection gains the one new table, and the TM AD-4 row is updated (Appendix B.2); none changes wording.

| # | Invariant (English working text) | Gate / evidence |
|---|---|---|
| T58 | No bridge line (plain or PT) in logs, crash dumps, Arti state/cache, or any file outside wrapped storage | PT-P1 canary scans; G-T7 |
| T59 | The app executes only the lyrebird binary extracted from its own APK assets and SHA-256-verified; no other process spawn exists in any module | G-T5, G-T6; V-T6 emulator |
| T60 | A PT hop is client→bridge only; the relay/onion/issuer-facing shape is identical to the direct client | PT-L2 assertions; T1 PT fixtures |

---

## 11. Schema, migration and merge coordination (normative)

- **One migration**, taking the **next free schema version at merge** under Phase 14's X-D12 rule (first come, first served among the open phase branches). The table of §6.3 (`transport_bridge`) is the only schema change; Phase 13's `migration UX` and any late Phase 11 merge reserve their own versions the same way — no version numbers are claimed in this document.
- The migration is a plain additive `CREATE TABLE` (no rebuild, no data movement, no `REPLACE` paths), so it joins the introspection suite and the T20 time-column discipline without a T33 review beyond the day-granularity check of §6.3.
- The `native-libs.sha256` mechanism is **not** reused for lyrebird (that file is for `.so`s; G-T4 owns the PT assets); `SHA256SUMS` under `ghost/third_party/lyrebird/` is its assets-side twin, and the two are checked against each other by the S3 harness so a drift between them fails loudly.

---

## 12. Test plan and exit-gate argument

**Lessons built in.** From Phase 10/11: counts are pinned only after their cost is measured (L-1); a gate without a negative fixture is decoration (the §22.33 evasion review); loopback evidence is a lower bound and the report says so (the Phase 6 live-tor harness already models "manual, recorded" for anything needing the public network, `live_tor.rs:1-9`).

### 12.1 S0 evidence checks (V-T1 … V-T8; run locally, no CI precondition — ADR-58)

| # | Check | Pass criterion |
|---|---|---|
| V-T1 | Lyrebird pin reality: the tag exists, the commit hash matches the tag, the source tree builds; **licence file read and recorded** (§4.2); the main-package path and server-mode flags are what this design assumes | `BUILD.sh` green end to end on a clean checkout; licence + notices recorded |
| V-T2 | No maintained Rust obfs4/WebTunnel client alternative (the D2 rejection re-checked at pin date) | a note in the S0 report naming what was searched (crates.io, Tor's PT list) |
| V-T3 | Server mode: the pinned lyrebird runs as an obfs4 server wrapping a local ORPort and as a WebTunnel server; exact flags recorded | loopback PT-L1 green on the host before any Rust work |
| V-T4 | ptmgr contract read: spawn mechanics, env handling, config keys (`transport.pt_*`), log knobs — the §5.3 assumptions confirmed or corrected into revision 2 | a `tor-ptmgr@<pin>` source note in the S0 report; normative text corrected where wrong |
| V-T5 | Double-build reproducibility (same path, two builds) + the leak check + measured sizes per ABI vs the §9.1 provisional budgets | hashes equal; sizes recorded; OA-3 path documented if over budget |
| V-T6 | Emulator extraction+exec (API 29 and API 35 gate images): PT-1 extracts, verifies, chmods, and a trivial `lyrebird -version`-class exec succeeds from `filesDir/pt/<abi>/` | emulator script green; recorded in the S0 report (the API 37 image, if still available, runs too) |
| V-T7 | Feature-graph check: `pt-client`'s full dependency addition listed, allowlist/licence/size updates drafted | `cargo deny` + allowlist green on the draft branch |
| V-T8 | The loopback obfs4 bootstrap **measurement** (client → lyrebird server → local ORPort): time, bytes on the wire (the PT-L1 capture), post-bootstrap assertion set | PT-L1/PT-L2 green; numbers recorded |

### 12.2 Unit, property and shape tests (PT-U series)

- **Rust (`cargo test -p ghost-client-net`, the `rust` job):** PT-U1 the grammar table (every §3.2/§6.2 acceptance and refusal, incl. the three iat-modes, webtunnel `url`/`ver`, the snowflake distinct refusal, the length cap, duplicates); PT-U2 `TransportConfig` shapes (direct/bridges-only preference, `pt_dir` None/Some, `PtBinaryMissing` when a PT line meets no binary); PT-U3 bootstrap semantics unchanged (the existing `transport.rs` tests pass unmodified — CS-T2); PT-U4 the reduced auto-mode sequence as a pure policy (mocked transports: direct-fail → PT attempt; lines order; spent chains; never clearnet); PT-U5 property test over the validator (§6.2.5); PT-U6 T58's storage half in-process (state/cache/filesDir scan after a mocked PT lifecycle).
- **Kotlin/JVM (`android` job, host library):** PT-U7 PT-3/PT-4 round trip through the host build (validation errors carry the index; nothing is logged — the log fixture fails on a hit); PT-U8 the migration (table shape, day granularity, WITHOUT ROWID, introspection); PT-U9 extraction idempotence and hash-mismatch failure on a JVM-mocked asset stream.

### 12.3 Localhost integration (the gate; PT-L series, `#[ignore]`-class like `live_tor.rs`)

**Harness.** A loopback Tor daemon provides an ORPort (the same Tor the issuer staging runs, `infra/issuer`; the harness starts its own instance with its own datadir and a generated identity — no fixture trusts any external state). The pinned lyrebird runs in **server mode** wrapping that ORPort (obfs4: `-target` the ORPort; WebTunnel: its server flags — exact invocations from V-T3). The client is `ghost-client-net` with `bridge_lines = ["obfs4 127.0.0.1:<port> <fingerprint> cert=<server cert> iat-mode=0"]` and `pt_dir` pointing at the built host binary. Assertions (PT-L2):

1. Bootstrap completes within `BOOTSTRAP_DEADLINE`.
2. The post-bootstrap assertion set of `live_tor.rs`, adapted to a private network: bootstrap success means a **directory-validated circuit to the loopback relay's ORPort through the PT** — the harness proves it by extending the loopback Tor with one throwaway v3 onion service of its own (the Tor daemon can do this natively; no GHOST relay is involved) and asserting the client opens a stream to it — plus the unchanged invariants: keystore empty after bootstrap (the Phase 6 assertion), vanguards-lite pinned, two isolation scopes on two circuits.
3. **PT-L1 (capture):** the harness records the bytes between client and lyrebird-server during handshake and steady state; the fixture asserts the obfs4 stream has no Tor TLS record shape (no `\x16\x03` TLS record layer at the client↔bridge hop — the *entire point*, checked mechanically) and the WebTunnel stream presents a TLS ClientHello + HTTP semantics.
4. Two isolation scopes still get two circuits after a PT bootstrap (the Phase 6 assertion, unchanged).

**Scale and schedule:** the loopback harness runs in the `rust` job locally on dispatch (ADR-58; it needs the built host lyrebird — V-T1's output — so it is a dispatch/weekly gate, never push, the Phase 10 capacity rule). CI scheduling note: like the channel gates, the PT loopback gate runs on dispatch and weekly (the S0 measured runner load of Phase 10, L-3, is the standing reason).

### 12.4 The live run (manual, recorded; OA-1)

One run of the extended `live_tor.rs` with a real public obfs4 line (and one WebTunnel line if OA-1 provides it): bootstrap through the public bridge, the public onion HEAD probe of `live_tor.rs`, the capture recorded, the bootstrap time recorded. This is distribution-day evidence, not a CI gate (public bridges are flaky and unbounded — the same reason `live_tor.rs` is `#[ignore]`d today).

### 12.5 Capture and privacy suites (PT-P series)

- PT-P1: the T58 canary scans (§6.4) — after create, after a (mocked) PT lifecycle, after process death mid-attempt.
- PT-P2: the T1 capture extended with PT fixtures: the relay-visible byte stream on a PT path is byte-class-identical to the direct path (P-T3/T60's capture half).
- PT-P3: the APK fixture: zero bridge lines in the shipped APK (§6.1's canary) and the lyrebird asset bytes equal to `SHA256SUMS` (G-T4's twin in the privacy harness).

### 12.6 Exit-gate argument

The phase's gate claim is the conjunction: (a) PT bridges work end to end — loopback PT-L1/PT-L2 green at the pinned lyrebird and a recorded live run (OA-1); (b) the binaries are what they claim — G-T1/G-T2 reproducibility, G-T4/G-T5 hash chains, licences recorded; (c) the privacy delta is real and bounded — P-T1/P-T2/P-T3 with their tests, LT declared, AD-4 text updated; (d) nothing regressed — CS-T1/CS-T2, all Phase 6 suites unmodified green, size re-measures within budgets. Each claim names its evidence; none is a UI claim (CP-10).

---

## 13. Gates (each with a negative fixture, near-miss positives and a `self-test.sh` hit count; the Phase 9 practice)

| # | Gate | Rule | Fails on |
|---|---|---|---|
| G-T1 | `pt-source-pin.sh` | `pins.env`'s tag/commit/hashes match the recorded values and the built tree; the licence file is recorded in notices | any drift between pin, hash and tree; a mutable ref instead of a commit hash |
| G-T2 | `pt-double-build.sh` | two same-path builds of the pins produce identical SHA-256 (the native library's rule applied to lyrebird) | any difference; a missing second build |
| G-T3 | `pt-size.sh` | extracted and compressed sizes ≤ the S0-pinned budgets (§9.1) | size growth past the pin (a bump that grows the binary without a re-pin) |
| G-T4 | `apk-pt-assets.sh` (T12's assets twin) | the APK's `assets/pt/<abi>/lyrebird` bytes equal `SHA256SUMS`; only the two shipped ABIs present; no other executable asset | any hash mismatch; a third ABI; an unexpected executable in assets |
| G-T5 | runtime hash check (code, tested not scripted) | PT-1 refuses to hand arti a binary whose SHA-256 mismatches the compiled-in sums; release twin has no switch (G-DM5's rule) | any bypass; a debug-only hash skip in release |
| G-T6 | `pt-exec-site.sh` | no `std::process`/`tokio::process`/`ProcessBuilder`/`Runtime.exec` anywhere outside the two allowlisted sites (the ptmgr wiring in `client-core/net`, the PT-1 extraction helper in `android/network`); no module gains `org.ghost.network` imports for PT types outside the allowlist | any new spawn site; a near-miss like `sh -c` in Kotlin |
| G-T7 | `pt-no-bridge-line-in-logs.sh` | no log statement in the net/network modules formats a bridge-line variable; the PT-L/PT-P fixtures' logs contain no injected line | a hit; a fixture that passes vacuously (empty scan fails, the D28 rule) |
| G-T8 | `pt-refusals.sh` | the grammar table is pinned: snowflake and unknown transports refused with distinct errors; PT lines require PT compiled in + binary installed; the APK fixture contains no real bridge line | a grammar change without the fixture update; an accepted snowflake line |

**Extensions to existing gates (no new philosophy):** `rust-dependency-allowlist.txt` and `dependency-allowlist.sh` gain the `tor-ptmgr` family; `rust-feature-policy.sh` gains `pt-client` (and fails on `pt-server` — arti must never gain the server feature); `deny.toml` gains the ptmgr crates' licences; `apk-native-libs.sh` is untouched (lyrebird is an asset, G-T4 owns it); the privacy harness T1 fixtures gain the PT rows (PT-P2).

---

## 14. Implementation slices (each ends green locally; ADR-58)

| Slice | Content | Depends on | Exit condition | Agent-days |
|---|---|---|---|---|
| **S0** evidence | V-T1 … V-T8: the lyrebird pin reality (tag/commit/licence/server flags), ptmgr contract read (normative text corrected into revision 2 if needed), the reproducible double build + leak check + measured sizes, the emulator extract/exec probe, the feature-graph deltas, and the **loopback obfs4 measurement** (client→lyrebird server→ORPort: bootstrap time, PT-L1 byte capture, post-bootstrap assertions) | — (runs on a clean checkout; no product code) | every V-T check green with its record in `docs/design/faza12-s0-evidence.md`; budgets pinned (or OA-3 fired); `BUILD.sh` + `SHA256SUMS` committed | 2.5 |
| **S1** Rust | `pt-client` feature + allowlist/licence/feature-policy updates; the grammar table and validator; `TransportConfig.pt_dir`; `PtBinaryMissing`; the ptmgr wiring with env scrub and per-attempt state dirs; PT-U1 … PT-U6; the refusal relaxations with G-T8's fixtures | S0 | `rust` job green incl. the unmodified Phase 6 tests; library size re-measured within budget; PT-U suite green; `deny`/allowlists green | 3 |
| **S2** Android | the `third_party/lyrebird` Gradle asset hook; `:network` extraction (PT-1/PT-2) with idempotence and hash-verify; the `transport_bridge` migration + DAO (PT-3/PT-4); the reduced auto-mode sequence in the session owner; G-T6 over the tree | S1 | JVM suites green on the host build (PT-U7 … PT-U9); the emulator extract/exec probe green on API 29 + 35 (V-T6 re-run as a suite); auto-mode policy tests green | 3 |
| **S3** tests and gates | the PT-L loopback harness (Tor ORPort + lyrebird server + client, the four assertion groups); PT-P1 … PT-P3; G-T1 … G-T8 with fixtures and self-tests; the dispatch/weekly schedule wired locally; the live-run script (for OA-1) | S1 | PT-L1/PT-L2 green at the pinned binary; all eight gates green with negative fixtures; the exit-checklist evidence table filled | 3 |
| **S4** docs and close | Appendix B applied (INVARIANTS T58–T60, TM AD-4, LIMITE L12, STATUS row, ADR index, plan erratum if the owner rewords row 12); ADR-61/62 filed as "Propus"; the phase's adversarial review and its findings corrected or recorded | S3 | §15 checklist green; review findings dispositioned | 1 |

**Effort.** About **12.5 agent-days** to "implemented and tested locally" (S0's 2.5 + 3 + 3 + 3 + 1), roughly **2–3 calendar weeks** at the repo's two-parallel-session pace. The loopback gate's dispatch/weekly schedule adds calendar time only if its first green run is delayed behind other gates' load (the measured Phase 10 capacity). **Not in these numbers:** the 12b snowflake design (sized when picked up), Phase 14's distribution work, and row 12's tuning clause (F-T1).

---

## 15. Exit-gate checklist (all on the closing commit)

1. Loopback obfs4 bootstrap green at the pinned lyrebird: PT-L1 (byte capture: no Tor TLS shape at the client↔bridge hop) and PT-L2 (bootstrap within deadline, post-bootstrap assertions, empty keystore, two circuits for two scopes). **Evidence:** the S3 report.
2. One recorded live public-bridge run (obfs4; WebTunnel if OA-1 provided a line): bootstrap + public-onion probe + capture + time. **Evidence:** the recorded run (OA-1; if the owner declined OA-1, this item is recorded as not executed and the distribution-day checklist carries it).
3. G-T1 … G-T8 green with fixtures and self-test hit counts; the existing gates they extend unchanged green. **Evidence:** local run records (ADR-58).
4. T58/T59/T60 evidenced: PT-P1 canary scans, G-T5/G-T6, PT-P2 relay-shape fixtures. **Evidence:** the PT-P report.
5. No regression: every Phase 6 test unmodified and green; `libghost_client_net.so` within its re-measured budget; APK within the pinned PT budgets. **Evidence:** the S1/S2 exit re-measures.
6. Appendix B applied; ADR-61 and ADR-62 filed as "Propus"; STATUS updated in the same commit. **Evidence:** S4's diff.
7. The phase's adversarial review done; findings corrected or recorded. **Evidence:** the review note, §16's continuation.

---

## 16. Risks and findings outside the phase

### 16.1 Risks

| # | Risk | Likelihood / impact | Mitigation | Residue |
|---|---|---|---|---|
| R-T1 | The pinned lyrebird tag ages; a censorship environment starts fingerprinting the old obfs4/uTLS | medium / medium | the bump procedure (§4.4) re-runs the whole gate set; L12's evidence table names the pin date | bridge reachability is bridge-operator work; GHOST ships the client half |
| R-T2 | `tor-ptmgr` pulls a dependency the allowlist/deny rejects, or its size pushes the library budget | low / medium | V-T7 drafts the graph before S1; the S1 re-measure; a refusal here means the ptmgr feature waits for an arti bump — the design has no fallback launcher (deliberately: a hand-rolled PT manager is worse) | — |
| R-T3 | A PT child misbehaves on a specific device (SELinux policy, OEM noexec on /data on exotic devices) | low / medium | V-T6 on two API levels; OA-2's device step; failure is a clean config error, never a crash or a silent direct fallback | exotic OEMs may lack PT; the copy says "bridges unavailable on this device" (Phase 13 wording) |
| R-T4 | WebTunnel's uTLS parrot drifts from real browsers; an active DPI learns the WebTunnel shape | medium / low for GHOST | upstream maintenance is the only real answer; the loopback capture catches gross breakage at bumps | LT-4 lives in L12 |
| R-T5 | The loopback harness rots (Tor daemon flags, lyrebird server flags change) | medium / low | flags pinned in V-T3; the harness fails loudly, never silently skips | — |
| R-T6 | User-provided-only lines mean most users never get bridges (no distribution until Phase 14) | certain / medium (availability, not privacy) | Q5's explicit default; Phase 13's paste/QR makes manual lines usable; L12-C6 declares it | availability gap until Phase 14 |
| R-T7 | The reduced auto mode's second attempt doubles bootstrap latency on bad networks | certain / low | per-attempt deadlines (D11); the Phase 13 progress copy; measured numbers in the exit checklist | — |
| R-T8 | A bridge line is a durable identifier of the user's network intent on seizure (unlocked DB) | low / medium | same custody as the whole database (D7); T58 keeps lines out of every *other* place | L12-C2 |

### 16.2 Findings outside the phase (for the owner)

- **F-T1.** Plan row 12's other two clauses (jitter/batch tuning; independent metadata-capture review) have no design home. The Phase 11 design deferred three "decuplarea din Faza 12" items to this phase by name (L9-M2's descriptor-delay decoupling, L9-M4's write/read-owner rule "Faza 12", L9-M5's "conexiuni reutilizate în Faza 12"). None belongs to the transports slice; they belong to the tuning slice. **The owner should commission the row-12 remainder design** (small: traffic-shaping deltas over ADR-15 + a review protocol), or reassign those L9 pointers.
- **F-T2.** `faza13-ux.md:209` lists "Bridges and pluggable transports UI" under Phase 12. This design resolves the split: engine + plumbing = Phase 12 (here); paste/QR/settings = Phase 13 (that design's own components and rules). No document needs an erratum; the row stays true if read as "the bridges work lands across Phases 12–13".
- **F-T3.** The plan's FR-2.9 row (plan:258) says "Bridges / pluggable transports configurabile" without naming transports; ADR-16 names the set. This design follows ADR-16's named set minus the deferred snowflake — if the owner wants snowflake in P0 after all, Q1 is the place (default says no).
- **F-T4.** ADR-16's "Test: captura de trafic nu conține fingerprint Tor cunoscut" is delivered here **for the client↔bridge hop** (PT-L1) and declared, not extended, for the bulk (LT-2). The independent capture review (row 12's third clause) is the check that the *whole* capture set stays inside the allowed set — F-T1 again.

---

## Appendix A: ADR drafts (Romanian)

*The full drafts are filed as `docs/adr/ADR-61-transporturi-pluggable-lyrebird.md` and `docs/adr/ADR-62-liniile-de-bridge.md` (Status: Propus); the texts below are the design's copies (identical).*

### ADR-61 — Transporturi pluggable: obfs4 și WebTunnel prin lyrebird, proveniență din sursă fixată, build reproductibil, execuție prin tor-ptmgr

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-17 (design Faza 12, `docs/design/faza12-transports.md`), în așteptarea deciziei proprietarului (Q11) |
| Sursă | design Faza 12 §3–§5, §7, §9, §12.3; ADR-16 (planul pentru Faza 12); `ghost/scripts/build-native.sh` (disciplina de build) |
| Modifică | ADR-16 (nota „binarele livrate ca `lib*.so` în `jniLibs`" — X-T1; modul auto devine modul redus până la Faza 14 — X-T2); `ghost/Cargo.toml` (feature `pt-client`); `ghost/third_party/lyrebird/` (nou); porțile T12 se completează cu G-T1 … G-T5 |

**Context.** Până în Faza 12 clientul acceptă doar bridges simple, recognoscibile ca Tor (refuzul explicit din `transport.rs`); AD-4 cere ca, pe o cale cu transport pluggable, observatorul local să nu vadă nici măcar că e Tor. Arti 0.46 are suportul de client PT (feature `pt-client`, `tor-ptmgr`), necompilat azi în GHOST; `tor-ptmgr` nu e în `Cargo.lock`.

**Decizie.**
1. Setul P0 de transporturi pluggable: **obfs4 și WebTunnel**, ambele din **lyrebird** (pachetul Go întreținut de Tor Project; un singur binar implementează ambele transporturi, client și server). Fiecare transport se alege din linia de bridge prin protocolul de management PT.
2. **Snowflake e amânat explicit la o Fază 12b** (binar WebRTC separat și mare, cu propria distribuție și propriul review); liniile `snowflake` rămân refuzate cu o eroare distinctă.
3. Binarul lyrebird se construiește dintr-un **tag git fixat** (pinul real e hash-ul commit-ului; tag-ul e documentație) cu un **toolchain Go fixat** (versiune + hash înregistrate, descărcat de la go.dev la build, ca cargo-ndk 4.1.2 la biblioteca nativă), `GOFLAGS=-trimpath -mod=readonly -buildvcs=false`, `CGO_ENABLED=0`, strip cu llvm-strip din NDK, pentru ABI-urile `arm64-v8a` și `x86_64`. Rețeta, pinurile și hash-urile de ieșire stau în `ghost/third_party/lyrebird/` (BUILD.sh oglindind disciplina `build-native.sh`: cale fixă, verificare de scurgeri de căi, **dublă construcție cu comparație de hash-uri** la aceeași cale).
4. Licența lyrebird se citește la pin și se consemnează în notificările terților (așteptare: BSD-3-Clause prin descendenta obfs4 — verificat în S0, nu presupus).
5. **Modelul de proces: `tor-ptmgr` din Arti** (feature `pt-client` pornit în `arti-client`). GHOST îi dă calea binarului, un director de stare per încercare (șters la finalul încercării) și un mediu curățat. Android extrage binarul din **assets** în `filesDir/pt/<abi>/lyrebird`, îl verifică pe SHA-256 înainte de execuție și îi pune drepturi 700. **Abatere de la nota ADR-16 (X-T1):** livrarea ca `lib*.so` în `jniLibs` nu funcționează — Android nu execută din APK sau din directorul de biblioteci native (W^X, noexec); serviciile Tor pe Android (Orbot, Tor Browser) fac exact extragerea în filesDir. Singurul punct din depozit care pornește un proces e cablarea ptmgr din `client-core/net` (poartă G-T6).
6. Bugete de dimensiune provizorii (≤ 8 MiB extras per ABI, ≤ +4 MiB comprimat per ABI), fixate din măsurători în S0; `libghost_client_net.so` se re-măsoară (feature `pt-client` aduce `tor-ptmgr` în graful livrat, cu allowlist și licențe proprii).
7. Testarea de poartă e pe **loopback**: lyrebird rulează și server (obfs4/WebTunnel peste ORPort-ul unui Tor local din infrastructura de staging), clientul face bootstrap prin el — modelul din `tests/live_tor.rs`. Rularea live pe bridge-uri publice e manuală și consemnată.

**Consecințe.** (+) Observatorul local nu mai vede Tor-ness pe calea cu PT (obfs4: octeți aleatorii; WebTunnel: HTTPS); un singur binar, o singură pistă de proveniență; serverul din același binar face testarea de poartă independentă de bridge-uri publice; forma față de relee nu se schimbă deloc. (−) un binar Go suplimentar de câțiva MiB per ABI; o suprafață de supply-chain nouă (Go toolchain, ținută de aceleași pinuri + dublă construcție + hash la runtime); snowflake lipsește până la 12b; PT-ul nu ascunde volumul, timingul sau IP-ul bridge-ului.

**Alternative respinse.** Binare preconstruite (proveniență neverificabilă); lyrebird ca `.so` dlopen (e un program `main()`, nu o bibliotecă; și mount-ul APK nu e executabil); un launcher PT propriu (reimplementează prost protocolul stdio PT); un client obfs4 în Rust (nu există una întreținută — reverificat în S0); snowflake acum (dublează suprafața pentru un transport a cărui distribuție e nedecisă până în Faza 14).

**Teste.** PT-U1 … PT-U9; PT-L1/PT-L2 (loopback: captura de octeți fără formă TLS Tor la hop-ul client↔bridge, bootstrap în termen, keystore gol, două circuite pentru două scope-uri); PT-P1 … PT-P3; porțile G-T1 … G-T8 cu fixture-uri; V-T1 … V-T8.

### ADR-62 — Liniile de bridge: doar de la utilizator, stocare învelită, fără listă încorporată, mod auto redus

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-17 (design Faza 12, `docs/design/faza12-transports.md`), în așteptarea deciziei proprietarului (Q11) |
| Sursă | design Faza 12 §6, §7, §8.5; ADR-16 (modul auto); `faza13-ux.md:209` (interfața e a Fazei 13) |
| Modifică | ADR-16 (modul auto complet cu listă livrată devine mod redus până la Faza 14 — X-T2); schema (o tabelă nouă, migrație la versiunea liberă următoare); suprafața JNI (PT-1 … PT-5); INVARIANTS (T58–T60); TM AD-4 (textul se actualizează) |

**Context.** Faza 6 acceptă doar linii simple și refuză explicit liniile PT; interfața de introducere (paste/QR) aparține Fazei 13, iar distribuția liniilor (cine operează bridge-uri, rotație, costul unei liste confiscate) e spațiul de design al Fazei 14. ADR-16 cere un mod auto, dar modul auto presupune o listă livrată.

**Decizie.**
1. În P0 liniile de bridge sunt **doar de la utilizator**: Faza 12 livrează parsarea, validarea, stocarea și intrarea de test pe host; lipirea/QR-ul rămân în Faza 13 (aceeași apelare PT-3/PT-4).
2. **Nicio listă încorporată**, niciun fetch, nicio rotație: distribuția e întrebarea Fazei 14 (Q5). APK-ul conține zero linii (fixture de poartă) — **abatere declarată față de „bridges implicite" din ADR-16** (X-T2).
3. Validarea e o singură funcție, totală, cu tabel de gramatici fix (plain, obfs4 cu iat-mode 0/1/2, webtunnel cu url https și ver): parametrii opaci semantic pentru GHOST nu se interpretează niciodată de GHOST; `snowflake` și orice alt nume se refuză distinct; limită de 1 024 de caractere și de 8 linii; deduplicare exactă.
4. Stocarea: o tabelă (`transport_bridge`: linia, ziua adăugării; fără coloană de timp, WITHOUT ROWID) în baza SQLCipher existentă — criptată cu cheia bazei, fără cheie nouă, cu aceeași politică no-backup. Nicio linie în loguri, în stare/cache Arti sau în afara bazei (T58, scanare-canar).
5. **Modul auto redus** (X-T2): mai întâi direct; la eșec/timeout, un client nou pe bridge-uri, în ordinea liniilor, fiecare cu termenul propriu de 180 s; niciodată clearnet. Modul auto complet cu listă livrată se decide cu distribuția (Faza 14).
6. Suprafața JNI e închisă (PT-1 … PT-5): instalare/disponibilitate PT, setare/listare linii, câmpurile de configurare; erorile poartă indexul linii, nu linia.

**Consecințe.** (+) fără poveste de custodie separată pentru linii; fără suprafață de distribuție proiectată pe jumătate; refuzurile rămân deliberate și testate. (−) majoritatea utilizatorilor n-are bridge-uri până la Faza 14 (disponibilitate, nu confidențialitate — L12-C6); a doua încercare de bootstrap dublează latența pe rețele proaste; o linie de bridge e un identificator durabil al intenției de rețea la sechestru cu baza deblocată (aceeași custodie ca tot restul bazei).

**Alternative respinse.** Listă încorporată acum (distribuția nerezolvată: cine operează, rotația, costul confiscării — reproiectată de Faza 14 oricum); fetch de linii la prima rulare (aceeași problemă, plus un contact de rețea nou); un fișier învelit separat per linie (a doua poveste de custodie, fără câștig); stocarea liniilor în configurația Arti pe disc (T58 interzice explicit).

**Teste.** PT-U1, PT-U2, PT-U5, PT-U7; PT-P1 (canarul T58); G-T7, G-T8; secvența modului auto ca politică pură (PT-U4).

---

## Appendix B: Text changes in other documents (Romanian; applied in slice S4)

### B.1 INVARIANTS.md — rows to add

| ID | Text (row for `ghost/test-harness/privacy/INVARIANTS.md`) |
|---|---|
| T58 | **Nicio linie de bridge în afara bazei.** O linie de bridge (simplă sau cu transport pluggable) nu apare niciodată în loguri, în crash dump-uri, în directoarele de stare/cache Arti sau în vreun fișier de pe dispozitiv în afara bazei SQLCipher. Dovadă: canarul PT-P1 (o linie sintetică injectată de test nu apare în niciun alt loc); poarta G-T7. |
| T59 | **Doar binarul verificat se execută.** Aplicația pornește un proces doar pentru transporturile pluggable și doar pe binarul lyrebird extras din propriul APK, verificat pe SHA-256, din `filesDir/pt/<abi>/`; niciun alt modul nu pornește procese. Dovadă: G-T5 (verificarea la runtime), G-T6 (poarta textuală pe toate modulele), V-T6 pe emulator. |
| T60 | **Hop-ul PT e doar client→bridge.** Un circuit cu transport pluggable arată identic cu unul direct dinspre relee, onion service-uri și issuer: forma față de ele nu se schimbă niciodată. Dovadă: fixture-urile PT-P2 din captura T1; aserțiunile PT-L2. |

### B.2 THREAT_MODEL_v2.1.md — AD-4 row, updated

| ID | Rând nou (înlocuiește TM:52) |
|---|---|
| AD-4 | **Observator de rețea local** (ISP, Wi-Fi ostil, angajator) | Vede IP-ul utilizatorului și că vorbește cu Tor/bridge; volum și timing | Destinație, conținut, GHOST ca aplicație. Cu bridges simple: vede și fingerprint-ul Tor. Cu transport pluggable (Faza 12, după poartă): **nu vede nici Tor** pe hop-ul client↔bridge (obfs4: octeți aleatorii; WebTunnel: HTTPS); vede în continuare IP-ul bridge-ului, volumul și timingul (L12). |

### B.3 LIMITE — new section L12

*Header: `## L12. Transporturi pluggable (Faza 12; ADR-61, ADR-62; design docs/design/faza12-transports.md §2, §7)` — cu tabelul de mai jos și o trimitere la evidența PT-L/PT-P pentru fiecare margine.*

| # | Reziduu | Mitigare | Limita rămasă |
|---|---|---|---|
| L12-C1 | PT-ul ascunde Tor-ness doar față de observatorul local și doar până la bridge; operatorul bridge-ului vede un client Tor (aceeași clasă de încredere ca un guard) | forma față de relee neschimbată (T60) | — |
| L12-C2 | Volumul și timingul sunt la fel de vizibile ca înainte; padding-ul de fond e clauza de tuning a rândului 12 (Q7), nu a transportului | LT declarat | bulk traffic rămâne măsurabil (LT-2) |
| L12-C3 | IP-ul și portul bridge-ului sunt vizibile; un bridge cunoscut/enumerat e el însuși un semnal; un adversar activ poate confirma că IP-ul vorbește obfs4/webtunnel (probing) | T58 (linia nu scapă nicăieri); distribuția e Faza 14 | enumerarea bridge-urilor rămâne un risc de operator (LT-1, LT-3) |
| L12-C4 | Parrotul uTLS al WebTunnel-ului îmbătrânește față de browserele reale; un DPI activ poate măsura deriva | bump-urile lyrebird re-rulează poarta | drift-ul față de upstream e consemnat la fiecare pin (R-T4) |
| L12-C5 | Bootstrap-ul prin PT e mai lent decât cel direct (măsurat pe loopback în S0/S3; cifra reală vine din rularea live) | termen per încercare; copia de onboarding măsoară | numărul real e în checklist-ul de ieșire, nu aici |
| L12-C6 | Fără listă de bridge-uri încorporată: majoritatea utilizatorilor n-are bridge-uri până la distribuție (Faza 14) — disponibilitate, nu confidențialitate | Q5 explicit; paste/QR în Faza 13 | golul de disponibilitate până la Faza 14 (R-T6) |
| L12-C7 | Un binar Go înseamnă o suprafață nouă de supply-chain (toolchain Go, module Go) | același regim ca biblioteca nativă: pin, dublă construcție, hash în repo și la runtime, licență consemnată | un al doilea lanț de încredere, declarat |

### B.4 STATUS row, ADR index, plan

- **STATUS.md** — Phase 12 row changes from "neîncepută" to the standard in-progress wording when S0 lands (the exact text is S4's job; this design's Appendix only notes the row must name: the PT set, the deferral of snowflake, the open exit gate).
- **docs/adr/README.md** — ADR-61 and ADR-62 added under "Propuse" with the titles of Appendix A.
- **Plan** — no erratum needed for row 12's wording if Q7's default stands; if the owner commissions the row-12 remainder design, its row reference is updated then (F-T1).

---

## Appendix C: Evidence — verified vs assumed

| # | Claim | Status |
|---|---|---|
| C-1 | Lyrebird implements obfs4 + WebTunnel (client and server) in one binary, maintained by the Tor Project; a pinned tag/build recipe is achievable | **assumed** (V-T1, V-T3 verify: tag, commit, flags, build) |
| C-2 | Lyrebird licence is BSD-3-Clause (obfs4 lineage) | **assumed — verified in S0 before any commit of binaries** (V-T1; §4.2) |
| C-3 | Android executes only app-private files; the APK mount and the native-lib dir are noexec; Orbot/Tor Browser extract PT binaries to filesDir (X-T1's basis) | **assumed** at AOSP/primary-source level (V-T6 demonstrates it on the gate emulators; Appendix D names the sources) |
| C-4 | arti-client 0.46's `pt-client` feature enables tor-ptmgr; ptmgr spawns/supervises PT processes over the PT stdio protocol; config keys and env behaviour are as §5.3 assumes | **assumed** (V-T4 reads the crate source at the pin and corrects this document where wrong); what is verified today: `pt-client` is off and `tor-ptmgr` is absent from `Cargo.lock` (read in this worktree) |
| C-5 | obfs4's client node-id is derived from the bridge line's certificate (no client disk state) | **assumed** (obfs4 spec; the PT-P1/keystore assertions test its consequence) |
| C-6 | `transport.rs` today refuses PT lines with `TransportError::Config` and has the plain-bridge plumbing, the 180 s deadline and the spent-client rule | **verified** (`transport.rs:24,31-34,116-128,162-186,290-298`, read at `16e1a3da`) |
| C-7 | The build/gate discipline to mirror: pinned cargo-ndk, fixed target dir, path remapping, leak check, same-path double-build in CI, `apk-native-libs.sh` allowlist + per-file hash | **verified** (`build-native.sh`, `apk-native-libs.sh`, STATUS Phase 6 row) |
| C-8 | The live-tor harness model (`tests/live_tor.rs`, `#[ignore]`, manual runs) and the issuer staging infra running Tor | **verified** (files read at `16e1a3da`; `infra/issuer`) |
| C-9 | Size budgets (§9.1) are provisional by design; Go binaries compress ≈ 40–60 % | **assumed** (S0 measures; the compression ratio is a planning guess, not evidence) |
| C-10 | AD-4's goal text, ADR-16's Phase-12 plan, the plan row 12 scope, the Phase 13 UI-row split | **verified** (TM:52; ADR-16; plan:316; `faza13-ux.md:209`) |

## Appendix D: Sources (accessed 2026-10-17)

| Source | Used for |
|---|---|
| Repository files cited inline (`transport.rs`, `build-native.sh`, `apk-native-libs.sh`, `net/Cargo.toml`, `Cargo.lock`, `live_tor.rs`, `faza13-ux.md`, plan, TM, LIMITE, ADR-16, STATUS) | all "verified" rows of Appendix C |
| Tor Project, lyrebird repository (`gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird`) and its README | the PT-set facts of §3 (to be re-verified at the pin, V-T1/V-T3) |
| Tor Project specifications: `pt-spec.txt`, the obfs4 spec (`obfs4-spec.txt`), the WebTunnel proposal | the management protocol, obfs4's derived node-id, WebTunnel's HTTPS cover (C-4, C-5's basis) |
| Arti workspace docs/crate sources for `tor-ptmgr` and the `pt-client` feature | §5's process model (V-T4's reading list) |
| AOSP docs on W^X / app private storage; Orbot and Tor Browser for Android's PT packaging (their source trees ship lyrebird/obfs4proxy as extracted executables) | §5.4's exec model (C-3) |
| Go toolchain distribution practice (go.dev versioned tarballs, `GOFLAGS`/`-trimpath` semantics) | §4's recipe (V-T1 exercises it) |
