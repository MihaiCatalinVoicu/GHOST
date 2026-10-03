# GHOST Phase 14: Distribution — Design (proposed)

| Field | Value |
|---|---|
| Status | **Proposed, 2026-10-03, for the owner's approval before any code** (the owner's rule: an approved design before implementation). ADR-48 … ADR-52 (Appendix A, Romanian) are "propus"; they become "propus, aplicat" only if the owner approves this design or lets the question defaults of §15 stand under the standing instruction to continue between phases. Nothing here is a UI claim (CP-10). |
| Revision | 1 (branch `p14-design`, based on `197b2b4`). Drafting author's synthesis of five research digests (requirements, signing and keys, channels, reproducible builds, threats and testing; 2026-09-25), with every load-bearing claim re-checked in the repository or at a primary source for this draft (Appendix C). Three digest claims were found wrong and are corrected here (Appendix C.4): GitHub's self-hosted runner fee was postponed, not introduced (§6.4); Accrescent's requirements page names no bundletool version (§8.2); the key requirement is FR-8.2, not FR-8.5 (§1.4). |
| Date | 2026-10-03 |
| Phase | 14 (plan §6.2 row 14, the authoritative scope): "Distribuție: semnare offline/HSM, manifest, anti-rollback, onion mirror, repo F-Droid/Accrescent, build reproductibil din două medii" (plan:318) |
| Exit gate | "tamper/downgrade/rotation drill; hash identic din două medii" (plan:318), read with spec FR-7.5 ("Tampered APK/manifest and downgrade are rejected", spec p.10), FR-8.1 and FR-8.2 ("Key compromise and rotation drill completed", spec p.11), spec §12.2 (p.21) and the production checklist items C-07, C-08, C-12 (spec p.28). §1.2 says exactly what the gate proves and what it leaves to release gates |
| Depends on | Phase 1 only (plan:318, "1 (paralel)"). **In fact also:** Phase 6 (`client-core/net`, the unused `IsolationScope::Update`, `isolation.rs:30-31`), Phase 7 (`relay_directory`, `RelayDirectory.kt:5`, periodic runs), Phase 8 (the ES and its gate, quiet runs, `SessionParticipant.kt:26-39`), the Phase 9 code on `main` (the closed-JNI pattern, the licence gates G-L1 … G-L5). It does not depend on Phases 10–13 and changes none of their designs except where §9.8 says so |
| ADR impact | New: **ADR-48** (keys, roles, custody, ceremonies, trust root), **ADR-49** (signed manifest, binary transparency log, attestation-bound updates), **ADR-50** (reproducible build from two environments, release artifact set), **ADR-51** (the in-app updater: update runs, anti-rollback, staged rollout, installer, directory), **ADR-52** (distribution channels and application identity). Deviations recorded in §0.3 (X-D1 … X-D16). **Numbering:** Phase 10 uses ADR-40 … ADR-43, T36–T41, migrations 6 and 7, LIMITE L8 (`faza10-forum.md:12,42`); Phase 11 uses ADR-44 … ADR-47, T42–T47, migration 8, LIMITE L9 (`faza11-media.md:8,893`). This design takes **ADR-48 … ADR-52, T48–T52, LIMITE L10** and **migration U**, the next free schema version at merge (9 if Phases 10 and 11 land first; §9.6) |
| Sources | Master plan v2.1; spec v2.0 PDF (`output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf`, text extracted with `pdftotext`, since the Read tool cannot render it here: FR-7.5 p.10, FR-8.x p.11, §12 p.21, §13.1 p.22, R-09/R-11 p.25, Appendix C p.28); ADR-01 … ADR-39; THREAT_MODEL v2.1; LIMITE; INVARIANTS T1–T35; STATUS; the Phase 7, 8, 9, 10 and 11 designs; `docs/ci-self-hosted.md`; the build scripts, gates and workflows; primary sources listed in Appendix D (accessed 2026-10-03 unless stated). Repository citations are `path:line` at `197b2b4`, relative to the worktree root (`ghost/…` for the monorepo). `F7`, `F8`, `F9`, `F10`, `F11` = `docs/design/faza7-sync-engine.md`, `faza8-issuer.md`, `faza9-dm.md`, `faza10-forum.md`, `faza11-media.md`; `TM` = `docs/THREAT_MODEL_v2.1.md`; `INV` = `ghost/test-harness/privacy/INVARIANTS.md`; `LIM` = `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`. Appendix C separates verified from assumed; Appendix D lists sources |

**How to read this document.** §0 is the summary: decisions, guarantees, deviations, non-goals. §1 fixes scope, requirements and the exit gate; §2 the threat and privacy model of the distribution chain. §3–§8 are normative: keys and ceremonies (§3), data formats at byte level (§4), the transparency log and attestations (§5), the reproducible build (§6), the update protocol and the client (§7), the channels (§8). §9 is the integration (modules, JNI, `:sync`, schema), §10 the invariants, §11 tests and the exit-gate argument, §12 gates, CI and dependencies, §13 slices, effort and the checklist, §14 risks, §15 owner questions, §16 owner actions and legal items, §17 findings outside the phase. Appendix A holds the ADR drafts (Romanian), Appendix B the text changes in other documents (Romanian where the target is Romanian), Appendix C the evidence and the S0 checks, Appendix D the sources. A section marked "(normative)" wins over a summary table.

**Identifier conventions.** Decisions `D1…D24`; requirements `RQ-D1…`; guarantees `CS-D1…` (security and correctness) and `P-D1…` (privacy); deviations `X-D1…`; threat scenarios `DS-1…`; keys `K-…`; ceremonies `RK0…RK6`; formats `GHRT` (root), `GHRC` (root chain), `GHRM` (manifest), `GHRA` (attestation statement), `GHRP` (log proof), `GHRB` (bundle); invariants `T48…T52`; gates `G-D1…`; mutants `MC-D…` (security, correctness) and `PM-D…` (privacy); twin worlds `NI-U1…`; S0 checks `V-D1…`; risks `R-D1…`; questions `Q1…`; owner actions `OA-1…`; legal items `LG-1…`; findings `F-D1…`; residues `L10-D1…` (new LIMITE section L10). Slices `S0a`, `S0b`, `S1…S10`, and the deferred `S-store`.

---

## 0. Summary

### 0.1 Decisions

| # | Decision | Rejected alternatives (why) | Plan / ADR alignment |
|---|---|---|---|
| D1 | **Channels.** The onion mirror is the primary channel and the only one built in Phase 14: static, signed, logged files on ≥ 2 onion services. First installs come from the mirror (Tor Browser) or any channel at all, checked by the standalone verifier (D21). **Accrescent** is deferred behind conditions GHOST does not control today (sign-up open only to allowlisted accounts, verification of the app-ID domain, no self-updater in the uploaded app, APK sets only; §8.2). **No F-Droid-format repository** (Q71's default, applied under the standing instruction, `faza9-s0-hygiene.md:147`). | Google Play (Google holds the app signing key, `support.google.com/…/9842756`; legal identity of the developer; A7, TB-6); the F-Droid main repository (FLOSS only, inclusion policy); a clearnet HTTPS mirror (users' IPs and a GHOST domain on clearnet, against LIM:158); IPFS (gateway sees IP and version; removed by ADR-07); building the Accrescent flavor now (no admission, cost ≈ 1 week, Q26) | FR-8.10 (plan:279), ADR-37 point 7 (`ADR-37:20`), Q71; deviation X-D6 |
| D2 | **Networks and identities.** Stagenet and mainnet each get their own trust root and their **own Android signing key** (spec §12.1, "separate signing and secrets", p.21); stagenet builds carry `applicationIdSuffix ".stagenet"`, so an alpha install can never be updated to, or by, a production APK. The final `applicationId` is decided before the first distribution (Q3): it is permanent after one release, and `org.ghost.app` (`app/build.gradle.kts:11`) names a domain the project does not hold. | One signing key for both networks (spec §12.1; an alpha key compromise would reach production installs); keeping `org.ghost.app` by inertia (Accrescent's domain check, §8.2; a name already used by others needs extra review under Android developer verification, §8.5) | spec §12.1; ADR-22 point 4 (keys pinned per network) |
| D3 | **Roles and algorithms** (§3.1). `K-APK`: the Android signing identity, **ECDSA P-256** (APK v2 algorithm 0x0201; Ed25519 is not an APK signature algorithm). `K-REL1`, `K-REL2`: release keys, **Ed25519**, threshold 1 of 2. `K-ROOT1…3`: root keys, Ed25519, threshold 2 of 3, one held by a second party. `K-ATT-*`: independent builders' (auditors') attestation keys, Ed25519, listed in the root. The schedule key `K-SCHED` keeps its role (ES). Every key is listed in a versioned root document; losing or rotating a release, attestation, log or witness key is a root update, not an app update. | Ed25519 for the APK (impossible); RSA-4096 for the APK (valid, slower on tokens, no gain; RSA-3072 is not in the v2 size list; recorded alternative); one pinned manifest key without a root (its loss strands every installed updater); FROST or multi-party signatures (no token support; independent signatures with a threshold give the same property) | A7, AS-10 (`TM:25,41`), FR-8.2 |
| D4 | **Custody** (§3.2, §3.3). Hardware tokens: YubiKey 5 series with firmware ≥ 5.7 (PIV Ed25519). `K-APK` is generated on the air-gapped signer host, imported into two tokens and split by **SLIP-39 3-of-5** into paper shares in separate custody, because a lost Android signing key cannot be rotated away (rotation needs the old key's signature) and is a new app identity. Release keys are generated on their tokens (loss → root update). The offline signer host is a dedicated air-gapped laptop booted from a verified read-only image. | On-token generation of `K-APK` (no backup: loss = every user reinstalls and loses local data); cloud KMS (online, identity-bound, clearnet); YubiHSM 2 (sound, ≈ 10× the cost; alternative in Q6); a software key on the online workstation (TB-6, A7) | FR-8.2 "offline/HSM-backed storage, multi-party access, documented rotation"; R-11 (spec p.25) |
| D5 | **Ceremonies** (§3.4): RK0 genesis (two people), RK1 release and heartbeat signing (the owner alone), RK2 root update (root threshold, a second party), RK3 Android-key rotation, RK4 compromise response, RK5 annual restore drill, RK6 heartbeat-only re-signing. **Multi-party** applies to the root and to recovery, **not** to each release (deviation X-D5): a solo owner must be able to ship a security fix alone. | Two people for every release (unoperable for a solo owner); one person for everything (no recovery, no check on root changes) | FR-8.2; K1 precedent (`faza8-issuer.md:456`) |
| D6 | **Short signed statements** (§4.2): every GHOST signature is Ed25519 (`verify_strict`) over `"ghost/v1/<type>" ‖ 0x00 ‖ network ‖ SHA-256(body)` (≤ 61 bytes), so a hardware token signs it whatever the body's size. | Signing whole bodies as the ES does (`schedule.rs:282-284`): tokens reportedly cap Ed25519 messages near 1 KiB (V-D7); JSON/JWS (parsing surface; the ES precedent is canonical binary) | CP-09 exception recorded in ADR-49 with vectors |
| D7 | **Formats** (§4): canonical binary documents in the ES style — root `GHRT` (versioned, N→N+1 needs both thresholds), root chain `GHRC`, manifest `GHRM`, attestation statement `GHRA`, log proof `GHRP`, bundle `GHRB` — with TUF's properties (thresholds, versioned root, expiry, monotonic sequence, exact hash and length, size bounds) and TUF's attack list as tests. | TUF through `tough` 0.24.0 (pulls `aws-lc-rs`, C and assembly, into the APK; JSON parsing; no delegations; a timestamp role that wants an online key, TB-6); python-tuf / go-tuf (not Rust, not Android); in-toto layouts (no client) | spec §12.2 steps 1–4 |
| D8 | **Freshness**: a manifest expires at most **91 days** after issue (`not_after_day`), is re-signed at least at every quarterly K1 ceremony (RK6) or release; every update run reads the bundle from **two mirrors** and the highest `(root_version, manifest_seq)` pair wins; an expired manifest makes the channel STALE (no offers; the app keeps working). | An online timestamp key (TB-6, A7); freshness from witness timestamps with a scan of the log's tail (a shared public log's tail is large over Tor); no expiry (unbounded freeze by stale mirrors); 6 weeks (stronger bound, monthly ceremonies: Q8) | spec §12.2 step 1 ("at least two independent locations"); TM S10 (`TM:165`) |
| D9 | **Binary transparency log: Sigsum** (log protocol v1, stable), public logs with a named trust policy (2 logs; witnesses Glasklar Teknik, Mullvad VPN, Tillitis). Each manifest is logged as a Sigsum leaf (`message = SHA-256(manifest)`) signed by a release key; mirrors serve the inclusion proof and the cosigned tree head; **clients never contact the log** and verify offline; cosignatures need no freshness, so a dead log never strands clients. | Rekor v2 (witnessing "will be implemented soon" at GA; yearly log shards); a GHOST-run log (its operator is the vendor, witnesses would need recruiting); no log (ADR-38 point 6, approved) | ADR-38 point 6 (`ADR-38:19`); spec §12.2 step 2 "release-registry commitment" (X-D3) |
| D10 | **Attestation-bound updates** (§5.5, §7.4): the updater parses the downloaded APK as Android does (EOCD, central-directory offset, APK Signing Block before it) and hashes its **unsigned core**; the core must equal the release's attested unsigned build, signed by at least the root's attestation threshold of independent builders (0 on stagenet until an auditor exists; ≥ 1 on mainnet). T12b becomes a property the installed app enforces. | Trusting the release key's word for the build (AD-V signs anything); attestations from GitHub's hosted runner (no keys in CI, TB-6; GitHub artifact attestations need GitHub Enterprise Cloud for a private repository, `actions/attest-build-provenance` README) | ADR-38 point 5 (T12b), FR-8.9 (plan:278) |
| D11 | **Builder and two environments** (§6): one recipe (`infra/builder/Dockerfile` + `pins.txt`), every input pinned by digest or SHA-256, built inside the container from a git checkout of a signed tag, on tmpfs, at fixed paths, with a fixed CPU count. Environment A: the owner's workstation (Docker). Environment B: a GitHub-hosted `ubuntu-24.04` runner. `SHA256SUMS(A) = SHA256SUMS(B)` before signing. Environment C, the auditor's, is a release gate (FR-8.9). | Native Windows builds (backslash paths, `build-native.sh:9-11`); Cargo `trim-paths` (open PR #17488, targeted at Rust 1.101; the pin is 1.98.1); Nix (+1–2 weeks to learn, still Google binaries); Guix (no Android SDK); a prebuilt image alone (not itself reproducible); the self-hosted runner as B (same laptop and WSL2 VM as A, `ci-self-hosted.md` §7) | plan:318 gate; INV T12 (`INV:20`); ADR-19 (`ADR-19:13`) |
| D12 | **Release artifact set** (§6.1): the zip-aligned unsigned APK; both stripped native libraries **and their split symbol files** (line tables), bound by a deterministic GNU build-id and by the manifest; `ghost-relay`, `ghost-issuer`, `ghost-issuer-ops`, `ghost-release-ops`; the notices; CycloneDX 1.7 SBOMs generated deterministically; AGP's `vcsInfo` **off** (the commit is bound by the logged manifest and the attestations, so a source-escrow tarball also reproduces). | Shipping unstripped libraries (size, NFR-4); symbols without a build-id (no standard symbolication); keeping `vcsInfo` (builds from a tarball differ; the file adds nothing the log lacks); SPDX 2.3 (requires a creation timestamp) | ADR-38 points 5, 9 (`ADR-38:18,22`); ADR-37 point 8; C-08 |
| D13 | **Signing preserves the core** (§6.5): `apksigner` from build-tools 37.0.0 with `--alignment-preserved true`, v2 and v3 on, v1 and v4 off; `ghost-release-ops` checks `core(signed) = unsigned` byte for byte before anything is logged or published. | `apksigcopier` (archived 2025-05-12, GPLv3+); the default re-alignment of build-tools ≥ 35 (rewrites padding, breaks the relation; F-Droid issue 3299) | — |
| D14 | **Mirrors and protocol** (§7.1, §7.2): static files over **HTTP/2 with prior knowledge** inside the onion stream (the client's existing hyper `http2` stack), fixed paths, one bundle per network, APKs by SHA-256 with `Range` in fixed 4 MiB steps, no client-specific header, no access logs, PoW defenses. Server: nginx if S0 confirms h2c (V-D12), else a ~300-line `ghost-mirror`. | HTTP/1.1 (a second HTTP parser in the client); gRPC (third parties could not mirror plain files); relays as mirrors (capabilities, circuit linkage) | ADR-01 (`ADR-01:14`), T6 |
| D15 | **Update runs** (§7.3): a third kind of periodic run, drawn from client randomness only (1 in 24 of the runs that are not quiet runs), with neither a relay session nor an issuer call; its own isolation scope `Update`; two mirrors; the APK is downloaded in update runs (resumable) or at the user's request. **No check at app start** (deviation X-D1 from FR-7.5's "startup update checks"). | A check at app open (the mirror would see app opens: T19's spirit, ADR-15); inside quiet runs (co-occurs with issuer calls, T23); during relay sessions | FR-7.5; T19, T23 (`INV:27,31`) |
| D16 | **Anti-rollback** (§7.5): the platform's `versionCode` rule plus persisted, append-only facts (root version, the `(root_version, manifest_seq)` pair and its hash, floor); an equal pair with other bytes = persistent `CONFLICT`; a new root version starts a new sequence space (escape from a fast-forwarded sequence); `versionCode` = a release counter in a committed file, checked against the log by the release tool. No downgrade path (deviation X-D4). | An "emergency recovery" downgrade (Android refuses lower `versionCode`; uninstall loses local data) | CP-08, FR-7.5, spec §12.2 step 3, C-07 |
| D17 | **Staged rollout and halt** (§7.6): a per-release permille and salt in the manifest; the bucket is `HMAC(rollout_key, salt)` from a per-install secret that never leaves the device; halt = permille 0; **rollback = roll-forward** (the previous source with a higher `versionCode`), since a schema version and an ES never go back. | Server-side cohorts (identifiers); one fixed bucket per install (the same users always first) | FR-8.8, spec §12.2 step 5, C-12, §13.1 "missing release rollback" |
| D18 | **Installer hand-off** (§7.7): a `PackageInstaller` session, the user always confirms; the verified bytes are streamed into the session through the native verifier (no check-then-use window); `REQUEST_INSTALL_PACKAGES` joins T15 by ADR-51; no silent updates. | `ACTION_VIEW` on a file URI (a `FileProvider`, a second copy); `UPDATE_PACKAGES_WITHOUT_USER_ACTION` (user control; Phase 13 may revisit, Q16) | T15 (`common.sh:15`), `AndroidManifest.xml:5` |
| D19 | **Directory and ES** (§7.8, §7.9): bootstrap relay and mirror entries compiled into the native library from committed, gate-checked files (source `config`); the first verified manifest takes the directory over and later ones add and withdraw relays (bootstrap entries included), so a hostile relay leaves every client without an app release; the ES stays embedded (no network path, ADR-22 point 5) and each release records `es_seq` and `es_sha256`, so a changed ES is visible in the log (F8 F6). | ES over the network (ADR-22); the release key signing the ES (GHES v1 signs its whole body, so a token cannot sign it, F-D1); no bootstrap (production code fills the directory nowhere today, F-D3) | `RelayDirectory.kt:5`, `relay-directory.txt:2-3`, `ADR-22:23,45`, `faza8-issuer.md:2255` |
| D20 | **Module split** (§9): a new Rust crate `ghost-client-update` (pure: no I/O, clock or logging) in `libghost_client_net.so`; the mirror fetch in `client-core/net` on `IsolationScope::Update`; a **closed JNI surface** `org.ghost.network.UpdateNative` (gate G-D5, the G-R6 pattern); a Kotlin module `:update`; update runs in `:sync`; schema migration U; the offline tool `ghost-release-ops`; the public verifier `ghost-verify` on the same format crate. No new external crate in any shipped graph. | Verification in Kotlin (ADR-19); a second native library (a second Rust runtime) | ADR-19 (`ADR-19:13`), ADR-20 |
| D21 | **First install, operators, monitors** (§5.4): the standalone verifier `ghost-verify` (desktop CLI, offline proof checks, optional Tor fetch) and the published signing-certificate fingerprint (apksigner, AppVerifier); relay operators check `ghost-relay` against the logged release before running it, and operator images take the released binary; a public monitor checks every logged GHOST leaf against the archive. | An in-app self-check (a malicious APK would skip it); trusting store or mirror operators | ADR-38 points 6, 7 (`ADR-38:19-20`), F9 §22.8.8 point 3 |
| D22 | **Provenance and publication** (§5.3): releases only from **signed tags** (hardware-backed key, committed allowed-signers file); the release record (manifests, proofs, APKs, symbols, SBOMs, notices, MPL sources, ES files, relay binary, attestations, escrow digest) is published in the mirrors' archive and referenced by hash from the logged manifest. | Publishing from CI or on GitHub (G-L5, `no-public-binaries.sh:22-24`; ADR-39) | FR-8.1 (STATUS:25 gap), C-08 |
| D23 | **Supply-chain hardening in scope**: pin the `aapt2` jars (today trusted without checksum, `verification-metadata.xml:8`), pin the JDK patch level, one pins file feeding the builder and CI (G-D2); Gradle signature verification decided in S0 (Q22); `cargo-vet` not adopted (Q23). | — | T7, AD-9 (`TM:58`) |
| D24 | **Android developer verification and Play Protect** are platform facts outside GHOST's control: no registration in Phase 14; the owner decides before the beta with counsel (Q18); the Android key's backup keeps registration possible; the residues are declared (L10-D9, L10-D10). | Registering now (ties the owner's legal identity to the package at Google before it is needed) | §8.5 |

### 0.2 Guarantees claimed (each has a test in §11; none is a UI claim before the gate closes, CP-10)

| ID | Guarantee | Proof |
|---|---|---|
| CS-D1 | **Signed and logged.** The updater installs only APK bytes listed in a manifest signed by the release threshold of the newest verifiable root, and only when that manifest is included in a policy log under a checkpoint cosigned by the witness quorum. | T48: vectors, every-byte tamper suites, MC-D1 … MC-D12, MC-D20, MC-D23 |
| CS-D2 | **Reproduced before trusted** (when the root's attestation threshold is ≥ 1). The unsigned core of the installed APK, found as Android finds it, equals a build attested by that many independent builders. | T48 attestation clause; crafted-APK suite; MC-D15, MC-D21 |
| CS-D3 | **No rollback.** Root version, the `(root_version, manifest_seq)` pair and floor never decrease; nothing at or below the installed `versionCode` is offered; equivocation at one pair is detected and kept. | T49; MC-D6, MC-D7, MC-D16 … MC-D18; emulator downgrade case |
| CS-D4 | **Bounded freeze and bounded input.** No offer comes from an expired manifest; every fetched object has a size bound fixed before reading; a mirror cannot hold the client below the newest manifest the other mirror serves. | T50; MC-D8, MC-D13; hostile model mirrors |
| CS-D5 | **Identical from two environments.** The release outputs of a tagged commit have identical SHA-256 in environment A and environment B. | T12 (extended); `release-build.yml` |
| CS-D6 | **Signing keys never online.** No signing secret is in the repository, in CI or on a mirror; signing happens on the offline host, and `core(signed) = unsigned` holds for every published APK. | T52; G-D1; the RK1 checklist |
| CS-D7 | **Key loss and compromise are recoverable** within the declared bounds: any single token, any single root key, the release keys, the log and witness sets and the attestation keys rotate without a new app identity; the Android key survives total token loss through its shares. | rotation drills (§11.5), RK5 |
| P-D1 | **Update traffic is independent of activity.** Update runs and their fetches are a function of the process's random key and run index only. | T51; NI-U1, NI-U2; PM-D1, PM-D6 |
| P-D2 | **Onion-only, own scope.** Every update fetch goes over Tor to an onion listed in a verified manifest or the bootstrap list, on the `Update` isolation scope, never during a relay session or an issuer call. | T51, T6; PM-D2 |
| P-D3 | **Uniform requests.** Every client in an update run asks for the same objects with the same headers; no request carries a version, root version, identifier or conditional header. | T51; NI-U3, NI-U4; PM-D3 … PM-D5, PM-D8 |
| P-D4 | **Rollout without identifiers.** The rollout bucket is per release, derived from a secret that never leaves the device. | T51; PM-D7 |

### 0.3 Deviations from approved documents (each recorded in an ADR of Appendix A)

| ID | Deviation | From | Recorded in |
|---|---|---|---|
| X-D1 | Update checks happen in activity-independent update runs and at the user's request, not at app start | FR-7.5 "startup update checks" (spec p.10) | ADR-51 |
| X-D2 | APKs come only from onion mirrors | spec §12.2 step 4 "HTTPS/IPFS" (already ADR-07; restated) | ADR-52 |
| X-D3 | The binary transparency log is the "release-registry commitment" | spec §12.2 step 2 (an on-chain registry, removed by ADR-02) | ADR-49 |
| X-D4 | No authorised downgrade; recovery is roll-forward | spec §12.2 step 3 "unless an emergency recovery policy explicitly authorizes them" | ADR-51 |
| X-D5 | Multi-party access for the root and recovery, single-party (owner) release signing | FR-8.2 "multi-party access" (spec p.11) | ADR-48 |
| X-D6 | "repo F-Droid/Accrescent" decided and documented, not built in Phase 14 | plan:318, ADR-37 point 7 (Accrescent) | ADR-52 |
| X-D7 | Effort 6–7 calendar weeks for a team of 5–6 (≈ 21 person-weeks), not 3–4 | plan:318 | §13.2, Appendix B.1 |
| X-D8 | `REQUEST_INSTALL_PACKAGES` in the T15 allowlist; one non-exported installer-status receiver (T15m) | T15 (`INV:23`, `common.sh:15`), `AndroidManifest.xml:5` | ADR-51 |
| X-D9 | A new crate in `libghost_client_net.so` and a new closed JNI class | ADR-19 (consistent with it; recorded) | ADR-51 |
| X-D10 | One file outside SQLCipher: the staged APK under `noBackupFilesDir/update` | the T20 discipline (`INV:28`), applied by analogy | ADR-51 |
| X-D11 | The phase gate's "două medii" = two vendor environments (workstation, hosted runner); the auditor's environment (FR-8.9) is a release gate | plan:318 read with FR-8.9 (plan:278) | ADR-50 |
| X-D12 | Schema migration numbers follow merge order, not reservation | F11 §13.6 rule (c) (`faza11-media.md:893`) | §9.6, Q34 |
| X-D13 | Staging mirrors run by one party until a second operator exists | spec §12.2 step 1 "independent locations", TM:165 | ADR-52 |
| X-D14 | `vcsInfo` off; `versionCode` from a committed release counter; `.stagenet` suffix | `app/build.gradle.kts:11,14-15` | ADR-50, ADR-52 |
| X-D15 | Release native libraries built with line-table debug info, split, stripped after link, with a GNU build-id | `ghost/Cargo.toml:97-99` (`strip = "symbols"`), `build-native.sh` | ADR-50 |
| X-D16 | Per-release signing by one person; the K1 "two people" rule kept for genesis and root changes only | the K1 practice (`faza8-issuer.md:456`) | ADR-48 |

### 0.4 What this design deliberately does not do

- **Self-update UX** (screens, the "Install unknown apps" prompt, alarms for STALE and CONFLICT, release notes): Phase 13. Phase 14 delivers a UI-less facade (§9.5).
- **Bridges in the manifest**: the field is reserved and must be empty in v1 (§4.5); Phase 12 fills it and must also embed a default set, since a manifest cannot be fetched while Tor is blocked (F-D7).
- **The mainnet genesis** (RK0 for network 1) and network selection at build: with the mainnet K1, Phase 16/17 (`ADR-22:29`). Phase 14 runs the full chain on stagenet.
- **Operating the rollout** (choosing percentages, health signals, the rollback threshold): Phases 17–18 with the runbook of §7.6; Phase 14 builds the mechanism and rehearses it.
- **The audit itself and the auditor's first attestation**: Phase 15 and a release gate.
- **Accrescent submission, an F-Droid-format repository, Google Play, delta updates, APK Signature Scheme v3.2 (ML-DSA hybrid, Android 17+), multi-device, desktop clients, open-sourcing** (ADR-37; Q61 of F9).
- **Any telemetry or health metric collected from clients** (ADR-06).
- **Changing the ES format** (GHES v2, hash-then-sign): F-D1, before the mainnet K1.

---

## 1. Scope, requirements, non-goals

### 1.1 Requirements (normative; each has a source and a test)

| ID | Requirement | Source | Test |
|---|---|---|---|
| RQ-D1 | Every production update is signed, hash-verified and protected against rollback | CP-08 (spec p.5) | T48, T49 |
| RQ-D2 | Signed manifests, APK hash verification and anti-rollback are mandatory; "Tampered APK/manifest and downgrade are rejected" | FR-7.5 (spec p.10; the FR-7 table's text order places this sentence fifth); plan:202 | T48, T49; drills §11.5 |
| RQ-D3 | Every production artifact reproducibly built where practical, signed, with a hash and an SBOM; "Release pipeline verifies provenance and dependency lock" | FR-8.1 (spec p.11; mapping in §1.4 item 1) | T12, G-D2, signed tags (D22) |
| RQ-D4 | Release signing keys offline/HSM-backed, multi-party access, documented rotation; "Key compromise and rotation drill completed" | FR-8.2 (spec p.11); R-11 (spec p.25); TM key table (`TM:89`) | RK0 … RK6, drills §11.5 |
| RQ-D5 | Signing material never in CI | TB-6 (`TM:72`); `ci.yml:7-8`; `ci-self-hosted.md` §10 | T52, G-D1 |
| RQ-D6 | The manifest is fetched from at least two independent locations | spec §12.2 step 1 (p.21); TM S10 (`TM:165`) | T50 |
| RQ-D7 | The manifest verifies against a pinned key and a "release-registry commitment when available" | spec §12.2 step 2 | T48 (root anchor, log proof) |
| RQ-D8 | Versions below the installed anti-rollback floor are rejected | spec §12.2 step 3 | T49 |
| RQ-D9 | Exact APK hash and Android signing identity verified, then the platform install flow | spec §12.2 step 4 | T48; emulator §11.4 |
| RQ-D10 | Rollout staged and haltable without invalidating installed versions; 5/25/50/100 rehearsal | spec §12.2 step 5; FR-8.8; C-12 (p.28) | §11.5 rollout cases |
| RQ-D11 | Every connection, the update manifest included, only over Tor to v3 onions listed in the signed manifest; fail-closed | ADR-01 (`ADR-01:14-15`); plan:145; T6 (`INV:14`) | T51, T6 |
| RQ-D12 | No protocol logic in Kotlin | ADR-19 (`ADR-19:13`) | G-D5, module split §9 |
| RQ-D13 | No telemetry; no version, user-agent or locale on the wire | ADR-06; ADR-08 last point (plan:214); Phase 6 review (STATUS:15, "fără `user-agent`") | T51 |
| RQ-D14 | Background network activity independent of user activity | T19, T23 (`INV:27,31`); ADR-15 | T51; NI-U1, NI-U2 |
| RQ-D15 | Reproducible build verified before signing by two independent environments, one an external auditor who publishes the attestation | FR-8.9 (plan:278); ADR-38 point 5 (`ADR-38:18`); T12/T12b (`INV:20`) | T12 (two vendor environments, phase gate); T48 attestation clause and RK1 (auditor, release gate) |
| RQ-D16 | Channels: onion mirror, Accrescent, optional own F-Droid-format repository; not the main F-Droid repository; IPFS not primary | FR-8.10 (plan:279); ADR-37 point 7 (`ADR-37:20`); Q71 (`faza9-s0-hygiene.md:147`) | §8 (decided per channel) |
| RQ-D17 | Witnessed binary transparency log; the updater refuses an APK without an inclusion proof and a cosigned checkpoint; a standalone verifier for first installs; relay and issuer releases logged; operators verify before running | ADR-38 point 6 (`ADR-38:19`); F9 §22.8.8 point 3 | T48; `ghost-verify` tests |
| RQ-D18 | Native symbol files published per release, hash-bound to the shipped library | ADR-38 point 9 (`ADR-38:22`) | G-D3 completeness; V-D9 |
| RQ-D19 | A separate public repository with the first-install verifier and the black-box kit's manifest and native-library checks | ADR-38 point 7 (`ADR-38:20`); Q63 | S7 exit |
| RQ-D20 | Source escrow per version, its hash in the log | ADR-38 point 10 (`ADR-38:23`) | manifest artifact kind 16 |
| RQ-D21 | Third-party notices for every shipped artifact; SBOM per version with the notices' hash; MPL sources on the distribution channels | ADR-37 points 2, 3, 8 (`ADR-37:15,16,21`) | G-L1 … G-L4; G-D3 |
| RQ-D22 | SBOM, dependency locks, provenance and APK hash and signature published or archived | C-08 (p.28) | release record (§5.3) |
| RQ-D23 | Signed update rejects tamper and rollback; emergency key-rotation drill complete | C-07 (p.28) | §11.5 |
| RQ-D24 | Runbooks: release signing-key compromise and emergency trust-root rotation; forced minimum version | spec §12.3 (p.21); FR-8.5 | RK4; floor (§7.5) |
| RQ-D25 | Staging has separate signing and secrets | spec §12.1 (p.21) | D2; G-D4 |
| RQ-D26 | The ES has no network path; its consistency against a compromised release key is open until Phase 14 | ADR-22 points 5 and consequences (`ADR-22:23,45`); F8 F6 (`faza8-issuer.md:2255`) | `es_seq`, `es_sha256` in every release; monitor (§5.3) |
| RQ-D27 | The relay directory is filled from the signed manifest | `RelayDirectory.kt:5`; `Schema.kt:277-279`; `relay-directory.txt:2-3`; `DirectoryEsSlots.kt:31` | §7.8 tests |
| RQ-D28 | No workflow publishes anything; no public binaries | G-L5 (`no-public-binaries.sh:22-24`); ADR-39 | G-L5 extended (G-D1) |
| RQ-D29 | A release ships ≥ 26 weeks of ES keys (no gate checks it today: it would depend on the build date) | `ghost/protocol/entitlement/README.md:37-42` | `ghost-release-ops manifest-build` (release-time check, not build-time; G-D4) |
| RQ-D30 | A missing release rollback blocks production | spec §13.1 (p.22) | D17 roll-forward drill |
| RQ-D31 | UI claims only with published evidence and the residue sentence | ADR-38 point 11 (`ADR-38:24`); CP-10; FR-8.7 | Phase 13 copy (§2.6) |

### 1.2 The exit gate, read precisely

The gate has four parts, and this design closes each with stated evidence (§11.7, §13.3):

1. **Tamper drill.** Every tampered root, manifest, proof, bundle and APK is refused, by the Rust core (vectors and every-byte mutation), by the JVM update world against hostile model mirrors, on an emulator with the real installer, and once **live** on stagenet: the real mirrors, the real log, a real phone.
2. **Downgrade drill.** A rolled-back manifest, an older root, a release at or below the installed `versionCode`, an APK below the floor: refused or not offered; the platform's own refusal of a lower `versionCode` is shown on the emulator.
3. **Rotation drill.** On stagenet with the real tokens (RK2, RK3, RK5): a release-key rotation, a root-key rotation, an Android-key rotation through a v3.1 lineage installed over the previous release on API 33+ and on API 29 (where the old key keeps working, L10-D3), a witness-set change, an attestation-key change, a mirror retirement, and the emergency revocation of a release key.
4. **"Hash identic din două medii".** The closing tag's release outputs (§6.1) have identical SHA-256 in environment A (the owner's workstation) and environment B (a GitHub-hosted runner), both built from the committed recipe.

**Not proved by the phase gate (release gates, §13.3 last row):** the auditor's reproduction and attestation (T12b, FR-8.9's second environment), the production log policy on mainnet, a second independent mirror operator, the Android developer verification decision, counsel's items (§16), the licence screen (Phase 13).

### 1.3 Non-goals and deferrals (each with the constraint that decides it)

| Item | Why not here | Where |
|---|---|---|
| Update screens, permission prompt, release notes | UX is Phase 13 (plan:317) | Phase 13 on the §9.5 facade |
| Bridges in the manifest | a blocked Tor cannot fetch a manifest; needs an embedded set first (ADR-16) | Phase 12 (F-D7) |
| Mainnet genesis and network selection at build | follows the mainnet K1 (`ADR-22:29`) | Phase 16/17 (RK0 on network 1) |
| Accrescent flavor and APK sets | no admission possible today (§8.2) | S-store, when the conditions of §8.2 hold (Q26) |
| F-Droid-format repository | no verifier covers it (Q71) | not planned |
| Delta updates | each delta is another artifact to reproduce, attest and log | not planned |
| APK Signature Scheme v3.2 (ML-DSA hybrid) | Android 17+ only; no hardware token signs ML-DSA; needs new classical and PQC keys | Q33 |
| Health telemetry | ADR-06 | manual signals only (§7.6) |

### 1.4 Contradictions between documents and how this design resolves them

1. **FR-8 numbering.** In the spec's §4.8 table the ids, the requirement texts and the acceptance criteria come in the same order in the extracted text (spec p.11): FR-8.1 reproducible, signed, hash and SBOM ("Release pipeline verifies provenance and dependency lock"); FR-8.2 offline/HSM keys ("Key compromise and rotation drill completed"); FR-8.3 telemetry; FR-8.4 declarative infrastructure; FR-8.5 incident response; FR-8.6 security contact; FR-8.7 claims; FR-8.8 staged rollout. The plan (§7, "CP-10 și FR-8.7"), TM S9 ("SBOM (FR-8.1)") and ADR-07 ("Înlocuiește … FR-8.1") agree; **ADR-37 point 8** cites FR-8.2 for the SBOM, **ADR-38's header** completes "FR-8.2, FR-8.8", and **F9 §2.10.6** cites FR-8.8 for UI claims. This design uses the spec's order and proposes the three errata of Appendix B.5 (citation fixes; no decision changes).
2. **FR-7.5 "startup update checks"** against T19 and T23: a check at app start tells the mirror when the app opens. Resolved by update runs (X-D1).
3. **"Pinned release key"** (spec §12.2 step 2): the pinned object is the root (D3), which survives a lost release key; the release key is pinned through it.
4. **"Emergency recovery policy"** (spec §12.2 step 3): Android refuses a lower `versionCode` (developer.android.com, "Version your app"), and an uninstall loses the local data. Resolved by roll-forward (X-D4).
5. **Accrescent** is a channel in ADR-37 point 7 and Q71's default, but its rules (no self-updater, APK sets, app-ID domain verification) and its closed sign-up make it unreachable now (X-D6, §8.2).
6. **"Două medii"** (plan:318) and FR-8.9's auditor: no auditor exists before Phase 15; the phase gate uses two vendor environments, the auditor's is a release gate (X-D11).
7. **LIM:158** ("distribuția prin F-Droid repo/onion mirror") and **TM S10** ("F-Droid repo cu build reproductibil") predate ADR-37: Appendix B.3 and B.4 rewrite them.
8. **"Phase 14 may make the release key sign the ES directly"** (`faza8-issuer.md:463`): not adopted, because GHES v1 signs its whole body, which a token cannot (D6, F-D1); the release record logs the ES instead (D19).
9. **Migration numbers**: F11 reserves 8 after Phase 10's 6 and 7; schema versions must be contiguous on a device, so whichever phase merges first takes the next number (X-D12).

---

## 2. Threat and privacy model of the distribution chain

### 2.1 Assets (TM AS-10 split; Romanian rows in Appendix B.3)

| ID | Asset | Where | If compromised | If lost |
|---|---|---|---|---|
| AS-10a | `K-APK`, the Android signing key, per network | two tokens + SLIP-39 shares (§3.3) | anyone can sign APKs Android accepts as GHOST updates **outside** the updater (sideloads); the updater still needs a logged manifest (and attestations) | without shares: a new app identity, every user reinstalls and loses local data (identity recoverable from the mnemonic; tokens not, `LIM` E11) |
| AS-10b | `K-REL1`, `K-REL2` | one per token | can sign manifests: metadata and availability attacks (directory, mirrors, freeze within expiry), all logged; no code execution without AS-10a | root update replaces them |
| AS-10c | `K-ROOT1…3` | token, paper shares, second party | with 2 of 3: replaces every other key (logged through the next manifest) | 1 of 3: root update; 3 of 3: recovery only through a new APK carrying a new root (§3.5) |
| AS-10d | `K-ATT-*` (auditors) | the auditor's machine | false attestations; harmless without AS-10a/b | root update |
| AS-10e | `K-SCHED` (existing, ES) | offline, raw 32-byte file (`protocol/entitlement/README.md:20-28`) | can sign tagging ES versions; they reach clients only inside logged APKs | new key pinned in the next APK |
| AS-10f | mirror onion keys | mirror hosts | impersonation of that mirror (serves only what a mirror can: signed bytes or nothing) | retire the mirror in the next manifest |
| AS-10g | `K-TAG`, the git signing key | hardware-backed (FIDO2 SSH key) | signed tags for malicious commits; caught only by review and the auditor's reproduction of the source it read | new key in the allowed-signers file |
| AS-10h | `K-RL`, the Sigsum rate-limit key | owner's workstation, DNS TXT | none for trust (rate limiting only) | new key, new TXT record |
| AS-10i | the release record (archive) | mirrors | none (public, hash-bound by logged manifests) | republish |

### 2.2 Adversaries (TM §3)

AD-1 and **AD-V** are one party for new versions (`TM:49,56`): the vendor can sign, log and publish anything. The design does not prevent a malicious vendor release; it makes it **public and attributable** (log), **reproducibility-checked** (attestations, once an auditor exists) and **identical for everyone** (no per-user manifests). Other parties: a **malicious mirror operator** (AD-2 class), **AD-9** (supply chain: dependency, toolchain, CI), **AD-12** (legal compulsion), **AD-4** (local network), **AD-8** (device), **log and witness operators**, the **auditor**, **Google** (the platform's developer verification and Play Protect on GMS devices), **store operators** (Accrescent, if ever used).

### 2.3 Scenarios (each → mitigation → residue → test)

| ID | Scenario | Mitigation | Residue (LIMITE L10) | Test |
|---|---|---|---|---|
| DS-1 | CI or a self-hosted runner is compromised (anyone who can push runs code with sudo, `ci-self-hosted.md:192-196`) | CI holds no key (T52); CI outputs only hash lists (text); the signed APK is the workstation build, signed only if equal to the hosted runner's hashes; signing on the offline host | a compromise identical in A and B (a poisoned pinned input) passes (L10-D7) | G-D1; `release-build.yml` |
| DS-2 | The owner's workstation is compromised (source changed before tagging) | signed tags with a hardware-backed key; the auditor reproduces from the source it reviews (release gate) | before an auditor exists, a malicious source change by the workstation's attacker is not detected by reproducibility (L10-D7; L-SRC) | tag verification in G-D4 |
| DS-3 | The offline signer host is compromised | read-only verified boot image; it only checks hashes and asks tokens to sign (PIN, touch); `core(signed) = unsigned` checked again online before logging; monitors compare logged APKs with attested builds | it could get a wrong-but-valid-looking manifest signed if the owner approves without reading the RK1 output (L10-D11) | RK1 checklist; monitor |
| DS-4 | A malicious mirror serves stale, garbage, endless or split data | signatures and log proofs; size bounds; two mirrors per run, highest `(root_version, manifest_seq)` pair; equivocation flag; expiry | a freeze up to the expiry if every reachable mirror is stale (L10-D4) | T50; hostile model mirrors |
| DS-5 | A release key is compromised | it cannot make an installable APK; every manifest it signs must be logged (clients refuse unlogged ones) and is seen by monitors; RK4 rotates it out through the root | metadata attacks until rotation (directory, mirrors, rollout); logged (L10-D11) | rotation drill; MC-D3 |
| DS-6 | `K-APK` is compromised | the updater still requires a logged manifest and, with threshold ≥ 1, attestations; RK3 rotates with a v3.1 lineage; the floor forces the rotated release | sideloaded malicious APKs are accepted by Android outside the updater; on API 29–32 the old key keeps working after a rotation targeted at 33 (L10-D3, L10-D12) | emulator rotation cases |
| DS-7 | Keys are lost | SLIP-39 shares for `K-APK`; root threshold 2 of 3; tokens in pairs | all three root keys lost: the updater strands; recovery needs a new APK (sideload, verified with `ghost-verify`) carrying a new root (L10-D13) | RK5 drill |
| DS-8 | Downgrade (manifest, root, APK) | §7.5; platform `versionCode` | a fresh install of an old, validly signed APK is accepted by Android; the app reports UNSUPPORTED after its first update run (L10-D5) | T49; emulator |
| DS-9 | Targeted build (AD-V, AD-12) | one manifest for everyone, logged; equivocation detection across mirrors and by monitors; attestations | detection after the fact, not prevention; first installs and store channels outside the updater (L10-D1, L10-D2) | T48; monitor |
| DS-10 | The log or witnesses misbehave or disappear | client verification is offline; split views need the log and a witness quorum to collude; proofs do not expire | the default policy's witnesses share a parent company (L10-D6); no new manifest can be logged while every policy log is down; a root change needs a log of the previous policy (L10-D17) | MC-D11, MC-D12 |
| DS-11 | The auditor is compromised or coerced | attestations bind only the reproduced bytes; useless without AS-10a and AS-10b | collusion of auditor and vendor is not covered | — |
| DS-12 | Supply-chain compromise (AD-9) | Gradle checksums (and signatures, Q22), cargo-deny, `--locked`, crate allowlists, pinned toolchains, SBOM | an upstream compromise of a pinned version before disclosure (TM S9) | T7; G-D2 |
| DS-13 | Update-channel metadata | update runs (T51); onion only; uniform requests; no logs at mirrors | the mirror sees update-run fetches and APK downloads, i.e. "a client updates now" and the APK size (the version); a download resumed over several runs links those runs by its ranges (L10-D8) | T51; NI-U1 … NI-U4 |
| DS-14 | The local network sees the download | Tor | a ~70 MiB Tor download burst is visible (L10-D14) | — |
| DS-15 | Google on GMS devices (Play Protect, developer verification) | none possible in the app; disclosed; de-Googled systems recommended in Phase 13 copy | the platform may send app details or the APK to Google at install; from 2027 unregistered apps need the "advanced flow" on certified devices (L10-D9, L10-D10) | — |
| DS-16 | Store channels (if Accrescent is ever used) | none (no updater in a store build) | store updates bypass log and attestation; the store learns installs (L10-D2) | — |
| DS-17 | Operators run unverified relay binaries | `ghost-verify operator`; operator images built from the released binary | an operator who does not check (L10-D15) | S8 |
| DS-18 | Device clock manipulated to revive an expired manifest | decisions about time only under the sync engine's clock trust (READY ⇒ ±3 days, F7:58; ±1 h step rule, F7:1655) | ±3 days around expiry (L10-D4) | MC-D8 |

### 2.4 Who sees what in the update channel (Romanian rows in Appendix B.3)

| Event | Mirror (onion) | Local network | Relays, issuer | Log, witnesses | Google (GMS device) | Device (AD-8) |
|---|---|---|---|---|---|---|
| Update run | at an activity-independent time, one circuit fetches `current.ghrb` from each of two mirrors; same path, headers and bytes for every client | Tor traffic | — (no relay session, no issuer call in an update run) | — | — | the latest manifest, proof, root and the facts of §9.6 |
| APK download | a circuit fetches `apk/<sha256>` in 4 MiB ranges: "a client updates to the offered version" | a Tor burst of the APK's size | — | — | — | the staged file until installed |
| Install | — | — | — | — | Play Protect may send app details or the APK (L10-D9) | the platform's install records |
| User "check now" (Phase 13) | as an update run, at the user's moment (declared) | Tor | — | — | — | — |
| First install (Tor Browser) | as an APK download, from Tor Browser's circuit | Tor Browser traffic | — | — | as Install | — |
| Release publication (owner) | receives files over its onion | — | — | the owner's submission over Tor; the leaf is public | — | — |

### 2.5 The property the gate proves

For a client running a GHOST build from the log, under the assumptions A3 (Tor) and the hardness of Ed25519, SHA-256 and the APK signature: (i) it installs, through its updater, only APK bytes listed in a manifest signed by the release threshold of its newest verifiable root and included in a policy log under a quorum-cosigned checkpoint; (ii) when the root's attestation threshold is k ≥ 1, only APKs whose unsigned core k independent builders attested; (iii) its root version, its `(root_version, manifest_seq)` pair and its floor never go back, and it never offers a version at or below its own; (iv) its update traffic is a function of its process key and run index and of the public manifest only. **Against AD-V** the property is detection: a targeted or malicious release reaches updater users only after appearing in a public log (and, with k ≥ 1, after an auditor attested a build of it), and never differs between users. **It says nothing** about first installs not checked with `ghost-verify`, store updates, operators who do not check their binaries, the platform's own reporting to Google, or the correctness of reviewed source (L-SRC).

### 2.6 Claims (CP-10; ADR-38 point 11)

Allowed in Phase 13 copy only after the gate closes and with the evidence named: "Actualizările sunt semnate, înregistrate într-un jurnal public cosemnat de martorii numiți în politica <nume> și, de la <versiune>, reproduse de <auditor>." Always beside the residue: "Prima instalare și actualizările din magazine nu trec prin această verificare; folosiți verificatorul public." Forbidden: "sigur", "imposibil de falsificat", "verificat de oricine", "martori independenți" while the policy's witnesses share a parent company (L10-D6), "reproductibil" without a named attestation, any statement about Google's handling of installs.

---

## 3. Keys, roles, custody and ceremonies (normative; ADR-48)

### 3.1 Roles and algorithms

| Key | Algorithm | Signs | Lives | Threshold | Rotation | Backup |
|---|---|---|---|---|---|---|
| `K-APK` (per network) | ECDSA P-256, self-signed X.509 certificate (subject `CN=GHOST`, no personal name; the certificate's DER bytes are part of the identity and are committed, `protocol/release/<network>/apk-signer.crt`) | the APK Signing Block (v2 + v3; v3.1 after a rotation) | tokens T1, T2 (PIV slot 9c, PIN always, touch always) | — | RK3 (v3.1 lineage) | SLIP-39 3-of-5 of the 32-byte scalar |
| `K-REL1`, `K-REL2` | Ed25519 | `GHRM` statements; Sigsum leaves | generated on T1 and T2 respectively (PIV slot 9d), non-exportable | 1 of 2 | RK2 | none needed (root replaces) |
| `K-ROOT1` | Ed25519 | `GHRT` statements | token T3 (owner) | 2 of 3 | RK2 | none (threshold) |
| `K-ROOT2` | Ed25519 | `GHRT` statements | SLIP-39 2-of-3 paper shares of its 32-byte seed, signed with on the offline host only | 2 of 3 | RK2 | the shares are the key |
| `K-ROOT3` | Ed25519 | `GHRT` statements | token T4, held by a second party (Q7) | 2 of 3 | RK2 | none (threshold) |
| `K-ATT-<name>` | Ed25519 | `GHRA` statements | each independent builder's own machine | root's `attest` threshold | RK2 | the builder's |
| `K-SCHED` (existing) | Ed25519 | the ES (`"ghost/v1/entitlement-schedule" ‖ body`) | offline, raw seed (stagenet key outside the repository today) | — | pinned per network in `ghost-entitlement` | unchanged by this phase (F-D1) |
| `K-TAG` | Ed25519 (OpenSSH `sk-ssh-ed25519`, FIDO2 on a token) | release tags | owner's token | — | allowed-signers file | second token |
| `K-RL` | Ed25519 | Sigsum rate-limit tokens | owner's online workstation | — | DNS TXT `_sigsum_v1.<domain>` | none needed |

**Why two algorithm families.** APK Signature Scheme v2 accepts RSA (1024 … 16384 bits), ECDSA (P-256, P-384, P-521) and DSA, not Ed25519 (source.android.com, "APK Signature Scheme v2"); the manifest keys follow the ES precedent (Ed25519, `ed25519-dalek` 2.2.0 already in the client, `ghost/Cargo.toml:75`) and Sigsum's leaf signatures (Ed25519). **Why P-256 and not RSA-4096:** both are in the v2 list and in YubiKey PIV; P-256 signs faster on a token and gives the same security level for this purpose; RSA-3072 is not in the v2 size list. RSA-4096 stays the recorded alternative (Q6).

### 3.2 Hardware and the offline signer host

- **Tokens.** YubiKey 5 series with firmware ≥ 5.7 (PIV Ed25519 and X25519, key import, move and delete; docs.yubico.com, "YubiKey 5.7 firmware specifics"). Firmware cannot be upgraded, so the tokens are bought with 5.7+. Four per network at minimum: T1, T2 (signing pair), T3 (root key 1), T4 (second party's root key 3). PIV PIN and management key changed from defaults at RK0; touch policy "always" for every signing slot.
- **Signer host.** A dedicated laptop whose radios are disabled in firmware, never networked, booted from a **read-only, signature-verified Debian live image** (the image's `SHA256SUMS` and its signature checked on the online workstation, written to write-protected media). Tools on a second write-protected medium, each checked against `SHA256SUMS` from the two build environments (§6.4): `ghost-release-ops` (§9.1), build-tools 37.0.0 (`apksigner`, `zipalign`) and a JDK 17 runtime (apksigner is Java; JDK 21 needs extra flags for SunPKCS11, fdroidserver issue 1313), Yubico's `ykcs11` or OpenSC (PKCS#11), `yubico-piv-tool`. Inputs and outputs travel on a separate medium that is wiped after each ceremony.
- **PKCS#11 paths (checked in S0b, V-D6, V-D7).** `apksigner sign --provider-class sun.security.pkcs11.SunPKCS11 --provider-arg <cfg> --ks NONE --ks-type PKCS11` is the documented token path (it is example 5 of build-tools 37.0.0's own `apksigner sign --help`, read locally on 2026-10-03). Ed25519 statements are signed through PKCS#11 (`CKM_EDDSA`) or `yubico-piv-tool`; ykcs11 gained the Ed25519 key type in yubico-piv-tool 2.5.0 (release notes), but the signing mechanism is not documented there (V-D7). **Fallback** if V-D7 fails: the release and root Ed25519 seeds live encrypted on the signer host's media (never on a networked machine), with the same thresholds; recorded in ADR-48.
- **Why short statements matter here.** A third-party project reports that YubiKey PIV refuses Ed25519 messages above about 1 KiB (search result, unverified; V-D7 measures). Every GHOST statement is ≤ 61 bytes and every Sigsum leaf statement 56 bytes (§4.2), so the limit never applies; the ES, which signs its whole body (`schedule.rs:282-284`), stays a software key (F-D1).

### 3.3 Backups and the multi-party rule

- **`K-APK`** is generated on the signer host (OpenSSL, P-256), its certificate created there once (validity per V-D19), the key and certificate imported into T1 and T2, the raw scalar split by **SLIP-39** (status Final; reference implementation `python-shamir-mnemonic`, MIT, run on the signer host) into **3-of-5** shares: owner's home safe, a bank deposit box, two trusted persons, counsel or an escrow agent. The scalar never exists elsewhere; the signer host's RAM is the only place it is assembled (RK0, RK5).
- **Root.** Threshold 2 of 3 with `K-ROOT3` held by a second party: no single person can rewrite the trust root, and the owner can always act with `K-ROOT1` plus the `K-ROOT2` shares (slow by design: the shares sit in different places).
- **Per-release signing is single-party** (the owner with T1 or T2). This is X-D5: FR-8.2's "multi-party access" is met for the trust root and for recovery, not for routine releases, because a solo owner must be able to ship a fix alone; the log makes every release public, which is the check a second signer would give.

### 3.4 Ceremonies (runbook `ghost/infra/release/RUNBOOK.md`, Romanian, each step with its expected output)

| Ceremony | When | Who | What | Output |
|---|---|---|---|---|
| **RK0 genesis** | once per network (stagenet in this phase; mainnet with the mainnet K1, Phase 16/17) | owner + witness (second party) | generate `K-APK` and its certificate, import to T1/T2, SLIP-39 shares; generate `K-REL1` on T1, `K-REL2` on T2, `K-ROOT1` on T3, `K-ROOT2` seed (shares), `K-ROOT3` on T4; sign root v1 with all three root keys | `root-1.ghrt`, `apk-signer.crt`, public keys; signed checklist |
| **RK1 release** | each release | owner | verify inputs (two `SHA256SUMS`, unsigned APK, attestations, manifest source); `apksigner sign` (PKCS#11); `ghost-release-ops apk-core` (`core(signed) = unsigned`); build the manifest, sign it, sign the Sigsum leaf statement and write the add-leaf request | signed APK, `GHRM`, add-leaf request |
| **RK2 root update** | key rotation, witness or log change, attestation keys, APK signer list | two of three root key holders | build root v(n+1); sign with ≥ 2 old and ≥ 2 new root keys; log its leaf under the **old** root's policy (signed by an old release key) and assemble its `GHRP`; then an RK1-style manifest under the new root | `root-(n+1).ghrt` and its proof, a new manifest |
| **RK3 Android-key rotation** | every 2 years (Accrescent's recommendation, should it ever apply) or on compromise | owner + witness | new `K-APK'` as in RK0; `apksigner rotate` (the old signer's `rollback` capability off — apksig's default); RK2 adds the new certificate digest | lineage file, `root-(n+1).ghrt` |
| **RK4 compromise response** | on suspicion | owner (+ root holders) | revoke by RK2 (drop the key from the root); raise the floor; RK3 if `K-APK`; publish a notice in the archive; Phase 13 shows CONFLICT or the floor | new root and manifest |
| **RK5 restore drill** | yearly (`TM:89`) and at RK0 | owner + one share holder | restore `K-APK` from three shares onto a blank token on the signer host, compare public key and certificate, sign a test APK, wipe; restore `K-ROOT2` and sign a test statement | signed drill record |
| **RK6 heartbeat** | at least every 91 days (with each quarterly K1) | owner | re-sign the current manifest with sequence + 1 and new dates; log it | `GHRM`, add-leaf request |

**RK1 in steps** (the runbook's form: each step names its expected output; any other output stops the ceremony, as runbook K1 does, `infra/issuer/RUNBOOK.md` §5.1):

1. On the online workstation: `git verify-tag v<code>` against `protocol/release/<network>/allowed_signers` → "Good signature"; `release-build.yml` for the tag green; the local environment-A build done. Copy to the transfer medium: the unsigned APK, `SHA256SUMS-A` (local), `SHA256SUMS-A` (job) and `SHA256SUMS-B` (job, from the run's summary), the manifest source, the current root chain, the attestations received.
2. On the signer host: `ghost-release-ops sums-compare A-local A-job B-job` → `SUMS_EQUAL files=<n>`; `sha256sum -c` of the APK against them → `OK`.
3. `apksigner sign …` (§6.5) with T1 or T2 (PIN, touch) → no output; `apksigner verify -v --print-certs signed.apk` → v2 and v3 "true" and the certificate digest of the root.
4. `ghost-release-ops apk-core --apk signed.apk --expect <unsigned sha256>` → `CORE_EQUAL`.
5. `ghost-release-ops manifest-build --source … --root-chain … --apk signed.apk --attestations …` → `MANIFEST_BUILT seq=<s> root=<r> releases=<n> sha256=<…>`; it refuses (`MANIFEST_REFUSED <reason>`) a counter not above every logged one, an ES ending before the release week + 25, a missing ES slot onion, an attestation that does not verify.
6. `ghost-release-ops statement --manifest …` → the 59-byte statement file; sign it on the token; `ghost-release-ops attach` → `SIGNED keys=<k>/<t>`.
7. `ghost-release-ops leaf-statement` → the 56-byte Sigsum statement; sign it on the token; `ghost-release-ops leaf-request` → `LEAF_REQUEST message=<sha256>`.
8. Copy back: signed APK, manifest, add-leaf request. Wipe the transfer medium's copy on the host; power off. Continue with §5.2.

### 3.5 Rotation and compromise, per key

- **Release key** (lost or compromised): RK2 removes it; clients adopt the new root from the next bundle and refuse manifests signed only by the removed key, whatever their sequence. Malicious manifests signed before that are in the log.
- **Root key**: one lost or compromised key is replaced by RK2 with the other two. All three lost: the updater cannot follow; a new APK embedding a new root v1′ is accepted by Android (signed by `K-APK`) but must be installed outside the updater (verified with `ghost-verify` against the new root published in the public repository and on the mirrors) — L10-D13.
- **Android key** (compromised): RK3 with `--rotation-min-sdk-version` default 33. Devices on API 33+ that install the rotated release refuse later updates signed by the old key (capability `rollback` off: apksig `SigningCertificateLineage`, default flags exclude `PAST_CERT_ROLLBACK`). Devices on API 29–32 keep verifying the original signer in the v3 block (source.android.com, "APK Signature Scheme v3.1"), so a sideloaded old-key APK still updates them (L10-D3); `28` would rotate there too, but key rotation is "not recommended for Android 12 (API level 31) and earlier" (source.android.com, v3) — Q9. Raising `minSdk` to 33 removes the residue at a device-coverage cost (Q9).
- **Android key** (lost, shares intact): RK5's path, then continue. Shares also lost: a new identity (L10-D13); the transparency log and the public repository announce the new certificate.
- **Log, witnesses, attestation keys**: RK2.
- **Mirror onion key**: retire the mirror in the next manifest; clients drop it.

### 3.6 Networks

`network` is a signed byte everywhere (1 mainnet, 2 stagenet, 3 regtest for vectors only), as in the ES (`schedule.rs:1-30`). Each network has its own root, its own `K-APK` and certificate, its own mirrors and its own `applicationId` (stagenet: suffix `.stagenet`). A client uses the root of its embedded ES's network and refuses anything of another network (`WRONG_NETWORK`). Phase 14 runs RK0 for stagenet only.

---

## 4. Data formats (normative; byte level; ADR-49)

### 4.1 Conventions

The ES conventions (`faza8-issuer.md:409-433`): big-endian fixed-width integers; `<u16>` and `<u32>` are length-prefixed byte strings; ASCII only where stated; exact lengths, counts within bounds, **no trailing bytes**; lists that are sets are **strictly ascending** in the stated key (one canonical encoding per value); unknown versions refused; `ext` bytes must be 0 in version 1. `day` is `u32` days since 1970-01-01 UTC. A key id is SHA-256 of the 32-byte Ed25519 public key (the Sigsum key hash). An onion is `<u16 ASCII "<56 base32>.onion:<port>">`, validated as `OnionAddress` (v3 checksum, `isolation.rs`'s crate). Every parser is total: it never panics and never reads past its input (property tests, fuzzing; §11.1).

### 4.2 Signed statements and signature blocks

```
statement(type, network, body) := "ghost/v1/" ‖ type ‖ 0x00 ‖ u8 network ‖ SHA-256(body)
    type ∈ { "release-root", "release-manifest", "build-attestation" }      (≤ 61 bytes)
sigblock := u8 n (1..16) ‖ n × ( key_id[32] ‖ signature[64] )             (key_id strictly ascending)
```

A signature block meets `(keys, t)` when at least `t` entries name a key id in `keys` and verify with `ed25519-dalek` `verify_strict` over the statement; entries naming other keys or failing verification are ignored, never an error (TUF's rule; a block cannot hold two entries for one key, by the ordering rule). The Sigsum leaf statement is `"sigsum.org/v1/tree-leaf" ‖ 0x00 ‖ checksum` (56 bytes; Sigsum log protocol v1), so no GHOST statement and no Sigsum statement can be mistaken for each other.

### 4.3 Root `GHRT`

```
GHRT v1 := body ‖ sigblock over statement("release-root", network, body)
body := "GHRT" ‖ u8 version = 1 ‖ u8 network ‖ u32 root_version (≥ 1)
  ‖ keyset(root)    := u8 n (1..8) ‖ n × pk[32] ‖ u8 t (1..n)          (pk ascending by key id)
  ‖ keyset(release) := u8 n (1..8) ‖ n × pk[32] ‖ u8 t (1..n)
  ‖ keyset(attest)  := u8 n (0..16) ‖ n × pk[32] ‖ u8 t (0..n)
  ‖ apk_signers := u8 n (1..4) ‖ n × cert_sha256[32]                   (ascending)
  ‖ logs := u8 n (1..4) ‖ n × ( pk[32] ‖ <u16 ASCII origin> )          (ascending by key id)
  ‖ witnesses := u8 m (0..32) ‖ m × pk[32] ‖ u8 quorum (0..m)           (ascending by key id)
  ‖ u8 ext = 0
```

Rules: a key appears in at most one keyset of a root; on network 1 (mainnet), `attest.t ≥ 1`, `quorum ≥ 2` and `m ≥ 3`; on network 2 (stagenet), `quorum ≥ 1` and `attest.t` may be 0 (staging before an auditor exists; RQ-D15 is a release gate); network 3 (regtest) exists only in vectors and test worlds, and production builds refuse it as the ES does. **Chain rule (TUF §5.3, "new root signed by a threshold of the old and of the new keys"), plus logging:** given trusted `v(n)`, `v(n+1)` is adopted iff same network, `root_version = n + 1`, its signature block meets `(root(n).keys, root(n).t)` **and** `(root(n+1).keys, root(n+1).t)`, **and** a `GHRP` whose message is `SHA-256(v(n+1) file)` verifies under **`v(n)`'s** log policy, with a leaf signed by a release key of `v(n)`. The logging clause closes a targeted root swap: two stolen root keys could otherwise hand a few clients a root naming the attacker's own log and witnesses, after which a forged "logged" manifest would pass; with it, every root change is public in the log the clients already trust before any client adopts it. A root is trusted as the **anchor** if it is the newest root embedded in the client's native library (`include_bytes!` of the committed chain, so the anchor is inside the reproducible, logged APK) or a root reached from the anchor by the chain rule. Residue: a root change needs one log of the previous policy to be alive (L10-D17).

### 4.4 Root chain `GHRC`

```
GHRC v1 := "GHRC" ‖ u8 version = 1 ‖ u8 network ‖ u16 count (1..64)
           ‖ count × <u32 GHRT>      (root_version 1, 2, …, count; contiguous)
```

Every client fetches the whole chain (a few KiB a year), so a fetch never reveals which root version the client holds (P-D3). The client verifies from its anchor upward and ignores older entries after parsing them.

### 4.5 Release manifest `GHRM`

```
GHRM v1 := body ‖ sigblock over statement("release-manifest", network, body)     (≤ 65 536 B)
body := "GHRM" ‖ u8 version = 1 ‖ u8 network ‖ u64 manifest_seq (≥ 1)
  ‖ u32 root_version ‖ root_sha256[32]                    (= SHA-256 of that GHRT file)
  ‖ u32 issued_day ‖ u32 not_after_day                     (issued_day < not_after_day ≤ issued_day + 91)
  ‖ u32 floor_version_code                                  (minimum supported; 0 = none)
  ‖ u8 nrel (1..4)    ‖ nrel × release                      (strictly ascending version_code)
  ‖ u8 nmirror (2..16) ‖ nmirror × ( onion ‖ operator_id[16] )   (distinct onions; ≥ 2 distinct operator ids)
  ‖ u16 nrelay (0..512) ‖ nrelay × ( onion ‖ operator_id[16] ‖ u8 flags = 0 )   (strictly ascending onion)
  ‖ u16 nbridge = 0                                         (reserved for ADR-16, Phase 12)
  ‖ u8 ext = 0
release := u32 version_code (1 … 2^31 − 1) ‖ <u16 ASCII version_name (1..32)> ‖ u8 min_sdk ‖ u8 flavor (1 = mirror)
  ‖ apk_sha256[32] ‖ u64 apk_length (1 … 268 435 456)
  ‖ unsigned_sha256[32] ‖ u64 unsigned_length
  ‖ u16 rollout_permille (0..1000) ‖ rollout_salt[16]
  ‖ commit[20]                                              (git SHA-1 of the tagged commit)
  ‖ u64 es_seq ‖ es_sha256[32]                              (the ES embedded in this build)
  ‖ u8 nart (0..32) ‖ nart × ( u8 kind ‖ sha256[32] ‖ u64 length )   (strictly ascending kind)
  ‖ sigblock_or_empty over statement("build-attestation", network, GHRA(release))   (u8 n may be 0)
```

Artifact kinds (§6.1): 1, 2 native library arm64-v8a, x86_64; 3, 4 their symbol files; 5 `ghost-relay`; 6 `ghost-issuer`; 7 `ghost-issuer-ops`; 8 `ghost-release-ops`; 9 the APK notices asset; 10, 11 relay and issuer notices; 12, 13, 14 client, relay and issuer SBOMs; 15 the MPL source bundle; 16 the source-escrow digest (length = escrow archive length); 17 the ES file; 18 the builder recipe (Dockerfile ‖ `pins.txt`). The manifest carries no time finer than a day and nothing per client.

### 4.6 Attestation statement `GHRA` (what an independent builder signs)

```
GHRA v1 := "GHRA" ‖ u8 version = 1 ‖ u8 network ‖ commit[20] ‖ u32 version_code ‖ u8 flavor
  ‖ unsigned_sha256[32] ‖ u64 unsigned_length ‖ u64 es_seq ‖ es_sha256[32]
  ‖ u8 nart ‖ nart × ( u8 kind ‖ sha256[32] ‖ u64 length )
```

The client rebuilds `GHRA` from the release record's own fields; an attester never sees or signs the signed APK. The human-readable attestation (who built, where, with which recipe, what was reviewed) is a separate document in the archive (§5.5).

### 4.7 Log proof `GHRP` (the Sigsum v1 components in a GHOST container)

```
GHRP v1 := "GHRP" ‖ u8 version = 1 ‖ message[32]          (= SHA-256 of the logged GHRM or GHRT file; the leaf checksum is SHA-256(message))
  ‖ u8 log (index into the governing root's logs: the manifest's root, or for a root v(n+1), v(n))
  ‖ leaf_signature[64] ‖ leaf_key_id[32]                   (a release key of the governing root; over the Sigsum leaf statement)
  ‖ u64 tree_size ‖ u64 leaf_index (< tree_size) ‖ u8 npath (0..63) ‖ npath × node[32]
  ‖ root_hash[32] ‖ log_signature[64]                     (the log's signature on its tree head)
  ‖ u8 ncos (0..32) ‖ ncos × ( witness_key_id[32] ‖ u64 time ‖ cosignature[64] )   (ascending key id)
```

The leaf is `checksum ‖ leaf_signature ‖ leaf_key_id` (128 bytes) and its tree hash `SHA-256(0x00 ‖ leaf)` (RFC 6962 §2, as Sigsum v1 states); the inclusion path is checked by the RFC 6962 / RFC 9162 algorithm; the tree head is the C2SP checkpoint body with origin `sigsum.org/v1/tree/<hex key hash of the log>` signed by the log; each cosignature is a C2SP `cosignature/v1` signature over `"cosignature/v1\ntime <t>\n" ‖ checkpoint body`. Sigsum's own proof-bundle and policy formats are "work in progress" (sigsum.org/docs), so GHOST carries the components itself; **the exact checkpoint bytes are fixed by vectors produced with sigsum-go v0.14.1 and checked by GHOST's parser (V-D11)**, not by this paragraph. Cosignature times may not exceed the device's trusted time by more than one day; there is **no lower bound**: an old cosigned checkpoint still proves that the manifest was logged.

### 4.8 Bundle `GHRB` (what a mirror serves) and bounds

```
GHRB v1 := "GHRB" ‖ u8 version = 1 ‖ u8 network ‖ <u32 GHRC>
  ‖ u16 nroot ‖ nroot × <u32 GHRP>        (one proof per root version 2 … count, ascending: the root-logging clause of §4.3)
  ‖ <u32 GHRM> ‖ <u32 GHRP>               (the manifest and its proof)                                   (≤ 1 048 576 B)
```

Bounds, fixed before reading: bundle 1 MiB; root 16 KiB; manifest 64 KiB; proof 16 KiB; APK exactly `apk_length` (≤ 256 MiB). Worst cases from the formats: a root ≈ 4.1 KiB (16 attestation keys, 32 witnesses, a full signature block), a proof ≈ 5.6 KiB (63 path nodes, 32 cosignatures), a manifest ≈ 59 KiB at every maximum at once (4 releases × 32 artifacts × 16 attestations, 16 mirrors, 512 relays, 16 signatures), so 64 roots with their proofs and one manifest (≈ 680 KiB) fit in 1 MiB; a realistic bundle (a few roots, tens of relays) is tens of KiB. A response longer than its bound is cut at the bound and refused (endless-data attack, TUF); a shorter one is refused.

### 4.9 Files in the repository

`ghost/protocol/release/README.md` (this section, condensed); `ghost/protocol/release/<network>/root-<n>.ghrt` (the committed chain, the anchor's source); `…/apk-signer.crt`; `…/mirrors.txt` (`mirror <onion:port> <operator id hex>`, the bootstrap list); `ghost/protocol/release/<network>/allowed_signers` (git tag keys); `ghost/protocol/test-vectors/release_{root,manifest,proof,bundle,apk_core}.txt` with every negative case of §11.1. The existing `ghost/protocol/entitlement/relay-directory.txt` stays the bootstrap relay list.

---

## 5. Transparency log, attestations, publication (normative; ADR-49)

### 5.1 Why Sigsum, and the policy

Sigsum's log server protocol is a stable v1 (v1.0.1); its witness cosigning protocol is a release candidate; its proof-bundle and trust-policy formats are work in progress (sigsum.org/docs). A leaf is `checksum[32] ‖ signature[64] ‖ key_hash[32]`; logs accept only 32-byte messages and store nothing else (the log protocol, `git.glasklar.is/sigsum/…/log.md`). Glasklar Teknik's named production policy `sigsum-generic-2025-1` lists two logs (Glasklar Teknik, Mullvad VPN) and three witnesses (Glasklar Teknik, Mullvad VPN, Tillitis), and itself names the weakness that the three witness operators share a parent company (glasklarteknik.se, 2026-02-04). GHOST encodes that policy's logs, witnesses and quorum in the root (`GHRT.logs`, `GHRT.witnesses`, `quorum`), **transcribed from the policy file in S0b (V-D11)**; the flat k-of-m quorum must be at least as strict as the policy's own rule. Rekor v2 (GA 2025-10-10) is rejected for now: at GA its post says witnessing "will be implemented soon", and its log shards rotate yearly. A GHOST-run log is rejected: its operator is the vendor (AD-V), and independent witnesses would have to agree to watch it. (Precedent for logging release metadata rather than binaries: Google's Pixel Binary Transparency log of factory-image metadata.)

**What is logged.** One leaf per manifest (`message = SHA-256(GHRM file)`) and one leaf per new root version (`message = SHA-256(GHRT file)`, logged under the previous root's policy, §4.3), each signed by `K-REL1` or `K-REL2` in Sigsum's namespace. A manifest commits to its root (`root_sha256`), to every release's signed APK, unsigned core, artifacts, commit and ES, and to the attestations, so one leaf logs the whole release state; relay and issuer binaries, symbols, SBOMs and the escrow digest are logged through it.

**Submission and rate limiting.** Public Sigsum logs are expected to apply domain-based rate limiting: a `sigsum-token` header signed by a key whose public key sits in a DNS TXT record `_sigsum_v1.<domain>` the submitter controls (the `sigsum-tools(7)` manual: "as publicly accessible logs are expected to do"; log.md). So publishing needs a DNS domain (Q4, OA-4), used only for that record (and, if ever, Accrescent's check, §8.2); **no client ever contacts it** (LIM:158 stands for the app). The leaf is signed offline by the token; `ghost-release-ops leaf-request` writes the body of a Sigsum add-leaf request (`sigsum-submit` without `-k` "must be the body of an add-leaf request … parsed and verified before submission"); the owner submits it from the online workstation **over Tor** with sigsum-go's `sigsum-submit -p <policy> -a <K-RL> -d <domain>` (v0.14.1, BSD-2-Clause; `-a` takes an OpenSSH-format key), which collects the inclusion proof and the cosigned tree head that `ghost-release-ops proof-assemble` turns into a `GHRP`.

**Staging.** The stagenet chain may use the public logs (real path, cheap). Until the domain exists (OA-4), the JVM and Rust worlds use generated log and witness keys, and the live drill waits (§13.3 item 7).

### 5.2 Publication procedure (RK1 continued, online; runbook R-P)

1. Bring back from the signer host: signed APK, `GHRM`, the add-leaf request (and, after an RK2, the new root's request).
2. `ghost-release-ops apk-core --apk <signed> --expect <unsigned sha256>` again (the online re-check of `core(signed) = unsigned`).
3. `sigsum-submit` over Tor (`torsocks` or a SOCKS proxy); `proof-assemble` → `GHRP`; `bundle` → `GHRB` (with the committed `GHRC` and the roots' proofs).
4. `ghost-verify apk --bundle current.ghrb --apk <signed> --root <anchor>` must print `VERIFIED` exactly as a client would decide (§7.4), including the attestation clause.
5. Upload over each mirror's onion SSH service (client authorisation): archive files first, then `current.ghrb` by atomic rename.
6. Fetch `current.ghrb` and the APK back from every mirror through Tor and compare hashes; record the run in the release record.

### 5.3 The release record and monitors

**Release record** (the mirror's `/ghost/v1/<network>/archive/`, every file named by its SHA-256): every `GHRM` and `GHRP` ever logged, every `GHRT`, every signed APK, the unsigned core's hash list from both environments, the symbol files, SBOMs, notices, the MPL source bundle (ADR-37 point 2), the ES file of each release, `ghost-relay` (operators; ADR-37 point 6), the human-readable attestations, the escrow digest, the CI run links of environment B, the RK1 checklist (redacted of PINs and serial numbers). The `ghost-issuer` binary is logged and attested but not published (owner-operated).

**Monitor** (`ghost-verify monitor`, in the public repository; the owner runs it weekly and publishes the output; anyone can run it): for every leaf of the policy logs whose key hash is a release key of any GHOST root, (a) the archive holds a manifest or a root whose SHA-256 is the leaf's message and whose signatures verify (a root also by the chain rule from its predecessor); (b) no two manifests share a `(root_version, manifest_seq)` pair, and pairs increase in log order; (c) every release's APK is in the archive with the stated hash, its core matches the attested hash and every attestation verifies; (d) the ES of consecutive releases is append-only (`ghost-issuer-ops schedule-verify --previous`, ADR-22 rule 5), which closes F8 F6's "key consistency against a malicious release key" for every logged release; (e) each symbol file's build-id equals its library's. A failure is a public alarm (RK4).

### 5.4 First installs, operators and the public repository

- **`ghost-verify`** (Rust, the `ghost-client-update` format crate plus a CLI; in the separate public repository with a permissive licence, ADR-38 point 7, Q28): `apk --bundle --apk [--root-sha256]` performs §7.4's decision offline and prints a fixed vocabulary (`VERIFIED version=… version_code=… manifest_seq=… log=<origin> cosigned=<k>/<m> attested=<k>/<t> signer=<sha256>` or `REFUSED <code>`); `fetch --socks <127.0.0.1:9050|9150>` fetches the bundle and an APK from a mirror over a local Tor (optional, compiled separately); `operator --binary <file> --kind relay|issuer` checks an operator binary against the newest verified manifest; `monitor` as §5.3. Its own builds are reproducible from the public source, which is the point: the verifier is the one GHOST component users can read.
- **Manual path** (weaker, no log check): the signing certificate's SHA-256 published in the public repository's README, on the mirrors and in the signed tag message, checkable with `apksigner verify --print-certs` (Signal's documented practice) or with AppVerifier (ISC; it compares package name and certificate hash).
- **Operators** check `ghost-relay` with `ghost-verify operator` before every start of a new version; the relay image (`infra/relay/Dockerfile.release`, S8) copies the released binary after `sha256sum -c` against the manifest's artifact list, instead of compiling the source (the compose file of `infra/relay/docker-compose.staging.yml` builds from source today, which closed-source operators cannot do). The issuer image follows the same pattern (owner-operated; consistency with the log).

### 5.5 Attestations (T12b mechanics)

An independent builder (Phase 15's auditor or later ones) receives the tagged commit (source access under ADR-38 point 4), builds it with the committed recipe (§6) on its own machine, compares its `SHA256SUMS` with the vendor's, and if equal signs `GHRA` with its key (listed in the root by RK2) and publishes a human-readable attestation (identity of the attester, date, recipe digest, hashes, what was reviewed). RK1 embeds the signatures in the release record. With `attest.t = 0` (stagenet before an auditor) the clause is vacuous, and the UI may not claim reproduction (§2.6). On mainnet `attest.t ≥ 1` (§4.3), so **no mainnet release can reach an updater without an auditor's attestation** — an availability dependency on the auditor, accepted (R-D10).

---

## 6. Reproducible build from two environments (normative; ADR-50)

### 6.1 What "identical hash" means

The release outputs of commit C are, in a fixed order with fixed names, the files of `SHA256SUMS` (LF, sorted by path, `sha256␠␠path`):

| Path | What | Note |
|---|---|---|
| `apk/ghost-<network>-<version_code>-unsigned.apk` | the **zip-aligned unsigned APK**: AGP's `assembleRelease` output if `zipalign -c -P 16 -v 4` passes on it, else `zipalign -P 16 -f 4` of it (V-D4 decides once; both environments run the same script) | the bytes `core(signed)` must equal (§6.5) |
| `lib/<abi>/libghost_client_net.so` (arm64-v8a, x86_64) | stripped, with a SHA-1 GNU build-id | what the APK contains (`apk-native-libs.sh`) |
| `symbols/<abi>/libghost_client_net.so.debug` | split line-table debug info | ADR-38 point 9 |
| `bin/ghost-relay`, `bin/ghost-issuer`, `bin/ghost-issuer-ops`, `bin/ghost-release-ops` | `x86_64-unknown-linux-gnu`, `--release --locked` | relay and issuer: ADR-38 point 5; release-ops: it runs on the signer host |
| `notices/THIRD_PARTY_NOTICES-{android,client-net,relay,issuer}.txt` | regenerated, equal to the committed files (G-L1) | ADR-37 point 3 |
| `sbom/{client,relay,issuer}.cdx.json` | CycloneDX 1.7 (released 2025-10-21; ECMA-424 2nd ed.), generated by `ghost-release-ops sbom` from `cargo metadata --locked` per shipped target and from `:app:releaseRuntimeComponents` (`app/build.gradle.kts:183-197`) with `verification-metadata.xml` digests; sorted keys and arrays, **no timestamp**, no serial number | ADR-37 point 8, C-08 |
| `recipe/Dockerfile`, `recipe/pins.txt` | the recipe itself | artifact kind 18 |

The **signed APK is not** in `SHA256SUMS`: its hash differs by the signing block; the manifest binds both (`apk_sha256`, `unsigned_sha256`). Today's `reproducible-build.sh` proves same-path determinism of the unsigned APK (`reproducible-build.sh:30-41`) and `android-native` of the libraries (`ci.yml:219-232`); both stay, and the cross-environment gate is new.

### 6.2 The builder recipe (`ghost/infra/builder/`)

`Dockerfile`, `x86_64` only, every input pinned, nothing fetched unpinned:

| Input | Pin | Today |
|---|---|---|
| base image | `debian:bookworm-slim@sha256:<digest>` (Q12: trixie acceptable; bookworm matches the relay and issuer images) | relay: `rust:1.98.1-bookworm` (`infra/relay/Dockerfile:5`) |
| apt packages | `snapshot.debian.org` at one timestamp, `check-valid-until=no`, exact versions | — |
| JDK | Temurin 17, one exact `17.0.x+y` tarball by SHA-256 (V-D17) | CI: `temurin` `"17"` with the patch unpinned (`ci.yml:306,465`) |
| Android SDK | `commandlinetools` zip by SHA-256; `platforms;android-37.0`, `platforms;android-37.2`, `build-tools;37.0.0`, `build-tools;36.0.0`, `ndk;30.0.16248370` (sdkmanager checks each package's checksum) | `ci.yml:43-44`; `app/build.gradle.kts:62` |
| Rust | `rustup-init` by SHA-256; toolchain 1.98.1; targets `aarch64-linux-android`, `x86_64-linux-android`, `x86_64-unknown-linux-gnu` | `rust-toolchain.toml` |
| cargo-ndk | 4.1.2, `cargo install --locked` | `build-native.sh:16` |
| protoc | 36.1 by SHA-256 | `install-protoc.sh:6-7` |
| Gradle | 9.7.1 wrapper by `distributionSha256Sum` | `gradle-wrapper.properties:3-4` |
| Gradle and Maven dependencies | `verification-metadata.xml` checksums, **aapt2 jars pinned** (today trusted without checksum, `verification-metadata.xml:8`) | 333 components pinned |
| Cargo dependencies | `Cargo.lock` checksums, crates.io only (`deny.toml`) | — |

**`scripts/release/build-release.sh <tag>`** (the same script in A, B and C): (1) `git clone` of the repository into `/w/src` on a tmpfs and `git checkout --detach <tag>`, `git verify-tag` when the allowed-signers file is present; (2) fixed environment (§6.3); (3) `build-native.sh` with the symbol split (§6.3) into `/w/out/lib` and `/w/out/symbols`, copied into `android/network/src/main/jniLibs`; (4) `cargo build --release --locked --target x86_64-unknown-linux-gnu -p ghost-relay-node -p ghost-issuer -p ghost-issuer-ops -p ghost-release-ops` with the same remaps; (5) `./gradlew --no-daemon --no-build-cache :app:assembleRelease` with `org.gradle.workers.max=4`, then the alignment step of §6.1; (6) `license-notices.sh` and `apk-notices.sh` (G-L1, G-L3), `apk-native-libs.sh`; (7) `ghost-release-ops sbom`; (8) `SHA256SUMS` over `/w/out`. Network use is limited to fetching pinned inputs; a step that downloads anything not pinned fails G-D2's static check of the script.

`pins.txt` is the single source of every version and digest; gate **G-D2** fails when `ci.yml`, `rust-toolchain.toml`, `gradle-wrapper.properties`, `install-protoc.sh`, `build-native.sh` or the Dockerfile disagree with it. The image is built from the Dockerfile in each environment (G-L5 forbids pushing images, `no-public-binaries.sh:9-11`); image digests are recorded, not required to match (making the image itself reproducible with BuildKit's `SOURCE_DATE_EPOCH` is a stretch goal, not a gate).

### 6.3 Determinism measures and the known hazards

| Hazard (source) | Measure | Status |
|---|---|---|
| Build paths in Rust output: Windows `\` separators, remap flags hashed into build-script directory names (`build-native.sh:9-11`; F9 hygiene §10's note on `relay/crates/api/build.rs`) | Linux container; the checkout at `/w/src`, `CARGO_HOME=/cargo`, `CARGO_TARGET_DIR=/target` in every environment; the existing remaps and leak check kept | measured cross-env in V-D2 |
| File-system ordering (tools that do not sort directory listings) | the checkout is cloned into a **tmpfs** inside the container, so listing order follows creation order, identical everywhere | V-D3 (tmpfs vs overlay) |
| CPU-count-dependent output (R8, F-Droid's list; a 2026 R8 regression reported in Google issue 554586985, details behind a login) | `docker run --cpus 4` in every environment (the JVM sizes its pools from the cgroup); `org.gradle.workers.max=4` | V-D3, V-D16 |
| Clock, locale, time zone, umask, user | `TZ=UTC`, `LANG=C.UTF-8`, `umask 022`, uid 1000, `SOURCE_DATE_EPOCH` = the commit time (for any tool that honours it); builds on two different days | the same-path T12 builds minutes apart already show no clock input (`reproducible-build.sh:30-41`, green on `e267b3f`, STATUS:17); V-D3 adds days |
| `META-INF/version-control-info.textproto` (AGP ≥ 8.3, on by default; F-Droid's list) | `vcsInfo { include = false }` in the release build type (D12) | V-D4 |
| Dependency metadata block | already off (`app/build.gradle.kts:84-89`) | — |
| AGP re-stripping the native library | already off (`app/build.gradle.kts:81`) | — |
| Symbols and build-id | `[profile.release] debug = "line-tables-only"`, `strip = "none"`, `-C link-arg=-Wl,--build-id=sha1`; after linking, NDK `llvm-objcopy --only-keep-debug` then `--strip-all` (`.dynsym` stays, so G-R6 keeps working) | V-D9 |
| libcrux SIMD build scripts without `rerun-if-env-changed` | the existing clean before every client build (`build-native.sh:59-66`), G-R3 | unchanged |
| JDK patch level | pinned (V-D17) | — |
| aapt2 | pinned jar checksums; its output deterministic given the jar | V-D2 |
| Bundled C code (`libsqlite3-sys` "bundled", `client-core/net/Cargo.toml`) | NDK clang pinned; `.comment` strings are a drift detector | V-D2 |
| Third-party prebuilt `.so` (`libsqlcipher.so`, `libandroidx.graphics.path.so`) | compared by name only today (`apk-native-libs.sh:5-7`); their bytes are fixed by the pinned AAR and the pinned NDK strip; declared, not built from source | declared (L10-D7) |

### 6.4 The two environments and the comparison

- **Environment A — the owner's workstation**: Docker Desktop on the owner's Windows machine (not the `ghost-runner` distribution, whose Docker Engine the CI jobs control, `ci-self-hosted.md:34`), `scripts/release/build-release.sh <tag>` inside the image. Its outputs are the ones carried to the signer host. Both engines run in the same WSL2 virtual machine, which is why A's outputs are trusted only when they equal B's.
- **Environment B — a GitHub-hosted runner**: `ubuntu-24.04`, which for a private repository is 2 CPUs, 8 GB RAM and 14 GB SSD (docs.github.com, "GitHub-hosted runners"); the same script in the same image built there; a cleanup step frees disk first; its `SHA256SUMS` reaches the comparison as a job output (text, G-L5). The private plan includes 2 000 hosted minutes a month (`ci-self-hosted.md:3`). The fee GitHub announced for self-hosted runner minutes from 2026-03-01 was **postponed** ("We're postponing the announced billing change for self-hosted GitHub Actions", GitHub changelog 2025-12-16, updated), contrary to one research digest. If V-D10 shows the hosted runner cannot fit the build, the fallback is a second machine of the owner's that never runs the CI runners (Q11).
- **Why not the self-hosted runner as B**: it is the same laptop and the same WSL2 VM as A (`ci-self-hosted.md` §7, "Toate distribuțiile WSL2 … rulează în aceeași mașină virtuală"), so a compromise of one is likely a compromise of both.
- **Comparison** (`release-build.yml`, on a signed tag and by dispatch, and weekly on `main` to catch drift): job A on the self-hosted runner, job B hosted, job C diffs the two `SHA256SUMS` and checks completeness against the expected path list (G-D3). The owner's local environment-A run for a release repeats job A's script; RK1 requires `local A = job A = job B`.
- **Environment C — the auditor** (release gate): the same recipe on the auditor's machine, signed `GHRA` (§5.5).

### 6.5 Signing preserves the core

The v2/v3 signing block is inserted immediately before the ZIP central directory (source.android.com, v2), and the end-of-central-directory record's offset field is moved by the block's length. With v1 off and the entries untouched, the signed file is the unsigned file plus the block. build-tools ≥ 35 `apksigner` re-aligns by default ("forcibly replaces existing alignment padding", apksigcopier README; F-Droid fdroiddata issue 3299); build-tools 37.0.0's own help says `--alignment-preserved` "Whether the existing alignment within the APK should be preserved; the default for this setting is false", with `--lib-page-alignment` defaulting to 16 384 (read locally, 2026-10-03). RK1 therefore signs with:

```
apksigner sign --provider-class sun.security.pkcs11.SunPKCS11 --provider-arg pkcs11.cfg \
  --ks NONE --ks-type PKCS11 --ks-key-alias <alias> \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
  --v4-signing-enabled false --alignment-preserved true --min-sdk-version 29 \
  --out signed.apk unsigned.apk          (+ --lineage <file> after RK3)
```

and `ghost-release-ops apk-core` refuses to continue unless the core (§7.4 step 9's parse) of `signed.apk` equals `unsigned.apk` byte for byte (V-D5 on a software key, V-D6 on the token). v4 (`.idsig`) is only for incremental installs over ADB (source.android.com, v4) and is not produced.

### 6.6 Variation matrix and diagnostics (S0a; then weekly on `main`)

Environment A builds the same commit twice per row and compares: checkout path (`/w/src` vs `/w/src2`); CPU count (2 vs 16); listing order (tmpfs vs the image's overlay); date (two days apart); uid and umask; and A against B. A difference is classified with **diffoscope** (GPL-3.0, CI diagnostic image only, never shipped) into native, dex, resources, zip metadata or other, and each class gets a measure in §6.3 before S3 closes. If an R8 difference cannot be fixed, Q-level escalation (R-D1): pin R8 by version and threads, or report upstream; the gate is never relaxed to "logically equivalent".

### 6.7 Provenance and SBOM: what exists, what this phase adds (FR-8.1, C-08)

| Control | Exists today | Phase 14 adds |
|---|---|---|
| Rust dependencies | `--locked`; `cargo-deny` (licences, bans by exact name, crates.io only) and `cargo-audit` in `rust` (`ci.yml:61-176`); the client crate allowlist on both ABIs and the crypto pins per graph (`rust-client-allowlist.sh`, `rust-crypto-pins.sh`); the vendored-source scans G-R5, G-R8 | the client graph unchanged (G-D6); per-target CycloneDX SBOMs in every release |
| Gradle dependencies | dependency verification with SHA-256 for 333 components, signatures off, `.pom`/`.module` and `aapt2` trusted (`verification-metadata.xml:4-9`); the group allowlist and denylist (T7); per-coordinate licences (G-L2) on `releaseRuntimeComponents` | `aapt2` pinned (G-D8); signature verification decided (Q22); the runtime components in the SBOM |
| Toolchains | Rust 1.98.1, NDK 30.0.16248370, cargo-ndk 4.1.2, protoc 36.1 by hash, Gradle by hash; JDK 17 unpinned at patch level | one `pins.txt` for all of them, JDK by hash (G-D2) |
| Licence notices | generated and compared (G-L1), in the APK (G-L3), MPL sources (G-L4), no public binaries (G-L5) | notices hashed into each release record; MPL source bundle published on the mirrors |
| Source identity | commits unsigned (STATUS:25) | releases only from hardware-signed tags (D22); the commit bound in every manifest and attestation |
| Artifact identity | same-path T12 for the APK and the libraries | two environments, the auditor's attestation, the log (§5, §6.4) |

---

## 7. Mirrors, the update protocol and the client (normative; ADR-51)

### 7.1 Mirrors

A mirror is a v3 onion service (the relay template, `infra/relay/torrc`: `HiddenServicePoWDefensesEnabled 1`, `SafeLogging 1`, `SocksPort 0`) in front of a static file tree, **with access logging off** (ADR-11's discipline; an aggregate counter is not kept either). Each mirror has its own onion key (never in the repository; G-D1 extends `entitlement-schedule.sh`'s onion-key search to `infra/mirror`). Production needs mirrors of **at least two operators** (`GHRM` requires two distinct operator ids); a relay operator may run one as a separate onion service. Staging runs two owner mirrors with distinct labels (X-D13, as staging relays do, `relay-directory.txt:10-13`). Server (Q20): **nginx** (BSD-2-Clause) if V-D12 confirms HTTP/2 with prior knowledge on a cleartext listener (its docs name the `h2c` protocol value, but do not state the mode), else **`ghost-mirror`** (Rust; hyper's server half already in the relay's graph; serves only the fixed paths below; no logging, gate `no-logging.sh` scope). Either way the server: listens on loopback for its Tor daemon only; answers HTTP/2 with prior knowledge and nothing else; serves `GET` on the three path forms of §7.2 with `content-length` and single-range `Range` support, and 404 for anything else; sets no cookie and no cache-validation header; keeps no access log, error log of requests or counter; reads a publish directory updated by atomic rename (§5.2 step 5). The deployment (`infra/mirror/`: torrc, server configuration, compose file, Romanian runbook) mirrors `infra/relay/`.

### 7.2 Paths and HTTP rules

| Path (`<net>` = `mainnet` or `stagenet`) | Content | Client use |
|---|---|---|
| `/ghost/v1/<net>/current.ghrb` | the current bundle | every update run, from two mirrors |
| `/ghost/v1/<net>/apk/<64 hex>` | a signed APK by SHA-256 | download, `Range: bytes=<4 MiB × i>-<4 MiB × (i+1) − 1>` |
| `/ghost/v1/<net>/archive/<64 hex>` | the release record (§5.3) | never by the app; `ghost-verify`, monitors, operators |

Rules (the client's request builder is closed, test PM-D3): HTTP/2 with prior knowledge on the onion stream (the hyper `http2` client already in `client-core/net`, `ghost/Cargo.toml:61-62`); only `:method GET`, `:scheme http`, `:authority <onion:port>`, `:path`, and `range` for APK chunks; **no** `user-agent`, `accept-encoding`, cookies, `if-none-match`, `if-modified-since` or any value that differs between clients; responses: status 200 (bundle) or 206 with a matching `content-range` (APK), `content-length` present and within the bound of §4.8; no redirects followed; body read to the bound only; 60 s per request (the RPC deadline of `ADR-19:21`).

### 7.3 Update runs (scheduling; `:sync`)

A periodic job run is, by client randomness only, a **quiet run** (probability 1/8, unchanged, `QuietRunScheduler.kt:60`), else an **update run** with probability 1/24, else a normal relay session. The draw uses the process's random key and the run index with a new domain (`RandomSources.updateRun(index)`), the T19/T23 pattern: nothing else is an input (no update state, no app visibility, no pending work). An update run has the transport READY, **no relay session, no issuer call**, and one participant: the update engine, through a lease like `ParticipantSession` (`SessionParticipant.kt:45-73`) with a new access `updateMirror` that exists only in update runs. In it the engine: (1) fetches `current.ghrb` from two mirrors chosen uniformly from the stored list (distinct operators when possible) on the `Update` isolation scope (`isolation.rs:30-31`); (2) accepts per §7.4; (3) if an offer exists and is not staged, downloads APK chunks until the lease deadline (resumable, `upd_staged`); (4) ends. At about one periodic run per 15 minutes this is roughly one update run every 7 hours; Doze and app-standby buckets lower it; Q15 sets the rate. **A user-requested check or download** (Phase 13) runs the same steps in the foreground session's process, at the user's moment (declared, like `USER_ISSUER_CALL`, `SessionParticipant.kt:44-56`). Nothing else ever fetches from a mirror (T51); in particular nothing happens at app start (X-D1).

### 7.4 The client's decision (normative; implemented in `ghost-client-update`, called through `UpdateNative`)

Inputs: the stored facts (§9.6), the embedded anchor, today's trusted day (from `:sync`'s clock trust: READY in this process and `|Δwall − Δmono| ≤ 1 h`, F7:1655; when untrusted, every time-dependent step stops with `CLOCK_UNTRUSTED` and nothing changes), the installed `versionCode` and SDK (Kotlin passes them).

**Accept a bundle**

1. Parse `GHRB` within bounds; `network` = the app's (`WRONG_NETWORK`).
2. **Root.** Anchor := the newer of the embedded root and the stored root. Walk `GHRC` from anchor version + 1, applying the chain rule with its logging clause (§4.3: each new root's own `GHRP` verified under the previous root's policy); stop at the first failure (`ROOT_CHAIN_BROKEN` or `ROOT_UNLOGGED`, reported, the last good root kept). R := the newest root reached. A root older than the anchor is never adopted (`ROOT_ROLLBACK` is the absence of progress, never a change).
3. **Manifest.** Parse; `root_version = R.version` and `root_sha256 = SHA-256(R)` (`ROOT_MISMATCH`); the signature block meets `(R.release.keys, R.release.t)` (`BAD_SIGNATURE`).
4. **Log.** `GHRP.message = SHA-256(GHRM)`; `leaf_key_id ∈ R.release.keys` and the leaf signature verifies; `log < |R.logs|`; the tree head verifies under that log's key; the inclusion path recomputes the root hash; at least `R.quorum` cosignatures by distinct keys in `R.witnesses` verify; no cosignature time exceeds trusted now + 1 day (`LOG_PROOF_INVALID`, `QUORUM_NOT_MET`).
5. **Time.** `issued_day ≤ today + 1` (`NOT_YET_VALID`); `today ≤ not_after_day`, else the manifest may still be accepted as a fact but the channel is `STALE` (no offer from it).
6. **Sequence.** Manifests are ordered by the pair `(root_version, manifest_seq)`, lexicographically, against the stored pair. Lower: `ROLLBACK`, no change. Equal: identical hash → `UNCHANGED`; different hash → `CONFLICT` (persistent flag, no change). Higher: accept. Because a new root version starts a new sequence space, a sequence pushed to 2⁶⁴ − 1 by a stolen release key (TUF's fast-forward attack) is escaped by RK4's root update, which TUF obtains by deleting the trusted timestamp and snapshot metadata after a key rotation.
7. **Persist** in one SQLCipher transaction: root (if newer), manifest, proof, sequence and hash, `floor := max(floor, floor_version_code)`, and the directory change of §7.8. A newer root reached in step 2 is persisted even when a later step refuses the manifest: it was verified on its own, and its key removals must take effect at once.

Two bundles in one run (two mirrors) are processed in the order of their pairs; equal pairs with different hashes set `CONFLICT`.

**Offer**

8. From the stored manifest: if `STALE`, none. If installed `versionCode < floor`: `UNSUPPORTED`, and the offer is the highest release with `version_code ≥ floor`, `min_sdk ≤ SDK`, flavor 1, ignoring the rollout bucket. Else the highest release with `version_code > installed`, `min_sdk ≤ SDK`, flavor 1, `rollout_permille > 0` and `bucket < rollout_permille`, where `bucket = ⌊1000 · BE64(HMAC-SHA256(rollout_key, "ghost/v1/rollout" ‖ rollout_salt)[0..8]) / 2^64⌋`. No offer: `UP_TO_DATE`.

**Check an APK (download, staging, and again while it is streamed into the installer)**

9. **Android-equivalent parse.** Before streaming, from the file's last 22 bytes: an end-of-central-directory record with comment length 0 at exactly `length − 22`, a single disk, no ZIP64 (`APK_LAYOUT`); `cd_offset` from it; the 24 bytes before `cd_offset` must end with the magic `"APK Sig Block 42"` and give the block size `s`, and the block's leading 8-byte size field, checked when the pass reaches it, must also equal `s` (both copies, as Android checks); the block spans `[cd_offset − s − 8, cd_offset)`. Then one in-order streaming pass computes **(a)** SHA-256 and length of the whole file and **(b)** the **core**: the file without the block, with the end record's offset field replaced by `cd_offset − s − 8`. Inside the block, the v3 (`0xf05368c0`) or v2 (`0x7109871a`) signer's first certificate is parsed (lengths only, no signature check: the platform verifies the signature) and hashed.
10. Require: length = `apk_length`, full hash = `apk_sha256` (`APK_HASH`); core length and hash = `unsigned_length`, `unsigned_sha256` (`APK_CORE`); the certificate digest ∈ `R.apk_signers` (`APK_SIGNER`); the attestation block meets `(R.attest.keys, R.attest.t)` over `GHRA(release)` (`ATTESTATION_QUORUM`).

Because the parse finds the block and the central directory as the platform does, a file that adds anything Android would install, outside the attested core, cannot pass step 10 (crafted-APK suite, §11.1; mutants MC-D15, MC-D21).

### 7.5 Anti-rollback, floor, expiry, conflict

- The platform refuses an APK with a lower `versionCode` than the installed one ("The Android system uses the versionCode value to protect against downgrades", developer.android.com, "Version your app"). The updater never offers `version_code ≤ installed`.
- Root version, the `(root_version, manifest_seq)` pair and the floor are append-only facts with triggers (§9.6). A manifest can raise the floor (RK4: a vulnerable version), never lower it.
- **`versionCode` policy**: a release counter (1, 2, 3, …) per network in a committed file read by `app/build.gradle.kts` (replacing the literal at `:14-15`); `ghost-release-ops manifest-build` refuses a `version_code` not greater than every `version_code` in the network's logged manifests (it reads the archive). Nothing depends on the build date (T12).
- **No downgrade path** (X-D4): recovering from a bad release is a new release with a higher counter; an uninstall and reinstall loses local data (the identity comes back from the mnemonic; tokens do not, `LIM` E11).
- `CONFLICT` is persistent like `SCHEDULE_CONFLICT` (`ADR-22:22`): a Phase 13 alarm and evidence of equivocation; it does not block later, strictly newer manifests.
- `STALE`: the app keeps working on its last directory; no offer; the Phase 13 copy names it after 7 days.

### 7.6 Staged rollout, halt, roll-forward (the operator's runbook R-R)

- A release enters with `rollout_permille = 50`, then 250, 500, 1000 by RK6-style re-signing (C-12's 5/25/50/100). **Halt** = re-sign with 0: clients not yet updated stop being offered it; installed ones are untouched (spec §12.2 step 5).
- **Health signals without telemetry** (ADR-06): users' manual crash reports (FR-8.11), testers' reports, relay-visible refusals the relays already count, issuer `status.json`. The rollback threshold of C-12 is set in the runbook by Phase 17/18; this phase rehearses halt and roll-forward.
- **Roll-forward**: the previous release's source with the next counter, through the full pipeline (two environments, attestations, RK1). A schema version (`Schema.kt:115-118`: an existing version is never changed) and an accepted ES (rule 5) never go back, so the roll-forward keeps the newer schema and ES. Hence: a release that adds a migration or a new ES gets a first stage of at least 7 days at 5 % (Q30).

### 7.7 Download, staging, installation

- The offered APK is downloaded into `noBackupFilesDir/update/<sha256>.part` in 4 MiB ranges (one row in `upd_staged`); a finished file is checked (§7.4 steps 9–10) and renamed `<sha256>.apk`; one staged file at most; a superseded or installed one is deleted. This is the update module's only file outside SQLCipher (X-D10); the APK is public data, but its presence tells AD-8 an update is pending (L10-D16).
- **Install** (UI-less, called by Phase 13): a `PackageInstaller` session for the own package, with `setRequireUserAction(USER_ACTION_REQUIRED)` on API 31+ (earlier releases always ask the user); Kotlin reads the staged file in order and, chunk by chunk, passes it to the native check (`apkUpdate`) **and** writes the same bytes to `session.openWrite`; `session.commit` is called only if `apkFinish` returns `OK`, so the bytes the platform receives are exactly the bytes checked (no check-then-use window). The platform shows its confirmation; a non-exported receiver gets the status (T15m). After the update the new process confirms its own `versionCode`, clears the staging and reports `INSTALLED`.
- Since Android 8.0 the "Install unknown apps" permission, granted by the user per app and checked with `canRequestPackageInstalls()`, governs installs from an app (developer.android.com, Android 8.0 changes); the app declares `REQUEST_INSTALL_PACKAGES` for it (the exact session behaviour on API 29, 33 and 37 is V-D13). Phase 13 owns the prompt. On Android 14+, an app whose first installer claimed update ownership triggers a user prompt when another installer updates it (source.android.com, "App ownership"); GHOST's own sessions are user-confirmed anyway.

### 7.8 The relay directory

- **Bootstrap** (source `config`): the committed `ghost/protocol/entitlement/relay-directory.txt` and `ghost/protocol/release/<network>/mirrors.txt` are compiled into the native library (`include_bytes!`, the ES pattern) and exposed through `UpdateNative.embeddedDirectory` as validated entries; at first start, if `relay_directory` is empty, the engine inserts them. Today **no production code fills the directory** (only tests call `RelayDirectory.upsert`, F-D3), so without this step an installed app has no relay.
- **From a manifest** (source `manifest`): the first accepted manifest takes the directory over. In each acceptance transaction, upsert every `GHRM.relays` entry (an existing row, bootstrap or not, becomes source `manifest`) and retire every active entry the manifest does not list (`RelayDirectory.retire`, Phase 7 semantics: retired relays keep cursors and capabilities for a later re-add, `RelayDirectory.kt:10-14`). So a relay whose operator turned hostile can be withdrawn from every client without an app release: consumers already skip retired relays (ES slots map only to active entries by exact `onion:port`, `DirectoryEsSlots.kt:31-36`). `ghost-release-ops manifest-build` refuses a manifest that omits an ES slot onion of the current or next week unless the run names it as withdrawn (an E18 emergency move, `ADR-22:21`); a stolen release key could still withdraw relays, an availability attack that the log makes public (L10-D11).
- **Mirrors**: the stored list is the newest manifest's, else the bootstrap list.

### 7.9 The ES and the manifest (F8 F6)

The ES stays compiled into the native library with no network path (ADR-22 point 5). Each release record carries `es_seq` and `es_sha256`; the auditor attests them with the build; the monitor checks append-only across logged releases (§5.3 (d)). `ghost-release-ops manifest-build` refuses a release whose ES ends before its release week + 25 (RQ-D29: a release-time rule, so T12 is untouched). The first distributed release will need ES seq ≥ 2: seq 1's 26-week window closes with week 2964 (`protocol/entitlement/README.md:37-40`).

---

## 8. Distribution channels and application identity (normative; ADR-52)

### 8.1 The onion mirror (primary)

Built in this phase (§7.1). First installs: Tor Browser fetching `apk/<sha256>` from a mirror, or any channel at all (a friend's phone, a USB stick, a messenger) **followed by `ghost-verify`** on a computer; integrity does not depend on the channel, only on the verifier (D21). No clearnet mirror (D1).

### 8.2 Accrescent: facts and the entry conditions

Facts (accrescent.app docs and FAQ, 2026-10-03): "Apps do not need to be open-source to be submitted"; "Accrescent doesn't build, sign, or update developers' apps itself"; signature schemes v2, v3 or v3.1; **multiple signing certificates not supported**; **"Accrescent does not accept monolithic APKs"** — uploads are APK sets built with bundletool from an app bundle; ≤ 1 GiB; target SDK per Google Play's rules, with removal on non-compliance; **"Apps may not have self-updaters"**, including "improper use of the REQUEST_INSTALL_PACKAGES permission … downloaders which prompt the user to update from an APK"; sign-up "only permitted for allowlisted GitHub accounts"; **domain verification** of the app ID's domain by a DNS TXT record `_accverify.<domain>` (for `com.example.securechat.android`, `example.com`). The research digest's "bundletool ≥ 1.11.4" is not on the requirements page and is not repeated here. Accrescent's client has no documented Tor setting; what its servers learn per update check is undocumented (L10-D2).

**Entry conditions** (all must hold before S-store starts; Q26): (a) the owner's GitHub account is allowlisted (OA-8); (b) the `applicationId` lies under a domain the project controls (Q3, Q4); (c) a **store flavor** without the `:update` module and without `REQUEST_INSTALL_PACKAGES` (the updater lives in its own Gradle module so the flavor is a dependency switch, §9.1); (d) a reproducible `bundleRelease` and a deterministic `bundletool build-apks` whose splits are signed by `K-APK` through PKCS#11 (bundletool's own signing takes a keystore; the splits may need `apksigner` one by one — S-store measures), with the APK set's hashes in `SHA256SUMS` and attested; (e) the residue declared and shown (store updates bypass the log and attestations; the store learns installs).

### 8.3 An F-Droid-format repository

Not built (Q71's applied default). Facts: the main F-Droid repository accepts only FLOSS ("All applications in the repository must be Free, Libre and Open Source Software", Inclusion Policy) and points other apps to "a separate repository"; a repository is defined by its own index-signing key (Security Model), signs its index (index-v2 with SHA256withRSA), recommends that "the repo signing keys should not ever be on a public server" (Setup an F-Droid App Repo); F-Droid 2.0 (2026-09-24) moved "Use Tor" to generic proxy settings, recommends Tor VPN and installs updates by default through the session installer. An own repository would add a third key family (RSA index key) and its updates would bypass GHOST's log check like any store; users would need Orbot or a Tor VPN for an onion repository. Reconsider only if a verifier can cover it (Q71).

### 8.4 Google Play (rejected)

Google Play holds the app signing key (new apps are enrolled in Play App Signing with Google-generated keys; a developer-provided key is also held by Google; support.google.com 9842756): against A7, TB-6 and FR-8.2, and a Play-signed GHOST could not update a mirror-signed one or the reverse. Publishing also discloses the developer's legal identity for personal accounts (channels digest; not re-checked here, Appendix C). Not a channel.

### 8.5 Android developer verification and Play Protect (platform facts)

- **Developer verification** (developer.android.com/developer-verification and its FAQ, 2026-10-03): from **2026-09-30**, installs from participating stores in Brazil, Indonesia, Singapore and Thailand on certified devices (Android 7+) require registered developers; in **2027** it "expands globally for all apps on certified Android devices"; for now, "if users sideload your app directly, these new verification requirements won't apply to your app yet"; "Unregistered apps can only be installed or updated when the advanced flow is enabled or by using ADB so if the advanced flow is disabled updates to unregistered apps will fail"; registration takes package names and signing-certificate fingerprints, a legal name, a government ID and a fee; a limited-distribution account (no ID, no fee) covers at most 20 devices; "If you lose your signing key you won't be able to register your packages". The advanced flow (Developer options, screen-lock authentication, a no-coercion confirmation, a restart and a 24-hour wait, then 7 days or indefinitely; press reports of 2026-08) is a large burden for a privacy app's users.
- **Consequence:** from 2027, on certified devices, the onion mirror works for unregistered GHOST only through the advanced flow or ADB; registration ties the owner's legal identity to the package and certificate at Google. GrapheneOS and other non-certified systems are outside Google's stated scope [I]. Decision for the owner with counsel before the beta (Q18); this phase only keeps `K-APK` backed up so registration stays possible.
- **Play Protect** on GMS devices: "If you install apps from unknown sources …, Google Play Protect may ask you to send unknown apps to Google"; with "Improve harmful app detection" on, it sends them automatically; a scan "will send app details to Google for a code-level evaluation" (support.google.com 2812853). A GHOST install or update may therefore tell Google that a device installed GHOST (L10-D9). Phase 13 copy says so and suggests the setting and de-Googled systems.

### 8.6 Application identity

`applicationId` is permanent once a release ships: Android binds data, updates and signatures to it. `org.ghost.app` (`app/build.gradle.kts:11`) names `ghost.org`, which the project does not hold; Accrescent's domain check and developer verification's "package name already in use … additional review" make that costly later. Q3 asks the owner to fix the final id (with the domain of Q4) **before the first distributed APK**; stagenet appends `.stagenet` (D2).

---

## 9. Integration: modules, JNI, `:sync`, schema (normative)

### 9.1 Module layout

| Where | What | Rule |
|---|---|---|
| `ghost/client-core/update` (`ghost-client-update`) | formats (§4), the decision (§7.4), the APK parse and core hash, the rollout bucket, `GHRA` | pure: no I/O, no clock, no logging, no async runtime, `#![forbid(unsafe_code)]`; depends only on `sha2`, `ed25519-dalek` 2.2.0 and `hmac`, all already in the client graph and in `rust-dependency-allowlist.txt`; linked into `libghost_client_net.so`; the G-R8-style scan (G-D6) |
| `ghost/client-core/net` | `mirror.rs` (`MirrorClient::over_tor`, HTTP/2 GET on `IsolationScope::Update`, bounds, deadlines); the embedded anchor, bootstrap mirrors and bootstrap directory (`include_bytes!`); the JNI exports of §9.3 | onion only through `connect_isolated` (the clippy bans of `client-core/net/clippy.toml` unchanged) |
| `ghost/release/ops` (`ghost-release-ops`) | the offline and publication tool: `root-build`, `root-verify`, `manifest-build` (the release-time checks of §7.5, §7.9), `statement` (prints the bytes to sign), `attach` (adds a signature), `leaf-statement`, `leaf-request` (a Sigsum add-leaf request body from a token signature), `apk-core`, `proof-assemble`, `bundle`, `sbom`, `sums-compare`, `verify` | workspace member; prints only through a fixed vocabulary (the `ghost-issuer-ops` `report.rs` pattern); **holds no key** — signatures come from the token tools (§3.2); no network code (submission is `sigsum-submit`) |
| public repository | `ghost-verify` (§5.4) on a copy of `ghost-client-update` | permissive licence (Q28); reproducible from its source |
| `ghost/android/network` | `UpdateNative` (verification calls) and `TorMirrorTransport` (the fetch), thin wrappers decoding fixed layouts strictly | the `EntitlementCrypto` pattern (`EntitlementCrypto.kt:3-11`) |
| `ghost/android/update` (`:update`, new) | `UpdateEngine` (the update-run participant), `UpdateStore` (migration U's DAO), `ApkStager`, `InstallerPort` (`PackageInstaller`), the facade `Updates` for Phase 13 | no protocol logic (ADR-19); no `java.net` (the `kotlin-clearnet.sh` scope extended) |
| `ghost/android/sync` | update runs (§9.4) | T19, T23 unchanged in substance |
| `ghost/android/storage` | migration U (§9.6) | the F9 §13.6 practice |
| `ghost/android/app` | wiring; `REQUEST_INSTALL_PACKAGES`; the installer-status receiver; `vcsInfo` off; the release counter; `.stagenet` suffix | T15, T15m |
| `ghost/infra/{builder,mirror,release}`, `ghost/scripts/release/` | the recipe; mirror deployment; `RUNBOOK.md` (Romanian: RK0 … RK6, R-P, R-R); `build-release.sh`, `sums-compare.sh` | G-D2 |
| `ghost-dm-host` | gains the `UpdateNative` exports for the JVM worlds | G-R6 gains a list (as F10 and F11 add theirs) |

### 9.2 `ghost-client-update` API (normative signatures)

```rust
pub enum Code { Ok, Malformed, WrongNetwork, RootChainBroken, RootUnlogged, RootMismatch, BadSignature,
                LogProofInvalid, QuorumNotMet, NotYetValid, Rollback, Unchanged, Conflict,
                ApkLayout, ApkLength, ApkHash, ApkCore, ApkSigner, AttestationQuorum, OutOfOrder }
pub struct Stored<'a> { root: &'a [u8], root_version: u32, manifest_root: u32, manifest_seq: u64,
                        manifest_sha256: Option<[u8; 32]>, floor: u32 }
pub fn accept(stored: &Stored, embedded_anchor: &[u8], bundle: &[u8],
              today: u32, now_unix: u64) -> Accepted;           // §7.4 steps 1–6 (step 7 is Kotlin's transaction)
pub fn offer(root: &[u8], manifest: &[u8], installed: u32, sdk: u8,
             rollout_key: &[u8; 32], today: u32) -> Offer;     // step 8
pub struct ApkCheck { /* streaming state */ }
impl ApkCheck {
    pub fn begin(root: &[u8], manifest: &[u8], release: u8, length: u64,
                 eocd: &[u8; 22], footer: &[u8; 24]) -> Result<Self, Code>;   // step 9, layout
    pub fn update(&mut self, offset: u64, chunk: &[u8]) -> Result<(), Code>;  // in order only
    pub fn finish(self) -> Result<(), Code>;                                   // step 10
}
pub fn directory(root: &[u8], manifest: &[u8]) -> Result<Directory, Code>;   // validated onions, operator ids
pub fn ghra(network: u8, release: &Release) -> Vec<u8>;
```

### 9.3 The closed JNI surface (gate G-D5) and result codes

`org.ghost.network.UpdateNative` exports exactly: `nativeEmbeddedAnchor`, `nativeEmbeddedDirectory`, `nativeAccept`, `nativeOffer`, `nativeDirectory`, `nativeApkBegin`, `nativeApkUpdate`, `nativeApkFinish`, `nativeApkAbort`; `org.ghost.network.TorMirrorTransport` exports `nativeFetch(handle, onion, path, rangeStart, maxLen, deadlineMs)`. Byte in, byte out; fixed big-endian result layouts decoded strictly in Kotlin (a wrong length is `malformed_response`); results carry a one-byte `Code` (§9.2) and never a message; APK checks live in the ADR-19 handle registry (opaque ids, idempotent abort, `catch_unwind`). The fetch fails with the existing `NetworkException` categories (`transport`, `deadline`, `malformed_response`, `closed`, …; no new category unless S4 shows one is needed, then `ErrorPolicyTest` and `client-core/README.md` change together). G-D5 checks the exported `Java_org_ghost_network_UpdateNative_*` and `…TorMirrorTransport_nativeFetch` symbols of the shipped library with `llvm-nm -D --defined-only` (the G-R6 method, `ci.yml:234-240`) and that only `android/update` and `android/network` reference `UpdateNative`.

### 9.4 `:sync` additions (normative)

1. `RandomSources.updateRun(index)`: a new keyed domain of the process's random key; `JobFate.of(occupied, quietDraw, updateDraw, participant, updater)` → `UPDATE_RUN` when the run is not quiet, its update draw is `< 1/24` and an updater is installed (`JobFate.kt:20-36`).
2. `SyncController.setUpdater(UpdateParticipant?)`, one slot, set at wiring (the participant pattern, `SyncController.kt:20-25`).
3. `UpdateParticipant.onUpdateRun(session: UpdateSession)`; `UpdateSession` grants `mirror: MirrorAccess` only, with `clockTrusted()`, a deadline and `closed` (the `LeasedSession` contract: never inside a sync transaction, never feeding breakers or budgets).
4. `SyncController.runUserUpdateCall { … }`: only while the app is visible, never during a background session or a quiet run (the `runUserIssuerCall` rule).
5. No change to the read lane, to quiet runs or to relay sessions: an update run, like a quiet run, simply has no relay session; T19's tests gain the update draw as a pure function and NI-U1 shows the read schedule unchanged by update state.

### 9.5 `:update`: engine, states, facade

States per offered release, and channel flags beside them (`STALE`, `CONFLICT`, `UNSUPPORTED`, `NO_CHANNEL` when no mirror answered for 14 days). Every legal and illegal transition has a JVM test (the F9 §13.5 practice); the persisted part is `upd_staged.state` (§9.6), the rest is derived at start from the stored facts.

| From | Event | To | Side effects |
|---|---|---|---|
| `NONE` | an update run or a user check accepts a manifest whose offer (§7.4 step 8) is non-empty | `OFFERED` | none (no fetch triggered by acceptance itself) |
| `OFFERED` | an update run (or the user) starts the download | `DOWNLOADING` | `upd_staged` row `partial`, file `<sha256>.part` |
| `DOWNLOADING` | a 4 MiB range written | `DOWNLOADING` | `received` advances in the same transaction as the file sync |
| `DOWNLOADING` | last range written and §7.4 steps 9–10 return `OK` | `STAGED` | rename to `<sha256>.apk`; row `verified` |
| `DOWNLOADING`, `STAGED` | the check fails, or a newer accepted manifest no longer offers this release | `NONE` or `OFFERED` (the new offer) | file and row deleted |
| `STAGED` | `install()` (Phase 13, user present) | `INSTALLING` | session created; row `committed` only after `apkFinish = OK` and `session.commit` |
| `INSTALLING` | status receiver: success, then the new process sees its own `versionCode` = the release's | `INSTALLED` → `NONE` | file and row deleted |
| `INSTALLING` | status receiver: failure or user abort | `STAGED` (file kept) or `FAILED(code)` → `OFFERED` | session abandoned |
| any | wipe (Phase 3) | — | tables and `noBackupFilesDir/update` deleted |

```kotlin
interface Updates {                                   // UI-less, for Phase 13
    val status: UpdateStatus      // UpToDate | Available(name, code) | Downloading(received, total) | Ready(name, code)
                                  // | Installing | Installed(code) | Stale(day) | Unsupported(floor) | Conflict | NoChannel | Failed(code)
    fun requestCheck(): CheckOutcome            // user-initiated, foreground only (§7.3)
    fun requestDownload(): DownloadOutcome      // user-initiated, foreground only
    fun install(): InstallHandle                // §7.7; the platform confirms
    fun signerCertificateSha256(): ByteArray    // for the "verify this app" screen
}
```

### 9.6 Schema migration U (normative; one transaction, append-only, fail-closed)

`U` is the next free version at merge: 9 if Phases 10 and 11 merge first with their reserved 6, 7 and 8; whichever lands first takes the next number and the later ones move, because a device applies only versions above its own (X-D12, Q34). The F9 §13.6 rules apply: explicit columns, `typeof` CHECKs, REPLACE guards, write-once and monotonic triggers, no time column of activity (T33's rule; none is needed).

```sql
CREATE TABLE upd_state (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  network            INTEGER NOT NULL CHECK (typeof(network) = 'integer' AND network IN (1, 2)),
  root_version       INTEGER NOT NULL CHECK (typeof(root_version) = 'integer' AND root_version >= 1),
  root_file          BLOB    NOT NULL CHECK (length(root_file) BETWEEN 64 AND 16384),
  manifest_seq       INTEGER NOT NULL CHECK (typeof(manifest_seq) = 'integer' AND manifest_seq >= 0),
  manifest_root      INTEGER NOT NULL CHECK (typeof(manifest_root) = 'integer' AND manifest_root >= 0),
  manifest_sha256    BLOB    CHECK (manifest_sha256 IS NULL OR length(manifest_sha256) = 32),
  manifest_file      BLOB    CHECK (manifest_file IS NULL OR length(manifest_file) <= 65536),
  proof_file         BLOB    CHECK (proof_file IS NULL OR length(proof_file) <= 16384),
  floor_version_code INTEGER NOT NULL CHECK (typeof(floor_version_code) = 'integer' AND floor_version_code >= 0),
  conflict           INTEGER NOT NULL CHECK (conflict IN (0, 1)),
  rollout_key        BLOB    NOT NULL CHECK (length(rollout_key) = 32),
  CHECK ((manifest_seq = 0) = (manifest_file IS NULL)),
  CHECK ((manifest_file IS NULL) = (manifest_sha256 IS NULL) AND (manifest_file IS NULL) = (proof_file IS NULL))
);
-- triggers: network and rollout_key write-once; root_version never decreases;
--   (manifest_root, manifest_seq) never decreases lexicographically, and an equal pair keeps its manifest_sha256;
--   floor_version_code never decreases; conflict never returns to 0; no DELETE.
CREATE TABLE upd_staged (
  apk_sha256   BLOB    PRIMARY KEY NOT NULL CHECK (length(apk_sha256) = 32),
  version_code INTEGER NOT NULL CHECK (typeof(version_code) = 'integer' AND version_code > 0),
  apk_length   INTEGER NOT NULL CHECK (typeof(apk_length) = 'integer' AND apk_length > 0),
  received     INTEGER NOT NULL CHECK (typeof(received) = 'integer' AND received BETWEEN 0 AND apk_length),
  state        TEXT    NOT NULL CHECK (state IN ('partial', 'verified', 'committed'))
) WITHOUT ROWID;                    -- a trigger keeps at most one row
```

#### 9.6.1 Transactions and crash rules (normative)

| Transaction | Steps | Crash rule |
|---|---|---|
| `ACCEPT` | one SQLCipher transaction: `upd_state` (root, pair, hash, manifest, proof, floor, conflict) and the `relay_directory` changes of §7.8 | all or nothing; a crash leaves the previous facts, and the next update run fetches again |
| `STAGE-CHUNK` | write the range to `<sha256>.part` at its offset, `fsync`, then one transaction advancing `received` | a crash after the write and before the commit re-downloads that range (the file is overwritten at the same offset); `received` never exceeds what is on disk |
| `STAGE-VERIFY` | the full check of §7.4 steps 9–10 on the `.part` file, then `rename` to `.apk`, `fsync` of the directory, then the row to `verified` | at start, a `.apk` with a `partial` row is re-checked; a `.part` with a `verified` row is impossible (the row follows the rename); files without a row are deleted |
| `INSTALL-COMMIT` | stream into the session with the native check, `apkFinish = OK`, `session.commit`, then the row to `committed` | a crash before `commit` abandons the session (the platform's own session cleanup) and leaves `verified`; a crash after `commit` and before the row update is resolved at the next start by comparing the installed `versionCode` |
| `INSTALL-CONFIRM` | at the first start of the new version: the own `versionCode` equals the row's → delete row and file | idempotent |
| `SWEEP` | at start: delete staged files and rows no longer offered by the stored manifest, and any file without a row | idempotent |

The directory change of §7.8 runs on the Phase 7 `relay_directory` table in the same transaction (its `source` CHECK already admits `'manifest'`, `Schema.kt:287`). The migration creates the tables empty; the engine inserts the one `upd_state` row at its first start (the embedded anchor, sequence 0, floor 0), with `rollout_key` drawn from `SecureRandom` (not SQLite's `randomblob`); the key never leaves the database. A wipe (Phase 3) deletes both tables with the rest.

### 9.7 Manifest and permissions (T15, T15m; ADR-51)

- `<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />`, with an ADR-51 comment (`AndroidManifest.xml:5` requires one); `T15_ALLOWED_PERMISSIONS` gains it (`common.sh:15`) with the same reference.
- `<receiver android:name="org.ghost.update.android.InstallStatusReceiver" android:exported="false" />`, no intent filter, reached by an explicit, mutable `PendingIntent` (the platform adds the session status extras); `merged-manifest-lint.sh` lists it as G-DM7 lists the alarm receiver.
- No `UPDATE_PACKAGES_WITHOUT_USER_ACTION` (Q16). No `QUERY_ALL_PACKAGES`: the engine reads only its own package's `versionCode`.

### 9.8 Relation to other phases

**Relays and the issuer** get no protocol change: their binaries and the ES file each loads with `--schedule` (artifact kinds 5, 6, 17) enter the release record, and operators check them with `ghost-verify operator` before starting a new version (§5.4); the relay sees nothing of update runs (no relay session in them). **Entitlement** is untouched in behaviour: quiet runs keep their 1/8 draw and their single issuer call; the ES stays embedded; the release tool enforces the 26-week rule at release time (§7.9). Phase 13 builds the screens on §9.5 and writes the copy of §2.6 and L10. Phase 12 fills bridges and must embed a default set (F-D7). Phase 10's channel relays come from the same directory. Phase 16/17 runs RK0 for mainnet with the mainnet K1 and adds network selection at build. Phase 15 audits this code and the pipeline (plan:319 "supply chain"). The Phase 9 host library and G-R6 gain the update list.

---

## 10. Invariants (new T48–T52; changes to T2, T6, T12, T15, T19, T20, T23)

### 10.1 New invariants (Romanian rows for INVARIANTS.md in Appendix B.2)

| ID | Invariant | Verification | Executable from | Code |
|---|---|---|---|---|
| **T48** Signed, logged, attested updates | The updater writes into an installer session only bytes equal to an APK listed in a manifest that (a) is signed by the release threshold of the newest root reachable from the anchor by the chain rule (each new root signed by both thresholds and logged under the previous root's policy), (b) has the network and root binding of that root, (c) is included in a policy log under a tree head signed by that log and cosigned by the witness quorum, and (d) whose release's unsigned core, found by the Android-equivalent parse, equals the attested unsigned build with the root's attestation threshold met; size bounds fixed before reading | vectors and every-byte mutation of each format; the crafted-APK suite; the TUF attack list as tests; UpdateWorld with hostile mirrors and the recording installer; mutants MC-D1 … MC-D5, MC-D9 … MC-D15, MC-D20 … MC-D23 | Phase 14 | `client-core/update`, `client-core/net`, `android/update` |
| **T49** No rollback, equivocation kept | Root version, the `(root_version, manifest_seq)` pair and the floor never decrease; an equal pair with other bytes sets the persistent conflict flag and changes nothing; nothing at or below the installed `versionCode` is offered; below the floor, the app is `UNSUPPORTED` | trigger tests; JVM sequence suites (rollback, equal-pair conflict, fast-forward and its root escape); emulator downgrade; MC-D6, MC-D7, MC-D16 … MC-D18 | Phase 14 | `client-core/update`, `android/storage`, `android/update` |
| **T50** Bounded freshness | No offer comes from a manifest past `not_after_day` (on a trusted clock); every update run reads two mirrors and keeps the highest pair; a mirror cannot hold the client below what another serves; no time decision on an untrusted clock | freeze and stale-mirror worlds; clock-step cases; MC-D8, MC-D13, MC-D19 | Phase 14 | `client-core/update`, `android/update`, `android/sync` |
| **T51** Private update traffic | Mirror fetches happen only in update runs (drawn from the process key and the run index only) or at the user's explicit request; on the `Update` scope, never in a relay session or a quiet run; every update run requests the same objects with the same headers from two mirrors; no request carries a version, a root version, an identifier or a conditional header; APK ranges are fixed 4 MiB steps; the rollout bucket is per release and never leaves the device | NI-U1 … NI-U4 (twins differing in activity, entitlement state, installed version, stored root: identical mirror views); request-builder test; scope test in `client-core/net`; PM-D1 … PM-D8 | Phase 14 | `android/sync`, `android/update`, `client-core/net` |
| **T52** Keys offline, cores preserved | No signing secret is in the repository, in a workflow, in CI or on a mirror; no workflow signs or publishes; every published APK satisfies `core(signed) = unsigned` and its unsigned build's hashes were equal in two environments before signing | G-D1 (secret patterns, signing commands in workflows); `ghost-release-ops apk-core` on every release; `release-build.yml` records; RK1 checklist | Phase 14 | `scripts/gates`, `release/ops`, `infra/release` |

### 10.2 Changes to existing invariants

| ID | Change |
|---|---|
| T2 | Unchanged. Update runs read nothing of the entitlement state and make no issuer or relay call, so no join key appears; NI-U2 shows mirror views identical across entitlement states. |
| T6 | Mirror fetches are onion-only through `connect_isolated`; no clearnet mirror exists. The dynamic T6 test (Phase 13) includes an update run. |
| T12 | "Două medii" becomes executable: the release outputs of a tag are identical in environment A and environment B (`release-build.yml`); the same-path T12 job stays. T12b gains its mechanism: `GHRA` signatures enforced by the updater on networks whose root sets `attest.t ≥ 1`. |
| T15 | The allowlist gains `REQUEST_INSTALL_PACKAGES` (ADR-51); T15m allows `InstallStatusReceiver` (not exported, no filter). |
| T19 | The update draw is a pure function of the process key and the run index; update state never changes the read schedule (NI-U1). |
| T20 | Unchanged for the sync layer; the update module's one file outside SQLCipher is the staged APK (X-D10). |
| T23 | Update runs are never quiet runs and never contain an issuer call. |

---

## 11. Testing and the exit-gate argument

### 11.1 Rust: vectors, properties, fuzzing, cross-checks (`rust` job)

- **Vectors** `release_root.txt`, `release_manifest.txt`, `release_proof.txt`, `release_bundle.txt`, `release_apk_core.txt`: valid cases per format and network; every single-byte mutation of each valid case refused; every length and count bound ±1; non-canonical orderings, duplicates, trailing bytes, `ext ≠ 0`, wrong network, wrong statement type.
- **Chain rule**: old threshold only, new threshold only, both, a key moved between keysets, a skipped version, a chain with a broken middle link (the last good root kept); a correctly signed new root without its log proof, with a proof under its own (new) policy instead of the previous one, and with a leaf signed by a key of the new root only (`ROOT_UNLOGGED` each).
- **TUF attack list as tests**: arbitrary installation (APK not in the manifest), endless data (each bound), extraneous dependencies (not applicable: one artifact; stated), fast-forward (a pair pushed to the maximum, then the root escape), indefinite freeze (expiry on a trusted clock), malicious mirrors preventing updates (two mirrors, highest pair), mix-and-match (a proof of another manifest, a root of another network, a manifest of another root), rollback, key compromise below threshold (one of two root keys), wrong software (another network, signer or flavor).
- **Log proofs**: vectors from sigsum-go v0.14.1 (a CI-only Go tool in the `vendor-tests` pattern, BSD-2-Clause): real leaves, inclusion proofs at several tree sizes, signed tree heads, `cosignature/v1` lines; GHOST's parser must agree on every byte (V-D11).
- **Crafted-APK suite**: an EOCD comment; two EOCD records; ZIP64; a missing block magic; mismatched block sizes; a central-directory offset pointing into the block; bytes between the block and the central directory; an extra local entry; a v2-only, a v3, a v3.1-with-lineage APK (from apksigner with test keys); a certificate not in the root; a core differing in one byte. Each must give its exact `Code`.
- **Properties**: 10⁶ seeded inputs per parser per run (never panics, never reads past input); the bucket function's distribution (χ² over 10⁵ salts).
- **Fuzzing**: `update-fuzz` targets for every parser and the APK layout, on a dated nightly (the `dm-fuzz` arrangement, F9 §16.2).
- **Independent implementation**: a JVM test-only decoder (JDK `MessageDigest` and BouncyCastle's Ed25519, the F9 §15.2 practice) replays the manifest, root and statement vectors; the Merkle path check replays sigsum-go's vectors.

### 11.2 The update world (JVM; `android` job and the gate job)

`UpdateWorld` (`android/update/src/test`): 2–50 clients, each the real `:update` engine over the real `:storage` (SQLite JDBC, migrated to U) and the `:sync` driver with update runs, calling the real native core through the host library; **model mirrors** with hostile modes STALE, ROLLBACK, EQUIVOCATE (each mirror a different manifest at one pair), GARBAGE, TRUNCATE, ENDLESS, SLOW, WITHHOLD_PROOF, WRONG_PROOF, MIXED_ROOT, FAST_FORWARD, APK_SWAP (a different core), APK_EXTRA (bytes added inside the block), DROP_MID_RANGE; a model log and witnesses with generated keys; a virtual clock with steps; a **recording installer port** that keeps every byte written to a session and fails the world if they differ from the checked bytes; crash enumeration at every SQL statement and every file operation of the §9.6.1 transactions (the F7 §8.3 method) with the structural invariants re-checked after each restart.

**Twin worlds (T51).** Each pair differs in one input only and must give **identical mirror views** (every request's time, mirror, path, headers and range, over 60 virtual days):

| Twin | The two worlds differ in | Must not differ |
|---|---|---|
| NI-U1 | user activity: app opens, DM sends, channel reads, foreground time | mirror views, and the read schedule (T19 unchanged) |
| NI-U2 | entitlement state: purchases, trials, an expired subscription, quiet-run issuer calls | mirror views (T2 untouched) |
| NI-U3 | installed version (current vs one behind with no offer reaching it) and stored manifest (fresh vs stale) | bundle requests (headers, paths); APK requests exist only where an offer exists, in fixed ranges |
| NI-U4 | stored root version (current vs three behind) | bundle requests |

### 11.3 Mutants (31; each detected against a same-scale control; implemented only in test sources)

| ID | Mutation | Killed by |
|---|---|---|
| MC-D1 / MC-D2 | root chain without the old / the new threshold | chain vectors; RK2 world |
| MC-D3 | manifest accepted under a key no longer in the root | revocation world |
| MC-D4 | duplicate signatures by one key counted twice | sigblock vectors |
| MC-D5 | network byte ignored | wrong-network vectors |
| MC-D6 | lower pair accepted | ROLLBACK mirror |
| MC-D7 | equal pair, other bytes accepted | EQUIVOCATE mirror |
| MC-D8 | expiry ignored | STALE world |
| MC-D9 | inclusion path not checked | WRONG_PROOF |
| MC-D10 | tree-head signature not checked | WRONG_PROOF variant |
| MC-D11 | witness quorum not enforced | quorum vectors |
| MC-D12 | cosignature by an unknown witness counted | quorum vectors |
| MC-D13 | response read past its bound | ENDLESS |
| MC-D14 | full-file hash skipped | APK_SWAP |
| MC-D15 | core or attestation check skipped | APK_SWAP, attestation vectors |
| MC-D16 | offer at or below the installed version | offer suite |
| MC-D17 | floor lowered by a manifest | trigger test, floor world |
| MC-D18 | older root adopted | root-rollback vectors |
| MC-D19 | one mirror per run | stale-mirror world |
| MC-D20 | proof of another manifest accepted | mix-and-match vectors |
| MC-D21 | block located from manifest data, not from the file | APK_EXTRA, crafted suite |
| MC-D22 | session committed without `apkFinish = OK` | recording installer |
| MC-D23 | a new root adopted without its log proof under the previous root's policy | the root-swap world (two stolen root keys, the attacker's own log and witnesses) |
| PM-D1 | check at app start | NI-U1 |
| PM-D2 | fetch on a namespace or issuer scope | scope test |
| PM-D3 | a header that differs between clients | request-builder test, NI-U3 |
| PM-D4 | conditional fetch with the stored hash | NI-U3 |
| PM-D5 | fetch of only the missing roots | NI-U4 |
| PM-D6 | update fetch inside a quiet run or relay session | `JobFate` and lease tests |
| PM-D7 | one rollout bucket across releases | bucket test |
| PM-D8 | APK ranges at resume offsets instead of fixed steps | NI-U3 |

The report line `update mutants: 31 run, 31 detected` is required by `update-report-check.sh` (G-D7).

### 11.4 Emulator and devices (V-D13, V-D14 become tests)

`update-emulator.yml` (manual and nightly; it needs KVM, which the runners lack, so the evidence is a recorded local run until a KVM runner exists, as in F9 §22.32 and F11 §17.1): API 29, 33 and 37 images; install v1 (test key), update to v2 through the engine against loopback model mirrors (a transport seam in the `gate` build type only, G-DM5's rules), user confirmation driven by UI Automator; a lower `versionCode` refused by the platform (`INSTALL_FAILED_VERSION_DOWNGRADE`); the rotated release installed over v2 on each image; then an old-key-signed v4: refused on API 33 and 37, accepted on API 29 (the declared L10-D3). **Live drill** (S9, manual, signed): a phone with the stagenet build, the two real staging mirrors over Tor, the real log, a real release produced by RK1 on the signer host.

### 11.5 Drills (the gate's three drills)

| Drill | Case | Where | Evidence |
|---|---|---|---|
| Tamper | each format byte-mutated; APK swapped, extended, truncated; proof of another manifest; manifest of another network | Rust, JVM, emulator, live (one tampered bundle served by a staging mirror) | vectors, world report, emulator log, signed live record |
| Downgrade | lower pair, older root, release ≤ installed, below floor, fresh install of an old APK then first update run → `UNSUPPORTED` | JVM, emulator | world report, emulator log |
| Rotation | RK2 release key; RK2 root key (two of three); RK2 witness set; RK2 attestation key; RK3 Android key with lineage; RK4 emergency revocation and floor; mirror retirement; a correctly signed but unlogged root refused (`ROOT_UNLOGGED`) | JVM (formats), emulator (lineage), live with tokens on stagenet (RK2, RK3, RK5) | world report, emulator log, signed ceremony records |
| Rollout | 50 → 250 → 1000 permille; halt at 0; roll-forward of the previous source with the next counter | JVM, live | world report, live record |

### 11.6 Cross-environment reproducibility

`release-build.yml` green on the phase's closing tag: `SHA256SUMS(A) = SHA256SUMS(B)` for every path of §6.1, both builds from the committed recipe; the variation matrix of §6.6 recorded in Appendix C with each row's result.

### 11.7 The exit-gate argument

The four parts of §1.2 map to evidence: (1) tamper — T48's suites, the crafted-APK suite, 23 security mutants, the emulator and the live drill; (2) downgrade — T49's suites, the platform's refusal on the emulator; (3) rotation — the RK2, RK3, RK5 ceremonies with real tokens on stagenet and the emulator lineage cases; (4) two environments — `release-build.yml` on the closing tag. T50 and T51 are not named by the plan's gate; they are this design's own guarantees (CS-D4, P-D1 … P-D4) and close with the world's twins and the 8 privacy mutants. **What remains outside**: the auditor's attestation, the production log policy, a second mirror operator, Google's platform behaviour, counsel (§1.2).

---

## 12. Gates, CI, dependencies

### 12.1 Gates (each with negative fixtures and a `self-test.sh` hit count)

| Gate | Rule | Supports |
|---|---|---|
| **G-D1** `release-no-secrets.sh` | (a) no signing material in the tree: PEM and OpenSSH private-key headers, Java and PKCS#12 keystores (by extension and magic), PKCS#8 files, onion secret keys anywhere under `infra/` (the search of `entitlement-schedule.sh`, extended), except listed test fixtures signed with throwaway keys; (b) no workflow runs `apksigner sign`, `jarsigner`, `bundletool build-apks --ks`, a PKCS#11 tool, `ykman`, `yubico-piv-tool` or `sigsum-submit`, and no Gradle `signingConfig` other than the debug key of the smoke and gate builds (`app/build.gradle.kts:40,55`); (c) G-L5's "nothing is published" stays | T52, TB-6 |
| **G-D2** `builder-pins.sh` | `infra/builder/pins.txt` is the single source: the Dockerfile's every `FROM` by digest, every download with a SHA-256 from it, the apt snapshot set; `ci.yml` (`RUST`, NDK, SDK packages, JDK), `rust-toolchain.toml`, `gradle-wrapper.properties`, `install-protoc.sh`, `build-native.sh` agree with it | T12, RQ-D3 |
| **G-D3** `release-sums.sh` | two `SHA256SUMS` are equal and complete (every path of §6.1); the APK's `lib/` entries equal the `lib/` lines; each symbol file's build-id equals its library's | T12, RQ-D18 |
| **G-D4** `release-records.sh` | per network: the committed root chain verifies from version 1 by the chain rule; the newest root lists the committed `apk-signer.crt` digest; `mirrors.txt` parses with ≥ 2 operators; the release counter never decreases over the first-parent history (the `entitlement-schedule.sh` history method); the tag-signing allowed-signers file exists; stagenet roots are never embedded in a mainnet build | D2, D16, RQ-D25 |
| **G-D5** `update-jni-surface.sh` | §9.3's closed list in the shipped library and in `ghost-dm-host` (`llvm-nm -D --defined-only`); only `android/update` and `android/network` reference `UpdateNative` | ADR-19, D20 |
| **G-D6** `update-rust-purity.sh` | `ghost-client-update` adds no crate to the client graph (`rust-client-allowlist.sh` unchanged); its sources contain no `std::fs`, `std::net`, `std::time`, `SystemTime`, `Instant`, `println!`, `eprintln!`, `dbg!`, `log::` or `tracing::` (the G-R8 scanner, `test-harness/vendored-scan`, run on the crate) | T51, T3 |
| **G-D7** `update-report-check.sh` | the gate job's report has `update mutants: 31 run, 31 detected`, the NI-U1 … NI-U4 lines equal, the drill lines; refuses a report claiming more than it measured (the `dm-report-check.sh` rule) | T48 … T51 |
| **G-D8** in `dependency-allowlist.sh` | `verification-metadata.xml` has no `trusted-artifacts` entry for `aapt2` (checksums instead) | D23 |
| T15, T15m | `common.sh:15` gains `REQUEST_INSTALL_PACKAGES` (ADR-51); `merged-manifest-lint.sh` lists `InstallStatusReceiver` | X-D8 |
| scopes | `no-logging.sh`, `anti-placeholder.sh`, `kotlin-clearnet.sh`, `sync-no-catch-all.sh` cover `android/update` and `client-core/update` | T3, T6, T8 |

### 12.2 CI jobs

| Job | Change |
|---|---|
| `static-gates` | G-D1, G-D2, G-D4, G-D5 (source half), G-D8, the widened scopes and their fixtures |
| `rust` | `ghost-client-update` unit, vector, property, chain, TUF-list and crafted-APK tests; `ghost-release-ops` tests (statements, manifest build refusals, `apk-core`, SBOM determinism: two runs byte-equal); G-D6 |
| `android-native` | the split symbols and build-id (V-D9); G-D5 on the shipped libraries; G-R6 unchanged |
| `android` | `:update` unit tests; `UpdateWorld` at PR scale (10 clients, every hostile mode once, crash singles); the JVM replay of the vectors; G-D5 host half; merged manifest |
| `reproducible` | unchanged (two same-path builds) plus a check that the APK has no `META-INF/version-control-info.textproto` |
| **`release-build.yml`** (new; signed tags, dispatch, weekly on `main`) | job A (self-hosted) and job B (`ubuntu-24.04`, hosted, disk cleanup first) run `scripts/release/build-release.sh` in the image built from the recipe; job C runs G-D3 on the two `SHA256SUMS` passed as job outputs; uploads nothing binary (G-L5) |
| **`update-exit-gate.yml`** (new; nightly, dispatch) | `UpdateWorld` at gate scale (50 clients, 120 virtual days, all hostile modes, crash enumeration at every statement), the 31 mutants, G-D7 |
| **`update-fuzz`** (new; nightly) | the fuzz targets on a dated nightly toolchain, own lock file checked by cargo-deny (the `dm-fuzz` arrangement) |
| **`update-emulator.yml`** (new; manual, nightly) | §11.4 on API 29, 33, 37; needs KVM ("not run is red", the `dm-emulator.yml` rule) |
| `vendor-tests` | + sigsum-go v0.14.1 built from source (Go toolchain pinned by hash) to regenerate and compare the log-proof vectors |

### 12.3 Dependencies and licences (closed source: only permissive licences in anything shipped)

| Item | Scope | Licence | Approval |
|---|---|---|---|
| `ghost-client-update` | release (in `libghost_client_net.so`); a copy in the public repository | proprietary; public copy permissive (Q28) | ADR-49, ADR-51 |
| `sha2`, `ed25519-dalek` 2.2.0, `hmac`, `hyper` (`http2`) | release | already in the client graph and its allowlist | existing pins (`rust-crypto-pins.txt`) |
| `ghost-release-ops` | offline and publication tool | proprietary; uses `serde_json` (already in the workspace) for the SBOM | ADR-50 |
| sigsum-go v0.14.1 | owner's workstation (`sigsum-submit`), CI vectors | BSD-2-Clause | ADR-49 |
| yubico-piv-tool and `ykcs11`, OpenSC | signer host only, never shipped | BSD-2-Clause; LGPL-2.1 (OpenSC, a separate program) | ADR-48 |
| `python-shamir-mnemonic` | signer host only | MIT | ADR-48 |
| nginx, or `ghost-mirror` | mirrors | BSD-2-Clause; proprietary | ADR-52 |
| diffoscope | CI diagnostic image only | GPL-3.0+ (a tool, never shipped or linked) | ADR-50 |
| Debian packages, Temurin 17, the Android SDK and NDK, the Rust toolchain | builder image (never distributed; each builder accepts the SDK licence) | various; Temurin GPLv2 + Classpath Exception | ADR-50 |
| **Not added** | `tough`, `aws-lc-rs`, any TUF library, any PKCS#11 Rust crate, any Gradle plugin (no CycloneDX Gradle plugin), OkHttp, any HTTP/1 client, any JSON parser in the client | — | — |

---

## 13. Slices, effort, exit-gate checklist

### 13.1 Slices (the Q defaults apply unless the owner objects)

| Slice | Content | Depends on | Exit condition |
|---|---|---|---|
| **S0a** Spikes without the owner | V-D1 … V-D5, V-D9, V-D10, V-D12 … V-D20 (Appendix C): the builder recipe and image in A and B; the variation matrix; AGP alignment and `vcsInfo`; apksigner `--alignment-preserved` and the core relation with a software key; symbols and build-id; hosted-runner capacity; h2c on nginx; installer and rotation on local emulators; CycloneDX determinism; R8 and JDK pins; relay and issuer binaries; certificate validity; APK v3 parse against `apksigner verify --print-certs`; ADR-48 … ADR-52 filed as "propus" | — | Appendix C updated with each result; any failed check re-plans its slice before S1 |
| **S0b** Spikes that need the owner | V-D6 (PKCS#11 ECDSA on a YubiKey with `apksigner`), V-D7 (Ed25519 statement signing on the token; the message limit), V-D8 (SLIP-39 split and restore, re-import), V-D11 (Sigsum submission over Tor with the domain token; the policy's exact witnesses and quorum; vectors); the signer host prepared | tokens (OA-1), signer laptop (OA-2), domain (OA-4) | Appendix C updated; **gates only the checklist items 6–8 (§13.3), never S1 … S10** |
| **S1** Formats and decision | `ghost-client-update`: §4 parsers and encoders, §7.4 decision, chain rule, bucket, `GHRA`, APK parse and core hash; vectors; properties; fuzz targets; JVM replay | S0a | `rust` green; vectors replayed on the JVM |
| **S2** `ghost-release-ops` | root and manifest building with every release-time refusal (counter, ES horizon, slot retirement warning), statements, signature attachment, `apk-core`, `proof-assemble`, `bundle`, `sbom`, `sums-compare`, `verify`; report vocabulary; runbook drafts RK0 … RK6, R-P, R-R | S1 | tool tests green; a full stagenet release rehearsed with software test keys |
| **S3** Builder and two environments | `infra/builder`, `build-release.sh`, the symbol split, `vcsInfo` off, the release counter, the aapt2 and JDK pins, G-D2, G-D3, G-D8, `release-build.yml` | S0a | `release-build.yml` green on a test tag: A = B |
| **S4** Native fetch and JNI | `mirror.rs`, `UpdateNative`, `TorMirrorTransport`, handle registry, G-D5, G-D6, host-library exports | S1 | `rust` and `android-native` green; a live fetch from a staging mirror (manual `live-tor` job) |
| **S5** Android | `:sync` update runs (§9.4); migration U; `:update` engine, stager, installer port, facade; bootstrap and manifest directory (§7.8); T15/T15m changes | S4 (S5 can start on S1's facade with a fake) | JVM tests green; `sync-exit-gate` unchanged green |
| **S6** Update world | `UpdateWorld`, hostile mirrors, recording installer, crash enumeration, NI-U1 … NI-U4, the 31 mutants, `update-exit-gate.yml`, G-D7 | S5 | the gate job green |
| **S7** Log, verifier, monitor | Sigsum submission procedure (R-P), `proof-assemble` on real proofs, `ghost-verify` (apk, fetch, operator, monitor) in the public repository's layout, the release record layout | S2, S0b (V-D11) | `ghost-verify` verifies a real stagenet release offline and over Tor |
| **S8** Infrastructure | `infra/mirror` (torrc, server, compose, runbook), two staging mirrors deployed (owner), `Dockerfile.release` for relay and issuer from released binaries | S0a (V-D12), S3 | both mirrors serve a bundle over Tor; an operator check with `ghost-verify operator` |
| **S9** Drills | RK0 on stagenet with the real tokens; RK1 releases; RK2, RK3, RK5; the emulator suite (local run recorded until a KVM runner); the live tamper and downgrade drill on a phone; rollout and halt; the closing tag through `release-build.yml` | S2 … S8, S0b | signed records; §11.5 table complete |
| **S10** Documents and review | Appendix B applied; an adversarial review in three lenses (cryptography and formats; privacy; supply chain and operations), its corrections recorded as §18 "Normative corrections" | S9 | §13.3 checklist |
| S-store (not in Phase 14) | Accrescent flavor, AAB and APK-set reproducibility, split signing | §8.2 entry conditions | — |

### 13.2 Effort

**Team model (the plan's team of 5–6, §6.4 plan:341: lead, two Android, one Rust, one part-time Rust, QA, SRE).**

| Slice | Person-weeks | Who |
|---|---|---|
| S0a | 1.5 | SRE 1, Rust 0.5 |
| S0b | 0.5 (+ owner time; calendar-bound by deliveries) | SRE, owner |
| S1 | 2.0 | Rust |
| S2 | 1.5 | part-time Rust, lead |
| S3 | 2.5 | SRE |
| S4 | 1.5 | Rust 1, Android 0.5 |
| S5 | 3.0 | Android 2 |
| S6 | 2.5 | QA, Android |
| S7 | 1.5 | part-time Rust, lead |
| S8 | 1.0 | SRE |
| S9 | 1.5 | QA, owner |
| S10 | 1.5 | lead |
| **Total** | **≈ 20.5 person-weeks** | |

With four engineers in parallel (S1 ∥ S3 ∥ S0b; S5 starting on a faked facade; S6 built during S5; S7 ∥ S8), the critical path S0a → S1 → S4 → S5 → S6 → S9 → S10 is **about 6–7 calendar weeks**, not the plan's 3–4 (X-D7, Q35). The part most likely to slip is S3: a cross-environment difference in R8 or Kotlin output has no known fix until it is seen (R-D1).

**Calibration on observed pace.** Phase 9's slices landed in about nine calendar days of parallel agent sessions against a 10–12-week estimate, while its gate evidence did not finish (F11 §17.2, STATUS:18). The same pattern is expected here: **implementation ≈ 25–35 agent-days (2–3 calendar weeks of parallel sessions)**, and the gate **waits on owner actions** — tokens and the signer laptop (OA-1, OA-2), the domain and the Sigsum token (OA-4), the hosted-runner minutes (OA-5), a KVM runner or recorded local emulator runs, a phone, the second staging mirror host — after which one to two weeks of drills and fix rounds.

### 13.3 Exit-gate checklist (all on the closing commit)

1. S0a's and S0b's V-D results recorded in Appendix C; no open fallback.
2. `rust`, `android`, `android-native`, `static-gates`, `reproducible` green **on a runner**.
3. `update-exit-gate`: the world at gate scale, `update mutants: 31 run, 31 detected`, NI-U1 … NI-U4 equal, crash enumeration; G-D7 passes.
4. `release-build.yml` green on the closing tag: A = B for every output of §6.1 (G-D3).
5. `update-emulator.yml` green on API 29, 33, 37 on a runner, or a signed local run of the same scripts recorded as such (tamper, downgrade, lineage).
6. RK0 (stagenet) done with the real tokens and a witness; the stagenet root, certificate and mirror list committed; G-D4 green.
7. Rotation drill on stagenet with the real tokens: RK2 (release key, root key, witness set, attestation key), RK3 (lineage), RK4 (revocation and floor), RK5 (restore from three shares); signed records.
8. Live tamper and downgrade drill: a phone, the two staging mirrors over Tor, the real log, a tampered bundle and an old APK refused; signed record.
9. Rollout rehearsal: 50 → 250 → 1000, a halt, a roll-forward release.
10. Appendix B applied (INVARIANTS T48–T52 and the changes; THREAT_MODEL; LIMITE L10; plan errata; ADR errata of B.5; STATUS; ADR index); ADR-48 … ADR-52 decided or applied under the default rule.
11. The review's findings corrected or recorded as owner decisions.
12. No UI claim (CP-10); STATUS says what ran where.
— **Release gates (not phase gates):** the auditor's attestation with `attest.t ≥ 1` on the release network; the mainnet RK0 and the production log policy; a second, independent mirror operator; the Android developer verification decision (Q18); counsel's items (§16); the licence screen (Phase 13); `ghost-verify` published in the public repository.

---

## 14. Risks

| ID | Risk | Likelihood / impact | Mitigation |
|---|---|---|---|
| R-D1 | A cross-environment difference (R8, Kotlin, AGP, file order) that pins cannot remove | medium / high (the gate) | the variation matrix first (S0a); fixed CPUs and tmpfs; diffoscope classes; report upstream; never relax the gate to "equivalent" |
| R-D2 | The hosted runner (2 CPU, 8 GB, 14 GB) cannot hold the build | medium / medium | disk cleanup; V-D10 measures; fallback: a second owner machine that runs no CI (Q11) |
| R-D3 | Ed25519 signing on the YubiKey through PKCS#11 fails, or its message limit is lower than reported | medium / low | short statements (≤ 61 B); `yubico-piv-tool`; fallback: encrypted software seeds on the air-gapped host |
| R-D4 | `--alignment-preserved` still changes bytes, so `core(signed) ≠ unsigned` | low / high | V-D5 first; fallback: zip-align in the build (part of the reproduced output) and sign preserved; or F-Droid's signature-copy check |
| R-D5 | No domain for the Sigsum rate-limit token (owner declines) | medium / medium | ask the log operators for another arrangement; else Rekor or a GHOST log with recruited witnesses (Q5), weaker |
| R-D6 | Android developer verification (2027) forces the advanced flow on users of an unregistered GHOST, or registration links the owner's identity | high / high | Q18 before the beta, with counsel; keep `K-APK` backed up; GrapheneOS and non-certified systems outside its stated scope |
| R-D7 | Accrescent stays closed, so GrapheneOS users have no store route | high / low | the mirror and `ghost-verify` work there; S-store kept ready |
| R-D8 | `K-APK` lost with its shares | low / critical | 3-of-5 SLIP-39 in five places; yearly RK5 |
| R-D9 | A missed heartbeat leaves every client STALE | medium / medium | heartbeat at each K1 (calendar), 91-day window, Phase 13 warns at expiry only |
| R-D10 | Mainnet releases depend on the auditor's availability (`attest.t ≥ 1`) | medium / medium | two attesters in the root when possible; an RK2 path that lowers the threshold publicly (logged) |
| R-D11 | Releases that change the schema or the ES cannot be rolled back | certain / medium | roll-forward; longer 5 % stage for such releases (Q30) |
| R-D12 | A bug in the custom formats or the APK parse (a CP-09 exception) | medium / high | vectors, independent JVM replay, sigsum-go vectors, crafted APKs, fuzzing, the Phase 15 audit |
| R-D13 | APK downloads over Tor are slow or break | medium / low | 4 MiB resumable ranges across update runs; user-initiated foreground download |
| R-D14 | Users skip `ghost-verify` for first installs | high / medium | declared (L10-D1); fingerprints in three places; Phase 13 copy |
| R-D15 | The witnesses of the default policy are not independent of each other | certain / medium | declared (L10-D6); adopt a more diverse named policy when Glasklar publishes one |
| R-D16 | A solo owner's ceremony load (heartbeats, releases, drills) | medium / medium | the 91-day window; ceremonies scripted with expected outputs; the second party only for RK0, RK2, RK3 |
| R-D17 | Changing `applicationId` late costs every user a reinstall | low (if Q3 decided now) / high | Q3 before the first distribution |

---

## 15. Owner questions (the proposed default applies unless the owner objects)

| # | Question | Proposed default | Pe scurt (RO) |
|---|---|---|---|
| Q1 | Approve ADR-48 … ADR-52 (Appendix A) as "propus, aplicat"? | **yes** | Aprobarea ADR-48 … ADR-52 |
| Q2 | Channels in Phase 14: onion mirror only (built); Accrescent deferred behind the §8.2 conditions; no F-Droid-format repository; no Google Play? | **yes** | Doar mirror-ul onion acum; Accrescent când se poate; fără depozit F-Droid și fără Google Play |
| Q3 | Fix the final `applicationId` before the first distributed APK, under a domain the project controls (with Q4), rather than keep `org.ghost.app`? | **yes, change it now**; if Q4 is "no", keep `org.ghost.app` and accept that Accrescent is impossible | Alegem acum identificatorul definitiv al aplicației, sub un domeniu al proiectului |
| Q4 | Register a project DNS domain, used only for the Sigsum rate-limit TXT record (and, later, Accrescent's check); never contacted by the app? | **yes** (privacy-preserving registrar; OA-4) | Un domeniu al proiectului, doar pentru înregistrarea în jurnal; aplicația nu îl contactează niciodată |
| Q5 | Transparency log: Sigsum public logs with the named policy (two logs, three witnesses with one parent company, declared), rather than Rekor v2 (no cosigning at GA) or a GHOST-run log? | **Sigsum** | Jurnalul public Sigsum, cu martorii lui; limita declarată |
| Q6 | Keys: `K-APK` ECDSA P-256 imported into two YubiKeys (5.7+) with SLIP-39 3-of-5 shares; release keys Ed25519 on the tokens, 1 of 2; root 2 of 3 with one key at a second party; or RSA-4096 for `K-APK`, or a YubiHSM 2? | **P-256, YubiKeys, SLIP-39** | Cheia Android P-256 pe două YubiKey, cu backup în 5 părți (oricare 3) |
| Q7 | Who is the second party (witness at RK0, holder of `K-ROOT3`)? Until named, all three root keys stay with the owner in separate places (no multi-party yet, declared)? | **the owner names one before RK0 on mainnet; stagenet may proceed without** | Cine e a doua persoană pentru cheia rădăcină 3 și ceremonia inițială |
| Q8 | Manifest expiry 91 days with a heartbeat at each quarterly K1, or 42 days with monthly ceremonies (tighter freeze bound)? | **91 days** | Manifestul expiră după 91 de zile; îl re-semnăm trimestrial |
| Q9 | Android-key rotation target: `--rotation-min-sdk-version` 33 (API 29–32 keep the old key after a rotation, L10-D3) or 28 (rotation on Android 9–12, "not recommended" there); and keep `minSdk` 29 or raise it to 33 before the first release? | **33; keep `minSdk` 29; revisit at Phase 16** | Rotația cheii Android protejează doar Android 13+; păstrăm minSdk 29 |
| Q10 | Attestation-bound updates: the updater requires the root's attestation threshold of independent builders over the unsigned core (0 on stagenet until an auditor exists; ≥ 1 on mainnet)? | **yes** | Actualizatorul cere atestarea build-ului de către un auditor (pe mainnet) |
| Q11 | Environment B = a GitHub-hosted `ubuntu-24.04` runner (free minutes; S0a measures capacity), fallback a second owner machine that runs no CI? | **hosted runner** | Al doilea mediu de build: un runner GitHub găzduit |
| Q12 | Builder base: Debian 12 bookworm (as the relay and issuer images) or Debian 13 trixie? | **bookworm** | Imaginea de build pe Debian 12, ca releele |
| Q13 | `vcsInfo` off (the commit bound by the logged manifest; escrow tarballs reproduce)? | **yes** | Fără informația git în APK; commit-ul e legat prin manifestul din jurnal |
| Q14 | Symbol files with line tables only (function names and lines), or full debug info (larger, longer builds)? | **line tables** | Fișiere de simboluri cu nume de funcții și linii |
| Q15 | Update runs: 1 in 24 of the periodic runs that are not quiet runs, two mirrors per run? | **yes** | Verificarea actualizărilor la momente aleatoare, din două mirror-uri |
| Q16 | No silent updates: every install confirmed by the user (no `UPDATE_PACKAGES_WITHOUT_USER_ACTION`)? | **yes** (Phase 13 may revisit) | Fiecare actualizare se confirmă de utilizator |
| Q17 | Download the offered APK in update runs (background, resumable), install only on user confirmation? | **yes** | Descărcarea în fundal; instalarea doar cu confirmare |
| Q18 | Android developer verification: no registration in Phase 14; decide before the beta with counsel (registration = legal identity at Google; none = advanced flow for users of certified devices from 2027); consider the ≤ 20-device limited-distribution account for the alpha? | **no registration now; decide before Phase 17** | Înregistrarea la Google: decizie înaintea beta, cu avocatul |
| Q19 | First install: onion mirror (Tor Browser) or any channel, checked with `ghost-verify`; no clearnet mirror? | **yes** | Prima instalare din mirror-ul onion sau de oriunde, verificată cu verificatorul public; fără mirror pe clearnet |
| Q20 | Mirror server: nginx if HTTP/2 prior knowledge works (V-D12), else `ghost-mirror`? | **yes** | Serverul mirror-ului: nginx sau unul propriu, minimal |
| Q21 | A second mirror operator (for example a relay operator, separate onion) before production; staging with two owner mirrors meanwhile (declared)? | **yes** | Un al doilea operator de mirror înainte de producție |
| Q22 | Gradle dependency signature verification (`verify-signatures=true` with a committed keyring), decided by S0a's count of artifacts without signatures? | **on, if S0a finds the keyring maintainable** | Verificarea semnăturilor dependențelor Gradle, dacă e întreținabilă |
| Q23 | `cargo-vet`? | **no** (cargo-deny, cargo-audit, pins, SBOM) | Fără cargo-vet |
| Q24 | Releases only from tags signed with a hardware-backed key (FIDO2 SSH); commit signing on `main` recommended, gated once the owner's keys are set? | **yes** | Versiunile doar din tag-uri semnate cu cheie hardware |
| Q25 | Keep the schedule key separate from the release keys (same custody), not have the release key sign the ES? | **separate** | Cheia programului rămâne separată |
| Q26 | Accrescent: build the store flavor, AAB and APK-set tooling now (≈ +1 week), or when §8.2's conditions hold? | **when the conditions hold** | Varianta pentru Accrescent o construim doar când ne acceptă |
| Q27 | A public monitor run weekly by the owner, with published output, and the same tool for anyone? | **yes** | Un monitor public al jurnalului, rulat săptămânal |
| Q28 | Publish `ghost-client-update` and `ghost-verify` in the public repository under a permissive licence (`MIT OR Apache-2.0`), as the open verifier needs? | **yes** | Codul verificatorului e public, cu licență permisivă |
| Q29 | An expired manifest makes the channel STALE, not the app unusable? | **yes** | Un manifest expirat nu blochează aplicația |
| Q30 | Roll-forward only; releases that change the schema or the ES stay at 5 % for at least 7 days? | **yes** | Revenirea se face doar înainte; versiunile cu schimbări de schemă stau mai mult la 5 % |
| Q31 | The rollout bucket per release, from a per-install secret that never leaves the device? | **yes** | Treapta de lansare se trage local, per versiune |
| Q32 | Buy the hardware: at least four YubiKey 5 (firmware ≥ 5.7) per network, a dedicated offline laptop, metal plates for the shares? | **yes** (OA-1, OA-2) | Cumpărăm cheile hardware și laptopul offline |
| Q33 | APK Signature Scheme v3.2 (ML-DSA hybrid, Android 17+): not in P0; revisit when a token signs ML-DSA and the tooling is stable? | **defer** | Semnătura post-cuantică a APK-ului: mai târziu |
| Q34 | Schema migration numbers by merge order (Phase 14's U is the next free number), overriding F11's reservation? | **yes** | Numărul migrației se stabilește la merge |
| Q35 | Amend plan row 14 to 6–7 calendar weeks for a team of 5–6 (≈ 21 person-weeks), with the gate's owner-dependent items listed? | **yes** | Faza 14 durează realist 6–7 săptămâni |
| Q36 | The first accepted manifest takes the relay directory over and may withdraw any relay, bootstrap ones included (an availability lever for a stolen release key, logged), or may manifests never retire the bootstrap (`config`) entries (a hostile bootstrap relay then needs an app release)? The ES stays without a network path either way | **the manifest takes over** | Manifestul preia directorul de relee și poate retrage orice releu; ES-ul rămâne în aplicație |

---

## 16. Owner actions and legal items (not code)

| ID | Action | Before |
|---|---|---|
| OA-1 | Buy ≥ 4 YubiKey 5 (firmware ≥ 5.7) per network; set PINs and management keys at RK0 | S0b |
| OA-2 | A dedicated laptop for the signer host; radios disabled; the verified Debian live image | S0b |
| OA-3 | Name the second party (Q7) and the five share custodians | RK0 (stagenet may proceed with the owner and one witness) |
| OA-4 | Register the project domain (Q4) with a privacy-preserving registrar; publish `_sigsum_v1` | S0b (V-D11) |
| OA-5 | Allow the hosted-runner minutes for `release-build.yml` (GitHub Free includes 2 000/month for private repositories) | S3 |
| OA-6 | Host the second staging mirror (any machine with Tor); later a second operator for production (Q21) | S8 |
| OA-7 | Configure the hardware-backed git signing key and the allowed-signers file (closes STATUS:25's gap for tags) | the first signed tag (S3) |
| OA-8 | If Accrescent is wanted: request allowlisting of the GitHub account | S-store |
| OA-9 | Engage the auditor for T12b (Phase 15) and agree the attestation format and publication | the first mainnet release |
| OA-10 | Source escrow agent and public release conditions (ADR-38 point 10) | the first distribution |

| ID | Legal or consulting item (counsel; engineering readings only here) |
|---|---|
| LG-1 | Android developer verification: registering (identity, package, certificate) versus not, and its terms (Q18) |
| LG-2 | Export-control classification of an encrypted messenger distributed from the EU (for example the mass-market treatment of encryption items in the EU dual-use regulation) — counsel's reading, none given here |
| LG-3 | The name "GHOST" and the `org.ghost` namespace against existing marks and projects (ghost.org); the final application id (Q3) |
| LG-4 | Distribution terms: a licence for end users of a proprietary APK; terms for relay operators who receive `ghost-relay` (ADR-37 point 6) |
| LG-5 | Third-party notices and the MPL source offer on the mirrors (ADR-37 points 2, 10), with the public-history question already open |
| LG-6 | Auditor contract: publication rights for attestations and reports; escrow agreement |
| LG-7 | A privacy notice for the distribution channel (no logs at mirrors; what Google may receive on GMS devices) |

---

## 17. Findings outside Phase 14 (proposed as separate tasks)

- **F-D1.** GHES v1 signs its whole body (`schedule.rs:282-284`), so `K-SCHED` cannot live on a token whose Ed25519 messages are limited; a GHES v2 that signs `SHA-256(body)` under a domain prefix would let the mainnet K1 use hardware. Before the mainnet K1 (Phase 16/17).
- **F-D2.** FR-8 citation errata in ADR-37 point 8, ADR-38's header and F9 §2.10.6 (§1.4 item 1; Appendix B.5).
- **F-D3.** No production code fills `relay_directory` (only tests call `RelayDirectory.upsert`); an installed app has no relay until §7.8's bootstrap lands. In this phase (S5); recorded because Phases 9–11 assumed a filled directory.
- **F-D4.** CI's JDK patch level is unpinned (`ci.yml:306,391,465`), which matters to every JVM-side reproducibility claim; fixed for the release path by G-D2, and should be fixed in every job.
- **F-D5.** `verification-metadata.xml:8` trusts the `aapt2` jars without checksums; fixed by G-D8 here, but it affects every Android job today.
- **F-D6.** The relay staging compose builds the relay from source (`infra/relay/docker-compose.staging.yml`), which independent closed-source operators cannot do; S8 adds the released-binary image.
- **F-D7.** Phase 12 must embed a default bridge set in the APK: a manifest cannot be fetched while Tor is blocked.
- **F-D8.** Phase 13: the update screens, the "Install unknown apps" prompt, the STALE, CONFLICT and UNSUPPORTED alarms, the copy of §2.6 and L10, and the Play Protect disclosure.

---

## Appendix A: ADR drafts (Romanian)

Numerele încep la ADR-48: designul Fazei 10 folosește ADR-40 … ADR-43, iar designul Fazei 11 ADR-44 … ADR-47 (ADR-21 rămâne rezervat). Toate cinci sunt **propuse** 2026-10-03 și devin „propus, aplicat” la aprobarea designului (Q1).

> # ADR-48 — Cheile distribuției: roluri, custodie hardware, ceremonii, rădăcina de încredere
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-10-03 (designul Fazei 14, `docs/design/faza14-distribution.md` §3, §4.3) |
> | Sursă | FR-8.2 (spec p.11: chei offline/HSM, acces multi-parte, rotație documentată; „Key compromise and rotation drill completed”); spec §12.1 („separate signing and secrets” pentru staging), §12.3; R-11; THREAT_MODEL A7, AS-10, TB-6 și tabelul cheilor; ceremonia K1 a Fazei 8 |
> | Modifică | THREAT_MODEL (AS-10 se împarte în AS-10a … AS-10i; A7, TB-6 și rândul „Cheie release”); FR-8.2 (accesul multi-parte se aplică rădăcinii și recuperării, nu fiecărei versiuni: abaterea X-D5); practica K1 (două persoane la geneză și la schimbarea rădăcinii, nu la fiecare versiune: X-D16) |
>
> ## Context
> Semnătura APK-ului (identitatea Android a aplicației) nu poate fi Ed25519, iar o cheie Android pierdută nu se mai poate roti: rotația v3 cere semnătura cheii vechi, deci pierderea ei înseamnă o aplicație nouă, reinstalată de fiecare utilizator, cu datele locale pierdute. O singură cheie de manifest fixată în aplicație ar lăsa actualizatorul fără cale de recuperare la pierderea ei. Proprietarul e o singură persoană: ceremoniile trebuie să poată fi făcute de el, iar încrederea în rădăcină nu trebuie să depindă doar de el.
>
> ## Decizie
> 1. **Roluri.** `K-APK` (ECDSA P-256, certificat autosemnat cu subiectul `CN=GHOST`, fără nume personal; octeții certificatului fac parte din identitate și se comit), câte una per rețea; `K-REL1`, `K-REL2` (Ed25519, prag 1 din 2) semnează manifestele și frunzele de jurnal; `K-ROOT1…3` (Ed25519, prag 2 din 3) semnează rădăcina; `K-ATT-*` (Ed25519) sunt cheile constructorilor independenți (auditori); `K-SCHED` își păstrează rolul (ES); `K-TAG` semnează tag-urile de versiune.
> 2. **Rădăcina de încredere** e un document versionat (`GHRT`, §4.3 al designului) care listează cheile de rădăcină, de versiune, de atestare, amprentele certificatelor Android admise, jurnalele și martorii cu pragul lor. Versiunea n + 1 e valabilă doar semnată de pragul cheilor versiunii n **și** de pragul cheilor versiunii n + 1 (regula TUF), și doar cu dovada includerii ei în jurnalul politicii versiunii n (o înlocuire țintită a rădăcinii devine publică înainte de adoptare). Ancora e cea mai nouă rădăcină inclusă în biblioteca nativă a versiunii instalate.
> 3. **Custodie.** Chei hardware YubiKey 5 cu firmware ≥ 5.7 (PIV Ed25519), PIN și atingere obligatorii. `K-APK` se generează pe stația offline, se importă în două chei hardware și se împarte prin SLIP-39 în 5 părți (oricare 3 o refac), păstrate separat; cheile de versiune se generează direct pe chei hardware (pierderea lor se rezolvă printr-o rădăcină nouă); `K-ROOT2` există doar ca părți SLIP-39; `K-ROOT3` o ține o a doua persoană.
> 4. **Stația de semnare** e un laptop dedicat, fără rețea, pornit dintr-o imagine Debian live verificată și protejată la scriere; uneltele ajung pe un mediu separat, verificate față de sumele celor două medii de build.
> 5. **Mesaje scurte.** Orice semnătură GHOST e Ed25519 peste `"ghost/v1/<tip>" ‖ 0x00 ‖ rețea ‖ SHA-256(corp)` (cel mult 61 de octeți), ca o cheie hardware să poată semna orice document.
> 6. **Ceremonii** (runbook-ul `ghost/infra/release/RUNBOOK.md`): RK0 geneza (două persoane), RK1 versiunea (proprietarul), RK2 schimbarea rădăcinii (pragul de rădăcină, cu a doua persoană), RK3 rotația cheii Android (linie v3.1, capacitatea `rollback` a cheii vechi oprită), RK4 răspunsul la compromitere, RK5 exercițiul anual de restaurare din părți, RK6 re-semnarea periodică a manifestului.
> 7. **Rețele separate.** Stagenet și mainnet au rădăcini și chei Android diferite; versiunile stagenet poartă sufixul `.stagenet` al identificatorului aplicației. Faza 14 face geneza doar pentru stagenet; mainnet urmează ceremonia K1 reală (Faza 16/17).
> 8. **Nicio cheie de semnare în depozit, în CI sau pe un mirror** (poarta G-D1).
>
> ## Consecințe
> (+) Pierderea oricărei chei hardware, a oricărei chei de rădăcină sau a cheilor de versiune nu schimbă identitatea aplicației; cheia Android supraviețuiește pierderii ambelor chei hardware prin părțile ei; orice document se semnează pe hardware. (−) Patru chei hardware per rețea și un laptop dedicat; o a doua persoană pentru rădăcină; semnarea fiecărei versiuni rămâne la o singură persoană (compensată de jurnalul public); după o rotație țintită la API 33, dispozitivele cu Android 10–12 acceptă în continuare cheia veche (L10-D3); pierderea tuturor celor trei chei de rădăcină cere o instalare manuală (L10-D13).
>
> ## Alternative respinse
> Ed25519 pentru APK (Android nu îl acceptă); RSA-4096 pentru APK (valid, mai lent pe cheia hardware; alternativă înregistrată, Q6); generarea cheii Android pe cheia hardware, fără backup; KMS în cloud (online, legat de identitate, clearnet); o cheie de manifest fixată fără rădăcină; semnături prag FROST (fără suport hardware); două persoane la fiecare versiune (de neoperat pentru un proprietar singur).
>
> ## Teste
> Vectorii rădăcinii și ai regulii de lanț; exercițiile de rotație (cheie de versiune, cheie de rădăcină, martori, cheie de atestare, cheie Android cu linie v3.1 pe emulator API 29, 33, 37); RK5 cu restaurare reală din părți; poarta G-D1 cu fixture-uri negative; mutanții MC-D1 … MC-D4, MC-D18, MC-D23.

> # ADR-49 — Manifestul semnat, jurnalul de transparență binară și actualizările legate de atestări
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-10-03 (designul Fazei 14, §4, §5, §7.4) |
> | Sursă | CP-08; FR-7.5; spec §12.2 pașii 1–4; ADR-38 punctele 5, 6, 9, 10; ADR-22 (consecința „consistența cheilor față de o cheie de release compromisă”); designul Fazei 8 §18 F6 |
> | Modifică | Spec §12.2 pasul 2 („release-registry commitment”, un registru pe lanț eliminat de ADR-02): devine jurnalul de transparență (X-D3); INVARIANTS T12 (T12b primește mecanismul) |
>
> ## Context
> ADR-38 (aprobat) cere ca actualizatorul să refuze un APK fără dovadă de includere și checkpoint cosemnat, iar ADR-22 lasă deschisă consistența ES-ului față de o cheie de release compromisă. Cu sursă închisă, furnizorul (AD-V) poate semna orice: o versiune țintită trebuie să devină publică, iar reproducerea de către auditor trebuie să fie verificată de aplicație, nu doar declarată.
>
> ## Decizie
> 1. **Formate binare canonice** (în stilul ES-ului): rădăcina `GHRT`, lanțul `GHRC`, manifestul `GHRM`, declarația de atestare `GHRA`, dovada de jurnal `GHRP` și pachetul `GHRB` servit de mirror-uri; fără JSON, fără octeți la final, liste strict ordonate, limite de dimensiune fixate înainte de citire.
> 2. **Manifestul** (cel mult 64 KiB) are secvență, rădăcina sub care e semnat (versiune și hash), zi de emitere și de expirare (cel mult 91 de zile), versiunea minimă suportată, cel mult 4 versiuni (cu APK-ul semnat, nucleul nesemnat, artefactele, commit-ul, ES-ul încorporat și atestările), mirror-urile (cel puțin două, de doi operatori) și releele. Nimic per client, niciun timp mai fin decât ziua.
> 3. **Jurnal Sigsum** (protocolul de jurnal v1, stabil): fiecare manifest e o frunză (`mesaj = SHA-256(manifest)`) semnată cu o cheie de versiune; fiecare rădăcină nouă e și ea o frunză, înregistrată sub politica rădăcinii anterioare, iar clientul o adoptă doar cu dovada ei (o înlocuire țintită a rădăcinii, cu un jurnal și martori ai atacatorului, devine astfel publică înainte de adoptare); politica (jurnale, martori, cvorum) stă în rădăcină, preluată din politica numită `sigsum-generic-2025-1`; martorii ei au aceeași companie-mamă, limită declarată (L10-D6). Clienții nu contactează niciodată jurnalul: mirror-urile servesc dovada, verificată offline; cosemnăturile nu expiră.
> 4. **Actualizări legate de atestări.** Aplicația găsește blocul de semnătură al APK-ului exact cum îl găsește Android (sfârșitul directorului central, offsetul lui, blocul dinaintea lui), calculează nucleul nesemnat și cere ca el să fie build-ul atestat de pragul de constructori independenți din rădăcină (0 pe stagenet până există un auditor; cel puțin 1 pe mainnet).
> 5. **ES-ul** rămâne fără cale de rețea (ADR-22); fiecare versiune înregistrează `es_seq` și `es_sha256`, iar monitorul public verifică regula 5 între versiunile din jurnal (închide F6).
> 6. **Registrul versiunii** (manifeste, dovezi, APK-uri, simboluri, SBOM-uri, notificări, sursele MPL, fișierele ES, binarul `ghost-relay`, atestările, hash-ul escrow) se publică în arhiva mirror-urilor, legat prin hash de manifestele din jurnal; un monitor public (`ghost-verify monitor`) îl verifică săptămânal.
> 7. **Excepție CP-09 înregistrată:** formatele, regula de lanț, verificarea dovezii Sigsum și parcurgerea APK-ului sunt cod GHOST peste primitive standard (Ed25519, SHA-256, arbori RFC 6962), cu vectori (inclusiv vectori generați cu sigsum-go), o implementare JVM independentă de test, fuzzing și auditul Fazei 15.
>
> ## Consecințe
> (+) Un build țintit sau rău-intenționat ajunge la actualizator doar după ce apare într-un jurnal public cosemnat și (pe mainnet) după atestarea unui auditor; toți utilizatorii primesc același manifest; ES-ul devine verificabil între versiuni. (−) Publicarea cere un domeniu DNS pentru limitarea Sigsum (folosit doar de proprietar); un jurnal oprit blochează publicarea unor versiuni noi, nu clienții, iar o schimbare a rădăcinii cere un jurnal activ al politicii anterioare (L10-D17); versiunile mainnet depind de disponibilitatea auditorului; prima instalare, magazinele și binarele operatorilor rămân în afara verificării actualizatorului (L10-D1, L10-D2, L10-D15).
>
> ## Alternative respinse
> TUF prin `tough` (aduce `aws-lc-rs`, cod C, în APK; JSON; rol de timestamp cu cheie online); Rekor v2 (fără cosemnare la GA; instanțe anuale); un jurnal rulat de GHOST (operatorul ar fi furnizorul); a crede declarația cheii de versiune despre build; atestări din runner-ul GitHub (fără chei în CI; atestările GitHub cer Enterprise Cloud pentru un depozit privat).
>
> ## Teste
> Invarianții T48 și T49; vectorii `release_*.txt` cu fiecare octet modificat; suita APK-urilor fabricate; lista atacurilor TUF ca teste; vectorii sigsum-go; lumea de actualizare cu mirror-uri ostile; mutanții MC-D1 … MC-D15, MC-D20, MC-D21, MC-D23; exercițiul live de alterare pe stagenet.

> # ADR-50 — Build reproductibil din două medii: rețeta cu căi fixe, setul de artefacte, simboluri și SBOM
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-10-03 (designul Fazei 14, §6) |
> | Sursă | Plan §6.2 rândul 14 („hash identic din două medii”); FR-8.1; FR-8.9; ADR-07; ADR-19 (builder-ul cu căi fixe e lucrul Fazei 14); ADR-37 punctele 3, 8; ADR-38 punctele 5, 9; INVARIANTS T12; LIMITE L5 |
> | Modifică | T12 (identitatea între medii devine executabilă); `ghost/Cargo.toml` (profilul release: informații de linie, separare și eliminare după legare, build-id; X-D15); `app/build.gradle.kts` (`vcsInfo` oprit, contorul de versiune comis; X-D14); `ci.yml` (JDK fixat la patch) |
>
> ## Context
> T12 dovedește azi doar determinismul la aceeași cale: pe Windows căile păstrează `\`, iar cargo include flag-urile de remapare în numele directoarelor de build-script. `trim-paths` nu e stabil pe Rust 1.98.1. FR-8.9 cere două medii independente, unul al unui auditor; până la audit, poarta fazei folosește două medii ale furnizorului.
>
> ## Decizie
> 1. **O singură rețetă** (`ghost/infra/builder/Dockerfile` și `pins.txt`): imaginea de bază prin digest, pachetele apt dintr-un instantaneu `snapshot.debian.org`, Temurin 17 cu patch fixat, SDK-ul și NDK-ul Android, Rust 1.98.1 cu țintele lui, cargo-ndk 4.1.2, protoc 36.1, Gradle 9.7.1, dependențele prin `Cargo.lock` și `verification-metadata.xml` (inclusiv aapt2, azi fără sumă); poarta G-D2 cere ca restul depozitului să fie de acord cu `pins.txt`.
> 2. **Build-ul** rulează în container, dintr-un checkout git al unui tag semnat, clonat într-un tmpfs, la căi fixe, cu 4 procesoare fixate, `TZ=UTC`, `LANG=C.UTF-8`, `umask 022`.
> 3. **Ieșirile** (`SHA256SUMS`): APK-ul nesemnat aliniat, bibliotecile native fără simboluri (cu build-id SHA-1) și fișierele lor de simboluri cu informații de linie, `ghost-relay`, `ghost-issuer`, `ghost-issuer-ops`, `ghost-release-ops`, notificările, SBOM-urile CycloneDX 1.7 deterministe, rețeta.
> 4. **Două medii la fiecare versiune:** stația proprietarului (A) și un runner GitHub găzduit `ubuntu-24.04` (B); sumele trebuie să fie egale înainte de semnare; un job săptămânal pe `main` prinde derivele. Mediul auditorului (C) e condiție de lansare.
> 5. **Semnarea păstrează nucleul:** `apksigner` din build-tools 37.0.0 cu `--alignment-preserved true`, v2 și v3, fără v1 și v4; `ghost-release-ops apk-core` refuză orice versiune la care nucleul APK-ului semnat diferă de APK-ul nesemnat reprodus.
> 6. **Matricea de variații** (cale, procesoare, ordinea fișierelor, dată, utilizator) rulează în S0a și apoi săptămânal; diferențele se clasifică cu diffoscope, doar în CI.
>
> ## Consecințe
> (+) „Hash identic din două medii” devine o poartă reală; auditorul primește o rețetă exactă; simbolurile și SBOM-urile sunt reproductibile și legate de versiune. (−) Un build în container durează mai mult; runner-ul găzduit privat are 2 procesoare, 8 GB și 14 GB; intrările fixate identice în ambele medii (SDK-ul Google, JDK-ul, toolchain-ul) nu sunt verificate de reproductibilitate (L10-D7); o diferență R8 neașteptată poate întârzia poarta (R-D1).
>
> ## Alternative respinse
> Build nativ pe Windows; `trim-paths` (nestabil pe 1.98.1); Nix (cost de învățare, tot binare Google); Guix (fără SDK Android); doar o imagine precompilată (nereproductibilă ea însăși); runner-ul self-hosted ca al doilea mediu (același laptop și aceeași mașină virtuală WSL2); `apksigcopier` (arhivat, GPLv3+); SPDX 2.3 (cere marcă de timp).
>
> ## Teste
> `release-build.yml` (A = B) pe tag-ul de închidere; matricea de variații; G-D2, G-D3, G-D8; `reproducible` (aceeași cale) păstrat; V-D1 … V-D5, V-D9, V-D10, V-D15 … V-D18.

> # ADR-51 — Actualizatorul din aplicație: rulări de actualizare, anti-rollback, lansare în trepte, instalare, directorul de relee
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-10-03 (designul Fazei 14, §7, §9, §10) |
> | Sursă | FR-7.5; spec §12.2 pașii 3–5; FR-8.8; C-07, C-12; §13.1 („missing release rollback”); ADR-01, ADR-06, ADR-19, ADR-20, ADR-22, ADR-23; INVARIANTS T6, T15, T19, T20, T23 |
> | Modifică | FR-7.5 („startup update checks”: verificări în rulări de actualizare independente de activitate, X-D1); spec §12.2 pasul 3 (fără retrogradare autorizată, X-D4); T15 (`REQUEST_INSTALL_PACKAGES`) și T15m (receptorul de stare al instalării; X-D8); ADR-19 (crate și clasă JNI noi, X-D9); disciplina T20 (fișierul APK în așteptare, X-D10); `:sync` (al treilea tip de rulare periodică); schema (migrația U); directorul de relee al Fazei 7 |
>
> ## Context
> O verificare la pornirea aplicației îi spune mirror-ului când e deschisă aplicația. Android refuză oricum un `versionCode` mai mic, iar o dezinstalare pierde datele locale. Directorul de relee e azi completat doar de teste. Lansarea în trepte nu poate folosi identificatori.
>
> ## Decizie
> 1. **Rulări de actualizare:** o rulare periodică care nu e liniștită devine, cu probabilitatea 1/24 trasă doar din cheia aleatoare a procesului și indicele rulării, o rulare de actualizare: fără sesiune cu relee, fără apel la issuer, un singur participant (motorul de actualizare), scopul de izolare `Update`. Citește pachetul de la două mirror-uri; nimic nu se citește la pornirea aplicației; o verificare cerută de utilizator e o excepție declarată.
> 2. **Cereri uniforme:** HTTP/2 în fluxul onion, căi fixe, fără `user-agent`, fără antete condiționale sau valori care diferă între clienți; APK-ul în intervale fixe de 4 MiB.
> 3. **Decizia** (în Rust, `ghost-client-update`): lanțul de rădăcini, semnătura manifestului, dovada de jurnal cu cvorumul de martori, timpul doar pe un ceas de încredere, perechea `(versiunea rădăcinii, secvența)` care nu scade; aceeași pereche cu alți octeți = conflict persistent.
> 4. **Anti-rollback:** nicio ofertă la sau sub `versionCode`-ul instalat; versiunea minimă poate doar să crească; sub ea, aplicația e „nesuportată”; fără retrogradare: revenirea se face înainte (sursa anterioară cu contorul următor), fiindcă schema și ES-ul nu se întorc.
> 5. **Lansare în trepte:** pragul per mie și sarea per versiune în manifest; treapta clientului = HMAC dintr-un secret local, per versiune, care nu părăsește dispozitivul; oprirea = prag 0.
> 6. **Instalare:** o sesiune `PackageInstaller` confirmată mereu de utilizator; octeții scriși în sesiune sunt exact octeții verificați, în aceeași trecere; fără actualizări silențioase; `REQUEST_INSTALL_PACKAGES` intră în allowlist-ul T15.
> 7. **Directorul de relee:** intrări inițiale compilate în biblioteca nativă (sursa `config`); primul manifest acceptat preia directorul, iar manifestele adaugă și retrag relee (inclusiv pe cele inițiale), ca un releu devenit ostil să fie scos fără o versiune nouă a aplicației; unealta de versiune refuză un manifest care omite un slot ES al săptămânii curente sau următoare fără o retragere declarată.
> 8. **Module:** crate-ul Rust pur `ghost-client-update`; preluarea în `client-core/net`; suprafața JNI închisă `UpdateNative` (poarta G-D5); modulul Kotlin `:update` cu o fațadă fără UI pentru Faza 13; migrația U (tabelele `upd_state`, `upd_staged`, cu triggere monotone, fără coloane de timp).
>
> ## Consecințe
> (+) Mirror-ul nu află nimic despre activitate; un mirror nu poate bloca clientul sub ce servește celălalt; anti-rollback-ul nu depinde doar de platformă; instalarea nu are fereastră între verificare și folosire. (−) Verificările sunt mai rare decât la fiecare pornire; un fișier APK stă pe disc până la instalare (L10-D16); utilizatorul trebuie să permită „Instalare aplicații necunoscute” (Faza 13); revenirea la o versiune anterioară e mereu o versiune nouă.
>
> ## Alternative respinse
> Verificare la pornire; verificări în rulările liniștite sau în sesiunile cu relee; retrogradare de urgență; grupuri de lansare alese de server; o treaptă fixă pe instalare; `ACTION_VIEW` pe un fișier; actualizări fără confirmare; verificarea în Kotlin; o a doua bibliotecă nativă.
>
> ## Teste
> Invarianții T48 … T51; lumea de actualizare (mirror-uri ostile, instalator care înregistrează, enumerarea crash-urilor); gemenii NI-U1 … NI-U4; mutanții PM-D1 … PM-D8, MC-D6 … MC-D8, MC-D16 … MC-D19, MC-D22; emulatorul API 29, 33, 37; exercițiul live.

> # ADR-52 — Canalele de distribuție și identitatea aplicației
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-10-03 (designul Fazei 14, §8) |
> | Sursă | FR-8.10; ADR-37 punctul 7; Q71 (valoarea implicită aplicată); ADR-07; documentația Accrescent, politica F-Droid, documentația Google despre semnarea Play, verificarea dezvoltatorilor Android și Play Protect (accesate 2026-10-03) |
> | Modifică | Plan rândul 14 („repo F-Droid/Accrescent”: decise, neconstruite în Faza 14, X-D6); ADR-37 punctul 7 (Accrescent amânat de condiții externe); spec §12.2 pasul 4 (APK doar din mirror-uri onion, X-D2); THREAT_MODEL S10 și LIMITE L4 („F-Droid repo” eliminat); identificatorul aplicației (X-D14) |
>
> ## Context
> Accrescent acceptă aplicații cu sursă închisă, dar interzice actualizatoarele proprii, acceptă doar seturi de APK-uri, verifică domeniul identificatorului aplicației și primește dezvoltatori doar dintr-o listă. Depozitul principal F-Droid acceptă doar software liber. Google Play ține cheia de semnare. Din 2027, pe dispozitivele certificate, aplicațiile dezvoltatorilor neînregistrați se instalează doar prin „fluxul avansat” sau ADB.
>
> ## Decizie
> 1. **Mirror-ul onion e canalul principal și singurul construit în Faza 14**; prima instalare vine din mirror (Tor Browser) sau din orice canal, verificată cu `ghost-verify`; fără mirror pe clearnet.
> 2. **Accrescent** se amână până când: contul e pe lista de acces, identificatorul aplicației e sub un domeniu al proiectului, există o variantă fără modulul `:update` și fără `REQUEST_INSTALL_PACKAGES`, iar pachetul aplicației și setul de APK-uri sunt reproductibile și semnate cu `K-APK`.
> 3. **Fără depozit în format F-Droid** (Q71); **fără Google Play**.
> 4. **Identificatorul aplicației** se stabilește definitiv înaintea primei distribuiri, sub un domeniu controlat de proiect (Q3, Q4); stagenet adaugă `.stagenet`.
> 5. **Verificarea dezvoltatorilor Android și Play Protect** sunt fapte ale platformei: nicio înregistrare în Faza 14; decizia proprietarului, cu avocatul, înaintea beta; backup-ul `K-APK` păstrează posibilitatea înregistrării.
>
> ## Consecințe
> (+) Un singur lanț de distribuție, verificat de actualizator; nicio dependență de clearnet pentru aplicație. (−) Utilizatorii GrapheneOS nu au o cale prin magazin; prima instalare depinde de Tor Browser sau de verificatorul extern; pe dispozitivele cu Google, platforma poate trimite către Google detalii despre aplicație la instalare (L10-D9); din 2027 o aplicație neînregistrată cere fluxul avansat (L10-D10).
>
> ## Alternative respinse
> Google Play (Google ține cheia; identitatea dezvoltatorului); depozitul principal F-Droid (doar software liber); un depozit propriu F-Droid (a treia familie de chei; actualizări fără verificarea jurnalului); un mirror HTTPS pe clearnet (IP-ul utilizatorilor, domeniu public al aplicației); IPFS (gateway-ul vede IP-ul și versiunea); varianta Accrescent construită acum (fără admitere).
>
> ## Teste
> T51 (cereri doar către onion-uri din manifest sau din lista inițială); verificatorul pe o versiune reală de stagenet; G-D4 (rădăcini și chei de rețele separate).

## Appendix B: Text changes in other documents (applied in S10)

### B.1 Master plan errata (Romanian)

- **Rândul 14 (plan:318)**, coloana „Durată”: „3–4 s” → „6–7 s (≈ 21 de săptămâni-persoană; designul Fazei 14 §13.2)”; după gate se adaugă: „(cele „două medii” ale porții sunt stația proprietarului și un runner găzduit; mediul auditorului, FR-8.9, e condiție de lansare; design Faza 14 §1.2)”.
- **FR-8.10 (plan:279)**, la final: „În Faza 14 se construiește doar mirror-ul onion; Accrescent e amânat până la condițiile din designul Fazei 14 §8.2; fără depozit în format F-Droid (Q71) și fără Google Play (ADR-52).”
- **G12 (plan:125)**, coloana „Optimizare”: „… onion mirror (canalul principal și singurul construit în Faza 14) + Accrescent (amânat, condiții externe, ADR-52) …”.
- **§6.6 (plan:365)**: `infra/` „… staging/prod, F-Droid repo” → „… staging/prod, builder (rețeta de build reproductibil), mirror (onion), release (runbook-ul ceremoniilor)”; se adaugă `android/update/` („actualizatorul: rulări de actualizare, verificare, instalare”) și `client-core/update` („formatele și decizia de actualizare, fără I/O”).
- **Anexa A a deltei (plan:286)**: „+ … F-Droid server” → „+ … sigsum-go (doar la publicare)”.
- **Notă la FR-7.5** (citat la plan:202): „„startup update checks” se citește ca verificări în rulări de actualizare independente de activitate și la cererea utilizatorului (ADR-51).”

### B.2 INVARIANTS.md (Romanian rows)

| ID | Invariant | Verificare | Executabil din | Cod |
|---|---|---|---|---|
| T48 | Actualizatorul scrie într-o sesiune de instalare doar octeții unui APK listat într-un manifest care e semnat de pragul cheilor de versiune ale celei mai noi rădăcini atinse din ancoră prin regula de lanț (fiecare rădăcină nouă semnată de ambele praguri și înregistrată sub politica rădăcinii anterioare), are rețeaua și legătura de rădăcină ale ei, e inclus într-un jurnal al politicii sub un checkpoint semnat de jurnal și cosemnat de cvorumul de martori, iar nucleul nesemnat al APK-ului, găsit cum îl găsește Android, e build-ul atestat de pragul de constructori independenți; limitele de dimensiune se fixează înainte de citire | vectori cu fiecare octet modificat; suita APK-urilor fabricate; lista atacurilor TUF ca teste; lumea de actualizare cu mirror-uri ostile și instalatorul care înregistrează; mutanții MC-D1 … MC-D5, MC-D9 … MC-D15, MC-D20 … MC-D23 | Faza 14 | `client-core/update`, `client-core/net`, `android/update` |
| T49 | Versiunea rădăcinii, perechea `(versiunea rădăcinii, secvența manifestului)` și versiunea minimă nu scad; aceeași pereche cu alți octeți pune indicatorul persistent de conflict și nu schimbă nimic; nu se oferă nimic la sau sub `versionCode`-ul instalat; sub minim, aplicația e „nesuportată” | teste de triggere; suitele de secvență (rollback, conflict, „fast-forward” și ieșirea prin rădăcină nouă); retrogradarea pe emulator; MC-D6, MC-D7, MC-D16 … MC-D18 | Faza 14 | `client-core/update`, `android/storage`, `android/update` |
| T50 | Nicio ofertă dintr-un manifest expirat (pe un ceas de încredere); fiecare rulare citește două mirror-uri și păstrează perechea cea mai mare; nicio decizie de timp pe un ceas fără încredere | lumi cu mirror-uri vechi și pași de ceas; MC-D8, MC-D13, MC-D19 | Faza 14 | `client-core/update`, `android/update`, `android/sync` |
| T51 | Preluările de la mirror au loc doar în rulări de actualizare (trase doar din cheia procesului și indicele rulării) sau la cererea explicită a utilizatorului, pe scopul `Update`, niciodată într-o sesiune cu relee sau într-o rulare liniștită; fiecare rulare cere aceleași obiecte, cu aceleași antete, de la două mirror-uri; nicio cerere nu poartă versiunea, versiunea rădăcinii, un identificator sau un antet condiționat; intervalele APK sunt pași ficși de 4 MiB; treapta de lansare e per versiune și nu părăsește dispozitivul | gemenii NI-U1 … NI-U4; testul constructorului de cereri; testul de scop din `client-core/net`; PM-D1 … PM-D8 | Faza 14 | `android/sync`, `android/update`, `client-core/net` |
| T52 | Niciun secret de semnare în depozit, în workflow-uri, în CI sau pe un mirror; niciun workflow nu semnează și nu publică; fiecare APK publicat are nucleul egal cu APK-ul nesemnat, ale cărui sume au fost egale în două medii înainte de semnare | G-D1; `ghost-release-ops apk-core` la fiecare versiune; înregistrările `release-build.yml`; checklist-ul RK1 | Faza 14 | `scripts/gates`, `release/ops`, `infra/release` |

Modificări: **T6** — preluările de la mirror sunt doar onion, prin `connect_isolated`; testul dinamic din Faza 13 include o rulare de actualizare. **T12** — „Identitatea între medii diferite … builder cu căi fixe în Faza 14” → „Identitatea între medii: rețeta `infra/builder`, mediile A (stația proprietarului) și B (runner găzduit), sume egale pe tag-ul de închidere (`release-build.yml`); T12b: atestările `GHRA` sunt cerute de actualizator când rădăcina rețelei are pragul de atestare ≥ 1”. **T15** — allowlist-ul primește `REQUEST_INSTALL_PACKAGES` (ADR-51); T15m admite `InstallStatusReceiver` (neexportat, fără filtru). **T19** — tragerea rulării de actualizare e o funcție pură de cheia procesului și indicele rulării; starea actualizării nu schimbă programul de citire (NI-U1). **T23** — rulările de actualizare nu sunt niciodată rulări liniștite și nu conțin apeluri la issuer.

### B.3 THREAT_MODEL (Romanian)

- **A7** → „Cheia Android a versiunii (`K-APK`) rămâne offline, pe chei hardware, cu părți SLIP-39; cheile de versiune și de rădăcină rămân offline, cu pragurile rădăcinii (ADR-48)”. Coloana „Dacă e falsă”: „APK-uri acceptate de Android în afara actualizatorului; prin actualizator doar după includerea publică în jurnal (T48)”.
- **AS-10** se înlocuiește cu rândurile AS-10a … AS-10i ale designului Fazei 14 §2.1.
- **TB-6** → „Build ↔ release | sumele SHA-256 din două medii (A, B), manifest semnat offline, intrare în jurnalul de transparență, atestarea auditorului (T12b, condiție de lansare) | cheile de semnare (niciodată în CI, pe un mirror sau pe o mașină cu rețea; T52)”.
- **AD-V**, coloana „Ce NU poate”: atenuările „jurnal de transparență cu martori și verificarea includerii în actualizator, verificator independent pentru prima instalare, versiunile relay în jurnal verificate de operatori, fișiere de simboluri” devin „proiectate în Faza 14 (ADR-49 … ADR-52), neimplementate”; restul rămâne.
- **S10** se rescrie: „Mitigări: rădăcină versionată cu praguri, manifest semnat, jurnal Sigsum cu martori, nucleul APK atestat (T48), anti-rollback cu perechea (rădăcină, secvență) și versiune minimă (T49), două mirror-uri și expirare (T50), rulări de actualizare independente de activitate (T51). **Rezidual:** prima instalare și magazinele (L10-D1, L10-D2); cheia Android veche pe Android 10–12 după rotație (L10-D3); înghețare până la expirare (L10-D4). **Test:** exercițiile de alterare, retrogradare și rotație ale Fazei 14.”
- **Tabelul cheilor**, rândul „Cheie release” se înlocuiește cu: „Cheie Android (`K-APK`) | offline, importată în două chei hardware | chei hardware + SLIP-39 3 din 5 | RK3 (linie v3.1), la 2 ani sau la compromitere | RK4; exercițiu anual RK5”; „Chei de versiune | pe chei hardware | — | RK2 | rădăcina le scoate”; „Chei de rădăcină | 1 hardware, 1 în părți, 1 la a doua persoană | — | RK2 (pragul vechi și cel nou) | —”; „Chei de atestare | la constructorii independenți | — | RK2 | rădăcina le scoate”.
- **§6**, rânduri noi: „Rulare de actualizare | — (fără sesiune cu relee) | — | trafic Tor | — | T51” și „Descărcare APK | — | — | o rafală Tor de mărimea APK-ului | — | T51 (mirror-ul vede că un client se actualizează)”, cu nota: „Mirror-ul onion vede preluările pachetului la momente independente de activitate și descărcările APK; pe dispozitivele cu servicii Google, Play Protect poate trimite detalii despre aplicație la instalare (LIMITE L10-D9).”

### B.4 LIMITE: new section L10 (Romanian)

> ## L10. Distribuție (Faza 14; ADR-48 … ADR-52; design `docs/design/faza14-distribution.md` §2)
>
> | ID | Reziduu | De ce rămâne | Atenuare |
> |---|---|---|---|
> | L10-D1 | Prima instalare nu trece prin actualizator; un APK modificat și re-semnat cu altă cheie e acceptat de Android ca aplicație nouă | nicio aplicație nu se poate verifica singură | `ghost-verify` pe alt dispozitiv; amprenta certificatului publicată în trei locuri; AppVerifier |
> | L10-D2 | Actualizările dintr-un magazin (dacă se va folosi vreodată) ocolesc jurnalul și atestările; magazinul vede instalările | varianta pentru magazin nu are actualizator | canal amânat (ADR-52) |
> | L10-D3 | După o rotație a cheii Android țintită la API 33, dispozitivele cu Android 10–12 acceptă în continuare actualizări semnate cu cheia veche (în afara actualizatorului) | v3 păstrează semnătarul original pentru API 28–32 | versiune minimă; `minSdk` 33 (Q9) |
> | L10-D4 | O înghețare până la 91 de zile dacă toate mirror-urile accesibile sunt vechi; ±3 zile în jurul expirării pe ceasul de încredere | fără cheie online | două mirror-uri pe rulare; re-semnare trimestrială |
> | L10-D5 | O instalare nouă a unui APK vechi, semnat valid, e acceptată de Android; aplicația o declară „nesuportată” abia după prima rulare de actualizare | regula `versionCode` acoperă doar actualizările | versiunea minimă din manifest |
> | L10-D6 | Martorii politicii Sigsum implicite au aceeași companie-mamă | politica publică disponibilă | o politică mai diversă când apare |
> | L10-D7 | Intrările fixate identice în ambele medii (SDK, NDK, JDK, toolchain, bibliotecile native precompilate ale terților) nu sunt verificate de reproductibilitate | ambele medii folosesc aceleași binare | surse oficiale verificate prin semnături; auditul Fazei 15 |
> | L10-D8 | Mirror-ul vede momentele rulărilor de actualizare (independente de activitate) și descărcările APK, deci „un client se actualizează acum” și versiunea; o descărcare reluată în mai multe rulări leagă acele rulări prin intervalele cerute | descărcarea e inerentă; reluarea economisește trafic | servicii onion fără jurnale; cereri uniforme; intervale fixe de 4 MiB |
> | L10-D9 | Pe dispozitivele cu servicii Google, Play Protect poate trimite detalii despre aplicație sau APK-ul la instalare | comportamentul platformei | textul din Faza 13; sisteme fără Google |
> | L10-D10 | Din 2027, pe dispozitivele certificate, un GHOST neînregistrat se instalează sau se actualizează doar prin fluxul avansat sau ADB; înregistrarea leagă identitatea proprietarului de pachet la Google | regula platformei | decizia Q18, cu avocatul |
> | L10-D11 | O cheie de versiune furată permite atacuri asupra metadatelor (director, mirror-uri, lansare) până la rotație; o stație de semnare compromisă poate obține semnătura unui manifest greșit dacă proprietarul nu citește ieșirea | semnarea fiecărei versiuni e la o singură persoană | jurnal public; RK4; verificarea online înaintea publicării |
> | L10-D12 | O cheie Android furată semnează APK-uri acceptate de Android în afara actualizatorului | identitatea Android e o singură cheie | rotație RK3; versiune minimă |
> | L10-D13 | Pierderea celor trei chei de rădăcină (sau a cheii Android cu părțile ei) cere o instalare manuală | regula de lanț | pragul 2 din 3; părți SLIP-39; RK5 |
> | L10-D14 | Rețeaua locală vede o rafală Tor de mărimea APK-ului | descărcarea | — |
> | L10-D15 | Un operator care nu își verifică binarul `ghost-relay` | verificarea e a operatorului | `ghost-verify operator`; imaginea din binarul publicat |
> | L10-D16 | APK-ul în așteptare stă pe dispozitiv până la instalare | instalarea cere fișierul | se șterge după instalare sau înlocuire |
> | L10-D17 | O schimbare a rădăcinii cere ca cel puțin un jurnal al politicii anterioare să fie activ; dacă toate jurnalele vechi dispar, rădăcina nu se mai poate schimba prin actualizator | rădăcina nouă se înregistrează sub politica pe care clienții o cunosc deja, ca o înlocuire țintită să fie publică | două jurnale în politică; schimbarea politicii din timp, cât jurnalele vechi trăiesc |

Corecturi: **L4**, rândul „Limitare” (LIM:158): „distribuția prin F-Droid repo/onion mirror” → „distribuția prin mirror-ul onion (ADR-52)”. **L5**, rândul „Build nativ reproductibil doar la aceeași cale” (LIM:170): planul devine „rețeta cu căi fixe și cele două medii ale Fazei 14 (ADR-50)”, cu starea „proiectat, neimplementat”. **L-SRC** (LIM:256-258): „Azi niciuna dintre acestea nu există” rămâne, cu adăugarea „designul Fazei 14 le definește (ADR-49 … ADR-52), neimplementate”.

### B.5 ADR errata (FR numbering; §1.4 item 1)

- ADR-37 punctul 8: „(FR-8.2)” → „(FR-8.1)”.
- ADR-38, rândul „Completează”: „FR-8.2, FR-8.8” → „FR-8.1, FR-8.7” (FR-8.2, cheile, e completat de ADR-48).
- Designul Fazei 9 §2.10.6 (English): "(CP-10, FR-8.8)" → "(CP-10, FR-8.7)", as a forward note.

### B.6 STATUS, ADR index, other designs

- `docs/STATUS.md`: a row "Faza 14 (distribuție) | design propus 2026-10-03 (`docs/design/faza14-distribution.md`), neaprobat; niciun cod" until approval; the row "Faze 12–18" becomes "Faze 12, 13, 15–18".
- `docs/adr/README.md`: ADR-48 … ADR-52 under a new heading "Propuse (designul Fazei 14)".
- F8 §3.3 (English forward note at `faza8-issuer.md:463`): "Phase 14 keeps the schedule key separate; the release record logs each ES (F14 D19); a GHES v2 that signs a digest would allow a hardware schedule key (F-D1)."
- F7 §10.1 (forward note at `faza7-sync-engine.md:1433`): "Phase 14 fills the directory from an embedded bootstrap list (`config`) and from verified manifests (`manifest`), F14 §7.8."

## Appendix C: Evidence, verified vs assumed

### C.1 Verified in the repository (at `197b2b4`)

Plan row 14 (plan:318) and FR-8.9, FR-8.10 (plan:278-279); ADR-07:10,13; ADR-37:15-23; ADR-38:18-24; ADR-39:13-19; TM A7, AS-10, AD-V, AD-9, TB-6, S9, S10, key table (`TM:25,41,56,58,72,161-165,89`); INV T6, T12, T15, T19, T20, T23 (`INV:14,20,23,27,28,31`); LIM L4 (158), L5 (170), L-SRC (256-258); STATUS:17, 22, 24, 25; `app/build.gradle.kts:11,14-15,33-41,62,74-89`; `libs.versions.toml:4-8`; `gradle-wrapper.properties:3-4`; `verification-metadata.xml:4-9`; `ghost/Cargo.toml:75,97-99`; `rust-toolchain.toml`; `build-native.sh:9-11,16,47-55,59-70,72-88`; `reproducible-build.sh:30-44`; `apk-native-libs.sh:5-18`; `no-public-binaries.sh:9-24`; `common.sh:15`; `ci.yml:3-8,41-44,179-271,306,391,439-469`; `install-protoc.sh:6-7`; `isolation.rs:30-31`; `RelayDirectory.kt:5-27`; `Schema.kt:115-120,277-290`; `DirectoryEsSlots.kt:31-36`; `SessionParticipant.kt:26-73`; `QuietRunScheduler.kt:25-68`; `EntitlementCrypto.kt:3-11`; `AndroidManifest.xml:5`; `ADR-22:21-29,45`; `faza8-issuer.md:409-465,482,2255`; `protocol/entitlement/README.md:11-46`; `relay-directory.txt:1-20`; `infra/relay/{Dockerfile,torrc,docker-compose.staging.yml}`; `ci-self-hosted.md` §1, §2, §6–§8, §10; F10:12,42; F11:8,893; `faza9-s0-hygiene.md:147,165-170`. **Production code never calls `RelayDirectory.upsert`** (searched over `android/*/src/main`: only `SyncStores.kt`'s implementation; the callers are tests). **The spec's FR-7 and FR-8 tables** (extracted with `pdftotext`, raw order): FR-7.5 is the distribution sentence with "Tampered APK/manifest and downgrade are rejected"; FR-8.1 … FR-8.8 as §1.4 item 1.

### C.2 Verified at primary sources (2026-10-03)

APK Signature Scheme v2 algorithms and the signing block's position and magic; v3 ("not recommended for Android 12 … and earlier"; Android 13 `checkSignatures`); v3.1 (Android 13; older devices use the original signer in the v3 block); v3.2 (Android 17 = API 37; ML-DSA-65/87; new keys; block `0x70e1c89f`); v4 (incremental installs); apksigner's `--rotation-min-sdk-version` and `rotate`; apksig's default lineage flags (no `PAST_CERT_ROLLBACK`); `versionCode` downgrade protection; Android 8.0 "Install unknown apps"; Android 14 update ownership; Accrescent requirements, new-app page, building page and FAQ; F-Droid Inclusion Policy, Security Model, repo setup, Reproducible Builds page, F-Droid 2.0 post; apksigcopier archived (2025-05-12, GPLv3+); Play App Signing; Android developer verification page and FAQ; the advanced flow (press, 2026-08); Play Protect help; YubiKey 5.7 PIV (Ed25519, X25519, import); yubico-piv-tool 2.5.0 (Ed25519 key type in ykcs11); SLIP-39 Final and `python-shamir-mnemonic` (MIT); TUF 1.0.36 (2026-08-05), its attack list, root-rotation rule and freeze check; `tough` 0.24.0 (2026-09-23; `aws-lc-rs`; no delegations); Sigsum docs status, log protocol (leaf, rate limiting, tree head, cosignatures), `sigsum-go` v0.14.1 (BSD-2-Clause, 2026-06-08), the named policy post (2026-02-04); C2SP `tlog-checkpoint` and `tlog-cosignature`; Rekor v2 GA post; Pixel Binary Transparency; Cargo PR #17488 (open, Rust 1.101); GitHub-hosted runner sizes; GitHub's postponed self-hosted fee; artifact attestations need Enterprise Cloud for private repositories; CycloneDX 1.7; Signal's APK page; AppVerifier (ISC).

### C.3 Verified locally (read-only)

Build-tools 37.0.0 `apksigner sign --help` on the owner's Windows SDK: `--alignment-preserved` (default false), `--lib-page-alignment` (default 16 384), `--rotation-min-sdk-version` (≤ 32 = the original v3 block without targeting; default v3.1 for Android T+), the PKCS#11 example. Not run: any build (no build output exists in this worktree).

### C.4 Corrected digest claims

The reproducible-builds digest said self-hosted runner use in private repositories carries a fee since 2026-03-01: postponed (§6.4). The channels and requirements digests named "bundletool ≥ 1.11.4": not on Accrescent's pages (§8.2). One digest mapped FR-8.5 to the key requirement: the raw text order maps it to FR-8.2 (§1.4).

### C.5 Assumed, with the S0 check that decides each

| Check | Question | Slice | If it fails |
|---|---|---|---|
| V-D1 | The recipe builds in A and B; tool versions identical | S0a | fix pins |
| V-D2 | `SHA256SUMS(A) = SHA256SUMS(B)` on a test commit | S0a | diffoscope classes; R-D1 |
| V-D3 | Variation matrix (path, CPUs, file order, date, uid) | S0a | a measure per class |
| V-D4 | AGP 9.4.0's unsigned APK alignment and `vcsInfo` presence | S0a | zip-align in the build |
| V-D5 | `core(signed) = unsigned` with `--alignment-preserved true` (software key) | S0a | R-D4's fallback |
| V-D6 | The same through PKCS#11 on a YubiKey (JDK 17, SunPKCS11) | S0b | another PKCS#11 module; YubiHSM 2 (Q6) |
| V-D7 | Ed25519 statement signing on the YubiKey (`CKM_EDDSA` or `yubico-piv-tool`); its message limit | S0b | encrypted software seeds on the signer host |
| V-D8 | SLIP-39 split and restore of the P-256 scalar; re-import gives the same key and certificate | S0b | another share tool |
| V-D9 | Line-table debug info, split, strip-all, build-id: deterministic, `.dynsym` intact, size delta | S0a | full strip without symbols (ADR-38 point 9 then unmet) |
| V-D10 | The hosted runner fits the build (time, RAM, disk) | S0a | Q11's fallback |
| V-D11 | Sigsum submission over Tor with a domain token; the policy's exact witnesses and quorum; vectors match | S0b | R-D5 |
| V-D12 | HTTP/2 prior knowledge on nginx behind an onion; hyper's client over Arti; 70 MiB over Tor (time) | S0a | `ghost-mirror` |
| V-D13 | `PackageInstaller` session install and update on API 29, 33, 37; the status receiver; platform downgrade refusal | S0a | — |
| V-D14 | Lineage rotation behaviour on API 29 and 33 (rollback capability off) | S0a | revise L10-D3's text |
| V-D15 | CycloneDX 1.7 output byte-equal across runs; schema-valid | S0a | SPDX with the commit time |
| V-D16 | R8 output independent of CPU count on AGP 9.4.0 | S0a | R-D1 |
| V-D17 | Temurin 17 exact pin; identical class files across A and B | S0a | — |
| V-D18 | Relay and issuer binaries identical across A and B | S0a | per-crate investigation |
| V-D19 | Whether Android enforces the APK certificate's validity dates (decides the validity written at RK0) | S0a | a very long validity |
| V-D20 | GHOST's v2/v3 certificate parse equals `apksigner verify --print-certs` on real APKs | S0a | fix the parser |

**Also assumed, not checkable by this phase:** that Google Play shows a personal developer account's legal name (taken from the channels digest, not re-fetched; it only adds to §8.4's reasons, which stand on the signing-key fact alone); the behaviour of Google's on-device verifier and of Play Protect beyond their help pages; that GrapheneOS is outside developer verification (Google's scope statement names certified devices); Accrescent's server-side view of update checks; the reported ~1 KiB Ed25519 message limit (V-D7 measures).

## Appendix D: Sources (accessed 2026-10-03 unless stated)

- Spec: `output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf` (text via `pdftotext`, pages cited in place).
- Android: https://source.android.com/docs/security/features/apksigning/v2 ; …/v3 ; …/v3-1 ; …/v3-2 ; …/v4 ; https://developer.android.com/tools/apksigner ; https://developer.android.com/studio/publish/versioning ; https://developer.android.com/about/versions/oreo/android-8.0-changes ; https://source.android.com/docs/setup/create/app-ownership ; https://android.googlesource.com/platform/tools/apksig/+/master/src/main/java/com/android/apksig/SigningCertificateLineage.java ; https://android.googlesource.com/platform/tools/apksig/+/refs/heads/main/src/apksigner/java/com/android/apksigner/ApkSignerTool.java ; https://developer.android.com/developer-verification ; https://developer.android.com/developer-verification/guides/faq ; https://www.androidauthority.com/google-android-advanced-flow-sideloading-rollout-begins-3700073/ (press) ; https://support.google.com/googleplay/answer/2812853 ; https://support.google.com/googleplay/android-developer/answer/9842756 .
- Stores: https://accrescent.app/docs/guide/appendix/requirements/ ; https://accrescent.app/docs/guide/getting-started/new-app/ ; https://accrescent.app/docs/guide/getting-started/building/ ; https://accrescent.app/faq/ ; https://f-droid.org/docs/Inclusion_Policy/ ; https://f-droid.org/docs/Security_Model/ ; https://f-droid.org/docs/Setup_an_F-Droid_App_Repo/ ; https://f-droid.org/en/docs/Reproducible_Builds/ ; https://f-droid.org/2026/09/24/f-droid-2.0-a-new-chapter-for-android-freedom.html ; https://gitlab.com/fdroid/fdroiddata/-/issues/3299 ; https://gitlab.com/fdroid/fdroidserver/-/issues/1313 ; https://github.com/obfusk/apksigcopier .
- Transparency: https://www.sigsum.org/docs/ ; https://git.glasklar.is/sigsum/project/documentation/-/raw/main/log.md ; https://pkg.go.dev/sigsum.org/sigsum-go ; https://manpages.debian.org/trixie-backports/sigsum-go/sigsum-tools.7.en.html ; https://manpages.ubuntu.com/manpages/stonking/man1/sigsum-submit.1.html ; https://www.glasklarteknik.se/post/named-policies-for-sigsum/ ; https://c2sp.org/tlog-checkpoint ; https://c2sp.org/tlog-cosignature ; https://c2sp.org/tlog-witness@v1.0.0 ; https://blog.sigstore.dev/rekor-v2-ga/ ; https://developers.google.com/android/binary_transparency/pixel_overview ; https://theupdateframework.github.io/specification/latest/ ; https://docs.rs/tough/latest/tough/ .
- Keys: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html ; https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html ; https://developers.yubico.com/yubico-piv-tool/Release_Notes.html ; https://github.com/satoshilabs/slips/blob/master/slip-0039.md ; https://github.com/trezor/python-shamir-mnemonic ; https://docs.digicert.com/en/software-trust-manager/code-signing/sign-with-third-party-signing-tools/android-applications/sign-android-files-with-apksigner-using-pkcs11-library.html (PKCS#11 practice).
- Builds and CI: https://github.com/rust-lang/cargo/pull/17488 ; https://docs.github.com/en/actions/reference/runners/github-hosted-runners ; https://github.blog/changelog/2025-12-16-coming-soon-simpler-pricing-and-a-better-experience-for-github-actions/ ; https://github.com/actions/attest-build-provenance ; https://cyclonedx.org/news/cyclonedx-v1.7-released/ ; https://nginx.org/en/docs/http/ngx_http_v2_module.html .
- Precedents: https://signal.org/android/apk/ ; https://github.com/soupslurpr/AppVerifier .
- Research digests of 2026-09-25 (requirements, signing and keys, channels, reproducible builds, threats and testing): inputs only; every claim used here was re-checked above or is marked assumed.
