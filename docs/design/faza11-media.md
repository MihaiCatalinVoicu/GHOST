# GHOST Phase 11: Media — Design (proposed)

| Field | Value |
|---|---|
| Status | **Proposed, 2026-09-25, for the owner's approval before any code** (the owner's rule: an approved design before implementation). ADR-40 … ADR-43 (Appendix A, Romanian) are "propus"; they become "propus, aplicat" only if the owner approves this design or lets the question defaults of §19 stand under the standing instruction to continue between phases. |
| Revision | 2 (branch `p11-design`, based on `f244b80`): revision 1 (`4bd01ec`) corrected after an adversarial review in three lenses (protocol and cryptography; privacy and metadata; feasibility, testability and scope). Every finding, whether it was verified, and what changed is in §21; the normative sections below already carry the corrections |
| Date | 2026-09-25 |
| Phase | 11 (plan §6.2 row 11, the authoritative scope): "Media: AEAD per chunk 256 KiB, fragmentare 64 KiB, strip metadata, Media3 fără cache plaintext, media efemeră și «vezi o singură dată» (P1; ADR-27)" (plan:315) |
| Exit gate | "corruption/resume; EXIF-zero; no-plaintext-cache" (plan:315), with the acceptance criteria of FR-2.3, FR-2.4, FR-7.4 ("Seek/resume/corruption tests pass without plaintext cache"), FR-7.10 (T5), FR-7.15 and T25 for media (INV:33) |
| Depends on | Phase 7 (`android/sync`; plan:315 "7 (paralel cu 10)"). **In fact also:** Phase 8 (tokens and registrations for a new owner namespace), the Phase 9 **code** on `main` (DM context, L0 codec, `MediaPort`, schema v5; *not* Phase 9's exit gate, which is open, `docs/STATUS.md`), and Phase 10 for the channel binding (§5.6, X-M4) |
| ADR impact | New: ADR-40 (media object format), ADR-41 (media namespace and transfer), ADR-42 (media hygiene: re-encoding, canonical profiles, decoder isolation, no plaintext at rest), ADR-43 (ephemeral and view-once media; refines ADR-27 points 10 and 12). Deviations recorded there and in §0.3 (X-M1 … X-M12): plan row 11 and the module layout, spec §7.4 step 3, ADR-08's "remux with Media3 Transformer", the Phase 7 promise `Inbox.want`, T15m, T20's scope, the Phase 9 design (kind 0x05, seven JNI functions, two table rebuilds), the Phase 8 demand model, T10's phase for media windows, T35's scope. Numbering note: Phase 10 has no design yet; whichever design merges second renumbers its ADRs, invariants and migration (§13.6) |
| Sources | Master plan v2.1; spec v2.0 PDF (§7.4 p.16, FR-2.3/2.4 p.8, FR-3.4 and FR-4.3 p.9, FR-7.4 p.10, §8 p.17, Appendix A p.26); ADR-01 … ADR-39; THREAT_MODEL v2.1; LIMITE; INVARIANTS T1–T35; `allowed-observables.json` v2; the Phase 7, 8 and 9 designs; five research digests of 2026-09-25 (requirements, crypto and format, platform media, relay integration, privacy and testing), each load-bearing claim re-checked in the repository or at a primary source for this draft. Repository citations are at `f244b80` and relative to the worktree root; `F7`, `F8`, `F9` = `docs/design/faza7-sync-engine.md`, `faza8-issuer.md`, `faza9-dm.md`; `INV` = `ghost/test-harness/privacy/INVARIANTS.md`; `TM` = `docs/THREAT_MODEL_v2.1.md`. Appendix C separates verified from assumed; Appendix D lists sources with access dates. |

**How to read this document.** §0 is the summary: decisions, guarantees, deviations, non-goals. §1 fixes scope and requirements, §2 the adversaries and the declared media leakage. §3–§11 are normative: the object format (§3), the descriptor and key custody (§4), where fragments live and who pays (§5), the sender and recipient pipelines (§6, §7), canonical formats and metadata stripping (§8), decoder isolation (§9), playback and the no-plaintext rule (§10), ephemeral and view-once media (§11). §12 is traffic and residues, §13 modules, JNI, schema and threads, §14 invariants, §15 tests and the exit-gate argument, §16 gates, CI and dependencies, §17 slices and effort, §18 risks, §19 owner questions, §20 findings outside the phase, §21 the review round of revision 2 (findings, verification, dispositions). Appendix A holds the ADR drafts (Romanian), Appendix B the text changes in other documents (Romanian where the target is Romanian), Appendix C the evidence and the S0 checks, Appendix D the sources. A section marked "(normative)" wins over a summary table.

**Identifier conventions.** Decisions `D1…D27`; requirements `RQ-M1…`; guarantees `P-M1…` (privacy) and `CS-M1…` (correctness); deviations `X-M1…`; declared media leakage `LM`; residues `L8-M1…` (new LIMITE section L8); invariants `T36…T41`; transactions in capitals (`MEDIA-COMMIT`, …, §13.5); world checks `JM1…` (joins) and `NI-M1…` (twins); crash scenarios `SCN-MA…SCN-MF`; mutants `PM-M1…` (privacy) and `MC-M1…` (correctness); gates `G-M1…`; S0 checks `V-M1…`; questions `Q1…Q35`; risks `R-M1…`; findings `F-M1…`; review findings `RV-…` (§21). Slices `S0a`, `S0b`, `S1…S10`.

---

## 0. Summary

### 0.1 Decisions

| # | Decision | Rejected alternatives (why) | Plan / ADR alignment |
|---|---|---|---|
| D1 | **Scope, exactly as the plan states.** P0: per-chunk AEAD, 64 KiB fragmentation, metadata stripping, Media3 without plaintext cache, ephemeral media. P1: view-once (FR-7.15, LIMITE:136). **Content types (P0): still images and video (with its audio track).** Not designed: audio-only and voice notes (RECORD_AUDIO is not in the T15 list), animated images, documents and arbitrary files (no generic stripping exists), RAW/DNG, in-app camera capture, an inbound share target, forwarding UI (§1.3) | designing voice notes or file transfer now (beyond the plan row; each needs its own permission or stripping decision, Q2) | plan row 11; FR-7.10, FR-7.15; ADR-08 names images and video |
| D2 | **One media object = one STREAM of 256 KiB AEAD chunks aligned to 64 KiB relay fragments**: 262 128 B of plaintext seal to exactly 262 144 B = 4 × 65 536 B, so fragments are headerless slices of chunk ciphertext (§3.3). | a 64 KiB AEAD unit (age/Tink shape; deviates from "AEAD per chunk 256 KiB" with no gain, kept as the fallback); misaligned chunks (262 160 B → 5 blobs, a non-bucket tail); a sequential chained stream (no random access, so no seeking) | plan row 11 read as 256 KiB of ciphertext (X-M2) |
| D3 | **Keys:** random `K_f` (32 B) and `object_id` (16 B) per object **and per destination**; `K_p`, `K_m` and a 32-byte **key commitment** derived with HKDF-SHA256 salted by `object_id`; STREAM nonce `0^7 ‖ u32_be(i) ‖ last` (§3.2) | the spec's literal "file nonce plus chunk index" inside a 96-bit nonce (a 128-bit nonce does not fit beside a counter); XChaCha20 with random per-chunk nonces (no truncation or reorder binding); convergent keys (cross-user equality) | spec §7.4 steps 1–3 (step 3 reworded, X-M3) |
| D4 | **Manifest:** one 64 KiB blob `commit ‖ AEAD(K_m, …)` with the kind, the size class, the content length, dimensions, a ≤ 32 KiB preview and every fragment hash in order (§3.5); integrity = blob hash (relay) + per-chunk tag + index binding + last flag + manifest hash list + commitment | manifest inline in the DM (its size would leak the object size through the DM bucket); per-object namespace listing (trusts the relay's listing); Merkle/Bao tree (a second hash system, a new crate) | spec §7.4 steps 4–5, 7 |
| D5 | **Size classes:** fragment counts `F ∈ {16, 24, 36, 56, 84, 128, 192, 288, 432, 648, 804}` (×1.5 steps, multiples of 4), plus one manifest blob; the class is a function of the content length only; images are normalised to fit class 0 (16 fragments, 1 MiB), so every image and every video under 1 MiB look alike (§3.6) | exact counts (known-file fingerprinting); Padmé (≤ 12 % overhead but about 60 classes); powers of two (≤ 100 % overhead, paid ×3 over Tor) (Q5) | T9 extended to objects (T36) |
| D6 | **Descriptor = the body of L0 kind 0x05 MEDIA**, fixed 86 B plus a caption of at most 1 024 B, so every media message is in the 4 KiB class of short text under R-B1 (§4.1) | a TLV in 0x0100–0x01FF (ignored by clients that do not know it; stays reserved); a variable descriptor (size leak) | F9 §7.1 reservation used as intended |
| D7 | **Native key custody with a key slot:** `K_f` is generated in Rust, stored only as `key_env` under `session_state_key` **bound to (role, destination, `object_id`, `manifest_hash`)**, and enters an L0 only inside `encrypt` (which fills a zeroed 32-byte slot after checking the binding) and leaves one only inside **the two functions that return a decrypted L0, `decrypt` (13) and `sessionInbound` (14)**, each of which wraps it and zeroes the slot; the JVM heap never holds a file key (§4.2) | the key in Kotlin under the content key (in the GC heap, not zeroisable, and in `dm_outbound_item.l0_env` for retries); a binding of `object_id` only (a caller bug could send one contact's key to another, who as a card holder can read the first contact's `M`) | F9 §2.5 rule extended; T35 extended to media keys (§3.8) |
| D8 | **Crypto in Rust:** a new pure crate `client-core/media` = `ghost-client-media` (format, STREAM, manifest, descriptor, classes, canonical-format walkers), exported through a second closed JNI class `MediaNative` from `ghost-client-dm`, which holds the one DM context and its registries; **no new crate in the shipped graph** (`chacha20poly1305` 0.11.0, `hkdf` 0.13.0, `hmac` 0.13.0, `sha2` 0.11.0, `zeroize` 1.9.0 are already pinned) (§13.2) | Kotlin with JCA/Conscrypt ChaCha20-Poly1305 (ADR-19 forbids protocol logic in Kotlin; the key would sit in the JVM heap; the Phase 10 MLS crate would need a second implementation); a separate context and wrap key (a second Keystore key for no gain) | ADR-19; ADR-20 point 8; the plan's `android/media` holds the Kotlin half (X-M1) |
| D9 | **Where DM fragments live: a recipient-owned media namespace per card, `M_i = HKDF(card_secret_i, "ghost/v1/card/media-ns")`**, written by every card holder with one shared deposit credential per relay slot, registered and paid by the recipient with its own capability, read with a seed-derived read credential; relay set `set(M_i, w)` of F9 §5.2 (§5.1) | the DM inbox `X_i` (media would exhaust the text allowance, fill `FETCHED_CAP` and be consumed as undecryptable DMs); sender-owned or per-object namespaces (tokens follow media activity, T27 broken; foreign reads, T31 broken) (Q3) | T26, T27, T31 extended; ADR-41 |
| D10 | **Automatic download on `M`'s own Phase 7 schedule**; a descriptor or a view causes **no** traffic (§7.1), and **neither does local state**: ingestion never stops for the pool cap, the binding state or free space (it evicts or discards locally instead, §7.5). The price: every media object deposited into my `M` is fetched, bounded by the stores others can pay for (§5.3) | fetch on descriptor (`Inbox.want`: a reflex that links a DM to its media and times it); fetch on tap (a relay-visible read receipt, and for view-once the viewing minute) (Q4) | T28 kept; F7 `want` not implemented (X-M6) |
| D11 | **Uniform registration:** every activated identity registers, pays (one ACCESS token per relay of `set(M_0, w)` per week) and lists `M_0`, whether or not it ever uses media, so "uses media" is not a relay-visible class (§5.2) | registering on first use (a new class of identities) | F8 demand model: +1 namespace (X-M10) |
| D12 | **TTL = the conversation's bucket** for every media blob (ADR-27 point 11, R-T2), deadlines `author + min(bucket, 7 d)`; no media-specific or view-once TTL (§5.4) | a short TTL for view-once (marks the message type) | ADR-27 C.11, ADR-32 unchanged |
| D13 | **Upload through the unmodified Phase 7 outbox in a bounded window** (≤ 32 unreleased ops per object, ≤ 64 per device) fed from the ciphertext store, **with per-ordinal upload state and an op table** (`media_outbound_op`, the F9 `dm_outbound_op` pattern) so resends and retries are counted per blob; the descriptor is sent only after every blob of the object has an outcome in {SENT, DEGRADED, INDETERMINATE after resends} (§6.4) | enqueueing the whole object (up to 51 MiB frozen in SQLCipher and its WAL); an "external payload" outbox (reopens the Phase 7 proofs; a Phase 12 option) | F7 outbox contract unchanged |
| D14 | **Media lane in `:sync`:** consumer-priority store ordering (DM, bundles, channels before media) and media fetch and store budgets; the read schedule is untouched (T19) (§5.5) | a separate engine (a second crash-consistency proof); today's budgets (≈ 24 min to fetch 25 MB in the foreground, ≈ 3 h in the background, relay-integration digest §4) | F7 "media bulk lane" (F7:1434) |
| D15 | **Mandatory re-encoding, never surgical stripping of source files:** images decoded and re-encoded to **canonical baseline JPEG** (long edge ≤ 2 048 px, sRGB, orientation baked, no APPn/COM, nothing after EOI); video transcoded by Media3 Transformer to **H.264 + AAC in fragmented MP4** written by **GHOST's own muxer wrapper** (no metadata entries, constant times, disallowed SEI dropped) with a GHOST-built `mfra` index for seeking; **encoding is forced for both tracks** (the encoder factory answers `videoNeedsEncoding()` and `audioNeedsEncoding()` with `true`, and an export without both encoder names is refused), because Transformer otherwise transmuxes a source that already matches the output format (§8) | surgical stripping (every container has trailers, secondary images and vendor boxes; ExifInterface writes only EXIF/XMP of three formats); Transformer's default `InAppMp4Muxer` (writes a plaintext file and forwards location, times, XMP and `mdta` entries, §8.4); remux without re-encoding, **including Transformer's automatic transmux of a matching source** (keeps the camera's bitstream, SPS/VUI, SEI, AAC data elements and bitrate) | ADR-08 kept in substance, its "remux" wording corrected (X-M5); FR-7.10 |
| D16 | **Canonical-format walkers in Rust run inside the sealer and the reader:** the sender cannot seal, and the recipient cannot display, bytes outside the canonical JPEG or fMP4 profile (§8.2, §8.3) | validation in Kotlin only (a second implementation; ADR-19); trusting the sender's pipeline | T37 |
| D17 | **Image decoding confined to an isolated process** (`android:isolatedProcess="true"`, not exported, no permissions), for received media and for the user's picked source files, **a fresh process instance per request** (`bindIsolatedService` with a new instance name, torn down after the reply; never shared between stripping and decoding, Q25); the main process never calls `ImageDecoder`, `BitmapFactory`, `ExifInterface` or `MediaMetadataRetriever` on media bytes; video is parsed only by Media3's Java fMP4 extractor after validation and decoded by `MediaCodec`, whose codecs run outside the app process (§9) | main-process platform decoders with header checks (the in-process native RCE surface of CVE-2023-4863 and the DNG chain of CVE-2025-21042); Rust image decoders in the shipped library (new crates and unsafe SIMD, and video still needs the platform) | T40; ADR-42 |
| D18 | **No plaintext media at rest:** the only persistent media bytes are E2E ciphertext exactly as stored on relays, in `noBackupFilesDir/m/`, one 64 KiB file per blob with a random name; previews, thumbnails, decoded pixels and decrypted chunks live only in RAM; Media3's `SimpleCache`, `CacheDataSource`, download and HTTP data sources, `MediaStore`, temp files, share intents and `MediaSession` are banned by static gates and checked on the emulator by sandbox scans (§10) | fragments as SQLCipher BLOBs (the DB never shrinks, WAL of up to 51 MiB, reader contention; Q18); Media3 `AesCipherDataSource` (AES/CTR, unauthenticated) | FR-7.4, spec Appendix A media row; T38 |
| D19 | **Crypto-shredding for expiry:** the `SWEEP` cascade (F9 §10.6) deletes the object rows and `key_env` in the same transaction as the message, then files are reconciled away after the commit (§11.1) | deleting files inside the transaction (file I/O cannot roll back) | ADR-27 point 10; T25 |
| D20 | **View-once (P1):** no preview in the manifest; the recipient's key is moved into a native reader and deleted from the database **in the transaction that opens the view**, followed by a `wal_checkpoint(TRUNCATE)` before any byte is shown, so a device displays it at most once even across crashes (a crash after the commit loses it); the sender keeps no re-viewable copy once its descriptor has a final outcome (§11.2) | erasing the key after rendering (a crash allows a second view); a relay-side short TTL (a type marker) | ADR-27 point 12 made exact; ADR-43 |
| D21 | **Schema migration M** (the next free version at merge, after any Phase 9 fix migration and before or after Phase 10's, §13.6) drops the never-written v1 `media`/`media_blobs` behind a fail-closed guard, rebuilds `dm_message` and `dm_outbound_item` to admit kind 5 (folding in Phase 9's open L5 columns if the owner has decided them, Q27), and adds `media_object`, `media_upload`, `media_blob`, `media_fragment`, `media_outbound_op` (§13.6) | amending v5 in place (allowed by the "never shipped" rule, but it reopens Phase 9's migration evidence; Q13) | CS-M7 |
| D22 | **Channels:** Phase 11 delivers a destination-agnostic engine (`MediaDestination`) and the DM binding; the channel binding (namespace, readers, fan-out cost, the key slot in MLS application messages) is a contract for Phase 10 (§5.6) | building channel media before Phase 10 exists | plan "paralel cu 10" (X-M4) |
| D23 | **Exit-gate evidence split honestly:** everything cryptographic, transactional and privacy-structural runs on the JVM with the real Rust (host build); re-encoding, isolation, Media3 playback, EXIF-zero and the sandbox scans need Android and run on an emulator job that needs a KVM runner (an owner action already open for Phase 9) or a signed manual run; **local Windows-emulator runs, recorded as Phase 9 recorded them (F9 §22.32), are slice evidence but not gate evidence** (§15.8, §17.1) | claiming EXIF-zero or no-plaintext-cache from JVM fakes | CP-10 |
| D24 | **Effort calibrated on Phase 9, not on a team model:** about 20–32 agent-days of implementation (2–3 calendar weeks at Phase 9's parallelism, whose slices S1 … S14 landed in nine days against a 10–12-week estimate), while the exit gate is dated by CI hours and owner actions (KVM runner, CI artifact quota, reference phones, staging relays), exactly what kept Phase 9's gate open (§17.2) | the revision-1 "7–9 weeks for 5–6 people" (no calibration; mis-cited STATUS); committing to a gate date | plan row 11 duration (R-M1) |
| D25 | **Content-addressed ciphertext store with references:** one `media_blob` row and one file per distinct blob hash; any number of objects may name the same hash (`media_fragment` is keyed by object and ordinal); each object's own AEAD decides whether a blob is really its fragment; a file goes only when nothing references it (§7.2, §13.6) | first binder wins (revision 1: a card holder who lists another sender's fragment hashes in its own manifest captures them and makes the honest object `corrupt`) | CS-M2, P-M4 |
| D26 | **The sender's countdown of a media message starts when its upload ends** (`MEDIA-READY`, or the op deadline for an object that never became ready), bounded by `deadline_hour + timer` from the commit (an R-T6 "only earlier" update); so a burst is never cut short by the timer, only by the deadline (a function of the bucket), a FAILED outcome or a user deletion (§6.3, §11.1) | the countdown from `MEDIA-COMMIT` (revision 1: an upload longer than 5 minutes is truncated at the 5-minute timer, which relays can tell from a 1-hour timer in the same bucket, breaking R-T1) | ADR-27 point 11, T25 (Q26) |
| D27 | **Plaintext sinks the OS writes are controlled or declared:** every window that shows media (including the gate harness) sets FLAG_SECURE and, on API 33+, `setRecentsScreenshotEnabled(false)` from Phase 11 (T10's rule brought forward for media screens); task snapshots, tombstones and dropbox entries are scanned on the emulator; storage-backed swap is declared (§10.3) | leaving task snapshots to Phase 13 (the gate harness displays media, so the sink is live during the gate) | T10, T38 (Q34) |

### 0.2 Guarantees claimed (each has a test in §15; none is a UI claim before the gate closes, CP-10)

**Metadata at relays and on the network (AD-1, AD-2, AD-4, AD-5, AD-7)**

| ID | Guarantee | Proof |
|---|---|---|
| P-M1 | **Uniform media bytes.** Every media blob is exactly 65 536 B of PRF or AEAD output with no cleartext header; an object whose upload completes is exactly `F + 1` blobs with `F` in the class set and a function of the content length only. A burst ends short only after a FAILED outcome, at the op deadline (a function of the TTL bucket) or when the sender's user deletes the message or the contact; never because of the conversation's timer inside its bucket (declared in `LM`). | T36: JM1 (with its stated exemptions), JM2, byte χ², NI-M7, PM-M1 … PM-M4, PM-M20 |
| P-M2 | **Nothing inside a class is visible.** Within one class, image vs video, view-once vs normal, with or without caption, and which sender are indistinguishable in relay bytes, sizes, TTLs and credential scopes. | NI-M3, NI-M4, JM4, JM5 |
| P-M3 | **No sender field in `M`.** Every store into one `M` at one relay presents the same deposit scope (T27 applied to `M`). | JM5, PM-M7 |
| P-M4 | **No reflex.** A received descriptor, a completed download, a validation, a display, a view-once opening, the pool's occupancy or the binding state causes no relay traffic; `M` is fetched only at `M`'s own list events, for what others stored. | T41: NI-M1, NI-M2, NI-M6, PM-M5, PM-M19 |
| P-M5 | **No cross-object links in bytes.** No two objects of honest senders share a blob or a 16-byte window of ciphertext; the same file sent to two recipients is two objects. | JM3 (exact on hashes and keys, sampled on windows), PM-M6 |
| P-M6 | **Metadata-zero content.** The decrypted content of every object and preview is canonical baseline JPEG or canonical fMP4 produced by a re-encode of both tracks; no EXIF, XMP, IPTC, ICC, MPF, C2PA, maker note, trailer, location, device, software or time atom, no source bitstream and no disallowed SEI survives. AAC raw data blocks are opaque to the walker (a modified sender can put bytes in AAC data elements; declared, Q35). | T37 (T5): the corpus with ExifTool and canary search, including sources that already match the output format; PM-M11, PM-M12, PM-M18 |
| P-M7 | **GHOST writes no plaintext at rest.** GHOST writes no plaintext media byte, preview or decoded pixel to any file, database, cache, log, clipboard, `MediaStore`, notification or another app, and every media window denies the OS its task snapshot. The OS's own residues (a crashed decoder's tombstone and dropbox entry, storage-backed swap) are declared, not claimed away (§10.3, L8-M8). | T38: G-M1, G-M2, sandbox and system-directory scans, PM-M9, PM-M10, PM-M23 |
| P-M8 | **Erasure.** After a message expires or a view-once object is opened, no key stored on the device opens that object's relay-stored bytes (after the sweep lag, including the WAL: a TRUNCATE checkpoint follows every transaction that nulls or deletes a `key_env`), and its files are gone after the reconcile lag unless another live object still names the same blob hash (an attack case, declared); honest relays drop the bytes by `deadline_hour + bucket + 1 h`. | T39, T25: logical and physical scans of the database and WAL, SCN-MD, SCN-ME, MC-M6, MC-M7, MC-M19 |

**Correctness and local soundness**

| ID | Guarantee | Proof |
|---|---|---|
| CS-M1 | **No nonce reuse, ever.** No (key, nonce) pair seals two plaintexts, across crashes, retries and resumes: a key is persisted only after every chunk of its object is sealed, and the sealer refuses a repeated index. | nonce registry in the test build over every world and crash run; SCN-MA; MC-M1 |
| CS-M2 | **Integrity before exposure.** A modified, truncated, extended, reordered, duplicated, spliced or substituted fragment or manifest, a wrong key, a non-zero pad or pad byte of the preview, or manifest fields that disagree with the content the walker parsed are rejected with a typed code before any decoded byte reaches an image or video consumer; a manifest opens under at most one key; a blob hash named by another object's manifest never makes an honest object `corrupt`. | vector and property suites (§15.2), the hash-squatting world (§15.4), MC-M2 … MC-M5, MC-M11, MC-M17, MC-M21 |
| CS-M3 | **Exactly-once descriptor, only after upload.** Each media message's descriptor is enqueued at most once per SEND attempt and only after every ordinal of its object reached a final outcome in {SENT, DEGRADED, final INDETERMINATE}; a FAILED ordinal blocks it. | SCN-MB, MC-M9, MC-M18 |
| CS-M4 | **Resume.** An interrupted upload or download continues after any crash without re-sealing, re-storing an acknowledged blob or re-fetching a stored one; resends are counted per ordinal (≤ 2 per retry generation) and user retries per object (≤ 3). | SCN-MA … SCN-MC, seeded worlds, MC-M18 |
| CS-M5 | **View-once at most once per device**, across crashes at any statement and file operation. | SCN-MD, MC-M6 |
| CS-M6 | **Bounded local state.** Pooled (unmatched) blobs ≤ `POOL_CAP` by local eviction (fetching never stops), outbox media window ≤ 64 ops, readers ≤ 8, sealers ≤ 2, previews in RAM ≤ 16 MiB, live decoder processes ≤ 2; each has a GC rule. | unit tests; SCN-MC; MC-M10 |
| CS-M7 | **Migration safety.** v5 (or the version before M) → M preserves every DM row and trigger; a crash at any statement leaves the previous version. | SCN-MF |
| CS-M8 | **Decoder containment.** Each decode or strip request runs in its own isolated process that dies after the reply; a crashing or hanging decoder never crashes the main process and is never retried in a loop (an object is `undecodable` after two sandbox failures); the Application class does no work in the isolated process. | T40 suite (distinct PIDs per request), MC-M13, PM-M21, MC-M23 |

### 0.3 Deviations from approved documents (each recorded in an ADR of Appendix A)

| # | Document | Deviation | Why | ADR |
|---|---|---|---|---|
| X-M1 | plan row 11 and module layout (plan:360: `android/media/ # chunking, AEAD, …`) | chunking, AEAD, manifest and canonical walkers live in Rust (`ghost-client-media`); `android/media` keeps the Kotlin half (store, pipelines, sandbox, Media3) | ADR-19 ("nicio logică de protocol în Kotlin"), F9 §2.4, key custody (D7) | ADR-40 |
| X-M2 | plan row 11 "AEAD per chunk 256 KiB" | the 256 KiB are ciphertext: 262 128 B of plaintext per chunk | alignment with 64 KiB fragments without a cleartext length or a non-bucket tail (T9) | ADR-40 |
| X-M3 | spec §7.4 step 3 ("a nonce derived from a collision-resistant file nonce plus chunk index") | the file nonce (`object_id`) salts an HKDF that derives a per-object key; the nonce is the STREAM counter and last flag | a 16-byte file nonce does not fit beside a counter in 12 bytes; the salt binds `object_id` and separates domains (it adds no multi-user gain here, since `K_f` is already random per object) | ADR-40 |
| X-M4 | plan row 11 dependencies "7 (paralel cu 10)" | DM media also needs the Phase 9 code on `main`; channel media needs Phase 10 and lands with it | FR-2.4 wraps the key "by the DM or MLS context" | ADR-41 |
| X-M5 | ADR-08 and plan:208 ("video remuxat … (Media3 Transformer)", "ICC-GPS") | video is transcoded, not remuxed, and written by GHOST's muxer wrapper; ICC profiles and GPS are both removed | the default Media3 muxer keeps location, times and XMP; a remux keeps the source bitstream | ADR-42 |
| X-M6 | F7:1419 ("Media (Phase 11) will add `Inbox.want`") | not added; `M` is listened and fetched on its schedule | `want` is a reflex (T28) | ADR-41 |
| X-M7 | INV T20 ("stratul de sync nu scrie nimic în afara SQLCipher") | unchanged for the sync layer; the media store (not the sync layer) writes ciphertext files, governed by the new T38 | ciphertext-at-rest in files (D18) | ADR-42 |
| X-M8 | T15m (no exported component except LAUNCHER; exceptions list empty) | no exported component is added; the gate learns one **non-exported isolated** service | decoder confinement (D17) | ADR-42 |
| X-M9 | F9 §7.1, §2.6, §13.6 | kind 0x05 gets its body; functions 2, 3, 4, 8, 13, **14**, 18 of `DmNative` gain inputs or outputs (names unchanged); `dm_message` and `dm_outbound_item` are rebuilt to admit kind 5 | D6, D7, D21 | ADR-40, ADR-41 |
| X-M11 | INV T10 ("Faza 13") | for windows that show media, FLAG_SECURE and `setRecentsScreenshotEnabled(false)` (API 33+) are required from Phase 11, including the gate harness | the task snapshot is a plaintext sink the OS writes (D27) | ADR-42 |
| X-M12 | INV T35 (provenance labels cover DM keys) | extended to `K_f` → `K_p`, `K_m`; the intro-inner-layer gap of T35 applies to media sent in a first message | media keys ride inside DM L0s (§3.8) | ADR-40 |
| X-M10 | F8 demand model (F8:535) | every activated identity owns a third DM namespace `M_0` | D11 | ADR-41 |

### 0.4 What this design deliberately does not do

- It designs no content type the plan does not name (D1), no forwarding, no share target, no in-app camera; each is recorded with its constraint (§1.3).
- It changes no relay protocol, no relay code and no observable field: `M` is an ordinary namespace, its blobs ordinary 64 KiB stores with an existing TTL bucket, its registrations ordinary `register` events (§5, §12.3).
- It claims nothing about timing or volume correlation: a 1 MiB image uploaded to three relays and downloaded once is a strong signal to a network-level adversary until cover traffic (P2) exists (L8-M1).
- It claims no bound on the media a hostile card holder can make me download beyond what that card holder can pay for (deposit allowances of every relay of my union set, plus its own tokens redeemed for write capabilities on my `M`, L7-D16) until Phase 12's owner-bound write and read rule (Q36 of F9) exists (§5.3, L8-M4).
- It does not stream playback before an object is complete and validated (§7.4), and it does not play media in the background (§10.2).
- It does not protect media from its legitimate recipient: pixels, sound, dimensions, duration and the encoder's fingerprint reach the correspondent, and a camera pointed at the screen defeats view-once (ADR-27 residues; L8-M9, L8-M10).

---

## 1. Scope, requirements, non-goals

### 1.1 Requirements (normative; each has a source and a test in §15)

| ID | Requirement | Prio | Source |
|---|---|---|---|
| RQ-M1 | Random 256-bit file key and random file identifier per file | P0 | spec §7.4 step 1; FR-2.4; TM:84 |
| RQ-M2 | Plaintext in logical 256 KiB chunks, each AEAD-encrypted with a nonce bound to the file and the chunk index; nonce-reuse property tests and tamper rejection pass | P0 | spec §7.4 steps 2–3; FR-2.3; plan:315 |
| RQ-M3 | Encrypted output **and manifest** fragmented into relay blobs ≤ 65 536 B; the relay accepts only {1, 4, 16, 64} KiB with uniform bytes and no cleartext length (T9) | P0 | spec §7.4 step 4; ADR-09; INV:17 |
| RQ-M4 | Blob key = SHA-256 of the exact ciphertext blob; the client keeps only hashes, credentials and an encrypted manifest reference; the file key stays wrapped | P0 | spec §7.4 step 5; FR-5.2; spec §8 `media` |
| RQ-M5 | The file key is wrapped inside the DM or MLS context, never stored as plaintext beside relay ciphertext; "relay data and manifest do not contain the plaintext key; modified chunk fails authentication"; the key "expiră cu mesajul" | P0 | spec §7.4 step 6; FR-2.4; TM:84 |
| RQ-M6 | Blob hash and AEAD tag verified before any decoded byte reaches an image or video consumer | P0 | spec §7.4 step 7 |
| RQ-M7 | Encrypted video through AndroidX Media3/ExoPlayer with local authenticated chunk decryption; seek, resume and corruption tests pass without plaintext cache | P0 | FR-7.4; spec Appendix A media row |
| RQ-M8 | Plaintext media only on the endpoint, decrypted in memory; backup and device transfer never contain decrypted cache | P0 | AS-4 (TM:35); FR-7.9; INV T4 (:12) |
| RQ-M9 | EXIF, XMP, GPS and video location/device atoms stripped before encryption; T5: "fișiere cu metadate cunoscute → decriptare → parser de metadate returnează gol" | P0 | FR-7.10 (plan:272); ADR-08; INV:13 |
| RQ-M10 | DM supports media | P0 | FR-4.3 |
| RQ-M11 | Channel posts support media up to 50 MiB, with boundary-size and invalid-media tests | P0, **Phase 10** | FR-3.4 |
| RQ-M12 | At expiry every device deletes the media and its thumbnails, then `secure_delete` and a WAL checkpoint; T25 covers media and thumbnails | P0 | ADR-27 point 10; FR-7.15; INV:33 |
| RQ-M13 | Media blobs use the conversation's TTL bucket (ADR-27 point 11, ADR-32 point 2); the relay sees nothing finer | P0 | ADR-27, ADR-32; T25, T30 |
| RQ-M14 | T1 capture ⊆ `allowed-observables.json` v2; adding a field needs an ADR | P0 | INV:9, :66 |
| RQ-M15 | Every blob written to ≥ 2 relays of distinct operators | P0 | ADR-11; ADR-20 point 7 |
| RQ-M16 | Permissions ⊆ the T15 list; no exported component except LAUNCHER; no third-party SDK; `androidx.media3` allowed | P0 | `ghost/scripts/gates/common.sh:15`; T15m; ADR-06; plan:464 |
| RQ-M17 | No copy, share, "Trimite către" or drag-out for media; FLAG_SECURE; constant notification text (UI in Phase 13) | P0, Phase 13 | ADR-27 points 1–3; T10, T11, T24 |
| RQ-M18 | View-once: decrypted only in memory at display, cannot be reopened, key erased after the first display | **P1** | ADR-27 point 12; FR-7.15; LIMITE:136 |
| RQ-M19 | Per-recipient watermarking of "sensitive" media | P2, not designed | LIMITE:138; TM S4 |

### 1.2 P0 and P1, exactly

"(P1; ADR-27)" in row 11 attaches to «vezi o singură dată»: FR-7.15 (plan:277) marks the whole ephemeral requirement P0 and names "media «vezi o singură dată» P1 (ADR-27)"; LIMITE:136 says "media «vezi o singură dată» (P1, Faza 11)"; ADR-27 point 10 makes deleting media and thumbnails at expiry part of the approved P0 ephemeral rule. So **ephemeral media is P0 and view-once is P1** (spec §3: a P1 may be off in a labelled private alpha but is required before GA). This design implements view-once in slice S8 and puts it in the gate by default (Q11).

### 1.3 Non-goals and deferrals (each with the constraint that decides it)

| Item | Status | Constraint |
|---|---|---|
| Audio-only messages, voice notes | not designed | RECORD_AUDIO is not in the T15 list (`common.sh:15`); the plan does not name them |
| Documents and arbitrary files | not designed | no generic metadata stripping exists; FR-7.10 would be unmet |
| Animated GIF / animated WebP / Motion Photo video part | refused at import; a Motion Photo is imported as its still | not named; the JPEG-only wire (§8.2) |
| RAW/DNG, HEIC and AVIF on the wire | refused on the wire; HEIC/AVIF accepted as **sources** if the sandbox can decode them (V-M5, Q9) | decoder surface (CVE-2025-21042 was a DNG chain) |
| In-app camera capture | Phase 13 (CameraX brings `libimage_processing_util_jni.so`, a native-library gate change); never `ACTION_IMAGE_CAPTURE` (a third-party app writes the photo to disk) | Q15 |
| Inbound share target (`ACTION_SEND`) | not in Phase 11 | needs an exported activity (T15m) |
| Forwarding inside GHOST | not in Phase 11; the rule is fixed now: a forward is a new object (fresh key, fresh fragments), never blob reuse; view-once is never forwardable | P-M5 |
| Streaming playback during download | not in Phase 11 | step 7 plus the full validation pass (§7.4) |
| Background playback, `MediaSession`, lock-screen controls | never | FOREGROUND_SERVICE_MEDIA_PLAYBACK is not in T15; a session publishes artwork and titles (§10.3) |
| Watermarking, cover traffic, duress wipe | P2 | LIMITE:138, ADR-15 |

### 1.4 Contradictions between documents and how this design resolves them

1. **Ordering.** Row 11 depends on "7 (paralel cu 10)", but FR-2.4 wraps the key "by the DM or MLS context" and Phase 10 has not started (`docs/STATUS.md`: "Faze 10–18 neîncepute"). Resolution: DM binding in Phase 11 on Phase 9's code; channel binding contracted to Phase 10 (§5.6, X-M4). Phase 11's gate items are media-specific and closable on DMs; any claim about DM media inherits Phase 9's open gate.
2. **Kotlin vs Rust.** Plan:360 puts AEAD in `android/media`; ADR-19 forbids protocol logic in Kotlin. Resolution: Rust (X-M1).
3. **256 KiB chunks vs exact 64 KiB buckets.** Spec p.2 claims v2.0 "reconciles 256 KB media chunks with 64 KB relay blobs" but defines no framing. Resolution: 262 128 B chunks (X-M2).
4. **Truncation and reordering** are not required by any document (FR-2.4's acceptance names only "modified chunk"). Resolution: index, last flag, hash list and class bound (§3.4) and tests for each (§15.2).
5. **The number of blobs per object** (≈ 800 for 50 MiB) is visible and not covered by T1 or TM §6. Resolution: size classes (D5), a TM §6 media row and LIMITE L8 (Appendix B).
6. **"ICC-GPS"** (plan:208) is not a metadata class. Resolution: ICC profiles and GPS are both removed; output is sRGB (X-M5).
7. **Container times** (EXIF DateTimeOriginal, OffsetTime, `mvhd`/`tkhd`/`mdhd` seconds) conflict with ADR-08's minute rule and G13's time-zone fingerprint. Resolution: no time in any content (§8).
8. **Phase 12's metadata-capture review depends on 6, 7, 10, not 11** (plan:316), so media traffic would never be reviewed. Resolution: finding F-M1 (add 11 to row 12's dependencies).
9. **Local forensics.** T33 bounds DB time columns; files carry inode times. Resolution: `mtime` forced to 0, `ctime` declared (L8-M6).
10. **Schema v1 `media`** keeps an exact `size_bytes` and plaintext `mime`, and has no timer column. Resolution: dropped and replaced (§13.6).

---

## 2. Adversaries and the declared media leakage

### 2.1 Who sees what (effective views; TM §3 adversaries)

| Adversary | Sees of a media object | Does not see |
|---|---|---|
| AD-2 relay | in the recipient's `M`: `F + 1` stores of 64 KiB within minutes, the conversation's TTL bucket, the shared deposit scope, the sender's circuit; later the recipient's `get`s of those hashes at `M`'s list events | content, kind within a class, view-once, caption, sender identity, any cryptographic link between the descriptor and the object (a relay in both sets can still guess it from timing, L8-M2) |
| AD-1 (all relays, one operator) | the same on every relay of `set(M, w)`; session co-occurrence ties the sender's `M` stores to its deposit of the descriptor into `X` shortly after (§6.4), and the recipient's `M` and `X` listings to one client (L7-D2) | the same |
| AD-7 card holder | can deposit into `M` (spam, allowance exhaustion) and, with its own token, list and get `M` and store into it under a write capability charged to its own quota (L7-D16): media volume and times of the whole card, the fragment hashes of other senders' objects as they arrive | which contact sent which object (fragments are uniform; `M` has no recognition hint); it cannot capture another sender's fragments by naming their hashes in its own manifest (D25) |
| AD-4 / AD-5 network | upload `3 × (F + 1) × 64 KiB` from the sender, download `(F + 1) × 64 KiB` by the recipient; correlation of the two bursts | anything cryptographic |
| AD-8 seized device | live objects' rows and ciphertext files with inode times; after expiry: tombstones only (§12.4) | expired content (T39) |
| Correspondent | the re-encoded pixels and sound, dimensions, duration, the encoder's stream parameters, the sensor's noise pattern (PRNU) | the source file's metadata (T37) |

### 2.2 Declared media leakage `LM` (the only information the media world lets through; extends F9's LD)

For each object: the recipient's `M` namespace at each relay of its set; the minute of each store and `get`; the class `F`; the TTL bucket of its conversation; the shared deposit scope; the sender's and recipient's circuits; the store burst's position relative to the same client's other stores (the descriptor deposit into `X`); **a burst shorter than `F + 1` stores, with no descriptor after it, when the upload ended FAILED, reached its op deadline (a function of the bucket and of transfer speed) or was stopped by the sender's user deleting the message or the contact**; the volume a card holder stores into `M` and the recipient then fetches. Everything in F9's LD stays. **Nothing else**: no kind inside a class, no view-once flag, no caption presence, no timer inside a bucket, no viewing time, no completion time, no validation or decoding event, no pool or binding state, no link between two objects in bytes.

### 2.3 The property the media world proves

(a) Joins JM1–JM7 over the full effective relay view find nothing outside `LM` (exact, except JM3's window search, which is sampled, §15.6); (b) twins NI-M1–NI-M7, differing only in something `LM` excludes, give identical **normalized** relay views: every event with its minute, operation, namespace role, size, TTL, scope and circuit, blob hashes replaced by their rank of first appearance and payload bytes by their length (§15.6). Byte identity is not claimed: native randomness is the OS's (F9's seeded `getrandom` backend was never built, F9 §22.16 item 13 and §22.22 item 7; Q33), and twins whose content differs (image vs video) have different ciphertext by construction. **Not proved:** how much a media burst speeds up the timing attacks F9 measures on LD (S-DM2's reply-timing SDA converges faster when one side of an edge moves megabytes). The burst is declared (L8-M1, L8-M2) and no statistical media attacker is built in Phase 11; measuring it belongs with the independent metadata-capture review (F-M1, Q23).

---

## 3. The media object (normative; ADR-40)

### 3.1 Constants

```
FRAG      = 65 536                 relay blob size of every media blob (the 64 KiB bucket)
TAG       = 16                     Poly1305 tag
CHUNK_CT  = 4 × FRAG = 262 144     ciphertext of one chunk
CHUNK_PT  = CHUNK_CT − TAG = 262 128   plaintext of one chunk ("256 KiB chunk", X-M2)
CLASSES   = [16, 24, 36, 56, 84, 128, 192, 288, 432, 648, 804]   fragment counts F; class_code = index 0..10
MAX_CONTENT = 52 428 800           50 MiB (FR-3.4; the v1 schema bound)
IMAGE_MAX_CONTENT = 4 × CHUNK_PT = 1 048 512   an image always fits class 0 (F = 16)
```

An object with class `F` has `n = F / 4` chunks, every one of them full (`F` is a multiple of 4), and `F + 1` relay blobs: `F` fragments and one manifest.

### 3.2 Keys and derivations

```
K_f       = CSPRNG(32)            file key, per object and per destination; never derived, never reused
object_id = CSPRNG(16)            the spec's "random file identifier" and the file nonce of step 3
K_p       = HKDF-SHA256(ikm = K_f, salt = object_id, info = "ghost/v1/media/payload",  L = 32)
K_m       = HKDF-SHA256(ikm = K_f, salt = object_id, info = "ghost/v1/media/manifest", L = 32)
commit    = HKDF-SHA256(ikm = K_f, salt = object_id, info = "ghost/v1/media/commit",   L = 32)
```

- **Why HKDF with the file nonce as salt (X-M3).** A 16-byte file nonce cannot sit beside a chunk counter in ChaCha20-Poly1305's 12-byte nonce. Deriving a per-object key from `(K_f, object_id)` is the construction of age (`payload key = HKDF-SHA-256(ikm = file key, salt = nonce, info = "payload")`, C2SP age spec) and of Tink's streaming AEAD (analysed by Hoang and Shen, CCS 2020, ePrint 2020/1019). Hoang and Shen's multi-user argument concerns Tink's **long-lived** main key, which a per-file salt diversifies; here `K_f` is already 256 fresh random bits per object, so the salt adds **no** multi-user gain. It is kept because it binds `object_id` into every derived key and follows a published construction. `object_id` also names the object in the local store and binds the manifest and every chunk (AD, §3.3).
- **Labels** live in `ghost-client-media` under the prefix `ghost/v1/media/`; a prefix test asserts that no label is a prefix of another (the `DerivationLabelsTest` rule), and `protocol/test-vectors/media_object.txt` pins them.
- **Per destination.** The same picked file sent to two contacts (or, in Phase 10, to a contact and a channel) is sealed twice with independent `K_f` and `object_id`: identical ciphertext at two destinations would link them by hash (P-M5). No key is ever derived from content (no convergent encryption).

### 3.3 Chunks and fragments

```
nonce_i  = 0x00^7 || u32_be(i) || u8(last_i)          last_i = 0x01 iff i = n − 1   (aead-stream StreamBE32 layout, zero prefix)
AD_c     = "ghost/v1/media/chunk" || 0x01 || object_id(16) || u8(kind)
C_i      = ChaCha20-Poly1305(K_p, nonce_i, AD_c, P_i)      |P_i| = CHUNK_PT, |C_i| = CHUNK_CT
fragment_{4i+k} = C_i[k·FRAG .. (k+1)·FRAG]                k ∈ {0, 1, 2, 3}; ordinal j = 4i + k ∈ [0, F)
P        = P_0 || … || P_{n−1} = content || 0x00^(n·CHUNK_PT − content_len)
```

- **R-O1 (headerless, T9).** A fragment is a slice of a ChaCha20-Poly1305 output (ciphertext or tag): the ciphertext is uniform under the PRF security of ChaCha20, and the tag is uniform because Poly1305's output is masked by `s`, 16 pseudorandom bytes of the ChaCha20 block 0 keystream for that nonce (RFC 8439 §2.8), under a key used for nothing else. (Poly1305 being a one-time MAC is what makes it unforgeable, not what makes the tag look random.) No cleartext version, length or index exists anywhere on a relay.
- **R-O2 (zero prefix).** `K_p` is unique per object with overwhelming probability (`K_f` is 256 random bits), so the 7-byte nonce prefix need not be random; within a key each `(i, last)` is used once (§3.7). The layout is exactly `aead-stream` 0.6.0's `StreamBE32` (7-byte prefix, big-endian 32-bit counter, one last-block byte), which the test build uses as a differential oracle (§16.3). `n ≤ 201`, far below 2³².
- **R-O3 (canonical padding).** Bytes of `P` beyond `content_len` are zero; a reader that finds a non-zero pad byte reports `NON_CANONICAL` (no covert channel, no malleability; F9 R-S2 in spirit).
- **Random access.** Byte `x` of the content is in chunk `⌊x / 262 128⌋`, which needs fragments `4i … 4i + 3` only; a seek costs at most one chunk decryption.

### 3.4 What binds what (the integrity argument; CS-M2)

| Attack | Stopped by |
|---|---|
| a flipped byte in a fragment in transit or at rest | SHA-256 of the exact blob at every `get` (`ghost/client-core/net/src/relay_client.rs:345-360`) and at ingest (§7.2); the chunk tag |
| a fragment of another object, or at another position | the manifest's ordered hash list; `object_id` and `kind` in `AD_c`; the index in `nonce_i` |
| truncation or extension | `F` and the hash count in the manifest; the last flag on chunk `n − 1` only (so a prefix of an object never authenticates as complete); a reader refuses an object with other than `F` fragments. `F` is not in `AD_c` because a streaming video's class is known only at `sealFinish` |
| reordering, duplication | hashes are ordered and pairwise distinct (a repeated hash is `NON_CANONICAL`); the index in the nonce |
| a manifest valid under two keys (invisible salamanders; Dodis, Grubbs, Ristenpart, Woodage, CRYPTO 2018; Albertini et al., USENIX Security 2022) | `commit` at the head of the manifest blob: two keys with one `commit` need an HMAC-SHA256 collision; ChaCha20-Poly1305 alone is not key-committing |
| a descriptor pointing at another manifest | `manifest_hash` rides inside the E2E-authenticated L0 |
| a relay replaying an old object into `M` | harmless: only a descriptor makes blobs an object, and every descriptor names a fresh `object_id` (F9's dedup layers apply to the descriptor) |
| a card holder naming another sender's fragment hashes in its own manifest (it can list `M` and see them arrive, L7-D16) | harmless: a hash may be named by any number of objects (D25); only the object whose key and `object_id` authenticate the chunks can use the blob, the other object becomes `corrupt` and releases its references without deleting a blob another object names (§7.2) |

**Why the commitment matters here.** Keys travel only inside E2E messages, so every recipient of one descriptor opens the same bytes. The commitment makes "this `manifest_hash` and this key determine one plaintext" a property of the format rather than of honest senders: Phase 10 moderation evidence (an ADR-13 flag carrying a descriptor), local caches keyed by hash and any future abuse report rely on it, for 32 bytes per object. **It binds a key to a plaintext, not to a sender:** there is no message franking, so a report proves "these bytes are what this descriptor opens", never "this contact sent them"; a recipient could forward a descriptor it received as if it were another's. Any moderation use in Phase 10 must state that limit (or add franking, which this design does not).

### 3.5 The manifest blob (65 536 B)

```
manifest_blob = commit(32) || ChaCha20-Poly1305(K_m, nonce = 0^12, AD_m, MP)        |MP| = 65 488
AD_m          = "ghost/v1/media/manifest" || 0x01 || object_id(16) || commit(32)
```

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 1 | `m_version` | `0x01` |
| 1 | 1 | `kind` | `0x01` image (canonical JPEG, §8.2); `0x02` video (canonical fMP4, §8.3) |
| 2 | 1 | `flags` | bit 0 `view_once`; other bits 0 |
| 3 | 1 | `class_code` | 0 … 10; `F = CLASSES[class_code]`; **`kind = 0x01` ⇒ `class_code = 0`** |
| 4 | 16 | `object_id` | equals the descriptor's |
| 20 | 8 | `content_len` | u64 BE; `1 ≤ content_len ≤ min(n · CHUNK_PT, MAX_CONTENT)` and `class(content_len) = F` (§3.6); **`kind = 0x01` ⇒ `content_len ≤ IMAGE_MAX_CONTENT`** |
| 28 | 2 | `width` | u16 BE; image 1 … 2 048, video 1 … 1 280; **equals the value the walker parsed** (JPEG `SOF0`; video `tkhd` and the `avc1` sample entry, which must agree) |
| 30 | 2 | `height` | u16 BE; same bounds and the same rule |
| 32 | 4 | `duration_ms` | u32 BE; 0 for an image; for a video 1 … `VIDEO_MAX_MS` and **equal to the walker's sum of the video track's `trun` sample durations** in `mdhd` timescale units, rounded down to milliseconds |
| 36 | 2 | `preview_len` | u16 BE, ≤ 32 768; **0 when `view_once`** |
| 38 | 32 768 | `preview` | canonical baseline JPEG (§8.2), each side 1 … 320 px (walker-checked), then **zero padding, verified zero** |
| 32 806 | 32 · F | `hashes` | SHA-256 of fragments 0 … F − 1, in order, pairwise distinct |
| 32 806 + 32F | rest | zeros | verified zero |

The sealer derives `width`, `height` and `duration_ms` from the stream it walked; Kotlin supplies none of them (`sealFinish` takes only the preview, §13.2), and the reader recomputes them during `MEDIA-VERIFY` and refuses a manifest that disagrees (`NON_CANONICAL`).

- `nonce = 0^12` is safe: `K_m` seals exactly one manifest (the F9 seal pattern, "k fresh per salt, nonce 0").
- The largest hash list (804 × 32 = 25 728 B) leaves 6 954 spare bytes, so every manifest is exactly one blob.
- The preview is the sender's; the recipient decodes it only in the sandbox (§9) and only while a conversation is on screen.
- `content_len` is exact inside the encryption; outside, only the class is visible.

### 3.6 Size classes (T36)

`class(L) = min{ F ∈ CLASSES : (F / 4) · 262 128 ≥ L }`; `L > MAX_CONTENT` is refused before sealing.

| `class_code` | F | Chunks | Max content (B) | Blobs | Bytes per relay | Objects per 256 MiB allowance |
|---|---|---|---|---|---|---|
| 0 | 16 | 4 | 1 048 512 | 17 | 1 114 112 | 240 |
| 1 | 24 | 6 | 1 572 768 | 25 | 1 638 400 | 163 |
| 2 | 36 | 9 | 2 359 152 | 37 | 2 424 832 | 110 |
| 3 | 56 | 14 | 3 669 792 | 57 | 3 735 552 | 71 |
| 4 | 84 | 21 | 5 504 688 | 85 | 5 570 560 | 48 |
| 5 | 128 | 32 | 8 388 096 | 129 | 8 454 144 | 31 |
| 6 | 192 | 48 | 12 582 144 | 193 | 12 648 448 | 21 |
| 7 | 288 | 72 | 18 873 216 | 289 | 18 939 904 | 14 |
| 8 | 432 | 108 | 28 309 824 | 433 | 28 377 088 | 9 |
| 9 | 648 | 162 | 42 464 736 | 649 | 42 532 864 | 6 |
| 10 | 804 | 201 | 52 687 728 (capped at 52 428 800) | 805 | 52 756 480 | 5 |

- Steps are ×1.5 rounded to a multiple of 4 (the last step is the 50 MiB cap). The worst overhead, for content just above a class boundary, is below 59 % including the manifest; the mean over sizes spread evenly within a ×1.5 class is 3 · ln 1.5 − 1 ≈ 22 % plus the manifest (class 0 is a fixed floor, not a ratio).
- **Why these and not Padmé or powers of two (Q5).** Padmé (Nikitin et al., PETS 2019) caps overhead at 12 % but yields about sixty classes over 16 … 804 fragments, enough to fingerprint a known video; powers of two give seven classes at up to 100 % overhead, paid three times on upload over Tor. Eleven classes with every image in the first hide what users send most (photos) completely and leave video sizes at about 3.5 bits.
- **Images.** The re-encoder targets `IMAGE_MAX_CONTENT` (§8.2), so every image is class 0 whatever its source. A video shorter than about four seconds may land in class 0 too, which is intended.

### 3.7 The sealer discipline (CS-M1; normative)

1. A **sealer** is a native object (§13.2) that owns `K_f`, `object_id`, the used-index set and the running hash list; Kotlin never chooses an index or sees a key.
2. Sealing is one pass with a one-chunk lookahead: `sealAppend` seals chunk `i` (with `last = 0`) once chunk `i + 1` has begun, so at most one plaintext chunk (262 128 B) waits in native memory; `sealFinish` learns `content_len`, computes `F`, seals the held chunk and the zero padding chunks with `last = 1` on index `n − 1` only, builds the manifest and returns `key_env` (§4.2). An index is sealed at most once (a second attempt is `INDEX_REUSED`, a bug).
3. **No key is persisted before `sealFinish` returns and `MEDIA-COMMIT` commits.** Until then `K_f` exists only in the sealer's native memory; a process death discards it with the unfinished object, whose fragment files are orphans removed by the next reconcile (§10.4). Resuming an interrupted preparation **always starts a new object with a new key**: transcoding is not deterministic, so sealing chunk `i` again under the old key would encrypt different plaintext under the same nonce.
4. After `MEDIA-COMMIT` (§6.3) nothing is sealed again under that key; uploads, retries and resends move identical ciphertext bytes (a Phase 7 identical-bytes resend is not a re-encryption).
5. A test build of `ghost-client-media` (`--features nonce-registry`) records every `(SHA-256(K_p), nonce)` pair in a registry that survives the harness's simulated crashes; any repeat fails the run (§15.3). The registry does not need seeded randomness. If a seeded `getrandom` backend is ever built for the host library (Q33), its stream must **continue** across a simulated crash, never rewind to the seed: a rewound stream would draw the same `K_f` for the resumed preparation, which would seal different plaintext under a repeated `(K_p, nonce)` and trip the registry for a harness artefact.

### 3.8 Bounds, the CP-09 exception, post-quantum wording

- **Integrity.** For ChaCha20-Poly1305, `IA ≤ v · (L′ + 1) / 2^103` with `L′` in 16-byte blocks (draft-irtf-cfrg-aead-limits-13, 2026-09-03, an Internet-Draft, not an RFC). A 262 128-byte chunk has `L′ + 1 ≈ 2^14`, so one forgery attempt succeeds with probability about `2^−89`. Confidentiality has no data limit at these sizes: every key seals at most 201 chunks.
- **CP-09 (no custom crypto).** The chunking is the published STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár, CRYPTO 2015, ePrint 2015/189) in the form age and Tink use; the GHOST parts are the composition (manifest, commitment, alignment, classes). ADR-40 records it as a CP-09 exception with vectors, a differential oracle and property tests, and adds the media format to the scope of the external cryptographic review that is already a release gate for Phase 9 (F9 §9.5).
- **Post-quantum (CP-10; T35 extended, X-M12).** `K_p` and `K_m` seal bytes stored on relays, so T35 covers them: they are derived from `K_f`, and `K_f` is transported only inside DM L0s under the Phase 9 envelopes. T35's statement gains "or derived from a key transported only inside such envelopes", and its provenance build labels `K_p` and `K_m` as `transported(K_f)` with `K_f` inheriting the label of the envelope that carried its L0. **The known T35 gap applies to media:** the provenance labels do not cover the intro inner layer (INV T35 row; F9 §22.16 item 18), and a media message sent as a first message, after a reset or before the peer's first reply travels in an intro envelope (F9 §6.8). 256-bit ChaCha20 is not the weak point against a quantum adversary. Media therefore inherits exactly the DM envelope's harvest-now-decrypt-later property, which Phase 9 has **not** validated (model not run in CI, no external review). No media UI claims anything post-quantum.

### 3.9 Vectors

`protocol/test-vectors/media_object.txt` (new): derivations for fixed `K_f` and `object_id`; every class boundary (`L = cap(F)` and `cap(F) + 1`); a full class-0 and class-1 object with every fragment hash; a manifest with and without a preview; the last flag on the final chunk only; one negative case per row of §3.4 and per rule of §3.5 (an image above class 0 or above `IMAGE_MAX_CONTENT`, dimensions or duration that disagree with the walked stream, a preview side above 320 px, a non-zero preview pad); `key_env` for fixed state keys and bindings, including a binding mismatch. Replayed by `ghost-client-media`'s tests, by the `aead-stream` 0.6.0 oracle for the chunk layer (dev graph only), and by an independent JDK implementation in `android/media/src/test` (JCA `ChaCha20-Poly1305` and a test HKDF): the F9 practice of two independent implementations of every vector.

---

## 4. The descriptor and key custody (normative; ADR-40, ADR-41)

### 4.1 L0 kind 0x05 MEDIA

The Phase 9 L0 (F9 §7.1) is unchanged except that `kind = 0x05` gets a body:

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 1 | `d_version` | `0x01` |
| 1 | 1 | `kind` | `0x01` image, `0x02` video; equals the manifest's |
| 2 | 1 | `flags` | bit 0 `view_once`; others 0; equals the manifest's |
| 3 | 1 | `class_code` | 0 … 10; equals the manifest's |
| 4 | 16 | `object_id` | |
| 20 | 32 | `key_slot` | **zero in every L0 Kotlin builds or reads**; filled only inside `encrypt`, zeroed only inside `decrypt` and `sessionInbound` (§4.2) |
| 52 | 32 | `manifest_hash` | SHA-256 of the exact 64 KiB manifest blob |
| 84 | 2 | `caption_len` | u16 BE, ≤ 1 024 |
| 86 | n | `caption` | strict UTF-8 |

- **R-D1 (bucket).** `|body| ≤ 1 110 B`, below the 4 KiB class's 2 220-byte body capacity (F9 §6.6), so every media message is a 4 KiB envelope exactly like a short text (R-B1 unchanged; P-M2).
- **R-D2 (TLVs).** A MEDIA L0 is a user-initiated send and may carry `seal_root`, `seal_root_pq` and `pq_key` under F9 R-C3 and R-C5, like TEXT.
- **R-D3 (strictness).** A MEDIA body that does not parse exactly, has an out-of-range `class_code`, `kind` or flag, an image (`kind = 0x01`) with `class_code ≠ 0`, or a caption over 1 024 B or not strict UTF-8 refuses the whole L0 (`NON_CANONICAL`, F9 R-C4); the manifest is later checked against every descriptor field (§7.2).
- **Kind 0x05, not the TLV range.** A non-critical TLV is ignored by a client that does not know it, which would show an empty message; kind 0x05 is refused as a whole by such a client (F9 §7.1). No Phase 9 client has been distributed, so no version skew exists; the TLV range 0x0100–0x01FF stays reserved.
- **Timer and deletion.** The message's `timer_code` governs the object (§11.1); the caption is the message body (`body_env`, content key) and follows the message.

### 4.2 Key custody: `key_env` and the key slot

```
key_env = nonce(12) || ChaCha20-Poly1305(session_state_key, nonce,
              AD = "ghost/v1/wrap/" || "media-file-key" || binding, K_f)                                 (60 B)
binding = u8(role) || dest_id(16) || object_id(16) || manifest_hash(32)      role: 0x01 out, 0x02 in
```

- `key_env` is F9 §2.5's envelope (`wrap.rs`, a new `WrapName::MediaFileKey`) with a binding that stays the same wherever the value moves (the F9 §22.8.3 rule). `dest_id` is the contact id for a DM (the recipient's on the sender, the sender's on the recipient) and, in Phase 10, the channel's destination id. It is the only durable form of `K_f` (`media_object.key_env`, next to `role`, `dest_id`, `object_id` and `manifest_hash`, §13.6). The binding follows F9's `olm_session_binding`, which names the contact: a `key_env` of one contact's object does not open for another contact, so a caller bug (or a future forward feature) cannot put contact X's `K_f` into a message to contact Y, who as a card holder of X could read X's `M` (L7-D16).
- **Sender.** `sealBegin` takes `dest_id`; `sealFinish` returns `key_env` bound to `(out, dest_id, object_id, manifest_hash)`. `SEND` calls `DmNative.encrypt(h, contactId, sessionId, stateEnv, l0, today, mediaKeyEnv)`: for a kind-5 L0, Rust checks that `key_slot` is zero, unwraps `key_env` under `(out, contactId, object_id, manifest_hash)` with the last two read from the same L0, writes `K_f` into the slot, Olm-encrypts and zeroises; a `key_env` that does not open under that binding is refused (`NON_CANONICAL`: a caller bug, counted; the item fails and nothing is encrypted); for any other kind `mediaKeyEnv` must be empty. `dm_outbound_item.l0_env` (content key) therefore stores the L0 with a zero slot, and a FAILED retry fills it again from `key_env`.
- **Recipient: both functions that return a decrypted L0.** F9 has two: `decrypt` (13), for a normal message or a PreKey message on a known session, and `sessionInbound` (14), for a PreKey message that creates a session (RECV R7, F9 §7.4) and for the held-replay path after a key change (`HeldReplay.kt:27`, `DmSessions.kt:510`; the code returns `Field::L0` there, `client-core/dm/src/jni.rs:1268-1269`). First messages, messages after a reset or reconnect and every message of a session the peer has not answered are PreKey (F9 §6.8), so a photo sent first takes function 14. **Both** parse a kind-5 L0 natively, wrap `K_f` into a new `key_env` bound to `(in, contactId, object_id, manifest_hash)`, zero the slot and return the L0 **and** `key_env`; `l0Decode` accepts kind 5 only with a zero slot. `RECV` (and the held replay) stores `key_env` in `media_object` in the same transaction as the message row. Tests: the key-slot suite runs through function 13, function 14 and the held-replay path, and "the first message is media" is a case of the worlds and of SCN-MC (§15).
- **Effect.** The file key never exists in the JVM heap on either device (F9 §2.5's rule for opening secrets, extended), so deleting `key_env` (and checkpointing the WAL, §11) and zeroising native memory is the whole of key erasure (P-M8). Decrypted **content** does reach the JVM heap during video playback (Media3 buffers are Java arrays; §10.2, L8-M7).
- **Functions changed** (names unchanged, so G-R6's `DmNative` list is unchanged): 2 `ownCard` (also returns `M_i`), 3 `cardDerive` (also `M_c` and `MD_{c,s}`), 4 `ownReadSecret` (also `RM_{i,s}`), 8 `encrypt` (`mediaKeyEnv` input), 13 `decrypt` and **14 `sessionInbound`** (`mediaKeyEnv` output), 18 `l0Encode`/`l0Decode` (kind 5 with a zero slot). The typed facade gains `mediaKeyEnv` in `DmSessions.decrypt`'s `Ok` result, whichever native function produced it.

### 4.3 The MLS contract (for Phase 10)

A channel post carrying media uses the same body inside the MLS application message, and Phase 10's MLS crate implements the same key-slot rule (fill inside encryption, wrap and zero inside decryption, never a file key in Kotlin). ADR-41 states it as a requirement on the Phase 10 design.

---

## 5. Where fragments live, who pays, how they move (normative; ADR-41)

### 5.1 The media namespace and its credentials

New `CardLabels` and `DmLabels` (F9 §3.1–§3.2), in `ghost-client-dm`, with prefix tests and vectors in `dm_derive.txt`:

| Output | Derivation | Presented to relays? |
|---|---|---|
| media namespace `M_i` (32) | `HKDF(card_secret_i, "ghost/v1/card/media-ns")` | as the namespace id |
| media deposit secret `MD_{i,s}` (32) | `HKDF(card_secret_i, "ghost/v1/card/media-deposit" ‖ u8(s))` | yes, as a deposit credential v3 to the relay of slot s |
| media read secret `RM_{i,s}` (32) | `HKDF(m, "ghost/v1/dm/media-read" ‖ u16_be(i) ‖ u8(s))` (seed-derived, like `RX`) | yes, as a read credential v3, by the owner only |

| Namespace | Registered by | `Namespaces.register` | Read | Write |
|---|---|---|---|---|
| own media `M_0` | owner, at activation, restore and the one-time upgrade step (§5.2) | `(M_0, MEDIA, union set, listen = true, REDEEM)` | owner: `RM_{0,s}`, or its write capability | card holders with `MD_{0,s}` |
| contact media `M_c` | us, at the first media send to c | `(M_c, MEDIA, set(M_c, w), listen = false, LOCAL)` | nobody on our side | us, with `MD_{c,s}` |

- **Relay-blind (T26).** `M_i` and `MD_{i,s}` derive from `card_secret_i`, `RM` from the seed's MESSAGING branch; nothing relay-visible is computable from public identity material. `M` has no recognition key: nothing in it is matched by hint; blobs become an object only through a descriptor.
- **Relay set** `set(M_i, w)` by F9 §5.2 (the keyed permutation of the week's ES slots, ≥ 2 operators, the owner's 6-week union). Pinning `M_i` to `X_i`'s set saves no token (tokens are per relay and namespace) and would make `M` a special case.
- **Credentials** are deposit and read credentials v3 exactly as F9 §4.3; relays see nothing new: `register` events with `key_kind` `deposit` and `read`, stores and reads with v3 scopes (T1 unchanged).
- `Namespaces.remove(M_c)` with the contact, after its last media op's deadline (F9 §21.12's orphan rule).

### 5.2 Owner registrations, tokens, reachability (changes to F9 §4.8)

- `REGROWS` and `KEEPER` cover `M_0` like `X_0`: DEPOSIT and READ registrations for weeks `{w, c, c + 1}`, the READ credential installed per relay, the healing rule unchanged. **One-time upgrade:** a time-triggered pass on a client whose `dm_own_namespace` lacks `M_0` registers it (resumable, the F9 §21.12 ACTIVATE pattern), so devices activated before Phase 11 converge.
- **Token accounting (T27, D11).** Exactly one ACCESS token per (relay, own namespace, week) on the EXPIRING path, now for `X_0`, `P_0` **and `M_0`**, whatever the media activity: at most 3 per ES slot per week, against `access_per_slot = 16` (F8:415). Senders spend nothing on `M_c` (`LOCAL`, never redeemed; PM-1b's rule).
- **Phase 8 T2 world.** The `population` line's `dm_owner_namespaces` becomes 3 per activated client (F9 §4.9 point 3), baselines are re-recorded and `t2-report-check.sh` updated: a uniform shift for every client; no issuer input reaches `M` events.
- **Offline tolerance** is F9's: deposits into `M_0` succeed for about two to three weeks after the owner's last renewal.
- **Restore from the seed.** `RM_{i,s}` is seed-derived, so a restored device reads `M_0` at once, like `X_0` (F9 §4.8). Objects whose descriptors were sent to the lost device are lost with those descriptors (F9 §8.6, L7-D12); their blobs are still fetched and are dropped as unmatched after at most eight days (§7.5). A restored device therefore downloads up to its media allowance of objects it can never open, bounded by `POOL_CAP` (declared with L8-M3).

### 5.3 Allowance, quotas, denial of service

- Deposits into `M_0` are charged to its own `DepositLedger` records (F9 §4.5): 268 435 456 B (256 MiB, `capability_quota_bytes`, F8:417) per registering capability per relay per week. An honest sender puts every blob on every relay of `set(M_0, w)`, so **honest contacts together can deliver about 256 MiB of media per week** (240 images or 5 videos of 50 MiB, §3.6), separately from the text allowance.
- **What a hostile card holder can make me download is larger, and not bounded by my allowance alone** (L8-M4, the media counterpart of L7-D8 and L7-D16):
  1. it need not write the same blob to every relay: distinct blobs on each relay of my 6-week union set cost it nothing and exhaust each relay's allowance separately, about `|union set| × 256 MiB` per week (≈ 768 MiB with three relays, more when the union is larger);
  2. it can redeem **its own** ACCESS tokens for a write capability on `M_0` (M is card-derived; "write grants read", F9 §4.5, L7-D16) and store under that capability's own quota, which my allowance does not limit; this is bounded only by the tokens it holds (up to `access_per_slot` per ES slot per week, F8:415).
  Every such store is fetched (D10: fetching may not depend on what I hold). Closing (2) needs the owner-bound write and read rule of Phase 12 (F9 Q36). A second registering capability per week doubles only the honest allowance (Q20).
- Exhausting the allowance refuses honest media for the rest of the week (texts unaffected).
- Relay disk is bounded by allowances × TTL as for every namespace; no relay change (finding F-M3).

### 5.4 TTL and deadlines

- **R-MT1.** Every media blob (fragments and manifest) uses `bucket(conversation timer)` of F9 §10.1, like every other blob of the conversation (R-T2): 5 min and 1 h → 1 h; 1 d → 1 d; 7 d → 7 d; 30 d and off → 30 d. View-once changes nothing (a TTL of its own would mark it; NI-M4).
- **R-MT2.** Every media op carries the deadline `author + min(bucket, 7 d)` with `author` the compose minute (F9 R-T4); after it no copy is stored and the op closes. A large object in a 1-hour-bucket conversation must finish uploading within the hour, which needs the app in the foreground: at Phase 7's per-RPC cost a class-9 or class-10 object needs about 23–64 minutes of foreground upload to three relays (§5.5), so **in conversations whose bucket is 1 h a video is limited to class 8** (content ≤ 28 309 824 B: a source of at most `VIDEO_MAX_MS_SHORT` = 100 000 ms, checked before work, at the profile's ≈ 2.13 Mbit/s; an output that still lands above class 8 fails the preparation), and `sendMedia` answers `TOO_LARGE_FOR_TIMER` (Q29); smaller classes may still miss the deadline in background jobs (L8-M5). The deadline depends only on the bucket, never on the timer inside it (D26).
- **R-MT3.** Fragments are stored before the descriptor (§6.4), so on an honest relay every fragment of an object expires no later than its descriptor: `E_frag ≤ E_desc`.

### 5.5 The media lane in `:sync` (normative; the "media bulk lane" of F7:1434)

| Change | Rule |
|---|---|
| Consumer priority (stores) | inside every store round (a STANDARD pass or a HIGH pair event), due ops are taken `DM, PREKEYS, CHANNEL, IDENTITY` before `MEDIA`, then by `not_before_minute` and `operation_id` (F7 had no fairness) |
| Media store budget | `mediaStoresPerPass = 16` per STANDARD pass, taken **after** the pass's `storesPerPass = 32` non-media stores, the pass reposting itself while media is due (`Session.kt:178`'s at-cap rule) so other work items interleave between passes; `mediaStoresPerPairEvent = 8` in HIGH |
| Fetch fairness (new) | the work lane has **one thread** (`Session.threads`, `Session.kt:129`) and fetches run inside `PairWork` items on it (`WorkLane.kt:77-83`), so a long media bundle delays every DM fetch behind it. A media pair's `PairWork` therefore fetches at most `mediaFetchesPerItem = 8` blobs and reposts the rest of its bundle as a new item **behind** the non-media items already queued; a non-media `PairWork` is never queued behind a media continuation |
| Media fetch budget | pairs of a `Consumer.MEDIA` namespace fetch up to `mediaForegroundFetchesPerEvent = 64` per event and `mediaBackgroundFetchesPerEvent = 128` per background event, in slices of 8 |
| Media share of the relay budget (new) | in a background session media work (stores and fetches) may use at most `mediaBackgroundRelayWorkMillis = 45 000` of each relay's 90 s work budget (`TrafficPolicy.backgroundRelayWorkMillis`, charged by `Steps.timed`, `Steps.kt:91`); the rest stays for DM, bundle and channel work of that relay |
| Unchanged | the read schedule (T19), list limits and pages, `FETCHED_CAP = 256` per namespace (the media actor drains `M` continuously and never stops claiming, §7.5), quorum 2, the 7-day window, deadlines, resends |

T19 holds by construction: budgets and slicing change how many `get`s and stores a work item carries and in which order queued items run, never when lists happen. `T19BasicTest` gains media activity in its run (b), and mutant MC-M14 (media work moves a list) must be detected. A new `MediaFairnessTest` measures, in a world where a card holder floods `M_0`, the delay of DM fetches against a control without media: at most one media slice (8 calls) per DM fetch. The Phase 7 exhaustive suite and `sync-exit-gate` re-run with a `MEDIA` consumer in their worlds.

**Throughput (estimates, [I]; measured in S0b, V-M10).** Onion-service bulk throughput was a median 2.5–5.4 Mbit/s over 2026-09-10 … 20 (Tor Metrics onionperf), but Phase 7 builds a new relay client per RPC (pooling is a Phase 12 item, F7:85), so one 64 KiB store or `get` costs about two round trips plus the transfer, 0.7–1.6 s. **The work lane is serial across relays**, so an upload costs `3 × (F + 1)` calls one after another: an image (51 store calls) about 36–82 s in the foreground; a class-8 object (1 299 calls) about 15–35 min; a class-10 video (2 415 calls) about 28–64 min in the foreground, and in background jobs about 18–40 jobs per relay (a job gives media at most 45 s per relay, about 28–64 calls). A download is `F + 1` calls: 12–27 s for an image, 9–21 min for class 10. Upload is three replicas: 3.2 MiB for an image, 151 MiB for a 50 MiB video, plus about 3 % of Tor cell overhead (498 payload bytes per 514-byte cell). **Worked example:** a 25 000 000-byte video is class 8 (432 fragments, capacity 28 309 824 B), so 433 blobs and 28 377 088 B per relay (+13.5 %), 85.1 MB uploaded to three relays, 10.6 % of one weekly media allowance per relay, and about 15–35 min of foreground upload at the per-RPC cost above. **No transfer-time claim is made** (finding F-M2: connection pooling is the lever).

### 5.6 `MediaDestination` and the channel contract (Phase 10)

The engine (§6, §7) never names a DM concept; it receives a destination:

```kotlin
class MediaDestination(
    val destId: DestinationId,           // 16 B: the contact id for a DM; in key_env's binding (§4.2)
    val namespace: NamespaceId,          // M_c for a DM; the channel's media namespace in Phase 10
    val relays: Set<RelayId>,            // the namespace's relay set
    val ttl: TtlBucket,                  // the conversation's or channel's bucket (R-MT1)
    val deadlineEpochSeconds: Long,      // author + min(bucket, 7 d) (R-MT2)
)
```

Phase 10 must decide, and ADR-41 lists as requirements on it: a relay-blind channel media namespace with its read and write credentials; automatic download by members (the T28 argument of §7.1 applies unchanged) and the relay egress of fan-out (a 50 MiB post read by 1 000 members is about 50 GB leaving the relays; finding F-M5); the key slot in MLS application messages (§4.3); the channel timer mapped by R-MT1; and what a removed member keeps (the keys of objects it already received). Phase 11's gate closes on DMs and on a test destination in the JVM world (§15.5); FR-3.4's channel acceptance belongs to Phase 10.

---

## 6. Sender pipeline (normative; ADR-41, ADR-42)

**End to end: A sends a photo to B, who is offline** (each step is specified below and in §7).
1. A picks a photo; `sendMedia` returns `QUEUED`. A fresh sandbox process re-encodes it to a canonical JPEG of at most 1 048 512 B and dies; Rust canonicalises the main process's copy; a sealer seals 4 chunks into 16 fragment files and builds a 64 KiB manifest (§6.2).
2. `MEDIA-COMMIT` stores the object, `key_env`, the message row (its countdown not yet started, D26) and the pending item in one transaction (§6.3).
3. `MEDIA-FEED` enqueues the manifest and 16 fragments into `M_B` with B's shared media-deposit credential, the conversation's TTL and the op deadline; Phase 7 stores each on the three relays of `set(M_B, w)` and verifies two operators' copies (§6.4).
4. After the last outcome, `MEDIA-READY` starts the sender's countdown and lets F9's `SEND` encrypt the kind-5 L0 (the key slot filled inside Rust) and deposit a 4 KiB envelope into `X_B`.
5. B comes online. Phase 7 lists `X_B` and `M_B` on their own schedules and fetches everything new, independently of each other (§7.1).
6. `MEDIA-INGEST` stores the 17 blobs as ciphertext files; `RECV` opens the descriptor (through `decrypt` or, for a first message, `sessionInbound`) and records the object with a fresh `key_env`; `MEDIA-BIND` opens the manifest and binds the fragments by hash; `MEDIA-VERIFY` authenticates and validates every chunk (§7.2, §7.3).
7. When B opens the conversation, the preview is decoded in the sandbox; opening the photo decrypts it into shared memory for the sandbox to decode (§7.4). No step from 5 on causes relay traffic beyond `M_B`'s scheduled listings and fetches.
8. At the message's expiry both devices delete the object's rows and key in the SWEEP transaction, checkpoint the WAL, and delete its files after the commit; the relays drop the blobs by their bucket (§11.1).

### 6.1 Sources

- **Picker only.** `ActivityResultContracts.PickVisualMedia` (the system photo picker on API 30+ with Modular System Components; on API 29 it falls back to `ACTION_OPEN_DOCUMENT`, developer.android.com photo-picker page). No storage permission is requested (none is in T15). The GMS backport's `com.google.android.gms.metadata.ModuleDependencies` manifest entry is forbidden (ADR-06; G-M4).
- **No copy.** The content URI is read with `ContentResolver.openInputStream` straight into a `SharedMemory` region (images, ≤ 64 MiB) or handed to Transformer through Media3's `ContentDataSource` (video); nothing is copied to `cacheDir` or any file.
- **Image sources accepted:** JPEG, PNG, static WebP, and HEIC/HEIF/AVIF if the sandbox can decode them (V-M5; otherwise refused, Q9). Refused before decoding (magic-byte sniff in Rust): GIF, animated WebP, DNG and other RAW, BMP, ICO, WBMP, SVG, anything else. **Video sources:** MP4 and 3GP/QuickTime with H.264, H.265, VP9 or AV1 video that the device can decode; others are refused by Transformer's error, typed.
- **Limits before work:** image source ≤ 64 MiB and ≤ 100 megapixels (header), video source duration ≤ `VIDEO_MAX_MS` = 190 000 (the 50 MiB budget at the profile's bitrate, §8.3), or ≤ `VIDEO_MAX_MS_SHORT` = 100 000 in a conversation whose bucket is 1 h (class 8, R-MT2), each checked before a byte is re-encoded.

### 6.2 Preparation (no database transaction; the media worker thread)

**Image:** the sandbox's `STRIP_IMAGE` (§9.2), in a process instance of its own, decodes, orients, converts to sRGB, drops any gain map, downsizes to a 2 048-px long edge and re-encodes baseline JPEG with adaptive quality until the output is ≤ `IMAGE_MAX_CONTENT`; after the instance is torn down, the main process copies the output out of the shared region (so the bytes it checks are the bytes it seals, and no live sandbox can change them), runs `MediaNative.jpegCanonicalize` (§8.2) on its copy, builds a ≤ 320-px preview the same way (unless view-once), and feeds the canonical bytes to a sealer.

**Video:** Transformer transcodes to the profile of §8.3 through `GhostMuxer`, whose channel is a `SealingChannel` that hands every completed 262 128-byte chunk of plaintext to `MediaNative.sealAppend` and writes the four returned fragments as ciphertext files (§10.4). The sealer's fMP4 walker validates the stream as it passes and builds the `mfra` index, which `sealFinish` appends (§8.3). The preview is taken **before** sealing, from the first frame of the source: a Media3 player over `ContentDataSource` renders it into an `ImageReader` surface (the container is parsed by Media3's Java extractors and the frame decoded by `MediaCodec` out of process, the same surface Transformer's input already has), and the main process only rotates and scales its own pixels, compresses them and canonicalises the result; `sealFinish` then receives only the preview, and takes the output's dimensions and duration from its own walker (§3.5). Before `sealFinish`, `GhostTranscoder` requires Transformer's `ExportResult.videoEncoderName` to be non-null, and `audioEncoderName` to be non-null whenever the output has an audio track (each is null when no encoder ran for its track, i.e. when Transformer transmuxed it); otherwise it calls `sealAbort` and the preparation fails (`UNSUPPORTED_SOURCE`, counted; §8.3). `MediaMetadataRetriever` and Media3's `FrameExtractor` are not used (G-M3; the latter's platform-diagnostics behaviour is unknown). Rendering from the sealed object instead would need the manifest that the preview is part of.

**Files during preparation** get random names registered in the media actor's in-memory `preparing` set, so a concurrent reconcile keeps them (§10.4). An abort (`sealAbort`, a Transformer error, a size overflow, a process death) leaves orphans that the next reconcile deletes; the key never existed outside native memory (§3.7).

### 6.3 `MEDIA-COMMIT` (one transaction on the DM actor; `SEND`'s media half)

After `sealFinish` returned the manifest blob, its hash, `key_env`, the class and the hashes of the `F` fragments, and after every file was `force(true)`d and the directory synced:

1. Register `M_c` with `Namespaces.register(M_c, MEDIA, set(M_c, w), listen = false, LOCAL)` and install the `MD_{c,s}` credentials if absent (the F9 `EST-READY` pattern for `X_c`).
2. Insert the `dm_message` (direction `out`, kind 5, `body_env` = the caption, state `queued`) and the `dm_outbound_item` (kind 5, `l0_env` = the L0 with a zero key slot, state `pending`), exactly as F9 `SEND` does for a text **except that no ratchet step and no enqueue of the descriptor happen yet, and the sender countdown does not start** (D26): `expire_at_minute` is inserted as the upper bound `ceil_minute(deadline_hour + timer)` and lowered to `ceil_minute(end + timer)` when the upload ends, at `MEDIA-READY` or, for an object that never became ready, at the op deadline (a FAILED object may still be retried until then), an "only earlier" update that `dm_message_expiry` already admits (R-T6, `Schema.kt:1179-1185`).
3. Insert `media_object(object_id, role = 'out', dest_id = c, kind, view_once, class_code, manifest_hash, key_env, state = 'uploading', message_id)`, one `media_blob(hash, file_name, origin = 'sealed')` per blob, and the `media_fragment` rows (`state = 'bound'`, `upload_state = 'unsent'`, ordinal −1 for the manifest and 0 … F − 1).
4. Insert `media_upload(object_id, namespace = M_c, ttl, deadline_hour, retry_gen = 0)`.
5. After the commit, remove the object's names from `preparing` and post `MEDIA-FEED`.

The order follows the foreign keys (`media_upload → sync_namespace`, `media_object → dm_message`). If the contact has no usable session yet, the item waits exactly as a text does (F9 §5.5), and the upload proceeds meanwhile: `M_c` needs no session. A crash before the commit loses the preparation (orphans reconciled, no key anywhere); a crash after it resumes at `MEDIA-FEED`.

**Why the countdown waits for the upload (D26, Q26).** With the countdown from the commit (revision 1), a 5-minute message whose upload takes longer than 5 minutes expired mid-burst: the feeder stopped and relays saw fewer than `F + 1` stores cut off about 5 minutes after they began, with no descriptor after them, which a 1-hour timer in the same TTL bucket never produces. That separated 5-minute from 1-hour timers, which R-T1 (ADR-27 point 11) merges precisely so relays cannot tell them apart. Starting the countdown at the upload's end makes the burst's length a function of the class, the deadline (itself a function of the bucket) and the network only. The cost: the sender's caption and ciphertext live up to the op deadline plus the timer (for a 5-minute timer, at most about 1 h 5 min after the commit), declared in L8-M13.

### 6.4 Upload: `MEDIA-FEED`, outcomes, `MEDIA-READY`

State lives **per ordinal**, in `media_fragment.upload_state` (`unsent`, `open`, `sent`, `degraded`, `indeterminate`, `failed`), and **per op**, in `media_outbound_op(operation_id → object_id, ordinal, retry_gen, resend_count)`: Phase 7's `OutboundOutcome` names only an operation id and a namespace (`sync/api/Outbox.kt`), so the op table is what maps an outcome back to its blob, exactly as F9's `dm_outbound_op` does for DM items (`Schema.kt:1017-1027`). `media_upload.retry_gen` counts the user's retries of the object (0 … 3).

```
op_id = SHA-256("ghost/v1/media/op" || object_id(16) || i16_be(ordinal) || u8(retry_gen) || u8(resend_count))[0..16]
```

- **`MEDIA-FEED`** (DM actor; triggered by `MEDIA-COMMIT`, by `SyncChange.OUTCOMES` for `Consumer.MEDIA`, by a retry and by time-triggered passes; **never by an inbound blob**, T28): while the object has fewer than 32 ordinals `open`, the device has fewer than 64, and an ordinal is `unsent` (lowest first, the manifest first), read that blob from its file, verify its SHA-256 against the row, and in one transaction `Outbox.enqueue(OutboundBlob(op_id, M_c, bytes, ttl, deadline))` with `resend_count = 0`, insert its `media_outbound_op` row and set the ordinal `open`. Deterministic op ids make a repeated feed idempotent (`AlreadyEnqueued`). At most 64 × 64 KiB = 4 MiB of media payload sits in `outbox_op` at any time (D13). A file whose hash does not match its row (local corruption) makes the object `failed` with no retry (the ciphertext is gone; `retryMedia` answers `NOT_RETRYABLE` and the user must pick the file again).
- **`MEDIA-OUTCOME`.** For each released outcome of a media op (`Outbox.outcomes(Consumer.MEDIA)` then `release`, F7 §9), look the op up: an op whose row is gone (its message was deleted by the user) is released and ignored (counted). Otherwise: SENT or DEGRADED → the ordinal's final state; INDETERMINATE with `resend_count < 2`, before `resendNotAfter` and the deadline → the Phase 7 identical-bytes resend as a new op (`resend_count + 1`, same `retry_gen`; F9 §7.5's rule), the ordinal stays `open`; INDETERMINATE otherwise → final `indeterminate`; FAILED → the ordinal `failed`, the object `failed`, the feeder stops, the message becomes `failed`; its countdown still waits (a retry may follow until the deadline, and a retried burst must not be cut by the timer either, D26).
- **`MEDIA-READY`** (one transaction, when no ordinal is `unsent`, `open` or `failed`, i.e. all `F + 1` are final in {`sent`, `degraded`, `indeterminate`}): `state = 'uploaded'`; the sender countdown starts (`expire_at_minute` lowered, §6.3); the `dm_outbound_item` becomes sendable, and F9's `SEND` runs for it in the same actor pass (session selection, the key-slot `encrypt` of §4.2, seal, `Outbox.enqueue` into `X_c`). The descriptor is a user send that completes the user's action, so it follows G-DM2's caller list (extended, §16.1).
- **Deadline.** At `deadline_hour` an object still `uploading` or `failed` is (or stays) `failed` (the ops close in Phase 7 by the same deadline) and the message's countdown starts; `retryMedia` then answers `DEADLINE_PASSED`. A process that is not running at the deadline applies this at its next start; the inserted upper bound `deadline_hour + timer` bounds the row meanwhile.
- **Why a final INDETERMINATE counts.** A copy may exist on the relay, and Phase 7 cannot tell; blocking the descriptor would lose a message that is probably complete, while sending it risks a recipient-side `incomplete` state (§7.5), which the recipient sees and which the sender's UI can report as "may be incomplete". FAILED means no copy exists and blocks.
- **User retry of a FAILED object** before the deadline: `retry_gen + 1` (at most 3), the object back to `uploading`, the `failed` ordinals back to `unsent`; `sent`, `degraded` and `indeterminate` ordinals are **not** stored again (CS-M4), and the ordinals are fed from the **same ciphertext files** (no re-encryption; FAILED means no copy existed, F7 §9). The new op ids differ by `retry_gen`. After the deadline the facade answers `DEADLINE_PASSED` and the user must pick the file again (a new object).
- **Descriptor outcomes** follow F9 `OUTCOME`. For a view-once object the sender deletes its fragment rows, files and `key_env` (in one transaction, then the checkpoint of §11.1 and a reconcile) once the descriptor op has a **final** outcome other than FAILED: SENT, DEGRADED, or INDETERMINATE after its resends (INDETERMINATE has no later path that would need the copy); a FAILED descriptor keeps them for a retry until the deadline, then the same cleanup runs. For a normal object they stay until the message expires (§11.1).
- **Timing visible to relays.** The descriptor deposit into `X_c` follows the last media outcome, so AD-1 sees a burst into `M_c` and, shortly after, a 4 KiB deposit into `X_c` from the same client session (L8-M2).

### 6.5 Facade additions (`:messaging`, UI-less, for Phase 13)

```kotlin
fun sendMedia(contact: ContactId, source: MediaSource, caption: String?, viewOnce: Boolean): SendResult
    // QUEUED | TOO_LARGE | TOO_LARGE_FOR_TIMER | UNSUPPORTED_SOURCE | UNDECODABLE | KEY_CHANGED | BLOCKED | REVOKED
    // | REQUEST_NOT_ACCEPTED | NO_REPLICAS | LIMIT_REACHED | STORAGE_FULL | CRYPTO_UNAVAILABLE
    // (preparation runs after the call returns QUEUED; retryMedia may also answer DEADLINE_PASSED or NOT_RETRYABLE)
fun mediaState(message: MessageId): MediaStateView?   // kind, class, state, progress counts (fragments held / F); no times
fun openMedia(message: MessageId): MediaHandle?       // a reader over a verified object (§10.2); null otherwise
fun openViewOnce(message: MessageId): MediaHandle?    // §11.2; null if already viewed, not verified or not view-once
fun retryMedia(message: MessageId): SendResult        // FAILED objects only, before the deadline, at most 3 times
```

`MediaSource` wraps a content URI and nothing else. Every value type's `toString()` is redacted (T3). A `MediaHandle` is closed by the UI; closing zeroises the native reader.

### 6.6 Limits

`MAX_CONCURRENT_PREPARATIONS = 2`, `MEDIA_WINDOW_PER_OBJECT = 32`, `MEDIA_WINDOW = 64`, `MAX_RESENDS = 2` per ordinal and retry generation, `MAX_USER_RETRIES = 3` per object, `MAX_DECODER_PROCESSES = 2` live at once, `MAX_CAPTION_BYTES = 1 024`; a send is refused with `STORAGE_FULL` when free space is below `3 × F × 64 KiB` (the files, the outbox window and SQLCipher headroom). A send-side refusal is local and visible to nobody else; the receive side never refuses for space (§7.5).

---

## 7. Recipient pipeline (normative; ADR-41)

### 7.1 Automatic download, and why it is the only reflex-free choice

`M_0` is a listened namespace: Phase 7 lists it on its own pair schedule and fetches every listed blob within the media fetch budget (§5.5), exactly as it fetches `X_0`. The media actor claims `Consumer.MEDIA` blobs and moves them into the ciphertext store.

- **No reflex (T28, T41).** Nothing the recipient receives, decrypts, validates or views, and no local state (the pool's occupancy, which blobs are bound, free space), changes what it asks relays for: the `get`s on `M_0` follow the stores others made into `M_0` (declared in LIMITE L2.1 #3 and F9 §11.1), never a descriptor. A descriptor withheld by a relay and one delivered produce identical normalized relay views (NI-M1), also when the pool is full (NI-M6).
- **Rejected: fetch on descriptor** (`Inbox.want`, F7:1419). It needs a "want pair" schedule the engine lacks (the fetch step runs only in a read pair's bundle, `ghost/android/sync/src/main/kotlin/org/ghost/sync/engine/WorkLane.kt:77-83`) and it is a reflex: the relay sees `X` consumed, then `M` fetched, linking the descriptor to its object and timing the consumer.
- **Rejected: fetch on tap.** The first `get` of an object tells the relay when the user looked (for view-once, when it was opened): a read receipt to the relay.
- **Cost, declared.** Every object deposited into my `M` is downloaded, bounded only by what the depositors can pay for (§5.3: the allowances of every relay of my union set, plus a hostile card holder's own tokens), including from contacts I have blocked (they keep my card) and from card holders who spam. A Phase 13 global "pause media download" is a user action that turns `M_0`'s listening off (relays then see the listening stop; L8-M3). Q4 keeps the choice with the owner.

### 7.2 Ingest, descriptors, binding (transactions on the media actor unless stated)

The ciphertext store is **content-addressed with references** (D25): one `media_blob(blob_hash, file_name, origin, retain_until_day)` row and one file per distinct hash, and `media_fragment(object_id, ordinal) → blob_hash` rows that name blobs; any number of objects may name one hash. A blob is **pooled** when no `bound` fragment row names it.

- **`MEDIA-INGEST`** (media actor): for each claimed blob (`Inbox.claim(MEDIA, 32)`): check `|blob| = 65 536` (anything else is consumed and dropped, counted); if a `media_blob` with that hash already exists (a second relay's copy, a replay), consume it without writing a file; else write it to a new random-named file, `force(true)`, sync the directory; then one transaction: `Inbox.markConsumed`, insert `media_blob(hash, file_name, origin = 'ingested', retain_until_day = min(day(E) + 1, today + 8))` with `E = InboundBlob.relayExpiryHour`, and set **every** `expected` fragment row naming that hash, of any object, to `bound`. Then apply the pool rule of §7.5 (eviction, never a stop). A crash between the file write and the commit leaves an orphan file (reconciled) and an unconsumed row (offered again); nothing is lost and no file is written twice.
- **Descriptor (inside F9 `RECV` or the held replay, DM actor).** A kind-5 L0 from a contact, returned by `decrypt` or `sessionInbound` with its `key_env` (§4.2), creates the message row as F9 does and, through `MediaObjects.onDescriptor(tx, messageId, contactId, body, key_env)`, a `media_object(role = 'in', dest_id = contactId, state = 'awaiting', key_env, manifest_hash, kind, flags, class, incomplete_after_hour = relayExpiryHour of the descriptor blob)`. A second descriptor naming an existing `object_id` is `drop(duplicate_object)` for the object (the message follows F9's dedup); `object_id` never appears outside E2E encryption, so a third party cannot squat it.
- **`MEDIA-BIND`** (media actor; runs when an `awaiting` object's manifest hash has a `media_blob`, or when a manifest blob is ingested for an `awaiting` object): read the manifest file, verify its hash, call `MediaNative.readerOpen` (§13.2), which unwraps `key_env` under its binding, checks the commitment, opens the manifest, parses it strictly and compares `object_id`, `kind`, `flags`, `class_code` with the descriptor, then closes the reader (the key leaves native memory again); then in one transaction insert one `media_fragment` row per ordinal, `bound` if a `media_blob` with that hash exists and `expected` otherwise, whether or not another object names the same hash; set `state = 'fetching'`. A manifest that does not open, or disagrees with its descriptor, makes the object `corrupt` (counted; the message shows "media unavailable").
- **Ownership is decided by authentication, never by arrival order.** A card holder who can list `M` (L7-D16) and names another sender's fragment hashes in its own manifest only makes its **own** object fail in `MEDIA-VERIFY` (`AD_c` binds `object_id` and the chunk key is its own), and the honest object verifies from the same files. Revision 1's "a hash already bound to another object is `corrupt` for the newer one" let such a card holder capture fragments during a victim's upload and make the victim's object `corrupt`; it is removed.
- **Releasing references.** An object that becomes `corrupt` or `incomplete` deletes its fragment rows and sets its `key_env` to NULL in the same transaction (the checkpoint of §11.1 follows); an `ingested` blob that no row names any more returns to the pool with its original `retain_until_day` (another object's descriptor may still arrive for it), a `sealed` one is deleted. An erasure (SWEEP, view-once close, the sender's view-once cleanup) deletes the object's rows **and** every blob no row names any more, whatever its origin; a blob another live object still names stays until that object releases it (only possible when a card holder names the same hashes; declared in P-M8).
- **Completeness.** When the last `expected` row of an object is bound, the object becomes `complete` and `MEDIA-VERIFY` is queued.

### 7.3 `MEDIA-VERIFY` (the full validation pass before any exposure; RQ-M6)

On the media actor, outside a transaction: open a reader, feed every chunk in order to `readerChunk(mode = validate)`, which authenticates it, checks the pad and runs the canonical walker (§8.2, §8.3); then `readerValidateFinish`, which also compares the manifest's dimensions and duration with the walked stream (§3.5). One transaction records `verified` or `corrupt` (a `corrupt` object releases its references, §7.2). Nothing is shown before `verified`; plaintext exists only chunk by chunk in native memory and is zeroised. A file found corrupted **after** `verified` (a hash or tag failure while reading, §15.8 item 3) makes the object `corrupt` too: the reader fails with `HASH_MISMATCH` or `NOT_OPEN`, the player ends with a typed error, and one transaction records `verified → corrupt`.

### 7.4 Display

- **Previews** are decoded in the sandbox only while the conversation is on screen (never in the background, never for a **request** from an unknown card holder or a blocked contact until the user accepts; F9 §12.3), kept in a bounded RAM cache (§10.5).
- **Images:** the reader decrypts the object into a `SharedMemory` region (≤ 1 MiB), the sandbox decodes it (§9.2), the main process wraps the returned pixels in a `Bitmap`.
- **Video:** Media3 plays the verified object through GHOST's `DataSource` (§10.2).
- **The sender's own objects** are opened the same way; the sealer's walker already validated every byte, so an `out` object in `uploading`, `uploaded` or `failed` state is readable without `MEDIA-VERIFY` (a view-once object only until the sender's cleanup, §6.4).
- **Countdown.** `markDisplayed` starts the message's recipient countdown as for text (F9 §10.3; ADR-27 point 9); opening the full media does not restart it.

### 7.5 Incomplete, expired, unmatched

- An object not `complete` by `incomplete_after_hour` (the descriptor's relay expiry; by R-MT3 every honest fragment has expired by then) becomes `incomplete` (declared loss, L8-M5); it releases its references (§7.2).
- A pooled blob past `retain_until_day` is deleted with its file: unmatched blobs live at most eight days or until their relay expiry, whichever is first. A descriptor that F9 holds undecrypted behind a key change (F9 §8.3, up to 30 d + 1 h) for more than eight days therefore finds its fragments gone and the object becomes `incomplete` (declared, L8-M5); keeping unmatched blobs longer would let a card holder pin disk space for a month.
- **`POOL_CAP` = 512 MiB of pooled files, enforced by local eviction, never by fetching less.** After every ingest transaction, while pooled bytes exceed `POOL_CAP`, the pooled blobs with the earliest `retain_until_day` (ties by hash) are deleted, rows in the transaction and files by the reconcile. `MEDIA-INGEST` **keeps claiming** and Phase 7 keeps fetching, so the `get`s on `M_0` stay a function of what others stored and never of what is pooled, bound, withheld or delivered. Revision 1 stopped claiming at the cap, which filled `FETCHED_CAP` and stopped the `get`s (F7:850); since binding frees pool space, a delivered descriptor and a withheld one then led to different fetching near the cap, a relay-visible reflex (T28, T41) that NI-M1 did not exercise; NI-M6 now does. The cost: under a flood an honest object whose descriptor arrives late can find its fragments evicted and become `incomplete` (declared, L8-M4).
- **Free-space floor.** Below `MEDIA_FREE_FLOOR` = 256 MiB of free device storage, `MEDIA-INGEST` consumes each claimed blob **without** writing a file (counted, the object may become `incomplete`), again so that local state never changes what is fetched.

### 7.6 Object states (each transition has a trigger in the schema, §13.6)

| Role | States | Driven by |
|---|---|---|
| out | `uploading` → `uploaded` / `failed`; `failed` → `uploading` (user retry before the deadline, at most 3); any → `gone` | MEDIA-COMMIT, MEDIA-FEED, MEDIA-OUTCOME, MEDIA-READY, retry, deadline, SWEEP |
| in | `awaiting` → `fetching` / `corrupt`; `fetching` → `complete`; `complete` → `verified` / `corrupt`; `awaiting`/`fetching` → `incomplete`; `verified` → `corrupt` (on-disk corruption found while reading, §7.3); `verified` → `undecodable` (two sandbox failures, §9.2); `verified` → `viewing` → `viewed` (view-once only); any → `gone` | RECV, held replay, MEDIA-BIND, MEDIA-INGEST, MEDIA-VERIFY, reader, display, VIEW-ONCE-OPEN/CLOSE, MEDIA-GC, SWEEP |

`gone` exists only inside the transaction that deletes the row; it is a trigger-checked transition name, not a stored state.

---

## 8. Canonical formats and metadata stripping (normative; ADR-42; T37 = T5 made exact)

### 8.1 Principle

Metadata is removed by **re-encoding**, never by editing the source, and the output is proved clean by **canonicalisation and validation in Rust** twice: the sealer refuses to seal a non-canonical stream on the sender, and the reader refuses to show one on the recipient. Surgical stripping is rejected because the places metadata hides are open-ended: JPEG APP segments, IFD1 thumbnails that can show the uncropped original, MPF secondary images, bytes after EOI (a Motion Photo appends a whole MP4 with its own atoms; Samsung's SEFT trailer carries a country code and depth maps), PNG text chunks, HEIF items, MP4 `udta`, `meta`/`keys` and `uuid` boxes, telemetry tracks and H.264 SEI user data. AndroidX `ExifInterface` writes only JPEG, PNG and WebP and edits only EXIF and XMP (platform-media digest, B3), so it cannot be the stripper.

### 8.2 Images: re-encode, canonicalise, validate

**In the sandbox (`STRIP_IMAGE`):** decode with `ImageDecoder.createSource(ByteBuffer)` (software allocator), a header listener that refuses more than 100 MP and sets a target size for a ≤ 2 048-px long edge, `setTargetColorSpace(SRGB)`; apply the EXIF orientation if `ImageDecoder` did not (V-M4: ExifInterface in the sandbox is the fallback); composite any alpha onto white; `setGainmap(null)` on API 34+; `Bitmap.compress(JPEG, q)` with q = 85, 80, … 60, then scale by 0.85 and repeat, until the output is ≤ 1 048 512 B.

**Canonical JPEG profile (`ghost-client-media::jpeg`).**

| Allowed | Refused |
|---|---|
| `SOI`; `DQT` (8-bit, 1–4 tables); `SOF0` only (baseline, 8-bit, 1 or 3 components, width and height 1 … 2 048 for an object, 1 … 320 for a preview; the walker reports them to the sealer and the reader, §3.5); `DHT`; `DRI`; `SOS`; entropy-coded data with `RST0`–`RST7`; `EOI` | every `APP0`–`APP15` (JFIF, EXIF, XMP, ICC, MPF, IPTC, JUMBF/C2PA, Adobe), `COM`, `SOF1`–`SOF15` other than `SOF0` (progressive, lossless, arithmetic), `DNL`, `DAC`, `DHP`, `EXP`, reserved markers, **any byte after EOI**, a missing EOI, a second SOI |

- `jpegCanonicalize` (sender, over GHOST's own encoder output only) drops `APP0`–`APP15` and `COM`, keeps the allowed segments byte for byte, and fails on anything in the refused column; the security property comes from the re-encode (only pixels cross), the profile makes it checkable. Whether Skia writes `APP0`, an ICC `APP2`, or Ultra HDR `MPF` with a trailing gain-map image is not documented (V-M6); the canonicaliser removes the first two, and a trailing image after EOI fails the send, which S0 must show never happens once the gain map is dropped.
- The recipient's reader requires `canonicalize(x) = x` for the object and for the preview: a sender with a modified client cannot deliver a JPEG outside the profile to a decoder.

### 8.3 Video: transcode, GhostMuxer, sealed stream

**Transformer configuration.** `Transformer.Builder(context)` with `setVideoMimeType(VIDEO_H264)`, `setAudioMimeType(AUDIO_AAC)`, a `Presentation` capping the long edge at 1 280 px (720p) and 30 fps, an encoder factory requesting 2 000 000 bit/s video and 128 kbit/s AAC, `setUsePlatformDiagnostics(false)` (Media3 `Transformer.Builder`), an asset loader reading the source through `ContentDataSource` only, and `setMuxerFactory(GhostMuxer.Factory)`.

**Encoding is forced (D15).** These settings alone do **not** force a transcode: "If the input media format already matches the configurations for audio or video, Transformer automatically switches to transmuxing" (Media3 Transformer documentation, Transformations page). In `TransformerUtil.shouldTranscodeVideo`, a single-item composition whose encoder factory does not require encoding, with HDR mode "keep", the requested MIME type equal to the input's, square pixels, default speed and only no-op or rotation effects (a `Presentation` whose output size equals the input size is a no-op) is transmuxed; `shouldTranscodeAudio` transmuxes AAC input when no audio processor is set. A phone video that is already H.264 + AAC at ≤ 720p would then reach the recipient as the camera's own bitstream: its SPS/VUI encoder fingerprint, its original bitrate (breaking the `VIDEO_MAX_MS` budget) and any AAC data-stream or fill elements. So:
1. `GhostTranscoder`'s `Codec.EncoderFactory` overrides `videoNeedsEncoding()` and `audioNeedsEncoding()` to return `true` (both default to `false`; `Codec.java`), which makes both `shouldTranscode…` functions return `true` first;
2. HDR sources are tone-mapped to SDR (the Composition HDR mode, not "keep HDR"), so the output is always 8-bit SDR H.264 (checked with V-M17);
3. before `sealFinish`, the export must name its encoders (`ExportResult.videoEncoderName` non-null, and `audioEncoderName` non-null when the output has audio; each is "null if none were used", `ExportResult.java`), or the preparation is aborted and its orphans reconciled (§6.2);
4. the T5 corpus includes sources that already match the output (H.264 + AAC, ≤ 720p30, SDR, square pixels) with distinctive SPS/VUI values and a canary in an AAC data-stream element (§15.7), and mutant PM-M18 ("transmux allowed") must be caught. Transformer's `start(…, path)` needs a path; `GhostMuxer.Factory.create(path)` ignores it. The Transformer class itself creates, deletes and checks no file (its source, read 2026-09-25); whether any component it drives writes a file is V-M1, checked in S0 by a file-inventory and `FileObserver` probe over every app directory.

**`GhostMuxer`** implements `androidx.media3.muxer.Muxer` around `FragmentedMp4Muxer.Builder(WritableByteChannel)` (the `Mp4Muxer` alternative needs a `SeekableMuxerOutput` and seeks back to patch the `mdat` size and to rewrite `moov` near the end, `Mp4Writer`, so it cannot feed a one-pass sealer; `FragmentedMp4Writer` is strictly sequential):
1. **No metadata passes.** `addMetadataEntry` forwards nothing except `Mp4OrientationData` with 0/90/180/270 and one `Mp4TimestampData` with constant creation and modification times, set by `GhostMuxer` itself (Media3's `MetadataCollector` otherwise stamps `System.currentTimeMillis()`). Location (`Mp4LocationData`), `XmpData` and every `MdtaMetadataEntry` are dropped, which is exactly what Media3's own `InAppMp4Muxer` would have forwarded (`MuxerUtil.isMetadataSupported`, platform-media digest B2).
2. **Only video and audio tracks.** Any other track the asset loader offers is refused.
3. **SEI filter.** Each H.264 sample is split into NAL units; SEI NAL units are kept only if every payload type is buffering period (0), picture timing (1) or recovery point (6); user-data SEI (payload types 4 and 5, where encoders write version strings) and any other are dropped before the sample reaches the muxer. V-M12 measures what reference encoders emit.
4. **Fragments of 2 s** (`FragmentedMp4Muxer`'s default fragment duration).

**`SealingChannel`** buffers bytes into 262 128-byte chunks and calls `sealAppend`; the native sealer runs the **fMP4 walker** on every chunk and, at `sealFinish`, appends a GHOST-built `mfra` box (`tfra` for the video track with one entry per `moof`, then `mfro`), because `FragmentedMp4Muxer` writes no `sidx`, `mfra` or `tfra`, and Media3's `FragmentedMp4Extractor` without them outputs `SeekMap.Unseekable` unless `FLAG_READ_MFRA_FOR_SEEK_MAP` is set and an `mfra` exists (its source, read 2026-09-25). Seeking therefore needs this index (FR-7.4's seek test; V-M2 checks that every fragment starts with a sync sample and that the extractor seeks with the flag).

**Canonical fMP4 profile (`ghost-client-media::fmp4`).** Top level exactly `ftyp`, `moov`, then (`moof`, `mdat`) pairs, then `mfra`; inside, only the box types and fixed field values that `FragmentedMp4Muxer` 1.11.x writes for one AVC and one AAC track, **pinned by S0 goldens** (the F9 practice of freezing `O_MAX` from a measurement): `mvhd`, `tkhd` and `mdhd` times equal the constant; `hdlr` names from a fixed list; no `udta`, `meta`, `ilst`, `keys`, `uuid`, `free`/`skip`, `sidx`, `edts` unless the goldens show them; `tfra` entries point at `moof` boxes whose `tfdt` matches; sample tables and `trun` offsets stay inside their `mdat`; AVC samples contain only NAL types 1, 5, 6 (allowed payloads), 7, 8 and 9; the `avc1` sample entry and `tkhd` agree on the dimensions (≤ 1 280 each) and the video track's summed `trun` durations give the duration (§3.5). Anything else is `NON_CANONICAL`: the sender cannot seal it and the recipient does not play it. A Media3 bump re-records the goldens (G-M8).

**AAC is outside the walker's reach (declared; Q35).** The walker checks the AAC track's sample entry (`mp4a` with an `esds` naming AAC-LC, 44.1 or 48 kHz, one or two channels) and the sample sizes and offsets, but not the raw data blocks: finding element boundaries inside an AAC frame means Huffman-decoding the spectral data of every channel element, a codec, not a parser. AAC's data-stream (`ID_DSE`) and fill (`ID_FIL`) elements can carry arbitrary bytes. For the honest pipeline this does not matter: audio is always re-encoded (forced encoding above), so no source byte reaches it, and V-M12 records whether the reference encoders emit DSE or non-zero FIL payloads. A modified sender can put bytes there; they reach only the recipient's out-of-process AAC decoder, which ignores them, and never a metadata parser. P-M6 states the limit.

### 8.4 Why the defaults are not used (facts read in Media3 1.11.1 sources, 2026-09-25)

- `InAppMp4Muxer` (Transformer's default) opens `new FileOutputStream(path)`: a plaintext file by construction.
- `BoxParser` reads `©xyz` into `Mp4LocationData` and `mvhd` into `Mp4TimestampData`; `MuxerWrapper` forwards every `Format.metadata` entry; the MP4 muxers accept location, timestamps, XMP and string or float `mdta` entries. A default transcode of a phone video therefore carries its GPS, creation time and `com.android.*` keys into the output (platform-media digest B2; AOSP `MPEG4Writer` writes `com.android.version`, optionally manufacturer and model, capture fps and `©xyz`).
- Media3's `AesCipherDataSource` is `AES/CTR/NoPadding` (`AesFlushingCipher`): unauthenticated, so it cannot satisfy step 7.

### 8.5 What survives, by design (declared; L8-M9, L8-M10)

The correspondent receives pixels and sound. Re-encoding does not remove the camera sensor's noise pattern (PRNU), which can link photos to one camera; the sender's video encoder leaves stream parameters (SPS/PPS/VUI) typical of a device class; dimensions, duration and aspect ratio reach the recipient; C2PA provenance, where the source had it, is removed with the rest. Watermarking is P2 (LIMITE:138).

---

## 9. Decoding attack surface and isolation (normative; ADR-42; T40)

### 9.1 Surfaces

| Surface | Who controls the bytes | Where it runs | Control |
|---|---|---|---|
| Received image and preview | any contact, a modified client | **isolated process** (platform `ImageDecoder`, libjpeg-turbo in Skia) | canonical JPEG only, validated before the sandbox sees it; dimensions ≤ 2 048 (object) or ≤ 320 (preview); one request per process instance |
| Picked source image (user's own file, possibly downloaded from anywhere) | whoever made the file | **isolated process** | magic-byte allowlist first; 64 MiB and 100 MP limits |
| Received video container | any contact | main process: Media3 `FragmentedMp4Extractor` (Java, memory-safe) | canonical fMP4, validated end to end before playback; only that extractor is registered |
| Received video bitstream | any contact | `MediaCodec`: the codecs run in the platform's media processes, not in the app; since Android 10 software codecs run in a constrained process with tightened SELinux and seccomp (Android Developers blog, 2019-05) | canonical fMP4; only H.264 and AAC |
| Picked source video | the file's author | main process: Media3 extractors (Java); codecs out of process | Transformer's typed errors |

The record motivates the isolation: libwebp CVE-2023-4863 was exploited in the wild; the LANDFALL spyware used a malformed DNG against Samsung's `libimagecodec.quram.so` (CVE-2025-21042) through a messaging app; the Android bulletin of 2026-09 lists a Critical remote-code-execution fix in the System component's media codecs (CVE-2026-28618, no user interaction needed) and a High remote-code-execution fix in the Framework (CVE-2026-28609). Platform decoders are patched by monthly updates and Mainline, which de-Googled or unpatched devices may not receive; the app cannot fix them, only confine them.

### 9.2 The isolated decoding service

- **Manifest:** `<service android:name="org.ghost.media.sandbox.MediaDecodeService" android:isolatedProcess="true" android:process=":mdec" android:exported="false">` with no intent filter. An isolated service "runs under a special process that is isolated from the rest of the system and has no permissions of its own" (Android `<service>` reference): no network (no INTERNET), no access to GHOST's files, database or Keystore.
- **One process instance per request (D17, Q25).** The main process binds with `Context.bindIsolatedService(intent, BIND_AUTO_CREATE, instanceName, executor, connection)` (API 29 = minSdk) and a **fresh random `instanceName` per request**: without `BIND_SHARED_ISOLATED_PROCESS`, each instance name gets its own isolated process. After the reply (or a failure) it unbinds, and the instance's process dies, taking decoded plaintext with it. A `STRIP_IMAGE` and a `DECODE_IMAGE` never share an instance, and neither do two objects (an image's preview and its full decode are two requests). Lock and wipe unbind every instance at once. At most `MAX_DECODER_PROCESSES = 2` instances live at a time. **Why:** revision 1 kept one `:mdec` process for 30 s after the last request and served both operations from it; an exploit delivered by one image (received, or a file the user picked) then stayed resident, saw every later decoded image from every contact, and produced the "re-encoded" JPEGs of the user's next sends, where it could hide other contacts' pixels in entropy-coded data that still passes the marker-level canonicaliser, for GHOST's own send path to deliver. With one request per process, an exploit sees only the bytes of its own request. The cost is one isolated-process start per request, measured in S0a (V-M18); if it is too slow for previews, Q25's fallback batches the previews of one sender on one screen into one instance (weaker, declared).
- **The Application does nothing in the isolated process (V-M19).** Android instantiates the app's `Application` in every process, including isolated ones; `GhostApp.onCreate` (`GhostApp.kt:146-158`) runs `wiring.onProcessStart()` and `messagingWiring.onProcessStart(keys.exists())`, which open no-backup files, the Keystore and system services an isolated process may not touch, so `:mdec` would fail on every bind. `GhostApp.onCreate` therefore returns right after `super.onCreate()` when `Process.isIsolated()` (API 28+), before any lazy field is touched; `MediaDecodeService` uses only the platform decoder APIs. An emulator test binds the service on API 29, 35 and 37 and decodes a canonical JPEG (T40 suite), and mutant MC-M23 (the early return removed) must fail it.
- **Protocol.** A Binder interface with exactly two operations, inputs and outputs in `SharedMemory` regions the main process creates, maps and unmaps: `STRIP_IMAGE(encoded source, maxEdge, maxBytes) → encoded JPEG` (§8.2) and `DECODE_IMAGE(canonical JPEG, maxW, maxH) → ARGB_8888 pixels, w, h`. Input regions are set read-only (`SharedMemory.setProtect(PROT_READ)`) before they are passed. Type sniffing is not the sandbox's job: `MediaNative.sniff` (Rust, main process) reads the first 64 bytes and refuses anything outside the source allowlist before the sandbox sees a byte. The main process checks every answer **on its own copy, taken after the instance is unbound** (no live sandbox can change the bytes between the check and the use): `w` and `h` in range and `size = w · h · 4` for pixels, `jpegCanonicalize` for re-encoded output; it parses nothing else the sandbox returns. Every region is zero-filled before it is unmapped and closed.
- **Parcel discipline.** The interface's parcels carry only `SharedMemory` handles and ints; a malformed reply (wrong handle count, a size mismatch) is a failure, never parsed further. The sandbox has no callback into the main process.
- **Failure.** A timeout (10 s per request), a crash of the instance (`DeadObjectException`) or an out-of-range answer is a typed failure; after two failures on one object the object is `undecodable` and is never offered to the sandbox again (the F9 poison-guard idea; CS-M8). A crash leaves a tombstone the OS writes (§10.3).
- **Unknowns (S0).** Whether HEIF and AVIF decode inside an isolated process (they need the platform's HEVC or AV1 decoder, V-M5); the per-instance start cost (V-M18); whether `memtagMode` can be set for `:mdec` alone (MTE only helps on MTE hardware, V-M15; Q21).

### 9.3 Zero-click policy

Nothing is decoded in the background. A preview is decoded only while its conversation is on screen; requests and blocked contacts are never decoded (§7.4). `MEDIA-VERIFY` parses containers (Rust walkers, memory-safe) and authenticates, but does not decode pixels or samples.

---

## 10. Playback and the no-plaintext-at-rest rule (normative; ADR-42; T38)

### 10.1 The rule

The only persistent bytes of a media object anywhere on the device are its E2E ciphertext blobs, byte-identical to relay blobs, in `noBackupFilesDir/m/`, plus its rows (§13.6). Plaintext (content, previews, decoded pixels, decrypted chunks, captions outside `body_env`) exists only in RAM, and only while shown or being prepared.

### 10.2 Media3 configuration

- `GhostMediaDataSource` implements Media3's `DataSource` over one open reader: `open` returns the content length; `read(buffer, offset, length)` maps the position to a chunk, fetches its four fragment files, calls `readerChunk(mode = read)` into a direct buffer and copies into Media3's array; at most two decrypted chunks are cached in native memory and zeroised on eviction and at `close`.
- The player is `ExoPlayer.Builder(context, ProgressiveMediaSource.Factory(ghostDataSourceFactory, fmp4OnlyExtractorsFactory))` with `setUsePlatformDiagnostics(false)` and a `DefaultLoadControl` of 5–15 s and at most 8 MiB of buffer (Media3's defaults buffer 50 s and up to about 125 MiB of video). The extractors factory returns only `FragmentedMp4Extractor` with `FLAG_READ_MFRA_FOR_SEEK_MAP`.
- `androidx.media3.common.util.Log.setLogLevel(Log.LOG_LEVEL_OFF)` at process start (an `@UnstableApi` public call).
- No `MediaSession`, no notification, no background playback: the player pauses at `onStop` and is released at lock (Android 17 also requires a foreground service for background audio in apps targeting 37, which GHOST does not declare).
- **Declared:** Media3's sample buffers are Java arrays in the JVM heap, so decrypted video exists there while it plays (L8-M7); `MediaCodec` itself reports metrics to the platform, which `setUsePlatformDiagnostics(false)` does not stop (Media3 documentation; L8-M8).

### 10.3 Inventory of plaintext sinks and their controls

| Sink | Control | Test |
|---|---|---|
| Media3 `SimpleCache`, `CacheDataSource`, `CacheDataSink`, `CacheWriter`, `DownloadManager`, `DownloadService`, `DownloadHelper` (shipped inside `media3-datasource` and `media3-exoplayer`, so a dependency ban cannot exclude them) | G-M1 source ban; release-dex check where R8 allows it (V-M14) | PM-M10 |
| `DefaultDataSource`, `DefaultHttpDataSource`, `HttpEngineDataSource`, `UdpDataSource` (clearnet paths `kotlin-clearnet.sh` cannot see in library bytecode) | G-M1; player built only through `GhostMediaDataSource` | static; T6 dynamic (Phase 13) |
| Transformer's default muxer and output path | G-M1 (`InAppMp4Muxer`, `Transformer.start` outside `GhostTranscoder`); V-M1 | sandbox scan |
| Temp and cache files (`createTempFile`, `cacheDir`, `codeCacheDir`, `openFileOutput`, external dirs, `getExternalMediaDirs`) | G-M1; the only file writer is `CiphertextFiles` | sandbox scan |
| `MediaStore` inserts, `MediaScannerConnection` (an insert records GHOST as `OWNER_PACKAGE_NAME`) | G-M1 | `MediaStore` query on the emulator |
| Share intents, `FileProvider`, clipboard, drag and drop | G-M1; T24 (Phase 13) | static |
| Notifications with pictures (`BigPictureStyle`, `setLargeIcon`) | G-M1; T11 | static |
| Thumbnails and previews | RAM cache only (§10.5) | sandbox scan, PM-M9 |
| Logs, crash text | Media3 logging off; T3 canaries | logcat marker scan (F9 §22.32) |
| Backup, device transfer | `allowBackup="false"`, data extraction rules exclude everything; the store is under `noBackupFilesDir` | T4 on the emulator |
| Isolated process memory | one process per request, dead after the reply (§9.2) | T40 PID test; PM-M21 |
| **Task snapshots (OS-written)**: Android persists a Recents snapshot of the last frame as a `.jpg` under `/data/system_ce/<user>/snapshots` (AOSP `TaskSnapshotController.SNAPSHOTS_DIRNAME = "snapshots"`, `BaseAppSnapshotPersister.BITMAP_EXTENSION = ".jpg"`) | every window that shows media, including the gate harness's activity, sets FLAG_SECURE and, on API 33+, `setRecentsScreenshotEnabled(false)` from Phase 11 (T10's rule brought forward for media windows, X-M11, D27); what API 29–32 persist for a FLAG_SECURE window is measured (V-M20) | emulator scan of the snapshot directory with `adb root` (§15.8 item 1); PM-M23 |
| **Tombstones, dropbox, bug reports (OS-written)**: a crashed decoder's tombstone holds its registers, stack and memory near them, so plaintext fragments of the decoded image; `/data/tombstones` and dropbox entries are included in an `adb bugreport` taken on the unlocked device, so they are **not** root-only | the process per request limits a tombstone to one request's bytes; nothing else is possible from the app | declared (L8-M8); the emulator scan lists what a forced `:mdec` crash leaves (V-M20) |
| **Storage-backed swap (OS-written)** on devices that write compressed RAM to flash (zram writeback, vendor "RAM extension" features) | none possible from the app | declared, [I] (L8-M8) |

### 10.4 The ciphertext store

- One file per blob, 65 536 B, random 16-byte hex names, in `noBackupFilesDir/m/`, written by `CiphertextFiles` only (a port with a fault-injecting test implementation, §15.3); every write is `force(true)` and the directory is synced before the transaction that references the file.
- `setLastModified(0)` after each write so that `mtime` carries no time (V-M16 checks that it holds on f2fs and ext4 app directories); `ctime` cannot be set by an app (L8-M6).
- **Reconcile** (media actor): list the directory; delete every file that no `media_blob` row names and that is not in `preparing`; sync the directory. It runs after every transaction that deletes media rows (SWEEP through `MediaPort`, view-once close, `incomplete`, `corrupt`, pool eviction and GC, view-once sender cleanup) and at process start. A crash between a deletion's commit and the reconcile leaves ciphertext whose key is already erased; the next reconcile removes it.
- **Why files, not SQLCipher BLOBs (Q18).** Up to 51 MiB per object would pass through the WAL, the database file never shrinks after deletion (a forensic high-water mark), and video reads would contend with DM transactions on the primary connection (`SupportSqlExecutor` holds it for a whole transaction). The cost of files is inode times (L8-M6), declared.

### 10.5 RAM hygiene

Decoded previews live in one `LruCache` of at most 16 MiB, cleared at lock, wipe, `onTrimMemory(TRIM_MEMORY_UI_HIDDEN)` and when an object is deleted; image bitmaps are recycled when their screen closes; native buffers are zeroised on release; readers close at lock. Readers ≤ 8, sealers ≤ 2 per context; `ctxClose` closes all of them.

---

## 11. Ephemeral media and view-once (normative; ADR-43)

### 11.1 Ephemeral media (P0; ADR-27 point 10)

- **Deletion cascade.** F9's `SWEEP` calls `MediaPort.onMessagesDeleted(tx, ids)` before deleting the messages (`Sweeper.kt:311-314`); the implementation deletes, in that transaction, every `media_object` of those messages with its `key_env`, `media_upload`, `media_fragment` and `media_outbound_op` rows and every `media_blob` no remaining fragment row names (the FK from `media_object.message_id` also cascades from any other deletion of a message, such as a deleted contact; `MediaObjects` deletes the unnamed blobs in that path too), then posts a reconcile after the commit.
- **Checkpoint after every key deletion (RQ-M12; P-M8).** `secure_delete = ON` zeroes freed pages, but an updated or deleted `key_env` survives in two places until a checkpoint: the pre-image page in the main `.db` file (WAL mode writes the new page to the WAL; the checkpoint copies it back over the old one) and the WAL frames. So **every transaction that deletes or nulls a `key_env`** (SWEEP, `VIEW-ONCE-OPEN`, the sender's view-once cleanup, `MEDIA-GC`, the `incomplete` and `corrupt` paths, a contact deletion) is followed by F9 §10.7's checkpoint: `PRAGMA wal_checkpoint(TRUNCATE)`, require `busy = 0`, retry 3 times 100 ms apart, else keep `checkpoint_due` and retry at the next sweep (R-K1's checkpoint at every open also applies). `VIEW-ONCE-OPEN` runs it before returning the handle (§11.2). What remains below the file system (flash blocks of the truncated WAL) is outside the app's reach, as for every F9 deletion.
- **Sender.** The sender's copy (files and key) lives as long as its message row, whose countdown starts when the upload ends (D26, §6.3): at `MEDIA-READY`, or at the op deadline for an object that never became ready. A message therefore never expires mid-upload. If the **user** deletes the message or the contact during an upload, the rows and key go at once, the feeder stops, unreleased ops run to their outcome or deadline with ciphertext nothing on the device opens (F9 §21.10: no `Outbox.cancel`; their outcomes are released and ignored), and the descriptor is never sent: a short burst, declared in `LM`.
- **Recipient.** The object goes with the message: at `expire_at_minute` after display, or at the unread deadline `min(E, consume + bucket + 1 h)` (F9 §10.3). An object still `awaiting` or `fetching` goes the same way; blobs arriving later are pooled and dropped at their retention day.
- **Relays.** Honest relays drop fragments and manifest by `deadline_hour + bucket + 1 h` (T30), fragments no later than the descriptor (R-MT3). Every media store receipt passes F9 §10.2 point 6's upper bound, so a relay promising to keep a blob more than σ = 3 d longer than its bucket is detected (and one within σ is tolerated, L7-D27, which applies unchanged). A dishonest relay may keep ciphertext anyway; without `K_f`, erased on both devices, it opens nothing (ADR-27 residues). The relay never learns the timer, only the bucket (T25).
- **T25 bounds for media** (the oracle of §15.5): no `media_object`, `media_upload`, `media_fragment`, `media_outbound_op` row, no `key_env` bytes in the raw database and WAL, and no file of the object after `delete_at_minute + lag + reconcile lag` (unless another live object names the same blob hash, an attack case, P-M8); no fragment bytes in the raw database after the later of that bound and the `deadline_hour` of the object's Phase 7 ops (frozen outbox payloads legitimately live until their op's last possible store, F9 §10.3); no preview in the RAM cache after the message left the screen. The sender's bound counts from the end of the upload (D26), and the sender's caption and ciphertext may live up to `deadline_hour + timer` from the commit (L8-M13).

### 11.2 View-once (P1; ADR-27 point 12)

- **Sender.** `viewOnce = true` seals with `flags.view_once`, **no preview**, the conversation's TTL and class like any other object (NI-M4). The sender's UI shows a placeholder; once the descriptor has a final outcome other than FAILED (SENT, DEGRADED, or INDETERMINATE after its resends) the sender deletes its files and `key_env` and checkpoints (§6.4, §11.1). A FAILED descriptor keeps them until the deadline for a retry, then the same cleanup runs.
- **Recipient, `VIEW-ONCE-OPEN`** (one transaction on the DM actor): require `state = 'verified'` and `key_env` present; call `readerOpen`, which moves `K_f` into a native reader; set `key_env = NULL`, `state = 'viewing'`; commit; run the TRUNCATE checkpoint of §11.1 (busy = 0, three retries); **only then** return the handle to the UI. If the transaction fails, the reader is closed (zeroised) before the exception propagates. If the checkpoint still reports busy after its retries, the handle is returned anyway (the key is already gone from the logical database, and refusing would lose the object) with `checkpoint_due` set: the old page survives until the next successful checkpoint, a lag declared in L8-M10 and measured by SCN-MD.
- **`VIEW-ONCE-CLOSE`** (when the UI closes the handle, at lock, at wipe, and at process start for any `viewing` row): close the reader, set `state = 'viewed'`, delete the fragment rows and every blob no row names any more, reconcile. The message row stays ("viewed") until its timer.
- **Crash semantics (CS-M5).** A crash before the commit leaves the key in the database and nothing shown: the user can open it again. A crash after the commit loses the object (the key existed only in native memory): at most one display per device, never two. Q11 records the choice (the alternative, erasing after rendering, allows a second view after a crash).
- **Honest limits (never a stronger UI claim).** FLAG_SECURE (T10) blacks out screenshots and recordings; it does not stop a second device or a camera, a modified client that ignores the flag, or a rooted phone (ADR-27 residues). Relay copies live until their TTL (view-once does not shorten it). Before it is opened, a seized device holds the key (wrapped) and the ciphertext. View-once protects honest devices and accidental re-viewing, not against the recipient. It is not forwardable.

---

## 12. Traffic, metadata and residues (ADR-09, ADR-15, ADR-20)

### 12.1 When media traffic happens (normative)

| Traffic | STANDARD | HIGH | Depends on |
|---|---|---|---|
| Own `M_0` listings | Phase 7 schedule (T = 30 s × U[0.5, 1.5] per pair; background W = 90 s) | same | nothing media-related (T19) |
| `get`s on `M_0` | at `M_0`'s list events, within the media fetch budget | same | others' stores into `M_0` (declared, LIMITE L2.1 #3) |
| Stores into `M_c` (manifest, fragments) | when due, in the media store budget after DM work | at `M_c`'s pair events after U[0, 10 min] | the user's send (`MEDIA-COMMIT`, `MEDIA-FEED`); never the conversation's timer (D26) |
| Media identical resends | when the INDETERMINATE outcome is released, within `resendNotAfter` | at pair events | the user's own send |
| Descriptor deposit into `X_c` | right after `MEDIA-READY` | pair event after U[0, 10 min] | the user's send, after its upload |
| Own redeem and `register` for `M_0` | with `X_0` and `P_0`: at activation, at the upgrade step, weekly at the EXPIRING PRF time | same | the week |
| Anything caused by a descriptor, a download, a validation, a display, a view-once opening, the pool's occupancy or free space | **nothing** (T41) | nothing | — |

### 12.2 Per-event observation matrix (TM §6 rows; Romanian text in Appendix B.3)

| Event | Relay (AD-2) | AD-1 adds | AD-4 / AD-5 | AD-7 (holds my card) | AD-8 (seized device) |
|---|---|---|---|---|---|
| I send media to c | `F + 1` × `store(M_c, hash, 65 536, ttl(bucket), minute, the shared media-deposit scope of M_c at that relay, my circuit)` within minutes (fewer, and no descriptor, after a FAILED outcome, the op deadline or my deleting the message); then a 4 KiB deposit into `X_c` | the same on every relay of `set(M_c, w)`; my session ties the `M_c` burst to the `X_c` deposit (L8-M2) | upload `3 × (F + 1) × 64 KiB` | — | the object's ciphertext files and rows until the message expires; the frozen outbox window |
| I receive media | `list(M_0)` at T19 times with my read scope; `F + 1` `get`s at list events | presence; `M_0` and `X_0` listed by one client (L7-D2) | download `(F + 1) × 64 KiB` | with its own token for `M_0`: my media volume and times, never which contact sent what | ciphertext and rows; after expiry, inbox tombstones of `M_0` (F7 retention) |
| I open, view or view once | **nothing** | nothing | nothing | nothing | `viewed` state |
| Media expires | nothing | — | — | — | nothing of the object after the lags; tombstones remain (L8-M6) |
| A card holder floods `M_0` | stores under the shared deposit scope until each relay's allowance is spent, and under its own write capabilities as far as its tokens go (L7-D16) | — | my forced download, bounded as in §5.3 | — | pooled ciphertext ≤ 512 MiB (oldest evicted) for ≤ 8 d |

### 12.3 Consequences for existing invariants

- **T1:** no new field or value; `M` events are `store`, `get`, `list`, `check`, `redeem`, `register` as today. `privacy-capture.sh` gains a fixture of a media burst (only `size_bucket = 65536` and existing TTLs).
- **T9:** made executable for media (T36).
- **T19:** unchanged; re-tested with media activity (§5.5).
- **T21:** `M_c` and `M_0` calls use their own namespace's circuit; a media upload and a descriptor deposit never share a circuit.
- **T27, T28, T31:** extended to `M` (T41).
- **T2 (Phase 8):** `M_0` adds one owner namespace per client, uniformly (§5.2).

### 12.4 Local forensic residue (AD-8; T33 extended)

| Item | Where | Lifetime |
|---|---|---|
| `media_object` (kind, class, flags, state, destination, manifest hash, wrapped key), `media_fragment` (hashes, ordinals, upload states), `media_blob` (hashes, file names, `retain_until_day`) and `media_outbound_op` (op ids, resend counts) | SQLCipher | with the message; pooled blobs ≤ 8 d |
| ciphertext files: 64 KiB each, random names, `mtime` = 0, **`ctime` to the nanosecond** | `noBackupFilesDir/m/` | with the object; orphans until the next reconcile |
| frozen media payloads in `outbox_op` | SQLCipher | until each op's last possible store (F7) |
| inbox tombstones of `M_0` (namespace, hash, day) | SQLCipher | `ceil7(day(E) + 24)` (F7 retention, ADR-20 point 6) |
| captions | `dm_message.body_env` | with the message |
| no time column other than `*_day` and `*_hour` with `typeof` CHECKs (T33) | | |

### 12.5 New LIMITE section L8 (media residues; Romanian text in Appendix B.4)

| ID | Residue | Why it remains | Mitigation |
|---|---|---|---|
| L8-M1 | Media volume is a strong correlation signal: an upload of `3 × (F + 1) × 64 KiB` and a matching download of `(F + 1) × 64 KiB` are linkable by a network-level adversary (flow correlation such as DeepCorr needs about 900 packets) | no cover traffic (P2) | HIGH delay; classes; cover traffic P2; no UI claim |
| L8-M2 | Relays see the class `F` of every object (11 classes; every image in class 0), the burst into a recipient's `M` and, from the sender's session, the descriptor deposit into the same owner's `X` shortly after | fragments must be stored; the descriptor waits for the upload | classes (D5); one TTL per conversation; HIGH delay |
| L8-M3 | Automatic download: every object deposited into my `M` is downloaded (data cost), including from blocked contacts and spammers; turning downloads off is visible to relays as `M` listing stopping | the only reflex-free choice (§7.1); fetching may not depend on local state | allowance; card rotation (Phase 13); Q4 |
| L8-M4 | A card holder can exhaust my weekly media allowance on every relay of my union set (distinct blobs per relay: about 256 MiB per relay of the union set per week) **and** store more under write capabilities bought with its own tokens (L7-D16), all of which I download; it can fill my pool to 512 MiB for 8 days, and under a flood a late descriptor of an honest contact can find its fragments evicted (`incomplete`) | no sender-bought capabilities for honest senders (T27); write grants read and write at relays; fetching may not depend on the pool (T41) | allowance per registration; `POOL_CAP` by eviction; the owner-bound write and read rule of Phase 12 (F9 Q36); card rotation (Phase 13); Q20 |
| L8-M5 | Large media in 5-minute and 1-hour conversations may miss the deadline in background jobs; an object whose fragments expired before the recipient fetched them is `incomplete`; transfers are slow (per-RPC clients) | TTL = conversation bucket (ADR-27 point 11); Phase 7 client per call | foreground transfers; Phase 12 pooling (F-M2) |
| L8-M6 | On a seized device: ciphertext files carry inode `ctime` to the nanosecond while the object lives; rows show kinds, classes and states; `M_0` tombstones outlive objects by up to ~4 weeks | Android files; F7 retention | `mtime` = 0; files deleted with the object; ciphertext only |
| L8-M7 | Decrypted video lives in the JVM heap (Media3 sample buffers) while it plays; decoded pixels in native memory while shown | Media3 is Java | playback only in the foreground; release at lock; small buffers |
| L8-M8 | `MediaCodec` reports codec metrics to the platform (`dumpsys media.metrics`: codec, resolution, duration), and the platform may share diagnostics with Google if the user opted in; a crashed decoder's tombstone and dropbox entry may hold plaintext fragments of that request's image and are included in an `adb bugreport` that anyone holding the unlocked device can take (not root-only); on devices with storage-backed swap, heap pages may reach flash | platform services | ExoPlayer and Transformer platform diagnostics off; one isolated process per request; FLAG_SECURE against task snapshots |
| L8-M9 | The recipient gets the pixels, sound, dimensions and duration; the camera's sensor noise (PRNU) and the sender's encoder parameters survive re-encoding | physics and codecs | watermarking P2 (LIMITE:138) |
| L8-M10 | View-once does not stop a second device or a camera, a modified client or a rooted phone; relay copies live until their TTL; a crash after opening loses the item; if the checkpoint after opening stays busy, the old `key_env` page survives in the WAL until the next successful checkpoint | ADR-27 residues; SQLite WAL | FLAG_SECURE (T10); key erased and checkpointed before display |
| L8-M11 | Received and picked images are decoded by platform decoders inside an isolated process, one per request: an exploit there sees that request's bytes and can lie about its pixels (for a picked file, shape the JPEG GHOST then sends), but not reach keys, files, the network or any other request; video codecs run in platform processes | platform decoders are the only practical ones | canonical JPEG and fMP4 only; isolation per request (T40); patched devices |
| L8-M12 | Every identity pays one more token per relay per week and lists `M_0` whether or not it uses media | uniformity (D11) | — |
| L8-M13 | A sender's media burst can end short of `F + 1` stores, with no descriptor after it, after a FAILED outcome, at the op deadline or when the sender's user deletes the message or contact; the sender's caption and ciphertext live until the upload ends plus the timer, at most `deadline_hour + timer` from the commit (≈ 1 h 5 min for a 5-minute timer) | the countdown must not cut bursts inside a bucket (D26); Phase 7 has no cancel | the deadline depends on the bucket only; no truncation by the timer |

---

## 13. Modules, JNI surface, schema, threads (normative)

### 13.1 Module layout

| Module / package | Contents | Depends on |
|---|---|---|
| `client-core/media` = `ghost-client-media` (Rust, new) | constants and classes (§3.1, §3.6), derivations, the sealer and reader state machines, STREAM, the manifest and descriptor codecs, the magic-byte sniffer, the JPEG canonicaliser and the fMP4 walker with the `mfra` builder; no JNI, no I/O, no clock, no logging, no state | `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `zeroize` (already pinned) |
| `client-core/dm` (`ghost-client-dm`) | gains the dependency on `ghost-client-media`, the `MediaNative` JNI class behind `jni-bridge` with sealer and reader registries inside the DM context, the `M` labels, the `MediaFileKey` wrap name, and the key-slot handling in `encrypt`/`decrypt`/`sessionInbound`/`l0` | as today + `ghost-client-media` |
| `:crypto-bridge` | `MediaNative` (the closed list of §13.2), `MediaResult`, the typed facade `MediaCrypto` | as today |
| `:media` `org.ghost.media` (new code in the existing module) | `.store` (`MediaObjects`, the tables, `CiphertextFiles`, reconcile), `.send` (`MediaPreparer`, `GhostTranscoder`, `GhostMuxer`, `SealingChannel`, `MediaFeeder`), `.receive` (`MediaIngest`, `MediaBinder`, `MediaVerifier`), `.play` (`GhostMediaDataSource`, player factory, preview cache), `.sandbox` (`MediaDecodeService`, the only package that may reference platform decoders), `.api` (`MediaDestination`, `MediaHandle`, states) | `:crypto-bridge`, `:sync` API, `:storage`, Media3 |
| `:messaging` | kind 5 in `SEND`/`RECV`/`OUTCOME`, the `MediaPort` implementation, `sendMedia`/`openMedia`/`openViewOnce`/`retryMedia`, `M_0` in the owner steps | `:media` |
| `:sync` | the media lane (§5.5) | — |
| `:storage` | migration M (§13.6) | — |
| `:app` | wiring, the isolated service in the manifest, the `Process.isIsolated()` early return in `GhostApp.onCreate` (§9.2), Media3 logging off | all |

**Why the cryptography is in Rust, by evidence (D8).**

| Criterion | Rust (`ghost-client-media` via `MediaNative`) | Kotlin (JCA/Conscrypt ChaCha20-Poly1305, BouncyCastle HKDF) |
|---|---|---|
| ADR-19 ("nicio logică de protocol în Kotlin"), ADR-20 point 8 | complies | a deviation to record |
| File key off the JVM heap (D7, P-M8) | yes: `K_f` lives in native memory and `key_env` | no: the key sits in GC-managed arrays that cannot be zeroised |
| One implementation for DMs and channels | the Phase 10 MLS crate links the same crate | a second implementation in Rust for MLS, or JNI back into Kotlin |
| New shipped dependencies | no new external crate (every primitive already pinned); the workspace crate itself needs its allowlist line (G-M7) | none |
| Test infrastructure | the existing host build runs the real code on the JVM | JVM-native |
| Performance | RustCrypto `chacha20` has a NEON backend, `poly1305` 0.9.1 only soft and AVX2 (lock and registry sources); estimated ≥ 100 MB/s on a mid-range phone [I, V-M9] | Conscrypt uses BoringSSL assembly and is faster |
| Verdict | **chosen**: at Tor speeds (a few Mbit/s) throughput is irrelevant; custody, ADR-19 and a single implementation decide | rejected |

Rules: `:media` references no `org.ghost.network`, `java.net`, `javax.net`, socket or HTTP class and no coroutines (G-DM1's rule extended); no `catch (Exception)` (typed catches, `sync-no-catch-all.sh`); no logging (T3).

### 13.2 `MediaNative`: the closed JNI surface (gate G-R6 gains a second list)

All functions are `static native` on `org.ghost.crypto.bridge.MediaNative`, take the DM context handle `h` (F9 §2.5), byte arrays, direct `ByteBuffer`s and ints, return `code(1) ‖ TLV fields`, perform no I/O, read no clock, log nothing, and catch panics under the silent hook (F9 §2.6). Sealers and readers are native registry entries owned by the context; `ctxClose` zeroises all of them.

| # | Function | Main outputs | Codes besides `OK` |
|---|---|---|---|
| M1 | `sealBegin(h, destId, kind, viewOnce, maxClass)` | `sealerId`, `object_id` | `LIMIT` (2 sealers), `CRYPTO_UNAVAILABLE` |
| M2 | `sealAppend(h, sealerId, plaintext direct buffer, len, out direct buffer)` | the fragments of every chunk completed by this call and their hashes | `NON_CANONICAL` (walker), `OVERSIZE` (> `MAX_CONTENT` or above `maxClass`, R-MT2), `INDEX_REUSED` (bug) |
| M3 | `sealFinish(h, sealerId, preview)` | the padding chunks' fragments and hashes, the manifest blob, `manifest_hash`, `class_code`, `content_len`, the walked dimensions and duration, `key_env` bound to `(out, destId, object_id, manifest_hash)` | `NON_CANONICAL` (walker incomplete, preview not canonical or above 320 px), `OVERSIZE` |
| M4 | `sealAbort(h, sealerId)` | — | — |
| M5 | `readerOpen(h, keyEnv, role, destId, objectId, manifestBlob, descriptorFields)` | `readerId`, the manifest fields (kind, flags, class, `content_len`, dimensions, duration, preview, hashes) | `NOT_OPEN`, `COMMIT_MISMATCH`, `HASH_MISMATCH`, `NON_CANONICAL`, `STATE_CORRUPT` (`key_env` does not open under its binding), `LIMIT` (8 readers) |
| M6 | `readerChunk(h, readerId, index, fragments direct buffer, out direct buffer, mode ∈ {validate, read})` | the chunk's content bytes (read) or nothing (validate) | `NOT_OPEN` (tag), `NON_CANONICAL` (pad, walker), `HASH_MISMATCH`, `INDEX_RANGE` |
| M7 | `readerValidateFinish(h, readerId)` | — | `NON_CANONICAL` (walker incomplete, chunks missing, manifest dimensions or duration unlike the walked stream) |
| M8 | `readerClose(h, readerId)` | — | — |
| M9 | `jpegCanonicalize(bytes)` | canonical bytes | `NON_CANONICAL` |
| M10 | `sniff(first64)` | a source type from the allowlist of §6.1 | `UNSUPPORTED` |

`ghost-dm-host` adds two test-only symbols, `MediaNative.testVectors` and `MediaNative.testSealBeginWithKey` (a sealer whose `K_f` and `object_id` come from the world's seeded generator, so the model relay can re-derive media blobs instead of storing them, §15.6), and G-R6 checks that no shipped library exports either (the `DmEquivalence` precedent). `ErrorPolicyTest`'s 21 network categories are unchanged; `MediaResultCodesTest` is exhaustive over the new enumeration.

### 13.3 `:sync` additions (normative)

- `TrafficPolicy` gains `mediaStoresPerPass = 16`, `mediaStoresPerPairEvent = 8`, `mediaForegroundFetchesPerEvent = 64`, `mediaBackgroundFetchesPerEvent = 128`, `mediaFetchesPerItem = 8`, `mediaBackgroundRelayWorkMillis = 45 000` (validated like the existing fields; the last must be below `backgroundRelayWorkMillis`).
- `StoreStep` orders due ops by consumer priority first and takes media stores only after the pass's non-media stores (§5.5); `FetchStep` reads the pair's consumer to pick the budget, fetches a media bundle in slices of `mediaFetchesPerItem` and reposts the remainder behind queued non-media items; the work budget charges media calls to a separate per-relay share.
- No new API: `Inbox.want` is **not** added (X-M6); `Consumer.MEDIA`, `CapabilitySource.LOCAL` and the registration API already exist.
- `sync-exit-gate`'s worlds gain a media consumer with bursts of 17 and 129 blobs; the report line is unchanged apart from the scenario list; the 17 Phase 7 mutants stay detected.

### 13.4 `:messaging` and `:entitlement` changes

- `SEND`: a kind-5 item is sendable only when its object is `uploaded`; `encrypt` receives `mediaKeyEnv`. `RECV` and the held replay: a kind-5 L0, from `decrypt` or `sessionInbound`, calls `MediaObjects.onDescriptor` with its `key_env` in the same transaction. `OUTCOME`: a view-once descriptor's final outcome other than FAILED triggers the sender cleanup (§6.4). `SWEEP`: the `MediaPort` implementation (§11.1), then the checkpoint. The sender countdown of a kind-5 row is set by `MEDIA-READY` or the deadline (D26).
- Owner steps (`ACTIVATE`, `OWNER-WEEK`, `KEEPER`, `REGROWS`) include `M_0`; the one-time `MEDIA-ACTIVATE` step (§5.2).
- `:entitlement` needs no code change: `M_0` is one more `REDEEM` namespace with pending registrations (F9 §13.4); the JD8 worlds count three owner namespaces.

### 13.5 Transaction inventory (additions to F9 §7.2)

| Tx | Actor | Trigger | Writes | After commit |
|---|---|---|---|---|
| `MEDIA-COMMIT` | DM | preparation finished (a user send) | `media_object`, `media_blob` (sealed), `media_fragment` (bound, `unsent`), `media_upload`, `dm_message` (expiry upper bound), `dm_outbound_item`, `M_c` registration and credentials | remove from `preparing`; post `MEDIA-FEED` |
| `MEDIA-FEED` | DM | commit; `OUTCOMES` for MEDIA; retry; time-triggered pass | `Outbox.enqueue` (MEDIA), `media_outbound_op`, ordinals `open` | `requestExpedite()` in STANDARD |
| `MEDIA-OUTCOME` | DM | `OUTCOMES` for MEDIA | `Outbox.release`, ordinal states, resend ops, object `failed` | `MEDIA-READY` check |
| `MEDIA-READY` | DM | last final outcome | object `uploaded`; `expire_at_minute` lowered (countdown starts); the item becomes sendable; F9 `SEND` for it in the same pass | as `SEND` |
| `MEDIA-DEADLINE` | DM | time-triggered pass after `deadline_hour` | object `failed`; `expire_at_minute` lowered | — |
| `MEDIA-INGEST` | media | `INBOX` hint for MEDIA; consumer tail | `markConsumed`, `media_blob` (ingested), `expected` rows of every object naming the hash → `bound`, pool eviction | `MEDIA-BIND` / completeness check; reconcile after an eviction |
| `MEDIA-BIND` | media | a manifest or an awaiting object meets its pair | `media_fragment` (bound, expected), object `fetching` / `corrupt` | — |
| `MEDIA-VERIFY` | media | object `complete`; a read failure after `verified` | object `verified` / `corrupt`; a `corrupt` object's references released | listener hint; reconcile |
| `VIEW-ONCE-OPEN` / `-CLOSE` | DM | UI; lock; wipe; start | `key_env = NULL`, `viewing` / `viewed`, fragment rows and unnamed blobs deleted | checkpoint (OPEN, before the handle); reconcile |
| `MEDIA-GC` | media | time-triggered pass | pooled blobs past their day; `incomplete` objects' references | checkpoint if a `key_env` went; reconcile |
| F9 `RECV`, held replay, `SWEEP`, `OUTCOME` | DM | as F9 | also `media_object` via `MediaObjects` / `MediaPort`; the view-once sender cleanup | checkpoint and reconcile after `SWEEP` and after the cleanup |

No media transaction performs network I/O. File writes happen before the transaction that references them; file deletions after the commit that dereferences them (reconcile).

### 13.6 Schema migration M (normative; one transaction, append-only, fail-closed; the F9 §13.6 practice)

**Number.** The next free version at merge. `Schema.CURRENT_VERSION` is 5 today (`ghost/android/storage/src/main/kotlin/org/ghost/storage/Schema.kt:120`), but two other schema changes are pending and may land first: **Phase 9's open defects** in LIMITE L5 each need a column and a migration (the TIMER_SET bucket on the pending path needs a column in `dm_outbound_item`; the FAILED-control reschedule needs an attempts column in `dm_scheduled`; F9 §22.21 item 2, §22.13 item 9), and **Phase 10's** first migration. Rules: (a) migration M's rebuilds copy the columns of the tables **as they are at merge**, generated from the current shared definitions, never from a copy of v5 frozen in this design; (b) if the owner decides the Phase 9 fixes before S3, their columns are added **in M's rebuild** of `dm_outbound_item` (one rebuild instead of two, Q27); (c) whichever design merges second renumbers its migration, ADRs and invariants (R-M8).

1. **Guard and drop the v1 media tables.** `media` and `media_blobs` (`Schema.kt:211-225`) never had a writer: a `vM_migration_guard (row_count … CHECK (row_count = 0))` counts both; then `DROP TABLE media_blobs; DROP TABLE media`. `expectedTables` loses them.
2. **Rebuild `dm_message`** (`Schema.kt:972-1001`) with the explicit-column copy of migration 4's outbox rebuild (G-9, E-5): only `kind IN (1, 2)` becomes `kind IN (1, 2, 5)`, the column CHECK on `body_env` becomes `length(body_env) BETWEEN 28 AND 61485`, and `(kind = 1) = (body_env IS NOT NULL)` becomes `(kind IN (1, 5)) = (body_env IS NOT NULL)` with two table CHECKs, `kind <> 1 OR length(body_env) >= 30` (today's text minimum, unchanged) and `kind <> 5 OR length(body_env) BETWEEN 28 AND 1052` (the content-key envelope's 28 bytes of overhead, `ContentCipher.OVERHEAD`, plus at most `MAX_CAPTION_BYTES`; an empty caption is a 28-byte envelope); every other column, CHECK, index and trigger (`dm_message_identity`, `dm_message_state`, `dm_message_expiry`, `dm_message_no_replace`) is recreated from shared constants; the `legacy_alter_table = OFF` guard and the `pragma_foreign_key_check` guard of migration 4 are repeated.
3. **Rebuild `dm_outbound_item`** (`Schema.kt:1004-1016`) the same way: `kind BETWEEN 1 AND 4` becomes `BETWEEN 1 AND 5`, plus the Phase 9 column if Q27 applies, nothing else.
4. **Create the media tables:**

```sql
CREATE TABLE media_object (
  object_id      BLOB PRIMARY KEY NOT NULL CHECK (length(object_id) = 16),
  role           TEXT NOT NULL CHECK (role IN ('out', 'in')),
  dest_id        BLOB NOT NULL CHECK (length(dest_id) = 16),       -- the contact (DM); in key_env's binding (§4.2)
  kind           INTEGER NOT NULL CHECK (kind IN (1, 2)),
  view_once      INTEGER NOT NULL CHECK (view_once IN (0, 1)),
  class_code     INTEGER NOT NULL CHECK (class_code BETWEEN 0 AND 10),
  manifest_hash  BLOB NOT NULL CHECK (length(manifest_hash) = 32),
  key_env        BLOB CHECK (key_env IS NULL OR length(key_env) = 60),
  state          TEXT NOT NULL CHECK (state IN ('uploading', 'uploaded', 'failed', 'awaiting', 'fetching', 'complete',
                                                'verified', 'corrupt', 'incomplete', 'undecodable', 'viewing', 'viewed')),
  message_id     BLOB REFERENCES dm_message(message_id) ON DELETE CASCADE,        -- NULL only for a test or Phase 10 destination
  decode_failures INTEGER NOT NULL DEFAULT 0 CHECK (decode_failures BETWEEN 0 AND 2),
  incomplete_after_hour INTEGER CHECK (incomplete_after_hour IS NULL
                          OR (typeof(incomplete_after_hour) = 'integer' AND incomplete_after_hour % 3600 = 0)),
  CHECK (kind <> 1 OR class_code = 0),                                            -- every image is class 0
  CHECK ((role = 'out') = (state IN ('uploading', 'uploaded', 'failed'))),
  CHECK (state NOT IN ('viewing', 'viewed', 'corrupt', 'incomplete') OR key_env IS NULL),
  CHECK (state NOT IN ('viewing', 'viewed') OR view_once = 1),
  CHECK (role = 'out' OR incomplete_after_hour IS NOT NULL)
) WITHOUT ROWID;
CREATE UNIQUE INDEX idx_media_object_message ON media_object(message_id) WHERE message_id IS NOT NULL;

CREATE TABLE media_upload (
  object_id     BLOB PRIMARY KEY NOT NULL REFERENCES media_object(object_id) ON DELETE CASCADE,
  namespace_id  BLOB NOT NULL REFERENCES sync_namespace(namespace_id),
  ttl_seconds   INTEGER NOT NULL CHECK (ttl_seconds IN (3600, 86400, 604800, 2592000)),
  deadline_hour INTEGER NOT NULL CHECK (typeof(deadline_hour) = 'integer' AND deadline_hour % 3600 = 0),
  retry_gen     INTEGER NOT NULL DEFAULT 0 CHECK (retry_gen BETWEEN 0 AND 3)          -- user retries of the object
) WITHOUT ROWID;

-- One row and one file per distinct ciphertext blob; any number of fragment rows may name it (D25).
CREATE TABLE media_blob (
  blob_hash        BLOB PRIMARY KEY NOT NULL CHECK (length(blob_hash) = 32),
  file_name        BLOB NOT NULL CHECK (length(file_name) = 16),
  origin           TEXT NOT NULL CHECK (origin IN ('sealed', 'ingested')),
  retain_until_day INTEGER CHECK (retain_until_day IS NULL
                     OR (typeof(retain_until_day) = 'integer' AND retain_until_day >= 0)),
  CHECK ((origin = 'ingested') = (retain_until_day IS NOT NULL))
) WITHOUT ROWID;
CREATE UNIQUE INDEX idx_media_blob_file ON media_blob(file_name);
CREATE INDEX idx_media_blob_retention ON media_blob(retain_until_day) WHERE retain_until_day IS NOT NULL;

CREATE TABLE media_fragment (
  object_id     BLOB NOT NULL REFERENCES media_object(object_id) ON DELETE CASCADE,
  ordinal       INTEGER NOT NULL CHECK (ordinal BETWEEN -1 AND 803),                  -- -1 = the manifest
  blob_hash     BLOB NOT NULL CHECK (length(blob_hash) = 32),                          -- not unique: D25
  state         TEXT NOT NULL CHECK (state IN ('expected', 'bound')),
  upload_state  TEXT CHECK (upload_state IS NULL
                  OR upload_state IN ('unsent', 'open', 'sent', 'degraded', 'indeterminate', 'failed')),
  PRIMARY KEY (object_id, ordinal)
) WITHOUT ROWID;
CREATE INDEX idx_media_fragment_hash ON media_fragment(blob_hash);
CREATE INDEX idx_media_fragment_open ON media_fragment(object_id) WHERE upload_state = 'open';

-- Maps a Phase 7 operation back to its blob (the F9 dm_outbound_op pattern, Schema.kt:1017-1027).
CREATE TABLE media_outbound_op (
  operation_id  BLOB PRIMARY KEY NOT NULL CHECK (length(operation_id) = 16),
  object_id     BLOB NOT NULL,
  ordinal       INTEGER NOT NULL,
  retry_gen     INTEGER NOT NULL CHECK (retry_gen BETWEEN 0 AND 3),
  resend_count  INTEGER NOT NULL CHECK (resend_count BETWEEN 0 AND 2),
  FOREIGN KEY (object_id, ordinal) REFERENCES media_fragment(object_id, ordinal) ON DELETE CASCADE,
  UNIQUE (object_id, ordinal, retry_gen, resend_count)
) WITHOUT ROWID;
```

5. **Triggers:** `media_object_fixed` (identity, role, destination, kind, view_once, class, manifest hash, message immutable); `media_object_key` (an UPDATE of `key_env` may only set NULL); `media_object_state` (the transitions of §7.6); `media_fragment_state` (`expected → bound` only; `upload_state` only along `unsent → open → {sent, degraded, indeterminate, failed}`, and `failed → unsent` only together with a `retry_gen` increment of its object); `media_fragment_role` (`upload_state` is non-NULL exactly for fragments of `out` objects, and every fragment of an `out` object is `bound`); `media_fragment_bound_blob` (a `bound` row names an existing `media_blob`); `media_upload_monotonic` (`retry_gen` never decreases); `media_outbound_op_fixed` (rows are never updated); REPLACE guards for the five tables (the F9 `replaceGuard` helper). Deleting a `media_blob` that a `media_fragment` row still names is refused by a trigger (`media_blob_referenced`), so "a file goes only when nothing references it" is a schema property, not only a code path. `expectedTables` and `expectedTriggers` gain them; `DmSchemaIntrospectionTest` (T33) gains `incomplete_after_hour`, `deadline_hour` and `retain_until_day`.

`G-DM4` (no `REPLACE`, no upsert) and `G-DM6` (no FTS) cover the media SQL.

### 13.7 Threads and wiring

- **DM actor** (unchanged, F9 §13.7): every transaction that touches `dm_*` rows, including `MEDIA-COMMIT`, `MEDIA-FEED`, `MEDIA-OUTCOME`, `MEDIA-READY`, `VIEW-ONCE-*`.
- **Media actor** (new, `ghost-media`, one thread): `MEDIA-INGEST`, `MEDIA-BIND`, `MEDIA-VERIFY`, `MEDIA-GC`, reconcile, the `preparing` set. It never writes `dm_*` rows. Both actors write media rows only inside transactions, so SQLite serialises them; the only cross-actor state is `preparing`, owned by the media actor.
- **Media worker** (one thread, `ghost-media-prep`): sandbox calls, Transformer, sealing; no transaction.
- **Consumer tail** (F9 §13.3 item 6): drains `Consumer.MEDIA` in background sessions and quiet runs after the transport closed, so session close times cannot depend on inbound media volume (the PM-25 argument).
- **Lock and wipe:** close readers, sealers and the sandbox binding, release players, clear the preview cache; wipe also deletes `noBackupFilesDir/m/`.

### 13.8 Keys at rest

`K_f` is stored only as `key_env` (§4.2); `K_p`, `K_m`, `commit` are derived per call in native memory and zeroised; `session_state_key` wraps nothing new beyond `key_env`; no media secret is derived from the seed except `RM_{i,s}` (re-derived, never stored). The content key still wraps captions (`body_env`) and `l0_env` (with a zero key slot).

---

## 14. Invariants (new T36–T41; changes to T3, T4, T5, T9, T10, T20, T21, T25, T27, T28, T31, T33, T35)

### 14.1 New invariants (Romanian rows for INVARIANTS.md in Appendix B.2)

| ID | Invariant | Verification | Executable from | Code |
|---|---|---|---|---|
| **T36** Uniform media objects | every media blob is exactly 65 536 B with no cleartext header; an object whose upload completes is `F + 1` blobs with `F ∈ CLASSES` = `class(content_len)` (a shorter burst only after FAILED, the op deadline or a user deletion, never because of the timer inside a bucket); images are class 0; a destination change (another recipient, a forward) is a new object: no two honest objects share a blob hash or a 16-byte ciphertext window | vectors; property test over kinds × sizes; byte χ² per offset over 10 000 fragments; JM1–JM3; NI-M3, NI-M7; mutants PM-M1 … PM-M4, PM-M6, PM-M20 | Phase 11 | `client-core/media`, media world |
| **T37** Metadata-zero (T5 made exact) | the decrypted content and preview of every object are canonical baseline JPEG or canonical fMP4 (§8.2, §8.3) produced by a re-encode of every track (never a transmux): no APPn, COM, trailer, `udta`, `meta`, `uuid`, location, device, software or time atom, no source bitstream, no disallowed SEI; the sealer refuses and the reader rejects anything else; AAC raw data blocks are declared opaque | the T5 corpus (§15.7) through the real Android pipeline, including sources that already match the output format: ExifTool finds only allowed tags, a canary search finds nothing, the output's SPS/VUI are the device encoder's, orientation goldens hold; walker property tests; mutants PM-M11, PM-M12, PM-M18 | Phase 11 (emulator or signed device run) | `android/media` tests, `client-core/media` |
| **T38** No plaintext media at rest | GHOST writes no plaintext media byte, preview or decoded pixel to a file, database, cache, log, clipboard, `MediaStore`, notification or another app, and every window that shows media denies the OS its task snapshot; the only persistent media bytes GHOST writes are relay-identical ciphertext in `noBackupFilesDir/m/`; the OS's tombstones, dropbox entries and storage-backed swap are declared | G-M1, G-M2; release-dex check (V-M14); the emulator sandbox scan and the system-directory scan (snapshots, tombstones, dropbox; §15.8); the `MediaStore` owner query; mutants PM-M9, PM-M10, PM-M23 | Phase 11 (static: PR; dynamic: emulator) | `android/media`, `scripts/gates/` |
| **T39** Media key custody and erasure | `K_f` exists only in native memory and as `key_env` bound to its role, destination, object and manifest; it is never in the JVM heap, never in `l0_env` or `body_env`, whichever DM function (13 or 14) decrypted its L0; it is deleted with its message (SWEEP) and before the first display of a view-once object, each deletion followed by a WAL checkpoint; after the lags no row, `key_env` byte (database and WAL) or file of the object remains | key-slot tests through functions 13 and 14 and the held replay (every L0 Kotlin sees has a zero slot); binding tests; T25 media cases with raw `.db` and `-wal` scans; SCN-MD, SCN-ME; seizure check (§15.6); mutants MC-M6, MC-M7, MC-M19, PM-M13, PM-M17, PM-M22 | Phase 11 | `client-core/dm`, `android/media`, `android/messaging` |
| **T40** Decoder confinement | no received or picked image byte is parsed by a native decoder in the main process; received images reach the sandbox only after canonical validation; each strip or decode request runs in its own isolated process that dies after the reply, and the Application does nothing in it; video is parsed only by Media3's `FragmentedMp4Extractor` after validation and decoded only by `MediaCodec`; nothing is decoded in the background or for requests and blocked contacts | G-M3 (platform decoder APIs only in `org.ghost.media.sandbox`); a decoder spy in tests; the sandbox crash suite; distinct PIDs per request; the emulator binding test; mutants PM-M14, PM-M21, MC-M23 | Phase 11 | `android/media`, `android/app` |
| **T41** Media traffic rules | `M` is relay-blind (T26), deposits into one `M` at one relay share one scope (T27), media blobs use the conversation's TTL bucket and deadline (T30), clients read only their own `M` (T31), and no descriptor, download, validation, display, opening, pool occupancy, binding state or free space causes or suppresses traffic (T28); `M_0` is registered and paid by every identity whatever its media activity | JM4–JM7; NI-M1, NI-M2, NI-M4, NI-M5, NI-M6; G-DM2 extended (G-M6); mutants PM-M5, PM-M7, PM-M8, PM-M16, PM-M19 | Phase 11 | `android/messaging`, `android/media`, `android/sync`, media world |

### 14.2 Changes to existing invariants

| ID | Change |
|---|---|
| T3 | canaries add: file keys (host builds export `K_f` through the test-vectors entry only), `K_p`, media plaintext patterns, previews, captions, `object_id`s; scanned in every process output, including `:mdec` |
| T4 | the backup inspection also covers `noBackupFilesDir/m/` and asserts no decrypted media |
| T5 | replaced by T37's statement; executable in Phase 11 |
| T9 | executable for media (T36) |
| T10 | brought forward for windows that show media (X-M11, D27): FLAG_SECURE and, on API 33+, `setRecentsScreenshotEnabled(false)` from Phase 11, including the gate harness; the rest of T10 stays in Phase 13 |
| T20 | wording: "the sync layer" is unchanged; the media store's ciphertext files are governed by T38 (X-M7) |
| T21 | `M` credentials checked before I/O; the namespace's circuit |
| T25 | media and previews: the §11.1 bounds; executable for DM media in Phase 11 (channel media in Phase 10) |
| T27, T28, T31 | extended to `M` (T41) |
| T33 | the media tables' time columns (`incomplete_after_hour`, `deadline_hour`, `retain_until_day`); files: `mtime` = 0, `ctime` declared (L8-M6) |
| T35 | extended (X-M12, §3.8): "…or derived from a key transported only inside such envelopes"; the provenance build labels `K_p` and `K_m` as `transported(K_f)`; the intro-inner-layer gap applies to media in first messages |

---

## 15. Tests and the exit-gate argument

### 15.1 Infrastructure

- **Rust.** `ghost-client-media` unit, vector and property tests in the `rust` job; seeded decoder and walker property runs of 10⁶ inputs per CI run (the F9 R-C4 pattern: never panics, never over-reads, `NON_CANONICAL` or `OK` only); the `nonce-registry` feature in every test build (§3.7).
- **JVM.** `MediaWorld` (`android/media/src/test/.../harness/`), built on F9's `DmWorld` through the shared-test-source pattern: real `:sync`, `:messaging`, `:media` and `:crypto-bridge` stacks on SQLite files with production pragmas, the real ratchet, seal and media cryptography through the host build `ghost-dm-host` (which gains `ghost-client-media`), a `CiphertextFiles` port on a real temporary directory with a fault-injecting wrapper, and deterministic fakes for the Android-only parts: a fake sandbox that returns canonical JPEGs from a seeded generator and a fake transcoder that emits a golden canonical fMP4 stream (recorded from the real Transformer in S0a). **Native randomness is the OS's**: F9's planned seeded `getrandom` backend was never built (F9 §22.16 item 13 and §22.22 item 7, which found no `getrandom_backend = "custom"` anywhere in the tree), so ciphertexts and hashes differ between runs. Every media check is therefore on structures, joins, normalized views and recorded truth, never on bytes a rerun must reproduce: the crash enumeration checks invariants and oracles after every reboot rather than digest equality with a recording run, and the twins compare normalized views (§15.6). Building the backend is Q33 (default: no).
- **Scale and memory.** `ModelRelay` keeps every blob's bytes in the heap (`ModelRelay.kt:98`, `content = HashMap<BlobHash, ByteArray>`), and the JVM test tasks run with a 2 GB heap (`sync/build.gradle.kts:64`). At one image per client per day, N = 300 over 28 days would be about 27 GB across three relays. So the media world (a) fixes a **media rate** per world: 0.5 objects per client per day at the PR scale and 0.3 at the gate scale, 90 % class 0, 9 % classes 1–4, 1 % classes 5–10 (classes above 4 only in scripted objects); (b) stores media blobs in the model relay as **recipes** (object, ordinal) instead of bytes, and re-derives a blob on `get` by re-sealing its chunk: the world's senders seal through the host-only `MediaNative.testSealBeginWithKey`, whose `K_f` and `object_id` come from the world's seeded generator and are recorded in its truth, over content from the seeded fake sandbox or transcoder (≤ 1 ms per 256 KiB chunk, [I], measured in S1); non-media blobs stay as today; (c) keeps a full-bytes relay model for the PR-scale world's end-to-end runs, where the heap allows it. Production code never sees a chosen key (G-M5 keeps the symbol out of shipped libraries).
- **Android.** An emulator job (API 29, 35 and 37 x86_64 images) runs the real sandbox, Transformer, `GhostMuxer`, Media3 player and file system, and pulls outputs to the host for ExifTool; a `gate` build type variant (F9 §21.13 point 7) allows `run-as` inspection, and `adb root` on the emulator images reaches the system directories of §15.8. Until a runner has KVM, the same scripts run on the owner's Windows emulator (WHPX) as Phase 9's device suites did (F9 §22.32), recorded as local slice evidence and not as gate evidence (D23). A signed physical-device checklist covers what an emulator cannot (hardware codecs, real encoders' SEI and AAC elements, MTE).

### 15.2 Unit, vector and property tests (CS-M1, CS-M2)

1. Vectors of §3.9 in Rust, in the `aead-stream` oracle and in the JDK implementation.
2. **Corruption matrix** over a class-0 and a class-1 object: every single-bit flip at 4 096 sampled positions of every fragment and of the manifest; every fragment swapped with another position, with the same position of another object, duplicated, dropped; the last chunk's flag removed (re-sealed by the test's own key to isolate the flag); a chunk from another object with the same key material except `object_id`; `F` changed in the manifest; a non-zero pad byte; a manifest under a second key crafted to open under ChaCha20-Poly1305 without the commitment (the Albertini et al. multi-key construction, test-only) — each yields its typed code and exposes no content byte (the out buffer is checked zero).
3. **Nonce reuse:** property test over 10⁴ objects with random crashes injected into the sealer's host (the registry finds no repeat); `INDEX_REUSED` on a repeated index; a unit test that `sealBegin` after an abort returns a new `object_id` and key.
4. **Classes and sizes:** every boundary; images always class 0; a 52 428 801-byte input refused.
5. **Descriptor and key slot:** L0 kind 5 round trips with a zero slot; `encrypt` refuses a non-zero slot, a `mediaKeyEnv` on another kind, and a `key_env` whose binding names another contact, role, object or manifest; **both** `decrypt` (a normal message) and `sessionInbound` (a PreKey first message, and the held replay after a key change) return a zero slot and a `key_env` bound to `(in, sender, object_id, manifest_hash)` that unwraps to the sender's `K_f` (host build); a first message that is media, a media message after a reset and a held media message each reach `media_object` with no key in Kotlin; the F9 L0 vectors gain kind-5 cases.
6. **Walkers:** JPEG and fMP4 canonical profiles against the S0 goldens, every refused marker and box type, `mfra` consistency, the SEI filter, dimensions and duration derived from the stream (a manifest that disagrees is refused), preview side ≤ 320 and pad zero, an image above class 0 refused.

### 15.3 Crash enumeration (the F7 §8.3 and F9 §15.3 method, extended to file operations)

Every media transaction runs under the harness that crashes at every SQL statement **and** at every `CiphertextFiles` call (before and after `write`, `force`, directory sync, `delete`, `list`), reboots, checks structural invariants at once, runs to quiescence and checks everything. File faults include "an unsynced write is lost" at the reboot, which is what a power loss does.

| Scenario | What runs | Invariants checked after every reboot |
|---|---|---|
| SCN-MA | preparation, `MEDIA-COMMIT` | no committed object with a missing or wrong-hash file; no `key_env` without all `F + 1` bound rows; orphans only while preparing; the nonce registry holds no repeat; a restart never resumes a sealer |
| SCN-MB | `MEDIA-FEED`, outcomes, resends, `MEDIA-READY`, the deadline, user retries, the descriptor `SEND`, the view-once sender cleanup; run on a class-0 **and a class-10 object (805 ops)** with scripted INDETERMINATE and FAILED outcomes | **per ordinal:** op ids unique; every released outcome maps to exactly one `(object, ordinal, retry_gen, resend_count)`; ≤ 2 resends per ordinal and retry generation; an ordinal acknowledged (`sent`, `degraded`, final `indeterminate`) is never enqueued again, also after a retry; ≤ 32 open ordinals per object and ≤ 64 per device; **per object:** the descriptor enqueued at most once per SEND attempt and only when every ordinal is final and none `failed`; FAILED blocks it; `expire_at_minute` never increases and is lowered exactly at READY or the deadline; the view-once cleanup runs after any final descriptor outcome other than FAILED |
| SCN-MC | `MEDIA-INGEST`, `MEDIA-BIND`, `MEDIA-VERIFY`, `RECV` through `decrypt` **and** `sessionInbound` (a first message that is media), the held replay | no blob consumed without a durable file (unless below the free-space floor, counted); every `bound` row names an existing `media_blob`; a `media_blob` is deleted only when no fragment row names it; a hash named by two objects stays bound to both until each resolves; `complete` only with `F + 1` bound rows; `verified` only after a full pass; no L0 with a non-zero slot ever reaches Kotlin |
| SCN-MD | `VIEW-ONCE-OPEN`, the checkpoint, display, `VIEW-ONCE-CLOSE`, lock, restart | `oracle_displayed` has at most one row per view-once object; `key_env` is NULL whenever a display happened; **the raw `.db` and `-wal` hold no byte of the old `key_env` when the handle is returned** (unless the checkpoint reported busy three times, which the run records and counts); a `viewing` row at start becomes `viewed` |
| SCN-ME | `SWEEP` with media, reconcile, `MEDIA-GC`, the `incomplete` and `corrupt` paths | no row or `key_env` of an expired message's object after the commit, and no `key_env` byte in the raw `.db` or `-wal` after the checkpoint; no file after the next reconcile (except blobs another live object names); pooled blobs gone after their day |
| SCN-MF | migration M | a crash at any statement leaves v5 (or the previous version) with every row and trigger, which migrates again; the v5 → M object-set test (F9 G-9's `sqlite_master` comparison) |

Scale: `media-exit-gate` enumerates every crash point of one scripted run per scenario (both journal modes) plus 1 000 seeded worlds with random crashes, split into **8 shards of at most 180 minutes each** (the `entitlement-exit-gate` pattern of 12 shards; Phase 9's `t2-exit-gate` hit its 240-minute timeout four times, so no single job may approach it); the class-10 SCN-MB run is sampled (every crash point of the first and last 64 ops, 1 000 random points in between). The PR variant samples.

### 15.4 Seeded worlds (functional)

Worlds of 2–6 clients across week boundaries, with: relays that withhold, delay or corrupt fragments; a relay that lies short on expiry; allowance exhaustion; a card holder flooding `M` by deposits and by its own write capability; **a card holder that lists `M` and names another sender's fragment hashes in its own manifest, before, during and after the victim's upload** (hash squatting); a first message that is media (PreKey, function 14), media after a reset and a held media message after a key change; recipients offline 3 h, 3 d and 20 d; a message deleted by its user during upload; an upload that reaches its deadline; `FAILED` and INDETERMINATE fragment ops with user retries; objects of every class; view-once; 5-minute, 1-hour, 7-day and off timers. Oracles: every object whose descriptor is displayed is either `verified` byte-identical to the sender's content or in a declared loss (`incomplete` past its relay expiry because every relay of the set withheld or lost a blob, because the allowance was exhausted, or because a flood evicted its pooled fragments before its descriptor arrived); `corrupt` only for an object whose **own** sender was modified (a manifest that does not open or disagrees, a chunk that fails), never for an honest object because another object named its hashes (relays cannot alter hash-checked blobs, and ownership is decided by each object's AEAD, D25); no duplicate objects; resumption without re-fetching a stored blob (the relay-side `get` counts).

### 15.5 T25 for media (the EP-M suite)

For each timer × path (sender uploaded, sender failed (FAILED outcome, and deadline reached), sender deleted by its user during upload, view-once sender after a final SENT, DEGRADED and INDETERMINATE descriptor, recipient awaiting, fetching, verified-unread, verified-displayed, incomplete, corrupt, view-once opened, view-once unopened): advance the virtual clock to the §11.1 bound + 1 min, sweep, reconcile, then assert (1) logically: no `media_object`, `media_upload`, `media_fragment` or `media_outbound_op` row; (2) physically: the raw `.db` and `-wal` contain neither the plaintext canary nor `key_env` bytes, no fragment's bytes after the later of the bound and the object's op deadline (frozen outbox payloads, F9 §10.3), and `noBackupFilesDir/m/` contains no file of the object; (3) the WAL is 0 bytes after the checkpoint; **(3b) right after `VIEW-ONCE-OPEN` returns its handle, and right after every other transaction that nulls or deletes a `key_env`, the raw `.db` and `-wal` hold no byte of the old `key_env`** (mutant MC-M19 removes the checkpoint); (4) a clock stepped back one day does not delay deletion; (5) every captured media store's TTL is the conversation's bucket; (6) the preview cache holds no entry of the object. A **test destination** (a model channel namespace, §5.6) runs the same suite to keep the engine destination-agnostic.

### 15.6 The media privacy world (T36, T41; extends F9 §15.6)

At the PR scale (N = 60 clients, 14 days, one seed, the media rate of §15.1) in `android`, and at the gate scale (N = 300, 28 days, 5 seed pairs, media blobs as recipes, §15.1) in its own `media-exit-gate` job with a budget of 240 minutes, measured in S9 before the number is fixed (Phase 9's gate-scale privacy world never completed in CI, STATUS; if 5 seed pairs do not fit, the owner chooses between shards and fewer pairs, Q22). Joins over the full effective relay view against the world's ground truth:

| Check | Statement |
|---|---|
| JM1 | every media store is 65 536 B; every object has exactly `F + 1` stores with `F ∈ CLASSES`, **except** objects whose truth records a FAILED outcome, a reached deadline or a user deletion during upload: those have fewer, with no descriptor after them, and each is counted and listed (the `LM` exemptions); an object of a 5-minute conversation is never short because of its timer |
| JM2 | `F = class(content_len)`; every image is class 0; each object has exactly one manifest blob |
| JM3 | exact: no blob hash is shared by two objects of honest senders (including the same file sent to two recipients), and no two objects share `(K_f, object_id)` in the world's truth (so no keystream is shared); sampled: 16-byte windows at 64 random offsets of every media blob, in one hash set over the world, collide across objects only by chance (≤ the birthday bound; an exhaustive window join over every byte is too large at the gate scale) |
| JM4 | every media store's TTL is `bucket(conversation timer)` and no store is made after its op's deadline |
| JM5 | all stores into one `M` at one relay present one scope; no client redeems or registers for another's `M` |
| JM6 | every `list` and `get` of an `M` is made by its owner (reads confined) |
| JM7 | every `get` on an `M` happens in a work bundle of one of that namespace's pair events, for a hash a listing of that namespace returned (no `get` outside the schedule) |
| NI-M1 | twins: a descriptor delivered vs withheld by the relays of `X` → identical relay views of the recipient |
| NI-M2 | twins: the recipient opens, views and view-once-opens everything vs nothing → identical relay views |
| NI-M3 | twins: an image vs a video of class 0; with vs without caption; sender A vs sender B → identical recipient-side and relay views except the sender's own circuit |
| NI-M4 | twins: view-once vs normal objects of equal size → identical relay views on both sides |
| NI-M5 | twins: an identity that never uses media vs one that sends and receives media every day → identical redeem, register and list traces (T27, T31, D11) |
| NI-M6 | twins **at the pool cap**: a card holder floods the recipient's `M_0` past `POOL_CAP`; in one twin the honest descriptors are delivered, in the other the relays of `X` withhold them → identical relay views of the recipient (fetching never depends on what is pooled or bound; mutant PM-M19 stops ingesting at the cap) |
| NI-M7 | twins: a 5-minute vs a 1-hour timer in one conversation, a class-7 video (289 fragments; a 1-hour bucket admits at most class 8, Q29) uploaded **in background sessions only**, so that it reaches the deadline in both → identical relay views on both sides (the burst is never cut by the timer, D26; mutant PM-M20 starts the countdown at the commit) |

**Normalized views.** A twin comparison compares, per relay, the ordered list of events with their minute, operation, namespace role (own inbox, own media, a contact's media, …), size, TTL, credential scope class and circuit, with blob hashes replaced by their rank of first appearance and payload bytes by their length. Ciphertext differs between twins by construction (different content, the OS's randomness); what the relay can **group** and **time** must not.

The seizure check (T34-style, T39): at day 28, dump both databases, keys and files of every client; try every stored `key_env` (unwrapped with the harness state key) on every archived relay blob of expired or viewed objects: 0 opened; control: live objects open.

### 15.7 The T5 corpus and EXIF-zero (T37; emulator and device)

Inputs with a unique canary string in every text field and distinctive numeric values in every numeric field:

| Container | Metadata planted |
|---|---|
| JPEG | EXIF: GPS IFD, Make, Model, Software, BodySerialNumber, LensSerialNumber, DateTimeOriginal, OffsetTime, SubSecTime, ImageUniqueID, MakerNote, an IFD1 thumbnail showing a different picture; XMP (history, face regions with names, GCamera MotionPhoto); IPTC (APP13); ICC (APP2); MPF with an Ultra HDR gain map; COM; APP11 JUMBF/C2PA; a Motion Photo MP4 after EOI; a Samsung SEFT trailer; each of the 8 orientations |
| PNG | eXIf, tEXt, iTXt and zTXt (XMP), tIME, iCCP, alpha |
| WebP | EXIF, XMP, ICCP chunks |
| HEIC / AVIF (if V-M5 admits them) | Exif and XMP items, `thmb`, a depth auxiliary image |
| MP4 / MOV | `mvhd`/`tkhd`/`mdhd` times; `udta` with `©xyz`, `©mak`, `©mod`, `©swr`, `loci`; `meta`/`keys` with `com.android.version`, manufacturer, model, capture fps, ISO 6709 location; an XMP `uuid` box; a GPMF-style metadata track; H.264 SEI user data with a canary; rotation 90 |
| MP4 **already matching the output** (H.264 High or Main + AAC-LC, ≤ 720p30, SDR, square pixels, below the bitrate budget) | everything of the row above, plus distinctive SPS/VUI values (a non-default colour description and level) and a canary in an AAC data-stream element (DSE) and in a fill element; the check adds: the export named both encoders, the output's SPS/VUI are the device encoder's (not the source's), and no source NAL unit or AAC frame appears byte for byte in the output (V-M17, PM-M18) |

Each goes through `sendMedia` on the emulator (and on the gate devices), is received by a second instance, verified and decrypted; the host then checks: (1) `exiftool -a -G1 -s` (13.59, pinned by SHA-256) lists only an allowlist of structural tags with constant values; (2) a byte search finds no canary (ASCII, UTF-16LE, UTF-16BE) and no planted GPS rational or ISO 6709 string; (3) orientation goldens hold (pixel comparison within tolerance); (4) nothing follows EOI; the video has no `udta`, `meta`, `uuid` and its times equal the constant; (5) the preview passes the same checks. ExifTool is GPL-or-Artistic ("same terms as Perl"), run only on CI hosts, never shipped or linked (ADR-37 allows CI tools; point 9 is about implementing from AGPL sources, not running a tool).

### 15.8 No-plaintext-cache and Media3 (emulator; the gate's third item)

1. **Sandbox scan.** After a script that sends and receives the corpus, plays every video with 20 random seeks, opens a view-once item, backgrounds, locks and unlocks: pull every app directory (`files`, `cache`, `code_cache`, `no_backup`, `databases`, `shared_prefs`, `app_*`, `/data/user_de/0/<pkg>`, `/sdcard/Android/data/<pkg>`, `/sdcard/Android/media/<pkg>`) and search every file for 64-byte windows at 97 random offsets of every plaintext and preview, **of every picked source file and of the decoded RGBA rows** of every displayed image, and for the canaries: 0 hits. Every file under `m/` is 65 536 B and passes a χ² uniformity test; no other media-looking file exists (magic-byte sniff). **System directories** (emulator images with `adb root`): the same search over `/data/system_ce/0/snapshots` (task snapshots; every media window, including the harness activity, has FLAG_SECURE and on API 33+ `setRecentsScreenshotEnabled(false)`, so 0 hits is required; mutant PM-M23 drops them), and over `/data/tombstones` and `/data/system/dropbox` after a forced `:mdec` crash, whose content is **recorded, not required to be empty** (L8-M8, V-M20).
2. **`MediaStore`:** a query for rows whose `OWNER_PACKAGE_NAME` is GHOST returns 0; `dumpsys media_session` shows no GHOST session.
3. **Seek, resume, corruption (FR-7.4).** Seeks to 50 random positions land within one fragment duration of the target; playback resumes after `onStop`/`onStart` and after a process restart; a corrupted fragment file (one flipped byte, injected on disk after `verified`) makes the reader fail with `HASH_MISMATCH`, the player end with a typed error, not a crash, and the object become `corrupt` (`verified → corrupt`, §7.3; a JVM variant runs in `media-exit-gate`, mutant MC-M22), and nothing plaintext is written.
4. **Logs:** the F9 logcat scan with a random marker line (F9 §22.32) finds no canary across the run, including `:mdec`.
5. **Backup (T4):** `bmgr` and a device-transfer dry run contain nothing of `m/`.
6. **Decoder isolation (T40).** Every strip and decode request of the run reports a distinct PID and a process that is gone after the reply (`dumpsys activity processes`); a STRIP and a DECODE never share a PID (mutant PM-M21 reuses one instance); binding the service on API 29, 35 and 37 succeeds with the `GhostApp` early return and fails without it (MC-M23).

### 15.9 Mutants (46; each detected against a same-scale control)

Each mutant counts in exactly one report, its **home**: `media-exit-gate` (JVM `MediaMutantDetectionTest` and Rust `media_mutants`; 39 mutants, report line `media mutants: 39 run, 39 detected`), `media-emulator` (5 mutants that need Android, line `media emulator mutants: 5 run, 5 detected`) or `self-test.sh` (2 mutants that are static-gate fixtures, counted in the gate's hit counts). Revision 1 claimed 32 in one JVM report although five of them could only be caught on Android; revision 2 adds 14 for the corrected rules.

**Privacy (PM-M, 23)**

| ID | Mutation | Detected by | Home |
|---|---|---|---|
| PM-M1 | the last fragment stored in a smaller bucket | JM1 | exit-gate |
| PM-M2 | exact fragment counts, no classes | JM2, NI-M3 | exit-gate |
| PM-M3 | a cleartext header (object id or counter) on each fragment | JM3, χ² | exit-gate |
| PM-M4 | the manifest sized by its hash list (one to three blobs) | JM1, JM2 | exit-gate |
| PM-M5 | `M` fetched when a descriptor arrives (`want`) | NI-M1, JM7 | exit-gate |
| PM-M6 | a second recipient gets the same blobs (shared object) | JM3 | exit-gate |
| PM-M7 | the sender redeems its own capability for `M_c` | JM5 | exit-gate |
| PM-M8 | view-once objects stored with the 1-hour TTL | JM4, NI-M4 | exit-gate |
| PM-M9 | previews cached in `cacheDir` | the JVM file-port spy (and the sandbox scan) | exit-gate |
| PM-M10 | the player wrapped in `CacheDataSource` over `SimpleCache` | G-M1 fixture (and the sandbox scan) | self-test |
| PM-M11 | EXIF copied onto the re-encoded JPEG | reader rejection (and the T37 corpus) | exit-gate |
| PM-M12 | Transformer's default muxer and its metadata | T37 corpus; walker | emulator |
| PM-M13 | `decrypt` (function 13) returns the filled key slot to Kotlin | key-slot test; T3 heap canary | exit-gate |
| PM-M14 | received JPEGs decoded with `ImageDecoder` in the main process | G-M3 fixture | self-test |
| PM-M15 | the caption uncapped, so a media message can move to 16 KiB | bucket property test; NI-M3 | exit-gate |
| PM-M16 | `M_0` registered only at the first media use | NI-M5 | exit-gate |
| PM-M17 | `sessionInbound` (function 14) returns the filled key slot (a first message, the held replay) | key-slot test through function 14; SCN-MC | exit-gate |
| PM-M18 | transmux allowed (the encoder factory does not force encoding, no encoder-name check) | the matching-source corpus row (§15.7); V-M17 | emulator |
| PM-M19 | `MEDIA-INGEST` stops claiming at `POOL_CAP` | NI-M6 | exit-gate |
| PM-M20 | the sender's countdown starts at `MEDIA-COMMIT` | NI-M7; JM1's exemption list | exit-gate |
| PM-M21 | one decoder process reused across requests (and across STRIP and DECODE) | §15.8 item 6 (PIDs) | emulator |
| PM-M22 | `key_env` bound to `object_id` only (no role, destination or manifest) | binding tests (a contact-X `key_env` offered for contact Y must fail) | exit-gate |
| PM-M23 | a media window without FLAG_SECURE and `setRecentsScreenshotEnabled(false)` | the snapshot-directory scan (§15.8 item 1) | emulator |

**Correctness (MC-M, 23)**

| ID | Mutation | Detected by | Home |
|---|---|---|---|
| MC-M1 | `key_env` persisted at `sealBegin`, preparation resumed under it | SCN-MA nonce registry | exit-gate |
| MC-M2 | the chunk index missing from the nonce | reorder vectors | exit-gate |
| MC-M3 | the last flag not checked | truncation vectors | exit-gate |
| MC-M4 | fragments opened without checking their hashes | corruption matrix (`HASH_MISMATCH`) | exit-gate |
| MC-M5 | the pad not checked for zeros | pad vectors | exit-gate |
| MC-M6 | the view-once key erased after the display | SCN-MD | exit-gate |
| MC-M7 | media rows deleted after the SWEEP commit | SCN-ME | exit-gate |
| MC-M8 | random media op ids | SCN-MB (duplicate enqueue after a crash) | exit-gate |
| MC-M9 | the descriptor sent before the upload finished | SCN-MB ordering oracle | exit-gate |
| MC-M10 | no `POOL_CAP` | flood world (pooled bytes above the cap) | exit-gate |
| MC-M11 | the commitment not checked | multi-key vector | exit-gate |
| MC-M12 | `markConsumed` before the file is durable | SCN-MC with lost unsynced writes | exit-gate |
| MC-M13 | sandbox failures retried without a poison bound | T40 crash suite (JVM fake sandbox with injected failures) | exit-gate |
| MC-M14 | media work moves a list event | `T19BasicTest` with media | exit-gate |
| MC-M15 | reconcile ignores `preparing` | SCN-MA | exit-gate |
| MC-M16 | an object never becomes `incomplete` | expiry world | exit-gate |
| MC-M17 | first binder wins (a hash bound to one object only; revision 1's rule) | the hash-squatting world (§15.4) | exit-gate |
| MC-M18 | upload state per object (one `attempt` counter) instead of per ordinal | SCN-MB on the class-10 object with INDETERMINATE resends and a retry | exit-gate |
| MC-M19 | no WAL checkpoint after a transaction that nulls or deletes `key_env` | SCN-MD, EP-M (3b) raw `.db`/`-wal` scan | exit-gate |
| MC-M20 | the view-once sender cleanup skipped on a final INDETERMINATE descriptor | EP-M (view-once sender path); SCN-MB | exit-gate |
| MC-M21 | manifest dimensions and duration trusted from Kotlin, not walked | walker vectors (§15.2 item 6) | exit-gate |
| MC-M22 | on-disk corruption after `verified` not handled (`verified → corrupt` missing) | the JVM variant of §15.8 item 3 | exit-gate |
| MC-M23 | the `Process.isIsolated()` early return removed from `GhostApp.onCreate` | the binding test (§15.8 item 6) | emulator |

### 15.10 Exit-gate argument

| Gate item (plan:315) | Evidence | Where it runs |
|---|---|---|
| corruption/resume | §15.2 matrix and vectors (Rust and JVM); SCN-MA … SCN-MC (per-ordinal upload state, the class-10 object); seeded worlds incl. hash squatting; §15.8 item 3 (Media3 seek, resume, on-disk corruption) | `rust`, `android`, `media-exit-gate` (JVM); emulator job for item 3 |
| EXIF-zero | §15.7 corpus through the real pipeline, including sources that already match the output, ExifTool and canaries; walker property tests | emulator job (+ gate devices); `rust` |
| no-plaintext-cache | G-M1, G-M2, G-M3 static gates; §15.8 sandbox and system-directory scans, `MediaStore`, logs, backup, decoder isolation; T39 physical scans of the database and WAL | PR gates; emulator job; `media-exit-gate` |
| (also) T25 media, T36–T41, 46 mutants (39 + 5 + 2) | §15.5, §15.6, §15.9 | `android`, `media-exit-gate`, emulator job, `self-test.sh` |

**What is not proven without hardware or people (CP-10).** The Android half of the gate needs an emulator job on a runner with KVM, which the project does not have (`dm-emulator.yml` has never run on a runner; `docs/STATUS.md`), or a signed manual run of the same scripts. The `android` CI job itself has been skipped on every run since 2026-09-20, because `android-native` fails at its artifact upload (the CI artifact quota, an owner action, STATUS), so until that is fixed no Android slice can end green in CI and local runs are the slice evidence (D23, Q32). Real encoders' SEI and AAC elements, hardware codecs and MTE need the physical-device checklist on owner-provided phones (Q31). Transfer times need live Tor and, for realism, staging relays (an owner action). The media format is inside the external cryptographic review scope, which has not happened for Phase 9 either. Until all apply, `docs/STATUS.md` records Phase 11 as "implemented and tested locally", and no UI claim is made.

---

## 16. Gates, CI, dependencies

### 16.1 Gates (each with a negative fixture and a `self-test.sh` hit count)

| Gate | Rule | Supports |
|---|---|---|
| **G-M1** `media-no-plaintext-io.sh` | in `android/*/src/main` (and the `gate` source set): no reference to `SimpleCache`, `CacheDataSource`, `CacheDataSink`, `CacheWriter`, `DownloadManager`, `DownloadService`, `DownloadHelper`, `DefaultDataSource`, `DefaultHttpDataSource`, `HttpEngineDataSource`, `UdpDataSource`, `AesCipherDataSource`, `AesCipherDataSink`, `FileDataSource`, `InAppMp4Muxer`, `MediaStore`, `MediaScannerConnection`, `getExternalFilesDir(s)`, `getExternalCacheDir(s)`, `getExternalMediaDirs`, `Environment.getExternalStorage`, `createTempFile`, `getCacheDir`, `getCodeCacheDir`, `openFileOutput`, `FileProvider`, `ACTION_SEND`, `ClipData`, `BigPictureStyle`, `setLargeIcon`, `MediaSession`; `FileOutputStream`, `RandomAccessFile`, `Files.newOutputStream`, `FileChannel.open` with write options only in `CiphertextFiles`; `Transformer` only in `GhostTranscoder` | T38 |
| **G-M2** Gradle dependency rule | allowed Media3 artifacts: `media3-common`, `-datasource`, `-decoder`, `-extractor`, `-container`, `-exoplayer`, `-transformer`, `-effect`, `-muxer` (and `-ui` from Phase 13); forbidden: `media3-session`, `-datasource-okhttp`, `-datasource-cronet`, `-datasource-rtmp`, `-exoplayer-hls`, `-exoplayer-dash`, `-exoplayer-smoothstreaming`, `-exoplayer-rtsp`, `-exoplayer-ima`, `-exoplayer-workmanager`, `-cast`; `com.google.android.gms` stays denied | T38, ADR-06 |
| **G-M3** `media-decoder-confinement.sh` | `ImageDecoder`, `BitmapFactory`, `ExifInterface`, `MediaMetadataRetriever`, `HeifDecoder` referenced only in `org.ghost.media.sandbox` | T40 |
| **G-M4** `merged-manifest-lint.sh` | the exported-component rule is unchanged; the merged manifest has exactly one isolated service, `MediaDecodeService`, with `isolatedProcess="true"`, `exported="false"`, `process=":mdec"` and no intent filter; no `FileProvider`, no `com.google.android.gms.metadata.ModuleDependencies`, no new permission; a source check that `bindIsolatedService` is the only way `MediaDecodeService` is bound and never with `BIND_SHARED_ISOLATED_PROCESS` | T15m, T40 |
| **G-M5** G-R6 `dm-jni-surface.sh` | the exported `Java_org_ghost_crypto_bridge_MediaNative_*` symbols equal §13.2's list; `testVectors` and `testSealBeginWithKey` only in host and test libraries | ADR-19 |
| **G-M6** G-DM2 `dm-enqueue-callers.sh` | `Outbox.enqueue` for `Consumer.MEDIA` only from `MediaFeeder`; `Namespaces.register` for MEDIA only from `MEDIA-COMMIT` and the owner steps; never from ingest, bind, verify or display code | T41 |
| **G-M7** G-R1, G-R2, G-R4, G-R8, `rust-license-headers.sh` | `ghost-client-media` in the workspace allowlist and in the no-logging and no-clock scans; **a `ghost-client-media` line in `client-core/rust-dependency-allowlist.txt`** (it enters `libghost_client_net.so` through `ghost-client-dm`, as `ghost-client-dm` got its line in slice S4b), so `rust-client-allowlist.sh` gains exactly that workspace line and no external crate; **`rust-feature-policy.sh` (G-R2)** requires `ghost-client-media` in the shipped graph with no feature but its empty `default`, so `nonce-registry` and any test feature can never reach an Android build (the `ghost-client-dm` clause's pattern); `rust-crypto-pins.txt` unchanged | T3, T7 |
| **G-L2** `license-notices.sh android` | `gradle-license-allowlist.txt` gains the Media3 artifacts and their runtime transitives, **including `com.google.guava:guava` (33.3.1-android, a compile dependency of `media3-common` 1.11.1, its POM) and `com.google.guava:failureaccess`**, both Apache-2.0 (`listenablefuture` is already listed); each line is an ADR-06 licence review (Q28) | ADR-06, ADR-37 |
| **G-M8** `media-golden-lock.sh` | at a Media3 pin change, the fMP4 and encoder goldens of the new version exist and the walker passes them (the F9 G-R7 idea) | T37 |
| **G-M9** `media-report-check.sh` | requires the `media-exit-gate` lines: crash classes per SCN-M scenario, seeded worlds, `media mutants: 39 run, 39 detected`, JM1–JM7 = 0 (JM1 with its exemption list), NI-M1–NI-M7 equal, T25-media and seizure lines; and the emulator report's `media emulator mutants: 5 run, 5 detected`; refuses numbers larger than measured (the `dm-report-check.sh` rule) | exit gate |
| existing | `sync-no-catch-all.sh`, `no-logging.sh`, `anti-placeholder.sh`, `kotlin-clearnet.sh` cover `android/media`; `apk-native-libs.sh` unchanged (no new `.so`; V-M7); `capture-check` gains the media-burst fixture | T3, T6, T8, T12 |

### 16.2 CI jobs

| Job | Change |
|---|---|
| `rust` | `ghost-client-media` tests, vectors, property runs, the `aead-stream` oracle |
| `android` | `:media` JVM tests, `MediaWorld` at the PR scale, the host build with media, `MediaMutantDetectionTest` PR subset |
| `media-exit-gate.yml` (new) | full crash enumeration and 1 000 seeded worlds in 8 shards of ≤ 180 min; the gate-scale privacy world in its own job (≤ 240 min, measured in S9); the 39 JVM and Rust mutants; `media-report-check.sh`; artifact uploads `continue-on-error` so a quota failure cannot hide a green test step (the Phase 9 lesson) |
| `media-emulator.yml` (new, or a stage of `dm-emulator.yml`) | §15.7 and §15.8 on API 29, 35, 37, the 5 emulator mutants; ExifTool pinned by SHA-256 (owner pins, like ProVerif's); **needs a KVM runner**; about 2 h per API level [I] |
| `sync-exit-gate` | re-run with the media consumer (§13.3) |
| `t2-exit-gate` | `dm_owner_namespaces = 3` baselines; the job already takes up to 222 of its 240 minutes (F9 §22.24), so the third owner namespace may push it over: shard it or raise the timeout (owner, R-M13) |

### 16.3 Dependencies and licences

| Dependency | Version | Licence | Role | Status |
|---|---|---|---|---|
| `androidx.media3:media3-exoplayer`, `-transformer`, `-muxer` (+ transitives `-common`, `-datasource`, `-decoder`, `-extractor`, `-container`, `-effect`) | **1.11.1** (stable, 2026-09-10; the catalog pins 1.11.0, `libs.versions.toml:14`) | Apache-2.0 | player, transcoder, fMP4 muxer | new in the build; allowed by plan:464 and the `androidx.` prefix; `verification-metadata.xml` entries in S0 (Media3 has never been resolved); Q14 |
| `com.google.guava:guava` | 33.3.1-android (compile dependency of `media3-common` 1.11.1, with Media3's exclusions of `jsr305`, `checker-qual`, `error_prone_annotations`, `j2objc-annotations`, `animal-sniffer-annotations`) | Apache-2.0 | Media3 internals | **new in the shipped app**: a G-L2 line and an ADR-06 review (Q28); no network or telemetry code |
| `com.google.guava:failureaccess` | 1.0.2 (Guava's) | Apache-2.0 | Guava internals | new in the shipped app, G-L2 line (Q28) |
| `androidx.exifinterface:exifinterface` | latest stable at S0 | Apache-2.0 | orientation in the sandbox only, if V-M4 fails | conditional |
| `ghost-client-media` | workspace | proprietary | format and walkers | new crate in the shipped graph: a line in `rust-dependency-allowlist.txt` and a G-R2 feature clause (G-M7); no new external crate |
| `aead-stream` | =0.6.0 (2026-06-28) | Apache-2.0 OR MIT | differential oracle, **dev graph only** | new dev dependency (V-M8) |
| ExifTool | 13.59 (2026-05-27), pinned by SHA-256 | GPL or Artistic ("same terms as Perl") | CI-only oracle, never shipped | host tool |

No GPL, LGPL or AGPL component enters a shipped artifact (ADR-37 point 2); no libsignal source was read (point 9).

---

## 17. Slices, effort, exit-gate checklist

### 17.1 Slices (the Q defaults apply unless the owner objects)

**Evidence per slice.** A slice ends green in CI where CI can run it: the `rust` job, the static gates and the JVM jobs. The `android` job has been skipped since 2026-09-20 (the CI artifact quota, an owner action), and no runner has KVM, so until the owner fixes both (Q32) a slice's Android and emulator evidence is a **local run** (the owner's Windows machine, WHPX emulator), recorded in STATUS with its commit as Phase 9 recorded its device suites (F9 §22.32). Local runs are slice evidence, never gate evidence (D23).

| Slice | Content | Depends on | Exit condition |
|---|---|---|---|
| **S0a** Spikes that need no owner action | V-M1 … V-M8, V-M11, V-M13, V-M14, V-M16 … V-M20 on the local emulator (API 29, 35, 37) and the JVM; Media3 1.11.1 resolved with verification metadata and the G-L2 lines (Guava, `failureaccess`, Q28); the `ghost-client-media` allowlist line and G-R2 clause (G-M7); the fMP4 and JPEG goldens recorded from the emulator's encoders; ADR-40 … 43 filed as "propus" | — | Appendix C updated with each result; any failed check re-plans its slice (the fallbacks named there) before S1 |
| **S0b** Spikes that need the owner | V-M9, V-M12 (SEI and AAC elements of real encoders), V-M15 (MTE) on the reference phones (Q31); V-M10 against an onion relay (staging, an owner action); the ExifTool pin (owner, like ProVerif's); the device goldens added to the walker's allowlist | the owner's devices, relay and pin | Appendix C updated; **gates only the exit checklist (§17.3), never S1 … S10** |
| **S1** `ghost-client-media` | §3, §4.1 codecs, classes, sealer and reader state machines (walked dimensions and duration), JPEG canonicaliser, fMP4 walker and `mfra`, vectors, oracle, property tests, gates G-M7 | S0a | `rust` green; vectors replayed by the JDK implementation |
| **S2** Native surface | `MediaNative` (§13.2), registries, the key slot in `encrypt`, `decrypt` **and `sessionInbound`**, the `MediaFileKey` wrap and its binding, `M` labels in functions 2–4, host build (with `testSealBeginWithKey`), `MediaCrypto` facade, G-M5 | S1 | JVM tests through the host build (including function 14 and the held replay); G-R6 lists pass |
| **S3** Schema and store | migration M (with the Phase 9 columns if Q27 applies), `CiphertextFiles`, the content-addressed store with references, reconcile, `MediaObjects`, SCN-MF | S2 | migration crash enumeration green; introspection tests |
| **S4** Sync lane and owner namespace | §5.5 in `:sync` (store order, media share of the relay budget, fetch slices, `MediaFairnessTest`); `M_0` in the owner steps and the upgrade step; T2 world field; `sync-exit-gate` re-run; T19 with media | S2 (parallel with S3) | `sync-exit-gate` and `t2` PR variant green |
| **S5** Sender pipeline | sandbox `STRIP_IMAGE` (a process per request, the `GhostApp` early return), `GhostTranscoder` (forced encoding, encoder-name check), `GhostMuxer`, `SealingChannel`, `MEDIA-COMMIT`, `MEDIA-FEED`, `MEDIA-OUTCOME`, `MEDIA-READY`, the deadline, retries, `sendMedia`; SCN-MA, SCN-MB | S3, S4 | crash enumeration green; the local emulator smoke run sends one image and one video, one of them a matching source |
| **S6** Recipient pipeline | `MEDIA-INGEST` (eviction, free-space floor), `MEDIA-BIND` (references), `MEDIA-VERIFY`, previews and images through the sandbox; SCN-MC; zero-click rules | S5 | worlds green (incl. hash squatting, first-message media); the local emulator smoke run receives both |
| **S7** Playback and hygiene | `GhostMediaDataSource`, the player, RAM caches, FLAG_SECURE on media windows, G-M1 … G-M4; §15.8 items 1–6 | S6 | gates green; local emulator seek/resume/corruption, system-directory scan, PIDs |
| **S8** Ephemeral and view-once | `MediaPort`, the checkpoints, EP-M suite, `VIEW-ONCE-*`, the sender cleanup, SCN-MD, SCN-ME | S6 | T25 media and CS-M5 green |
| **S9** Privacy world, corpus, mutants | §15.6 (recipes, normalized twins, NI-M6, NI-M7), §15.7, §15.9; `media-exit-gate.yml` (shards timed), `media-emulator.yml`, G-M8, G-M9 | S5 … S8 | report lines at the gate scale where CI allows; mutants 39 + 5 + 2 of 46 |
| **S10** Documents and review | Appendix B applied; an adversarial implementation review round (crypto, privacy, implementability), its corrections as §22 | S9 | the checklist of §17.3 |
| S-CH (not in Phase 11) | channel binding | Phase 10 design | Phase 10's gate |

### 17.2 Effort (calibrated on Phase 9)

**Calibration.** Phase 9's design estimated about 10–12 weeks (F9 §17). Its slices S1 … S14 landed between 2026-09-16 and 2026-09-24, nine calendar days of parallel agent sessions (`git log`). What did **not** finish is the gate evidence: on 2026-09-25 STATUS lists 15 of 57 correctness and 15 of 40 privacy mutants built and run (the gate needs 97), a gate-scale privacy world that never completed in CI, an emulator job that never ran on a runner, and a two-phone checklist not executed. Revision 1's "7–9 weeks for 5–6 people, ≈ 31 person-weeks" was a team model with no calibration and cited STATUS for slice overruns it does not contain; it is withdrawn.

| Slice | Implementation (agent-days) | CI per run | Owner dependency |
|---|---|---|---|
| S0a | 2–3 | — | none (local emulator) |
| S0b | 1–2 | — | reference phones (Q31), onion relay / staging, ExifTool pin |
| S1 | 2–3 | `rust` | — |
| S2 | 1–2 | `rust`, `android` | — |
| S3 | 1–2 | `android` | Q27 decision (optional) |
| S4 | 1–2 | `sync-exit-gate`, `t2-exit-gate` (≤ 240 min, at risk, R-M13) | t2 timeout or shards |
| S5 | 3–4 | `android` + local emulator | — |
| S6 | 2–3 | `android` + local emulator | — |
| S7 | 2 | local emulator | — |
| S8 | 1–2 | `android` | — |
| S9 | 3–5 | `media-exit-gate` 8 × ≤ 180 min + world ≤ 240 min; `media-emulator` ≈ 2 h per API level | KVM runner, CI artifact quota (Q32) |
| S10 | 1–2 | — | — |
| **Total** | **≈ 20–32 agent-days** | | |

At Phase 9's parallelism (S3 ∥ S4, S7 ∥ S8) that is **about 2–3 calendar weeks to "implemented and tested locally"**, which the plan's 3–4 weeks covers. **The exit gate has no date this design can promise:** it needs the KVM runner (or a signed run of the same scripts), the CI artifact quota fixed so the `android` job runs again, two reference phones and a person for the checklist, and staging relays for V-M10, the same owner actions that keep Phase 9's gate open; after they exist, expect one to two weeks of CI and fix rounds (Phase 9's gate evidence took longer than its code). If a gate date is binding, Q22 lists the scope options.

### 17.3 Exit-gate checklist (all on the closing commit)

1. S0a's and S0b's V-M results recorded in Appendix C; no open S0 fallback.
2. `rust`, `android`, `sync-exit-gate`, `t2` PR variant green **on a runner** (not skipped).
3. `media-exit-gate`: every SCN-M scenario at every crash point (the class-10 SCN-MB sampled as §15.3 states); 1 000 worlds; the gate-scale privacy world with JM1–JM7 = 0 (JM1's exemptions listed) and NI-M1–NI-M7 equal; `media mutants: 39 run, 39 detected`; the seizure line; `media-report-check.sh` passes.
4. `media-emulator` on API 29, 35, 37 **run on a runner** (or a signed manual run of the same scripts, recorded as such): §15.7 and §15.8 pass; `media emulator mutants: 5 run, 5 detected`.
5. The physical-device checklist steps for media (two phones: send and receive an image and a video in both directions, a matching-source video, view-once, expiry at 5 minutes, sandbox and snapshot scans on a real device, a real encoder's SEI and AAC elements), signed.
6. G-M1 … G-M9 and G-L2 in `run-all.sh` with fixtures; PM-M10 and PM-M14 counted in `self-test.sh`.
7. Appendix B applied to INVARIANTS (T5 replaced, T36–T41, T10 and T35 changes), THREAT_MODEL, LIMITE (L8), the plan erata, STATUS, the Phase 7 and Phase 9 designs' forward notes.
8. The review rounds' findings corrected or recorded as owner decisions (§21 for the design, §22 for the implementation).
9. ADR-40 … 43 decided by the owner or applied under the default rule.
10. No UI claim (CP-10); STATUS says what ran where.

---

## 18. Risks

| ID | Risk | Likelihood / impact | Mitigation |
|---|---|---|---|
| R-M1 | The implementation fits the plan's 3–4 weeks but the exit gate does not, because its evidence waits on owner actions and CI capacity (as Phase 9's does); Phase 13's dependency on 11 slips | high / medium | §17.2 calibration; S0a first and S0b off the critical path; Q22 scope options; S-CH outside the phase |
| R-M2 | Media3 internals change between versions (muxer writes, extractor seek logic), breaking the canonical profile or seeking | medium / high | exact pin; G-M8 goldens; `GhostMuxer` owns metadata; the walker fails closed |
| R-M3 | The isolated process cannot decode HEIC/AVIF, or `SharedMemory` behaves differently on API 29 | medium / medium | V-M5; HEIC refused (Q9); JPEG, PNG, WebP sources suffice for P0 |
| R-M4 | Transfers are too slow over Tor with a client per RPC; background uploads miss short-TTL deadlines | high / medium | media lane; foreground transfers; Phase 12 pooling (F-M2); no timing claims |
| R-M5 | Allowance exhaustion by a hostile card holder blocks a user's media for a week | medium / low | L8-M4; Q20; card rotation (Phase 13) |
| R-M6 | Device encoders emit SEI or stream fields the walker refuses, so video sending fails on some phones | medium / medium | the SEI filter in `GhostMuxer`; V-M12 across the reference devices; the walker's allowlist from goldens of several devices |
| R-M7 | No KVM runner: the Android half of the gate never runs in CI | high / high | signed manual runs of the same scripts; the owner's runner action (shared with Phase 9) |
| R-M8 | Phase 10, or a Phase 9 fix migration (LIMITE L5's TIMER_SET and control-retry columns), claims the same ADR, invariant or migration numbers, or rebuilds `dm_outbound_item` separately | medium / low | the renumbering rule in the header and §13.6; rebuilds copy the tables as they are at merge; Q27 folds the Phase 9 columns into M |
| R-M9 | Phase 9's open gate or a Phase 9 defect (e.g. L5's TIMER_SET bucket) leaks through the descriptor | medium / medium | media adds no new DM mode; the descriptor is an ordinary 4 KiB user send; DM claims wait for Phase 9's gate |
| R-M10 | A platform image-decoder exploit in the sandbox escapes the isolated process | low / high | isolation limits it to a platform privilege-escalation chain; canonical JPEG only; patched devices; MTE where available |
| R-M11 | Plaintext in the JVM heap during playback is read by a memory-scraping attacker with root | low / medium | foreground only; release at lock; declared (L8-M7) |
| R-M12 | Forced automatic download costs users data, more than the honest allowance when a card holder floods with its own tokens (§5.3) | medium / medium | allowance; Phase 13 pause switch; Phase 12 owner-bound rule; Q4 |
| R-M13 | `t2-exit-gate` (already 222 of 240 minutes on one pair, F9 §22.24) exceeds its timeout with a third owner namespace | medium / medium | shard it or raise the timeout (owner decision, as for `messaging-exit-gate`'s 240 → 480) |
| R-M14 | One isolated process per decode is too slow for a conversation screen full of previews | medium / low | V-M18 measures it in S0a; Q25's fallback (one instance per sender and screen for previews only), declared weaker |
| R-M15 | Owner actions (KVM runner, CI artifact quota, reference phones, staging relays, ExifTool pin) are not done, so the gate cannot close | high / high | S0b and the gate-only items are off the implementation path; local runs recorded as slice evidence; Q31, Q32 |
| R-M16 | A device's encoder emits stream fields or AAC elements outside the goldens recorded on the emulator, so sends fail on that device | medium / medium | device goldens in S0b (V-M12); the walker fails closed with a typed error; the allowlist grows by recorded goldens only (G-M8) |

---

## 19. Owner questions (the proposed default applies unless the owner objects)

| # | Question | Proposed default | Pe scurt (RO) |
|---|---|---|---|
| Q1 | Approve ADR-40 … ADR-43 (Appendix A) as "propus, aplicat"? | **yes** | Aprobarea ADR-40 … ADR-43 |
| Q2 | Content types in Phase 11: still images and video only; no voice notes, audio files, animated images, documents or RAW? | **yes** | Doar imagini statice și video; fără mesaje vocale, fișiere, GIF-uri animate |
| Q3 | DM media in a recipient-owned, card-derived media namespace `M_i` with a shared deposit credential, paid by the recipient (one more token per relay per week for every identity), rather than in the DM inbox or in sender-paid namespaces? | **`M_i`** | Media stă într-un namespace separat al destinatarului, plătit de el, nu în inbox-ul de text |
| Q4 | Download: automatic on `M`'s schedule (no reflex; forced data use), rather than on descriptor or on tap (both tell relays when media is opened)? A Phase 13 global pause switch is allowed. | **automatic** | Descărcare automată, ca releul să nu afle când deschizi media |
| Q5 | Size classes ×1.5 (11 classes, all images in one class, ≤ 59 % overhead) rather than Padmé (≈ 60 classes, ≤ 12 %) or powers of two (7 classes, ≤ 100 %)? | **×1.5** | Clase de dimensiune din 1,5 în 1,5; toate pozele arată la fel |
| Q6 | Images always re-encoded to baseline JPEG, ≤ 2 048 px on the long edge, ≤ 1 MiB (quality lowered as needed); transparency composited on white? | **yes** | Pozele se re-encodează JPEG, maximum 2 048 px și 1 MiB |
| Q7 | Video always transcoded to H.264 + AAC, ≤ 720p, ≈ 2 Mbit/s, ≤ 50 MiB (≈ 3 min 10 s), in fragmented MP4? | **yes** (1080p would halve the maximum duration) | Video re-encodat la 720p, maximum ~3 minute |
| Q8 | Media written to the conversation's 3-relay set like DMs, rather than a 2-relay set (−33 % upload, less availability)? | **3 relays** | Media pe 3 relee, ca mesajele |
| Q9 | Image decoding in an isolated process for sent and received images; HEIC/AVIF sources accepted only if they decode there, otherwise refused (not decoded in the main process)? | **yes** | Decodarea imaginilor într-un proces izolat; HEIC refuzat dacă nu merge acolo |
| Q10 | Native custody of file keys through the key slot, amending Phase 9's functions 8, 13 and 14 (`encrypt`, `decrypt`, `sessionInbound`), with `key_env` bound to role, contact, object and manifest? | **yes** | Cheia fișierului nu ajunge niciodată în Kotlin, nici la primul mesaj |
| Q11 | View-once in Phase 11's gate, key erased in the transaction that opens it and the WAL checkpointed before display (a crash after opening loses the item; never a second view)? | **yes** | „Vezi o singură dată” în poarta fazei; cheia se șterge înainte de afișare |
| Q12 | Media blobs always use the conversation's TTL bucket, no media-specific or view-once TTL? | **yes** | Media folosește treapta TTL a conversației |
| Q13 | Schema: rebuild `dm_message` and `dm_outbound_item` in migration M, rather than amend v5 in place (allowed because v5 never shipped, but it reopens Phase 9's migration evidence)? | **rebuild** | Tabelele DM se reconstruiesc într-o migrare nouă |
| Q14 | Bump Media3 from 1.11.0 to 1.11.1 in S0? | **yes** | Media3 1.11.1 |
| Q15 | No camera capture in Phase 11; in-app CameraX in Phase 13 with the native-library gate change; never the system camera intent? | **yes** | Fără cameră în Faza 11; niciodată aplicația de cameră a sistemului |
| Q16 | No share target and no forwarding UI in Phase 11 (forwarding, later, always re-encrypts)? | **yes** | Fără „Partajează către GHOST” și fără redirecționare în Faza 11 |
| Q17 | Phase 11 delivers the destination-agnostic engine and the DM binding; channel media is designed and gated with Phase 10? | **yes** | Media în canale vine cu Faza 10 |
| Q18 | Ciphertext store as files (inode times declared) rather than SQLCipher BLOBs? | **files** | Ciphertext-ul media în fișiere, nu în baza de date |
| Q19 | Captions up to 1 024 B, so every media message stays in the 4 KiB class? | **yes** | Descriere de maximum 1 024 de octeți |
| Q20 | One registering capability per relay-week for `M_0` (about 256 MiB of honest media per week), not two? (A hostile card holder can make me download more, §5.3, until Phase 12's owner-bound rule.) | **one** | 256 MiB de media primită pe săptămână de la contacte oneste |
| Q21 | MTE (`memtagMode="sync"`) for the `:mdec` process if S0b shows it can be set per process; otherwise not in Phase 11? | **yes, conditional** | MTE pentru procesul izolat, dacă se poate per proces |
| Q22 | Accept the calibrated estimate (about 2–3 weeks to "implemented and tested locally"; the gate dated by owner actions) and the slice order (S0a first, S0b off the critical path)? If a gate date is binding, which scope to cut first: (a) view-once out of the gate (it is P1), (b) the gate-scale privacy world at 2 seed pairs instead of 5, (c) video seek (FR-7.4's seek test) moved to Phase 13? | **yes; no cut** (if one is needed: (a), then (b); never EXIF-zero or no-plaintext-cache) | Estimarea calibrată pe Faza 9; poarta depinde de acțiunile proprietarului |
| Q23 | Add Phase 11 to Phase 12's dependencies, so the independent metadata-capture review covers media (plan row 12)? | **yes** | Revizia capturii de metadate din Faza 12 include media |
| Q24 | `POOL_CAP` 512 MiB enforced by evicting the pooled blobs that expire first (never by fetching less), and unmatched blobs dropped after 8 days? | **yes** | Plafon de 512 MiB prin ștergere locală; descărcarea nu se oprește niciodată |
| Q25 | Decoder isolation: a fresh isolated process per strip or decode request (never shared between two objects, or between stripping and decoding)? If S0a (V-M18) shows the start cost too high for previews: one instance per sender and screen for previews only (weaker, declared)? | **per request** | Un proces izolat nou pentru fiecare imagine decodată |
| Q26 | The sender's countdown of a media message starts when its upload ends (`MEDIA-READY`, or the deadline), so a burst is never cut by a 5-minute timer and relays cannot tell 5-minute from 1-hour timers; the caption and ciphertext then live up to about 1 h 5 min for a 5-minute message? | **yes** | Numărătoarea expeditorului pornește la finalul încărcării |
| Q27 | Fold Phase 9's open schema fixes (LIMITE L5: the TIMER_SET bucket column in `dm_outbound_item`, the attempts column in `dm_scheduled`) into migration M's rebuild if the owner decides them before S3; otherwise M copies the tables as they are at merge? | **fold if decided; otherwise copy** | Remedierile de schemă ale Fazei 9 intră în migrarea media, dacă sunt decise |
| Q28 | Accept Guava 33.3.1-android and `failureaccess` (Apache-2.0, hard runtime dependencies of `media3-common`) in the shipped app, with G-L2 lines and an ADR-06 note? | **yes** | Guava intră în aplicație prin Media3 |
| Q29 | In conversations whose TTL bucket is 1 h (5-minute and 1-hour timers), limit video to class 8 (≈ 28 MB, sources ≤ 100 s) and answer `TOO_LARGE_FOR_TIMER` above it, since classes 9–10 need about 23–64 minutes of foreground upload? | **yes** | În conversațiile de 5 minute și 1 oră, video de maximum ~100 de secunde |
| Q30 | A foreground service (`FOREGROUND_SERVICE_DATA_SYNC`, allowed by T15) for large uploads: not in Phase 11 (UI-less); Phase 13 decides with its constant notification text? | **defer to Phase 13** | Serviciu în prim-plan pentru încărcări: decis în Faza 13 |
| Q31 | Reference devices for S0b and the checklist, provided by the owner: one Pixel with MTE (8 or later) and one Samsung; until then S0b and checklist items wait, with no claim? | **yes (owner provides)** | Două telefoane de referință: un Pixel cu MTE și un Samsung |
| Q32 | CI owner actions: fix the artifact-storage quota (the `android` job is skipped since 2026-09-20) and enable KVM on one runner; until then local runs, recorded with their commits, are slice evidence and the gate waits? | **yes** | Cota de artefacte CI și KVM pe un runner; până atunci, rulări locale |
| Q33 | Build a seeded `getrandom` backend for the host library (F9 planned it, never built)? The media checks are designed not to need it. | **no** | Fără generator determinist; testele nu depind de el |
| Q34 | FLAG_SECURE and `setRecentsScreenshotEnabled(false)` on every window that shows media from Phase 11 (T10's rule brought forward for media screens, including the gate harness)? | **yes** | FLAG_SECURE pe ecranele cu media încă din Faza 11 |
| Q35 | Treat AAC raw data blocks as opaque (declared: a modified sender can put bytes in AAC data elements, which reach only the out-of-process decoder), rather than write an AAC element parser? | **declare, do not parse** | Blocurile AAC nu se parsează; limita se declară |

---

## 20. Findings outside Phase 11 (proposed as separate tasks)

| ID | Finding | Proposed owner |
|---|---|---|
| F-M1 | Plan row 12 ("review independent al capturii de metadate") depends on 6, 7, 10, not 11, so no phase reviews media traffic | plan erratum (Q23) |
| F-M2 | Phase 7 creates a relay client per RPC (F7:85); bulk transfers pay two round trips per 64 KiB | Phase 12: connection pooling with a rotation epoch, measured on media |
| F-M3 | Relays have no disk cap beyond allowances × TTL; the FR-5 load and abuse suite should include media volumes | Phase 12 relay hardening |
| F-M4 | The DM privacy world has no HIGH mode (F9 §22.16); the media world inherits the gap | Phase 9 follow-up |
| F-M5 | Channel media fan-out: one 50 MiB post read by 1 000 members is about 50 GB of relay egress | Phase 10 design |
| F-M6 | SQLCipher ignores the no-backup directory request (`docs/STATUS.md`, F9 §22.32 point 5); media keys live in that database | Phase 9 owner decision, unchanged |
| F-M7 | T35's provenance labels do not cover the intro inner layer (F9 §22.16 item 18); media in first messages inherits the gap (§3.8) | Phase 9 follow-up |
| F-M8 | The Phase 7 work lane is one thread for every consumer's fetches and stores (`Session.kt:129`); any bulk consumer can delay DM fetches. Phase 11 adds media slicing and a budget share (§5.5); a general per-consumer fairness rule belongs to the sync track | Phase 12 sync review |

---

## 21. Review round of revision 2 (2026-09-25): findings, verification, dispositions

Three adversarial reviewers read revision 1 (`4bd01ec`) through three lenses: protocol and cryptography (`RV-C`), privacy and metadata (`RV-P`), feasibility, testability and scope (`RV-F`). Every finding was checked against the repository at `f244b80` or a primary source before it was accepted; several were raised by two lenses and are handled once. The reviewers' texts reached this revision truncated after crypto L6, privacy M3 and feasibility item 10: findings beyond those points could not be read and are **not** claimed as handled.

| ID | Finding (short) | Verified | Disposition | Where |
|---|---|---|---|---|
| RV-C1 = RV-F1 | **High.** The key slot was wrapped only in `decrypt` (13); `sessionInbound` (14) also returns a decrypted L0, for PreKey first messages and the held replay, so the file key would reach Kotlin or the media message would be lost | yes: `jni.rs:1268-1269` returns `Field::L0`; `HeldReplay.kt:27` and `DmSessions.kt:510` call `sessionInbound`; F9 §2.6 row 14, §6.8, §7.4 R7; revision 1 also wrongly said the held replay calls `decrypt` | fixed: function 14 wraps and zeroes like 13; lists, ADR-40, Q10 amended; tests through 14 and the held replay; mutant PM-M17; first-message media in the worlds and SCN-MC | D7, X-M9, §4.2, §13.4, §15.2, §15.3, §15.4, §15.9, ADR-40, Q10 |
| RV-C2 = RV-P6 | **High.** First binder wins: a card holder who lists `M` names a victim's fragment hashes in its own manifest, captures them during the victim's upload and makes the honest object `corrupt` | yes: `media_fragment.blob_hash` was the primary key; a card holder can list and get `M` (F9 §4.5, L7-D16) | fixed: content-addressed store with references (`media_blob`, `media_fragment(object_id, ordinal)`), ownership by AEAD, deletion only when unreferenced, return to pool on `corrupt`/`incomplete`; the oracle rewritten; hash-squatting world; mutant MC-M17 | D25, §3.4, §7.2, §13.6, §15.3, §15.4, §15.9 |
| RV-C3 | **Medium.** One long-lived `:mdec` process served every decode and strip for 30 s: an exploit stays resident, sees later images and shapes the user's next sends | yes (design text; `bindIsolatedService` with instance names exists since API 29 = minSdk) | fixed: a process instance per request, never shared; input regions read-only, output copied after teardown, regions zeroed; L8-M11 restated; PID test; mutant PM-M21; start cost measured (V-M18); fallback Q25 | D17, §9.2, §10.3, L8-M11, §15.8, Q25 |
| RV-C4 = RV-F2 | **Medium.** The schema could not express §6.4: `attempt` per object while op ids and "at most two resends" are per ordinal; no op → ordinal map; the CHECK broke on large objects; retries could re-store or skip blobs | yes: `OutboundOutcome` names only an op id and a namespace; F9 solved it with `dm_outbound_op` (`Schema.kt:1017`) | fixed: per-ordinal `upload_state`, `media_outbound_op`, `retry_gen` and `resend_count` in the op id, READY defined over ordinals; SCN-MB per ordinal on a class-10 object; mutant MC-M18 | D13, §6.4, §13.5, §13.6, §15.3 |
| RV-C5 = RV-P4 | **Medium.** View-once (and other) key erasure was only logical: no WAL checkpoint after `key_env = NULL` | yes: F9 §10.7 checkpoints only after SWEEP | fixed: F9's TRUNCATE checkpoint after every transaction that nulls or deletes a `key_env`, before the view-once handle is returned; raw `.db`/`-wal` scans right after; mutant MC-M19 | D20, P-M8, §11.1, §11.2, §15.3, §15.5, L8-M10 |
| RV-C6 | **Low-medium.** `key_env` bound only to `object_id`, so "per destination" rested on Kotlin | yes: F9 wraps bind the contact (`wrap.rs` `olm_session_binding`) | fixed: binding = role ‖ destination ‖ `object_id` ‖ `manifest_hash`; `encrypt` refuses a mismatch; mutant PM-M22 | D7, §4.2, §13.2, §13.6 |
| RV-C7 | **Low-medium.** T35 does not apply "unchanged": `K_p`/`K_m` seal relay bytes and `K_f` rides the intro inner layer, which T35's provenance does not cover | yes: INV T35 row ("nu acoperă stratul interior intro") | fixed: T35 extended, labels specified, the gap declared for media; F-M7 | §3.8, X-M12, §14.2, F-M7, B.2 |
| RV-C8 | **Low.** Format strictness: (a) image ⇒ class 0 not enforced; (b) dimensions and duration trusted from Kotlin, bound 4 096; (c) preview pad and size not checked; (d) caption `body_env` CHECK too wide; (e) no `verified → corrupt` | yes, each in the text or schema | fixed: (a) R-D3, manifest rule, schema CHECK; (b) walker-derived, bounds 2 048 / 1 280 / `VIDEO_MAX_MS`; (c) pad zero, ≤ 320 px; (d) ≤ 28 + 1 024 B; (e) transition, trigger, mutant MC-M22; also MC-M21 | §3.5, §4.1, §7.3, §7.6, §8.2, §13.2, §13.6 |
| RV-C9 | **Low.** AAC is outside the canonical fMP4 profile (data and fill elements carry bytes) | yes: the walker checked only AVC NAL types | declared (parsing AAC elements needs a decoder); forced audio re-encoding makes it irrelevant for the honest path; V-M12 covers encoders' AAC elements; Q35 | §8.3, P-M6, T37, Q35 |
| RV-C10 | **Low.** Claim accuracy: (a) CVE severities; (b) why the tag is uniform; (c) no multi-user gain from the salt; (d) commitment gives no sender attribution; (e) the seeded `getrandom` backend does not exist, and must not rewind if built | (a) yes: the 2026-09 bulletin lists CVE-2026-28609 as High (Framework) and CVE-2026-28618 as Critical (System, media codecs); (b)–(e) yes | corrected in place | §9.1, §3.3 R-O1, X-M3, §3.2, §3.4, §3.7, §15.1 |
| RV-C11 | **Low.** The view-once sender cleanup ignored a final INDETERMINATE descriptor | yes | fixed: cleanup after any final outcome other than FAILED; a FAILED one at the deadline; mutant MC-M20 | §6.4, §11.2, ADR-43 |
| RV-P1 | **High.** Transformer silently transmuxes a source that already matches the output, so a phone video could arrive as the camera's own bitstream | yes: Media3 documentation ("automatically switches to transmuxing"); `TransformerUtil.shouldTranscodeVideo/Audio`; `Codec.EncoderFactory.videoNeedsEncoding()`/`audioNeedsEncoding()` default `false`; `ExportResult.*EncoderName` "null if none were used" | fixed: forced encoding, encoder-name check, HDR tone-mapping, matching-source corpus row, V-M17, mutant PM-M18 | D15, §6.2, §8.3, §15.7, T37 |
| RV-P2 = RV-F8 | **High.** At `POOL_CAP` ingestion stopped, then fetching stopped; since binding frees pool space, fetching depended on descriptor state (a reflex); and the flood bound was understated (distinct blobs per relay; a card holder's own write capabilities) | yes: F7 `FETCHED_CAP`; F9 §4.5 ("write grants read"), L7-D16 | fixed: eviction, never a stop; a free-space floor that discards; NI-M6 and PM-M19; the bound restated with Phase 12's rule as the closure | D10, P-M4, §5.3, §7.1, §7.5, §12.2, L8-M3, L8-M4, Q24 |
| RV-P3 | **High.** A burst truncated by the expiry of a 5-minute message separated 5-minute from 1-hour timers (same bucket), and JM1's "exactly F + 1" could not hold for FAILED or deadline-bound objects | yes: R-T1 merges the two timers so relays cannot tell them apart; the countdown ran from `MEDIA-COMMIT` | fixed: the sender countdown starts at the upload's end (bounded by `deadline + timer`, an R-T6 "only earlier" update); JM1's exemptions stated; the partial burst declared in `LM` and L8-M13; NI-M7 and PM-M20; EP-M made consistent with frozen outbox payloads | D26, P-M1, §2.2, §6.3, §6.4, §11.1, §15.5, §15.6, Q26 |
| RV-P5 | **Medium.** The plaintext-sink inventory omitted OS-written sinks: task snapshots, tombstones (not root-only: bug reports include them), swap | yes: AOSP `TaskSnapshotController` (`SNAPSHOTS_DIRNAME = "snapshots"`), `BaseAppSnapshotPersister` (`.jpg`); INV T10 is Phase 13 | fixed: FLAG_SECURE and `setRecentsScreenshotEnabled(false)` on media windows from Phase 11; system-directory scans; L8-M8 corrected; P-M7 reworded; mutant PM-M23 | D27, X-M11, P-M7, §10.3, §15.8, L8-M8, Q34 |
| RV-F3 | **High.** The test method relied on a seeded backend that was never built and on a relay model that keeps every blob in the heap, at an unstated media rate | yes: F9 §22.16 item 13, §22.22 item 7; `ModelRelay.kt:98`; 2 GB test heap | fixed: checks on structures and normalized views; media rate fixed; recipes instead of bytes (`testSealBeginWithKey`, host only); JM3 exact on hashes and keys, sampled on windows; shards and time budgets; Q33 | §2.3, §15.1, §15.3, §15.6, §16.2 |
| RV-F4 | **High.** Owner-only actions block the critical path and were not called out (S0's phone, relay and pin; the skipped `android` job; the KVM runner) | yes: STATUS; the Phase 9 memory of owner actions | fixed: S0 split into S0a (gates S1) and S0b (gates only the checklist); local runs as slice evidence; Q31, Q32; R-M15 | D23, §15.1, §15.10, §17.1, §17.3 |
| RV-F5 | **High.** The isolated process would run `GhostApp.onCreate`, which touches files, the Keystore and system services | yes: `GhostApp.kt:146-158` | fixed: `Process.isIsolated()` early return; an emulator binding test; mutant MC-M23; V-M19 | §9.2, §13.1, §15.8, V-M19 |
| RV-F6 | **High.** The effort estimate was not calibrated and mis-cited STATUS | yes: STATUS has no slice estimates; Phase 9's slices took nine days against 10–12 weeks, its gate evidence is still open | fixed: re-estimated in agent-days with CI hours and owner dependencies; Q22 with scope options | D24, §17.2, R-M1, Q22 |
| RV-F7 | **Medium.** Media shares the single work-lane thread with text; the background budget is per relay and shared; throughput was understated (uploads are serial across relays) | yes: `Session.kt:129` (one work thread), `WorkLane.kt:77-83`, `Steps.kt:82,91`, `Session.kt:178` | fixed: fetch slices behind non-media items, a media share of the relay budget, smaller store budgets; numbers corrected; video limited to class 8 in 1-hour buckets (Q29); FGS question (Q30); F-M8 | §5.4, §5.5, §13.3, Q29, Q30 |
| RV-F9 | **Medium.** Dependency and licence gates misstated: Guava enters the app through `media3-common`; `ghost-client-media` needs an allowlist line; `nonce-registry` needs a G-R2 clause | yes: the `media3-common` 1.11.1 POM (Guava 33.3.1-android); `gradle-license-allowlist.txt` has no Guava line; `rust-dependency-allowlist.txt` lists `ghost-client-dm` (S4b); `rust-feature-policy.sh` constrains `ghost-client-dm` only | fixed: G-L2 lines, the allowlist line, the G-R2 clause, all in S0a; Q28 | §13.1, §16.1, §16.3, §17.1 |
| RV-F10 | **Medium.** Schema and numbering collide with Phase 9's pending fix migrations (LIMITE L5) and Phase 10 | yes: LIMITE L5 rows (TIMER_SET column in `dm_outbound_item`; attempts in `dm_scheduled`) | fixed: rebuilds copy the tables as they are at merge; the Phase 9 columns folded into M if decided (Q27); R-M8 | D21, §13.6, R-M8, Q27 |

**Also changed while applying the fixes:** `t2-exit-gate`'s time budget with a third owner namespace (R-M13); `media-exit-gate` artifact uploads made `continue-on-error` (the Phase 9 CI lesson); the mutant count split by where each mutant can run (39 + 5 + 2 = 46), since revision 1's "32 in one JVM report" included mutants only Android can catch.

---

## Appendix A: ADR drafts (Romanian)

Numerele continuă după ADR-39 (ADR-21 rămâne rezervat). Faza 10 nu are încă design; dacă își depune ADR-urile înaintea acestora, numerele de aici se decalează la integrare. Toate patru sunt **propuse** 2026-09-25 și devin „propus, aplicat” la aprobarea designului (Q1).

> # ADR-40 — Formatul obiectului media: STREAM pe chunk-uri de 256 KiB aliniate la fragmente de 64 KiB, manifest cu angajament de cheie, clase de dimensiune, cheia de fișier ținută nativ
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-25 (designul Fazei 11, `docs/design/faza11-media.md` §3, §4) |
> | Sursă | Spec §7.4 (pașii 1–7), FR-2.3, FR-2.4; plan §6.2 rândul 11; ADR-09, ADR-19; designul Fazei 9 (§2.5, §6.6, §7.1) |
> | Modifică | Plan rândul 11 („AEAD per chunk 256 KiB” = 256 KiB de ciphertext) și structura modulelor (plan:360: AEAD-ul trece în Rust); spec §7.4 pasul 3 (nonce-ul); designul Fazei 9 (corpul tipului 0x05 MEDIA, funcțiile JNI 2, 3, 4, 8, 13, 14, 18); T35 (extins la cheile media) |
>
> ## Context
> Spec §7.4 cere cheie de fișier aleatoare, AEAD per chunk de 256 KiB, fragmentare în blob-uri ≤ 64 KiB, hash pe blob exact și cheia învelită în contextul DM/MLS, dar nu definește încadrarea. Un chunk de 256 KiB plus tag nu umple un număr întreg de blob-uri de 64 KiB, iar T9 interzice lungimi în clar și cozi de altă dimensiune. Nonce-ul „file nonce plus index” nu încape în 12 octeți. ChaCha20-Poly1305 nu angajează cheia („invisible salamanders”).
>
> ## Decizie
> 1. Cheie de fișier `K_f` de 256 de biți și `object_id` de 128 de biți, aleatoare, per obiect **și per destinație**; niciodată derivate din conținut.
> 2. `K_p`, `K_m` și un angajament de 32 de octeți se derivă cu HKDF-SHA256 din `K_f`, cu `object_id` ca sare (construcția age/Tink; sarea leagă `object_id` și separă domeniile, fără câștig multi-utilizator, fiindcă `K_f` e deja aleatoare per obiect). Angajamentul leagă cheia de conținut, nu de expeditor: fără „franking”, un raport de abuz nu dovedește cine a trimis.
> 3. Conținutul, urmat de zerouri, se împarte în chunk-uri de 262 128 de octeți; fiecare se criptează cu ChaCha20-Poly1305 sub `K_p`, cu nonce-ul `0^7 ‖ u32_be(i) ‖ ultimul` (STREAM, Hoang–Reyhanitabar–Rogaway–Vizár 2015) și AD care leagă `object_id` și tipul; indicatorul „ultimul” apare doar pe ultimul chunk; rezultă exact 4 fragmente de 65 536 de octeți, fără antet.
> 4. Numărul de fragmente F ia doar valorile {16, 24, 36, 56, 84, 128, 192, 288, 432, 648, 804}, funcție doar de lungimea conținutului; orice imagine are clasa 0 (16 fragmente, 1 MiB), regulă verificată în descriptor, în manifest și în schemă.
> 5. Un manifest de exact 64 KiB: angajamentul în clar (octeți pseudo-aleatori), apoi AEAD sub `K_m` cu tipul, clasa, lungimea, dimensiunile și durata (derivate de verificatorul Rust din fluxul parcurs, nu primite din Kotlin), o previzualizare de cel mult 32 KiB și 320 px (niciuna la „vezi o singură dată”; restul zerouri verificate) și hash-urile fragmentelor, în ordine.
> 6. Mesajul DM de tip 0x05 poartă un descriptor fix de 86 de octeți plus o descriere de cel mult 1 024 de octeți, deci orice mesaj media e în treapta de 4 KiB.
> 7. `K_f` nu ajunge niciodată în Kotlin: se stochează doar învelită sub `session_state_key` (`key_env`), legată de rol, destinatar/expeditor, `object_id` și `manifest_hash`; în L0 stă într-un „slot” de 32 de octeți pe care doar `encrypt` îl completează (după verificarea legăturii) și doar cele două funcții care întorc un L0 decriptat, `decrypt` (13) și `sessionInbound` (14, primul mesaj și reluarea mesajelor reținute), îl golesc.
> 8. Criptografia media stă în crate-ul Rust `ghost-client-media`, exportat prin clasa JNI închisă `MediaNative` din `ghost-client-dm`; nu intră niciun crate extern nou în bibliotecile livrate.
> 9. O cheie nu se salvează înainte ca toate chunk-urile obiectului să fie sigilate; o pregătire întreruptă începe un obiect nou, cu cheie nouă (fără reutilizare de nonce).
> 10. Excepție CP-09 înregistrată: compunerea (manifest, angajament, aliniere, clase) intră în revizia criptografică externă, cu vectori, oracol diferențial (`aead-stream` 0.6.0, doar în teste) și teste de proprietăți.
>
> ## Consecințe
> (+) Fragmente uniforme de 64 KiB; acces aleator pentru derulare; resume la nivel de fragment; trunchierea, reordonarea și substituția sunt respinse; un manifest se deschide sub cel mult o cheie. (−) Umplutură de până la ~59 % în cel mai rău caz; releele văd una din 11 clase; o imagine mică costă 17 blob-uri de 64 KiB.
>
> ## Alternative respinse
> Unitate AEAD de 64 KiB (se abate de la plan fără câștig; rezervă); chunk-uri nealiniate (coadă care nu e bucket); flux secvențial înlănțuit (fără derulare); nonce aleator per chunk (fără legare de ordine); manifest în mesajul DM (dimensiunea obiectului ar apărea în treapta DM); Padmé (~60 de clase); puteri ale lui 2 (umplutură până la 100 %); cheia în Kotlin.
>
> ## Teste
> Vectorii `media_object.txt` (Rust, oracolul `aead-stream`, implementare JDK independentă); matricea de corupere; registrul de nonce-uri în toate lumile și scenariile de crash; testele slotului de cheie prin funcțiile 13 și 14 și prin reluarea mesajelor reținute; T36; mutanții PM-M1 … PM-M4, PM-M13, PM-M17, PM-M22, MC-M1 … MC-M5, MC-M11, MC-M21.

> # ADR-41 — Transferul media: namespace-ul media al destinatarului, depunere cu cheie comună, descărcare automată, TTL-ul conversației, banda media din sync
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-25 (designul Fazei 11, §5, §6, §7) |
> | Sursă | ADR-11, ADR-20, ADR-25, ADR-27, ADR-30′, ADR-32; designurile Fazelor 7, 8, 9 |
> | Modifică | Designul Fazei 7 (promisiunea `Inbox.want` nu se implementează; banda media: prioritate pe consumator și bugete); designul Fazei 8 (modelul de cerere: un namespace în plus per identitate); designul Fazei 9 (§3.2, §4.8: `M_i`, înregistrări și token-uri); plan rândul 11 (dependențe: și codul Fazei 9, iar pentru canale Faza 10) |
>
> ## Context
> Fragmentele trebuie să stea undeva pe relee, cineva trebuie să plătească, iar descărcarea nu are voie să devină reflex (T28). Inbox-ul DM ar amesteca media cu textul (aceeași cotă, `FETCHED_CAP`, consumul ca plicuri nedecriptabile); namespace-urile expeditorului ar face ca token-urile să urmeze activitatea (T27) și ar cere citiri străine (T31).
>
> ## Decizie
> 1. Fiecare card are un namespace media `M_i = HKDF(card_secret_i, "ghost/v1/card/media-ns")`, cu secrete de depunere per slot derivate din card (comune tuturor deținătorilor) și secrete de citire derivate din seed. Mulțimea de relee e `set(M_i, w)` din designul Fazei 9.
> 2. Orice identitate activată înregistrează, plătește (un token ACCESS per releu per săptămână) și ascultă `M_0`, chiar dacă nu folosește media niciodată; expeditorii nu cheltuie token-uri.
> 3. `M_0` se listează la programul propriu al Fazei 7 și tot ce apare se descarcă automat; un descriptor primit, o descărcare, o validare, o afișare, o deschidere sau starea locală (ocuparea bazinului, legarea fragmentelor, spațiul liber) nu produc și nu opresc trafic.
> 4. Toate blob-urile unui obiect folosesc treapta TTL a conversației și termenul `autor + min(treaptă, 7 zile)`; nu există TTL media sau „vezi o singură dată”. Numărătoarea expeditorului pornește la sfârșitul încărcării (sau la termen), ca o rafală să nu fie tăiată niciodată de un timer de 5 minute: releele nu pot deosebi 5 minute de 1 oră.
> 5. Încărcarea trece prin outbox-ul Fazei 7 neschimbat, într-o fereastră de cel mult 32 de operații per obiect și 64 per dispozitiv, din fișierele de ciphertext, cu stare per fragment și un tabel al operațiilor (retrimiteri numărate per fragment, reluări per obiect); descriptorul pleacă doar după ce fiecare blob a primit un rezultat final SENT, DEGRADED sau INDETERMINATE; un FAILED îl blochează.
> 6. Banda media din `:sync`: textele, bundle-urile și canalele înaintea media în fiecare rundă de stocare; aducerile media în felii de câte 8, în spatele lucrului non-media; cel mult jumătate din bugetul de fundal al fiecărui releu pentru media; programul de citire neschimbat (T19).
> 7. Motorul primește o destinație abstractă (`MediaDestination`); legarea de canale (namespace, cititori, costul de fan-out, slotul de cheie în mesajele MLS, ce păstrează un membru scos) e o cerință pentru designul Fazei 10.
> 8. Cota: ~256 MiB de media onestă primită pe săptămână per releu (o capabilitate de înregistrare); un deținător de card ostil poate forța mai mult (blob-uri diferite pe fiecare releu și capabilități de scriere cumpărate cu propriile token-uri), până la regula de scriere/citire legată de proprietar din Faza 12. Blob-urile nepotrivite cu niciun descriptor se păstrează cel mult 8 zile și cel mult 512 MiB, plafon aplicat prin ștergere locală, niciodată prin oprirea descărcării.
> 9. Magazinul de ciphertext e adresat prin conținut, cu referințe: un hash poate fi numit de oricâte obiecte, iar apartenența o decide autentificarea fiecărui obiect; un fișier se șterge doar când nu-l mai numește nimeni.
>
> ## Consecințe
> (+) Fără câmp de expeditor și fără reflex; textul nu poate fi blocat de media; un deținător de card nu poate captura fragmentele altui expeditor; niciun câmp observabil nou. (−) Descărcare forțată (inclusiv de la contacte blocate și spammeri); un token în plus per releu pe săptămână pentru fiecare identitate; releele văd clasa și rafala de încărcare (și o rafală scurtă după FAILED, termen sau ștergere); legenda și ciphertext-ul expeditorului trăiesc până la sfârșitul încărcării plus timer-ul; transferurile sunt lente până la conexiunile reutilizate din Faza 12; video-ul e limitat la clasa 8 în conversațiile de 5 minute și 1 oră.
>
> ## Alternative respinse
> Inbox-ul DM; namespace-uri ale expeditorului sau per obiect; aducere la descriptor (`Inbox.want`) sau la atingere (confirmare de citire către releu); înregistrare la prima folosire (clasă nouă de identități); TTL scurt pentru „vezi o singură dată”; un motor de transfer separat.
>
> ## Teste
> JM1 … JM7, NI-M1 … NI-M7 în lumea de confidențialitate media; SCN-MB, SCN-MC; lumea cu hash-uri „ocupate”; `sync-exit-gate` cu consumatorul media; `T19BasicTest` și `MediaFairnessTest` cu activitate media; baseline-urile T2 cu `dm_owner_namespaces = 3`; mutanții PM-M5 … PM-M8, PM-M15, PM-M16, PM-M19, PM-M20, MC-M8 … MC-M10, MC-M14, MC-M16 … MC-M18.

> # ADR-42 — Igiena media: re-encodare obligatorie, profiluri canonice, decodare izolată, fără plaintext pe disc, Media3 fără cache
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-25 (designul Fazei 11, §8, §9, §10) |
> | Sursă | ADR-08, ADR-06, ADR-27; FR-7.4, FR-7.10; spec Anexa A (rândul Media); T4, T5, T15m, T20 |
> | Modifică | ADR-08 și plan:208 („video remuxat … (Media3 Transformer)” devine transcodare cu muxer-ul GHOST; „ICC-GPS” se citește „ICC și GPS”, ambele eliminate); T5 (reformulat ca T37); T15m (un serviciu izolat, neexportat); formularea T20 (magazinul media nu e stratul de sync); T10 (FLAG_SECURE pe ferestrele cu media încă din Faza 11) |
>
> ## Context
> Metadatele se ascund în locuri deschise: segmente APP, miniaturi IFD1 cu imaginea necropată, imagini secundare MPF, octeți după EOI (Motion Photo, SEFT), chunk-uri PNG, cutii MP4 `udta`/`meta`/`uuid`, piste de telemetrie, SEI H.264. Muxer-ul implicit al Transformer scrie un fișier în clar și copiază locația, timpii și XMP-ul sursei. Decodoarele de imagini ale platformei sunt o suprafață clasică de execuție de cod la distanță (CVE-2023-4863, CVE-2025-21042). `AesCipherDataSource` din Media3 e AES/CTR, neautentificat.
>
> ## Decizie
> 1. Metadatele se elimină prin **re-encodare**, niciodată prin editarea sursei: imaginile devin JPEG baseline sRGB, cu orientarea aplicată în pixeli, ≤ 2 048 px și ≤ 1 MiB; video-ul devine H.264 + AAC în MP4 fragmentat, ≤ 720p, ≤ 50 MiB. Codarea e **forțată** pe ambele piste (fabrica de encodere cere codare; un export fără numele encoderelor e refuzat), pentru că Transformer altfel doar remuxează o sursă care se potrivește deja cu ieșirea.
> 2. Profiluri canonice verificate în Rust de două ori: sigilatorul refuză orice ieșire necanonică, iar cititorul refuză să afișeze una. JPEG: fără APP0–APP15, COM, alte SOF decât SOF0, nimic după EOI. fMP4: doar cutiile și valorile fixate de golden-urile S0, timpi constanți, fără `udta`, `meta`, `uuid`, doar SEI de tip 0, 1, 6. Blocurile AAC rămân opace (declarat).
> 3. Video-ul trece prin `GhostMuxer` (peste `FragmentedMp4Muxer`, secvențial): nu trece nicio metadată în afară de orientare și de un timp constant; SEI-ul nepermis se scoate; un index `mfra` construit de GHOST permite derularea.
> 4. Imaginile primite și fișierele alese de utilizator se decodează doar într-un proces izolat (`isolatedProcess`, neexportat, fără permisiuni), **un proces nou pentru fiecare cerere**, distrus după răspuns; clasa `Application` nu face nimic în procesul izolat; procesul principal nu apelează niciun decodor de imagini pe octeți media; video-ul se parsează doar cu extractorul Java fMP4 al Media3, după validare, și se decodează cu `MediaCodec`. Nimic nu se decodează în fundal, nici pentru cereri sau contacte blocate.
> 5. Singurii octeți media persistenți scriși de GHOST sunt ciphertext-ul E2E identic cu blob-urile de pe relee, în `noBackupFilesDir/m/`, câte un fișier de 64 KiB cu nume aleator și `mtime` = 0. Previzualizările, pixelii decodați și chunk-urile decriptate trăiesc doar în RAM. Ferestrele cu media au FLAG_SECURE și, de la API 33, `setRecentsScreenshotEnabled(false)`, ca sistemul să nu salveze un instantaneu; tombstone-urile unui decodor căzut și swap-ul pe stocare rămân reziduuri declarate ale sistemului.
> 6. Interzise prin porți statice: `SimpleCache`, `CacheDataSource`, sursele de descărcare și HTTP ale Media3, `AesCipherDataSource`, `InAppMp4Muxer`, `MediaStore`, fișiere temporare, cache-ul aplicației, directoare externe, `FileProvider`, partajarea, `MediaSession`, notificări cu imagini. Diagnosticele de platformă ale ExoPlayer și Transformer și jurnalizarea Media3 sunt oprite.
>
> ## Consecințe
> (+) EXIF-zero verificabil; un exploit de decodor de imagine nu ajunge la chei, fișiere sau rețea; nimic în clar pe disc. (−) Calitate redusă a imaginilor și video-urilor; HEIC/AVIF refuzate dacă nu se decodează în procesul izolat; video-ul decriptat trece prin heap-ul JVM în timpul redării; `MediaCodec` raportează metrici platformei; PRNU și parametrii encoderului rămân.
>
> ## Alternative respinse
> Eliminarea chirurgicală (ExifInterface scrie doar EXIF/XMP în trei formate); remux fără re-encodare, inclusiv remux-ul automat al Transformer; muxer-ul implicit al Transformer; decodare în procesul principal cu verificări de antet; un singur proces izolat de lungă durată pentru toate cererile; decodoare Rust în biblioteca livrată; fragmente ca BLOB-uri SQLCipher; `AesCipherDataSource`.
>
> ## Teste
> T37 (corpusul T5 cu ExifTool și canari, inclusiv surse care se potrivesc deja cu ieșirea, pe emulator și pe dispozitive), T38 (scanarea sandbox-ului și a directoarelor de sistem, interogarea `MediaStore`, porțile G-M1 … G-M4), T40 (spionul de decodor, suita de crash a procesului izolat, PID-uri distincte per cerere, testul de legare); mutanții PM-M9 … PM-M12, PM-M14, PM-M18, PM-M21, PM-M23, MC-M13, MC-M23.

> # ADR-43 — Media efemeră și „vezi o singură dată” (precizează ADR-27 punctele 10 și 12)
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-25 (designul Fazei 11, §11); ADR-27 rămâne neschimbat |
> | Sursă | ADR-27, ADR-32; FR-7.15; LIMITE:136 |
> | Modifică | nimic aprobat; precizează ordinea ștergerii cheii, checkpoint-ul și semantica la crash; designul Fazei 9 §10.3 (pentru mesajele media, numărătoarea expeditorului pornește la sfârșitul încărcării, nu la commit) |
>
> ## Decizie
> 1. Media urmează mesajul: în tranzacția SWEEP care șterge mesajul se șterg și rândurile obiectului, inclusiv cheia învelită; după **orice** tranzacție care șterge sau anulează o cheie învelită urmează un checkpoint WAL `TRUNCATE` (busy = 0, trei reîncercări), ca vechea pagină să nu rămână în WAL sau în fișierul bazei; fișierele de ciphertext se șterg după commit (reconciliere), doar dacă niciun alt obiect nu le mai numește. Expeditorul păstrează copia proprie cât trăiește mesajul lui, a cărui numărătoare pornește la sfârșitul încărcării (cel târziu la termen).
> 2. Releele oneste șterg fragmentele până la `ora-termen + treaptă + 1 h`; fragmentele expiră cel târziu odată cu descriptorul.
> 3. „Vezi o singură dată” (P1): fără previzualizare; la deschidere, într-o singură tranzacție, cheia trece într-un cititor nativ și se șterge din baza de date, iar checkpoint-ul WAL rulează **înainte** de afișarea oricărui octet; un crash după commit pierde elementul, dar nu permite niciodată o a doua afișare; la închidere se șterg fragmentele. Expeditorul nu păstrează o copie care poate fi revăzută după ce descriptorul are un rezultat final (SENT, DEGRADED sau INDETERMINATE după retrimiteri; la FAILED, la termen). Nu se poate redirecționa.
> 4. Limite declarate: FLAG_SECURE oprește capturile de ecran, nu un al doilea dispozitiv sau o cameră, un client modificat ori un telefon cu root; copiile de pe relee rămân până la TTL; înainte de deschidere, un dispozitiv confiscat conține cheia (învelită); dacă checkpoint-ul rămâne ocupat, vechea pagină trăiește până la următorul checkpoint reușit.
>
> ## Teste
> T25 pentru media (logic și fizic, inclusiv scanarea brută a bazei și a WAL-ului imediat după deschidere), SCN-MD (cel mult o afișare la orice punct de crash), SCN-ME, verificarea de confiscare; mutanții MC-M6, MC-M7, MC-M19, MC-M20, PM-M8.

---

## Appendix B: Text changes in other documents (applied in S10)

### B.1 Master plan erata (Romanian)

- **Rândul 11 (plan:315):** după text se adaugă: „*Erată (Faza 11, design `docs/design/faza11-media.md`, ADR-40 … ADR-43):* chunk-ul de 256 KiB înseamnă 256 KiB de ciphertext (262 128 de octeți de conținut), aliniat la 4 fragmente de 64 KiB; criptografia media stă în Rust (`ghost-client-media`, ADR-19), iar `android/media` păstrează partea Kotlin; media în DM folosește și codul Fazei 9, media în canale se livrează cu Faza 10; video-ul se transcodează (nu se remuxează) cu muxer-ul GHOST.”
- **Rândul 12 (plan:316):** dependențele devin „6, 7, 10, 11”, ca revizia independentă a capturii de metadate să acopere și media (Q23).
- **Structura modulelor (plan:360):** `media/  # stocarea ciphertext-ului, pipeline-urile de trimitere și primire, procesul izolat de decodare, sursa de date Media3 (criptografia în client-core/media)`.
- **ADR-08 în plan (plan:208):** „imagini re-encodate JPEG fără EXIF/XMP/ICC/GPS (profil canonic); video transcodat H.264 + AAC în MP4 fragmentat, fără atomi de locație, dispozitiv sau timp (muxer-ul GHOST peste Media3)”.
- **Spec §7.4 pasul 3 (citire):** „nonce-ul fișierului (`object_id`) e sarea HKDF a cheii per obiect; nonce-ul AEAD e contorul STREAM plus indicatorul de ultim chunk” (ADR-40).

### B.2 INVARIANTS.md (Romanian rows)

| ID | Invariant | Verificare | Executabil din | Cod |
|---|---|---|---|---|
| T5 | *Înlocuit de T37 (Faza 11).* Media criptată nu mai conține EXIF/XMP/GPS/atomi de locație | vezi T37 | Faza 11 | `android/media` tests |
| T36 | Obiectele media sunt uniforme: orice blob media are exact 65 536 de octeți, fără antet în clar; un obiect a cărui încărcare se termină are F + 1 blob-uri, cu F din cele 11 clase, funcție doar de lungimea conținutului (o rafală mai scurtă doar după FAILED, la termen sau la o ștergere a utilizatorului, niciodată din cauza timer-ului din aceeași treaptă); orice imagine are clasa 0 (16 fragmente, 1 MiB); alt destinatar sau o redirecționare înseamnă un obiect nou, fără blob-uri sau ferestre de 16 octeți comune | vectori; teste de proprietăți; χ² pe octeți; JM1–JM3, NI-M3, NI-M7; mutanții PM-M1 … PM-M4, PM-M6, PM-M20 | Faza 11 | `client-core/media`, lumea media |
| T37 | EXIF-zero: conținutul decriptat și previzualizarea sunt JPEG baseline canonic sau fMP4 canonic, produse prin re-encodarea fiecărei piste (niciodată remux); fără APPn, COM, cozi, `udta`, `meta`, `uuid`, atomi de locație, dispozitiv, software sau timp, fără fluxul sursei, fără SEI nepermis; sigilatorul refuză, cititorul respinge orice altceva; blocurile AAC sunt declarate opace | corpusul T5 prin pipeline-ul Android real, inclusiv surse care se potrivesc deja cu ieșirea: ExifTool doar cu etichete permise, niciun canar, SPS/VUI ale encoderului dispozitivului, orientări corecte; teste de proprietăți pe verificatoare; mutanții PM-M11, PM-M12, PM-M18 | Faza 11 (emulator sau rulare semnată pe dispozitiv) | `android/media`, `client-core/media` |
| T38 | Fără plaintext media în repaus: GHOST nu scrie niciun octet media în clar, nicio previzualizare și niciun pixel decodat într-un fișier, bază de date, cache, jurnal, clipboard, `MediaStore`, notificare sau altă aplicație, iar ferestrele cu media nu lasă sistemului instantaneul din „recente”; singurii octeți media persistenți scriși de GHOST sunt ciphertext-ul identic cu cel de pe relee, în `noBackupFilesDir/m/`; tombstone-urile, intrările dropbox și swap-ul pe stocare ale sistemului sunt declarate | G-M1, G-M2; verificarea dex-ului de release; scanarea sandbox-ului și a directoarelor de sistem pe emulator; interogarea `MediaStore`; mutanții PM-M9, PM-M10, PM-M23 | Faza 11 (static: PR; dinamic: emulator) | `android/media`, `scripts/gates/` |
| T39 | Custodia și ștergerea cheii media: `K_f` există doar în memoria nativă și învelită (`key_env`, legată de rol, destinatar, obiect și manifest), niciodată în heap-ul JVM, în `l0_env` sau `body_env`, oricare dintre funcțiile DM 13 și 14 a decriptat L0-ul; se șterge odată cu mesajul și înaintea primei afișări a unui obiect „vezi o singură dată”, fiecare ștergere urmată de un checkpoint WAL; după întârzierile declarate nu mai rămâne niciun rând, octet `key_env` (bază și WAL) sau fișier al obiectului | testele slotului de cheie prin funcțiile 13 și 14 și prin reluarea mesajelor reținute; testele de legare; T25 media cu scanarea brută a bazei și a WAL-ului; SCN-MD, SCN-ME; verificarea de confiscare; mutanții MC-M6, MC-M7, MC-M19, PM-M13, PM-M17, PM-M22 | Faza 11 | `client-core/dm`, `android/media`, `android/messaging` |
| T40 | Decodoarele sunt izolate: niciun octet de imagine primit sau ales nu e parsat de un decodor nativ în procesul principal; imaginile primite ajung în procesul izolat doar după validarea canonică; fiecare cerere rulează într-un proces izolat propriu, distrus după răspuns, iar clasa `Application` nu face nimic acolo; video-ul se parsează doar cu `FragmentedMp4Extractor` după validare și se decodează doar cu `MediaCodec`; nimic nu se decodează în fundal sau pentru cereri și contacte blocate | G-M3; spionul de decodor; suita de crash a procesului izolat; PID-uri distincte per cerere; testul de legare pe emulator; mutanții PM-M14, PM-M21, MC-M23 | Faza 11 | `android/media`, `android/app` |
| T41 | Traficul media: `M` e orb pentru relee (T26), depunerile într-un `M` la un releu au un singur scop (T27), blob-urile media folosesc treapta TTL și termenul conversației (T30), clienții citesc doar propriul `M` (T31) și niciun descriptor, descărcare, validare, afișare, deschidere, ocupare a bazinului, stare de legare sau spațiu liber nu produce și nu oprește trafic (T28); orice identitate înregistrează și plătește `M_0` indiferent de activitatea media | JM4–JM7; NI-M1, NI-M2, NI-M4, NI-M5, NI-M6; G-DM2 extins; mutanții PM-M5, PM-M7, PM-M8, PM-M16, PM-M19 | Faza 11 | `android/messaging`, `android/media`, `android/sync`, lumea media |

Modificări: **T3** — canarii includ cheile de fișier, `K_p`, tipare de plaintext media, previzualizări, descrieri și `object_id`, căutați în toate ieșirile, inclusiv ale proceselor izolate. **T4** — inspecția backup-ului acoperă și `noBackupFilesDir/m/`. **T9** — executabil pentru media (T36). **T10** — pentru ferestrele care arată media (inclusiv harness-ul porții), FLAG_SECURE și, de la API 33, `setRecentsScreenshotEnabled(false)` încă din Faza 11; restul rămâne în Faza 13. **T20** — formularea „stratul de sync” rămâne; fișierele magazinului media sunt guvernate de T38. **T25** — media și previzualizările, cu limitele din design §11.1 (numărătoarea expeditorului pornește la sfârșitul încărcării); executabil pentru media DM în Faza 11. **T33** — coloanele de timp ale tabelelor media; fișierele: `mtime` = 0, `ctime` declarat (L8-M6). **T35** — „…sau derivată dintr-o cheie transportată doar în astfel de plicuri”; etichetele de proveniență acoperă `K_p` și `K_m` (`transported(K_f)`); golul stratului interior intro se aplică și media trimise ca prim mesaj.

### B.3 THREAT_MODEL (Romanian)

- **§5, rândul „Cheie fișier media”:** „random 256 bit **per fișier și per destinație** | învelită nativ sub cheia de stare (`key_env`, legată de rol, contact, obiect și manifest); transportată doar în L0 DM (slot completat și golit doar în Rust) sau, din Faza 10, în mesajul MLS | per fișier | se șterge odată cu mesajul, urmată de checkpoint WAL; la «vezi o singură dată», înaintea primei afișări (ADR-40, ADR-43)”.
- **§6, tabel nou „Media (Faza 11; ADR-40 … ADR-43)”:**

| Eveniment | Relay | Issuer | Rețea locală | Contact | Test |
|---|---|---|---|---|---|
| Trimit media | în namespace-ul media al destinatarului (derivat din card): F + 1 blob-uri de 64 KiB în câteva minute, clasa F (una din 11; orice imagine în prima), treapta TTL a conversației, scopul de depunere comun tuturor expeditorilor, circuitul meu; apoi o depunere de 4 KiB în inbox; mai puține blob-uri și niciun descriptor după FAILED, la termen sau dacă șterg mesajul, niciodată din cauza timer-ului | — | upload 3 × (F + 1) × 64 KiB | — | T1, T36, T41 |
| Primesc media | listări `M` la programul T19; câte un `get` per blob, la evenimentele de listare, indiferent de starea locală | — | download (F + 1) × 64 KiB | — | T19, T41 |
| Deschid, văd, „vezi o singură dată” | **nimic** | — | — | — | T41 |
| Expirare media | nimic | — | — | — | T25, T39 |
| Un deținător de card inundă `M` | depuneri cu scopul comun până la epuizarea cotei fiecărui releu, plus stocări cu capabilități de scriere cumpărate cu propriile token-uri (L7-D16) | — | download forțat | — | L8-M4 |

### B.4 LIMITE: new section L8 (Romanian)

> ## L8. Media (Faza 11; ADR-40 … ADR-43; design `docs/design/faza11-media.md` §12.5)
>
> Reziduurile designului; Faza 11 nu e implementată. Nimic de aici nu se afirmă în UI (CP-10).
>
> | ID | Reziduu | De ce rămâne | Atenuare |
> |---|---|---|---|
> | L8-M1 | Volumul media e un semnal puternic de corelare: un upload de 3 × (F + 1) × 64 KiB și un download de (F + 1) × 64 KiB pot fi legate de un adversar la nivel de rețea | fără trafic de acoperire (P2) | întârzierea high-privacy; clase; cover P2 |
> | L8-M2 | Releele văd clasa fiecărui obiect (11 clase; toate pozele în prima), rafala în `M`-ul destinatarului și, din sesiunea expeditorului, depunerea descriptorului în inbox-ul aceluiași proprietar | fragmentele trebuie stocate; descriptorul așteaptă încărcarea | clase; o treaptă TTL per conversație |
> | L8-M3 | Descărcare automată: tot ce se depune în `M`-ul meu se descarcă, inclusiv de la contacte blocate și spammeri; oprirea descărcării se vede la relee | singura variantă fără reflex; descărcarea nu are voie să depindă de starea locală | cota; rotirea cardului (Faza 13) |
> | L8-M4 | Un deținător de card îmi poate epuiza cota media pe fiecare releu din mulțimea mea (blob-uri diferite pe fiecare releu: ~256 MiB per releu pe săptămână) și poate stoca în plus cu capabilități de scriere cumpărate cu propriile token-uri (L7-D16); descarc tot; îmi poate umple bazinul cu 512 MiB pentru 8 zile, iar sub inundație descriptorul întârziat al unui contact onest poate găsi fragmentele evacuate (obiect incomplet) | expeditorii onești nu cumpără capabilități (T27); la relee scrierea include citirea; descărcarea nu poate depinde de bazin (T41) | cota per înregistrare; plafonul prin evacuare locală; regula de scriere/citire legată de proprietar (Faza 12, F9 Q36); rotirea cardului |
> | L8-M5 | Media mare în conversațiile de 5 minute și 1 oră poate rata termenul în joburile de fundal (video limitat la clasa 8 acolo); un obiect ale cărui fragmente au expirat înainte de aducere e incomplet; transferurile sunt lente | TTL = treapta conversației; un client per apel în Faza 7 | transfer în prim-plan; conexiuni reutilizate în Faza 12 |
> | L8-M6 | Pe un dispozitiv confiscat, fișierele de ciphertext au `ctime` la nanosecundă cât trăiește obiectul; rândurile arată tipuri, clase, stări; tombstone-urile `M_0` supraviețuiesc până la ~4 săptămâni | fișiere Android; retenția Fazei 7 | `mtime` = 0; ștergere odată cu obiectul |
> | L8-M7 | Video-ul decriptat trece prin heap-ul JVM (bufferele Media3) cât rulează; pixelii decodați stau în memoria nativă cât sunt afișați | Media3 e Java | redare doar în prim-plan; eliberare la blocare |
> | L8-M8 | `MediaCodec` raportează metrici platformei (codec, rezoluție, durată), pe care platforma le poate trimite la Google dacă utilizatorul a acceptat; tombstone-ul și intrarea dropbox ale unui decodor căzut pot conține fragmente în clar ale imaginii acelei cereri și intră într-un `adb bugreport` pe care îl poate lua oricine ține dispozitivul deblocat (nu doar cu root); pe dispozitivele cu swap pe stocare, pagini din heap pot ajunge pe flash | servicii ale platformei | diagnosticele ExoPlayer și Transformer oprite; un proces izolat per cerere; FLAG_SECURE contra instantaneelor |
> | L8-M9 | Destinatarul primește pixelii, sunetul, dimensiunile și durata; zgomotul senzorului (PRNU) și parametrii encoderului rămân după re-encodare | fizică și codecuri | filigran P2 |
> | L8-M10 | „Vezi o singură dată” nu oprește alt dispozitiv sau o cameră, un client modificat, un telefon cu root; copiile de pe relee rămân până la TTL; un crash după deschidere pierde elementul; dacă checkpoint-ul de după deschidere rămâne ocupat, vechea pagină cu cheia trăiește în WAL până la următorul checkpoint reușit | reziduurile ADR-27; WAL-ul SQLite | FLAG_SECURE; cheia ștearsă și checkpoint înaintea afișării |
> | L8-M11 | Imaginile primite și alese sunt decodate de decodoarele platformei, în câte un proces izolat per cerere: un exploit acolo vede octeții acelei cereri și poate minți despre pixelii ei (pentru un fișier ales, poate modela JPEG-ul pe care GHOST îl trimite), fără acces la chei, fișiere, rețea sau alte cereri; codecurile video rulează în procesele platformei | decodoarele platformei sunt singurele practice | doar JPEG și fMP4 canonice; izolare per cerere; dispozitive actualizate |
> | L8-M12 | Fiecare identitate plătește un token în plus per releu pe săptămână și listează `M_0`, chiar dacă nu folosește media | uniformitate | — |
> | L8-M13 | Rafala unui expeditor poate rămâne sub F + 1 stocări, fără descriptor, după FAILED, la termen sau când utilizatorul șterge mesajul ori contactul; descrierea și ciphertext-ul expeditorului trăiesc până la sfârșitul încărcării plus timer-ul, cel mult `termen + timer` de la commit (~1 h 5 min la un timer de 5 minute) | numărătoarea nu are voie să taie rafale în aceeași treaptă; Faza 7 nu are anulare | termenul depinde doar de treaptă; nicio tăiere din cauza timer-ului |

### B.5 `allowed-observables.json`

No change: no new field or value (§12.3). The fixtures gain a media burst (`capture-ok.ndjson`).

### B.6 Phase 7 and Phase 9 designs (English forward notes)

- **F7 §9, after "Media (Phase 11) will add `Inbox.want`…":** "*Forward note (Phase 11 design, 2026-09-25):* not added; the media namespace is listened and fetched on its schedule (faza11-media.md §7.1, X-M6). The media lane is consumer-priority store ordering and media fetch and store budgets (§5.5)."
- **F9 §7.1 (kind 0x05), §2.6 (functions 2, 3, 4, 8, 13, 14, 18; the facade's `mediaKeyEnv`), §7.4 (RECV R7 and the held replay: a kind-5 L0 from `sessionInbound` carries a `key_env`), §10.3 (a media message's sender countdown starts at its upload's end), §10.6 (the `MediaPort` row), §13.6 (the two rebuilt tables and the Phase 9 columns if Q27 applies):** a forward note pointing to faza11-media.md §4, §6.3, §11.1 and §13.6, as F9's §22 notes do.
- **F7 §6 (the work lane):** a forward note on the media fetch slices and the media share of the per-relay background budget (faza11-media.md §5.5; F-M8).

### B.7 STATUS, ADR index

`docs/STATUS.md` gains a Phase 11 row ("design propus 2026-09-25; neînceput") when the design is filed and is updated at each slice; `docs/adr/README.md` lists ADR-40 … ADR-43 as "propus".

---

## Appendix C: Evidence, verified vs assumed

### C.1 Verified in the repository (at `f244b80`)

| Fact | Where |
|---|---|
| Row 11 text, duration 3–4 weeks, dependency "7 (paralel cu 10)", exit gate | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md:315` |
| Row 12 depends on 6, 7, 10 | plan:316 |
| FR-7.10, FR-7.14, FR-7.15 (view-once P1); ADR-08 media text; `androidx.media3` allowed | plan:272, :276, :277, :208, :464 |
| ADR-27 points 3, 9, 10, 11, 12 and residues | `docs/adr/ADR-27-screen-text-ephemeral.md` |
| T5, T9, T20, T25, T35 texts; the observables rule | `ghost/test-harness/privacy/INVARIANTS.md:13, :17, :28, :33, :43, :66` |
| No new observable needed; TTL buckets; `size_bucket` values | `ghost/test-harness/privacy/allowed-observables.json` |
| Relay: `MAX_BLOB_BYTES` 65 536, buckets {1, 4, 16, 64} KiB, TTL buckets, `MAX_BATCH` 256 | `ghost/relay/crates/api/src/lib.rs:13, :18, :26, :29` |
| `StoreBlob` hash = SHA-256 of data; `GetBlobResponse` fields | `ghost/protocol/relay/v1/relay.proto:26-58` |
| Client refuses non-bucket or wrong-hash `get` answers | `ghost/client-core/net/src/relay_client.rs:345-360` |
| Schema v5 current; v1 `media`/`media_blobs`; `dm_message.kind IN (1, 2)`; `dm_outbound_item.kind BETWEEN 1 AND 4`; `consumer 'media'` | `ghost/android/storage/src/main/kotlin/org/ghost/storage/Schema.kt:120, :211-225, :972-1001, :1004-1016, :295` |
| `MediaPort` shape and its call before the message deletes in SWEEP | `ghost/android/messaging/src/main/kotlin/org/ghost/messaging/api/MessagingPorts.kt`; `…/engine/Sweeper.kt:311-314` |
| Content key (JCA ChaCha20-Poly1305) for `*_env` | `…/messaging/store/ContentCipher.kt` |
| Fetch only in a read pair's bundle; budgets; `FETCHED_CAP` | `ghost/android/sync/src/main/kotlin/org/ghost/sync/engine/WorkLane.kt:77-83`, `TrafficPolicy.kt`, `store/StoreLimits.kt` |
| Kind 0x05 reserved; TLV range; body capacities; `MediaPort` row; deposit ledger; relay sets; the JNI closed list | F9 §7.1 (:894, :916), §6.6 (:857), §10.6 (:1473), §4.5, §5.2, §2.6 |
| `chacha20poly1305` =0.11.0, `hkdf` =0.13.0, `zeroize` =1.9.0 in `ghost-client-dm`; workspace `sha2` 0.11.0, `hmac` 0.13.0; lock `chacha20` 0.10.2, `poly1305` 0.9.1, `aead` 0.6.1; no image-decoder crate in the lock | `ghost/client-core/dm/Cargo.toml`; `ghost/Cargo.toml:43-45`; `ghost/Cargo.lock` |
| `media3 = "1.11.0"`, only `media3-exoplayer` catalogued; `:media` has only junit; minSdk 29, target/compile 37 | `ghost/android/gradle/libs.versions.toml:7-8, :14, :33`; `ghost/android/media/build.gradle.kts` |
| T15 permission list | `ghost/scripts/gates/common.sh:15` |
| Native-library allowlist | `ghost/scripts/gates/apk-native-libs.sh` |
| `capability_quota_bytes` 268 435 456; `access_per_slot` 16 | F8:415-417 |
| Phase 9 gate open; Phases 10–18 not started | `docs/STATUS.md` rows "Faza 9", "Faze 10–18" |
| Licence allowlist (permissive plus MPL-2.0 unmodified) | `ghost/deny.toml:54-66`; ADR-37 |
| **Revision 2.** `sessionInbound` returns the decrypted L0 (`Field::L0`); the held replay and PreKey path call it | `ghost/client-core/dm/src/jni.rs:1268-1269`; `…/crypto-bridge/.../DmSessions.kt:510`; `…/messaging/engine/HeldReplay.kt:27`; F9 §2.6 row 14, §6.8, §7.4 R7 |
| Wrap envelope format, `WrapName` list, bindings naming the contact (`olm_session_binding`) | `ghost/client-core/dm/src/wrap.rs:1-200` |
| `dm_outbound_op` (operation → item, `resend_count` 0–2); `dm_message` CHECKs incl. `body_env` 30 … 61 485; `dm_message_expiry` lets expiry times only move earlier | `Schema.kt:968-1027`, `:1179-1185` |
| Content-key envelope overhead 28 B | `…/messaging/store/ContentCipher.kt` (`OVERHEAD = NONCE_BYTES + TAG_BYTES`) |
| The work lane has one thread; fetches run in `PairWork` on it; a pass at its store cap reposts itself; the background budget is per relay, charged per call | `…/sync/engine/Session.kt:129, :178`; `WorkLane.kt:70-90`; `Steps.kt:75-100`; `TrafficPolicy.kt:23-29, :62` |
| `ModelRelay` keeps every blob's bytes in the heap; JVM test heap 2 GB | `…/sync/src/test/.../harness/ModelRelay.kt:98`; `android/sync/build.gradle.kts:64` |
| `GhostApp.onCreate` runs wiring that touches files and the Keystore | `ghost/android/app/src/main/kotlin/org/ghost/app/GhostApp.kt:146-158` |
| No Guava line in the release licence allowlist (`listenablefuture` only); `ghost-client-dm` has its own allowlist line (S4b); G-R2 constrains `ghost-client-dm`'s features only | `ghost/scripts/gates/gradle-license-allowlist.txt:65`; `ghost/client-core/rust-dependency-allowlist.txt:398-415`; `ghost/scripts/gates/rust-feature-policy.sh:115-128` |
| Phase 9's pending schema fixes (TIMER_SET column in `dm_outbound_item`, attempts in `dm_scheduled`) | `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` L5 rows; F9 §22.21 item 2, §22.13 item 9 |
| The seeded `getrandom` backend was never built | F9 §22.16 item 13, §22.22 item 7 |
| Phase 9 slices S1 … S14 committed 2026-09-16 … 2026-09-24; gate evidence open (mutants 15 + 15 of 97, no gate-scale world in CI, `android` job skipped since 2026-09-20); `t2-exit-gate`'s longest job 222 minutes | `git log`; `docs/STATUS.md` row "Faza 9"; F9 §17.1, §22.24 |
| T35's provenance does not cover the intro inner layer; T10 is Phase 13 | `INVARIANTS.md` rows T35, T10 |
| `FOREGROUND_SERVICE_DATA_SYNC` and `CAMERA` are in the T15 list | `ghost/scripts/gates/common.sh:15` |

### C.2 Verified at external sources (accessed 2026-09-25)

| Fact | Source |
|---|---|
| Media3 1.11.1 is the latest stable (2026-09-10); `media3-inspector-frame` holds `FrameExtractor` | developer.android.com/jetpack/androidx/releases/media3 |
| `AesFlushingCipher` uses `AES/CTR/NoPadding`, no authentication | androidx/media `release`, `libraries/datasource/.../AesFlushingCipher.java` |
| `Mp4Muxer.Builder(SeekableMuxerOutput)`; `Mp4Writer` seeks back to patch the `mdat` size and rewrites `moov` near the end, then truncates | `libraries/muxer/.../Mp4Muxer.java`, `Mp4Writer.java` |
| `FragmentedMp4Muxer.Builder(WritableByteChannel)`, implements `Muxer`, 2 s default fragments; `FragmentedMp4Writer` strictly sequential, no `sidx`/`mfra`/`tfra` | `FragmentedMp4Muxer.java`, `FragmentedMp4Writer.java` |
| `MetadataCollector` stamps creation and modification time with `System.currentTimeMillis()` | `MetadataCollector.java` |
| `InAppMp4Muxer` opens `new FileOutputStream(path)`; forwards entries accepted by `MuxerUtil.isMetadataSupported` | `libraries/transformer/.../InAppMp4Muxer.java` |
| `Transformer.Builder.setMuxerFactory`, `setUsePlatformDiagnostics`; `start` overloads take a path; the class touches no file | `Transformer.java` |
| `FragmentedMp4Extractor` outputs `SeekMap.Unseekable` without `sidx` unless `FLAG_READ_MFRA_FOR_SEEK_MAP` and an `mfra` | `libraries/extractor/.../FragmentedMp4Extractor.java` |
| ExoPlayer platform diagnostics through `MediaMetricsManager`, opt-out `setUsePlatformDiagnostics(false)`; `MediaCodec` diagnostics are separate | Media3 1.0.0-beta01 release notes; ExoPlayer.Builder documentation |
| `androidx.media3.common.util.Log.setLogLevel`, `LOG_LEVEL_OFF` (public, `@UnstableApi`) | `libraries/common/.../Log.java` |
| `ImageDecoder.createSource(ByteBuffer)` and other overloads; `setTargetColorSpace`; `ALLOCATOR_SOFTWARE`; no documented EXIF-orientation statement | AOSP `frameworks/base/graphics/java/android/graphics/ImageDecoder.java` |
| `Bitmap.setGainmap` / `hasGainmap`; `CompressFormat` = JPEG, PNG, WEBP (deprecated), WEBP_LOSSY, WEBP_LOSSLESS | AOSP `Bitmap.java` |
| `isolatedProcess`: "a special process that is isolated from the rest of the system and has no permissions of its own"; services without filters default to not exported | developer.android.com `<service>` reference |
| Photo picker on API 30+; `ACTION_OPEN_DOCUMENT` fallback on API 29; the GMS backport manifest entry | developer.android.com photo-picker guide |
| age payload: HKDF(file key, nonce, "payload"), 11-byte counter ‖ last flag, STREAM | C2SP `age.md` |
| draft-irtf-cfrg-aead-limits-13 (2026-09-03), `IA ≤ v(L′+1)/2^103` for ChaCha20-Poly1305; not an RFC | datatracker.ietf.org |
| ExifTool 13.59, 2026-05-27 | exiftool.org |
| **Revision 2.** "If the input media format already matches the configurations for audio or video, Transformer automatically switches to transmuxing" | developer.android.com/media/media3/transformer/transformations |
| `shouldTranscodeVideo` / `shouldTranscodeAudio`: the encoder factory's `…NeedsEncoding()` first, then HDR mode, MIME type, pixel ratio, speed, effects (no-op or rotation only → transmux), audio processors | androidx/media `release`, `libraries/transformer/.../TransformerUtil.java` |
| `Codec.EncoderFactory.videoNeedsEncoding()` and `audioNeedsEncoding()` are `default … return false` | `libraries/transformer/.../Codec.java` |
| `ExportResult.videoEncoderName` / `audioEncoderName`: "the name of the … encoder used, or null if none were used" | `libraries/transformer/.../ExportResult.java` |
| `media3-common` 1.11.1 depends on `com.google.guava:guava:33.3.1-android` (compile), with exclusions of `jsr305`, `checker-qual`, `error_prone_annotations`, `j2objc-annotations`, `animal-sniffer-annotations` | dl.google.com/android/maven2/androidx/media3/media3-common/1.11.1/media3-common-1.11.1.pom |
| `Context.bindIsolatedService(…, instanceName, …)` added in API 29; without `BIND_SHARED_ISOLATED_PROCESS` each instance name gets its own isolated process | developer.android.com `Context` reference (via the API 29 SDK sources and the platform documentation) |
| Android bulletin 2026-09: CVE-2026-28618 Critical RCE (System, media codecs, no user interaction); CVE-2026-28609 High RCE (Framework) | source.android.com/docs/security/bulletin/2026/2026-09-01 |
| Task snapshots persisted under the user's system directory `snapshots` (`TaskSnapshotController.SNAPSHOTS_DIRNAME`) as `.jpg` (`BaseAppSnapshotPersister.BITMAP_EXTENSION`) | AOSP `frameworks/base/services/core/java/com/android/server/wm/` |

**Taken from the research digests of 2026-09-25 (verified there, not re-fetched for this draft):** `aead-stream` 0.6.0 (2026-06-28, Apache-2.0 OR MIT, `StreamBE32`); Hoang and Shen (ePrint 2020/1019); Albertini et al. (ePrint 2020/1456); Dodis et al. (ePrint 2019/016); Padmé (PETS 2019); Tor Metrics onionperf throughput and latency; DeepCorr (arXiv 1808.07285); LANDFALL / CVE-2025-21042; CVE-2023-4863; software codecs in a constrained process since Android 10 (Android Developers blog, 2019-05); the Android 17 background-audio behaviour change; the Motion Photo format and Samsung SEFT tags; ExifTool's licence; AOSP `MPEG4Writer` metadata; `BoxParser` and `MuxerWrapper` metadata forwarding; CameraX's native library. The claim that tombstones and dropbox entries are included in `adb bugreport` is the AOSP debugging documentation's, not re-fetched; V-M20 observes it.

### C.3 Assumed, checked in S0a or S0b (each with its fallback)

| ID | Assumption | Check | Fallback if false | Slice |
|---|---|---|---|---|
| V-M1 | Transformer with `GhostMuxer` writes no file anywhere | file inventory and `FileObserver` on every app directory during 20 transcodes | a Transformer-internal file is a blocker: report upstream; video waits (images unaffected) | S0a |
| V-M2 | `FragmentedMp4Muxer` starts every fragment with a sync sample, and `FragmentedMp4Extractor` with `FLAG_READ_MFRA_FOR_SEEK_MAP` seeks through a GHOST `mfra` | golden transcodes; seek tests | build `tfra` entries on sync samples only; or seek by fragment with decode-to-target | S0a |
| V-M3 | `Mp4TimestampData` with a constant is accepted; the box inventory of 1.11.1 is stable | golden recording | fixed-value patch in the walker's allowlist | S0a |
| V-M4 | `ImageDecoder` applies EXIF orientation on API 29–37 | 8-orientation corpus | read Orientation with ExifInterface in the sandbox and rotate | S0a |
| V-M5 | HEIC/AVIF (and JPEG/PNG/WebP) decode inside an isolated process; `SharedMemory` crosses the boundary on API 29 | sandbox probe per API level | HEIC/AVIF refused (Q9) | S0a |
| V-M6 | `Bitmap.compress(JPEG)` emits baseline `SOF0`; with the gain map removed, no trailing image | marker dump | canonicaliser drops APPn; a trailer fails the send | S0a |
| V-M7 | the Media3 1.11.1 modules bring no `.so`; the transitive set (Guava, `failureaccess`, nothing else outside `androidx`); R8 size delta | APK listing, `apk-native-libs.sh`, `apk-size:`, `license-notices.sh android` | a native library or another third-party artifact needs an ADR-06 review | S0a |
| V-M8 | `aead-stream` 0.6.0 works as a dev oracle beside `chacha20poly1305` 0.11.0 (`aead` 0.6.1) | `cargo tree -e dev` | a hand-written oracle over the RFC 8439 test vectors | S0a |
| V-M9 | seal and open ≥ 100 MB/s on the reference mid-range phone (the soft `poly1305` backend has no NEON) | benchmark | acceptable anyway at Tor speeds; recorded | S0b |
| V-M10 | transfer times per class over live Tor | the `live-tor` harness against one onion relay | recorded; no claim | S0b |
| V-M11 | the picker's and SAF's streams are read without an app-side copy | `FileObserver` | — (GHOST never copies; recorded) | S0a |
| V-M12 | reference encoders' SEI payload types, and whether their AAC output contains DSE or non-zero FIL elements | NAL dump and a test-only AAC element dump on the gate devices (and the emulator's software encoders in S0a) | the SEI filter keeps video canonical; AAC elements stay declared (Q35) | S0b |
| V-M13 | no MediaMetrics playback session with diagnostics off | `dumpsys media.metrics` | declared | S0a |
| V-M14 | R8 removes `SimpleCache`, `Download*` and HTTP data sources from the release dex | dex listing | G-M1 alone, plus the sandbox scan | S0a |
| V-M15 | `memtagMode` can be set for `:mdec` alone | manifest probe on an MTE device | not enabled in Phase 11 (Q21) | S0b |
| V-M16 | `setLastModified(0)` holds on app directories (f2fs, ext4) | stat after write | declared (L8-M6) | S0a |
| V-M17 | with the forcing encoder factory and tone-mapping, a source already matching the output (H.264 + AAC, ≤ 720p30, SDR, square pixels) is re-encoded on API 29, 35 and 37: both encoder names are set, the output SPS/VUI are the device encoder's, no source NAL or AAC frame survives | the matching-source corpus row | if a platform encoder refuses forced encoding, that API level's video sends fail closed (typed) and the finding goes to the owner | S0a |
| V-M18 | a fresh isolated process per request (`bindIsolatedService`, new instance name) binds, decodes and dies on API 29, 35 and 37; its cold-start cost is acceptable for a screen of previews | timing over 100 requests per API level | Q25's fallback for previews only | S0a |
| V-M19 | with the `Process.isIsolated()` early return, `GhostApp` does nothing in `:mdec`, and no content provider or initializer runs there | the binding test; a log-free probe of what ran | move the remaining work behind the same check; a provider that insists on running is a blocker for the sandbox | S0a |
| V-M20 | on API 29–32 a FLAG_SECURE window's task snapshot holds no media pixels; on 33+ `setRecentsScreenshotEnabled(false)` prevents it; what a forced `:mdec` crash leaves in `/data/tombstones` and dropbox | emulator with `adb root`, the §15.8 system-directory scan | a pixel-bearing snapshot on some API level: owner decision (e.g. no media display on that level) | S0a |

---

## Appendix D: Sources (accessed 2026-09-25)

**Repository:** `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`; `output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf` (§7.4 p.16, §4.2 FR-2.x p.8, §4.3–§4.4 p.9, §4.7 p.10, §8 p.17, Appendix A); `docs/adr/ADR-06`, `-08`, `-09`, `-11`, `-19`, `-20`, `-25`, `-27`, `-32`, `-37`; `docs/THREAT_MODEL_v2.1.md`; `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`; `docs/STATUS.md`; `docs/design/faza7-sync-engine.md`, `faza8-issuer.md`, `faza9-dm.md`; `ghost/test-harness/privacy/INVARIANTS.md`, `allowed-observables.json`; the code files cited in Appendix C.1.

**External:**
- Media3 releases: https://developer.android.com/jetpack/androidx/releases/media3
- Media3 sources (branch `release`): https://github.com/androidx/media — `libraries/datasource/src/main/java/androidx/media3/datasource/AesFlushingCipher.java`, `libraries/muxer/src/main/java/androidx/media3/muxer/{Mp4Muxer,Mp4Writer,FragmentedMp4Muxer,FragmentedMp4Writer,MetadataCollector}.java`, `libraries/transformer/src/main/java/androidx/media3/transformer/{Transformer,InAppMp4Muxer}.java`, `libraries/extractor/src/main/java/androidx/media3/extractor/mp4/FragmentedMp4Extractor.java`, `libraries/common/src/main/java/androidx/media3/common/util/Log.java`
- Media3 1.0.0-beta01 release notes (platform diagnostics): https://github.com/androidx/media/releases/tag/1.0.0-beta01
- AOSP `ImageDecoder.java`, `Bitmap.java`: https://github.com/aosp-mirror/platform_frameworks_base/tree/main/graphics/java/android/graphics
- `<service>` element: https://developer.android.com/guide/topics/manifest/service-element
- Photo picker: https://developer.android.com/training/data-storage/shared/photo-picker
- age format: https://github.com/C2SP/C2SP/blob/main/age.md
- AEAD limits: https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-limits/
- STREAM: Hoang, Reyhanitabar, Rogaway, Vizár, "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance", CRYPTO 2015, https://eprint.iacr.org/2015/189
- Hoang, Shen, "Security of Streaming Encryption in Google's Tink Library", CCS 2020, https://eprint.iacr.org/2020/1019
- Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg, "How to Abuse and Fix Authenticated Encryption Without Key Commitment", USENIX Security 2022, https://eprint.iacr.org/2020/1456
- Dodis, Grubbs, Ristenpart, Woodage, "Fast Message Franking: From Invisible Salamanders to Encryptment", CRYPTO 2018, https://eprint.iacr.org/2019/016
- Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs" (Padmé), PETS 2019, https://petsymposium.org/popets/2019/popets-2019-0056.php
- RustCrypto `aead-stream`: https://crates.io/crates/aead-stream
- Tor Metrics onionperf: https://metrics.torproject.org/onionperf-throughput.csv
- DeepCorr: https://arxiv.org/abs/1808.07285
- Android security bulletin 2026-09: https://source.android.com/docs/security/bulletin/2026/2026-09-01
- LANDFALL (CVE-2025-21042): https://unit42.paloaltonetworks.com/landfall-is-new-commercial-grade-android-spyware/
- CVE-2023-4863: https://nvd.nist.gov/vuln/detail/CVE-2023-4863
- Media framework hardening (Android 10): https://android-developers.googleblog.com/2019/05/queue-hardening-enhancements.html
- Android 17 behaviour changes: https://developer.android.com/about/versions/17/behavior-changes-all
- Motion Photo format: https://developer.android.com/media/platform/motion-photo-format
- Media3 Transformer, transformations and transmuxing: https://developer.android.com/media/media3/transformer/transformations
- Media3 sources (branch `release`), revision 2: `libraries/transformer/src/main/java/androidx/media3/transformer/{TransformerUtil,Codec,ExportResult}.java` at https://github.com/androidx/media
- `media3-common` 1.11.1 POM: https://dl.google.com/android/maven2/androidx/media3/media3-common/1.11.1/media3-common-1.11.1.pom
- `Context.bindIsolatedService`: https://developer.android.com/reference/android/content/Context#bindIsolatedService(android.content.Intent,%20int,%20java.lang.String,%20java.util.concurrent.Executor,%20android.content.ServiceConnection)
- AOSP task snapshots: https://github.com/aosp-mirror/platform_frameworks_base/blob/main/services/core/java/com/android/server/wm/TaskSnapshotController.java and `BaseAppSnapshotPersister.java` in the same directory
- RFC 8439 (ChaCha20-Poly1305, §2.8 the tag mask): https://www.rfc-editor.org/rfc/rfc8439
- ExifTool: https://exiftool.org/ ; Samsung tags: https://exiftool.org/TagNames/Samsung.html
