# GHOST Phase 10: The Forum on OpenMLS (channels, epochs, history policy, pseudonyms, reveal, ephemeral posts) — Design

| Field | Value |
|---|---|
| Status | **Proposed, not approved.** A draft for the owner's decision; no Phase 10 code is written before approval (the owner's rule, `user-mihai-profile`). ADR-40 … ADR-43 are drafts (Appendix A, Romanian). The owner questions of §17 carry proposed defaults. |
| Revision | 2026-09-25, round 10a (drafting author). No review round yet; the review's corrections would become §19 and win over earlier sections (the Phase 8 §19 and Phase 9 §21 practice). |
| Date | 2026-09-25 |
| Phase | 10, plan §6.2 row 10 (plan:314): "Forum cu OpenMLS: bridge Rust→Android, canale, epoch, history policy, pseudonime, reveal opt-in, mesaje efemere per canal (politica canalului; ADR-27)"; 6–9 weeks; depends on phases 3 and 7; "suprapunere cu 9 după definirea envelope-ului" |
| Exit gate | Plan row 10, verbatim: **"20 clienți add/remove/resync; membru scos nu decriptează epoch-uri noi; T25 și în canale"**, with the spec's acceptance criteria FR-2.2 ("Welcome, add, remove, update, epoch and resync tests pass"), FR-3.1, FR-3.2, FR-3.3, FR-3.5, FR-3.8 (spec pp. 8–9), spec Appendix A "RFC 9420 interoperability fixtures required" (spec p. 26), and the threat-model tests assigned to Phase 10: S3 ("MLS transcript detects gaps", TM:144), S4 ("Remove → nu decriptează epoch nou", TM:147), S5 ("simulare guvernanță", TM:150), LIMITE:39 ("dispozitiv revocat nu decriptează epoch-uri noi") |
| Depends on | Phase 3 (`:identity`, the ADR-04 pseudonym derivation), 4 (`:storage`), 5 (relay), 6 (`client-core/net`), 7 (`:sync`), 8 (`:entitlement`, ES slots, capability v2), and **Phase 9's infrastructure**: `RegisterKey`, bearer credential v3 (READ, DEPOSIT), `keys.redb`, exact TTL buckets, `CapabilitySource`, `Registrations`, `ConsumerTail`, `Inbox.peek`/`claimOne`, the closed-JNI pattern and the host library `ghost-dm-host`. **Phase 9 is implemented but its exit gate is not met** (`docs/STATUS.md:18`); every Phase 10 claim that rests on Phase 9 code inherits that state (R-8). |
| Modifies | plan Annex B (channel namespace and read capability; X-1, X-2); Phase 8 D11 (read keys per generation, not per MLS epoch; X-2); ADR-13 and LIMITE §3.1 ("primul client care observă pragul emite Remove"; X-3); THREAT_MODEL:81 (pseudonym rotation; X-4); spec Appendix A MLS row (0.8.x → 0.9.0; X-5); spec §8 `posts` (author identity → pseudonym; X-6); ADR-27 point 11 for channels with timers ≤ 1 d (X-7); the `:sync` API (X-8); schema v1 channel tables (X-9); STATUS "Noise gossip (Faza 10)" (X-10); INVARIANTS T9, T13, T25, T28, T33 wording and new T36–T41 |
| ADR impact | **ADR-40** (library, provider, storage adapter, classical suite, closed JNI), **ADR-41** (relay-blind channels: seal, generations, shared keys, rotation, funding), **ADR-42** (commit ordering without a server, minimal governance), **ADR-43** (channel invitations, reveal, history "none", stable pseudonym). All four are "propus"; the owner decides (Q1). |
| Sources | Master plan v2.1 (rows 9–15, §3, §4, Annex B–D); spec v2.0 PDF (text extracted with `pdftotext` on 2026-09-25; page numbers are the PDF's); ADR-01 … ADR-39; THREAT_MODEL v2.1; LIMITE; INVARIANTS T1–T35; `allowed-observables.json` v2; the Phase 7, 8 and 9 designs; the OpenMLS 0.9.0 crate sources in the local cargo registry; the research digests of round 10a (requirements, MLS technology, integration, privacy, testing) and their probes; external sources in Appendix D (accessed 2026-09-25). |

**How to read this document.** §0 is the summary: decisions, guarantees, deviations, what the design does not do. §1 fixes scope, requirements and terminology. §2 states the adversary views and the declared channel leakage LC. §3 and §4 are the library and post-quantum decisions. §5 defines every new wire and storage format byte by byte. §6 is the protocol and its state machines. §7 integrates it with the relay, `:sync` and `:entitlement`. §8 covers ephemeral posts and history. §9 is the schema, §10 the modules and the JNI surface, §11 the invariants, §12 the test and exit-gate plan, §13 gates, CI and dependencies, §14 slices, §15 the exit checklist, §16 risks, §17 owner questions, §18 findings outside the phase. Appendix A holds the ADR drafts (Romanian), B the text changes in other documents (Romanian), C the evidence (verified vs assumed), D the sources. "(normative)" marks text that wins over a summary table. Citations `path:line` are relative to the worktree; `F7`, `F8`, `F9` are the Phase 7, 8 and 9 designs; `TM` the threat model; `INV` INVARIANTS; `om:` the `openmls-0.9.0` crate sources; `spec p.N` the spec PDF.

**Identifier conventions.** Decisions `D-n`; guarantees `P-Cn` (privacy) and `CS-Cn` (correctness); deviations `X-n`; requirements `R10-n`; conflicts `C-n`; commit-ordering rules `CO-n`; seal rules `CS-Sn`; residues `L8-Cn` (new LIMITE section L8) and the declared channel leakage `LC-n`; invariants `T36–T41`; crash scenarios `SCN-CA … SCN-CK`; the exit scenario `SCN-M20`; joins `JC-n`, twins `NI-CHn`; mutants `MM-n` (correctness), `PC-n` (privacy), `ME-Cn` (ephemeral); the exhaustive state model `EM-3`; slices `S0 … S12`; S0 checks `V10-n`; owner questions `Q-n`.

---

## 0. Summary

### 0.1 Decisions

| # | Decision | Rejected alternative (why) | Plan / ADR alignment |
|---|---|---|---|
| D1 | **What the forum is.** The forum is the set of invite-only channels a user belongs to. A **channel is one MLS group** (spec p.7: "An MLS group used as an encrypted forum thread"; FR-3.2). Inside a channel, posts are flat with optional reply references; threads are a Phase 13 rendering of reply references, not separate groups. **No content readable by non-members and no public discovery in Phase 10** (FR-3.1 makes discovery conditional: "if introduced"). | Public channels readable by non-members (a key anyone can obtain is a key the operator can obtain, so FR-3.3 would hold only in form); open joins through a published GroupInfo (external commits weaken PCS, RFC 9750 §5.3, and remove the sponsor that ADR-13 relies on); one MLS group per thread (a namespace, tokens and commits per thread) | FR-3.1, FR-3.2; LIMITE E27 ("canalele rămân pe invitație prin MLS") |
| D2 | **Library: OpenMLS 0.9.0** (MIT; released 2026-08-25, the newest version on crates.io on 2026-09-25) with the **libcrux crypto provider 0.4.0** (MIT), exact `=` pins, no default features, `forbid(unsafe_code)` outside tests (`om:src/lib.rs:142`). GHOST supplies the **storage provider** (a change-set adapter, D5), the **Signer** (the ADR-04 pseudonym key, in Rust) and the random source (the provider's HMAC-DRBG). Forbidden features: `crypto-debug`, `content-debug`, `test-utils`, `targeted-messages-draft`, `virtual-clients-draft`, `sqlite-provider`, `js`, `backtrace`, `0-8-1-storage-format`, `migration-import`; `extensions-draft`, `fork-resolution` and `draft-ietf-mls-pq-ciphersuites` off in P0. | mls-rs 0.56.0 (Apache-2.0/MIT, no public external audit found); DMLS (an expired individual draft); an own MLS (forbidden by FR-2.2 and CP-09) | FR-2.2, spec §7.3, plan:106; amends spec Appendix A "0.8.x" (X-5); ADR-40 |
| D3 | **Ciphersuite: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003) for every P0 channel. No post-quantum claim for channels.** ADR-12's own test ("suita hibridă OpenMLS când e stabilă") fails today: draft-ietf-mls-pq-ciphersuites-06 has only TBD code points and is "Waiting for WG Chair Go-Ahead / Revised I-D Needed"; OpenMLS's X-Wing suite uses the non-standard code point 0x004D behind a draft feature and was outside the SRLabs audit; and the measured X-Wing commits (a 1-member remove is 13.6–28.8 KB at 20 members) force 64 KiB blobs and cap channels near 32 members. Channels are therefore **not** protected against harvest-now-decrypt-later, unlike DMs (declared, L8-C1). The design is suite-agile (the suite is part of the invite and of the channel record; a change is a new channel incarnation, §4.4) and names the triggers for adopting the hybrid suite. | X-Wing 0x004D now (experimental code point, unaudited path, 16–64 KiB commits, cap ≈ 32, no ReInit API so the choice is sticky); the WG provisional 0x004F (TBD code point, untested with the libcrux provider); a GHOST-designed PQ PSK layer (new cryptography, CP-09) | ADR-12 unchanged ("când e stabilă"); CP-10; §4; Q2 |
| D4 | **A GHOST outer seal around every MLS byte** (Rule V1 of F9 §1.1 applied to channels). RFC 9420 §6.3 leaves `group_id`, `epoch`, `content_type` and `authenticated_data` of a PrivateMessage in clear, and a Welcome names each joiner's KeyPackageRef in clear. Every channel blob is `salt(16) ‖ hint(16) ‖ ChaCha20-Poly1305(k, 0¹², AD, P)` — the DM shape of F9 §6.2 — keyed per **MLS epoch** from the MLS exporter (posts and commits) or per **generation** (join traffic). Uniform bytes; one AEAD attempt per blob. | Raw MLS on relays (headers leak group id, epoch churn and joins); a static per-channel seal key (joiners and removed members would open every header) | Annex B "namespace opac"; T1, T9; ADR-41 |
| D5 | **Storage adapter with value semantics** (answers SRLabs finding S1-3, "group state and storage get out of step when a write fails"): Kotlin passes the channel's stored key-value rows into each native call; OpenMLS runs over an in-memory map; the call returns a **change-set** that Kotlin writes in the caller's SQLCipher transaction **only on OK**. Values cross JNI only wrapped under the channel state key. The adapter floors OpenMLS's stored wall-clock `added_at` to the day (a pinned-schema edit, the recorded deviation pattern of F9 §2.1), and every KeyPackage lifetime is day-aligned. A **reload oracle** in tests drops and reloads the group after every call. | OpenMLS's SQLite provider (non-atomic with GHOST's rows, a second database); the memory provider persisted as one blob (write amplification at every post) | spec §8.1 "transactions … to avoid epoch divergence"; F9 F-10 carry-over; ADR-40 |
| D6 | **Generations.** A channel lives in a sequence of generations g = 0, 1, … Each has a **generation secret** `G_g = MLS-Exporter("ghost/v1/ch/generation", channel_id, 32)` of the epoch that opened it, from which derive its **namespace**, its per-slot **READ** and **DEPOSIT** secrets and its **join seal key**. A new generation opens at every commit that removes a pseudonym (Remove, leave, eviction) or changes the size class. A removed member cannot compute `G_{g+1}` (it cannot compute the new epoch's exporter), so after the rotation it holds no secret for the new namespace. The old namespace is drained for 14 days. | Namespace per channel for life (a removed member keeps listing volume and timing for the channel's life; a token-bought write capability also reads, F9 §4.5); namespace per MLS epoch (a new write capability per epoch at each relay, and registrations reveal epoch churn); Annex B's `H(channel_public_key)` (computable from public material, against T26's principle) | amends Annex B and F8 D11 (X-1, X-2); ADR-41 |
| D7 | **Shared relay credentials (the T27 analogue).** Every member stores with the generation's DEPOSIT credential v3 and reads with its READ credential v3, per relay slot; the relay sees **one deposit scope and one read scope per (relay, generation namespace)** for all members. **Funders** (the owner and up to two members named in the policy) redeem their own ACCESS tokens for write capabilities used **only** for `RegisterKey`; no member ever stores or reads with a token-bought capability. **The relay needs no change.** | Every member redeems its own write capability (a writer field in substance, F9 §4.1; token use grows with channels); per-member blind rate tokens (a new relay kind and observable; P2) | D11 (F8 §10.7), ADR-25 point 9, ADR-30′; ADR-41 |
| D8 | **Commit ordering without a server (ADR-42).** Relays cannot order commits. Only **committers** (an ordered list of at most 8 pseudonyms in the channel policy: the owner at rank 0, then moderators) may commit membership or policy changes; any member may commit an **empty self-update** (lowest priority). For concurrent commits on one epoch every member picks the same winner — lowest rank, then lowest SHA-256 of the commit — after a **settle window of 20 minutes**; a merged epoch is **final**; a later conflicting commit is **fork evidence**, and the losing side recovers by an in-band **rejoin** (§6.7). Non-committers never send MLS proposals: joins, leaves and requests travel as application messages or join blobs, and committers include proposals by value. | A relay compare-and-swap or sequencer (a proto change and one relay with the power to fork or censor); exposing the relay sequence (per relay, and the leak Phase 9 sealed); revert-after-merge (posts processed under a reverted epoch); DMLS (expired draft); member proposals (OpenMLS refuses to encrypt application messages while its proposal store is non-empty, `om:src/group/mls_group/application.rs:92-94`) | RFC 9750 §5.2.2 ("deterministic tie-breaking policy"); amends ADR-13's removal trigger (X-3); ADR-42 |
| D9 | **No reflex traffic in channels (T40).** No store, redemption or registration is caused by a received blob. Committers commit at **scheduled passes** (at foreground session starts, at most every 6 h, and once a day in background, when work is pending; an empty PCS commit every 7 days) or at their own user actions; members self-update every 28 days at a PRF slot; funders fund at the Phase 8 renewal time and the rotating committer at its own merge. Declared exception LC-6: whether a pass produces a commit depends on pending requests. | Commits triggered by received requests (relays correlate the request's arrival with the committer's store); "the first client that observes the threshold removes" (LIMITE:113) | T28 extended to channels; X-3; ADR-42 |
| D10 | **Invitations by link or QR, admitted by a committer (ADR-43).** A sponsor creates an invite (`ghost://channel/…`, ≤ 270 bytes, §5.9) carrying the current generation's namespace, READ and DEPOSIT bases, the join seal key and a one-time **invite signing key**, and posts `INVITE_ISSUED(invite_id, invite_pk, expiry_day)` in the channel. The invitee deposits a **join request** (its KeyPackage, signed by the invite key) sealed under the join key; a committer admits it at its next pass; the **Welcome** is posted in the same namespace, one sealed copy per joiner, and carries the current generation bootstrap. Invites are single-use, expire within 7 days, and may be sent inside a GHOST DM as text. | KeyPackage and Welcome through the sponsor's DMs (the invitee must be a DM contact; a second online round trip for the sponsor, and the Welcome forward is a reflex); an invite without a signing key (any member who saw a join request could redirect the invite to a sock puppet) | ADR-05 (QR in person recommended, `ghost://` only); ADR-43 |
| D11 | **History policy "none" only in P0** (FR-3.8 requires an explicit policy; LIMITE:126,133 and TM S4 name "none" as the default). A joiner decrypts nothing before its join epoch — a cryptographic property of MLS. `since_join` is what "none" means in MLS; `full` or "N days" needs an application-level history transfer (new protocol, weaker FS and PCS, RFC 9750 §6.7) and is deferred to Phase 13 or later (Q11). | Sponsor re-sharing of recent posts now (new protocol, FS reduction, CP-09) | FR-3.8, LIMITE L3; ADR-43 |
| D12 | **Pseudonyms: ADR-04 unchanged** — `seed = HKDF(root, "ghost/v1/channel-pseudonym" ‖ len ‖ channel_id)` (`KeyDerivation.kt:24-30`), an Ed25519 key that is the member's MLS credential (`BasicCredential`, identity = the 32-byte public key). The seed is derived in Kotlin, crosses JNI once per channel context and signs in Rust (`ed25519-dalek`). **Stable per channel:** a person removed and re-added returns with the same pseudonym (THREAT_MODEL:81 "rotește odată cu părăsirea canalului" is corrected, X-4; Q13). The group id is the random 32-byte `channel_id`. | A per-join incarnation index (changes T14 vectors; not recoverable after a restore; a thief of the seed derives it anyway) | ADR-04, FR-3.9, T14; ADR-43 |
| D13 | **Reveal to one member, opt-in** (ADR-04, LIMITE:135). Each leaf publishes an X25519 **box key** derived from its pseudonym seed (a GHOST leaf-node extension). A `REVEAL` post carries `HPKE-Base(box_pk(M), card ‖ bindings)`; only M opens it; every member sees that the author revealed to *someone*, not to whom. The payload is the author's DM contact card v2 with a two-way binding (pseudonym ↔ `ghost1`). | OpenMLS targeted messages (the recipient leaf index is in clear to every member, `om:src/targeted_messages/mod.rs:55-72`); a broadcast reveal (every member learns the link); the v1 per-channel `revealed` flag (not per person) | ADR-04, TB-7, LIMITE:135; ADR-43 |
| D14 | **Ephemeral posts per channel (ADR-27 §C, FR-7.15).** The channel timer is in the policy (set by the owner; default 7 d); every post carries its `timer_code` in encrypted content; a change is a policy commit every member processes and the UI shows. Countdown, deletion cascade, WAL checkpoint and unread deadline exactly as ADR-32 points 3–7. **Relay TTL of posts = ADR-27 point 11.** Handshake blobs (commits, join traffic, Welcomes) use the post TTL in channels with timer 7 d, 30 d or off, and **7 d in channels with timers ≤ 1 d** (declared deviation X-7, Q12). | Handshake at the post TTL for short timers (members offline more than an hour or a day cannot catch up); the whole short-timer channel at 7 d (content on relays longer than on phones, against ADR-27's intent) | ADR-27, ADR-32; T25 extended; ADR-41 |
| D15 | **Size classes and buckets.** Two classes fixed per generation: **small** (≤ 32 members, bucket floor 4 KiB) and **large** (≤ 100 members, floor 16 KiB). A blob's bucket is the smallest of {4, 16, 64} KiB that is ≥ the floor and holds the body. With 0x0003, every commit of a channel within its class cap fits the floor (S0 measures, V10-4), so a commit and a post are indistinguishable per blob; Welcomes use a larger bucket (declared, LC-5). **P0 limits (NFR-14): 100 members per channel, 12 channels per client, 8 committers, 3 funders, 16 000 bytes of text per post.** | One bucket per message type (leaks commit timing and group size); a 64 KiB floor (16× cost per post); no cap (sparse-tree commits grow linearly: 83 KB at 1 000 members classical, measured) | T9, NFR-14, spec §11.2; ADR-41 |
| D16 | **Module split.** Rust crate `client-core/mls` (`ghost-client-mls`) linked into `libghost_client_net.so`; a closed JNI surface `org.ghost.crypto.bridge.MlsNative` (gate G-M6, the G-R6 pattern); no network, async runtime, logger or clock in the crate; `rayon` pinned to one worker. Kotlin: `:crypto-bridge` wraps `MlsNative`; `:messaging` gains a channel engine run by **the same messaging actor** as DMs (one writer); schema **migration 6** (`:sync`) and **migration 7** (channel tables; v1 channel tables dropped behind a fail-closed guard). The test host library `ghost-dm-host` also exports `MlsNative`. | A second native library (a second Rust runtime in the APK); a second actor thread (cross-feature flows would need a handoff table) | ADR-19 ("și, în fazele următoare, `ghost-client-mls`"); ADR-40 |
| D17 | **Governance scoped to what ordering needs.** Phase 10 delivers roles (owner, moderators = committers), Remove and leave, sponsor attribution (from `INVITE_ISSUED` and Add commits), idle eviction, and the S5 governance simulation over the threshold function. Flags, quarantine, strikes, exclusion lists and verified channels (ADR-13, P1) are specified as reserved formats and delivered with the Phase 13 UX (Q15). | All of ADR-13 now (plan row 10 does not list it; P1) | ADR-13 ("Fazele 10 (primitive MLS), 13 (UX); P1"); TM S5 |
| D18 | **Exit gate proved on the JVM with the real OpenMLS** through the host library, the real `:sync` engine and the conformance-pinned `ModelRelay` with new hostile modes (FORK, WITHHOLD_COMMIT, EXPIRE_LOG, …): **SCN-M20** (20 clients: adds, 200 posts, four kinds of removal, offline resync across ≥ 5 epochs and a rotation, a member offline beyond retention that rejoins, concurrent commits, a relay-induced fork, a re-add), crash enumeration at every SQL statement, an exhaustive commit-arbitration model EM-3, the removed-member and joiner seizure oracles, the reload oracle, the RFC 9420 WG test vectors and OpenMLS's own suite at the pinned tag, the channel privacy world, fuzzing, and mutants registered only with their killers. An emulator job and a device checklist cover what the JVM cannot. | Emulator-only or device-only gates (the Phase 9 runner has no KVM; STATUS:18) | plan row 10; F9 §15 method |

### 0.2 Guarantees claimed (each has a test in §12; none is a UI claim before the gate is met, CP-10)

**Metadata at relays (AD-1: the operator with every relay and the issuer).**

| ID | Guarantee | Proof |
|---|---|---|
| P-C1 | **No channel identity at relays.** No relay-visible value (namespace, verifier, credential, stored byte, capture field) is computable from `channel_id`, pseudonym or box keys, invite ids, KeyPackages, or any MLS header without a generation secret, an epoch secret or an invite. No MLS header byte (group id, epoch, content type, AAD, KeyPackageRef, sender data) appears outside the seal. | T36: JC-1, JC-2, derivation vectors, header scan, PC-1, PC-7, PC-13 |
| P-C2 | **No writer or reader field.** Every store into a generation namespace at a relay presents the one DEPOSIT credential of that (relay, namespace); every list and get presents the one READ credential; token-bought write capabilities appear only in `RegisterKey`. | T37: JC-3, PC-4, PC-10 |
| P-C3 | **Commits look like posts** in channels with timer 7 d, 30 d or off: every blob of a generation namespace uses TTL = the channel TTL and bucket = f(length, floor), and every commit of a channel within its class cap fits the floor. | T37: JC-4, NI-CH2, PC-3, PC-8 |
| P-C4 | **Removal.** (a) Cryptographic: nothing a removed member held opens a blob of an epoch after its removal. (b) Metadata: after the rotating commit, the removed member holds no secret of the new namespace (it cannot compute `G_{g+1}`). | T38: removed-member seizure oracle, PC-2, MM-7, MM-8 |
| P-C5 | **Joiner history "none".** Nothing a joiner holds opens a blob of an epoch before its join epoch. | T39: joiner oracle, PC-2 |
| P-C6 | **No reflex.** Worlds that differ only in what a client received (valid, forged, replayed, join requests, commits) give identical relay views of that client, except the declared LC-6. | T40: NI-CH1, PC-5, PC-6 |

**Correctness and local soundness.**

| ID | Guarantee | Proof |
|---|---|---|
| CS-C1 | **Atomic protocol state.** An OpenMLS state change is stored if and only if the calling SQLCipher transaction commits; a failed call, a crash or a native panic leaves the previous state. | SCN-CA … SCN-CK crash enumeration, reload oracle, MM-1 |
| CS-C2 | **Exactly-once display** per `op_id` per device, across crashes, relay repeats, resurrections and re-encryptions after FAILED. | `oracle_displayed` primary key, SCN-CB |
| CS-C3 | **Convergence (T41).** Honest members that hold the same set of valid commits for epoch e when they settle e merge the same commit, and their `epoch_authenticator`s are equal at every epoch. | EM-3, SCN-M20, SCN-CD, MM-3, MM-4 |
| CS-C4 | **Forks are detected and recovered.** A member that finalized the losing commit of an epoch detects it when the winning commit reaches it within the past-epoch retention, or through the stale-channel rule (§6.7), and recovers by rejoin while its generation is listened to; otherwise it reaches the declared state `REINVITE_NEEDED`, never a silent divergence. | EM-3, SCN-M20 FORK variant, SCN-CG, MM-16 |
| CS-C5 | **No loss inside the declared envelope.** A post whose op ends SENT or DEGRADED is displayed once by every member that lists the namespace within the TTL and holds the post's epoch, unless a declared loss applies (§6.3.6). | seeded worlds, SCN-CB, SCN-CE |
| CS-C6 | **Deterministic order** of display on every device (author minute, then `op_id`). | reorder suite RO-C |
| CS-C7 | **T25 bounds** for channel posts. | T25 channel suite, SCN-CF |
| CS-C8 | **Bounded local state** (§6.3.5, §8.3): past epochs, epoch keys, pending requests, join and rejoin state, dedup tags. | introspection, structural invariants after every reboot |
| CS-C9 | **Migration safety** v5 → v6 → v7. | SCN-CI, migration tests |

### 0.3 Deviations from approved or proposed documents (each recorded in an ADR draft)

| # | Deviation | From | ADR |
|---|---|---|---|
| X-1 | Channel namespace derived from a generation secret, not `H(channel_public_key)` | plan Annex B (plan:433); T26's principle (F9 D4) | ADR-41 |
| X-2 | Read (and deposit) keys shared per **generation**, registered with `RegisterKey` (weeks, accumulating); removed members are cut off by the generation rotation, not "la epoch-ul următor" | plan Annex B (plan:434); F8 D11 "per (namespace, epoch)"; ADR-25 point 9 | ADR-41 |
| X-3 | Only committers remove, at scheduled passes or their own user action; "primul client care observă pragul emite Remove" withdrawn | LIMITE:113; ADR-13 | ADR-42 |
| X-4 | A pseudonym is stable per channel for life; it rotates only with a new channel | THREAT_MODEL:81 | ADR-43 |
| X-5 | OpenMLS 0.9.0 (not 0.8.x) with the libcrux provider | spec Appendix A (spec p. 26) | ADR-40 |
| X-6 | `posts` hold the author pseudonym, not an "authenticated author identity" | spec §8 (spec p. 17) | ADR-43 |
| X-7 | In channels with timers ≤ 1 d, handshake blobs use TTL 7 d (relays can tell them from posts there) | ADR-27 point 11 (for those blobs only) | ADR-41 |
| X-8 | `:sync` API: `Funding`, `CapabilityKind.REGISTER`, registration capabilities kept apart from store credentials; schema migrations 6 and 7 | F7 §9 API; ADR-34′ | ADR-40 |
| X-9 | v1 tables `channels`, `channel_pseudonyms`, `mls_state`, `posts` dropped (fail-closed guard) and replaced; history policy values reduced to `none` | schema v1 (`Schema.kt:180-210`) | ADR-43 |
| X-10 | "Autentificare Noise între relay-uri și convergență de date (Faza 10)" is spec v2.0 numbering (its Phase 10 was "Multi-relay metadata protection: three relays, gossip, …", spec p. 23); v2.1 row 10 owes no gossip | STATUS:14; `relay/README.md:20` | erratum (Appendix B.4) |

### 0.4 What this design deliberately does not do

- **No post-quantum protection of channels and no PQ wording for them** (D3). DMs keep theirs (ADR-36); the UI must not imply the two are alike.
- **No public content, no discovery directory, no open joins, no external commits, no published GroupInfo** (D1).
- **No MLS proposals from non-committers, no targeted messages, no SafeAAD, no AppDataUpdate** (the `extensions-draft` feature stays off).
- **No history transfer to joiners** (D11), no pinned posts (FR-3.7, P2), no media (Phase 11; the content format reserves a TLV).
- **No relay change**: no new RPC, credential kind, observable field or value (§7.8).
- **No fork-resolution feature of OpenMLS** in the shipped graph: recovery uses GHOST's rejoin with `swap_members` (§6.7).
- **No reflex, no read receipts, no typing, no delivery status beyond Phase 7's outcome.**
- **No second native library, no second actor thread, no new Gradle coordinate, no logger.**
- **No claim that pseudonyms hide who is behind them from other members' behavioural analysis** (ADR-04's unlinkability is cryptographic only).
- **No claim that relays cannot learn channel membership**: session co-occurrence (LIMITE L2.1 #1, L7-D2) rebuilds the client ↔ namespace graph under AD-1; Phase 12 owns the decoupling. Q22 of Phase 9 (no UI claim of channel unlinkability against relays) stands.

---

## 1. Scope, requirements, terminology

### 1.1 The exit gate and what it pulls in (normative)

The plan's gate has three clauses. Each maps to a proof in §12:

| Clause | Read as | Proof |
|---|---|---|
| "20 clienți add/remove/resync" | 20 clients in one channel; adds by invitation and Welcome; removes by moderator, by leave, by idle eviction and by the device-revocation swap; resync after restart, after missed commits still on relays, after missed commits past their TTL, and after a fork (FR-2.2, FR-3.2) | SCN-M20 (§12.5) under crash enumeration and seeded worlds; EM-3 |
| "membru scos nu decriptează epoch-uri noi" | P-C4(a) under a seizure model: every secret a removed member held, including retained past-epoch secrets and generation secrets, against every blob of every later epoch (FR-3.8, TM S4, LIMITE:39) | T38 oracle (§12.8) |
| "T25 și în canale" | ADR-27's deletion on every honest device, the relay TTL table, and the relay observing only the bucket | T25 channel suite (§8.5, §12.6) |

The gate does not say whether the 20 clients run in-process, on emulators or on devices. This design runs them **in-process on the JVM** with the production cryptography (as F9 did for its worlds) and states in §12.12 what that leaves unproved (real SQLCipher, real Tor latency, device performance). Spec Appendix A's "RFC 9420 interoperability fixtures" are the MLS working group's test vectors, run against the pinned OpenMLS and through GHOST's adapter (§12.2).

### 1.2 Requirements (IDs R10-n; sources verified in the worktree)

| ID | Requirement | Source | Where |
|---|---|---|---|
| R10-1 | RFC 9420 through OpenMLS or another reviewed implementation; no simplified group encryption | FR-2.2 (spec p.8), spec §7.3 (p.15), plan:106 | §3 |
| R10-2 | Group state holds credential binding, epoch, tree, pending proposals and commits; Welcomes encrypted individually as opaque blobs; add/remove/update commits advance the epoch; app messages bind channel id, epoch, content type, operation id; desync triggers bounded resync, never a static key | spec §7.3 | §5.5, §5.6, §6 |
| R10-3 | Versioning, replay protection, bounded parsing, context binding, fuzzing; the four replay cases Phase 7 hands to the MLS layer | FR-2.8; F7:47-52 | §6.3, §12.10 |
| R10-4 | Rust crate `ghost-client-mls` behind JNI, bytes only, no protocol logic in Kotlin, reproducible native build | ADR-19:13,16 | §10 |
| R10-5 | PQ: hybrid suite "when stable"; no standalone KEM | ADR-12; plan:233 | §4 |
| R10-6 | F9's F-10 carry-over: storage adapter (S1-3), day rewrite and clock gate, log gate, `rayon` check, X-Wing size facts, `hpke-rs` MPL decision, SRLabs S0-1 risk-accepted, an ADR for spec Appendix A | `faza9-dm.md:2827` | §3.4, §3.6, §3.9, §13 |
| R10-7 | Invite-scoped channels; discovery only of explicitly public metadata | FR-3.1; LIMITE:233 | D1, §6.2 |
| R10-8 | One channel = one MLS group with persisted epoch and membership | FR-3.2 | §5.2, §9 |
| R10-9 | Posts encrypted and authenticated before the queue; author time at the minute | FR-3.3, FR-3.4, plan:262, T13 | §5.5 |
| R10-10 | Incremental sync with opaque cursors, dedup, idempotency (Phase 7) | FR-3.5 | §7 |
| R10-11 | Local filter, mute, block, hide (P1) | FR-3.6 | §10.3 (facade flags; UI Phase 13) |
| R10-12 | Removal blocks future epochs; new-member history follows an explicit policy | FR-3.8; LIMITE:126,133 | §6.6, §8.4 |
| R10-13 | Pseudonym derivation per channel as MLS credential | ADR-04; `KeyDerivation.kt:24-30` | D12 |
| R10-14 | T14: pseudonyms unequal across channels, not derivable without the seed | INV:22 | §11 |
| R10-15 | Reveal only by an explicit opt-in MLS message to a member; nobody can be forced | ADR-04; LIMITE:135; TB-7 | D13, §6.9 |
| R10-16 | Ephemeral per channel: values, default 7 d, timer in content, change shown to all, countdown, deletion + checkpoint, relay TTL = smallest bucket ≥ timer, T25 | ADR-27 §C; ADR-32; FR-7.15 | §8 |
| R10-17 | The relay sees only namespace, hash, bucket, minute, capability or nullifier, one circuit | plan:241; TM:97-98; T1 | §2, §7.8 |
| R10-18 | Padding buckets (T9), a circuit per namespace (T21), fixed-size batches | ADR-01, ADR-09 | D15, §7 |
| R10-19 | Every blob on ≥ 2 operators; withholding caught by readers and the MLS transcript | ADR-11; F7:637 | §6.3, §6.7 |
| R10-20 | Shared read keys per namespace registered by hash; tokens never buy reads | F8 D11; ADR-25 point 9 | D7, §7.3 |
| R10-21 | Read schedule independent of activity; a client reads its own namespaces and its channels | T19, T31 | §7.7 |
| R10-22 | Writes need a token per (relay, namespace, week); a pack gives 16 ACCESS tokens per (slot, week); DMs use ≤ 2 | F8:29; F9 §4.8 | §7.4 |
| R10-23 | Schema: history policy, time columns at minute/hour/day; MLS state out of backups | spec §8; T4, T20, T33 | §9 |
| R10-24 | Governance primitives in Phase 10, UX in Phase 13 (P1) | ADR-13 | D17, §6.10 |
| R10-25 | NFR-2 p95 < 8 s over Tor on a 20-member channel; NFR-14 documented limits enforced by the UI; spec §11.2 group-size and pending-message limits | plan:281; spec pp. 11–12, 20 | D15, §7.7 |
| R10-26 | No GPL, AGPL, LGPL; MPL-2.0 only unmodified with source offered; the Rust allowlist and cargo-deny; OpenMLS in the external audit | ADR-37; plan:319, plan:464 | §3.9, §13.3 |

**Non-goals** (restating §0.4 as scope): public channels, discovery, media, pins, history transfer, multi-device (P2), cover traffic (P2), relay-side changes, the Phase 13 UI, and the ADR-13 P1 governance mechanics beyond D17.

### 1.3 Terminology (normative; resolves the research's terminology conflicts)

| Term | Meaning in this design | Not to be confused with |
|---|---|---|
| **forum** | the set of channels a user belongs to; there is no global forum object | a public board |
| **channel** | one MLS group; `group_id = channel_id`, 32 random bytes chosen by the creator | spec p.7 calls it "thread"; plan and FR-3.1 call it "channel" (same object) |
| **post** | an MLS application message whose content is `ChannelContent` (§5.5); replies are posts with `reply_to` | a DM message |
| **epoch** | the MLS epoch only | the **ISO week** (`period_id` of `RegisterKey`, the Phase 8 access period) and the Phase 8 entitlement **epoch** (13-week pricing); F8 D11's "per (namespace, epoch)" is read as "per (generation, week)" (X-2) |
| **generation** | a run of epochs sharing one namespace and one set of relay secrets (§6.5) | an epoch |
| **history policy** | (a) what a joiner can read (FR-3.8): `none` only; (b) how long past-epoch secrets are kept (§8.3) | the relay TTL |
| **reveal** | an opt-in message that links the author's pseudonym to its DM card, readable by one chosen member (§6.9) | the v1 per-channel `revealed` flag, withdrawn (X-9) |
| **committer** | a pseudonym in the policy's ordered committer list; rank = index; rank 0 = owner | "moderator" (a committer of rank ≥ 1) |
| **funder** | a member named in the policy who pays the relay registrations of the current generation | a writer (all members write with the shared DEPOSIT key) |

### 1.4 Conflicts found in the sources and how this design resolves them

| # | Conflict | Resolution |
|---|---|---|
| C-1 | Annex B `namespace = H(channel_public_key)` vs T26's principle that nothing relay-visible is computable from public material | generation-derived namespace (D6; X-1) |
| C-2 | Annex B: removed members lose reads "la epoch-ul următor"; but `RegisterKey` registrations are per ISO week, accumulate and live until `start(w+2)+1h` (F9 §4.4), and a write capability grants reads | rotation to a new namespace at every removal (D6); per-epoch keys rejected (they would expose epoch churn) |
| C-3 | Annex B per-writer write capabilities vs Phase 9's finding that a per-writer scope is a sender field | shared DEPOSIT credential (D7) |
| C-4 | LIMITE:113 "primul client care observă pragul emite Remove" vs the no-reflex principle | committers at scheduled passes (D8, D9; X-3) |
| C-5 | TM:81 "pseudonimul rotește odată cu părăsirea canalului" vs the deterministic ADR-04 derivation | stable per channel; TM:81 corrected (D12; X-4) |
| C-6 | FR-1.9 / LIMITE:39 device revocation for groups vs single-device P0 and seed-derived pseudonyms | swap of the member's own leaf by rejoin; a thief with the seed holds the pseudonym key, so real exclusion is leaving that pseudonym (§6.12, L8-C9) |
| C-7 | History "full" needs a transfer protocol MLS does not have; relay TTL max 30 d vs spec FR-5.5's 90-day default | "none" only (D11); FR-5.5 is the relay default for other data and ADR-27 governs channel blobs |
| C-8 | ADR-13 and TM S5 put governance primitives in Phase 10; the plan row does not | D17 |
| C-9 | STATUS:14 assigns Noise gossip to "Faza 10" | spec v2.0 numbering (X-10) |
| C-10 | Spec §8 `posts` "authenticated author identity" vs ADR-04 | pseudonym (X-6) |
| C-11 | NFR-2 (p95 < 8 s) vs the ADR-20 30-second listing interval (estimated ~40 s p95 for NFR-1, LIMITE L2.1 #5) | not met by design; measured in Phase 12 (Q21) |
| C-12 | Spec Appendix A names OpenMLS 0.8.x; 0.9.0 fixes two pre-authentication decoding advisories | 0.9.0 (X-5) |
| C-13 | ADR-12's hybrid suite vs its stability, size and audit status | classical now (D3) |
| C-14 | OpenMLS refuses `create_message` while its proposal store is non-empty (`application.rs:92-94`); RFC 9420 §15.2 only requires handshake changes to be applied before new application messages | no proposals from non-committers; committers use their own proposals by value (RFC 9420 §12.4 allows it) (D8) |

---

## 2. Adversary views and the declared channel leakage LC

### 2.1 Effective views (not only T1 captures)

| Observer | What it sees for a channel |
|---|---|
| Relay (AD-2) | per generation namespace: stores (hash, bucket, TTL, minute, the one DEPOSIT scope), lists and gets (the one READ scope, per circuit), checks, funders' `RedeemToken` and `RegisterKey` (write-capability scope, `key_kind`, period), the circuit of every request; stored bytes (uniform) |
| AD-1 | the union over all relays and the issuer; session co-occurrence links a client's namespaces in ~3 sessions (L7-D2), so the client ↔ channel-namespace graph, and the generation chain of a channel (the new namespace starts in the same sessions as the old one) |
| Member (AD-6) | the roster of pseudonyms and box keys, leaf order (join order), every commit's author (who added, removed, changed policy), `INVITE_ISSUED` authors (sponsors), posts with author pseudonym and minute, reveals' authors (not recipients), leaves, KeyPackage lifetimes (day), the channel policy |
| Removed member | everything it held until removal: the old generation's secrets and namespace, retained past-epoch secrets, the roster; nothing of later epochs or generations (P-C4) |
| Invite holder (before admission, or a leaked invite) | the generation namespace, READ and DEPOSIT bases and join keys of that generation: it can list and store (volume, timing, quota) and open the outer layer of join traffic (KeyPackageRefs, KeyPackages of other joiners); no post or commit content |
| AD-8 (seized device) | local rows and WAL; OpenMLS state: current epoch, past epochs within retention (§8.3), the tree; epoch seal keys within retention; pending plaintext of posts not yet encrypted |

**Rule V1 for channels (normative).** Every relay-stored channel byte is sealed under keys never presented to a relay: epoch seal keys, the join seal key, KeyPackage and Welcome contents. READ and DEPOSIT secrets and write capabilities are presented; nothing else is.

### 2.2 Declared channel leakage LC (the only information the channel privacy world lets through)

Per generation namespace per relay:
- **LC-1** the minutes of stores, their size buckets (floor 4 or 16 KiB; Welcomes larger) and one TTL class (two in channels with timers ≤ 1 d: posts and handshake, X-7), and the one DEPOSIT scope; `check` events;
- **LC-2** each member's list schedule (T19), gets per list (≈ the number of fetching members), hence presence and approximate size;
- **LC-3** funders' weekly redemptions and registrations at the Phase 8 renewal time, and the rotating committer's redemptions and registrations for a new generation at its merge (§7.4);
- **LC-4** generation rotations: a new namespace starts, the old one drains for 14 days; under AD-1 co-occurrence links them, so the relays learn the count and timing of removals;
- **LC-5** joins: a Welcome-sized blob at a committer pass, and a new listener; the joiner's own join request (a floor-sized blob) before;
- **LC-6** whether a committer's scheduled pass produced a commit (it does only when work is pending or at the weekly PCS commit), which reveals that some request was pending;
- **LC-7** the Phase 7 session-start co-occurrence, the grouping of requests per circuit within a session, the result of every request, and an identical hash on an identical-bytes resend (as F9 LD).

Everything else a relay can compute from its effective view is a violation of T36, T37 or T40.

### 2.3 The privacy property the exit gate proves

(a) **Join-freedom:** the exact searches JC-1 … JC-6 find nothing in the effective relay view (§12.7). (b) **Non-interference:** twins that differ only in received content (NI-CH1), in commit versus post at the same moment (NI-CH2), or in the number of channels a client funds per week at fixed renewal times (NI-CH3) give identical views. (c) The removed-member and joiner oracles open 0 (T38, T39). (a) and (b) are exact per seed; there is no statistical clause in Phase 10 (the channel world is small and the LC attacker saturates, lesson L-4 of the testing research; Phase 12 owns statistics over traffic).

**Scope (as F9 §22.8.8).** These properties are proved for the design and hold against AD-1 only for a build published in the transparency log and reproduced by the auditors (ADR-38, planned); today neither exists.

---

## 3. Library: OpenMLS 0.9.0 (ADR-40)

### 3.1 Why OpenMLS, and what is new relative to Phase 9's evaluation (normative)

F9 kept OpenMLS as the Phase 10 library (Q44) and recorded its costs for DMs. For channels the costs change sign: MLS's single-ciphertext fan-out and tree PCS are what a group needs. Alternatives: **mls-rs** 0.56.0 (AWS, Apache-2.0 OR MIT; no public external audit found — kept only as an optional test oracle, Q22); **DMLS** (draft-kohbrok-mls-dmls-03, expired, weaker FS); an own implementation (forbidden). OpenMLS evidence, checked 2026-09-25:

| Item | Fact | Source |
|---|---|---|
| Version | 0.9.0 (2026-08-25), newest and max stable on crates.io; 0.9.0-rc.1 … rc.4 in August | crates.io API |
| Licence | openmls, openmls_traits 0.6.0, openmls_libcrux_crypto 0.4.0, openmls_memory_storage 0.6.0: MIT; `tls_codec` 0.5.0: Apache-2.0 OR MIT; **`hpke-rs`, `hpke-rs-crypto`, `hpke-rs-libcrux` 0.7.0: MPL-2.0** | local `Cargo.toml` files |
| MSRV | 1.91 (GHOST toolchain 1.98.1, `ghost/rust-toolchain.toml`) | local `Cargo.toml` |
| Unsafe | `#![cfg_attr(not(test), forbid(unsafe_code))]` | `om:src/lib.rs:142` |
| Android | "Unsupported, but built on CI": `aarch64-linux-android`, `x86_64-linux-android` are built, not tested | `om:README.md:34-47` |
| Advisories | GHSA-rrmv-c79f-cf5r (out-of-bounds panic in `DeserializeBytes` of `MlsMessageIn`, `PublicMessageIn`, `ProposalIn`, `Extensions`, … "decoded directly from untrusted wire bytes before any authentication"; ≤ 0.8.1, fixed 0.9.0); GHSA-w62v-gv48-63rh (quadratic duplicate detection in pre-authentication extension decoding; fixed 0.9.0); GHSA-8x3w-qj7j-gqhf (improper tag validation, High, 2026-02-04); GHSA-qr9h-x63w-vqfm (secret tree not persisted after processing, 2025-09-26) | GitHub advisories |
| Audit | SRLabs report v1.2 (2026-03-11): crypto and storage providers and the PQ suites out of scope; **S1-3** (state and storage diverge on a failed write, "Acknowledged"); **S0-1** (unbounded allocations, a group member's 50 MiB leaf extension slows every later tree operation, "Risk Accepted") | F9 §20 F-10; `phase9b/src/srl-openmls.txt` (not re-read) |
| Maintenance | Phoenix R&D and CE Labs; `main` active to 2026-09-24; unreleased: `ExportedSecret<T>` zeroized on drop (a breaking API change for the next bump; 0.9.0's `export_secret` still returns `Vec<u8>`, `om:src/group/mls_group/exporting.rs:35-41`) | GitHub, CHANGELOG, local source |
| Production | XMTP and Wire run OpenMLS forks; Air uses the crate | F9 R-libs (not re-checked) |

**Consequences.** Pin `=0.9.0` (the two decoding advisories are pre-authentication and reachable by anyone who can put bytes in a namespace — but GHOST's seal means only holders of a seal key — members, and invite holders for KeyPackages in join requests — can, §5.6); every JNI entry point under `catch_unwind` with the silent panic hook (the F9 §2.6 pattern; `ghost/Cargo.toml` keeps unwinding); the pre-authentication parsers are fuzzed through GHOST's entry points (§12.10).

### 3.2 Pins and features (normative)

```toml
openmls                = { version = "=0.9.0", default-features = false }   # openmls declares no default feature
openmls_traits         = { version = "=0.6.0", default-features = false }
openmls_libcrux_crypto = { version = "=0.4.0", default-features = false }
```

- The `libcrux-provider` feature of `openmls` is not enabled (it only adds the provider crate to `openmls`'s own graph); GHOST depends on the provider directly, uses its `CryptoProvider` type (`openmls_libcrux_crypto/src/crypto.rs:22`) and does **not** use its `Provider`, whose storage is the memory provider (`lib.rs:42`). `openmls_memory_storage` 0.6.0 remains in the graph as a non-optional dependency of the libcrux provider (its `Cargo.toml`); gate G-M2 checks that no GHOST code names it.
- **Forbidden in every shipped graph (G-M2):** `crypto-debug`, `content-debug` (they log secrets and content if any logger is installed), `test-utils`, `targeted-messages-draft` (leaks sender→recipient to members), `virtual-clients-draft`, `sqlite-provider`, `js`, `backtrace`, `0-8-1-storage-format`, `migration-import`, `extensions-draft`, `fork-resolution`, `draft-ietf-mls-pq-ciphersuites` (D3), `all-ciphersuites`, `generate-kats`, `unchecked-conversions`. The test graph may enable `test-utils` for OpenMLS's own suite (`mls-vendor-tests`, §13.2) only.
- `openmls_basic_credential` is not used: the Signer is GHOST's (§3.3).

### 3.3 Provider composition (normative)

| OpenMLS trait | GHOST implementation |
|---|---|
| `OpenMlsCrypto`, `OpenMlsRand` | `openmls_libcrux_crypto::CryptoProvider` (HMAC-DRBG seeded from `rand::rngs::SysRng`, reseeded from it, `crypto.rs:14-58`; `SysRng` reaches `getrandom`, so the host test build's deterministic `getrandom` backend of F9 §15.1 covers it — S0 check V10-6) |
| `StorageProvider` (72 methods, `openmls_traits-0.6.0/src/storage.rs`) | `GhostKv`: an in-memory map loaded from the rows Kotlin passes, recording every write and delete into a change-set (§3.4) |
| `Signer` | `PseudonymSigner`: `ed25519-dalek` 2.2.0 (the workspace version) over the 32-byte pseudonym seed held in native memory for an open channel context |
| `OpenMlsProvider` | `GhostProvider { crypto: CryptoProvider, storage: GhostKv }` |

The pseudonym **public key** computed by `:identity` (BouncyCastle, ADR-17) and by `PseudonymSigner` must be equal: RFC 8032 key generation from a seed is deterministic, and a shared vector (`protocol/test-vectors/ch_derive.txt`) is replayed by both. MLS credentials are signed and verified only in Rust (the "one verifier per artifact type" rule of ADR-35's X-21 correction).

### 3.4 The storage adapter (normative; answers S1-3)

1. **Scope.** OpenMLS storage keys are either **group-scoped** (they include the `GroupId`: tree, context, confirmation tag, message secrets, epoch secrets, own leaf, proposal queue, join config, …) or **global** (KeyPackages by `KeyPackageRef`, signature key pairs, encryption key pairs by public key, PSKs). `GhostKv` maps them to two tables: `mls_kv(channel_id, k, v_env)` and `mls_global_kv(k, v_env)` (§9). A key that matches neither pattern at runtime is a `STATE_CORRUPT` result, never a guess (`GhostKvScopeTest` enumerates the 72 methods).
2. **Load.** Before a call, Kotlin reads every `mls_kv` row of the channel and every `mls_global_kv` row **tagged with the channel** (every call is channel-scoped, so the adapter tags each global write — a KeyPackage and its private keys, a leaf encryption key pair — with the channel it was made for; GHOST's Signer stores no signature key in OpenMLS), and passes them as one TLV array. The rows' values are `nonce(12) ‖ ChaCha20-Poly1305(mls_state_key, AD = "ghost/v1/mls-kv" ‖ scope ‖ channel_id ‖ SHA-256(k), v)`; Rust unwraps them. A row that does not open is `STATE_CORRUPT`.
3. **Run.** OpenMLS runs over the map; every `write_*`, `queue_*`, `append_*`, `delete_*`, `remove_*` and `clear_*` updates the map and appends `(put | delete, scope, k, v)` to the change-set.
4. **Return.** On success the call returns its outputs and the change-set with wrapped values; on any error, `INTERNAL` (a caught panic) or a native crash, nothing is returned and Kotlin writes nothing. Kotlin applies the change-set **in the same SQLCipher transaction** as the channel rows the call affects (the inbox claim, the post row, the outbox op). There is no native cache across calls in P0 (Phase 9's value rule); S0 measures the cost (V10-5) and a version-checked cache is Q18's alternative.
5. **Day rewrite (the "clock" half of F-10).** OpenMLS stamps `MessageSecrets` with `SystemTime::now()` when an epoch becomes past (`om:src/group/mls_group/past_secrets.rs:80,105`) and serialises it (`added_at`). `GhostKv::write_message_secrets` serialises the entity to `serde_json::Value`, replaces every `added_at` by the start of its UTC day with zero nanoseconds, and stores the result. This reads and writes OpenMLS's serde layout, outside semver (**recorded deviation**, like F9's S0-15): gate G-M7 pins a golden `MessageSecrets` per OpenMLS pin and fails when the field moves; a missing or renamed field is `STATE_CORRUPT`, never a silent skip.
6. **Reload oracle (tests).** In every world, after every native call, the harness reloads the group from the stored rows (`MlsGroup::load`, `om:src/group/mls_group/mod.rs:500`) and compares epoch, `epoch_authenticator`, tree hash, own leaf index and a digest of the secret-tree state with the call's in-memory result. This is the test that would have caught GHSA-qr9h-x63w-vqfm.
7. **Storage format stability.** OpenMLS 0.9.0 changed its serde encoding relative to 0.8.1 and offers `0-8-1-storage-format` and `migration-import`; GHOST starts on 0.9.0 and never enables them. Every pin bump runs golden-state upgrade tests (§3.8, G-M7).

### 3.5 Configuration (normative)

| Setting | Value | Why |
|---|---|---|
| Ciphersuite | 0x0003 | D3 |
| Wire format policy | `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY` (the default, `config.rs:642-645`) | handshake and application messages encrypted |
| `padding_size` | 0 | the outer seal pads to the bucket |
| `use_ratchet_tree_extension` | true (the Welcome carries the tree) | the joiner has no other source; measured sizes in §5.7 |
| Sender ratchet | `SenderRatchetConfiguration::new(16, 1000)` | out-of-order tolerance 16 generations; peek ordering (§6.3.3) makes larger tolerance unnecessary |
| Past epochs | `max_past_epochs(64)` as a hard cap; time-based deletion by GHOST at SWEEP (§8.3) | late posts decrypt; bounded FS loss |
| KeyPackage lifetime | `Lifetime::init(day_start(today) − 86 400, day_start(today) + 83 · 86 400)` (`om:src/key_packages/lifetime.rs:79`; 84 days, within OpenMLS's maximum range of 84 d + 1 h, `lifetime.rs:13-23`) | no second-level clock in state; a peer one day behind accepts it |
| Leaf lifetime validation | on (the default) | idle members are evicted at 63 d (§6.6), before an un-updated leaf's 84-day lifetime ends |
| External commits | refused: GHOST never publishes a GroupInfo, and a commit whose sender is external is dropped before `process_message` (§6.4 CO-1) | RFC 9750 §5.3; the sponsor model |
| Credentials | `BasicCredential` whose identity is the 32-byte pseudonym public key, equal to the leaf's signature key | D12 |
| Capabilities | GHOST extension types 0xF0A1 (context), 0xF0A2 (box key) in every leaf; `RequiredCapabilities` of the group names both | §5.3, §5.4 |

### 3.6 Clocks, logs and threads in the OpenMLS graph (normative)

- **Clock sites** (verified by grep of the 0.9.0 sources): `past_secrets.rs:80,105` (stamps, rewritten to the day, §3.4), `past_secrets.rs:234,254` (time-based deletion with `older_than_duration`, never called by GHOST: GHOST uses `before_timestamp` with a Kotlin-supplied day), `key_packages/lifetime.rs:66` (`Lifetime::new`, never called: GHOST uses `Lifetime::init`), `lifetime.rs:88` (validation against the device clock, reads only). Gate **G-M8** (the G-R8 method of F9 §16.1) scans the compiled library code of the `ghost-client-mls` graph and compares the sites with a committed, justified baseline.
- **Logging.** `log` 0.4 is a hard dependency of OpenMLS; my pattern count over the non-test sources on 2026-09-25 is 200 matching lines, different from earlier hand counts (135, 190, 229; F9 RX-12), which is why the gate counts mechanically at the pin. No crate of the graph installs a logger (`log::set_logger` is never called), so every call is a no-op; `crypto-debug` and `content-debug` are forbidden (§3.2). Gate **G-M4** extends F9's G-R4 rule to the MLS graph.
- **Threads.** `rayon` is a normal dependency (`treesync/treekem.rs`, `treesync/node/parent_node.rs`). `ghost-client-mls` builds the global pool once at library load with **one worker** (`ThreadPoolBuilder::new().num_threads(1).build_global()`); a unit test asserts `rayon::current_num_threads() == 1` inside a native call (the F-10 "single-worker check"); this also keeps test runs deterministic.

### 3.7 Maturity table and the audit scope (normative evidence table)

| Component | Audits and advisories | Deployment | Formal analysis |
|---|---|---|---|
| OpenMLS 0.9.0 | SRLabs v1.2 (S1-3 acknowledged → answered by §3.4; S0-1 risk-accepted → bounded by the 64 KiB blob limit and KeyPackage checks, §6.2.4); four advisories, all fixed at or before 0.9.0 | Wire and XMTP forks, Air | RFC 9420's analyses are of the protocol (TreeKEM's DY* proof covers the authors' executable specification, not OpenMLS; eprint 2025/410) |
| libcrux provider 0.4.0, `hpke-rs` 0.7.0 | outside SRLabs's scope; GHSA-g433-pq76-6cmf (`hpke-rs` < 0.6) and GHSA-435g-fcv3-8j26 (libcrux ≤ 0.0.5) fixed below the pins | OpenMLS users | libcrux primitives partly verified (hax/F*); HPKE glue not |
| GHOST seal, generation derivations, commit arbitration, box-key HPKE, storage adapter, JNI | none yet | none | EM-3 (state model, §12.3); no ProVerif model in Phase 10 (Q23) |

The external audit of plan row 15 names "OpenMLS"; its scope for GHOST is: the pinned OpenMLS and provider revisions **as GHOST configures them**, `ghost-client-mls` in full, the Kotlin channel engine and schema, the generation and credential design, and the commit arbitration. It is a release gate, not a Phase 10 gate.

### 3.8 Size, build and bump policy (normative)

- **Size (measured by the research probe, not yet in the shipped library).** A stripped `cdylib` with OpenMLS 0.9.0 and the libcrux provider over a baseline that already holds X-Wing, Ed25519, ChaCha20-Poly1305 and `serde_json` grew by **+2.68–2.88 MB on arm64-v8a and +3.27–3.32 MB on x86_64** (probe `p10mls/sizeprobe`, cargo-ndk 4.1.2, NDK 30; the PQ feature added ≈ 16 KB more). In `libghost_client_net.so` crates already linked (serde, zeroize, thiserror, `rand_chacha`, …) are shared, so the real delta is smaller; **S0 measures it with `scripts/build-native.sh` (V10-3)**. The budget proposed: ≤ +3 MiB per ABI (Q24 of F9 set +1 MiB for the DM stack; NFR-4 is < 80 MiB universal).
- **Portable build.** The libcrux crates added by the provider (`libcrux-aead`, `libcrux-aes`, `libcrux-chacha20poly1305`, `libcrux-poly1305`, `libcrux-ed25519`, `libcrux-hkdf`, `libcrux-hmac`, `libcrux-sha2`, `libcrux-hmac-drbg`) are checked in S0 for platform intrinsics and build-script flags; the rule of F9's G-R3 (portable code only, verified from build outputs) extends to them (V10-7).
- **Reproducibility.** T12's same-path identity and `native-libs.sha256` cover the grown library.
- **Bumps.** Exact pins; a bump is its own PR running golden channel states per pin (`client-core/mls/tests/golden/openmls-<version>/`) with an upgrade test (load the previous pin's states, continue every group), G-M7, G-M8, the WG vectors, OpenMLS's suite at the new tag, the full `channel-exit-gate`, and a CHANGELOG review of storage format, wire format and error semantics.

### 3.9 Licensing (normative; ADR-37)

The OpenMLS stack adds **three MPL-2.0 crates** (`hpke-rs`, `hpke-rs-crypto`, `hpke-rs-libcrux`), required by both OpenMLS crypto providers. ADR-37 point 2 allows MPL-2.0 unmodified with the exact source published on the distribution channels and a note in the licence screen; the two existing MPL packages (`option-ext`, `priority-queue`) already follow that rule through G-L4 (`mpl-sources.sh`). Decision (Q16): accept the three crates unmodified, add them to G-L4 and the notices, no `[patch]`. The alternative — a GHOST `OpenMlsCrypto` over RustCrypto's `hpke` (MIT/Apache-2.0; already pulled, linker-dropped, by vodozemac) — removes MPL but adds a GHOST-written crypto provider to the audit scope. Everything else in the graph is MIT, Apache-2.0 or dual; `cargo deny check licenses` must stay green (G-M1).

---

## 4. Post-quantum posture (normative; ADR-12 applied, CP-10)

### 4.1 Facts (checked 2026-09-25)

- **draft-ietf-mls-pq-ciphersuites-06** (2026-07-21): 11 suites, code points **TBD1–TBD11**, state "Waiting for WG Chair Go-Ahead" with "Revised I-D Needed – Issue raised by WG"; its hybrids give "authenticity against classical attacks only".
- **X-Wing** (draft-connolly-cfrg-xwing-kem-11, 2026-09-23): an Independent Submission; HPKE KEM value **25722 (0x647A) requested**.
- **OpenMLS 0.9.0 / openmls_traits 0.6.0**: `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 = 0x004D` (an OpenMLS-specific code point, doc comment "X-WING KEM draft-01") and the WG provisional `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 = 0x004F` ("TBD1 (provisional code point)"), both behind `draft-ietf-mls-pq-ciphersuites`, both mapped to the HPKE KEM `XWingKemDraft6` (`openmls_traits-0.6.0/src/types.rs:449-472, 789-793`). The libcrux provider lists 0x0001, 0x0003 and 0x004D as supported (`crypto.rs:88-96`); its `supports()` accepts any Ed25519 suite with a supported AEAD and hash, so 0x004F would be accepted but is untested there.
- **Sizes** (research probe, host, OpenMLS 0.9.0, bytes): at 20 members, X-Wing: KeyPackage 2 694, remove commit 13 565 (populated tree) to 28 792 (sparse), Welcome for one add 35 908–52 350; classical 0x0003: KeyPackage 324, remove commit 1 010–2 076, Welcome 5 186–6 223. At 100 members, a sparse X-Wing remove is 125 KB, and at 1 000 members 1.18 MB.
- **No suite migration API**: RFC 9420's ReInit is not exposed (`om:src/group/mls_group/proposal_store.rs:608-609`, "TODO #751"); changing a channel's suite means a new group.

### 4.2 Decision

**P0 channels use 0x0003 only.** ADR-12's clause for MLS is kept literally: the hybrid suite is adopted "when stable", and by every available criterion it is not (TBD code points, an experimental OpenMLS code point, no audit of that path). Choosing 0x004D now would make every channel created in Phase 10 depend on a code point that neither the IETF nor the OpenMLS maintainers treat as final, with 16–64 KiB commits and a ≈ 32-member cap, and the choice cannot be migrated in place.

### 4.3 What is and is not protected (normative wording for LIMITE L8-C1)

| Layer | Against a harvest-now-decrypt-later adversary (records relay blobs now, breaks X25519 later) |
|---|---|
| Channel posts, commits, Welcomes | **not protected** (MLS key schedule from X25519 HPKE; the outer seal derives from the MLS exporter) |
| Reveal payloads (§6.9) | not protected (X25519 HPKE) — consistent with PQ-R8 (cards travel on classical channels) |
| Relay credentials, namespaces | not confidential material against that adversary (the relay already sees them) |
| DMs (Phase 9) | protected at the seal layer (ADR-36), unchanged |

### 4.4 Triggers and the migration path

Adopt a hybrid suite when all hold: (1) the WG assigns final code points or OpenMLS declares a suite non-experimental; (2) the external review covers OpenMLS's hybrid HPKE path and GHOST's use; (3) S0-style probes show commits within the class floors at the class caps, or GHOST adds fragmentation (Phase 11's blob fragmentation is a candidate). Migration: the owner creates a new channel on the new suite ("incarnation"), members are invited with the invite flow of §6.2 (a new `channel_id`, hence new pseudonyms — the UI must say so), the old channel is left. The invite carries the suite (§5.9), so clients refuse a suite they do not support.

### 4.5 CP-10 wording

Forbidden for channels: "post-cuantic", "quantum", "PQ", any comparison implying DM-level protection. The Phase 13 copy states: "Mesajele din canale folosesc criptografie clasică (X25519); spre deosebire de mesajele directe, nu sunt protejate împotriva unui viitor calculator cuantic."

---

## 5. Channel model and data formats (normative)

### 5.1 Objects and identifiers

| Object | Definition | Who knows it |
|---|---|---|
| `channel_id` | 32 random bytes from the creator's CSPRNG (Rust); also the MLS `group_id` | members, invite holders, removed members |
| pseudonym seed `ps` | `HKDF-SHA256(ikm = root entropy, salt = ∅, info = "ghost/v1/channel-pseudonym" ‖ u8(32) ‖ channel_id, L = 32)` (`KeyDerivation.kt:24-30`; unchanged) | the member; derivable from the seed |
| pseudonym key `P` | Ed25519 public key of `ps` (RFC 8032); the leaf signature key and the `BasicCredential` identity | members |
| box key | `b_sk = clamp(HKDF(ps, ∅, "ghost/v1/ch/box-key", 32))`, X25519; `b_pk` published in the leaf (§5.4) | members |
| `op_id` | 16 random bytes per post, reaction or request (the spec's "client operation ID") | members |
| invite | §5.9; `invite_id` 16 random bytes; invite signing key from a 32-byte random seed | sponsor, invitee (secret); all members (the public key, via `INVITE_ISSUED`) |
| generation g | counter of generations; `G_g` its secret (§5.2) | members of any epoch of g |

### 5.2 Derivations (normative; labels are part of the compatibility contract)

`Exporter_e(label, context, L)` is `MlsGroup::export_secret` at epoch e (RFC 9420 §8.5). `HKDF(ikm, salt, info, L)` is HKDF-SHA256.

| Value | Derivation | Held by |
|---|---|---|
| epoch key `K_ep(e)` | `Exporter_e("ghost/v1/ch/epoch", channel_id, 32)` | members of epoch e |
| epoch recognition key `R_ep(e)` | `HKDF(K_ep(e), ∅, "ghost/v1/ch-recognition", 32)` | the same; Kotlin holds only this one (CS-S6) |
| generation secret `G_g` | `Exporter_{E_g}("ghost/v1/ch/generation", channel_id, 32)`, where `E_g` is the epoch whose commit opened generation g (epoch 0 for g = 0) | members of g; joiners get it in the bootstrap (§5.4) |
| namespace `ns_g` | `HKDF(G_g, ∅, "ghost/v1/ch/ns", 32)` | members of g, invite holders of g |
| read base `RB_g`, deposit base `DB_g` | `HKDF(G_g, ∅, "ghost/v1/ch/read-base", 32)`, `HKDF(G_g, ∅, "ghost/v1/ch/deposit-base", 32)` | the same |
| per-slot secrets `RS_{g,s}`, `DS_{g,s}` | `HKDF(RB_g, ∅, "ghost/v1/ch/read" ‖ u8(s), 32)`, `HKDF(DB_g, ∅, "ghost/v1/ch/deposit" ‖ u8(s), 32)` | the same |
| credentials | bearer credential v3 of F9 §4.3, unchanged: `3 ‖ kind ‖ u8(s) ‖ ns_g ‖ RS_{g,s}` (kind 0x01 read) and `… DS_{g,s}` (0x03 deposit); verifiers `SHA-256(label(kind) ‖ u8(s) ‖ ns_g ‖ secret)` | presented to relays |
| join key `JK_g`, recognition `R_join(g)` | `HKDF(G_g, ∅, "ghost/v1/ch/join-key", 32)`; `HKDF(JK_g, ∅, "ghost/v1/ch-recognition", 32)` | members of g, invite holders of g, members removed at the end of g |
| invite key | Ed25519 from `invite_seed` (32 random bytes in the invite) | invitee (secret), all members (public, via `INVITE_ISSUED`) |

**Rules.** (1) Every derivation takes a secret key input (an exporter output, `G_g`, `ps` or a random seed); none takes `channel_id`, a pseudonym key or a KeyPackage as its key input (T36; gate G-M3 is the static half, the F9 G-DM3 pattern). (2) The generation that follows a rotating commit is derived from **that commit's new epoch**, which a removed member cannot compute (RFC 9420: the path secrets are encrypted to the remaining members' nodes). (3) The invite carries `ns_g`, `RB_g`, `DB_g` and `JK_g`, never `G_g`. (4) Vectors: `protocol/test-vectors/ch_derive.txt`, replayed by Rust and by an independent JDK implementation (the F9 §15.2 practice).

### 5.3 The GHOST GroupContext extension 0xF0A1 `GhostChannelContext` (TLS presentation language, RFC 9420 §2.1)

```
struct {
    uint8   version;               // 1
    opaque  channel_id[32];        // equal to group_id
    uint8   size_class;            // 0 small: <= 32 members, floor 4 KiB; 1 large: <= 100 members, floor 16 KiB
    uint8   timer_code;            // the F9 §10.1 codes: 0 off, 1 5 min, 2 1 h, 3 1 d, 4 7 d (default), 5 30 d
    uint16  timer_version;         // +1 at every timer change
    uint8   history_policy;        // 0 = none (the only value in P0)
    uint8   flags;                 // bit 0: members may invite; bits 1-7 zero
    uint16  idle_evict_days;       // 35..365, default 63
    opaque  name<V>;               // UTF-8, 0..48 bytes (RFC 9420 §2.1.2 variable-length vectors)
    opaque  committers<V>;         // 1..8 pseudonym keys, 32 bytes each, distinct; rank = index; [0] = owner
    opaque  funders<V>;            // 0..3 pseudonym keys, 32 bytes each, a subset of the members
} GhostChannelContext;             // at most 446 bytes (varint length headers: 1 byte for name, 2 for the key lists)
```

- Extension type 0xF0A1 is in RFC 9420's private-use range (0xF000–0xFFFF). The group's `RequiredCapabilities` lists 0xF0A1 and 0xF0A2, so a KeyPackage that does not support them cannot be added (RFC 9420 §11.1).
- **Validity (checked by every member on every commit, after `process_message`, before any merge; §6.4 CO-2):** canonical encoding; every committer and funder key is the signature key of a current leaf after the commit; `history_policy = 0`; `timer_code ≤ 5`; `size_class ≤ 1` and the member count after the commit ≤ the class cap; reserved flag bits zero.
- **The generation number is not in the context.** It is a deterministic count every member keeps (§6.5) and joiners receive in the bootstrap; keeping it out means a rotation needs no GroupContextExtensions proposal and no extra bytes.

### 5.4 Leaf extension 0xF0A2 and GroupInfo extension 0xF0A3

```
struct { uint8 version; opaque box_pk[32]; } GhostLeaf;                        // 33 bytes, in every LeafNode
struct { uint8 version; uint32 generation; uint64 open_epoch; opaque G[32]; } GhostBootstrap;   // 45 bytes
```

- `GhostLeaf` is covered by the leaf signature (RFC 9420 §7.2). A leaf whose `box_pk` is a low-order or non-canonical X25519 point is refused (the F9 §22.8.2 rule).
- `GhostBootstrap` gives a joiner the current generation. It travels in the Welcome's encrypted GroupInfo through `CommitBuilder::create_group_info_with_extensions` (`om:src/group/mls_group/commit_builder.rs:569`) **if S0 confirms that these extensions reach the Welcome's GroupInfo (V10-8)**. Otherwise it travels next to the Welcome, HPKE-sealed to the joiner's `box_pk` (§5.6 WELCOME body); it must never be readable under `JK_g` alone, because members removed at the end of g hold `JK_g` (P-C4(b); mutant PC-11).

### 5.5 Channel content: the MLS application plaintext `ChannelContent` v1

```
ChannelContent = version(1) = 0x01 || kind(1) || op_id(16) || author_minute(u32_be) || timer_code(1) || tlv*
tlv            = type(u16_be) || len(u16_be) || value
```

- `author_minute`: whole minutes since 1970-01-01T00:00Z on the author's trusted clock (FR-3.4, T13); there is no finer time anywhere in the content.
- Canonical form: TLVs strictly ascending by type, no duplicates, only the TLVs listed for the kind, lengths within bounds, no trailing bytes; otherwise `NON_CANONICAL` and the post is dropped and counted.
- The spec's binding of "channel ID, epoch, content type and client operation ID" (spec §7.3): the channel and epoch are bound by MLS (group id and key schedule), the content type by `kind`, the operation id by `op_id`, all inside the encrypted content. GHOST puts nothing in MLS `authenticated_data` (which RFC 9420 §6.3 leaves in clear).

| kind | Name | TLVs | Notes |
|---|---|---|---|
| 0x01 | POST | 0x0001 `text` (1 … 16 000 bytes UTF-8), 0x0002 `reply_to` (16, optional), 0x0003 `media_ref` (reserved for Phase 11; refused in Phase 10) | replies are posts |
| 0x02 | REACTION | 0x0004 `target` (16), 0x0005 `grapheme` (0 … 32 bytes; empty withdraws) | one reaction per (author, target) |
| 0x03 | INVITE_ISSUED | 0x0010 `invite_id` (16), 0x0011 `invite_pk` (32), 0x0012 `expiry_day` (u32, days since 1970) | the sponsor's record (§6.2) |
| 0x04 | LEAVE | none | asks a committer to remove the author (§6.6) |
| 0x05 | REVEAL | 0x0020 `hpke_enc` (32), 0x0021 `ciphertext` (≤ 512) | §6.9 |
| 0x06 | FLAG | 0x0030 `target` (32, a pseudonym key), 0x0031 `reason` (u8) | **reserved** (ADR-13, P1); refused in Phase 10 (Q15) |
| 0x07 | PIN | — | reserved (FR-3.7, P2) |

- **Timer.** A receiver deletes a post after `min(its timer_code, the channel timer of the post's epoch)`, so a member cannot lengthen a post's life beyond the policy; the author encrypts with the current policy timer (encrypt-at-session, §6.3.1).
- **Size.** MLS adds about 146 bytes per application message with 0x0003 (measured, `mlsscale` run: 0 → 145, 100 → 246, 3 000 → 3 146 bytes). The longest text post (16 000 bytes) fits the 16 KiB bucket (capacity 16 316 bytes, §5.6); posts never need 64 KiB.

### 5.6 The outer seal (normative; the DM shape of F9 §6.2 with channel labels)

```
blob(B) = salt(16) || hint(16) || ChaCha20-Poly1305(k, nonce = 0^12, AD, P)       |P| = B − 48,  B ∈ {4096, 16384, 65536}
hint    = HMAC-SHA256(R, "ghost/v1/ch-hint" || mode(1) || salt)[0..16]
k       = HKDF-SHA256(ikm = K, salt = salt, info = "ghost/v1/ch-seal" || ns(32), L = 32)
AD      = "ghost/v1/ch-seal" || 0x01 || ns(32) || u32_be(B) || mode(1)                 (not transmitted)
P       = mode(1) || body_len(u24_be) || order(16) || body || zeros                    capacity C(B) = B − 68
order   = epoch(u64_be) || sender_leaf(u32_be) || seq(u32_be)      (mode 0x11; zeros in the other modes)
```

| mode | Key K (recognition R) | Body |
|---|---|---|
| 0x11 EPOCH | `K_ep(e)` (`R_ep(e)`) | an `MlsMessageOut` (PrivateMessage: application message or commit) |
| 0x12 JOIN | `JK_g` (`R_join(g)`) | `JoinRequest` (below) |
| 0x13 WELCOME | `JK_g` (`R_join(g)`) | `WelcomeBlob` (below) |

```
JoinRequest = version(1) = 1 || type(1) ∈ {0x01 join, 0x02 rejoin} || invite_id(16; zeros for rejoin)
            || kp_len(u16_be) || key_package (an MlsMessage carrying a KeyPackage, TLS)
            || invite_sig(64; zeros for rejoin)
invite_sig  = Ed25519(invite key, "ghost/v1/ch/join" || channel_id || invite_id || SHA-256(key_package))
WelcomeBlob = version(1) = 1 || kp_ref_len(u8) || kp_ref (the joiner's KeyPackageRef)
            || welcome_len(u24_be) || welcome (an MlsMessage carrying a Welcome, TLS)
            || boot_flag(1) || [ hpke_enc(32) || HPKE(box_pk(joiner), GhostBootstrap) (61) ]   // only if V10-8 fails
```

- **CS-S1 (T9).** `|blob| = B` exactly; every length is inside P; the bytes are uniform (salt random, hint a PRF output, key fresh per salt). **Channel blobs and DM blobs have the same shape**; a relay cannot tell them apart by bytes.
- **CS-S2 (canonical).** A known mode for the key class that matched, lengths within P, all padding zero; otherwise consumed, dropped and counted.
- **CS-S3 (binding).** `k` and `AD` bind the namespace and the bucket: a copy into another namespace or a truncation does not open (the relay store can hold one ciphertext under several namespaces, `relay/crates/storage/src/lib.rs:314-420`).
- **CS-S4 (nonce).** `k` is fresh per salt, so the zero nonce never repeats under one key.
- **CS-S5 (one attempt).** The receiver computes the hints of its candidate (R, mode) pairs and opens with the one that matches; a match whose AEAD fails is a forgery, dropped and counted. Candidates per channel: `R_ep(e)` with mode 0x11 for the current epoch and every retained epoch (≤ 65, §8.3), and `R_join(g)` with modes 0x12 and 0x13 for each listened generation (≤ 3). No trial decryption across keys (the partitioning-oracle argument of F9 R-S5).
- **CS-S6 (recognition vs opening).** Kotlin stores and matches recognition keys only; `K_ep`, `JK_g` and `G_g` are stored wrapped under the channel state key and handed to Rust with the blob.
- **CS-S7 (order is a hint).** `order` is authenticated by the seal but is the sender's claim; MLS authenticates the real sender and generation, and a mismatch drops the message and counts it. It serves peek ordering only (§6.3.3); it is visible only to holders of `K_ep(e)`, who learn the sender anyway on decryption.
- **Welcomes are "encrypted individually" (spec §7.3):** each joiner gets its own sealed copy (its own salt) of the commit's Welcome, whose group secrets are HPKE-encrypted to that joiner's KeyPackage by MLS.

### 5.7 Size classes and buckets (normative)

`bucket(len) = min{ B ∈ {4096, 16384, 65536} : B ≥ floor(class) ∧ C(B) ≥ len }`; a body larger than C(65536) = 65 468 bytes is refused (`NO_FIT`), which bounds every OpenMLS object GHOST accepts to one blob (and so bounds SRLabs S0-1, §6.2.4).

Measured object sizes, suite 0x0003, OpenMLS 0.9.0, bytes (research probe `mlsscale`, host, 2026-09-25; "sparse" = right after one batch add, "populated" = every parent node set):

| Object | 20 sparse | 20 populated | 100 sparse | 100 populated | Class and bucket |
|---|---|---|---|---|---|
| KeyPackage | 324 | 324 | 324 | 324 | 4 KiB (join request) |
| Remove 1 member (commit) | 2 076 | 1 010 | 8 706 | 1 244 | small: 4 KiB at ≤ 32 (≈ 3.1 KB interpolated, **S0 measures, V10-4**); large: 16 KiB |
| Self-update (commit) | 2 069 | 1 003 | 8 699 | 1 237 | as remove |
| Add 1 (commit) | 2 397 | 1 331 | 9 027 | 1 565 | as remove |
| Welcome for 1 joiner, tree included | 5 186 | 6 223 | 23 170 | 30 191 | 16 KiB (small), 64 KiB (large) |
| Batch add of N − 1: commit / Welcome | 6 802 / 7 905 | same | 33 034 / 38 049 | same | not used: GHOST caps adds per commit (§6.2.4) |
| Application message overhead | 145–146 | 145–146 | 145–146 | 145–146 | — |

- **Rule (normative):** a committer builds its commit, and if the commit's body exceeds `C(floor)`, it removes Add proposals from the end of the pass's list until it fits (they wait for the next pass); a commit without Adds that still exceeds the floor is a class violation that S0 must rule out at the class caps (V10-4: remove, self-update and a context change at 32 members in 4 KiB and at 100 members in 16 KiB). A commit received above the floor is invalid (CO-2).
- Consequence (P-C3): in a generation namespace every commit and every short post share the floor bucket, and only Welcomes and long posts use a larger one.

### 5.8 TTL per blob (normative; ADR-27 point 11, ADR-32, deviation X-7)

| Channel timer | off | 5 min | 1 h | 1 d | 7 d (default) | 30 d |
|---|---|---|---|---|---|---|
| Post TTL (mode 0x11 application) | 2 592 000 | 3 600 | 3 600 | 86 400 | 604 800 | 2 592 000 |
| Handshake TTL (commits, JOIN, WELCOME) | 2 592 000 | **604 800** | **604 800** | **604 800** | 604 800 | 2 592 000 |
| Op deadline | author + 7 d | author + 1 h | author + 1 h | author + 1 d | author + 7 d | author + 7 d |

- Posts follow ADR-27 point 11 exactly. The op deadline is ADR-32 point 3 (`author + min(bucket, 7 d)`); a handshake op's deadline is `author + 7 d`.
- **X-7.** In channels with timers ≤ 1 d, handshake blobs live 7 days so that a member offline longer than the timer can still catch up on membership (otherwise it could never rejoin in-band either); relays can tell those blobs from posts by their TTL there (LC-1). In channels with timers 7 d, 30 d or off, every blob uses one TTL (P-C3). The alternatives (whole channel at 7 d; handshake at the post TTL) are Q12's.
- A timer change moves the post TTL at the change: the first post under the new timer marks it at the relays (as DMs, F9 §11.2 "Expirare / schimbare timer").

### 5.9 Channel invite v1 (`ghost://channel/`; ADR-05's link and QR rules)

```
ChannelInviteV1 = version(1) = 0x01 || suite(u16_be) = 0x0003 || size_class(1) || handshake_ttl_code(1)
                || channel_id(32) || generation(u32_be) || ns(32) || read_base(32) || deposit_base(32) || join_key(32)
                || invite_id(16) || invite_seed(32) || expiry_day(u32_be) || name_len(1) || name(0..48)      // 222..270 bytes
link = "ghost://channel/" || base32(ChannelInviteV1), lowercase, unpadded                                     // ≤ 432 characters
```

- No web host, no identity key in clear, no payment address (T16's rules for invitations applied to channel invites); an invite is single-use (§6.2.4) and expires at `expiry_day ≤ issue day + 7`.
- The invite is a **bearer secret for one generation**: whoever holds it can list and store in `ns_g` and open join traffic until the generation rotates (L8-C4). QR in person is the recommended path; a link sent inside a GHOST DM is end-to-end encrypted (ADR-05's warning about other messengers applies).

---

## 6. Protocol and state machines (normative)

### 6.1 Channel creation (transaction `CH-CREATE`)

1. The creator's client draws `channel_id`, obtains `ps` from `:identity`, and calls `MlsNative.groupCreate` with the policy (`committers = [P]`, `funders = [P]`, timer 7 d unless chosen, class small, `members_may_invite = 1`, `idle_evict_days = 63`, name).
2. The call returns the change-set, `K_ep(0)`, `G_0` and the derived generation values; in one transaction Kotlin writes `ch_channel`, `ch_generation(0)`, `ch_epoch(0)`, the `mls_kv` rows, registers `ns_0` (`Namespaces.register(ns_0, CHANNEL, set(ns_0, w), listen = true, LOCAL)`), installs READ and DEPOSIT credentials for every relay slot of the set, marks `ns_0` funded (`Funding.set`, §7.5) and requests READ and DEPOSIT registrations for `{c, c + 1}` of the capability the planner will redeem (the F9 §4.8 `REGROWS` rule).
3. No traffic follows from the creation except the funder's redemptions and registrations (Q31's rule of F9: pending registrations count as write work, so the planner redeems as soon as an eligible token exists).

### 6.2 Invitation and admission

#### 6.2.1 Sponsor (`CH-INVITE`, a user action)

A member may invite if `members_may_invite = 1` or it is a committer. The client draws `invite_id` and `invite_seed`, builds the invite (§5.9) and, in the same transaction, encrypts and enqueues an `INVITE_ISSUED(invite_id, invite_pk, expiry_day)` post; the invite link is returned to the UI. The invite link stays in `ch_invite_own` (sponsor side) only until `expiry_day`, for the UI; every member, the sponsor included, records the `INVITE_ISSUED` in `ch_invite_issued`.

#### 6.2.2 Invitee (`CH-ACCEPT`, a user action)

1. Parse strictly; refuse an unknown suite (only 0x0003 in P0), an expired invite, a `channel_id` the client is already a member of (unless in `RESYNC_NEEDED` or `REINVITE_NEEDED`, where the invite serves a rejoin, §6.7).
2. Derive `ps` for `channel_id`; `MlsNative.keyPackage` creates a KeyPackage (day-aligned lifetime, `GhostLeaf`, the required capabilities) and returns its global change-set (the init and encryption private keys, wrapped).
3. In one transaction: `ch_channel(state = joining)`, `ch_join(invite_id, generation, expiry_day, kp_ref)`, register `ns_g` (listen, LOCAL) with READ and DEPOSIT credentials, and enqueue the `JoinRequest` sealed in mode 0x12 with the invite's handshake TTL and the floor of its class.
4. The invitee lists `ns_g` like any member; it opens only mode 0x12 and 0x13 blobs (it holds `R_join(g)` and no epoch key). At `expiry_day + 1` without a Welcome it deletes the join state and the KeyPackage and stops listening (`JOIN_EXPIRED`).

#### 6.2.3 Committer (`CH-PASS`, §6.4)

At a pass, for each pending join request of the current or a draining generation, in arrival order: check (§6.2.4); if valid, propose the Add by value; build the commit; seal one WELCOME blob per joiner in the namespace the request came from; enqueue commit and Welcomes in the pass transaction. Joiners are admitted when the commit settles (§6.4); a committer whose commit loses the tie-break keeps the admitted requests pending for its next pass.

#### 6.2.4 Admission checks (normative; bound SRLabs S0-1)

A join request is admitted only if: its `INVITE_ISSUED` was received from a member in an epoch the committer processed, is unexpired and was not consumed; `invite_sig` verifies under `invite_pk`; the KeyPackage parses, has suite 0x0003, a `BasicCredential` whose identity equals its 32-byte Ed25519 signature key, a lifetime whose bounds are whole UTC days and span ≤ 84 days, capabilities that include 0xF0A1 and 0xF0A2, **exactly one** leaf extension (`GhostLeaf`, valid `box_pk`), total size ≤ 1 024 bytes; its pseudonym is not a current member (a current member's pseudonym is a rejoin, §6.7); the member count after the commit stays within the class cap. A rejoin request is admitted only if its pseudonym **is** a current member in the committer's view. Consumed invites are marked (`ch_invite_issued.consumed`, kept until `expiry_day`); a second join request for the same invite is ignored. A committer admits at most the number of Adds that keeps the commit within the floor (§5.7). Because every object is bounded by one blob and KeyPackage size and extensions are checked, the "50 MiB extension" of S0-1 cannot enter a GHOST channel through an Add; a malicious **member** can still send large valid objects up to 64 KiB per blob (declared, L8-C11).

#### 6.2.5 Joiner (`CH-JOIN`, on a WELCOME blob)

The invitee (or rejoiner) opens a WELCOME blob with `JK_g`, matches `kp_ref`, runs `MlsNative.welcomeJoin` (OpenMLS `StagedWelcome` → group), verifies `GhostChannelContext` and the bootstrap, derives `K_ep(e)` and the generation values, and in one transaction writes the group rows, `ch_channel(state = active, joined_epoch = e)`, the generation rows, re-registers namespaces if the bootstrap names a newer generation, and deletes the join state. No traffic results (T40): the joiner's first store is its user's first post or its scheduled self-update.

### 6.3 Posting and receiving

#### 6.3.1 Compose and encrypt-at-session (`CH-POST`)

A post is encrypted **only when the channel is current**: the client has, in the present session, completed one listing pass over every relay of the current generation's set and processed every openable blob of its current epoch. Otherwise, and whenever the client holds its own unsettled commit (OpenMLS refuses messages while a commit is pending, `om:src/group/mls_group/mod.rs:1115-1121`), the post waits as plaintext in `ch_pending_post` (under the content key, the F9 §13.8 pattern) and is encrypted and enqueued in the first transaction where the channel is current. Consequences: posts are almost always encrypted in the epoch their receivers hold, so late posts come only from store delays, not from offline composition; the store minute of a post composed offline depends on the session's catch-up time (declared in LC-7). A pending post that reaches its op deadline without being encrypted fails (`FAILED`, the user may retry).

The post's op: namespace `ns_g` of the current generation, bucket by §5.7, TTL by §5.8, deadline `author + min(bucket, 7 d)`, relays `set(ns_g, week(now))`, the Phase 7 send delay (`SendDelay.OFF` refused for `Consumer.CHANNEL`, as for DMs).

#### 6.3.2 Receive (`CH-RECV`)

The messaging actor drains `Consumer.CHANNEL` like `Consumer.DM` (the listener and the consumer tail are the existing single slots, wired to the one actor, D16). Per channel it `peek`s the fetched rows of its namespaces and classifies each blob by the hint that matches (CS-S5):

| Opened as | Action |
|---|---|
| no match | if some candidate could still appear (a future epoch of this channel, or a Welcome for a pending join): `Inbox.defer(60 s … 6 h, backing off)`; at the blob's relay expiry: consume and drop (`unopenable`, counted) |
| 0x11, epoch = current | application message: decrypt in peek order (§6.3.3), apply content, mark consumed; commit: validation run (§6.4 CO-2), record as candidate, mark consumed |
| 0x11, epoch < current, retained | application message: decrypt with the past epoch (late post); commit: fork check (§6.7) |
| 0x11, epoch older than retention | impossible (no key); falls under "no match" |
| 0x12 | committers: record a pending join or rejoin request; others: consume, ignore |
| 0x13 | joiners: §6.2.5; others: consume, ignore |

#### 6.3.3 Peek ordering (the F9 §7.7 idea for MLS)

Within an epoch, OpenMLS decrypts a sender's application messages out of order within the sender ratchet's tolerance (16). Blobs are fetched in blob-hash order (Phase 7), so a burst of more than 16 posts from one sender could be decrypted out of range. GHOST therefore decrypts the openable application messages of an epoch sorted by `order = (epoch, sender_leaf, seq)` from the seal (CS-S7) and holds a gap (a missing `seq` of a sender) for at most 12 minutes before decrypting past it (F9's measured hold). A lying `order` only misorders the liar's own messages.

#### 6.3.4 Dedup and replay (normative; the four layers)

1. Phase 7 `(namespace, hash)` tombstones (IN-2).
2. MLS: a replayed PrivateMessage fails decryption once its generation key was used (RFC 9420 §9.2 deletion schedule); a resurrected commit of a finalized epoch has the hash already merged and is ignored; a commit of an older epoch without a retained key does not open.
3. The seal binds namespace and bucket (CS-S3): a copy into another namespace, including after a namespace is removed and re-added or a relay re-added (F7:47-52), does not open.
4. `ch_seen(op_id)`: an `op_id` already displayed is dropped (a re-encryption after FAILED keeps its `op_id`), retained as `dm_seen` (F9 §7.6) with the channel's bucket.

#### 6.3.5 Bounds (CS-C8)

Past epochs ≤ 64 and ≤ the retention of §8.3; commit candidates ≤ 8 per epoch (the best 8 by the CO-3 key); pending join and rejoin requests ≤ 64 per channel, each until its invite's expiry; pending posts ≤ 256 per channel; peek limit 128 per pass; `ch_seen` rows bounded by retention.

#### 6.3.6 Declared losses (CS-C5)

A post is lost for a member when: its blob expired at the relays before the member listed it (offline beyond the TTL); its epoch's keys were deleted before it arrived (a store delayed beyond §8.3's retention); its sender lost the tie-break of a fork and posted on the losing branch (§6.7); it is a pending post that reached its deadline; or the member rejoined (posts of the epochs it missed on the losing branch or while `RESYNC_NEEDED` are not recovered).

### 6.4 Commit arbitration (normative; ADR-42)

- **CO-1 (who may commit).** A commit is a candidate only if its sender is a member. Rank = the sender's index in `committers` (0 … 7) or 255 otherwise. A rank-255 commit is valid only if it covers **no proposal** (an empty commit with a path: a self-update). External commits (sender type `new_member_commit`) are dropped before processing.
- **CO-2 (validity, checked on a validation run whose change-set is discarded).** OpenMLS accepts it; its body fits `C(floor)`; every Add passes §6.2.4 (the committer's checks, repeated by every member); a Remove by rank r targets only non-committers or committers of rank > r; a GroupContextExtensions change comes from rank 0, except that any committer may drop from `committers` and `funders` the keys its commit removes; the resulting `GhostChannelContext` is valid (§5.3).
- **CO-3 (winner).** Among the valid candidates for epoch e, the winner minimises `(rank, SHA-256(MLS commit bytes))`.
- **CO-4 (settle).** A member merges the winner when `now ≥ first_seen(e) + 20 min`, where `first_seen(e)` is the minute it first recorded any candidate for e. For its **own** commit the committer also requires a verified copy (the op's outcome is SENT or DEGRADED); if another candidate wins, it clears its pending commit (`clear_pending_commit`) and merges the winner; if its op ends FAILED (no copy can exist), it clears the pending commit; while the op is INDETERMINATE it keeps the commit pending (Phase 7 resends the identical bytes at most twice) and clears it when the op closes without a verified copy — if a copy did reach some members, they merged it and the committer is alone on a losing branch, which CO-6 detects.
- **CO-5 (merge).** The settle transaction (`CH-SETTLE`, time-triggered, local) re-processes the winner with persistence and merges it (`merge_staged_commit` or `merge_pending_commit`), derives `K_ep(e + 1)`, rotates the generation when §6.5 says so, records `ch_epoch(e + 1, winner hash, epoch_authenticator)`, and deletes the other candidates. Epoch e is then **final** at this member.
- **CO-6 (fork evidence).** A valid commit for a final epoch with a different hash is recorded as `fork_evidence(e, better)`, where `better` means its CO-3 key is lower than the merged one's (§6.7).
- **CO-7 (pass preconditions).** A committer runs a pass only when the channel is current (§6.3.1), it holds no candidate for its current epoch, and it holds no pending commit.
- **CO-8 (pass schedule; D9).** Rank 0 runs a pass at its own membership or policy actions (immediately, a user action), at each foreground session after catch-up plus U[0, 5 min] at most once per 6 h, and in a background job at most once per 24 h; the pass commits **if work is pending** (join and rejoin requests, leave requests, evictions due, a queued removal or policy change, a class change), and otherwise only if the committer's last commit is ≥ 7 days old (the PCS commit, empty with a path). A committer of rank r ≥ 1 runs passes only while no commit by a lower rank has been merged in the last `r × 48 h`.
- **CO-9 (self-updates).** A member of rank 255 commits an empty self-update once every 28 days, at the first session after its PRF slot (`HMAC(K_sched, channel_id ‖ u32(period))`, `K_sched` from the MESSAGING branch), and again at the next session after 24 h if it lost the tie-break.
- **CO-10 (bounded concurrency).** Concurrent commits arise only between a returning higher rank and an acting lower rank, or between self-updates; all are resolved by CO-3 when the candidates meet within the settle window, and otherwise detected by CO-6.

**Why a settle window and finality, not revert.** Reverting a merged epoch would re-decide posts already displayed and posts already encrypted under it; the settle window costs ≤ 20 minutes per membership change. RFC 9750 §5.2.2 describes exactly this option ("pause … to see if any other Commits are received for the same epoch … a deterministic tie-breaking policy"). A partition longer than the window, or relays that serve different commits to different members (possible under AD-1; a delivery service can always partition MLS), produces a fork, which CO-6 detects and §6.7 repairs.

### 6.5 Generations and rotation (normative; ADR-41)

- **Rotation rule.** A merged commit opens generation g + 1 iff it removes a pseudonym that it does not re-add (Remove, leave, eviction; a rejoin swap re-adds and does not rotate) or changes `size_class`. Every member computes it; joiners learn `(g, G_g, E_g)` from the bootstrap.
- **At the merge (`CH-SETTLE`):** derive `G_{g+1}` from the new epoch; register `ns_{g+1}` with its relay set, install its READ and DEPOSIT credentials for every slot, set `ch_generation(g + 1, current)` and `ch_generation(g, draining, drain_until_day = today + 14)`. New posts and commits go to `ns_{g+1}`; ops already enqueued for `ns_g` complete there.
- **Funding at a rotation:** the member whose commit rotated funds `ns_{g+1}` for the current week (it acted; no reflex) and the listed funders from their next renewal (§7.4). Until a registration lands, stores to `ns_{g+1}` wait (`wait_capability`) and complete when it does; if the rotating committer has no eligible token, the new generation waits up to a week for a funder's renewal (declared, L8-C6).
- **Drain.** Members list `ns_g` until `drain_until_day` (14 days: the 7-day store window plus 2σ of Phase 7's 3-day clock tolerance, rounded up), then `Namespaces.remove(ns_g)` and delete `G_g`, `JK_g` and the generation's credentials. Funders stop renewing `ns_g`; its registrations lapse at `start(w + 2) + 1 h` (F9 §4.4).
- **What a removed member keeps.** The old generation's namespace and secrets: it can list `ns_g` during the drain and see the volume of stale posts (whose content it could read anyway: they are of epochs it belonged to) and of join traffic addressed to `ns_g`. It holds nothing of `ns_{g+1}` (P-C4(b)).

### 6.6 Leave, remove, idle eviction

- **Leave** (`CH-LEAVE`, user): enqueue a `LEAVE` post, set `state = leaving`, stop posting; when the op resolves (any outcome), delete the MLS state, stop listening, keep local posts until their timers. A committer removes the leaver at its next pass (a leave request is pending work).
- **Remove** (committer, user action): an immediate pass with the Remove proposals (and the `committers`/`funders` update when needed); the removed member, on merging the commit, sees itself removed (OpenMLS marks the group inactive), sets `state = removed`, deletes the MLS state and stops listening.
- **Idle eviction.** A committer keeps, per member, the day of the member's last leaf refresh (join, rejoin, own self-update or own commit), `ch_member_refresh(channel, pseudonym, day)`; a member idle longer than `idle_evict_days` (default 63 = 2 × 28 + 7) is removed at the next pass (RFC 9420 §16.6 "Applications SHOULD have mechanisms for evicting group members that are offline for too long"; RFC 9750 §8.2.2). The evicted member may return through a new invite.

### 6.7 Resync and fork recovery (FR-3.2; TM S3)

| Situation | Detection | Recovery |
|---|---|---|
| Restart | none needed | state is persisted atomically (CS-C1) |
| Missed commits still on relays | blobs that do not open are deferred; the next epoch's commit arrives | replay in epoch order: at each epoch, posts then the winning commit, settled by CO-4 (all candidates are already present, so settling is immediate after the window) |
| Missed commits past their TTL | no blob opens for 72 h while ≥ 3 blobs from ≥ 2 operators arrived in a listened namespace | `RESYNC_NEEDED` (shown to the user) |
| Fork, this member lost | `fork_evidence(e, better = true)` | `RESYNC_NEEDED` |
| Fork, this member won | `fork_evidence(e, better = false)` | none: the other side rejoins |
| Rejoin not answered within 14 days, or the generation drained | no Welcome | `REINVITE_NEEDED`: any member's new invite admits the pseudonym as a rejoin (§6.2.4) |

**Rejoin (`CH-REJOIN`, a user action or the user's next action in the channel; never a reflex).** Create a fresh KeyPackage for the same pseudonym; enqueue a `JoinRequest(type = rejoin)` sealed in mode 0x12, one copy in each generation namespace the member listens to (current and draining; a fork at a rotating commit leaves the two sides with different new generations, and only the older one is shared); keep the old state until a Welcome arrives. A committer admits it with `swap_members` (the old leaf removed and the new KeyPackage added in one commit; no rotation). On the Welcome, the member replaces its MLS state (deleting the old rows), keeps its displayed posts, adopts the bootstrap's generation and resumes. OpenMLS's `fork-resolution` helpers are not needed: the committer's swap is ordinary `MlsGroup` API.

**What stays open (declared).** A member on the losing branch loses its posts of that branch for the others; a committer on the losing branch (a backup that committed while partitioned) rejoins like any member; members removed at the end of generation g, who hold `JK_g`, see that a rejoin happened in `ns_g` and the rejoiner's KeyPackage (its pseudonym) during the drain (L8-C5).

### 6.8 PCS and self-updates

Committers update their leaf with every commit: an Add-only commit needs no path in RFC 9420 §12.4 (OpenMLS includes one only when a proposal requires it, `om:src/group/mls_group/membership.rs` doc of `add_members`), so GHOST builds every commit with `CommitBuilder::force_self_update(true)` (`commit_builder.rs:287`); S0 measures the size cost (V10-4). Committers therefore refresh at least every 7 days, members every 28 days (CO-9). A member whose device was compromised and then recovered heals at its next self-update or rejoin; a removed member's state heals nothing for it (it is out). The 28-day cadence is Q9.

### 6.9 Reveal (`CH-REVEAL`, a user action; ADR-04, LIMITE:135)

1. The user chooses a member M. The client builds `RevealPayload = version(1) = 1 ‖ channel_id(32) ‖ P_author(32) ‖ P_M(32) ‖ minute(u32) ‖ card_v2(131) ‖ sig_id(64) ‖ sig_ps(64)` (360 bytes), where `sig_id` is the `ghost1` identity key's Ed25519 signature over `"ghost/v1/ch/reveal-id" ‖ channel_id ‖ P_author ‖ P_M ‖ minute` (made in Rust with the DM context's identity key, the ADR-35 X-21 rule), and `sig_ps` the pseudonym key's signature over `"ghost/v1/ch/reveal-ps" ‖ channel_id ‖ SHA-256(card_v2) ‖ P_M ‖ minute`.
2. HPKE (RFC 9180) base mode, KEM 0x0020 (DHKEM X25519, HKDF-SHA256), KDF 0x0001, AEAD 0x0003 (ChaCha20-Poly1305), through the provider's `hpke_seal` (the HPKE code MLS already uses), `info = "ghost/v1/ch/reveal" ‖ channel_id`, `aad = op_id`, to `box_pk(M)`; the result goes in a `REVEAL` post.
3. Every member tries its own box key on each `REVEAL` (one HPKE open per reveal post); M verifies both signatures, `P_M` = its own key and `P_author` = the post's MLS sender, and offers "add contact" through `Messaging.addContact(card, CardSource.CHANNEL_REVEAL, …)` (trust `unverified`).
4. **What members learn:** the author revealed to someone. **What M learns and keeps forever:** the author's DM card and the proof that the pseudonym belongs to that identity (L8-C8, the L7-D25 residue in a new form). Nothing crosses the channel otherwise (TB-7).

### 6.10 Governance primitives delivered in Phase 10 (D17)

| Primitive | Phase 10 | Later |
|---|---|---|
| Roles (owner, moderators = committers), policy object | yes (§5.3, CO-1, CO-2) | UX in Phase 13 |
| Remove, leave, idle eviction | yes (§6.6) | — |
| Sponsor attribution | yes: `ch_sponsor(member, sponsor, invite_id, day)` from `INVITE_ISSUED` and the admitting commit | strikes (P1) |
| Threshold function and the S5 simulation | yes: `threshold(n_active, policy)` as a pure function (ADR-13: `max(N, fraction)`, age weighting, sponsor-subtree diversity) and a simulation of Sybil brigades over it (TM S5) | wiring to real flags (Phase 13) |
| Flags, quarantine, strikes, exclusion lists, verified channels | reserved formats only (kind 0x06) | Phase 13 with ADR-13's UX (Q15) |

### 6.11 State machines (each has a JVM test of every legal and illegal transition)

| Machine | States | Driven by |
|---|---|---|
| Channel (member view) | joining → active → {leaving → left, removed, resync_needed → active (rejoin) or reinvite_needed → active}; joining → join_expired | CH-ACCEPT, CH-JOIN, CH-SETTLE, CH-LEAVE, CH-REJOIN, SWEEP |
| Epoch | open → candidates → final | CH-RECV, CH-PASS, CH-SETTLE |
| Own commit | pending → merged / cleared (lost or FAILED) | CH-PASS, CH-SETTLE, OUTCOME |
| Generation | current → draining → removed | CH-SETTLE (rotation), SWEEP |
| Post (outgoing) | pending_plaintext → queued → sent / degraded / failed / indeterminate; failed → queued (user retry) | CH-POST, OUTCOME, SWEEP |
| Post (incoming) | unread → read → deleted | CH-RECV, DISPLAY, SWEEP |
| Join request (committer) | pending → admitted (commit merged) / ignored (expired, consumed, invalid) | CH-RECV, CH-PASS, CH-SETTLE |
| Invite (sponsor) | issued → expired | CH-INVITE, SWEEP |
| Registration | the F9 §13.5 machine, for funded namespaces | work lane |

### 6.12 Device revocation, restore, wipe (C-6; LIMITE:39)

- **Restore from seed.** Channel state is not backed up (T4), so a restored client has no channel. A member's new invite readmits it: its pseudonym (derived from the `channel_id` in the invite) is a current member, so the committer swaps its leaf; the lost device's leaf is gone and **the lost device decrypts no later epoch** (the LIMITE:39 test, in SCN-M20).
- **Stolen device.** The thief holds the seed-derived pseudonym key and can rejoin as the member; a committer cannot tell the thief from the owner. Real exclusion is: the owner asks a committer out of band to remove the pseudonym (a rotation) and returns with a new identity (ADR-14's "identitate nouă" after compromise). Declared, L8-C9.
- **Wipe.** Deletes every channel row, `mls_kv` and `mls_global_kv`; no traffic; the pseudonym is evicted after 63 days.

---

## 7. Relay, sync and entitlement integration

### 7.1 Namespaces (normative)

| Namespace | Registered by | `Namespaces.register` | Read | Write |
|---|---|---|---|---|
| current `ns_g` | every member at join and rotation | `(ns_g, CHANNEL, set(ns_g, w), listen = true, LOCAL)`; funders also `Funding.set(ns_g, true)` | READ credential of the relay's slot | DEPOSIT credential of the relay's slot |
| draining `ns_{g−1}` | every member | listening until `drain_until_day`, then `remove` | READ | DEPOSIT, only for ops already enqueued |
| invite `ns_g` (invitee) | the invitee at accept | `(ns_g, CHANNEL, set(ns_g, w), listen = true, LOCAL)` | READ | DEPOSIT (its join request) |

### 7.2 Relay sets

`set(ns, w)` is F9 §5.2's public keyed permutation of the week's ES slots (≥ 2 operators, 3 relays, the 6-week union after a slot-table change), used unchanged for channel namespaces (its HMAC label names DM, but the function takes any namespace; the same vectors apply).

### 7.3 Credentials: Phase 9's relay features, unchanged

READ (`list`, `get`, `check`) and DEPOSIT (`store`, `check`) bearer credentials v3, their verifiers, `RegisterKey` with the `{cap_week, cap_week + 1}` rule, accumulation, `keys.redb` and the deposit ledger (F9 §4.2–§4.6) serve channels without change. `get` with a READ credential returns `uploaded_at` floored to the ISO week and the exact expiry (`relay/crates/node/src/lib.rs:463-469`), which the unread deadline needs. **No new RPC, kind, field or observable** (§7.8).

### 7.4 Funding and token accounting (normative)

- **Who funds.** The policy's `funders` (default: the owner; up to 3). A funder, for every relay r of `set(ns_g, w)`, keeps READ and DEPOSIT registration rows for `week(now)` and `{c, c + 1}` of its usable **registration capability** of week c (F9 §4.8's `REGROWS` rule, generalised to funded namespaces). Registration capabilities are redeemed by the Phase 8 planner at the EXPIRING renewal time (a PRF time in the last 23 h of the week) and, when a registration is pending without one, as soon as an eligible token exists (F9 Q31). They are stored apart from store credentials (`relay_register_capability`, §9) and used **only** by the registration step (mutant PC-10).
- **Tokens.** One ACCESS token per (relay of the set, funded namespace, week) per funder: **3 tokens per week per channel per funder**, plus 3 for the rotating committer at each rotation it performs. A pack gives 16 per slot per week and DMs take ≤ 2 (F9 §4.8), so a funder has ≤ 14 channel-weeks per slot per week (Q7). Members that are not funders spend **0** on channels.
- **Offline tolerance.** A funder online in week w registers `{w, w + 1}`; registrations live until `start(w + 2) + 1 h`, so deposits keep working for about two to three weeks after a funder's last renewal (F9 §21.2). Beyond that, stores wait in `wait_capability` and end at their deadlines (L8-C6).
- **Quota.** Every registration credits its capability's quota (256 MiB per week); any member (or invite holder) can exhaust it; the remedy is Remove and rotation (L8-C7).

### 7.5 `:sync` additions (normative; X-8)

```kotlin
/** A namespace this client funds: the planner redeems registration capabilities for it; stores and reads keep using bearer credentials. */
interface Funding {
    fun set(tx: SyncTransaction, namespace: NamespaceId, funded: Boolean)
    fun isFunded(tx: SyncTransaction, namespace: NamespaceId): Boolean
}
```

1. **`Funding`** and table `sync_namespace_fund`; `Capabilities.needed()` reports a `REGISTER` need (a new `CapabilityKind.REGISTER`) for a funded namespace with a pending registration row and no usable registration capability; the planner treats it like WRITE MISSING (redeem as soon as eligible).
2. **`relay_register_capability`** holds redeemed capabilities of funded namespaces; the registration step uses it (else, for Phase 9's owner namespaces, the write capability as today); store, list, get and check never read it.
3. **`SendDelay.OFF` refused for `Consumer.CHANNEL`** (a v6 trigger, the `sync_namespace_dm_delay_*` pattern).
4. No change to the listener and consumer-tail slots: the one messaging actor serves both consumers.
5. `Inbox.defer` is used for unopenable channel blobs (F7's "an MLS message for a future epoch"); deferred rows do not count against `FETCHED_CAP` (`InboxStore.kt:156-165`).

### 7.6 `:entitlement` changes

The planner handles `REGISTER` needs as WRITE needs of a REDEEM namespace (the Q29 redeem hold arms for them); NI-K stays identical (its worlds have no channels). The T2 world (Phase 8) gains channel funders (§7.9).

### 7.7 When channel traffic happens (normative; T19, T40)

| Relay-visible event | Trigger | Timing |
|---|---|---|
| list, get | Phase 7 schedule per (relay, namespace) | T19, independent of activity |
| store of a post, reaction, reveal, `INVITE_ISSUED`, `LEAVE` | user action | at the first session where the channel is current, then STANDARD immediately or HIGH after U[0, 10 min] |
| store of a join or rejoin request | user action | as a post |
| store of a commit and its Welcomes | committer pass or committer user action | CO-8 |
| store of a self-update | PRF slot every 28 days | CO-9 |
| check | Phase 7 verification of own copies | Phase 7 |
| redeem, register | funder renewal (PRF, last 23 h of the week); rotating committer at its own merge | F8 §12.4, §6.5 |
| **anything, because a blob arrived** | **never** | T40 |

Declared: LC-6 (a pass commits only when work is pending), the self-update retry after a lost tie-break (CO-9), and the catch-up-dependent store minute of posts composed offline (LC-7). **NFR-2** (p95 < 8 s): not met by design with the 30-second listing interval (the same reason as NFR-1, LIMITE L2.1 #5); measured in Phase 12 (Q21). **Read pairs:** each channel costs 3 pairs, 6 while a generation drains; with `maxReadPairs = 64` (`TrafficPolicy.kt:50`), DMs and drops, **12 channels** per client keep every pair on its own schedule; beyond that pairs share events and latency grows (the P0 limit, Q4).

### 7.8 Observables (T1)

No change to `allowed-observables.json` v2. Channel traffic uses `store` (hash, bucket, `ttl_bucket_seconds`, minute, the DEPOSIT `capability_scope`), `list`/`get`/`check` (the READ scope), and the funders' `redeem` and `register` (`key_kind` read or deposit). A new observable would be a privacy decision (INV:66); none is needed.

### 7.9 T2 world and gate (as F9 §4.9)

`t2-exit-gate` gains funders: world clients that own a channel fund it at the renewal time and at rotations they commit; the population line gains `channel_funded_namespaces`; the export is unchanged (no relay table is added). NI-1, NI-2, NI-3 and NI-K are unchanged in rule: no issuer input reaches channel events. **Dependency:** the nightly sweep of the T2 gate has never been green (NI-1d pairs 2 and 3, NI-1 across cells on pair 9; F9 §22.24, §22.28); Phase 10 adds no new failure mode but cannot make T2 green.

---

## 8. Ephemeral posts and the history policy

### 8.1 Timer, TTL, deadlines

The channel timer is `GhostChannelContext.timer_code` (set by the owner; default 7 d, ADR-27 point 7); a change is a GroupContextExtensions commit from rank 0 that every member processes and the UI shows ("the timer is itself a message shown to everyone", ADR-27 point 8). TTLs and deadlines: §5.8.

### 8.2 Countdown and deletion (ADR-32 points 4–7, applied to posts)

- The author's countdown starts at the commit of the `CH-POST` transaction that encrypted the post; a reader's at first display (`markDisplayed`).
- An unread post is deleted at `min(relay expiry E, consume + bucket + 1 h)`, E from `InboundBlob.relayExpiryHour`; deadlines only move earlier; the expiry clock never runs backwards.
- The cascade deletes, in one transaction: the post row, its reactions, its `ch_pending_post` row, the notification content, and every quote rendering (replies keep their own text; a `reply_to` that no longer resolves renders as expired); then `wal_checkpoint(TRUNCATE)` with `busy = 0` checked (the F9 `Checkpoint.truncate()`).
- Sweeps run where DM sweeps run (open, foreground sessions, the consumer tail, the in-process timer, the one inexact alarm of ADR-32); every channel read query filters expired rows (the F9 `DmExpiredRowLint` extended to `ch_*`).

### 8.3 Epoch-secret retention (the second meaning of "history policy"; spec §7.3, TM:83)

- Past epoch secrets (OpenMLS) and epoch keys `K_ep(e)` (GHOST) are kept until `final_day(e + 1) + R`, with `R = min(2 d, 2 × post_bucket + 1 h)` rounded up to whole days (1 d for 5 min, 1 h and 1 d channels; 2 d otherwise), and never more than 64 past epochs (`max_past_epochs(64)`). SWEEP calls `delete_past_epoch_secrets(PastEpochDeletion::before_timestamp(day))` with a Kotlin-supplied day (§3.6).
- Why short: posts are encrypted at session (§6.3.1), so a post of epoch e reaches the relays within the send delay unless a relay outage delays its store; a longer retention only widens what a seized device decrypts (AD-8: relay-retained ciphertext of retained epochs, including posts the device never fetched; L8-C10).
- Generation secrets live while the generation is current or draining (§6.5).

### 8.4 History policy "none" (FR-3.8; D11)

A joiner holds no key of an epoch before its join epoch, so it opens no earlier post or commit (P-C5); it can list the namespace and see earlier blobs' timing and volume (metadata only, L8-C3). The policy byte is 0; values 1 and 2 are reserved and refused until an ADR defines a history transfer.

### 8.5 T25 for channels (cases; the EP suite of F9 §15.5 over channels)

Every timer × {displayed, unread with honest E, unread with short E, pending plaintext, post of a removed member, post on a losing fork branch, post arriving after its deadline}; a timer change mid-conversation (older posts keep their own timer, clamped by §5.5); a clock step back; a busy reader during checkpoint; the physical scan of the database and the WAL for a plaintext canary after expiry; T1 on the relay capture: the TTL is the bucket of §5.8 and nothing finer.

---

## 9. Storage schema: migrations 6 and 7 (normative)

`CURRENT_VERSION` is 5 (`Schema.kt:120`). Phase 10 adds **migration 6** (the `:sync` half, slice S1) and **migration 7** (the channel tables, slice S3), each one transaction, append-only and fail-closed, following the v4/v5 split of F9 §13.6: explicit column lists, `typeof` CHECKs on integer columns, write-once and state-machine triggers, REPLACE guards (`replaceGuard`, `Schema.kt:1255-1258`), every time column `*_minute`, `*_hour` or `*_day` with its CHECK (T20, T33), no FTS (G-DM6 extended), no counters per channel, no activity times except the committer's refresh days (§6.6, declared L8-C12).

**Migration 6 (`:sync`).**

| Object | Definition |
|---|---|
| `sync_namespace_fund` | `namespace_id BLOB PRIMARY KEY REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE`, `WITHOUT ROWID`: presence = this client funds the namespace (§7.5). A side table because `sync_namespace.capability_source` has a frozen CHECK (`'redeem', 'local'`, `Schema.kt:852-853`) that SQLite cannot alter without rebuilding a referenced table |
| `relay_register_capability` | `(relay_id, namespace_id)` primary key, `token` (1..512 bytes), `expires_hour` (`% 3600 = 0`), `state IN ('usable','rejected','exhausted')`, `generation ≥ 1`; cascades from `relay_directory` and `sync_namespace`; `WITHOUT ROWID`; the `relay_capability` columns of v2 verbatim |
| triggers `sync_namespace_channel_delay_{insert,update}` | refuse `send_delay = 'off'` for `consumer = 'channel'` (the v4 DM triggers' text) |

**Migration 7 (channels).** Step 0: a guard table with `CHECK (row_count = 0)` fed by `count(*)` of each v1 table `channels`, `channel_pseudonyms`, `mls_state`, `posts` (no production code writes them: `ChannelPseudonymRepository` (`Repositories.kt:43-62`) has no caller outside tests, and its rows need a `channels` row that nothing writes; the guard fails closed if any row exists anyway; S3 deletes the repository and its tests), then `DROP INDEX idx_posts_channel` and the four `DROP TABLE`s. `media` and `media_blobs` stay for Phase 11. Step 1: the tables below. Secret-bearing columns are `*_env` (wrapped under the channel state key, §10.4); plaintext content columns are wrapped under the content key (F9 §13.8).

| Table | Key columns (all others NOT NULL unless marked) | Time columns | Notes |
|---|---|---|---|
| `ch_channel` | `channel_id` (32) PK; `state` ∈ {joining, active, leaving, left, removed, resync_needed, reinvite_needed, join_expired}; `suite` = 3; `generation`; `epoch`; `joined_epoch`; `size_class` ∈ {0,1}; `timer_code` 0..5; `my_pseudonym` (32); `name_env` NULL | `stale_since_minute` NULL | the MLS state is in `mls_kv`, not here |
| `ch_generation` | (`channel_id`, `generation`) PK; `namespace_id` (32) UNIQUE; `state` ∈ {current, draining}; `g_env`, `jk_env`; `r_join` (32, a recognition key) | `drain_until_day` NULL | at most one `current` per channel (trigger) |
| `ch_epoch` | (`channel_id`, `epoch`) PK; `state` ∈ {open, final}; `k_env`; `r_ep` (32); `winner_hash` (32) NULL; `own_seq` ≥ 0 (the `seq` of §5.6 for own posts) | `first_seen_minute` NULL, `final_day` NULL, `keep_until_day` NULL | ≤ 65 rows per channel (trigger) |
| `ch_candidate` | (`channel_id`, `epoch`, `hash`) PK; `rank` 0..255; `own` 0/1; `body_env` | — | ≤ 8 per epoch |
| `mls_kv` | (`channel_id`, `k`) PK; `v_env` | — | `WITHOUT ROWID`; written only from change-sets |
| `mls_global_kv` | `k` PK; `v_env`; `channel_id` (32), the channel the row was written for (§3.4) | `delete_after_day` NULL | KeyPackage and key-pair rows; deleted with the channel or by day |
| `ch_post` | `op_id` (16) PK; `channel_id`; `direction` ∈ {out, in}; `author` (32); `kind` ∈ {1, 2}; `reply_to` (16) NULL; `timer_code`; `epoch`; `body_env`; `state` ∈ {queued, sent, degraded, failed, indeterminate, unread, read} | `author_minute` (`% 60 = 0`), `displayed_minute` NULL, `delete_at_minute` NULL, `relay_expiry_hour` NULL | the expiry filter in every read query |
| `ch_reaction` | (`target`, `author`) PK; `channel_id`; `grapheme_env` | — | cascades from `ch_post` |
| `ch_pending_post` | `op_id` PK; `channel_id`; `kind`; `content_env` | `fail_after_hour` | encrypt-at-session queue (§6.3.1) |
| `ch_outbound_op` | `operation_id` PK; `channel_id`; `purpose` ∈ {post, commit, welcome, join, rejoin, request}; `ref` NULL | — | maps Phase 7 ops to channel objects |
| `ch_join` | `channel_id` PK; `type` ∈ {join, rejoin}; `invite_id` (16) NULL; `generation`; `kp_ref` | `expiry_day` | invitee or rejoiner side |
| `ch_join_request` | (`channel_id`, `hash`) PK; `generation`; `type`; `invite_id` NULL; `body_env` | `until_day` | committer side; ≤ 64 per channel |
| `ch_invite_issued` | (`channel_id`, `invite_id`) PK; `invite_pk` (32); `sponsor` (32); `consumed` 0/1 | `expiry_day` | from `INVITE_ISSUED` posts |
| `ch_invite_own` | `invite_id` PK; `channel_id`; `invite_env` | `expiry_day` | the sponsor's link, for the UI |
| `ch_sponsor` | (`channel_id`, `member`) PK; `sponsor`; `invite_id` | `admitted_day` | ADR-13 attribution |
| `ch_member_refresh` | (`channel_id`, `member`) PK | `refresh_day` | committers only (§6.6) |
| `ch_request` | (`channel_id`, `kind`, `subject`) PK; `kind` ∈ {leave, remove, policy, class} ; `payload_env` NULL | `until_day` | a committer's pending work |
| `ch_schedule` | `channel_id` PK | `next_selfupdate_day`, `last_own_commit_day` NULL, `next_pass_minute` NULL | CO-8, CO-9 |
| `ch_seen` | (`channel_id`, `tag`) PK, `tag` = `HMAC(local key, op_id)[0..16]` | `until_day` | `WITHOUT ROWID`; the `dm_seen` pattern |
| `ch_reveal` | (`channel_id`, `direction`, `peer`) PK | `minute` | the card goes to `dm_contact` through `addContact` |

`expectedTables` and `expectedTriggers` gain the new names and lose the four v1 tables; `DmSchemaIntrospectionTest`'s rule (every time column checked, no virtual table) extends to `ch_*` and `mls_*` (`ChannelSchemaIntrospectionTest`).

---

## 10. Modules, the closed JNI surface, the facade (normative)

### 10.1 Module layout

| Module / package | Contents | Depends on |
|---|---|---|
| `client-core/mls` (Rust, `ghost-client-mls`; new) | `GhostKv` (§3.4), `PseudonymSigner`, the channel operations over `MlsGroup`, the seal (§5.6), derivations (§5.2), `ChannelContent`, invite and join codecs, the reveal HPKE, result codes, the JNI export behind `jni-bridge`; no network, async runtime, logger or clock; `rayon` pinned to one worker | `openmls`, `openmls_traits`, `openmls_libcrux_crypto`, `ed25519-dalek` 2.2.0, `hkdf`, `hmac`, `sha2`, `chacha20poly1305`, `serde_json`, `zeroize`; `ghost-client-dm` (identity signing for reveals, the card) |
| `client-core/net` | `ghost_client_mls::export_jni!()` beside the DM export (`net/src/jni_bridge.rs:63` pattern) | `ghost-client-mls` |
| `client-core/dm-host` (`ghost-dm-host`) | also exports `MlsNative` (with a `test-vectors` entry), so JVM tests load one host library | `ghost-client-mls` |
| `:crypto-bridge` `org.ghost.crypto.bridge` | `MlsNative` (§10.2), `MlsResult`, `ChannelCrypto` (typed facade), `ChannelRecognition` (hint matching with recognition keys), `ChannelInvite` codec wrapper | `libghost_client_net.so`; `:sync` API |
| `:messaging` `…messaging.channel.engine` | the transactions of §10.4 run by the **messaging actor** (the DM actor, renamed in code comments only), `ChannelPeekOrder`, `CommitArbiter` (CO rules), `Generations`, `Funders`, `ChannelSweeper`, the channel consumer steps | `:crypto-bridge`, `:sync`, `:identity` |
| `…messaging.channel.store` | DAOs over `ch_*`, `mls_*` (every read applies the expiry filter) | `:storage`, `:sync` API |
| `…messaging.api` | `Channels` facade (§10.3), value types with redacted `toString` | — |
| `:storage` | migrations 6 and 7 | — |
| `:sync` | §7.5 | — |
| `:entitlement` | §7.6 | `:sync` |
| `:app` | wiring: the actor already holds the listener and the tail; the invite deep link `ghost://channel/` is Phase 13 UI | all |

Rules: `:messaging` and `:crypto-bridge` reference no network class and no coroutine (G-DM1 extended); only `:crypto-bridge` references `MlsNative` (G-M6); typed catches only (`sync-no-catch-all.sh` scope); no protocol logic in Kotlin beyond orchestration (ADR-19): parsing, sealing, derivations and every MLS operation are native.

### 10.2 `MlsNative`: the closed list (gate G-M6)

All functions are `static native`, take byte arrays and ints, return `code(1) ‖ TLV fields`, perform no I/O, read no clock (a `day` or `minute` input is supplied by Kotlin), log nothing, and run under `catch_unwind` with the silent panic hook (`INTERNAL`). `rows` is the TLV array of wrapped `mls_kv`/`mls_global_kv` rows of §3.4; every state-changing function returns a change-set.

| # | Function | Main outputs | Codes besides `OK` |
|---|---|---|---|
| 1 | `ctxOpen(stateKey32)`, `ctxClose(h)` | handle | `CRYPTO_UNAVAILABLE` |
| 2 | `channelOpen(h, channelId, pseudonymSeed32)`, `channelClose(h, channelId)` | P, `box_pk` (Kotlin compares P with `:identity`'s value) | `INVALID_KEY` |
| 3 | `groupCreate(h, channelId, policy, day)` | change-set, `K_ep(0)` env, `R_ep(0)`, `G_0` env, generation values (fn 13) | `INVALID_POLICY` |
| 4 | `keyPackage(h, channelId, day)` | KeyPackage bytes, `kp_ref`, global change-set | — |
| 5 | `welcomeJoin(h, channelId, rows, welcomeBlobBody, day)` | change-set, context fields, roster, epoch, `K_ep` env, bootstrap (g, `G_g` env) | `NOT_FOR_ME`, `INVALID_WELCOME`, `INVALID_POLICY`, `STATE_CORRUPT` |
| 6 | `receive(h, channelId, rows, epoch, mlsBytes, day)` | `APP`: content, sender P, change-set; `COMMIT`: a validation summary (sender rank inputs, adds, removes, context change, size, hash, the staged `epoch_authenticator`), **no change-set** | `INVALID_COMMIT(reason)`, `UNDECRYPTABLE`, `WRONG_EPOCH`, `NON_CANONICAL`, `STATE_CORRUPT` |
| 7 | `settle(h, channelId, rows, winnerBytes or OWN, day)` | change-set, new epoch, `K_ep` env, `R_ep`, rotation flag and, if set, `G_{g+1}` env and generation values, roster diff, `epoch_authenticator` | `INVALID_COMMIT`, `STATE_CORRUPT` |
| 8 | `clearOwn(h, channelId, rows)` | change-set | `STATE_CORRUPT` |
| 9 | `commit(h, channelId, rows, adds[kp], removes[P], swaps[(P, kp)], contextUpdate?, selfUpdateOnly, floor, day)` | commit bytes, Welcome bytes, joiners' `kp_ref`s, bootstrap handling, the Adds kept (§5.7 rule), change-set (pending commit) | `NO_FIT`, `INVALID_KEYPACKAGE(index)`, `INVALID_POLICY` |
| 10 | `encrypt(h, channelId, rows, content, seq, day)` (`seq` = `ch_epoch.own_seq`, incremented in the same transaction) | MLS bytes, `sender_leaf`, change-set | `PENDING_COMMIT`, `STATE_CORRUPT` |
| 11 | `seal(h, keyEnv, keyClass, ns, bucket, mode, order, body)` | blob | `NO_FIT` |
| 12 | `open(h, keyEnv, keyClass, ns, mode, blob)` | order, body | `NOT_OPEN`, `NON_CANONICAL` |
| 13 | `generation(h, gEnv, slots[])` | `ns`, per-slot READ and DEPOSIT credentials v3 and verifiers, `JK` env, `R_join` | — |
| 14 | `inviteBuild(h, channelId, gEnv, invite fields)`, `inviteParse(bytes)` | invite bytes and `INVITE_ISSUED` fields / parsed fields | `NON_CANONICAL`, `UNSUPPORTED_SUITE` |
| 15 | `joinRequest(h, invite, kp)`, `joinVerify(h, invitePk, channelId, body)` | body / KeyPackage and `kp_ref` | `BAD_SIGNATURE`, `INVALID_KEYPACKAGE` |
| 16 | `revealSeal(h, dmHandle, channelId, recipientP, recipientBoxPk, minute, opId)`, `revealOpen(h, channelId, enc, ct, opId, senderP)` | TLV values / verified card and bindings | `NOT_OPEN`, `BAD_SIGNATURE` |
| 17 | `contentEncode`, `contentDecode` | canonical `ChannelContent` | `NON_CANONICAL` |
| 18 | `roster(h, channelId, rows)` | members (P, leaf, `box_pk`), epoch, `epoch_authenticator`, tree hash | `STATE_CORRUPT` |
| 19 | `sweepPast(h, channelId, rows, beforeDay)` | change-set | `STATE_CORRUPT` |

`MlsResultCodesTest` enumerates the codes; G-M7 includes a compile-time exhaustive `match` over OpenMLS's error enums used, so a variant added at a bump fails the build (F9 G-R7(d)).

### 10.3 `Channels` facade for Phase 13 (normative signatures)

```kotlin
interface Channels {
    fun create(name: String, timer: Timer, sizeClass: SizeClass): CreateResult              // CREATED | LIMIT_REACHED | NO_REPLICAS | CRYPTO_UNAVAILABLE
    fun createInvite(channel: ChannelId, expiryDays: Int): InviteResult                    // link + QR bytes | NOT_ALLOWED | LIMIT_REACHED
    fun acceptInvite(link: ByteArray): AcceptResult                                        // PENDING | INVALID | EXPIRED | UNSUPPORTED_SUITE | ALREADY_MEMBER | LIMIT_REACHED
    fun channels(): List<ChannelView>                                                      // id, name, state, role, member count; no times
    fun posts(channel: ChannelId, limit: Int, before: PostCursor?): List<PostView>
    fun post(channel: ChannelId, text: String, replyTo: PostId?): PostResult               // QUEUED | TOO_LARGE | NOT_MEMBER | STORAGE_FULL | CRYPTO_UNAVAILABLE
    fun react(target: PostId, grapheme: String?): PostResult
    fun markDisplayed(ids: List<PostId>)
    fun members(channel: ChannelId): List<MemberView>                                     // pseudonym fingerprint, role, sponsor; no times
    fun remove(channel: ChannelId, member: PseudonymId): Result                            // committers only
    fun leave(channel: ChannelId): Result
    fun setPolicy(channel: ChannelId, change: PolicyChange): Result                        // owner: timer, name, moderators, funders, class, invites
    fun reveal(channel: ChannelId, member: PseudonymId): Result                            // after the Phase 13 warning
    fun resync(channel: ChannelId): Result                                                 // rejoin request
    fun hide(post: PostId); fun mute(channel: ChannelId, muted: Boolean)                   // FR-3.6: local only
    fun status(): ChannelStatus                                                            // counts only
    fun setListener(listener: ChannelListener?)                                            // content-free change hints
}
```

Every method posts to the messaging actor and returns after its transaction commits; none performs network I/O.

### 10.4 Transactions (normative inventory; each is one SQLCipher transaction, change-sets applied only on OK)

| Name | Trigger | Writes |
|---|---|---|
| `CH-CREATE` | user | channel, generation 0, epoch 0, `mls_kv`, namespace, credentials, funding, registrations |
| `CH-INVITE` | user | `ch_invite_own`, `INVITE_ISSUED` post and op |
| `CH-ACCEPT` | user | `ch_channel(joining)`, `ch_join`, `mls_global_kv`, namespace, credentials, join op |
| `CH-JOIN` | a WELCOME blob | group rows, channel, generation, epoch; deletes join state |
| `CH-POST` | user or the channel becoming current | post row, op; or `ch_pending_post` |
| `CH-RECV` | a claimed blob (one per blob, in peek order) | post or reaction rows, `mls_kv` change-set for application messages, candidates, join requests, invite records, reveal records, fork evidence; `markConsumed` or `defer` |
| `CH-PASS` | CO-8, CO-9, a committer's user action | pending commit (`mls_kv`), commit and Welcome ops, `ch_candidate(own)` |
| `CH-SETTLE` | time (first_seen + 20 min), outcome of own commit | merge, epoch rows, rotation, namespaces, credentials, funding, sponsor and refresh rows |
| `CH-REJOIN` | user | KeyPackage rows, `ch_join(rejoin)`, rejoin op |
| `CH-REVEAL` | user | reveal post and op, `ch_reveal` |
| `CH-LEAVE` | user | `LEAVE` post and op, state |
| `CH-OUTCOME` | Phase 7 outcomes | post states, own-commit bookkeeping |
| `CH-SWEEP` | the ADR-32 sweep points | expired posts, epochs past retention (`sweepPast`), drained generations, expired joins, invites, requests, seen tags; checkpoint |

**State key.** `mls_state_key`: 32 random bytes created at the first channel use, wrapped by a non-exportable Keystore key with the database key's authentication policy (the F9 §2.5 `session_state_key` pattern; one key for all channels), held in native memory while unlocked (L7-D19 extended). A restore creates a new one (channel state is lost anyway).

---

## 11. Invariants (new T36–T41; changes to existing ones)

### 11.1 New invariants (Romanian rows for INVARIANTS.md in Appendix B.1)

| ID | Invariant | Verification | Executable from |
|---|---|---|---|
| **T36** | Channel blindness at relays: no relay-visible value is computable from `channel_id`, pseudonym or box keys, KeyPackages, invite ids or MLS headers without a generation, epoch or invite secret; every channel blob is a §5.6 seal; no MLS header byte outside it | derivation vectors; G-M3 (static); JC-1 (every relay-visible value of the world recomputed from public material: 0 matches), JC-2 (header scan of every stored blob for group id, epoch, KeyPackageRef, pseudonym keys: 0); PC-1, PC-7, PC-13 | Phase 10 (S2, S10) |
| **T37** | One scope per kind and uniform shape: every store into a generation namespace at a relay presents that (relay, namespace)'s DEPOSIT credential, every list/get its READ credential, registration capabilities appear only in `register`; in channels with timer 7 d, 30 d or off, every blob has the channel TTL, and every commit has the floor bucket | JC-3, JC-4; NI-CH2; PC-3, PC-4, PC-8, PC-10 | Phase 10 (S10) |
| **T38** | Removal: nothing a removed member held (retained epoch and generation secrets, credentials, KeyPackage keys) opens a blob of an epoch after the removing commit, and it holds no secret of any later generation | the removed-member seizure oracle over every later blob; PC-2, MM-7, MM-8 | Phase 10 (S6, S10) |
| **T39** | Joiner history "none": nothing a joiner holds opens a blob of an epoch before its join epoch | the joiner oracle; PC-2 | Phase 10 (S4, S10) |
| **T40** | No reflex in channels: two worlds that differ only in what a client received give identical relay views of that client (stores, redeems, registrations, list schedule, session close times), except LC-6 | NI-CH1 (valid, forged, replayed, join request, commit, rejoin request); G-M5 (static: the enqueue, register and redeem call sites); PC-5, PC-6 | Phase 10 (S5, S11) |
| **T41** | Convergence: members that hold the same valid candidates for epoch e when they settle it merge the same commit, and equal `epoch_authenticator`s follow at every epoch; a member on a losing branch reaches `resync_needed` or `reinvite_needed`, never silent divergence | EM-3; SCN-M20 and its FORK variant; `oracle_epoch`; MM-2, MM-3, MM-4, MM-16 | Phase 10 (S5, S7) |

### 11.2 Changes to existing invariants

| ID | Change |
|---|---|
| T1 | no schema change; channel traffic fixtures added to `privacy-capture.sh` (stores with deposit scopes of channel shape, registrations by funders) |
| T3 | canaries extended: pseudonym seeds, box keys, `G_g`, `K_ep`, `JK_g`, invite seeds, KeyPackage private keys, post text, channel names; G-M4 over the MLS graph |
| T9 | channels: bucket = §5.7 (floor by class, never by type), bytes uniform (CS-S1) |
| T13 | channels: `author_minute` in `ChannelContent`; KeyPackage lifetimes day-aligned |
| T14 | unchanged (vectors); the "no rotation on re-join" reading of ADR-04 is recorded (X-4) |
| T20 | the new time columns of migrations 6 and 7 join the introspection sets |
| T21 | unchanged: channel namespaces use their circuit; registration capabilities pass through the existing matrix |
| T25 | extended to channels: the §8.5 cases |
| T28, T31 | T28's wording covers DMs; T40 is its channel twin. T31 already allows reading "canalele"; an invitee reads the invite's namespace until expiry |
| T33 | extended: channel tables; OpenMLS state holds no sub-day time (day rewrite, day-aligned lifetimes), verified by a state scan over every stored `mls_kv` value (ME-C-series mutants) |

---

## 12. Test plan and exit-gate argument

**Lessons from Phase 9 built in (testing research §2).** L-1: counts (seeds, mutants) are pinned only after S0 measures the cost, and a mutant is registered only once its killer exists. L-2: CI restoration (the artifact quota, a KVM runner) is an S0 precondition, not a late slice. L-3: the runner budget is 4 runners on one laptop; gate jobs run nightly and on dispatch. L-4: exact joins and twins carry the privacy proof; statistics over a saturated LC attacker prove nothing, so Phase 10 has none. L-5: every property needs a mutant that can falsify it.

### 12.1 Infrastructure: `ChannelWorld`

- **Clients:** 2–24 per world (60 in the privacy world), each a real `:messaging` + `:crypto-bridge` + `:sync` stack on its own SQLite file (production pragmas, WAL and DELETE journal modes), migrated to v7, driven by the Phase 7 `DeterministicDriver`, sharing the DM harness through the shared-test-source pattern of F9 §15.1.
- **Real OpenMLS** through `MlsNative` loading `ghost-dm-host` (which now links `ghost-client-mls`). **Determinism:** the host build's `getrandom` custom backend (F9 §22.8.10 point 7) drives the provider's `SysRng` seeding and `hpke-rs-libcrux`'s ChaCha20 seeding, and `rayon` runs one worker; **S0 check V10-6** requires two runs of a scripted world to produce byte-identical commits, Welcomes and blob hashes, or the harness records and replays native outputs instead.
- **`ModelRelay`** (conformance-pinned by `relay_semantics.txt` and `register.txt`) with the Phase 7 and 9 hostile modes plus: **FORK** (serves different same-epoch commits to two subsets), **WITHHOLD_COMMIT** (hides one commit from a subset for a chosen time), **REORDER_ACROSS_EPOCH** (application messages after the next commit), **RESURRECT_COMMIT**, **DROP_WELCOME**, **EXPIRE_LOG** (drops handshake blobs before an offline member returns), **FLOOD_SELFUPDATE** (a member's modified client floods rank-255 commits), **COPY_JOIN** (a join request copied to another namespace).
- **Faults:** `FaultySqlExecutor` at every statement, pre- and post-commit, `SQLITE_FULL` injection; `SimulatedNativeCrash` inside `receive`, `settle`, `commit` and `welcomeJoin`; a virtual clock with steps.
- **Oracles:** `oracle_epoch(client, epoch, winner_hash, epoch_authenticator, tree_hash)`; `oracle_displayed(client, op_id)` with a primary key; the **reload oracle** (§3.4 point 6); `oracle_seizure(removed client)` and `oracle_joiner(client)` (§12.8); `oracle_traffic(client, store | redeem | register, cause)` written by every facade call and every scheduled step, so NI-CH1 and G-M5 can map every relay-visible act to a non-inbound cause.

### 12.2 Unit, vector, property and interoperability tests

- **Rust (`cargo test -p ghost-client-mls`, `rust` job):** derivation vectors `ch_derive.txt`; seal vectors `ch_seal.txt` (every mode and bucket, hints, copy and truncation refused); `ch_content.txt`, `ch_invite.txt`, `ch_join.txt`; `GhostKvScopeTest` (all 72 storage methods mapped); the day rewrite (golden `MessageSecrets`); change-set atomicity (a call that fails after partial writes returns nothing); `rayon` single worker; the admission checks of §6.2.4 (each refusal); CO-2 validity (each rule); property tests with 10⁶ seeded inputs per CI run for every GHOST parser (never panics, never over-reads).
- **Kotlin (`android` job):** an independent JDK implementation replays `ch_derive.txt`, `ch_seal.txt` (outer layer and hints), `ch_content.txt` and `ch_invite.txt`; `MlsResult` exhaustiveness; migrations 6 and 7 (introspection, triggers, guards, REPLACE refusals); the `Funding` planner rule; the credential selection (a registration capability never reaches store, list or get).
- **RFC 9420 interoperability fixtures (spec Appendix A).** (1) The MLS WG test vectors (`mlswg/mls-implementations`, `test-vectors/`: `passive-client-welcome`, `passive-client-handling-commit`, `passive-client-random`, `tree-validation`, `treekem`, `message-protection`, `welcome`, `deserialization` and the others) run by OpenMLS's own KAT tests at the pinned tag in `mls-vendor-tests`. (2) GHOST replays the three passive-client files **through `GhostKv` and the value-semantics call sequence** and must reproduce every `epoch_authenticator` (this proves the adapter preserves RFC semantics). The vector files are committed with their SHA-256 and upstream commit. (3) An optional differential peer (mls-rs, test-only; Q22).

### 12.3 EM-3: the exhaustive commit-arbitration model (the F9 EM-1 method)

An abstract model of CO-1 … CO-10 and §6.5–§6.7 in Rust, enumerated exhaustively: 2 committers (ranks 0 and 1), 2 members, epochs ≤ 4, message loss, duplication and reordering, a partition of either side for a chosen interval, settle timers, process death at every step, one removal and one rejoin. Properties: **convergence** (T41 when no partition exceeds the window); **detection** (every partitioned run ends with each losing member in `resync_needed` or `reinvite_needed`); **no invalid merge** (no rank-255 commit with proposals, no removal of a lower rank); **liveness** (with rank 0 online and no partition, every pending request is committed within two passes); **rotation** (a removal always yields a generation the removed member cannot name). Mutants MM-2, MM-3, MM-4 and MM-16 must fail EM-3. Nightly job `channel-state-models`.

### 12.4 Crash enumeration (CS-C1, CS-C2; the F7 §8.3 method)

| Scenario | Content |
|---|---|
| **SCN-CA** create and admit | create; invite; accept; join request; the committer's pass; Welcome; join |
| **SCN-CB** posts | 3 members, 30 posts with SHUFFLE and REPEATS across 3 relays, a burst of 40 from one sender (peek ordering), a RESURRECTed post, a COPY_NAMESPACE'd post |
| **SCN-CC** membership | an add and a remove in one pass, settle, rotation, the new generation's funding and registrations, drain |
| **SCN-CD** concurrency | ranks 0 and 1 commit on one epoch; a rank-255 self-update on the same epoch; the loser clears and re-passes |
| **SCN-CE** offline | a member offline across 5 epochs and one rotation, then catch-up in order; a variant with EXPIRE_LOG → `resync_needed` → rejoin |
| **SCN-CF** ephemeral | 5 min, 1 h and 7 d channels; displayed, unread, pending; a timer change; a clock step back |
| **SCN-CG** fork | FORK mode splits members; both sides settle; fork evidence; the losing side rejoins; the winning side unaffected |
| **SCN-CH** faults | `SQLITE_FULL` at every statement of RECV, PASS, SETTLE; `SimulatedNativeCrash` in `receive` and `settle` (poison rules of F9 §7.8) |
| **SCN-CI** migration | a v5 database with live DM and sync rows → v6 → v7, then SCN-CA |
| **SCN-CJ** reveal | a reveal to one member; others open nothing; the recipient adds the contact |
| **SCN-CK** leave and evict | a leave, an eviction at 63 days, a restore-and-rejoin swap |

After every reboot: `integrity_check`, `foreign_key_check`, every trigger present; at most one current generation per channel; ≤ 8 candidates per epoch; `mls_kv` rows open under the state key; the reload oracle; every `queued` post has an op or a pending row; epoch keys exist for exactly the retained epochs. At quiescence: CS-C2, CS-C3, CS-C6, T40 (every store maps to a non-inbound cause), liveness (one more post decrypts everywhere).

### 12.5 The exit scenario SCN-M20 ("20 clienți add/remove/resync")

**Setup:** 20 clients; 3 relays over 2 operators (one per scenario variant hostile); both privacy modes; channel timer 7 d (a 1 h variant for the T25 clause); rank 0 = client 1, rank 1 = client 2; funders = clients 1 and 2.

**Script (virtual time ≈ 80 days, so that the 63-day eviction and a 30-day offline window fit):** client 1 creates the channel and invites 19 clients over three days (invites by link; batches bounded by the floor); ≈ 200 posts with reactions and replies; **removals:** a moderator removal, a leave, an idle eviction (a client silent 63 days — time is virtual), and a **device swap** (client 7 "restores": a new stack with the same seed rejoins through a new invite; its old stack keeps its state and is a seizure subject); two clients offline across ≥ 5 epochs and one rotation, then **resync** from the relays; one client offline past EXPIRE_LOG, which reaches `resync_needed` and rejoins; ranks 0 and 1 commit concurrently on one epoch (CO-3); a **FORK** variant in which the model relays serve two commits to two subsets for longer than the settle window, detected and repaired by rejoin; a removed client re-invited, returning with the same pseudonym (D12).

**Assertions:** at every epoch, every honest current member's `(winner_hash, epoch_authenticator)` is equal (T41); no duplicate display, one order everywhere; **the removed-member oracle opens 0** blobs of later epochs for each removed client and for the old stack of client 7 (the plan's second clause, LIMITE:39); the joiner oracle opens 0 for each joiner; T9 and T13 on every blob and post; the channel T25 cases pass (the plan's third clause); T37 and T40 on the world's relay view.

**Scale:** every PR runs SCN-M20 with one seed and crash singles on SCN-CA … SCN-CD; `channel-exit-gate` runs it with seeds pinned after S0 (target: 64, the number Phase 9's gate actually ran) and the full crash enumeration.

### 12.6 Functional suites

| Suite | Cases |
|---|---|
| **RO-C reorder** | all orders of 6 posts of one sender; bursts of 40 over 3 relays with HIGH delays; posts after the next commit (REORDER_ACROSS_EPOCH) within and beyond retention |
| **RS-C restart** | process death at every lane item and actor step; a member offline 60 days in a 30-day channel |
| **RP-C replay** | each dedup layer isolated (§6.3.4); a resurrected commit; a copied join request |
| **JN join** | every admission refusal of §6.2.4; single use; expiry; a join during a rotation (Welcome in the draining namespace); a rejoin by a current pseudonym; an invite for a channel already joined |
| **GV governance** | CO-2 rules (removal of a lower rank refused, context change by rank 1 refused); moderator list changes; the S5 simulation over the threshold function |
| **FD funding** | renewal at the PRF time; rotation funding by the rotating committer; a funder without tokens (stores wait, then complete); registrations lapsing after the drain |
| **FK fork** | FORK at a rotation (two generation secrets): recovery through the old generation during the drain |
| **EP-C ephemeral** | §8.5 |
| **RV reveal** | recipient-only opening; binding checks; a forged reveal (wrong pseudonym) refused |

### 12.7 The channel privacy world

A world of 60 clients, 12 channels (5–20 members), invites, removals and rotations, DMs present, modes STANDARD and HIGH; PR scale 28 virtual days, one seed; gate scale 56 days, seeds pinned after S0. Exact searches over the effective relay view (every capture event, stored bytes, `keys.redb`, circuits):

| ID | Search | Expected |
|---|---|---|
| JC-1 | every relay-visible value recomputed from public material (channel ids known to members, pseudonym and box keys, KeyPackages, invite ids) | 0 matches |
| JC-2 | stored blob bytes scanned for group ids, epochs, KeyPackageRefs, pseudonym keys, `ChannelContent` headers | 0 |
| JC-3 | distinct store scopes and read scopes per (relay, generation namespace) | exactly 1 and 1; registration capabilities only in `register` |
| JC-4 | per generation namespace in 7-day channels: distinct TTLs, and buckets of commits vs posts ≤ the floor | 1 TTL; commits only in the floor bucket |
| JC-5 | a removed member's credentials or secrets accepted in a later generation's namespace | 0 |
| JC-6 | the relay-visible time of any store equals, within the send-delay rules, the time of a non-inbound cause in `oracle_traffic` | all |
| NI-CH1 | twins differing only in what one client received (valid post, forged blob, replay, a join request addressed to it as committer, a commit, a rejoin request) | identical views of that client, except LC-6's pass outcome |
| NI-CH2 | twins where a committer stores a commit vs a post of equal length at the same minute | identical views |
| NI-CH3 | twins where a funder funds 1 vs 4 channels at fixed renewal times | identical per-namespace views; the count of funded namespaces is declared (LC-3) |

### 12.8 Seizure, removal and joiner oracles

- **Removed-member oracle (T38):** dump the removed client's database, WAL, `mls_kv` and native context; try every stored 32-byte value, every retained `K_ep` and `JK_g`, every past-epoch secret (through `MlsGroup::load` of its stale state and `process_message`) and every KeyPackage key against every mode-0x11 blob of every epoch after its removal and every blob of every later generation (the join traffic of the draining generation, which it may open by design, L8-C5, excepted). Opened must be 0. Variants: removed while offline; removed while its own commit was pending; re-added (the epochs between removal and re-add open 0).
- **Joiner oracle (T39):** the same over all blobs of epochs before the join epoch.
- **Device seizure (AD-8, declared bounds):** a current member's dump opens exactly the epochs within retention (§8.3), and no expired post's plaintext remains (T25 physical scan).

### 12.9 Mutants (registered only with their killer; counts pinned after S0)

| ID | Mutation | Killer |
|---|---|---|
| MM-1 | change-set applied before OK (partial state) | SCN-CH, reload oracle |
| MM-2 | own commit merged without a verified copy | EM-3, SCN-CD |
| MM-3 | no settle window | EM-3, SCN-M20 FORK |
| MM-4 | tie-break by hash only | EM-3 |
| MM-5 | rank-255 commit with proposals accepted | GV, EM-3 |
| MM-6 | context change from rank ≥ 1 accepted | GV |
| MM-7 | no rotation on removal | T38 oracle, JC-5 |
| MM-8 | next generation derived from the pre-commit epoch | T38 oracle |
| MM-9 | past epochs kept beyond retention | seizure bound test |
| MM-10 | posts encrypted at compose while not current | RO-C (late posts lost beyond retention) |
| MM-11 | hash-order decryption (no peek ordering) | SCN-CB burst |
| MM-12 | unopenable blobs dropped instead of deferred | SCN-CE |
| MM-13 | invite single-use not enforced | JN |
| MM-14 | `invite_sig` not verified | JN (sock-puppet case) |
| MM-15 | KeyPackage checks skipped (extra leaf extension, oversized) | JN |
| MM-16 | fork evidence not recorded | SCN-CG, EM-3 |
| MM-17 | eviction ignores self-updates | CK |
| MM-18 | rejoin rotates the generation | FD, SCN-CK |
| PC-1 | raw MLS stored (no seal) | JC-2 |
| PC-2 | one seal key per channel instead of per epoch | joiner oracle, T38 oracle |
| PC-3 | bucket by type | JC-4, NI-CH2 |
| PC-4 | members store with token-bought capabilities | JC-3 |
| PC-5 | a committer's pass triggered by a received request | NI-CH1, JC-6 |
| PC-6 | a non-rotating funder redeems at the merge of a received rotation | NI-CH1 |
| PC-7 | namespace derived from `channel_id` | JC-1 |
| PC-8 | commit TTL ≠ post TTL in a 7-day channel | JC-4 |
| PC-9 | reveal names its recipient in content | RV |
| PC-10 | registration capability used for list or store | JC-3 |
| PC-11 | bootstrap readable under `JK_g` | T38 oracle (join-traffic variant) |
| PC-12 | second-level time in content or lifetimes | T13, T33 scan |
| PC-13 | `order` outside the AEAD | JC-2 |
| ME-C1 | reactions not cascaded | EP-C |
| ME-C2 | unread deadline from content, not relay expiry | EP-C |
| ME-C3 | no checkpoint after a cascade | T25 physical scan |
| ME-C4 | `added_at` day rewrite skipped | T33 state scan |

### 12.10 Fuzzing

`mls-fuzz` (nightly, dated pinned nightly toolchain, `client-core/mls/fuzz` outside the workspace with its own lock checked by cargo-deny; the `dm-fuzz` arrangement): targets `open` (every mode), `contentDecode`, `inviteParse`, `joinVerify`, `receive` on arbitrary MLS bytes after a valid seal (the pre-authentication decoders of GHSA-rrmv and GHSA-w62v, reachable only by seal-key holders), `welcomeJoin`. OpenMLS's own decode targets run at the pinned tag in `mls-vendor-tests`.

### 12.11 Emulator and devices

`dm-emulator.yml` gains a channel smoke test: the release variant loads `libghost_client_net.so`, creates a channel, admits a second in-process client, exchanges posts, removes it; the host/Android equivalence test (F9 §15.9) gains deterministic MLS cases. **It has never run on the runner (no KVM; STATUS:18)**; the local Windows emulator run of F9 §22.32 is the fallback. A device checklist step (2 devices, one channel, add, post, remove, rejoin) joins F9 §15.10 and stays manual.

### 12.12 The exit-gate argument, and what it does not prove

| Claim | JVM (every PR and nightly) | Emulator | Devices | Staging / external |
|---|---|---|---|---|
| add, remove, resync with 20 clients | SCN-M20, EM-3, crash enumeration | smoke | checklist (2 devices) | — |
| removed member decrypts no new epoch | T38 oracle | — | — | — |
| T25 in channels | EP-C, physical scans | T25 smoke | checklist | — |
| relay blindness (T36, T37, T40) | privacy world | — | — | **staging capture not run** (the F9 O1 runbook) |
| real SQLCipher, Keystore, Tor | — | partly (loopback relays) | checklist | — |
| performance on low-end phones | host timings only (a 15–25× factor, estimated) | — | **not measured** | — |
| the composition's security | tests, EM-3 | — | — | **external review: not done; a release gate** |

---

## 13. Gates, CI and dependencies

### 13.1 Gates (each with a negative fixture and a `self-test.sh` hit count)

| Gate | Rule | Supports |
|---|---|---|
| **G-M1** `rust-client-allowlist.sh`, `rust-dependency-allowlist.txt`, `rust-crypto-pins.txt` | the new crate names of the OpenMLS graph, generated in S0 by `cargo tree -e normal` on both shipped triples (the research probe's list: `openmls`, `openmls_traits`, `openmls_libcrux_crypto`, `openmls_memory_storage`, `openmls_serialization_helpers`, `hpke-rs`, `hpke-rs-crypto`, `hpke-rs-libcrux`, `libcrux-aead`, `libcrux-aes`, `libcrux-chacha20poly1305`, `libcrux-poly1305`, `libcrux-ed25519`, `libcrux-hkdf`, `libcrux-hmac`, `libcrux-hmac-drbg`, `tls_codec`, `tls_codec_derive`, `rayon`, `rayon-core`, `crossbeam-deque`, `crossbeam-epoch`, `crossbeam-utils`, `either`, … — minus names already present); exact pins of `openmls`, `openmls_traits`, `openmls_libcrux_crypto`, `hpke-rs*`; `cargo deny check` green | T7 |
| **G-M2** `rust-feature-policy.sh` | the forbidden OpenMLS features of §3.2 absent from every shipped graph; no GHOST code names `openmls_memory_storage` or `openmls_basic_credential` | ADR-40 |
| **G-M3** `ch-derivation-inputs.sh` + a Rust test | every `derive_*` of `ghost-client-mls` takes a typed secret input (`EpochExport`, `GenerationSecret`, `PseudonymSeed`, `InviteSeed`) | T36 static half |
| **G-M4** `mls-rust-no-logging.sh` | no logger installed in any graph; `log` reached only as a dependency; no `println!`, `eprintln!`, `dbg!` in GHOST sources | T3 |
| **G-M5** `ch-enqueue-callers.sh` | `Outbox.enqueue`, `Registrations.*`, `Funding.set`, `Namespaces.register/remove` and `Capabilities.put` for channel namespaces are called only from `CH-CREATE`, `CH-INVITE`, `CH-ACCEPT`, `CH-POST`, `CH-PASS`, `CH-SETTLE`, `CH-REJOIN`, `CH-REVEAL`, `CH-LEAVE`, the funder renewal step and `CH-SWEEP` (removals) — never from `CH-RECV` or `CH-JOIN` | T40 static half |
| **G-M6** `mls-jni-surface.sh` (G-R6 extended) | the exported `Java_org_ghost_crypto_bridge_MlsNative_*` symbols of the shipped library equal §10.2's list; the host library's equal the list plus its test entry | ADR-19, ADR-40 |
| **G-M7** `mls-golden-lock.sh` | at an OpenMLS pin change: golden channel states and the upgrade test for the old and new pins, the golden `MessageSecrets` (day rewrite), the exhaustive error `match`, the WG vector replay through `GhostKv` | ADR-40 |
| **G-M8** `mls-vendored-clock-log.sh` (the G-R8 method) | clock, logging and network sites in the compiled code of the `ghost-client-mls` graph equal a committed, justified baseline (the four OpenMLS clock sites of §3.6 among them) | T3, T33 |
| **G-M9** `libcrux-portable.sh` extended | the provider's libcrux crates built portable-only on both triples (V10-7) | ADR-36 practice |
| G-L1 … G-L4 | notices regenerated with the OpenMLS graph; the three `hpke-rs` crates' sources in the release bundle (G-L4) | ADR-37 |
| `apk-native-libs.sh` | still one native library | T12 |
| `anti-placeholder.sh`, `no-logging.sh`, `sync-no-catch-all.sh`, `kotlin-clearnet.sh`, G-DM1, G-DM4, G-DM6 | scopes cover `client-core/mls` and the channel packages | T3, T6, T8 |
| **`ch-report-check.sh`** (new) | requires the `channel-exit-gate` and `channel-privacy-gate` lines: seeds, crash classes per SCN-C scenario, `channel mutants: <n> run, <n> detected` with n equal to the registered count, EM-3, JC-1 … JC-6 = expected, NI-CH1 … 3 equal, the oracle lines; refuses a report claiming more than it measured (the `dm-report-check.sh` rule) | T36–T41 |

**Phase 9 gates this design leans on that are not built yet** (STATUS:18): G-R3, G-R4's graph half, G-R7, G-R8. G-M4, G-M7, G-M8 and G-M9 are their MLS counterparts; S0 decides whether each pair is built once, generically, for both graphs (recommended).

### 13.2 CI jobs

| Job | Change |
|---|---|
| `static-gates` | the source-only G-M gates and their fixtures |
| `rust` | `ghost-client-mls` unit, vector, property tests; G-M1, G-M2, G-M4, G-M7, G-M8; the WG passive-client replay |
| `android-native` | the grown library twice at the same path (T12); G-M6, G-M9 |
| `android` | channel JVM tests; SCN-M20 (one seed); crash singles SCN-CA … SCN-CD; the mutants on a small world; the privacy world at PR scale |
| **`channel-exit-gate.yml`** (new; nightly, dispatch) | SCN-M20 over the pinned seeds, full crash enumeration, all mutants, `ch-report-check.sh` |
| **`channel-privacy-gate.yml`** (new; nightly) | the privacy world at gate scale |
| **`channel-state-models.yml`** (new; nightly) | EM-3 |
| **`mls-vendor-tests.yml`** (new; on pin changes and weekly) | OpenMLS's test suite at the pinned tag with its KAT vectors (crates.io access; `test-utils` only here) |
| **`mls-fuzz.yml`** (new; nightly) | §12.10 |
| `t2-exit-gate.yml` | §7.9 |
| `dm-emulator.yml` | §12.11 |

**Runner budget (Q20).** `messaging-exit-gate` took 121–197 minutes on the workstation (F9 lessons); the channel gate adds a comparable load. S0 measures the PR `android` job with channels and sets the nightly shards; if the four runners cannot hold both gates nightly, the gates alternate nights.

### 13.3 Dependencies and approvals

| Item | Scope | Licence | Approval |
|---|---|---|---|
| `openmls` =0.9.0, `openmls_traits` =0.6.0, `openmls_libcrux_crypto` =0.4.0 (+ `openmls_memory_storage` 0.6.0, `openmls_serialization_helpers` 0.1.0 transitively) | release, in `libghost_client_net.so` | MIT | ADR-40; G-M1, G-M2 |
| `hpke-rs`, `hpke-rs-crypto`, `hpke-rs-libcrux` 0.7.0 | release | **MPL-2.0**, unmodified, source offered | ADR-37 point 2, ADR-40, Q16; G-L4 |
| libcrux primitives of the provider (`libcrux-aead`, `-aes`, `-chacha20poly1305`, `-poly1305`, `-ed25519`, `-hkdf`, `-hmac`, `-sha2`, `-hmac-drbg` 0.0.1) | release | Apache-2.0 (per crate; G-M1 records each) | ADR-40; G-M9 |
| `tls_codec` 0.5.0, `rayon` 1.x, `rayon-core` 1.13.0 and the crossbeam crates | release | Apache-2.0 OR MIT / MIT OR Apache-2.0 | ADR-40 |
| MLS WG test vectors (`mlswg/mls-implementations`) | test data | per the repository's licence, recorded in S0 | — |
| `mls-rs` (optional differential peer) | test-only | Apache-2.0 OR MIT | Q22 |
| **Not added** | any AGPL, GPL or LGPL crate; `openmls_sqlite_storage`; `openmls_basic_credential` in release; OpenMLS drafts features; a second native library; any Gradle coordinate | — | — |

---

## 14. Implementation slices (each ends green in CI)

| Slice | Content | Depends on | Exit condition | Weeks (team of 5–6) |
|---|---|---|---|---|
| **S0** evidence | **Precondition: CI restored** (artifact quota, a KVM runner or the emulator job's fallback; owner action, Q20). Checks: V10-1 graph and licences (G-M1 list, cargo-deny, MPL); V10-2 advisories at the pins; V10-3 size in `build-native.sh`; V10-4 commit and Welcome sizes with GHOST extensions at 32 and 100 members (the class floors); V10-5 adapter cost (rows per call, change-set size, write amplification with retention at 32 and 100); V10-6 determinism; V10-7 portable libcrux; V10-8 bootstrap in the Welcome's GroupInfo; V10-9 0x004F/0x004D behaviour with the libcrux provider (evidence for Q2 only); V10-10 host timings at 20 and 100 members, and on one low-end Android device if available | — | `docs/design/faza10-s0-evidence.md`; every V10 check answered; decisions of §17 frozen or re-asked | 1.5 |
| **S1** sync | migration 6, `Funding`, `REGISTER` needs, `relay_register_capability`, the channel send-delay trigger, `ModelRelay` hostile modes | S0 | `:sync` and `:entitlement` suites green; `sync-exit-gate` unchanged green | 1 |
| **S2** native core | `ghost-client-mls`: provider, `GhostKv`, signer, seal, derivations, content, invite and join codecs; `MlsNative` with host library; vectors; G-M1 … G-M4, G-M6, G-M8 | S0 | Rust and JDK vector replays green; WG passive-client replay through `GhostKv` green; reload oracle green on scripted groups | 2.5 |
| **S3** schema and store | migration 7, DAOs, introspection | S1 | migration and introspection suites; SCN-CI | 0.5 |
| **S4** engine I | create, invite, accept, admit, join, post, receive (peek ordering, defer), dedup | S2, S3 | SCN-CA, SCN-CB, JN, RO-C, RP-C; joiner oracle | 1.5 |
| **S5** arbitration | CO-1 … CO-10, passes, settle, self-updates; EM-3 | S4 | SCN-CD, EM-3, GV (CO-2), NI-CH1 at PR scale | 1.5 |
| **S6** generations and funding | rotation, drain, funders, registrations, removal, leave, eviction | S5 | SCN-CC, SCN-CK, FD, T38 oracle, JC-5 | 1 |
| **S7** resync and forks | stale detection, rejoin, swap, `reinvite_needed`, FORK | S6 | SCN-CE, SCN-CG, FK, EM-3 detection | 1 |
| **S8** ephemeral | timers, cascade, retention, sweep; T25 channel cases | S4 | SCN-CF, EP-C, physical scans | 0.5 |
| **S9** reveal and governance | reveal; sponsor records; threshold function and S5 simulation | S5 | RV, SCN-CJ, GV simulation | 0.5 |
| **S10** exit harness | SCN-M20, seizure oracles, crash enumeration, `channel-exit-gate` | S6–S8 | SCN-M20 green under crash singles; nightly gate green once | 1 |
| **S11** privacy world and mutants | JC, NI-CH, mutants with killers, `channel-privacy-gate`, `ch-report-check.sh` | S10 | PR scale green; mutants `n run, n detected` | 1 |
| **S12** emulator, documents, review | emulator smoke, device step, Appendix B applied, adversarial review of the phase | S11 | §15 checklist | 1 |

**Effort, stated honestly.** The critical path S0 → S2 → S4 → S5 → S6 → S7 → S10 → S11 → S12 sums to **12 weeks**; S1 and S3 run beside S2, S8 and S9 beside S5–S7. With 5–6 people overlapping slices where the dependencies allow (for example, S10's harness built during S6–S7), the estimate is **9–12 calendar weeks**, against the plan's 6–9. The plan's range holds only if the owner accepts: the large size class deferred (Q3), governance limited to roles and removal (Q15), and the gate's seed count taken from what the runners hold (Q20). The estimate assumes Phase 9's infrastructure is stable; each Phase 9 defect found under channels (R-8) adds time. Phase 9's record (97 designed mutants, 30 run at its last count) says a design's test counts slip; §12 pins none before S0.

---

## 15. Exit-gate checklist (all on the closing commit)

1. SCN-M20 green in `channel-exit-gate` with the pinned seeds and the full crash enumeration (plan clause 1, FR-2.2, FR-3.2, FR-3.5).
2. The removed-member oracle opens 0 in every variant, including the device-swap stack (plan clause 2, TM S4, LIMITE:39).
3. The channel T25 cases green, including the physical scans (plan clause 3).
4. EM-3 green; T41 in SCN-M20.
5. The privacy world at gate scale: JC-1 … JC-6 as expected, NI-CH1 … 3 equal (T36, T37, T40).
6. Every registered mutant detected; `ch-report-check.sh` accepts the reports.
7. The WG test vectors pass in `mls-vendor-tests`; the passive-client replay through `GhostKv` passes (spec Appendix A).
8. Fuzzing ran nightly for at least 7 nights with no open crash.
9. Gates G-M1 … G-M9 green with fixtures; `cargo deny` green; notices and MPL sources updated.
10. The emulator smoke test ran (on the runner, or the local fallback recorded); the device step recorded or recorded as not executed.
11. Appendix B applied to INVARIANTS, THREAT_MODEL, LIMITE, the plan, STATUS and the ADR index; ADR-40 … ADR-43 filed as "propus".
12. The phase's adversarial review done and its findings corrected or recorded.
13. **Not required for the gate, required before distribution:** the external audit of OpenMLS as configured and of the GHOST composition (plan row 15), staging captures (T1), device performance.

---

## 16. Risks

| # | Risk | Likelihood / impact | Mitigation | Residue |
|---|---|---|---|---|
| R-1 | Commit arbitration has a subtle bug (divergence, lost admissions, liveness) | medium / high | EM-3 exhaustive model, FORK and WITHHOLD_COMMIT modes, reload oracle, `oracle_epoch` at every epoch, MM-2 … MM-4, MM-16 | forks under AD-1 partitions remain possible by design, detected and repaired |
| R-2 | OpenMLS's serde layout changes at a bump (the day rewrite, the storage format) | medium / medium | exact pins; G-M7 golden states and upgrade tests; `STATE_CORRUPT` instead of silent defaults | a bump costs a migration drill |
| R-3 | Value semantics cost on low-end phones: every call reloads the channel's rows (≈ 57–63 KB at 20 members and ≈ 225–261 KB at 100 in the probe's memory storage with 2 past epochs; GHOST keeps fewer) | medium / medium | V10-5, V10-10; retention short (§8.3); a version-checked native cache as Q18's alternative | unmeasured on devices until S0 or Phase 12 |
| R-4 | APK size: +2.7–3.3 MB per ABI (probe) | high / low | S0 measures in the shipped library; budget ≤ +3 MiB per ABI | NFR-4 (< 80 MiB) not at risk by itself |
| R-5 | Token budget and funding stalls (rotations cost 3 tokens; funders absent) | medium / medium | ≥ 2 funders recommended in the Phase 13 UI; registrations tolerate 2–3 weeks; stores wait, never fail silently | L8-C6 |
| R-6 | Pre-authentication decoding bugs in OpenMLS | low / medium | the seal limits who can reach the decoders to seal-key holders; `catch_unwind`; `mls-fuzz`; exact pins with advisory watch | members and invite holders can still reach them |
| R-7 | CI capacity: gates that never run (Phase 9's lesson) | high / high | S0 precondition (Q20); nightly alternation; report checks refuse unmeasured claims | — |
| R-8 | Phase 9's infrastructure is not closed; channel work may expose its defects | high / medium | S0 re-runs the Phase 9 suites the channel engine depends on; defects are fixed in Phase 9's code with their own tests | schedule |
| R-9 | Upstream churn (`ExportedSecret<T>` on `main`; Android "built but not tested" upstream) | medium / low | pins; the emulator equivalence test; upstream issues filed (F-5) | — |
| R-10 | The classical suite: channels exposed to harvest-now-decrypt-later; a later PQ migration needs new channels | certain / medium | declared (L8-C1, §4.5); suite-agile invites; triggers in §4.4 | owner decision Q2 |
| R-11 | Expectations of ADR-13's full governance in Phase 10 | medium / low | D17 and Q15 state the split | — |
| R-12 | GHOST uses OpenMLS in ways its examples do not (no member proposals, by-value adds, `swap_members` for rejoin, the pinned-schema day rewrite) | medium / medium | each is public API except the day rewrite (recorded deviation); golden tests; the external audit scope names them | — |
| R-13 | Loss of the owner's seed freezes the policy (committer list) | low / medium | backups keep membership moving; the UI (Phase 13) urges a moderator | L8-C16 |

---

## 17. Owner questions (the proposed default applies unless the owner objects)

| # | Question | Proposed default | Pe scurt (RO) |
|---|---|---|---|
| Q1 | Approve ADR-40 … ADR-43 (Appendix A) as "propus", and this design as the basis for Phase 10 code? | **yes** | Aprobarea ADR-40 … ADR-43 și a designului |
| Q2 | Ciphersuite: classical 0x0003 for every P0 channel, with no PQ claim for channels and the §4.4 triggers; or the X-Wing suite 0x004D now (experimental code point, 16–64 KiB commits, cap ≈ 32 members, outside the audit, not migratable in place)? | **0x0003** | Canalele folosesc suita clasică; suita post-cuantică doar când e stabilă și revizuită |
| Q3 | Two size classes (small ≤ 32 members with 4 KiB blobs; large ≤ 100 with 16 KiB blobs), or only the small class in Phase 10 (saves ≈ 0.5 week)? | **both** | Două clase: până la 32 de membri (4 KiB) și până la 100 (16 KiB) |
| Q4 | At most 12 channels per client (the Phase 7 read budget of 64 pairs), beyond which the app refuses to join? | **12** | Cel mult 12 canale pe dispozitiv |
| Q5 | Invites as single-use bearer links or QR codes that carry the generation's namespace and access secrets (a leaked invite lets its holder see the channel's traffic volume and fill its quota until the next rotation, L8-C4), rather than invitations only through DMs? | **links and QR** (sendable inside a GHOST DM) | Invitația e un link sau QR de unică folosință; cine îl obține vede volumul canalului până la următoarea rotație |
| Q6 | A new namespace and new access secrets at every removal (3 tokens for the removing committer), so a removed member sees nothing more at the relays; or keep the namespace and declare that a removed member keeps seeing volume and timing? | **rotate** | La fiecare scoatere canalul trece pe o adresă nouă; cel scos nu mai vede nimic |
| Q7 | Funders: the owner by default, up to 3 named members; each pays 3 tokens per week per channel; non-funders pay nothing? | **yes** | Proprietarul plătește releele canalului (3 token-uri pe săptămână); ceilalți membri nu plătesc |
| Q8 | Committers commit at scheduled passes only when work is pending (plus an empty weekly commit), declaring that relays can infer "a request was pending" (LC-6); or commit at every pass (more epochs, more storage writes, no LC-6)? | **when pending** | Moderatorul confirmă cererile la momente programate, nu imediat ce sosesc |
| Q9 | Members refresh their keys every 28 days; members idle 63 days are removed? | **yes** | Cheile membrilor se reîmprospătează la 28 de zile; cine lipsește 63 de zile e scos |
| Q10 | A 20-minute settle window before a membership change takes effect? | **20 min** | O schimbare de membri intră în vigoare după 20 de minute |
| Q11 | History policy "none" only (joiners see nothing from before), no history transfer until a later ADR? | **yes** | Membrii noi nu văd istoricul |
| Q12 | Channels with timers ≤ 1 day: commits and invitations live 7 days on relays (relays can tell them from posts there), or the whole channel at 7 days, or no timers below 7 days for channels? | **commits 7 days** | În canalele cu timer scurt, mesajele de administrare stau 7 zile pe relee |
| Q13 | One pseudonym per channel for life (a removed and re-added member returns with the same pseudonym; THREAT_MODEL:81 corrected)? | **yes** | Același pseudonim în același canal, pentru totdeauna |
| Q14 | Reveal to one member by encryption to its channel key; other members see that you revealed to someone, not to whom? | **yes** | Dezvăluirea identității e vizibilă doar celui ales; ceilalți văd doar că ai făcut o dezvăluire |
| Q15 | Governance in Phase 10 limited to roles, removal, leave, eviction, sponsor records and the S5 threshold simulation; flags, quarantine, strikes, exclusion lists and verified channels with the Phase 13 UI? | **yes** | Rapoartele, carantina și strike-urile vin în Faza 13 |
| Q16 | Accept `hpke-rs` 0.7.0 (MPL-2.0, three crates) unmodified with published sources, or write a GHOST crypto provider on RustCrypto's `hpke`? | **accept** | Acceptăm `hpke-rs` (MPL-2.0) nemodificat, cu sursa publicată |
| Q17 | No external commits and no published GroupInfo (joins only through a committer)? | **yes** | Intrarea în canal doar prin aprobarea unui moderator |
| Q18 | Past epochs kept 2 days (1 day in short-timer channels, at most 64); posts encrypted only when the channel is current; no native state cache in Phase 10? | **yes** | Cheile vechi se șterg după 2 zile; fără cache nativ |
| Q19 | Device loss: a restored device rejoins and replaces its old leaf; a stolen seed can only be excluded by leaving the pseudonym and a new identity (declared)? | **yes** | Un dispozitiv restaurat își reia locul; un seed furat cere identitate nouă |
| Q20 | Owner actions before S0: restore the CI artifact quota and provide a KVM runner (or accept the local emulator fallback); size the gate seeds from the runner budget? | **yes** | Refacerea CI (cota de artefacte, runner cu KVM) înaintea fazei |
| Q21 | NFR-2 (p95 < 8 s) declared unmet by the 30-second listing interval, measured in Phase 12? | **yes** | Ținta de latență NFR-2 nu e atinsă cu programul actual; se măsoară în Faza 12 |
| Q22 | An mls-rs differential peer in tests? | **no** in Phase 10 (WG vectors suffice) | Fără a doua implementare MLS în teste |
| Q23 | A formal model (ProVerif) of the channel layer before distribution? | **not in Phase 10**; the external review decides | Fără model formal al canalelor acum |
| Q24 | No public channels, no discovery, no content readable by non-members in Phase 10; any of them needs its own ADR? | **yes** | Fără canale publice sau descoperire |
| Q25 | Backup committers take over after `rank × 48 h` of silence; only the owner changes the policy? | **yes** | Moderatorii preiau după 48 h de absență a proprietarului; doar proprietarul schimbă regulile |
| Q26 | One messaging actor for DMs and channels (one writer)? | **yes** | Un singur fir de lucru pentru DM și canale |

---

## 18. Findings outside Phase 10 (proposed as separate tasks)

- **F-1.** STATUS:14 and `relay/README.md:20` assign "Noise gossip" to Phase 10; that is spec v2.0 numbering (its Phase 10 was multi-relay metadata protection). The v2.1 plan places relay-to-relay work nowhere explicitly; the owner should assign it (Phase 12 or operations). Erratum in Appendix B.4.
- **F-2.** The guarantee matrix (plan:241), TM:50 (AD-2 "nu vede … apartenență") and TM:38 (AS-7 "doar în capetele MLS") say relays do not see channel membership; under AD-1 session co-occurrence rebuilds it (L7-D2). Text corrected in Appendix B; decoupling is Phase 12.
- **F-3.** Spec FR-5.5 (90-day default TTL) is superseded for channel and DM blobs by ADR-27/ADR-32; the spec erratum should say so.
- **F-4.** Phase 9's G-R3, G-R4 (graph half), G-R7 and G-R8 are not built; building them once, generic over the DM and MLS graphs, is cheaper than twice (S0).
- **F-5.** Upstream OpenMLS requests (no fork): a storage transaction hook (begin/commit around an operation), which would let GHOST drop the change-set copy; a sender-data peek for ordering; a documented time source for past-epoch stamps.
- **F-6.** The v1 `media` table has `owner_operation_id` without a foreign key (`Schema.kt:211-219`); Phase 11 should replace it with the migration-7 style.

---

## Appendix A: ADR drafts (Romanian)

### ADR-40 — Forumul pe OpenMLS 0.9.0 în `client-core`: bibliotecă, furnizor, adaptor de stocare, suita clasică, JNI închis

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-25 (design Faza 10, `docs/design/faza10-forum.md`), în așteptarea deciziei proprietarului (Q1) |
| Sursă | design Faza 10 §3, §4, §10; cercetările rundei 10a; F9 §20 F-10 |
| Modifică | spec Anexa A, rândul MLS („OpenMLS 0.8.x baseline”); ADR-19 (crate-ul `ghost-client-mls`, suprafața JNI `MlsNative`); Anexa D a planului (crate-urile Rust ale OpenMLS); `deny.toml` și G-L4 (trei crate-uri MPL-2.0); API-ul `:sync` (`Funding`, capabilități de înregistrare); schema (migrațiile 6 și 7) |

**Context.** Spec §7.3 și FR-2.2 cer RFC 9420 prin OpenMLS sau o implementare revizuită. OpenMLS 0.9.0 (MIT, 2026-08-25) remediază două defecte de decodare accesibile înaintea autentificării; auditul SRLabs v1.2 a lăsat deschisă constatarea S1-3 (starea grupului și stocarea se pot desincroniza la o scriere eșuată). Suitele post-cuantice ale MLS sunt drafturi fără coduri atribuite.

**Decizie.**
1. OpenMLS `=0.9.0`, `openmls_traits` `=0.6.0`, furnizorul criptografic libcrux `=0.4.0`, fără funcții implicite; funcțiile de depanare, de test, drafturile (inclusiv suitele PQ, mesajele țintite, extensiile), stocarea SQLite și rezolvarea bifurcațiilor sunt interzise în graful livrat (G-M2).
2. Suita `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003) pentru toate canalele P0; fără nicio afirmație post-cuantică pentru canale (ADR-12: suita hibridă „când e stabilă”; azi nu e).
3. Furnizorul GHOST: criptografia libcrux, stocarea `GhostKv` (rândurile canalului intră în apel, apelul întoarce un set de schimbări scris de Kotlin în aceeași tranzacție SQLCipher, numai la succes), semnătura cu cheia pseudonimului în Rust (`ed25519-dalek`), `rayon` cu un singur fir.
4. Momentul `added_at` al secretelor epocilor trecute se rotunjește la zi la scriere (abatere consemnată: editare a formatului serde fixat, păzită de G-M7); duratele de viață ale KeyPackage-urilor sunt zile întregi.
5. Crate-ul `ghost-client-mls` se leagă în `libghost_client_net.so`; Kotlin cheamă o listă închisă de funcții pure (`MlsNative`, G-M6); biblioteca de test `ghost-dm-host` o exportă și ea.
6. `hpke-rs`, `hpke-rs-crypto`, `hpke-rs-libcrux` (MPL-2.0) se folosesc nemodificate, cu sursa publicată (ADR-37 punctul 2).

**Consecințe.** (+) O bibliotecă MLS întreținută, cu audit public și remedieri recente; atomicitatea vine din regula GHOST, nu din bibliotecă; nicio a doua bibliotecă nativă. (−) +2,7–3,3 MB per ABI (măsurat într-o probă, de confirmat în S0); trei crate-uri MPL noi; canalele nu sunt protejate împotriva decriptării cuantice ulterioare; un cost de copiere a stării la fiecare apel.

**Alternative respinse.** mls-rs (fără audit extern public); DMLS (draft expirat); o implementare proprie (interzisă); suita X-Wing 0x004D acum (cod experimental, mesaje de 16–64 KiB, neauditat, nemigrabil); stocarea SQLite a OpenMLS (neatomică față de rândurile GHOST).

**Teste.** Vectorii WG MLS și suita OpenMLS la eticheta fixată; reluarea vectorilor passive-client prin `GhostKv`; oracolul de reîncărcare; SCN-CA … SCN-CK; G-M1 … G-M9.

### ADR-41 — Canale oarbe pentru relee: sigiliu exterior pe epocă, generații, chei comune de citire și depunere, rotație la scoatere, finanțatori

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-25, în așteptarea deciziei proprietarului (Q1) |
| Sursă | design Faza 10 §5, §6.5, §7, §8 |
| Modifică | Anexa B a planului („namespace = H(cheia publică a canalului)”; „capabilitate de citire per epoch”); designul Fazei 8, D11 („per (namespace, epocă)”) și ADR-25 punctul 9; ADR-27 punctul 11 pentru mesajele de administrare ale canalelor cu timer ≤ 1 zi; INVARIANTS T9, T25 |

**Context.** MLS lasă în clar identificatorul grupului, epoca, tipul conținutului și, în Welcome, referințele KeyPackage. Releele nu au logică de grup. Înregistrările `RegisterKey` sunt pe săptămâni și se acumulează, deci nu pot fi revocate la „epoch-ul următor”.

**Decizie.**
1. Fiecare octet al unui canal stocat pe relee e sigilat (`salt ‖ hint ‖ AEAD`, forma DM) sub o cheie de epocă derivată din exportatorul MLS sau sub cheia de intrare a generației; niciun antet MLS nu apare în afara sigiliului.
2. Un canal trece prin generații; secretul generației derivă din exportatorul epocii care a deschis-o; din el derivă namespace-ul, secretele de citire și de depunere per slot și cheia de intrare. O generație nouă începe la fiecare commit care scoate un pseudonim (scoatere, plecare, evacuare) sau schimbă clasa de mărime; cel scos nu poate calcula noua generație. Namespace-ul vechi se golește în 14 zile.
3. Toți membrii depun cu credențialul DEPOSIT al generației și citesc cu credențialul READ (credențiale purtătoare v3, `RegisterKey`, neschimbate); finanțatorii (proprietarul și cel mult doi membri) răscumpără token-uri numai pentru înregistrări, la momentul de reînnoire al Fazei 8 și, pentru rotația proprie, la îmbinarea commit-ului.
4. Clase de mărime: mic (≤ 32 de membri, treaptă minimă 4 KiB), mare (≤ 100, 16 KiB); treapta unui blob depinde doar de lungime și de clasă; un commit încape în treapta minimă.
5. TTL: postările urmează ADR-27 punctul 11; mesajele de administrare folosesc același TTL în canalele cu timer de 7 zile, 30 de zile sau dezactivat și 7 zile în canalele cu timer ≤ 1 zi (abatere declarată).
6. Nicio modificare a releului și niciun câmp observabil nou.

**Consecințe.** (+) Releele nu leagă nimic de pseudonime sau de identificatorul canalului; un singur scop de depunere și unul de citire per releu și namespace; un membru scos nu mai vede nimic din generația nouă; commit-urile arată ca postările în canalele implicite. (−) 3 token-uri pe săptămână per canal per finanțator și 3 la fiecare rotație; releele văd rotațiile și intrările (co-apariția le leagă sub AD-1); o invitație scursă dă acces la metadatele generației; orice membru poate epuiza cota săptămânală.

**Alternative respinse.** MLS brut pe relee; o cheie de sigilare statică per canal; namespace pe viața canalului; namespace per epocă; capabilități de scriere per membru; token-uri de rată per membru (P2).

**Teste.** T36, T37, T38; JC-1 … JC-5; NI-CH2, NI-CH3; oracolul membrului scos; PC-1 … PC-4, PC-7, PC-8, PC-10, PC-11, PC-13; MM-7, MM-8.

### ADR-42 — Ordinea commit-urilor fără server și guvernanța minimă

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-25, în așteptarea deciziei proprietarului (Q1) |
| Sursă | design Faza 10 §6.4, §6.6–§6.8, §6.10; RFC 9750 §5.2.2 |
| Modifică | ADR-13 și LIMITE §3.1 („primul client care observă pragul emite Remove” se retrage); THREAT_MODEL S3 și S5 (testele indicate); INVARIANTS (T40, T41 noi) |

**Context.** Releele nu ordonează commit-urile; două commit-uri concurente pe aceeași epocă despart grupul. OpenMLS refuză mesajele de aplicație cât propunerile primite stau în depozitul lui de propuneri.

**Decizie.**
1. Doar comitenții (lista ordonată din politica canalului: proprietarul pe rangul 0, apoi moderatorii, cel mult 8) fac commit-uri care schimbă membrii sau politica; orice membru poate face doar un commit gol de reîmprospătare (prioritate minimă). Membrii nu trimit propuneri MLS: cererile (intrare, plecare) circulă ca mesaje de aplicație sau blob-uri de intrare, iar comitenții includ propunerile prin valoare.
2. Câștigătorul unei epoci: rangul cel mai mic, apoi SHA-256 cel mai mic al commit-ului; un membru îmbină câștigătorul la 20 de minute după primul candidat văzut; o epocă îmbinată e finală; un commit diferit pentru o epocă finală e dovadă de bifurcație; partea care a pierdut se reface printr-o cerere de reintrare, admisă de un comitent prin înlocuirea frunzei.
3. Comitenții lucrează la treceri programate (la sesiunile în prim-plan, cel mult la 6 ore, și o dată pe zi în fundal) când au de lucru, plus un commit gol săptămânal; membrii se reîmprospătează la 28 de zile; cei inactivi 63 de zile sunt scoși. Nimic nu pleacă pentru că a sosit un blob.
4. Un rang r scoate doar membri obișnuiți și comitenți de rang mai mare; doar proprietarul schimbă politica; un comitent de rang r preia după `r × 48 h` fără commit-uri ale rangurilor inferioare.
5. Faza 10 livrează rolurile, scoaterea, plecarea, evacuarea, evidența sponsorilor și simularea pragului (TM S5); flag-urile, carantina, strike-urile, listele de excludere și canalele verificate vin cu interfața Fazei 13.

**Consecințe.** (+) Convergență deterministă fără server; bifurcațiile se detectează și se repară în canal; fără trafic reflex. (−) O schimbare de membri durează cel puțin 20 de minute; releele pot deduce că o cerere aștepta (LC-6); o partiționare prin relee (AD-1) poate bifurca un canal, iar postările de pe ramura pierdută se pierd; pierderea seed-ului proprietarului îngheață politica.

**Alternative respinse.** Un secvențiator la releu (schimbare de protocol, putere de bifurcare pentru un releu); secvența releului (per releu și o scurgere); revenirea după îmbinare; DMLS; propunerile membrilor; scoaterea automată de „primul client care observă pragul”.

**Teste.** EM-3; SCN-CD, SCN-CG, SCN-M20 (varianta FORK); NI-CH1; GV; MM-2 … MM-6, MM-16, PC-5, PC-6.

### ADR-43 — Invitații în canal, dezvăluire opt-in, istoric „none”, pseudonim stabil

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-25, în așteptarea deciziei proprietarului (Q1) |
| Sursă | design Faza 10 §5.9, §6.2, §6.9, §8.4, D12 |
| Modifică | THREAT_MODEL:81 (rotirea pseudonimului); spec §8 (`posts`: pseudonimul autorului); schema v1 (`channels`, `channel_pseudonyms.revealed`, `mls_state`, `posts` înlocuite); ADR-05 (legătura `ghost://channel/`) |

**Decizie.**
1. **Invitația** e un link `ghost://channel/…` sau un cod QR (≤ 270 de octeți), de unică folosință, valabil cel mult 7 zile, cu namespace-ul și secretele de acces ale generației, cheia de intrare și o cheie de semnare a invitației; sponsorul publică în canal `INVITE_ISSUED` (identificatorul, cheia publică, expirarea). Invitatul depune o cerere semnată cu cheia invitației; un comitent o admite; Welcome-ul, câte o copie sigilată per invitat, poartă generația curentă, criptată pentru invitat.
2. **Dezvăluirea** către un singur membru: conținutul (cardul DM și o legătură semnată în ambele sensuri, pseudonim ↔ `ghost1`) e criptat HPKE către cheia de canal a membrului ales; ceilalți văd doar că autorul a dezvăluit ceva cuiva.
3. **Istoricul pentru membrii noi: „none”** (singura valoare în P0); orice transfer de istoric cere un ADR nou.
4. **Pseudonimul** e cel din ADR-04, stabil pe viața canalului; un membru scos și readus revine cu același pseudonim; un pseudonim nou înseamnă un canal nou.

**Consecințe.** (+) Invitații fără contact DM prealabil, fără server; sponsorul e vizibil în canal (ADR-13); dezvăluirea nu poate fi forțată și nu arată destinatarul. (−) O invitație scursă permite vederea metadatelor generației și umplerea cotei până la rotație; destinatarul unei dezvăluiri păstrează cardul definitiv; membrii noi văd volumul și momentele blob-urilor vechi (fără conținut).

**Alternative respinse.** Invitații doar prin DM; invitații fără cheie de semnare; mesaje MLS țintite (destinatarul în clar pentru membri); un indicator `revealed` per canal; istoric complet la intrare; un index de încarnare al pseudonimului.

**Teste.** JN; RV; oracolul membrului nou (T39); T14; PC-9, MM-13, MM-14, MM-15.

---

## Appendix B: Text changes in other documents (Romanian; applied in slice S12)

### B.1 `ghost/test-harness/privacy/INVARIANTS.md` (rânduri noi)

| ID | Invariant | Verificare | Executabil din | Cod |
|---|---|---|---|---|
| T36 | Canalele sunt oarbe pentru relee: nicio valoare vizibilă releelor nu se poate calcula din `channel_id`, din cheile pseudonimelor sau cutiilor, din KeyPackage-uri, din identificatorii invitațiilor sau din antete MLS fără un secret de generație, de epocă sau o invitație; orice blob de canal e sigilat (design Faza 10 §5.6); niciun octet de antet MLS în afara sigiliului | vectorii `ch_derive.txt`; G-M3; JC-1, JC-2 în lumea de confidențialitate a canalelor; mutanții PC-1, PC-7, PC-13 | Faza 10 | `client-core/mls`, `android/messaging` (lumea canalelor) |
| T37 | Un singur scop per tip: fiecare depunere într-un namespace de generație la un releu prezintă credențialul DEPOSIT al acelei perechi, fiecare listare sau citire credențialul READ; capabilitățile răscumpărate apar doar la `register`; în canalele cu timer de 7 zile, 30 de zile sau dezactivat, toate blob-urile au TTL-ul canalului, iar commit-urile treapta minimă | JC-3, JC-4, NI-CH2; PC-3, PC-4, PC-8, PC-10 | Faza 10 | lumea canalelor |
| T38 | Un membru scos nu deschide nimic dintr-o epocă de după scoaterea lui și nu deține niciun secret al generațiilor următoare | oracolul membrului scos (toate secretele păstrate, încercate pe toate blob-urile ulterioare); MM-7, MM-8, PC-2 | Faza 10 | lumea canalelor |
| T39 | Istoric „none”: un membru nou nu deschide nimic dintr-o epocă de dinaintea intrării lui | oracolul membrului nou; PC-2 | Faza 10 | lumea canalelor |
| T40 | Fără reflex în canale: două lumi care diferă doar în ce a primit un client dau vederi identice ale releelor asupra acelui client, cu excepția declarată LC-6 (existența unui commit la o trecere programată) | NI-CH1; G-M5; PC-5, PC-6 | Faza 10 | `android/messaging` |
| T41 | Convergență: membrii care au aceiași candidați pentru o epocă la îmbinare aleg același commit și au același `epoch_authenticator`; un membru de pe o ramură pierdută ajunge în `resync_needed` sau `reinvite_needed`, niciodată într-o divergență tăcută | EM-3; SCN-M20 cu varianta FORK; MM-2, MM-3, MM-4, MM-16 | Faza 10 | `client-core/mls` (modelul), lumea canalelor |

Rânduri modificate: T9, T13, T25 („Faza 10 (canale)” devine descrierea verificării din design §11.2); T3 (canarii canalelor); T20 (coloanele de timp ale migrațiilor 6 și 7); T33 (tabelele canalelor; starea OpenMLS fără timp sub zi). Nota de stare a Fazei 10 spune ce e construit și rulat la închidere, după modelul notei Fazei 9.

### B.2 `docs/THREAT_MODEL_v2.1.md`

- **AS-7:** „distribuit: doar în capetele MLS” devine „în capetele MLS; sub AD-1, co-apariția sesiunilor reconstruiește graful client ↔ namespace de canal (LIMITE L7-D2, L8-C2)”.
- **AD-2, „Ce NU poate”:** „apartenență” devine „apartenență, în afara celei deduse din co-apariție (L8-C2)”.
- **§5, rândul „Pseudonim per canal”:** coloana „Rotire” devine „stabil pe viața canalului (ADR-43); un pseudonim nou = un canal nou”.
- **§5, rândul „OpenMLS (epoch secrets)”:** „secretele epocilor trecute păstrate cel mult 2 zile (1 zi în canalele cu timer ≤ 1 zi), cel mult 64 (design Faza 10 §8.3)”.
- **§6:** rândul „Postare în canal” primește „scopul DEPOSIT unic al generației; treaptă după lungime și clasă; TTL-ul canalului”; rândul „Citire canal” primește „scopul READ unic al generației (D11 aplicat, per generație)”; rândul „Flag / Remove” devine „Scoatere: un commit al unui comitent la o trecere programată, arătând ca o postare; o rotație (namespace nou) vizibilă sub AD-1”; rânduri noi: „Invitație în canal” (o cerere de intrare de treapta minimă, un Welcome mai mare la trecerea comitentului, un ascultător nou), „Rotație de generație” (răscumpărări și înregistrări ale comitentului, namespace nou, cel vechi golit în 14 zile), „Dezvăluire” (nimic la relee; membrii văd autorul, nu destinatarul).
- **S3:** testul devine „FORK, WITHHOLD_COMMIT, EM-3, T41 (Faza 10)”. **S4:** „T38, oracolul membrului scos (Faza 10)”. **S5:** „simularea pragului (GV, Faza 10); mecanica flag-urilor în Faza 13”.

### B.3 `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`

- **L1, rândul „Limitare / PCS”:** „MLS: reîmprospătare la 7 zile pentru comitenți și la 28 de zile pentru membri (design Faza 10 §6.8)”. **Rândul „Recuperare”:** „Grupurile (MLS): un dispozitiv restaurat reintră și își înlocuiește frunza; dispozitivul vechi nu decriptează epocile noi (T38, SCN-M20); un seed furat se exclude doar părăsind pseudonimul, cu identitate nouă (L8-C9)”.
- **L3 §3.1, punctul 3:** „orice client cu rol de moderator (sau … primul client care observă pragul) emite `Remove`” devine „un comitent (proprietar sau moderator) emite `Remove` la o trecere programată; niciun client nu reacționează automat la un flag (ADR-42)”.
- **Secțiune nouă L8. Canale (Faza 10; ADR-40 … ADR-43; design `docs/design/faza10-forum.md` §2, §6)**, cu rândurile:

| ID | Reziduu | De ce rămâne | Atenuare / fază |
|---|---|---|---|
| L8-C1 | Canalele nu sunt protejate împotriva unui adversar care înregistrează acum și decriptează cuantic mai târziu (spre deosebire de DM) | suita hibridă MLS nu e stabilă (ADR-12) | declanșatorii din design §4.4; nicio afirmație PQ pentru canale |
| L8-C2 | Sub AD-1, co-apariția leagă namespace-urile canalelor unui client și lanțul de generații al unui canal; releele văd rotațiile (numărul și momentul scoaterilor) și intrările | Faza 7, L2.1 punctul 1 | decuplare în Faza 12 |
| L8-C3 | Un membru nou vede momentele și volumul blob-urilor vechi ale generației (fără conținut) | namespace-ul se schimbă doar la scoatere | — |
| L8-C4 | O invitație scursă dă, până la rotație, citirea metadatelor generației, depuneri (umplerea cotei) și deschiderea stratului exterior al traficului de intrare; nu dă intrarea (unică folosință) | invitația e un secret purtător | QR în persoană; expirare ≤ 7 zile |
| L8-C5 | Cei scoși la sfârșitul unei generații văd, cât se golește namespace-ul vechi (≤ 14 zile), cererile de intrare și reintrare de acolo (pseudonimele celor care revin) | cunosc cheia de intrare a generației vechi | — |
| L8-C6 | Dacă finanțatorii lipsesc peste 2–3 săptămâni sau nu au token-uri, depunerile așteaptă și expiră la termen; o rotație făcută de un comitent fără token-uri poate aștepta până la o săptămână | releele cer o înregistrare plătită | cel puțin doi finanțatori (UI Faza 13) |
| L8-C7 | Orice membru (sau deținător de invitație) poate epuiza cota săptămânală de depunere a canalului | cheia de depunere e comună | scoatere și rotație |
| L8-C8 | Destinatarul unei dezvăluiri păstrează definitiv cardul și dovada legăturii; ceilalți membri văd că autorul a dezvăluit cuiva | natura dezvăluirii | avertisment în Faza 13 |
| L8-C9 | Un seed sau un dispozitiv furat deține cheia pseudonimului: poate posta și reintra ca membrul | pseudonimul derivă din seed (ADR-04) | scoaterea pseudonimului, identitate nouă (ADR-14) |
| L8-C10 | Un dispozitiv confiscat deschide ciphertext-ul păstrat pe relee al epocilor încă reținute (≤ 2 zile), inclusiv postări neaduse | întârzieri de stocare | reținere scurtă |
| L8-C11 | Un membru rău-intenționat poate trimite obiecte valide de până la 64 KiB și commit-uri goale în exces (limitate la 8 candidați per epocă); un comitent poate emite commit-uri concurente (tranșate determinist) | membrii sunt autentificați, nu și onești | scoatere; S0-1 (SRLabs) limitat de treapta de 64 KiB |
| L8-C12 | Pe dispozitivul unui comitent rămân zilele ultimei reîmprospătări a fiecărui membru | evacuarea după inactivitate | ștergere la scoatere |
| L8-C13 | Postările de pe ramura pierdută a unei bifurcații se pierd pentru ceilalți; momentul stocării unei postări scrise offline depinde de durata recuperării sesiunii | fără secvențiator; criptare doar pe canal curent | — |
| L8-C14 | În canalele cu timer ≤ 1 zi, releele deosebesc după TTL mesajele de administrare de postări | abaterea X-7 | Q12 |
| L8-C15 | Membrii văd lista pseudonimelor, ordinea intrărilor, sponsorii și acțiunile comitenților; nelegabilitatea pseudonimelor e doar criptografică | natura grupului | — |
| L8-C16 | Pierderea seed-ului proprietarului îngheață politica (lista comitenților); membrii pot continua să fie adăugați și scoși de moderatori | doar rangul 0 schimbă politica | un moderator numit din timp |

- **§5 (sinteza):** o frază: „Un membru scos nu decriptează nimic din epocile următoare și nu mai vede nimic din generația nouă a canalului; releele văd totuși, sub AD-1, că un canal își schimbă adresa (L8-C2).”

### B.4 Plan, STATUS, ADR-uri

- **Plan, rândul 10:** textul rămâne; se adaugă „(design `docs/design/faza10-forum.md`; ADR-40 … ADR-43)”.
- **Plan, Anexa B:** notă „(Faza 10, 2026-09-25): punctele „Namespace de canal” și „Capabilitate de citire” sunt înlocuite de ADR-41: namespace și chei READ/DEPOSIT comune derivate dintr-un secret de generație, înregistrate cu `RegisterKey`; cel scos pierde accesul prin rotația generației, nu la „epoch-ul următor”.”
- **Plan, Anexa D:** Rust: „în plus `openmls`, `openmls_traits`, `openmls_libcrux_crypto` și graful lor, la versiuni exacte (ADR-40)”.
- **Plan, §4 (matricea):** rândul „Relay”, coloana „Nu vede”: „apartenență la canale” devine „apartenență la canale (în afara co-apariției, L8-C2)”.
- **STATUS, rândul Fazei 5:** „autentificare Noise între relay-uri și convergență de date (Faza 10)” devine „… (numerotarea spec v2.0; nealocat în planul v2.1)”; rândul „Faze 10–18”: Faza 10 „design propus 2026-09-25”.
- **`docs/adr/README.md`:** o secțiune „Propuse (Faza 10)” cu ADR-40 … ADR-43. **ADR-13:** notă „punctul „primul client care observă pragul” e retras de ADR-42; primitivele Fazei 10 sunt rolurile, scoaterea, evacuarea, evidența sponsorilor și simularea pragului”. **ADR-04:** notă „pseudonimul e stabil pe viața canalului (ADR-43)”. **ADR-12:** notă „canalele rămân pe suita clasică 0x0003 până la îndeplinirea condițiilor din design Faza 10 §4.4”.

### B.5 Erate spec

- Anexa A, MLS: „OpenMLS 0.8.x baseline” → „OpenMLS 0.9.0 cu furnizorul libcrux 0.4.0 (ADR-40)”.
- §8, `posts`: „authenticated author identity” → „pseudonimul autorului în canal (ADR-04, ADR-43)”.
- FR-5.5: TTL-ul implicit de 90 de zile nu se aplică blob-urilor DM și de canal, guvernate de ADR-27 și ADR-32.

---

## Appendix C: Evidence — verified vs assumed

| # | Claim | Status | Source / check |
|---|---|---|---|
| E-1 | OpenMLS 0.9.0 (2026-08-25) is the newest version; MIT | **verified** 2026-09-25 | crates.io API |
| E-2 | Licences of openmls, traits, libcrux provider, memory storage (MIT), `tls_codec` (Apache-2.0 OR MIT), `hpke-rs*` 0.7.0 (MPL-2.0) | **verified** | local `Cargo.toml` of each crate |
| E-3 | `forbid(unsafe_code)` outside tests; MSRV 1.91; Android built but not tested upstream | **verified** | `om:src/lib.rs:142`; `Cargo.toml`; `README.md:34-47` |
| E-4 | Four advisories and their fix versions; GHSA-rrmv is pre-authentication | **verified** | GitHub advisories page and GHSA-rrmv page |
| E-5 | `create_message` refuses while the proposal store is non-empty; `is_operational` refuses while a commit is pending | **verified** | `om:src/group/mls_group/application.rs:92-94`; `mod.rs:1115-1121` |
| E-6 | RFC 9420 §12.4 lets a committer include its own new proposals by value; §15.2 requires handshake changes applied before new application messages (no pending-proposal ban) | **verified** | RFC 9420 text |
| E-7 | Clock sites at `past_secrets.rs:80,105,234,254`, `lifetime.rs:66,88`; `Lifetime::init` public; KeyPackage maximum range 84 d + 1 h | **verified** | local sources |
| E-8 | Default wire-format policy pure ciphertext; default past-epoch policy `MaxEpochs(0)`; sender ratchet default (5, 1000) | **verified** | `config.rs:57-72, 642-645`; `sender_ratchet.rs:61-62` |
| E-9 | `StorageProvider` has 72 methods; `MlsGroup::load` exists; `swap_members`, `export_secret`, `epoch_authenticator`, `delete_past_epoch_secrets`, `CommitBuilder::create_group_info_with_extensions`, `propose_adds`, `propose_removals`, `force_self_update` exist | **verified** | local sources |
| E-10 | The libcrux provider's randomness is an HMAC-DRBG seeded and reseeded from `SysRng`; `hpke-rs-libcrux` seeds ChaCha20 from `SysRng` | **verified** | `crypto.rs:14-58`; `hpke-rs-libcrux/src/lib.rs:360-369` |
| E-11 | X-Wing suites 0x004D and 0x004F in `openmls_traits` 0.6.0, both mapped to `XWingKemDraft6`; the provider lists 0x0001, 0x0003, 0x004D | **verified** | `types.rs:449-472, 789-793`; `crypto.rs:88-96` |
| E-12 | draft-ietf-mls-pq-ciphersuites-06 state and TBD code points; X-Wing -11 Independent Submission, value 25722 requested; draft-ietf-mls-extensions-10 "Waiting for Implementation" | **verified** 2026-09-25 | IETF datatracker |
| E-13 | RFC 9750 §5.2.2 tie-breaking, §5.3 external joins and PCS, §6.7 history, §8.2.2 idle eviction | **verified** | RFC 9750 (summarised through the fetch tool; wording to be re-read in S0) |
| E-14 | Object sizes of §5.7 and §4.1 | **measured** by the research probe (host, one run, loaded machine); **not** with GHOST's extensions | scratchpad `p10mls/mlsscale/run-{20,100,1000}.txt` — S0 re-measures in-repo (V10-4) |
| E-15 | Library size delta +2.68–2.88 MB (arm64-v8a), +3.27–3.32 MB (x86_64) | **measured** in a probe, not in `libghost_client_net.so` | `p10mls/sizeprobe*` — V10-3 |
| E-16 | The relay's `put`, `get` (week-floored `uploaded_at` for bearer reads), credential v3 kinds and `RegisterKey` serve channels unchanged | **verified** by reading code | `relay/crates/storage/src/lib.rs:314-420`; `node/src/lib.rs:463-469`; `relay.proto:129-166` |
| E-17 | `Consumer.CHANNEL`, `Inbox.defer` (≤ 7 d), `maxReadPairs = 64`, `FETCHED_CAP = 256`, `QUORUM = 2`, `CURRENT_VERSION = 5`, the v1 channel tables, `capability_source` CHECK | **verified** | `Types.kt:84-86`; `StoreLimits.kt`; `TrafficPolicy.kt:50`; `Schema.kt:120,180-210,852-853` |
| E-18 | ADR-04 derivation in Kotlin with a length-prefixed `channel_id` | **verified** | `KeyDerivation.kt:24-30` |
| E-19 | The bootstrap extension reaches the Welcome's GroupInfo | **assumed** | V10-8 (fallback defined) |
| E-20 | Deterministic native outputs under the host `getrandom` backend with `rayon` at one worker | **assumed** | V10-6 |
| E-21 | Every commit at the class caps fits the floor with GHOST's extensions | **assumed** from interpolation | V10-4 |
| E-22 | Adapter cost acceptable on low-end devices | **assumed** (host only; 15–25× factor estimated in F9) | V10-5, V10-10 |
| E-23 | The libcrux primitives added by the provider build portable-only | **assumed** | V10-7 |
| E-24 | The WG test vectors pass in OpenMLS 0.9.0's KAT tests at the tag | **assumed** (OpenMLS ships them in `openmls/test_vectors`, per the testing research) | S2 (`mls-vendor-tests`) |
| E-25 | SRLabs v1.2 finding texts (S1-3, S0-1) | **not re-read** in round 10a (F9 and the research record them) | S0 re-reads the report |

---

## Appendix D: Sources (accessed 2026-09-25 unless stated)

**Repository (worktree `p10-design` at `f244b80`).** `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`; `output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf` (text via `pdftotext`); `docs/adr/ADR-04`, `-12`, `-13`, `-19`, `-25`, `-27`, `-30`, `-32`, `-35`, `-36`, `-37`, `README.md`; `docs/THREAT_MODEL_v2.1.md`; `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`; `docs/STATUS.md`; `ghost/test-harness/privacy/INVARIANTS.md`; `docs/design/faza7-sync-engine.md`, `faza8-issuer.md`, `faza9-dm.md`; `ghost/android/storage/.../Schema.kt`; `ghost/android/identity/.../KeyDerivation.kt`, `DerivationLabels.kt`; `ghost/android/sync/.../api/*.kt`, `store/StoreLimits.kt`, `engine/TrafficPolicy.kt`; `ghost/protocol/relay/v1/relay.proto`; `ghost/relay/crates/storage/src/lib.rs`, `node/src/lib.rs`; `ghost/Cargo.toml`, `ghost/deny.toml`, `ghost/client-core/{dm,dm-host,net}/Cargo.toml`.

**Crate sources (local cargo registry).** `openmls-0.9.0`, `openmls_traits-0.6.0`, `openmls_libcrux_crypto-0.4.0`, `openmls_memory_storage-0.6.0`, `hpke-rs-0.7.0`, `hpke-rs-crypto-0.7.0`, `hpke-rs-libcrux-0.7.0`, `tls_codec-0.5.0`, `libcrux-hmac-drbg-0.0.1`, `rayon-core-1.13.0`.

**Probes (scratchpad, not repository code).** `p10mls/mlsscale` (sizes and host timings at 20, 100, 1 000 members, suites 0x0003 and 0x004D); `p10mls/sizeprobe`, `sizeprobe2` (stripped Android `cdylib` sizes, cargo-ndk 4.1.2, NDK 30).

**External.**
- OpenMLS on crates.io: https://crates.io/api/v1/crates/openmls
- OpenMLS security advisories: https://github.com/openmls/openmls/security/advisories ; GHSA-rrmv-c79f-cf5r: https://github.com/openmls/openmls/security/advisories/GHSA-rrmv-c79f-cf5r
- OpenMLS CHANGELOG: https://raw.githubusercontent.com/openmls/openmls/main/CHANGELOG.md
- RFC 9420 (MLS): https://www.rfc-editor.org/rfc/rfc9420.txt
- RFC 9750 (MLS Architecture): https://www.rfc-editor.org/rfc/rfc9750.html
- RFC 9180 (HPKE): https://www.rfc-editor.org/rfc/rfc9180.html (cited, not re-fetched)
- draft-ietf-mls-pq-ciphersuites: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/
- draft-ietf-mls-extensions: https://datatracker.ietf.org/doc/draft-ietf-mls-extensions/
- draft-connolly-cfrg-xwing-kem: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
- MLS WG test vectors: https://github.com/mlswg/mls-implementations/tree/main/test-vectors (from the testing research; not re-fetched)
- TreeKEM DY* analysis, eprint 2025/410: https://eprint.iacr.org/2025/410 (from the testing research; not re-fetched)
- mls-rs on crates.io: https://crates.io/api/v1/crates/mls-rs (from the research; not re-fetched)
