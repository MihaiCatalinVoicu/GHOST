# GHOST Phase 8: Entitlement Issuer and Client Entitlement — Final Design

| Field | Value |
|---|---|
| Status | **Approved for implementation** (owner, 2026-09-12: "Merg pe recomandările tale. Continuă"), revised after the adversarial design review. The Q1–Q24 defaults of §17 apply, with Q20 as revised in its row (a stagenet-only schedule key for the alpha; the K1 ceremony with the real offline key is required before any mainnet ES). ADR-22 … ADR-26 are "propus, aplicat" (the ADR-17/18/19/20 practice): they are applied by this design and decided by the owner. |
| Review | The crypto, privacy, money and build reviews produced 49 findings; all were confirmed (some only in part, some duplicates). **§19 lists the normative corrections; where §19 and an earlier section disagree, §19 wins.** Local fixes are also made in place, marked "(§19.n)". |
| Date | 2026-09-12 |
| Phase | 8 (plan §6.2): "Entitlement issuer (Rust): blind signatures, `monero-wallet-rpc` view-only, invite tokens, referral ledger, payout în loturi; client `entitlement`" |
| Depends on | Phase 3 (`android/identity`), Phase 4 (`android/storage`), Phase 5 (relay), Phase 6 (`client-core/net`), Phase 7 (`android/sync`, schema v2, ADR-20) |
| Exit gate | "teste negative: reuse, expirat, forjat, perioadă greșită; test de unlinkability (jurnalul issuer-ului nu se poate uni cu nullifier-ele relay-urilor)" |
| Basis | The judged winner "security-first" (strongest privacy under AD-1). This version grafts twelve elements from "delivery-first" and "operations-and-correctness", decides the fifteen conflicts the judge listed, and fixes every error the judge found (§0.3). |
| ADR impact | **ADR-22 … ADR-26 (propus, aplicat)**, drafts in Romanian in Appendix A. They record 14 deviations (§0.5) from ADR-02, ADR-05, ADR-11, ADR-19 (addendum), ADR-20 (point 1), plan Annex A/B, `allowed-observables.json` and the supply-chain gates. ADR-21 is taken by the parallel resolved-classpath task. |
| Sources | Spec v2.0 PDF amended by Master Plan v2.1 (ADR-02, ADR-05, Annex A/B/C); ADR-01 … ADR-20; THREAT_MODEL_v2.1 (AD-1, AD-3, AD-8, AD-12, S2, S13, §6); LIMITE L1, L2.1, L4; INVARIANTS T1–T21; `allowed-observables.json`; the Phase 7 design; research reports R-monero ("RM §n"), R-code ("RC Gn"), R-privacy ("RP §n", rules R1–R10); the three candidate designs and the judge verdict. Appendix D separates what was verified from what is assumed. |

---

## 0. Summary

### 0.1 Decisions

| # | Decision | Issue | Plan alignment |
|---|---|---|---|
| D1 | **Token = Privacy Pass type 0x0002** (RFC 9578 §6: `token_type‖nonce‖challenge_digest‖token_key_id‖authenticator`, 354 bytes), signed with **RSABSSA-SHA384-PSS-Deterministic** (RFC 9474), RSA-2048, e = 65537. Public metadata is bound by **one key per (kind, epoch)**: ACCESS (ISO week), INVITE (4-week epoch), CREDIT (13-week epoch). No partially blind RSA. | I1 | ADR-02 ("RFC 9474 sau Privacy Pass") |
| D2 | **The client builds the TokenChallenge.** For access tokens `origin_info` names a **relay slot** of the Entitlement Schedule, so a token is valid at exactly one relay (no cross-relay double spend, no relay↔relay nullifier join). `redemption_context` binds kind and epoch a second time. **Nullifier = SHA-256("ghost/v1/nullifier" ‖ token_input)**, always computed by the verifier. | I1, I6 | Annex B "împărțire între relay-uri" made mandatory |
| D3 | **Split implementation, no new external crate in the Android library.** Clients and relays do public-key work only: EMSA-PSS on `sha2`, blinding and unblinding on `num-bigint-dig`, every signature verification by **`ring`** (`RSA_PSS_2048_8192_SHA384`), all already allowlisted. The issuer signs through a `Signer` trait whose default is the RFC co-author's **`blind-rsa-signatures` =0.17.2** (on `rsa` 0.10.0-rc.18 / `crypto-bigint` 0.7.5), **confined to the issuer graph** and pinned by a new gate. Signing is payment-gated, fault-checked by GHOST code, and replied on a 2 s quantum. Fallback signers are held in reserve (Q8). | I2 | CP-09 (standard with an existing implementation) |
| D4 | **Seed-derived deterministic blinding.** Each issuance flow persists one 32-byte CSPRNG seed; nonce, PSS salt and blinding factor r of every position are HKDF outputs over (kind, epoch, slot, position), r by rejection sampling. Retries are byte-identical by construction; the write-ahead is the seed plus a frozen layout, not thousands of inverse rows; Kotlin never sees r, salts, nonces, blinded messages or blind signatures. | I5, I10 | graft from "delivery" |
| D5 | **Key consistency by construction.** Every key, price, constant and the relay slot table live in one offline-signed, append-only **Entitlement Schedule (ES)**, compiled into the reproducible native library and loaded by every relay from its configuration. **There is no network path for keys**: no `IssuerKeys`, no `GetConfig`; no issuer response carries a key id, price, period or constant. | I3 | ADR-02 "rotația cheilor publicată în manifest"; Phase 14 folds the ES into the release manifest |
| D6 | **Key well-formedness proof** for every ES key: 8 e-th roots of hash-derived values (soundness ≤ 65537⁻⁸ ≈ 2⁻¹²⁸) proving x ↦ x^e permutes Z_n^\*, verified by clients and relays. Blindness then holds against a signer that chose its own key, and the final signature is unique, so it cannot carry a tag. | I3, I9 | answers RP Q-P8 now instead of Phase 15 |
| D7 | **Grid and product.** Access epochs are ISO weeks. One product, the **pack**: the current week plus the next 4, **16 access tokens per (relay slot, week)**, 2 invite tokens, and 1 credit token when paid in XMR. Counts are identical for every buyer; the price is public (ES) and changes only at 13-week boundaries. The client chooses the base week; the issuer only validates it. | I5, I9 | ADR-02 "perioada zi/săptămână" |
| D8 | **Issuance protocol.** The client picks a 32-byte `claim_key` and sends only its hash with `RequestInvoice` (idempotent by that hash). `BlindSign` carries the key (bearer proof) and a **fixed-layout** blob whose positions imply kinds and epochs; it doubles as the payment poll. The issuer stores only a **request digest**: an identical retry is re-signed byte-identically, a different request is refused in-band (**no double issuance, no signatures at rest**). An **append-only `issued.journal`** (fsync before the redb commit) makes a snapshot restore safe. | I5, I11 | Annex A with the poll folded into `BlindSign` |
| D9 | **Monero.** View-only `monero-wallet-rpc` v0.18.5.1 pinned by SHA-256, digest auth (`md-5`), own `monerod` over Tor, a **pre-created subaddress pool** so `RequestInvoice` never waits on the wallet, a **stateless scanner** that recomputes every open invoice each tick (reorg-safe), **EXPIRED only from a synced view**, 10 confirmations, `unlock_time = 0`, not `double_spend_seen`, heights instead of wall-clock times, 720 blocks (≈ 24 h) to be seen plus 2 160 blocks (≈ 72 h) of grace, underpay top-up, overpay kept, no refunds. The client recomputes the amount from the ES, validates the subaddress and builds the `monero:` URI itself. | I4 | ADR-02, RM §0–§9 |
| D10 | **Relay redemption.** New `RedeemToken(token, namespace_id, request_id)` RPC minting a **write capability v2** (98 bytes: v1 layout plus a 16-byte **deterministic serial** `HMAC(relay_key, "ghost/v1/cap-serial" ‖ period ‖ nullifier)[0..16]`), quota 256 MiB, expiry = end of the token's week + 1 h. A week's tokens are accepted from 24 h before it starts until 1 h after it ends. **Nullifiers are persisted** in `nullifiers.redb` as `(period ‖ nullifier) → 16-byte binding tag`, committed before minting; an identical retry, even after a restart, gets the identical capability. Every response carries `relay_period_id`. | I6 | **deviates** from ADR-11/ADR-02 "nullifier în memorie" (ADR-25) |
| D11 | **Read capabilities (LIMITE L2.1 #2, owed by Phase 8).** Tokens never buy per-client read capabilities. Target: **shared, hash-registered read keys per (namespace, epoch)**, specified here and implemented with their first consumers (Phase 9 inbox, Phase 10 channels). Interim: a READ need is met by redeeming a write capability (write grants read). | I6 | Annex B "capabilitate de citire"; LIMITE L2.1 #2 |
| D12 | **Invites.** **Invite v2** (538 bytes, 876 characters, one QR at version 21-L) carries a real invite token, a **per-invite** signing key derived from the seed with an index, and a per-invite **drop** (namespace, 3 relay slots, X25519 key) for referral credit; v1 is refused. **`RedeemInvite` grants a trial**: blind access tokens for the current and next week, 8 per slot per week, under the ordinary access keys, so onboarding is funded by the invite and not by a payment. | I7, I9 | ADR-05; deviations in ADR-23/24 |
| D13 | **Referral without a referral identifier at the issuer.** Every XMR-paid pack yields exactly 1 blind **credit token** worth 10 % of the pack price. An invited client sends the credit of its first XMR pack, sealed, to the inviter's drop; all other credits stay with the payer (the self-referral discount). A received credit is first exchanged for a fresh blind one (`RefreshCredit`, §19.8). Credits pay for packs (credits whose value covers the price: 10 at an unchanged price) or are claimed for XMR (`ClaimPayout`); a credit is accepted for 52–65 weeks (§19.8). Payouts: signed batch → operator workstation with its own view wallet → air-gapped signer, one recipient per transaction, random broadcast. **The 10 % cap holds by construction.** | I8 | **deviates** from ADR-02 "commitment creditat la fiecare plată" (ADR-24) |
| D14 | **Issuer contacts only in quiet runs.** A fixed 1/8 of periodic-job runs, drawn from client randomness alone, touch no relay; all automatic issuer calls happen in them, **at most one call per quiet run**, each on a fresh `IsolationScope::IssuerFlow([u8;16])`. Declared exceptions: `RedeemInvite` at onboarding and the optional buttons "get invoice now" and "check now" (STANDARD mode only). New pack tokens become eligible at an activation slot. | I9 | **amends** ADR-20 point 1 (ADR-23) |
| D15 | **Error surface.** No new client error category: issuer gRPC statuses map onto the existing 20 (`for_issuer`), and protocol-meaningful outcomes (`REPLAYED`, `WRONG_PERIOD`, `OTHER_REQUEST_ISSUED`, `CREDITS_SPENT`) travel **in-band** in responses and in packed JNI result bytes. `ErrorPolicyTest` stays at 21. | I10 | graft from "delivery" |
| D16 | **Android `:entitlement`.** Pure-JVM engine behind ports; **schema v3** (9 tables, 13 triggers, fail-closed guard dropping the unused v1 `entitlement`/`referral`); the engine is the single **`SessionParticipant`** of the Phase 7 `SyncRuntime` (one Tor transport per process); it fulfils `CapabilityNeed`s by redeeming tokens, installing the capability and deleting the token in one transaction. | I10 | ADR-19, ADR-20 |
| D17 | **Issuer service.** Crates under `ghost/issuer/crates/*` (inside the gates' scan scope); tonic gRPC on loopback behind a v3 onion service; redb schema 1 plus `issued.journal`; handlers `*_at(now)`; **no logging at all** (gate extended to `tracing`/`log`) and a fixed-vocabulary `status.json`; `PaymentRail` trait (FCMP++ contingency); private keys only for a sliding window and destroyed once no open obligation references them (at the earliest `end(epoch) + 8 d`, at the latest `end(epoch) + 42 d`, §19.1); offline ceremony and payout tools in `ghost-issuer-ops`. | I11 | ADR-02, ADR-18 |
| D18 | **Exit gate** proved by: negative suites on every verifier; crash-point enumeration on issuer (with `FaultyStore`/`FaultyRail`/`FaultyJournal`, double crashes) and client; T2 with twin-world non-interference on the full Rust system and on the real Kotlin engine (NI-1, NI-2, NI-K), a deterministic join search J1–J10, statistical tests S1–S3 at α = 0.001 plus the absolute bound S4, and 52 mutants that must be caught (23 privacy, 20 issuer/relay, 9 client; §19.16; *53 with 24 privacy since §19.26 point 7 added M22*); an automatic Monero regtest CI job with pinned binaries. | I12 | exit gate |

### 0.2 Guarantees claimed (each has a test in §13)

**Money safety**

| ID | Guarantee |
|---|---|
| MS-1 | **No double issuance.** A paid invoice yields at most one set of token inputs: after the first signed request only a byte-identical request is served, with byte-identical signatures. This survives crashes on either side and an issuer restore from a snapshot (journal replay). |
| MS-2 | **No issuance without value.** Access, invite and credit tokens are signed only for an invoice with credited ≥ amount (≥ 10 confirmations, `unlock_time = 0`, not `double_spend_seen`, mined before `grace_height`) or paid by 10 unspent credits. Trial tokens are signed only against an unspent invite token. |
| MS-3 | **No double spend.** An access token is redeemed at most once: at one relay slot (challenge binding), once per slot across restarts (persisted nullifiers). Invite and credit tokens are redeemed at most once at the issuer (nullifiers kept for the whole acceptance window, journaled). |
| MS-4 | **Referral ≤ 10 % of XMR revenue by construction** (§9.6). |
| MS-5 | **Spend key never online.** Issuer and payout workstation hold view keys only; signing happens on an air-gapped wallet. |
| MS-6 | **No silent loss after payment.** A crash on either side never loses a paid invoice's tokens while the client keeps retrying within the retention window (confirmed-unissued invoices kept 30 days); every private key an open invoice's layout references stays loaded until that invoice is purged (§19.1). Client-side issuance state is write-ahead. |
| MS-7 | **Reconciliation** (THREAT_MODEL S2): tokens signed = f(packs, trials); for every week w, the sum over all slots of relay redemptions ≤ the ACCESS tokens signed for w (the slot of a token is a blinded client choice, so per-slot counts are not an invariant, §19.3); the workstation's independent view wallet bounds the value received and the cumulative payouts (§19.7). |
| MS-8 | **Idempotent redemption.** An identical `RedeemToken` retry yields the identical capability, also after a relay restart; any other reuse is `REPLAYED`. |

**Privacy**

| ID | Guarantee |
|---|---|
| P-1 | **Blindness for every accepted key.** With a well-formed key (D6) and r uniform in Z_n^\*, the blinded message is uniform and independent of the token. With r derived from a per-flow seed (D4) this holds computationally, under the PRF security of HMAC-SHA-256; the seed is deleted at finalization. |
| P-2 | **Key consistency.** Every client and every honest relay accepts exactly one key per (kind, epoch): the one in the signed ES built into the reproducible release. |
| P-3 | **Non-interference (R1).** Every byte and instant a relay observes is a function of client randomness, public context and relay state only. Issuer inputs within one declared leak cell change nothing a relay sees (NI-1, NI-K). |
| P-4 | **No join key** between the issuer's complete view and the relays' complete views, also after hashing, key derivation, XOR, truncation, encoding and RSA transforms (J1–J8). |
| P-5 | **No statistical link beyond the declared leak L** (S1–S3, α = 0.001). |
| P-6 | **No referral graph at the issuer**: no referral identifier ever reaches it. A credit received from an invitee is known to that invitee (and, under AD-1, may have been minted by the operator), so it is exchanged for a fresh blind credit in an isolated call before any use (`RefreshCredit`, §19.8); the refresh call itself is the declared residue E17. |
| P-7 | **Issuer flow isolation and contact discipline**: no two issuer flow instances share a circuit; no automatic issuer call happens during a relay session; at most one issuer call per quiet run; the pattern of quiet runs is independent of issuer state (J6, J9, S3, NI-2). |

### 0.3 What changed from the base design

**Grafts (judge list, all adopted)**

| # | Graft | Source | Where |
|---|---|---|---|
| G-1 | New Rust crates live under `ghost/issuer/crates/*`, which `scripts/gates/common.sh` `rust_src_files` already scans (`relay`, `issuer`, `client-core`), instead of `ghost/crypto/…` and `ghost/entitlement/`, which no gate would scan. | delivery | §5.1, §14 |
| G-2 | Seed-derived deterministic blinding (one seed per flow, HKDF per position, r by rejection sampling); frozen/write-once triggers apply to the seed and layout. | delivery | §2.6, §11.3 |
| G-3 | Issuer outcomes mapped onto existing categories; `REPLAYED`, `WRONG_PERIOD`, `OTHER_REQUEST_ISSUED` in-band. `ErrorPolicyTest` stays at 21. | delivery, operations | §5.7 |
| G-4 | J9: a deterministic contact-schedule check; a separate `redeem.txt` conformance vector file instead of widening `relay_semantics.txt` (avoids RC G19 churn). | delivery | §10.8, §13.4 |
| G-5 | The `rsa` 0.9.10 hazmat `rsa_decrypt_and_check` path (blinding + re-encryption check, verified in the local registry) documented as a `Signer` fallback; a fixed reply quantum for `BlindSign`/`RedeemInvite` for whichever signer. | delivery | §2.7, §2.8 |
| G-6 | Append-only `issued.journal` (fsync before the redb commit, pruned after the re-serve window); restore = snapshot + journal replay. Extended here to invite, credit and claim records, because a snapshot restore would otherwise also re-open credit double spends. | operations | §6.3 |
| G-7 | Persisted relay nullifiers `(period ‖ nullifier) → 16-byte binding tag` and a deterministic mint, combined with capability v2 through a deterministic serial. Replaces the in-memory re-serve map that lost honest ambiguous retries after a restart. | operations | §10.3–§10.5 |
| G-8 | Monero hygiene: pre-created, locally validated subaddress pool with a refill job and startup reconciliation of `highest_minor` with `get_address`; stateless scanner recomputation; EXPIRED only from a synced view; purge of confirmed-but-unsigned invoices with a counter. | operations | §7 |
| G-9 | `relay_period_id` in every redeem response (R9 clock source); private-key destruction at `end(epoch) + 8 d`; sealed per-epoch key files with `ring`'s ChaCha20-Poly1305 (no new AEAD crate); runbooks K1–K4, B1, M2, O1. | operations | §3.3, §6.8, §10.2 |
| G-10 | Issuer crash harness (`FaultyStore`, `FaultyRail`, `FaultyJournal`, reopen the same files, double crashes during recovery), issuer and client mutants merged with the base money mutants; `SessionParticipantTest` (a participant cannot delay or suppress read-lane events, T19); `EntitlementSchemaIntrospectionTest`. | operations | §13.2, §13.5 |
| G-11 | `rust-crypto-pins.sh` (exact versions of `rsa`, `crypto-bigint`, `blind-rsa-signatures`, `num-bigint-dig`, `ring` per graph); `rust-feature-policy.sh` queries `rsa@<version>`; ops-status fixed-vocabulary unit test. | operations | §14.1 |
| G-12 | SQL-level anti-re-blind and binding guards (frozen purchase, delete only when terminal, a reserved token keeps relay, namespace, token and request id). | operations | §11.3 |

**Conflicts decided**

| # | Conflict | Decision | Why |
|---|---|---|---|
| C-1 | Blind-RSA implementation | Split (D3): public-key work on allowlisted crates + `ring`; issuer `Signer` default `blind-rsa-signatures` =0.17.2 confined to the issuer graph; fallbacks in-house `crypto-bigint`, then `rsa` 0.9.10 hazmat (Q8) | No new external crate reaches the APK; the issuer uses the reference implementation (CP-09); the pre-release `rsa` never reaches clients or relays; the reply quantum and payment gate apply to any signer |
| C-2 | Relay nullifiers persisted vs memory | Persisted with binding tag and deterministic mint (ADR-25) | With week periods a restart would otherwise reopen replay for up to 7 days (RC G2) |
| C-3 | Capability format | v2 with a deterministic HMAC serial | Distinct quota ledgers per token (fixes the shared-ledger defect of a v1 deterministic mint) and idempotent across restarts |
| C-4 | Issuer contact scheduling | Quiet runs only; S3 stays in the gate; J9 added | The only option that defeats co-presence; NI-1/NI-2 hold exactly; cost 1/8 fewer background syncs |
| C-5 | Onboarding grant | Trial: current + next week, 8 per slot per week, 2 invites per pack | Removes the payment → new-identity link; abuse bounded at 40 % of paid usage (§8.1); the delivery starter (≈ +150 %) was unbounded, the operations variant kept the link |
| C-6 | Referral mechanism | Credit tokens + sealed drop; first XMR pack of an invitee credits the inviter; no payout address in invite links | No referral identifier at the issuer; an address in a link exposes the inviter's wallet to anyone who sees it and groups credits at the issuer; the economics change is an explicit ADR-02 deviation (Q5) |
| C-7 | Key and parameter distribution | No network path; the ES is compiled into the native library (`include_bytes!`) and loaded by relays from their configuration | A `GetConfig` accepting newer signed configs is a per-client tagging channel under AD-1, who holds the offline key |
| C-8 | Base week | Client-chosen (its trusted-clock week); the issuer validates and never supplies it | An issuer-chosen `first_period` would select keys and coverage (R1 violation) |
| C-9 | Acceptance window | `[start(p) − 24 h, start(p+1) + 1 h)`; 48 h early is Q15 | Keeps "perioadă greșită" meaningful; at most two weeks of nullifiers live at once |
| C-10 | Token allocation across relays | 16 per ES slot per week, slot indirection, S ≤ 8 for the alpha, `access_per_slot` tunable in the ES | Tokens survive relay replacement within a slot; the split is invisible to the issuer |
| C-11 | READ needs before Phases 9/10 | Redeem a write capability | Tokens never buy per-client read capabilities; shared read keys decided now |
| C-12 | Key well-formedness | Permutation proof in the ES now | AD-1 runs the key ceremony; verification costs 8 modexps with e = 65537 per key |
| C-13 | Invite signing key | Derived per invite index from the seed; new derivation vectors | Restorable; matches ADR-05 "cheie efemeră (derivată)" |
| C-14 | T2 statistics | S1–S3 + J9 + NI-K on the real Kotlin engine | S3 is consistent with quiet runs; J9 bounds the schedule exactly |
| C-15 | Invoice windows | 720 blocks (≈ 24 h) to be seen + 2 160 blocks (≈ 72 h) grace | Quiet-run latency means the invoice may reach the user hours after the intent |

**Errors fixed**

| # | Error (judge) | Fix |
|---|---|---|
| E-1 | RFC 9474 Appendix A vectors were claimed to use a 2048-bit key; the modulus is 4096-bit (1 024 hex characters). A 2048-only API cannot replay them. | The arithmetic in `ghost-blind-rsa` is generic in the modulus length; the 2048-bit restriction lives only in the ES and type-0x0002 parsers. RFC 9474 Appendix A (4096-bit, RSABSSA-SHA384-PSS-Deterministic) is replayed through the generic raw functions; the 5 RFC 9578 Appendix A.2 vectors (2048-bit) are replayed through the production type-0x0002 API (§2.9). |
| E-2 | Crates at `ghost/crypto/blind-rsa` and `ghost/entitlement` escape `rust_src_files`. | G-1: all under `ghost/issuer/crates/*`, plus a self-test fixture proving nested crates are scanned (§14.1). |
| E-3 | A daily redb snapshot restore without a journal allows double issuance (MS-1). | G-6: `issued.journal`, generalized to every irreversible issuer event (§6.3). |
| E-4 | (operations) `GetConfig` accepting newer signed configs reopens key tagging. | No config RPC at all (C-7). |
| E-5 | (operations) Issuer-chosen `first_period` selects keys. | Client-chosen base week (C-8). |
| E-6 | (operations) Polls inside relay sessions would fail its own S3. | Quiet runs only (C-4); S3 is consistent with the schedule. |
| E-7 | (delivery) Starter bundle abuse unbounded (+150 %). | Trial counts with a 40 % bound (C-5, §8.1). |
| E-8 | (delivery) A deterministic v1 mint makes same-hour writers share one quota ledger. | Capability v2 with a per-nullifier serial (C-3). |
| E-9 | (delivery) QR version for an ~890-character link. | Our link is 876 characters; byte-mode capacity at 21-L is 929, at 20-L 858, so version 21-L (§8.2). |

### 0.4 Issue → section map

| Issue | Sections | Short answer |
|---|---|---|
| I1 scheme, metadata, key size, wire, nullifier | §2.1–§2.4 | Privacy Pass 0x0002, RSA-2048, key per (kind, epoch), client-built challenge bound to a relay slot, verifier-computed nullifier |
| I2 implementations, Marvin, vectors, dependencies | §2.5–§2.10 | public side on allowlisted crates + `ring`; issuer `Signer` = `blind-rsa-signatures` pinned to the issuer graph; RFC vectors (2048 and 4096) + differential tests |
| I3 key management and consistency | §3 | offline ceremony, ES in the native library and relay config, append-only, permutation proofs, sealed per-epoch keys, destruction |
| I4 Monero | §7 | R-monero rules plus pool, stateless scanner, synced-view expiry, client-side price and URI checks |
| I5 issuance protocol | §4, §5 | claim-key bearer, fixed layout, seed-derived blinding, deterministic re-serve, journal, fixed counts, weekly epochs |
| I6 relay redemption, read capabilities | §10 | `RedeemToken`, capability v2, persisted nullifiers with binding tags, `relay_period_id`, shared read keys decided |
| I7 invites | §8 | Invite v2, per-invite keys, trial, genesis unchanged, issuer invite nullifiers |
| I8 referral and payouts | §9 | credit tokens, sealed drop, discount or cold-signed XMR payout |
| I9 linkability | §1, §12, §19 | rules R1–R10, quiet runs, activation slots, declared leak L1–L7, residues E1–E19 (LIMITE L6) |
| I10 Android | §11 | schema v3, state machines, crash safety, `SessionParticipant`, redeem lane, JNI |
| I11 issuer service | §5, §6 | crates, redb + journal, no logging, config, infra, runbooks, failure modes |
| I12 tests and slices | §13–§15 | negative suites, crash enumeration, T2, regtest job, gates, slices S0–S12 |

### 0.5 Deviations from approved documents (each recorded in an ADR, "propus, aplicat")

| # | Deviation | From | ADR |
|---|---|---|---|
| X1 | Relays **persist** nullifiers (weeks whose window is open, at most two at once) instead of "în memorie cu TTL" | ADR-11, ADR-02 | ADR-25 |
| X2 | Access period = ISO week; acceptance window `[start − 24 h, end + 1 h)`; the relay's UTC-day `current_period` is replaced | ADR-02 ("zi/săptămână"), relay code | ADR-22, ADR-25 |
| X3 | Referral by **blind credit tokens**: no commitment in the invoice, no preimage claim, no credit "la fiecare plată"; the first XMR pack of an invitee credits its inviter | ADR-02, Annex A, spec FR-6.7, THREAT_MODEL S2 | ADR-24 |
| X4 | Invite payload v2: no `referral_commitment`; adds a drop; per-invite signing key derived with an index | ADR-05 payload list; spec FR-1.x | ADR-24 |
| X5 | `RedeemInvite` grants a **trial** of blind access tokens | ADR-05 (grant unspecified) | ADR-23 |
| X6 | Annex A flow: no `Poll`, no `IssuerKeys`; client-built URI; fixed-layout `BlindSign`; issuer calls only in quiet runs (with declared exceptions); tokens usable from an activation slot | Annex A | ADR-23 |
| X7 | 1/8 of periodic-job runs are **quiet** (no relay sync); `SessionParticipant` API added to `:sync` | ADR-20 point 1 | ADR-23 |
| X8 | Purchases complete in the background: invoice at the next quiet run, tokens hours after payment; invoice payable for 24 h | ADR-02 consequences ("~20 min") | ADR-23 |
| X9 | Capability **v2** (98 bytes) for redeemed write capabilities; v1 stays for CLI-minted ones | ADR-19 addendum | ADR-25 |
| X10 | T1 observables: `result` gains `rejected_token` and `rejected_period`; the capture now emits `nullifier` and `period_id` (already in the schema) | INVARIANTS rule of evolution | ADR-25 |
| X11 | `IsolationScope::Issuer` (unit) replaced by `IssuerFlow([u8;16])`; three new workspace crates in the Android library | ADR-19, T7 allowlist | ADR-22 |
| X12 | A GHOST crate (the issuer) depends on `rsa` 0.10.0-rc.18 through `blind-rsa-signatures`; the `rsa` gate, the `deny.toml` ignore reason and `ci.yml:80` change together; new version-pin gate | `rust-feature-policy.sh:88-97`, `deny.toml:9-22` | ADR-22 |
| X13 | The Monero regtest job runs **automatically** on issuer paths and nightly | plan §6.2 row 8 (open), RC §10 (manual) | ADR-26 |
| X14 | Issuer keeps no logs at all; operator sees only a fixed-vocabulary status file; `issued.journal` is the one append-only file | ADR-02 (operations unspecified) | ADR-26 |
| X15 | Drop sealing uses BouncyCastle X25519 and ChaCha20-Poly1305 (HKDF stays on the platform) (§19.12) | ADR-17 (BouncyCastle for Ed25519 only) | ADR-24 |

### 0.6 What this design deliberately does not do

- **No partially blind RSA** (`draft-irtf-cfrg-partially-blind-rsa`): not an RFC, needs safe primes and derived exponents, fewer implementations. It would save keys, not privacy.
- **No per-client read capabilities bought with tokens** (D11).
- **No refunds, no support channel, no issuer-side invite gate.** A refund needs a sender address or an identity, which Monero hides. Invite-only is a client rule plus the trial incentive (§8.6).
- **No token recovery from the seed.** Tokens are device-local bearer value, lost with the device (declared, E11).
- **No key, price or config RPC.** A client never learns keys, prices or periods from the issuer.
- **No second periodic job and no WorkManager** (ADR-20 unchanged except point 1).
- **No new external crate in the Android library and no new Gradle coordinate.**

---

## 1. Adversary model and the property T2 proves

### 1.1 Who sees what

AD-1 (the operator) controls the issuer, its Monero wallet and node and, in the worst case T2 assumes, **every relay**. It timestamps everything at full precision. AD-3 is the issuer alone; AD-2 one or more relays; AD-8 an attacker with the device database open; AD-12 a seizure of stored data. A3 (Tor resists local observers), A4 (RFC 9474/9578 are sound for well-formed keys) and A5 (Monero hides sender and amount on chain) hold.

The per-step observation table of RP §1.1 is accepted with these changes, which follow from this design:

- step 0 (`IssuerKeys`) disappears;
- step 1 (`RequestInvoice`) runs in a quiet background run by default;
- step 3 (`PollInvoice`) becomes the optional, user-initiated `InvoiceStatus`;
- step 4 (`BlindSign`) runs in a quiet run, typically once;
- step 8 (`RedeemInvite`) returns trial signatures;
- steps 9 and 10 carry credit tokens instead of a commitment or preimage.

### 1.2 Views and declared leak

- **V_I** (issuer view): exact request and response bytes, arrival times and a circuit label per connection; every `monero-wallet-rpc` request and response (for AD-1 the whole view-wallet history); snapshots of every redb table and of `issued.journal` at any time, before deletion.
- **V_R** (relay view): the union over all relays of the same, plus nullifier stores and capture lines.
- **Z** (public context): the ES (keys, proofs, prices, constants, slot table), the grid, slot boundaries, protocol constants and enum values.
- **L** (declared leak), the only information T2 allows to cross from V_I to V_R:
  - **L1** the activation slot (UTC day) of a batch's first eligible use;
  - **L2** the coverage-end week of a pack;
  - **L3** "online at the time of a user-requested immediate issuer call", plus the start time of a trial (`RedeemInvite` at onboarding);
  - **L4** the purchase type (pack in XMR / pack with credits / trial);
  - **L5** "the client was in a quiet run at the time of each background issuer call": at most log2(1/q_eff) ≤ 3 bits per call. The calls of one purchase are linked at the issuer by `invoice_id`, so the bits add up per invoice; the number of calls per invoice is capped independently of issuer answers at 1 `RequestInvoice` + 5 `BlindSign` (usually 2 calls in total, §19.11), so an issuer that lies `AWAITING_*` gains at most 6 linked samples;
  - **L6** the wallet's first-seen time of a payment, which correlates with the payer's relay sessions when the user pays while GHOST keeps a relay session (§19.11, residue E15);
  - **L7** the start time of a purchase the user makes after `ENTITLEMENT_NEEDED`, whose trigger (token exhaustion) relays can observe (§19.13, residue E16).

  Everything else is a T2 failure. Besides the relative tests S1–S3, T2 gates an absolute bound on what L alone allows (S4, §19.16).

### 1.3 T2, precisely (the exit-gate statement)

1. **(a) No join key.** V_I ∩ V_R ⊆ Z, also under the transform set J1–J8 (§13.4).
2. **(b) Non-interference.** V_R is a function of client randomness, user behaviour, Z and relay state. Two worlds that differ only in issuer-side inputs within one L-cell produce byte-identical V_R (NI-1, and NI-K on the Kotlin engine). Two worlds that differ only in client secrets and relay activity produce V_I identical up to the uniformly random blinded bytes (NI-2).
3. **(c) No correlation above threshold.** A learned attacker on V_I ∪ V_R matches relay clusters to invoices no better than the attacker restricted to L (S1, S2, S3 at α = 0.001).
4. **(d) Contact discipline.** The issuer-contact schedule obeys J9 exactly.

(a), (b) and (d) are exact and hold for every seed; (c) is statistical and holds for the pinned seeds. The residue inside L is declared in LIMITE L6 and the UI copy (CP-10).

### 1.4 Why blindness alone is not enough

Blindness removes one join key, the token bytes. The joins that remain under AD-1 (RP §3) and what removes or bounds each:

| Join | Removed or bounded by |
|---|---|
| Timing of first use after a purchase | activation slot (L1); for invitees, removed by trial funding (D12) and by a drop write at a time pre-drawn at activation, independent of purchases (§19.12) |
| Presence samples (issuer calls during sessions) | quiet runs, one call each, drawn independently of purchases (D14) |
| Key tagging and malformed keys | ES in the release plus permutation proofs (D5, D6) |
| Referral graph at the issuer | credit tokens (D13) |
| Circuit sharing | per-flow scopes (R5) |
| Unique amounts, URIs, periods | client-side recomputation from the ES; client-chosen base week |
| Cross-relay reuse | slot-bound challenge (D2) |
| Retries that change bytes | seed-derived blinding, deterministic re-serve, frozen rows (D4, D8) |
| Device clock offsets | trusted clock; issuer-facing periods from the device clock only, with a ±4 h issuer tolerance at week boundaries; relay-supplied time only for relay-facing decisions (R9, §19.4) |

---

## 2. Cryptographic core and token formats (I1, I2)

### 2.1 Token (RFC 9578 §6, type 0x0002), 354 bytes

| Offset | Bytes | Field | Value |
|---|---|---|---|
| 0 | 2 | `token_type` | `0x0002`, big-endian |
| 2 | 32 | `nonce` | seed-derived per position (§2.6); never derived from anything the issuer supplied |
| 34 | 32 | `challenge_digest` | SHA-256 of the TokenChallenge of §2.2 |
| 66 | 32 | `token_key_id` | SHA-256 of the key's SPKI DER (id-RSASSA-PSS, SHA-384, MGF1-SHA-384, saltLength 48), as RFC 9578 prescribes, computed locally from the ES bytes |
| 98 | 256 | `authenticator` | RSASSA-PSS signature (SHA-384, MGF1-SHA-384, sLen = 48) over `token_input` = bytes 0..98 |

Only `authenticator` depends on the key operation. For a well-formed key (§3.2) it is the unique e-th root of `EMSA-PSS-ENCODE(token_input, salt)` for the client-chosen salt, so it carries no issuer-chosen information.

### 2.2 TokenChallenge (built by the client, recomputed by the verifier)

TLS presentation encoding (RFC 9577 §2.1):

```
struct {
  uint16 token_type = 0x0002;
  opaque issuer_name<1..2^16-1>;       // ES.issuer_name, ASCII, e.g. "ghost-issuer-v1"
  opaque redemption_context<0..32>;     // always 32 bytes here
  opaque origin_info<0..2^16-1>;        // see table
} TokenChallenge;
challenge_digest   = SHA-256(TokenChallenge)
redemption_context = SHA-256("ghost/v1/redemption-context" || kind_byte || epoch_id(8, BE))
```

| Kind | kind_byte | Epoch | `origin_info` | Verified by |
|---|---|---|---|---|
| ACCESS | 0x01 | ISO week index | `"relay-slot-NN"` (two decimal digits: the relay's slot in the ES slot table) | the relay the ES lists for slot NN in that week |
| INVITE | 0x02 | 4-week epoch | `"issuer-invite"` | issuer (`RedeemInvite`) |
| CREDIT | 0x03 | 13-week epoch | `"issuer-credit"` | issuer (`RequestInvoice` with credits, `ClaimPayout`) |

Why the client builds the challenge:

- The relay binding sits **inside the blinded message**, so the issuer never learns which relay a token is for (RP V12).
- A token for slot 3 fails `challenge_digest` at every other relay, so one nullifier can never appear at two relays (RP V13, mutant M6).
- `redemption_context` binds kind and epoch for an honest client's token, so such a token cannot be replayed in another context. It does **not** protect against a malicious client if one RSA key appeared under two (kind, epoch) entries: the client builds the challenge inside the blinded message, so only the signing key binds kind and epoch against it. ES rule 2 therefore requires every key id and modulus to be distinct across all entries and against local memory (§19.2).
- `origin_info` names a slot, not an onion host. The capture schema forbids the substring `.onion` (`allowed-observables.json:20`), and a slot survives the replacement of the relay behind it (C-10).

### 2.3 Nullifier

`nullifier = SHA-256("ghost/v1/nullifier" || token_input)` (32 bytes), computed by the verifier (relay or issuer), never read from the wire. The draft field `RedeemInviteRequest.nullifier` is deleted (RP F7).

- Hashing `token_input` rather than the whole token means a second valid authenticator on the same input could not be spent twice; with a well-formed key there is only one anyway.
- The nullifier is a pure function of client randomness and Z, as R1 requires.

### 2.4 Keys: one per (kind, epoch), RSA-2048, e = 65537

**Why RSA-2048.**

- Blindness does not depend on the modulus size: with the permutation property (§3.2) it is independent of RSA hardness, so a future break of RSA-2048 would not retroactively link tokens to payments.
- Unforgeability only has to hold until an epoch's tokens stop being accepted: at most 27 weeks after the key is published.
- Type 0x0002 fixes Nk = 256, so the RFC 9578 vectors and `ring`'s PSS verifier apply unchanged. RSA-3072 would cost about 3.4× per signature and need a non-standard token type.

**Why one key per (kind, epoch), not partially blind RSA.**

- It is the RFC 9474 §6.2 pattern (one key per encoding option).
- Public metadata then costs nothing on the wire and cannot be chosen per token by the issuer.
- A key id at a relay names only (kind, epoch), which is public.

Cost: 52 access keys, 13 invite keys and 4 credit keys per year; about 2.3 KiB each with its proof, so about 160 KiB of ES per year.

### 2.5 Operations and where they run

| RFC 9474 step | Where | Crate and arithmetic | Constant-time requirement | Notes |
|---|---|---|---|---|
| Prepare (identity, Deterministic variant) | client | `ghost-entitlement` | — | RFC 9474 §7.3: the input contains a 32-byte nonce the signer cannot guess, so the Deterministic variant is safe; the key proofs add the well-formed-key condition |
| EMSA-PSS-ENCODE (SHA-384, 48-byte salt) | client | `ghost-blind-rsa` on `sha2` | no secret-dependent branch | salt from the seed derivation |
| Blind: `B = em · r^e mod n`, `inv = r⁻¹ mod n` | client | `ghost-blind-rsa` on `num-bigint-dig` | not constant-time; r is secret only against a **local** observer (residue R13, within AD-8) | r from the seed derivation by rejection sampling, `gcd(r, n) = 1`; `gcd(em, n) ≠ 1` is an error (RFC 9474 §4.2); r and inv never leave Rust |
| BlindSign: `s' = B^d mod n` | issuer | `Signer` trait; default `blind-rsa-signatures` =0.17.2 (`rsa` 0.10.0-rc.18 hazmat `rsa_decrypt_and_check` on `crypto-bigint` 0.7.5, CRT, base blinding, library re-encryption check) | **yes, attacker-chosen B** | GHOST checks `s'^e ≡ B (mod n)` itself (`num-bigint-dig`) before any byte leaves the process; `0 < B < n` enforced; reply on a 2 s quantum (§2.8) |
| Finalize: `s = s' · inv mod n`, then verify | client | `ghost-blind-rsa` (`num-bigint-dig`) + **`ring`** | no | a verification failure refuses the whole response (`malformed_response`, §5.7) |
| Verify | relay, issuer | **`ring`** `RSA_PSS_2048_8192_SHA384` via `RsaPublicKeyComponents` | — (public) | key = ES key for (kind, epoch) |
| Permutation proof: verify | client, relay, issuer | `ghost-blind-rsa` (`num-bigint-dig`) | — | once per ES load, cached by ES digest |
| Permutation proof: generate | offline ceremony | `ghost-issuer-ops` through the `Signer` | yes | `σ_i = ρ_i^d` is a blind signature on a hash-derived value |

Blind signing is deterministic in (key, B), and base blinding does not change the result. So an identical retried request gets identical signatures, which MS-1 and MS-6 rest on (§5.5).

### 2.6 Seed-derived batch derivation (client, Rust, `ghost-entitlement::batch`)

A flow (pack purchase or trial) persists **one** secret for blinding: `seed` (32 bytes from `SecureRandom`, written in SQLCipher before the first send). Everything else is recomputed on demand:

```
prk = HKDF-Extract(salt = "ghost/v1/blind-batch", ikm = seed)                         (SHA-256)
for position j of the layout (kind k, epoch e, slot s or 0xFF), j = 0 .. N-1:
    info_j   = k(1) || e(8, BE) || s(1) || j(2, BE)
    okm      = HKDF-Expand(prk, info_j || "n", 80)      -> nonce_j = okm[0..32], salt_j = okm[32..80]
    r_j      = the first c = 0, 1, ... 255 with R = OS2IP(HKDF-Expand(prk, info_j || "r" || c(1), 256)),
               1 < R < n and gcd(R, n) = 1                (expected <= 2 tries; failure after 256 is an error)
    input_j  = 0x0002 || nonce_j || challenge_digest(k, e, s) || key_id(k, e)
    em_j     = EMSA-PSS-ENCODE(input_j, emBits = 2047, SHA-384, MGF1-SHA-384, salt_j)
    B_j      = I2OSP(em_j * r_j^e mod n, 256)
request   = B_0 || ... || B_{N-1}
digest D  = SHA-256("ghost/v1/blindsign" || invoice_id || request)        (trial: SHA-256("ghost/v1/trial" || N_inv || base_week || request))
finalize_j(s'_j) = s'_j * r_j^{-1} mod n, then ring verify(key(k, e), input_j, s_j)  -> token_j
```

- **Layout.** A pure function of (base week, product) (§4.2), identical under every ES version that covers the base week (slot sets are immutable once covered, §19.2). Kotlin stores those two values (and the ES seq, as information only) and the layout digest `SHA-256("ghost/v1/layout" || (k || e || s) for every position)`; Rust recomputes and compares it before every send and every finalization.
- **Uniformity.** RFC 9474 asks for a uniformly random r. A PRF output keyed by a fresh CSPRNG seed is computationally indistinguishable from uniform, which is how P-1 is stated. The rejection sampling keeps r uniform over its admissible range. Mutants M5a (r = 1) and M5b (r = x²) show the tests notice a regression (§13.5).
- **What the write-ahead becomes.** Seed + layout parameters (§11.3) instead of up to 2 563 rows of token input and inverse. A retry after any crash recomputes the same request; triggers forbid changing seed or layout after the first send (G-12).
- **Who sees what.** The seed is the only blinding secret on the Kotlin side. Blinded messages, blind signatures, nonces, salts, r and inverses exist only inside one JNI call (§11.7).

### 2.7 Implementation choice (I2)

| Option | Private-key path | Status 2026-09-12 | Verdict |
|---|---|---|---|
| **Public side** on `sha2` + `num-bigint-dig` 0.8.6 + `ring` 0.17.14 | none | all already in the Android library and allowlist (`rust-dependency-allowlist.txt` lines for `num-bigint-dig`, `sha2`, `hkdf`, `ring`) | **chosen for clients and relays**: no new external crate in the APK; RFC 9474 blinding is about 150 lines of public-key arithmetic, pinned by vectors and cross-verified by `ring` |
| **Issuer `Signer` = `blind-rsa-signatures` =0.17.2** | `rsa` 0.10.0-rc.18 hazmat `rsa_decrypt_and_check` on `crypto-bigint` 0.7 (constant time is the design goal of that line), with RNG blinding and a re-encryption check | written by an RFC 9474 co-author; depends on a **pre-release** `rsa`; RUSTSEC-2023-0071 lists no patched version; new names `crypto-primes =0.7.0`, `hmac-sha256`, `hmac-sha512`, `ct-codecs`, `derive-new`, `derive_more`, `digest` 0.11, `rand` 0.10 | **chosen as the issuer default**, confined to the `ghost-issuer` and `ghost-issuer-ops` graphs by `rust-feature-policy.sh` and pinned by `rust-crypto-pins.sh` (§14.1); also the differential oracle for the public side |
| In-house constant-time signer on `crypto-bigint` 0.7.5 (CRT + base blinding + fault check, about 400 lines) | constant-time Montgomery exponentiation | stable 0.7.5 (0.7.0–0.7.4 yanked) | **fallback 1** (Q8), if the owner refuses a pre-release RSA crate on the issuer; weaker CP-09 fit (own crypto) |
| `rsa` 0.9.10 hazmat `rsa_decrypt_and_check` (blinding + re-encryption check, `algorithms/rsa.rs:135-150` in the local registry) | `num-bigint-dig`, variable time | RUSTSEC-2023-0071 applies | **fallback 2**, only with every §2.8 mitigation; no new crate at all |
| OpenSSL / BoringSSL raw RSA | constant-time, mature | C supply chain on the issuer, invisible to cargo-audit | rejected (ADR-18 reasoning) |
| `ring` / `aws-lc-rs` for signing | no raw RSA private operation in the safe API | — | not possible for BlindSign; `ring` is used for every verification |
| Kotlin `BigInteger` in production | — | not constant-time; ADR-19 forbids protocol logic in Kotlin | rejected (used only in JVM **tests** as `TestTokenCrypto`) |

**`Signer` trait** (`ghost-issuer::signer`; exactly one implementation in `src/`, fallbacks are designs held in reserve):

```rust
pub trait Signer: Send + Sync {
    /// (kind, epoch) this signer holds; its public key must equal the ES entry (checked at load).
    fn key(&self) -> (Kind, u64);
    /// Deterministic in (key, blinded). Must fail on 0, n and values >= n.
    fn blind_sign(&self, blinded: &[u8; 256]) -> Result<[u8; 256], SignError>;
}
```

The service wraps every `Signer` in `CheckedSigner`, which recomputes `s'^e mod n` with `num-bigint-dig` (an implementation independent of the signer's) and refuses to release a mismatch (`SignError::Fault`, alarm counter `SIGN_FAULT`).

**`ghost-blind-rsa` API** (`#![forbid(unsafe_code)]`, no feature flags; generic in the modulus length, the 2048-bit rule lives in the ES parser):

```rust
pub struct PublicKey { /* n, e */ }                               // from SPKI DER; any length the caller allows
pub fn emsa_pss_encode_sha384(msg: &[u8], salt: &[u8; 48], em_bits: usize) -> Result<Vec<u8>, Error>;
pub fn blind_raw(pk: &PublicKey, em: &[u8], r: &BigUint) -> Result<(Vec<u8> /*B*/, BigUint /*inv*/), Error>;
pub fn finalize_raw(pk: &PublicKey, msg: &[u8], blind_sig: &[u8], inv: &BigUint) -> Result<Vec<u8>, Error>; // verifies with ring
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error>;                                // ring
pub fn check_blind_signature(pk: &PublicKey, blinded: &[u8], blind_sig: &[u8]) -> bool;                    // s'^e == B
pub fn verify_permutation_proof(pk: &PublicKey, proof: &[[u8; 256]; 8]) -> Result<(), Error>;
```

`ghost-entitlement` builds everything type-0x0002-specific on top: `batch::blind(schedule, seed, layout)`, `batch::finalize(schedule, seed, layout, sigs)`, `Token::parse`, `challenge_digest`, `nullifier`, `verify_token(schedule, token, Expect)`.

### 2.8 Issuer signing hardening (independent of the library's timing claim)

1. **Payment-gated oracle.** `BlindSign` signs only for a CONFIRMED invoice with the right claim key (≤ 643 signatures for S = 8), `RedeemInvite` only for an unspent, valid invite token (16·S signatures). An attack needing 10⁵–10⁶ adaptive queries costs hundreds to thousands of paid packs. *(Corrected by §19.27 point 1: `RefreshCredit` is not payment-gated. A refreshed credit is a credit like any other, so a credit holder refreshes one credit in a chain and gets non-adaptive signatures under the CREDIT key for free; the chain is bounded per credit epoch by the paid packs of the epochs around it, not by a payment per query. Adaptive, chosen-B queries still cost one credit each, since a chosen B does not finalize into a new credit.)*
2. **Reply quantum.** `BlindSign` and `RedeemInvite` responses leave at `t_request + Q · ceil(elapsed / Q)` with Q = 2 s (issuer constant, Q18). Over Tor the signing time is visible only at 2 s granularity.
3. **Fault check** before release (RFC 9474 §4.3): `CheckedSigner` refuses any `s'` with `s'^e ≢ B`, which also stops Bellcore-style CRT fault attacks.
4. **Input checks.** Every blinded block is 256 bytes with `0 < B < n` under its position's key.
5. **Marvin, stated precisely** (for the `deny.toml` reason). A blind signer returns `B^d` to whoever asks, so Marvin's decryption-oracle class adds nothing an attacker does not already get. The residual risk is exponent-timing key recovery, which base blinding, the constant-time `crypto-bigint` path, the payment gate and the quantum address. A recovered key forges tokens for one (kind, epoch), and reconciliation (§6.9) shows redemptions beyond what was paid.
6. **Timing evidence (nightly, not a gate).** A dudect-style Welch t-test (10⁵ samples, fixed against random blinded inputs) on `Signer::blind_sign`; |t| > 4.5 opens an issue. *(Implemented by §19.27 point 2: `tests/signer_timing.rs`, workflow `signer-timing.yml`.)*

### 2.9 Test vectors and cross-checks (fixes E-1)

New file `protocol/test-vectors/blind_rsa_pp2.txt` ("one file, several replayers", like `onion_addresses.txt`):

| Section | Content | Replayed through |
|---|---|---|
| `rfc9474-a` | RFC 9474 Appendix A, RSABSSA-SHA384-PSS-Deterministic: p, q, n, e, d, msg, salt, encoded_msg, inv, blinded_msg, blind_sig, sig. **The modulus is 4096-bit** (1 024 hex characters, measured by the judge). | the generic raw functions of `ghost-blind-rsa` (`emsa_pss_encode_sha384`, `blind_raw`, `finalize_raw`, `verify` via `ring`, which accepts 2048–8192 bits) and `blind-rsa-signatures` =0.17.2 directly (its blind signature must equal `blind_sig`). Neither the production `Signer` (fixed to 256-byte inputs) nor the ES parser (2048-bit keys only) replays this section (§19.18). |
| `rfc9578-a2` | the 5 RFC 9578 Appendix A.2 type-0x0002 vectors (2048-bit): skI, pkI, token_challenge, nonce, blind, salt, token_request, token_response, token | the production type-0x0002 path of `ghost-entitlement` (key id, challenge, token parse, finalize, verify) and the production issuer `Signer` (the only RFC evidence for the production signer) |
| `ghost` | GHOST: test ES and keys, seeds → every nonce, salt, r, blinded message and digest; challenge encodings per kind; `redemption_context`; nullifiers; permutation proofs (valid and tampered); layout digests | `ghost-entitlement`, relay verifier, issuer, `client-core` (JNI round trip); the Kotlin `TestTokenCrypto` (JVM tests only) |

Further checks:

- **Differential test** (`ghost-blind-rsa` dev-dependency on `blind-rsa-signatures = "=0.17.2"`, 10 000 random (key, message) pairs): our blind with their sign, their blind with our finalize, all outputs verified by `ring`. Dev edges are excluded from `rust-feature-policy.sh` (`-e normal,build`), so the policy still proves which production graphs contain `rsa` 0.10.
- **Negative crypto tests:** every byte of every field flipped; B = 0, B = n, B > n; e ≠ 65537; 2047- and 2049-bit moduli refused by the ES parser; a key with 65537 | p−1 (the permutation proof must fail); an injected CRT fault (a test-only signer in `tests/`) caught by `CheckedSigner`.
- **`ring` PSS parameters:** `RSA_PSS_2048_8192_SHA384` requires sLen = hLen = 48, which type 0x0002 uses; confirmed by the A.2 vectors in S1.

### 2.10 Dependency impact (summary; full approval table in §14.3)

- **Android library:** three new **workspace** crates (`ghost-blind-rsa`, `ghost-entitlement`, `ghost-issuer-api`); no new external crate. `num-bigint-dig`, `sha2`, `hkdf`, `hmac`, `ring`, `ed25519-dalek`, `curve25519-dalek`, `sha3`, `keccak` are already on the allowlist (verified lines 58, 82, 127–128, 163, 187, 237, 262–263).
- **Issuer only:** `blind-rsa-signatures` =0.17.2 and its tree; `md-5` (wallet-rpc digest auth).
- **Not added anywhere:** `rsa` as a *direct* dependency of any GHOST crate, `reqwest`, `monero-rpc`, `openssl`, `aws-lc-*`, `chacha20poly1305`, any JVM crypto library.

---

## 3. Key management and key consistency (I3)

### 3.1 The Entitlement Schedule (ES)

A canonical binary document (little parsing surface, no JSON), versioned, signed offline. Big-endian fixed fields; `<u16>` marks u16-length-prefixed byte strings.

```
ES v1 := magic "GHES" (4) || version u8 = 1 || seq u64 || network u8 {1 mainnet, 2 stagenet, 3 regtest (mainnet prefixes)}
  || issuer_name <u16 ASCII, 1..64> || issuer_onion <u16 ASCII "<56>.onion:<port>">
  || constants: confirmations u8 (=10) || invoice_blocks u16 (=720) || grace_blocks u16 (=2160)
                || access_per_slot u8 (=16) || trial_per_slot u8 (=8) || invites_per_pack u8 (=2)
                || credits_per_free_pack u8 (=10) || min_claim_credits u8 (=5) || max_claim_credits u8 (=50)
                || early_window_hours u8 (=24) || capability_quota_bytes u64 (=268 435 456)
  || slot_table: count u8 (1..64) || count x (slot u8 (0..31) || onion <u16 "<56>.onion:<port>">
                                             || valid_from_week u64 || valid_until_week u64 (0 = open))
  || price_table: count u16 || count x (price_epoch u64 || pack_price_atomic u64 (divisible by 10))
  || keys: count u16 || count x (kind u8 || epoch u64 || spki <u16 DER> || proof 8 x 256)
  || revoked: count u16 || count x (kind u8 || epoch u64)
  || signature: Ed25519 over "ghost/v1/entitlement-schedule" || all preceding bytes, by the offline schedule key (64)
```

**Validity rules** (`ghost_entitlement::Schedule::verify`, shared by client, relay, issuer and ops; each rule has a negative test):

1. Magic, version, exact lengths, no trailing bytes; the signature verifies under the **pinned schedule public key**, a 32-byte constant in `ghost-entitlement`, printed in the release notes. Tests verify test schedules through `Schedule::verify_with_key`; production code has no other entry point.
2. `(kind, epoch)` unique; **every key id and every modulus n distinct across all entries and against every key id remembered from previously accepted schedules** (a key never reappears under another (kind, epoch), RFC 9474 §6.2, §19.2); every SPKI is canonical (re-encoding (n, e) gives the same bytes), n odd and exactly 2048 bits, e = 65537, no prime factor ≤ 65 537 (trial division); the permutation proof verifies (§3.2).
3. Access keys cover every week of `[first, first + 26)` without gaps; invite and credit keys cover the matching epochs; prices cover every price epoch touched.
4. For each slot number the entries have non-overlapping week ranges; at most 32 slots valid in any week; onion addresses parse (`OnionAddress` checksum). A slot's relay may change only at a week boundary.
5. **Append-only against local memory.** For every `(kind, epoch)` already accepted (client `ent_key` table, relay `es_keys` table in `nullifiers.redb`, issuer `es_memory` table), the key id must be identical, and `seq` must not go backwards. **Layout and price facts are immutable too (§19.2):** for every week covered by a previously accepted schedule, the set of slot numbers valid in that week is identical (client `ent_schedule_fact`, issuer `es_memory`), and for every price epoch already covered the price is identical. A slot's onion may change for an already-covered week only as an emergency relay move (declared residue E18). A schedule that changes an accepted key, slot set or price, or rolls back, is refused; the client raises the persistent flag `SCHEDULE_CONFLICT` (a Phase 13 security alarm), a relay refuses to start, the issuer refuses to start. `entitlement-schedule.sh` applies the same comparison between the committed ES and its predecessor in git.
6. The production client refuses `network = 3`.

**Where it lives (C-7):**

- **Source of truth:** `ghost/protocol/entitlement/schedule.ghes`, committed, produced by the offline ceremony.
- **Client:** compiled into `libghost_client_net.so` with `include_bytes!`, hence covered by the reproducible build (T12) and, in Phase 14, by the signed release manifest. Kotlin never handles the ES bytes; it receives a verified summary over JNI (§11.7). **No network path exists** by which a client receives or replaces an ES. A release ships ≥ 26 weeks of keys; a client whose ES ends within 5 weeks refuses to start a purchase (`UPDATE_REQUIRED`).
- **Relays:** `--schedule <file> --slot <n> --onion-hostname-file <path>` (the Tor `HiddenServiceDir/hostname` file, §19.10). The operator takes the file from the same release; the relay verifies it with the same pinned key, checks rule 5 against its own memory and that its onion is listed for its slot in the current week, and refuses to start otherwise.
- **Issuer:** loads the same file; refuses to start if any held private key does not match its ES entry.

### 3.2 Key well-formedness: the permutation proof

**Claim.** If e is prime and x ↦ x^e is not a permutation of Z_n^\* (e | λ(n)), the e-th powers form a subgroup of index ≥ e, so a uniform element of Z_n^\* is an e-th power with probability ≤ 1/e.

**Proof object.** For i = 0..7, `ρ_i = OS2IP(H_i,0 ‖ H_i,1 ‖ H_i,2 ‖ H_i,3 ‖ H_i,4) mod n` with `H_i,c = SHA-512("ghost/v1/perm-proof" ‖ n ‖ e ‖ u8(i) ‖ u8(c))` (320 bytes, a hash-derived value the key owner cannot choose), and `σ_i = ρ_i^d mod n`.

**Verifier:** n odd, 2048 bits, e = 65537; no prime factor ≤ 65 537; `gcd(ρ_i, n) = 1`; `σ_i^e ≡ ρ_i (mod n)` for all 8. A non-permutation key passes with probability ≤ 65537⁻⁸ < 2⁻¹²⁸. This is the GRSB19 construction for prime e; the match of every side condition is reviewed in S12 (Appendix D).

**Consequence (P-1).** With r uniform in Z_n^\*, r^e is uniform, so B = em·r^e is uniform and independent of em. And e-th roots are unique, so the verified authenticator is the unique `em^d`: **a malicious issuer can neither learn anything from B nor embed anything in the final signature.** Without the check, Lysyanskaya (PKC 2023) shows that a signer choosing (n, e) with gcd(e, φ(n)) ≠ 1 learns the residue class of em from B (RP V5, mutant M14).

### 3.3 Ceremony, custody, destruction (runbooks K1–K4)

| Step | Where | What |
|---|---|---|
| **K1 ceremony** (quarterly) | offline machine, two people, the same machine class as the Monero cold wallet | `ghost-issuer-ops keygen --kind access --from-week W --count 26 …` (primes from the reference signer's keygen, `crypto-primes`); checks p ≠ q, \|p − q\| > 2¹⁰⁰⁰, gcd(e, λ(n)) = 1; writes the public entries with proofs; seals each private key into its own file: ChaCha20-Poly1305 from **`ring`** under `k_seal(kind, epoch) = HKDF-SHA256(custody_secret, "ghost/v1/key-seal" ‖ kind ‖ epoch)`, where the 32-byte custody secret lives only on removable media; signs the ES with the offline schedule key |
| **K2 publish** | release and relay operators | the new ES goes into an app release and to every relay operator at least 8 weeks before it is needed (horizon alarm at < 8 weeks) |
| **K3 load** (every 2 weeks) | issuer host | the sealed files for the whole horizon sit on the issuer's encrypted disk; at week w the operator supplies the per-epoch `k_seal` values (never the custody secret) for every epoch through access week w + 6 (§19.1); the issuer unseals them into process memory only |
| **K4 destroy** (automatic + quarterly) | issuer host | the private key of (kind, epoch) leaves memory when now ≥ `end(epoch) + 8 d` **and** no invoice in CREATED, SEEN, CONFIRMED or ISSUED (not purged) has a layout that references it (§19.1); this happens at the latest at `end(epoch) + 42 d`; the runbook deletes sealed files of past epochs |

**Window held in memory (§19.1):** ahead, access weeks through at least `current + 4` and at most `current + 6` (biweekly K3 load through w + 6), the current invite and credit epochs, the previous credit epoch (for `RefreshCredit`, §19.8), and the next ones when they start within 6 weeks; behind, every key an open invoice still references (at most until `end(epoch) + 42 d`). `RequestInvoice` answers `UNAVAILABLE` unless every key of its layout is loaded. **Compromise bound (corrected, §19.1):** a key thief can mint access tokens for at most 6 weeks ahead; invite and credit tokens under every INVITE and CREDIT key held at the time stay valid until runbook I1 revokes those epochs at the issuer (their only verifier), which it does at once; past-epoch keys retained for open invoices add nothing, because their access tokens are no longer accepted at relays. With an honest issuer database (key theft only), the per-epoch counters show forged redemptions (credits redeemed > credits signed, §6.9).

**Schedule key:** Ed25519, offline, on the custody discipline of the release key (A7). Phase 14 may make the release key sign the ES directly.

**Compromise response (runbook I1):** stop the issuer (relays keep verifying offline); the next ES `seq` lists in `revoked` the leaked future access weeks **and every INVITE and CREDIT epoch whose private key was in memory**, including the current ones; relays enforce the access list from their configuration; the restarted issuer refuses tokens of revoked INVITE and CREDIT epochs immediately (it is their only verifier); until the next epoch begins it keeps signing the layout's positions of those epochs with the leaked key, so layouts, N and clients stay unchanged, and the resulting invites and credits are simply worthless; accepted keys never change (rule 5). Declared residue: honest users' unspent tokens, invites and credits of revoked epochs become worthless (E12); an exchange RPC is left to Phase 15 (§18 F3).

### 3.4 What each verifier accepts

| Verifier | Kind | Epochs accepted at time t | Extra binding |
|---|---|---|---|
| Relay of slot s | ACCESS | week p if `start(p) − early_window ≤ t < start(p+1) + 1 h`, p not revoked, and the ES lists this relay's onion for slot s **in week p** | `origin_info = "relay-slot-s"` |
| Issuer (`RedeemInvite`) | INVITE | 4-week epochs `e_now` and `e_now − 1` | `origin_info = "issuer-invite"` |
| Issuer (`RequestInvoice` with credits, `ClaimPayout`, `RefreshCredit`) | CREDIT | 13-week epochs `c_now − 4` … `c_now` (52–65 weeks of validity, §19.8) | `origin_info = "issuer-credit"` |
| Client (finalize) | any | exactly the (kind, epoch) of the layout position | ES keys only |

At most two access weeks are open at a relay at any moment (p−1 only during the first hour of p, p+1 only during the last 24 h of p), so nullifier retention is at most two weeks (C-9).

### 3.5 Why key tagging fails (RFC 9576 §6.2)

A tag would be a key, price, period or constant that differs for one client.

- **Keys:** a client uses only the ES in its native library; APKs are reproducible and identical for everyone (T12, Phase 14 manifest), so a split view needs two signed releases, which are public. Independent relays (ADR-11) refuse tokens under a non-ES key, so a tagged client would fail at every honest relay.
- **Periods:** chosen by the client (§4.1); the issuer only validates.
- **Prices:** computed by the client from the ES; a different amount aborts the purchase.
- **Confirmations and windows:** ES constants.
- **Signatures:** unique (§3.2) and verified.
- **Subaddress:** per invoice by design; it never reaches a relay (R1).

---

## 4. Grid, product and counts (I5)

### 4.1 Epochs and clock

- `week(t) = floor((t − 345 600) / 604 800)`; 345 600 s moves the Unix epoch (a Thursday) to Monday 1970-01-05 00:00 UTC; `start(p) = 345 600 + 604 800·p`.
- `invite_epoch(p) = floor(p / 4)`; `credit_epoch(p) = price_epoch(p) = floor(p / 13)`.
- `epoch_id` = the index as u64 big-endian (8 bytes), which keeps `period_id` at 8 bytes as the T1 schema requires (`allowed-observables.json:13`).
- **Activation slots** are UTC days (`floor(t / 86 400)`), used only for eligibility (§12.3).
- **Two clocks (§19.4).** *Issuer-facing* decisions (`base_week`, issuer-call due times) use only the device wall clock under the Phase 7 **trusted clock** (`SyncEngine.clockTrusted()`: READY in this process and no wall/monotonic step > 1 h since); relay-supplied values never enter them, because under AD-1 a relay-driven shift would be a relay → issuer covert channel. The issuer accepts `base_week ∈ {week(t − 4 h), week(t + 4 h)}`, so a client within 4 h of true time needs no boundary guard for issuer calls. *Relay-facing* decisions (redeem planning, the ±1 h redeem guard) use the relay-corrected estimate of §12.5. The issuer's clock is never an input to anything a relay sees.

### 4.2 Pack layout (positions in `BlindSignRequest.blinded`)

With `base` = the client's week at the first `RequestInvoice` attempt and `slots(w)` = the ES slots valid in week w, in ascending slot order:

```
for w in base .. base+4:                        // 5 weeks
  for slot in slots(w):
    for i in 0 .. access_per_slot:              // 16
      position -> ACCESS key of week w, challenge slot = slot
for i in 0 .. invites_per_pack:                 // 2
  position -> INVITE key of invite_epoch(base)
if paid in XMR:
  position -> CREDIT key of credit_epoch(base)
```

- **Count:** `N = 16·Σ_w |slots(w)| + 2 + [XMR]`; with a constant S, `80·S + 3` in XMR and `80·S + 2` with credits. Every buyer with the same (base week, payment type) has the same N under every ES version that covers the base week (slot sets are immutable once covered, §19.2), so the layout no longer depends on the ES seq.
- **The slot of a position is a client choice inside the blinded message.** The issuer cannot enforce "16 per slot"; an honest client follows the layout, a modified one may concentrate its positions on one slot. Reconciliation is therefore per week over all slots (§19.3).
- **Sizes:**

  | S | N (XMR) | `BlindSign` request and response, each | Signing at ~2 ms per signature |
  |---|---|---|---|
  | 3 | 243 | 61 KiB | ≈ 0.5 s |
  | 6 | 483 | 121 KiB | ≈ 1 s |
  | 8 (alpha cap, Q3) | 643 | 161 KiB | ≈ 1.3 s |
  | 32 (format maximum) | 2 563 | 641 KiB | ≈ 5 s |

- The issuer derives kinds from positions; a client cannot ask for an unusual mix (removes the draft's per-token `kind`/`period_id`, RC §2.1).

### 4.3 Trial layout (`RedeemInviteRequest.blinded`)

With `base` = the week of the redemption: `for w in base .. base+1: for slot in slots(w): for i in 0 .. trial_per_slot (8): ACCESS key of week w`. `N_t = 16·S`. No invite and no credit positions: a trial can neither invite nor earn referral credit.

### 4.4 Why counts are fixed, and the demand model

Fixed counts make every pack and every trial the same shape for every buyer, so the issuer learns nothing about how many namespaces or relays a client uses (RP C1, mutant M8). Demand model for `access_per_slot = 16`: a client with 10 DM peers and 5 channels writes about 16 namespaces, each on 3 of S relays, about 8 write pairs per slot per week for S = 6, plus exhaustion spares and the interim READ-by-write of its own inbox and drops (§10.7). A heavier user buys a second pack; two packs bought close together are linkable at the issuer by timing only (declared).

### 4.5 Coverage

A pack covers weeks base … base+4: the current, partial week (spares, and the week a renewal is bought in) plus 4 full weeks. Coverage always ends on a global week boundary (RP F6). A renewal bought before the current coverage ends is used from the following week at pair-PRF renewal times (§12.4); a resume after a lapse is used from the next activation slot. If an invoice is confirmed only after its base week has ended, that week's tokens are simply spares; coverage still ends at base+4.

### 4.6 Price and credit value

- `pack_price_atomic(price_epoch)` comes from the ES and changes only at 13-week boundaries (no external price feed).
- `credit_value(token) = pack_price(credit epoch of the token's key) / 10`, exact (the ES requires divisibility by 10); every credit carries the price of the epoch it was minted in (§19.8).
- A credits-paid pack needs credits of the accepted epochs (`c_now − 4` … `c_now`) whose values sum to at least `pack_price(price_epoch(base))`, and exactly the smallest such count, never fewer than `credits_per_free_pack = 10` (10 when every credit is of an epoch with a price ≥ the current one); its amount is 0; any excess value is kept (§19.8).
- **No partial discounts**: a partly credit-paid invoice that expires would have to release or burn credits, either a link or a loss.

---

## 5. Issuer service: API and protocol (I5, I11)

### 5.1 Crates and code shape (G-1)

```
ghost/issuer/crates/blind-rsa/   ghost-blind-rsa    lib: public-side RFC 9474 (§2.7); dev-dep blind-rsa-signatures =0.17.2
ghost/issuer/crates/entitlement/ ghost-entitlement  lib: grid, challenge, token, nullifier, ES parse/verify, seed batch
                                                     derivation, Monero address validation, URI builder (issuer, relay,
                                                     client-core, ops)
ghost/issuer/crates/api/         ghost-issuer-api   lib: tonic-build of protocol/issuer/v1/issuer.proto (build_transport(false))
ghost/issuer/crates/service/     ghost-issuer       lib + thin src/main.rs (the stub moves here; PROTOCOL_VERSION and
                                                     REFERRAL_SHARE_BPS = 1000 stay its single definitions)
    src/ config.rs custody.rs signer.rs store.rs journal.rs invoice.rs rail/{mod,monero,digest}.rs pool.rs scanner.rs
         invite.rs credit.rs claim.rs payout.rs reconcile.rs status.rs service.rs server.rs
    tests/ chain_port.rs faulty_store.rs faulty_rail.rs faulty_journal.rs negative.rs crash.rs semantics_vectors.rs
           monero_regtest.rs (env-gated) t2_unlinkability.rs t2_world/
ghost/issuer/crates/ops/         ghost-issuer-ops   bins: keygen, keys-seal, schedule-sign, schedule-verify, payout-check,
                                                     reconcile-check
ghost/test-harness/privacy/t2-join/  ghost-t2-join  lib + bin: J1–J10, T2b, T2c, S1–S3 analyzer (test-only)
```

- Workspace `members` replaces `issuer` with `issuer/crates/*`. Everything under `ghost/issuer/` is inside `rust_src_files` (`common.sh:27-32`), so anti-placeholder and no-logging scan all five crates (E-2).
- Handlers are `Issuer::{request_invoice, blind_sign, invoice_status, redeem_invite, claim_payout}_at(req, now)` with an explicit clock (relay precedent `node/src/lib.rs:144-147`); background work has the same shape (`scan_tick_at`, `pool_refill_at`, `sweep_at`, `payout_export_at`). The tonic trait impl adds only the wall clock.
- State goes through a `Store` trait (redb in production), the rail through `PaymentRail` (§7.6), the journal through `Journal`. Test doubles live in `tests/` only (anti-placeholder scans `#[cfg(test)]` inside `src/`, RC G23). No test switches in `src/` (T8).

### 5.2 `protocol/issuer/v1/issuer.proto` (replaces the unreleased draft in place; protocol version stays 1)

```proto
// GHOST entitlement issuer wire schema, protocol version 1 (Phase 8; ADR-02, ADR-22..ADR-24).
// The issuer never receives a GHOST identity, a relay name, a namespace or a referral identifier.
// Every value a client needs to validate a response (keys, prices, periods, constants) comes from the
// Entitlement Schedule built into the client, never from this service.
syntax = "proto3";

package ghost.issuer.v1;

option java_package = "org.ghost.protocol.issuer.v1";
option java_multiple_files = true;

enum Rail {
  RAIL_UNSPECIFIED = 0;
  RAIL_MONERO = 1;       // P0; the only value accepted in protocol version 1
  RAIL_LIGHTNING = 2;    // P1, same blind issuance
}

enum Product {
  PRODUCT_UNSPECIFIED = 0;
  PRODUCT_PACK = 1;      // ES layout: weeks base..base+4 x slots x access_per_slot, invites_per_pack, 1 credit if XMR
}

message RequestInvoiceRequest {
  uint32 version = 1;           // MUST be 1
  Rail rail = 2;                // MUST be RAIL_MONERO
  Product product = 3;          // MUST be PRODUCT_PACK
  bytes claim_hash = 4;         // 32 bytes: SHA-256("ghost/v1/issuer-claim" || claim_key)
  repeated bytes credits = 5;   // empty, or the smallest set (>= ES.credits_per_free_pack, <= 20) of distinct CREDIT tokens
                                // (354 bytes each) whose values cover the price (§4.6, §19.8)
  reserved 6;                   // was schedule_seq: the layout and price depend on base_week only (§19.2)
  uint64 base_week = 7;         // the client's week (device clock); validated with a ±4 h tolerance, never chosen by the issuer
}

enum RequestInvoiceResult {
  REQUEST_INVOICE_RESULT_UNSPECIFIED = 0;
  REQUEST_INVOICE_RESULT_OK = 1;
  REQUEST_INVOICE_RESULT_WRONG_PERIOD = 2;   // nothing recorded; base_week outside {week(t − 4 h), week(t + 4 h)}
  REQUEST_INVOICE_RESULT_CREDITS_SPENT = 3;  // nothing consumed; spent_mask names the credits already used
  REQUEST_INVOICE_RESULT_CLAIM_CONFLICT = 4; // claim_hash known with a different request
}

message RequestInvoiceResponse {
  RequestInvoiceResult result = 1;
  bytes invoice_id = 2;         // 16 random bytes (OK only)
  uint64 amount_atomic = 3;     // MUST equal the client's own computation (price or 0)
  string subaddress = 4;        // 95 chars, ES network, subaddress prefix; empty iff amount_atomic == 0
  uint32 spent_mask = 5;        // CREDITS_SPENT only: bit i set iff credits[i] was already used
}

message BlindSignRequest {
  uint32 version = 1;
  bytes invoice_id = 2;         // 16 bytes
  bytes claim_key = 3;          // 32 bytes; bearer proof for this invoice
  bytes blinded = 4;            // exactly N x 256 bytes in ES layout order (§4.2); each value in [1, n-1]
}

enum InvoiceState {
  INVOICE_STATE_UNSPECIFIED = 0;
  INVOICE_STATE_SIGNED = 1;                  // blind_signatures present (BlindSign) or already issued (InvoiceStatus)
  INVOICE_STATE_AWAITING_PAYMENT = 2;        // nothing seen
  INVOICE_STATE_AWAITING_CONFIRMATIONS = 3;  // seen (pool or < confirmations) covers the amount
  INVOICE_STATE_UNDERPAID = 4;               // 0 < seen + credited < amount: top up to the same subaddress
  INVOICE_STATE_EXPIRED = 5;                 // grace passed without full credit (decided from a synced view)
  INVOICE_STATE_OTHER_REQUEST_ISSUED = 6;    // issued for a different blinded request; nothing signed
}

message BlindSignResponse {
  InvoiceState state = 1;
  bytes blind_signatures = 2;   // SIGNED only: same length and order as `blinded`
  uint64 credited_atomic = 3;   // qualifying (>= ES.confirmations, unlock_time 0, not double-spent)
  uint64 seen_atomic = 4;       // pool or below ES.confirmations
}

message InvoiceStatusRequest {  // optional "check now" (user action, declared presence sample, STANDARD mode only)
  uint32 version = 1;
  bytes invoice_id = 2;
  bytes claim_key = 3;
}

message InvoiceStatusResponse {
  InvoiceState state = 1;       // never carries signatures; those come only from BlindSign
  uint64 credited_atomic = 2;
  uint64 seen_atomic = 3;
}

message RedeemInviteRequest {
  uint32 version = 1;
  bytes invite_token = 2;       // 354 bytes, kind INVITE (challenge origin "issuer-invite")
  uint64 base_week = 3;         // the client's week; must equal the issuer's
  bytes blinded = 4;            // exactly trial layout N_t x 256 bytes (§4.3)
}

enum RedeemInviteResult {
  REDEEM_INVITE_RESULT_UNSPECIFIED = 0;
  REDEEM_INVITE_RESULT_OK = 1;
  REDEEM_INVITE_RESULT_REPLAYED = 2;         // nullifier used with a different request (revoked or already used)
  REDEEM_INVITE_RESULT_WRONG_PERIOD = 3;     // base_week mismatch; nothing recorded
}

message RedeemInviteResponse {
  RedeemInviteResult result = 1;
  bytes blind_signatures = 2;   // OK only: same length and order as `blinded`
}

message ClaimPayoutRequest {
  uint32 version = 1;
  bytes claim_id = 2;           // 16 random bytes; idempotency key (client write-ahead)
  repeated bytes credits = 3;   // ES.min_claim_credits (10) .. ES.max_claim_credits (50) distinct CREDIT tokens
  string payout_address = 4;    // 95 chars: ES-network standard address or subaddress (integrated refused)
}

enum ClaimPayoutResult {
  CLAIM_PAYOUT_RESULT_UNSPECIFIED = 0;
  CLAIM_PAYOUT_RESULT_QUEUED = 1;
  CLAIM_PAYOUT_RESULT_CREDITS_SPENT = 2;     // nothing consumed; spent_mask names the credits already used
  CLAIM_PAYOUT_RESULT_CLAIM_CONFLICT = 3;    // claim_id known with a different body
  CLAIM_PAYOUT_RESULT_ADDRESS_REJECTED = 4;  // network, type, checksum or point decompression failed
}

message ClaimPayoutResponse {
  ClaimPayoutResult result = 1;
  uint64 queued_atomic = 2;     // QUEUED only: Σ price(epoch of each credit's key) / 10; paid later, one recipient per
                                // transaction, at a random time
  uint32 spent_mask = 3;
}

message RefreshCreditRequest {  // §19.8: a credit received through a drop is exchanged before any use
  uint32 version = 1;
  bytes credit = 2;             // 354 bytes, a CREDIT token of an accepted epoch
  bytes blinded = 3;            // exactly 256 bytes: one CREDIT position under the key of the SAME credit epoch
}

enum RefreshCreditResult {
  REFRESH_CREDIT_RESULT_UNSPECIFIED = 0;
  REFRESH_CREDIT_RESULT_OK = 1;
  REFRESH_CREDIT_RESULT_REPLAYED = 2;         // nullifier already used for another purpose or another blinded value
}

message RefreshCreditResponse {
  RefreshCreditResult result = 1;
  bytes blind_signature = 2;    // OK only: 256 bytes
}

service IssuerService {
  rpc RequestInvoice(RequestInvoiceRequest) returns (RequestInvoiceResponse);
  rpc BlindSign(BlindSignRequest) returns (BlindSignResponse);
  rpc InvoiceStatus(InvoiceStatusRequest) returns (InvoiceStatusResponse);
  rpc RedeemInvite(RedeemInviteRequest) returns (RedeemInviteResponse);
  rpc ClaimPayout(ClaimPayoutRequest) returns (ClaimPayoutResponse);
  rpc RefreshCredit(RefreshCreditRequest) returns (RefreshCreditResponse);
}
```

Removed from the draft, each for a named reason:

| Removed | Reason |
|---|---|
| `period_days` | a free length is a partition (RP F6) |
| `schedule_seq` (review) | the ES version is a partition visible at the issuer; layouts and prices are immutable once covered, so `base_week` suffices (§19.2) |
| `referral_commitment`, `ClaimReferral.referral_preimage` | no referral identifier at the issuer (D13) |
| `payment_uri`, string `amount`, `required_confirmations` | tagging vectors (RM §4.6, RP F5) |
| `PollInvoice` | folded into `BlindSign`; `InvoiceStatus` is user-only |
| `BlindedToken.kind/period_id` | the fixed layout implies them |
| `issuer_key_id`, `IssuerKeys` | tagging (RP F4); keys come only from the ES (D5) |
| client-supplied `nullifier` | computed by the verifier (RP F7) |

`proto-check.sh` is extended to require `uint32 version = 1;` in **every** `message *Request` (RC G18); response messages carry in-band results, never free text.

### 5.3 Flows

**Pack paid in XMR**

1. **Intent, local only.** `startPurchase(XMR)` writes a purchase row `prepared` with `claim_key`, `seed` (both CSPRNG), `base_week` (trusted clock) and `schedule_seq`; nothing is sent.
2. **`RequestInvoice`** runs in the next **quiet run** (§12.2) on a fresh `IssuerFlow`. The optional "get invoice now" button sends it at once from the foreground (declared L3; hidden in HIGH mode). The Rust client checks `amount == ES price(price_epoch(base))` and the subaddress (network byte, subaddress prefix, Keccak-256 checksum); the Kotlin engine persists the invoice (state `invoiced`) **before** anything can be shown.
3. **Payment.** The facade exposes `PaymentInstructions` once all disclosures are acknowledged: `monero:<subaddress>?tx_amount=<12-decimal amount>` built locally (no other parameters), the deadline (invoice receipt + 24 h) and the outstanding amount (§19.11), the FR-6.8 KYC warning, "no refunds, exact amount, no lock time, 24 h to pay, then up to 72 h to confirm", and the advice to pay from another device or later without GHOST open. The user pays from an external wallet. `PAYMENT_READY` is never an immediate notification: it is surfaced at the first natural foreground at least U[1 h, 6 h] after the invoice arrived. The payment screen closes any running relay session and no relay session starts while it is shown and for U[20 min, 60 min] after it was last shown (§19.11, residue E15). After the deadline no instructions are returned.
4. **`BlindSign` attempts (fixed plan, §19.11):** three planned attempts, pre-drawn at invoice receipt t0, due at `t0 + U[3 h, 5 h]`, `t0 + U[44 h, 52 h]` and `t0 + U[100 h, 112 h]` (after the grace window, when an honest synced issuer's answer is final), each in the first quiet run after its due time, each on its own fresh `IssuerFlow`; an attempt whose answer is not final (`AWAITING_*`, `UNDERPAID` or transient) is followed by the next planned one; after the third, at most two slow attempts at `t0 + U[7 d, 8 d]` and `t0 + U[20 d, 22 d]`; then the purchase is `lost`. The count never exceeds 5 whatever the issuer answers (J9 cap, mutant M16). Rust recomputes the request from the seed (§2.6), sends it, and on `SIGNED` checks every `s'^e ≡ B`, finalizes, verifies with `ring`, and returns tokens with their nullifiers.
   - `AWAITING_*`, `UNDERPAID` → the next planned attempt; the outstanding amount is stored (§19.11).
   - `SIGNED` → one transaction stores the tokens (`eligible_minute` per §12.3) and moves the purchase to `finalized` (secrets wiped).
   - `EXPIRED` → `expired` (the UI says whether money was seen).
5. The optional "check now" (`InvoiceStatus`, STANDARD mode) is a declared L3 sample; it never triggers `BlindSign` in the foreground.

**Pack paid with credits:** the same flow with 10 reserved credits and amount 0. The invoice is CONFIRMED at creation; `BlindSign` runs at the first due time in a later quiet run. Auto-renewal with credits (if enabled) needs no user presence at all.

**Trial:** §8.3. **Payout claim:** §9.4.

**Re-preparing after `WRONG_PERIOD`.** `WRONG_PERIOD` proves the issuer recorded nothing (the idempotency lookup by `claim_hash` precedes the week check, §5.6). The engine closes the purchase as `failed` and, in the same transaction, creates a new `prepared` purchase (new claim key, seed and base week); reserved credits move to it through the one permitted release path (§11.3). With the issuer's ±4 h tolerance (§19.4) this path is reachable only with a device clock more than 4 h off, which relays cannot cause.

### 5.4 Invoice state machine (issuer)

```
            scanner: seen > 0             scanner: credited >= amount        BlindSign committed (digest D)
  CREATED ─────────────────────► SEEN ─────────────────────────► CONFIRMED ───────────────────────────► ISSUED
     │ (amount 0: created CONFIRMED)  ▲  reorg: credited < amount    │                                        │
     │                                └───────────────────────────────┘  unissued 30 d: purge (counter)       │ +7 d
     │ synced ∧ wallet_height ≥ grace_height + C ∧ credited < amount                                          ▼
     └──────────────────────────────► EXPIRED ──(+7 d)──► purged                                           purged
```

| Transition | Guard | Effect in one redb write transaction |
|---|---|---|
| create | §5.6 checks pass | inside the write transaction, re-check, append and fsync the `INVOICE` journal entry (with the credit nullifiers of a credits-paid invoice), then take the lowest pool entry (XMR), insert invoice, `claim_index`, `minor_index`, credit nullifiers; commit (§19.5) |
| → SEEN / UNDERPAID (reported) | scanner recomputation (§7.3) | `seen_atomic`, `credited_atomic` |
| → CONFIRMED | `credited ≥ amount` counting only transfers mined at height ≤ `grace_height` | `confirmed_height` |
| CONFIRMED → SEEN/CREATED | recomputation lowered `credited` before issuance | none |
| → ISSUED | §5.5 | `issued_digest`, `issued_height`, counters |
| → EXPIRED | **synced view** (daemon synchronized ∧ wallet height ≥ daemon height − 1) ∧ `wallet_height ≥ grace_height + C` ∧ `credited < amount` | `purge_height = h + 5 040` |
| purge | ISSUED at max(issued + 5 040 blocks (≈ 7 d), confirmed + 21 600) (§19.27 point 4); EXPIRED + 5 040; CONFIRMED-unissued + 21 600 (≈ 30 d, counter `confirmed_unissued`) | delete invoice, indices, `credited_tx` rows |
| ISSUED with a vanished credited txid | — | alarm counter `reorg_after_issue` (financial residue, declared) |

No wall-clock time is stored per invoice: heights only, converted at creation (`seen_deadline = created + 720`, `grace_height = seen_deadline + 2 160`).

### 5.5 `BlindSign`: validation order and idempotency (MS-1)

1. Sizes exact (`invoice_id` 16, `claim_key` 32, `blinded` a non-empty multiple of 256) → else `INVALID_ARGUMENT`.
2. Look up the invoice; compare `SHA-256("ghost/v1/issuer-claim" ‖ claim_key)` with `claim_hash` in constant time. Mismatch and unknown invoice give **the same** `PERMISSION_DENIED` (no existence oracle).
3. CREATED, SEEN, EXPIRED → return the state and amounts; no signing, no digest recorded.
4. `len(blinded) == N(invoice) · 256`, every block in `[1, n_pos − 1]` under its position's key → else `INVALID_ARGUMENT`.
5. `D = SHA-256("ghost/v1/blindsign" ‖ invoice_id ‖ blinded)`.
6. ISSUED: `D == issued_digest` → re-sign every position and return identical signatures (at the quantum); otherwise `OTHER_REQUEST_ISSUED`, nothing signed.
7. CONFIRMED:
   - every needed private key is in the window, else `UNAVAILABLE` (fail closed; alarm `KEYS_MISSING`);
   - sign every position through `CheckedSigner`, outside any transaction, on the blocking pool;
   - one write transaction re-reads the invoice (compare-and-set); only if it is still CONFIRMED: append `ISSUE(invoice_id, D)` to `issued.journal` and fsync **inside that transaction** (§19.5), then ISSUED, `issued_digest = D`, `issued_height`, counters += per (kind, epoch); commit; respond at the quantum;
   - if another request won the race, nothing is journaled; continue at step 6 with the fresh state; the computed signatures are dropped and never leave the process.

No signature and no blinded message is ever stored. A crash between signing and journal leaves CONFIRMED (the retry re-signs identically); between journal and commit, startup replay applies the journal record (the identical retry is served, a different one refused); between commit and response, the retry is re-served.

### 5.6 Other handlers

**`RequestInvoice`**

1. Sizes and enum values → `INVALID_ARGUMENT`.
2. **Idempotency first.** `R = SHA-256("ghost/v1/request-invoice" ‖ rail ‖ product ‖ base_week ‖ nullifiers of the credits in request order)`. If `claim_index[claim_hash]` exists: same R → return the stored invoice byte-identically (even if `base_week` is now in the past); different R → `CLAIM_CONFLICT`. Nothing else is checked for a known claim hash.
3. The issuer's ES covers `base_week … base_week + 4` and every key of the layout is loaded → else `UNAVAILABLE` (transient, alarm `KEYS_MISSING`, §19.1).
4. `base_week ∈ {week(now − 4 h), week(now + 4 h)}` → else `WRONG_PERIOD`, nothing recorded (§19.4).
5. Credits, if present: distinct nullifiers, each a valid CREDIT token of `c_now − 4` … `c_now` (`ring` verification, origin `"issuer-credit"`), not of a revoked epoch, and the set is the smallest (≥ 10, ≤ 20) whose values `price(epoch)/10` cover `price(price_epoch(base_week))` (§19.8) → else `PERMISSION_DENIED`; any already in `credit_nullifier` → `CREDITS_SPENT` with `spent_mask`, none consumed.
6. XMR: the address pool is non-empty, the open-invoice cap (20 000) is not reached, and the scanner's last tick is synced (daemon synchronized, wallet ≥ daemon − 1) and less than 2 minutes old → else `UNAVAILABLE` (§19.6).
7. One write transaction (§19.5): re-check `claim_index` and the credit nullifiers; append and fsync one `INVOICE` journal entry (invoice fields, and for credits the nullifiers with `use = discount`); insert the invoice (CREATED with `created_height` = the daemon height of that synced tick, or CONFIRMED with amount 0), `claim_index`, `minor_index`, credit nullifiers, counters (`credits_discount`, `credits_discount_atomic`); commit; respond. A request that loses the re-check is answered as in steps 2 and 5 and journals nothing.

**`RedeemInvite`**

1. Sizes → `INVALID_ARGUMENT`.
2. The token parses, `token_type = 0x0002`, `token_key_id` is an ES INVITE key of **any** epoch listed in the ES, `challenge_digest` matches `"issuer-invite"` for that epoch, `ring` verifies → else `PERMISSION_DENIED`. (The acceptance window is checked only for new redemptions, step 5; §19.9.)
3. `N_inv = nullifier`; `D_t = SHA-256("ghost/v1/trial" ‖ N_inv ‖ base_week ‖ blinded)`.
4. `invite_nullifier[(epoch, N_inv)]` exists: same `D_t` → re-sign and return `OK` (idempotent retry, even across a week or epoch boundary) if the trial's keys are still held, else `REPLAYED` (the trial re-serve is guaranteed for at least 8 days, §19.1); different → `REPLAYED`.
5. The epoch is `e_now` or `e_now − 1` and not revoked → else `PERMISSION_DENIED`; `base_week ∈ {week(now − 4 h), week(now + 4 h)}` → else `WRONG_PERIOD`, nothing recorded.
6. `len(blinded) == N_t · 256` and range checks → else `INVALID_ARGUMENT`.
7. Sign through `CheckedSigner`; one write transaction re-checks the nullifier, appends and fsyncs `INVITE(epoch, N_inv, D_t)` inside the transaction (§19.5), inserts the nullifier (kept until the start of epoch + 2) and counters, commits; a loser of the re-check continues at step 4; respond at the quantum.

**`ClaimPayout`**

1. Sizes → `INVALID_ARGUMENT`.
2. `claim[claim_id]` exists: same body digest → return the stored result; different → `CLAIM_CONFLICT` (idempotency before every validity check, §19.9).
3. The address validates (§7.7): ES network, standard address or subaddress, Keccak-256 checksum, both keys decompress → else `ADDRESS_REJECTED`.
4. Credits: count within `[min_claim_credits (10), max_claim_credits (50)]`, distinct, valid, of `c_now − 4` … `c_now`, not revoked → else `PERMISSION_DENIED`; any credit already used → `CREDITS_SPENT` with `spent_mask`, none consumed.
5. One write transaction (§19.5): re-check `claim_id` and every nullifier; append and fsync one `CLAIM` journal entry (claim id, digest, amount, address and every credit nullifier with `use = payout`) inside the transaction; insert the nullifiers and the claim row `{amount = Σ price(epoch of each credit)/10, address, state queued}`; commit; respond. A loser of the re-check journals nothing and is answered as in steps 2 and 4.

**`RefreshCredit`** (§19.8)

1. Sizes → `INVALID_ARGUMENT`.
2. The credit parses and verifies under an ES CREDIT key of any listed epoch → else `PERMISSION_DENIED`.
3. `credit_nullifier[(epoch, N)]` exists: `use = refresh` and the same blinded digest → re-sign and return `OK`; otherwise `REPLAYED`.
4. The epoch is `c_now` or `c_now − 1` and not revoked (a received credit is refreshed at most about 10 weeks after it was minted, §19.8, so older ones never need it) → else `PERMISSION_DENIED`; `blinded` is one value in `[1, n − 1]` under that epoch's key, which the issuer holds for exactly this purpose (§19.1).
5. Sign through `CheckedSigner`; one write transaction re-checks, appends and fsyncs `REFRESH(epoch, N, digest)` inside the transaction, inserts the nullifier (`use = refresh`) and counters (`credits_refreshed`, `signed[CREDIT][epoch] += 1`), commits; respond at the quantum.

**`InvoiceStatus`** is a database read: steps 1–2 of §5.5, then the state and amounts. It never signs.

### 5.7 Outcome mapping and client error categories (G-3; no new category)

`client-core` gains `categories::for_issuer(code)` using only existing categories. `ErrorPolicyTest` stays at 21; the README gains one note on `relay_unavailable` ("remote onion service, relay or issuer, transient"). Protocol-meaningful outcomes are in-band.

| Condition | Transport status / in-band result | Client category → engine action |
|---|---|---|
| malformed sizes, layout, range | `INVALID_ARGUMENT` | `rejected` → flow `failed` (client or issuer bug; never a mutated retry) |
| bad claim key, unknown or purged invoice, invalid token or key | `PERMISSION_DENIED` | `unauthorized` → purchase `expired` if the last known state was EXPIRED, else `lost` (counted); trial fails closed; claim `failed` |
| keys not loaded, wallet unreachable or unsynced, scanner tick stale, pool empty, open-invoice cap, issuer ES not covering the layout | `UNAVAILABLE` | `relay_unavailable` → identical retry at the next due time (within the attempt cap, §19.11) |
| rate limit | `RESOURCE_EXHAUSTED` | `quota` → identical retry at the next due time |
| any other gRPC code | — | `relay_unavailable` (default of `for_issuer`) |
| issued for a different blinded set | `OTHER_REQUEST_ISSUED` (in-band) | purchase `failed`, flag `ISSUER_MISMATCH` (impossible for an honest client) |
| base week or ES seq not acceptable, nothing recorded | `WRONG_PERIOD` (in-band) | re-prepare (§5.3) |
| invite nullifier used with another request | `REPLAYED` (in-band) | trial fails closed ("invitation no longer valid") |
| received credit already used or refreshed with another value | `REPLAYED` (in-band, `RefreshCredit`) | the received credit is deleted (counter; possibly a malicious invitee) |
| credit already used | `CREDITS_SPENT` + `spent_mask` (in-band) | delete the spent credits; purchase or claim `failed`; the other credits are released |
| claim hash or claim id reused with a different body | `CLAIM_CONFLICT` (in-band) | `failed`, flag `ISSUER_MISMATCH` |
| response fails validation in Rust (amount ≠ ES price, subaddress network/prefix/checksum, count ≠ N, `s'^e ≢ B`, `ring` failure) | — | `malformed_response` → one identical retry, then `failed` + `ISSUER_MISMATCH` |
| `transport`, `timeout`, `closed`, `tor_*` | unchanged | identical retry at the next due time |

The sync `ErrorPolicy` never sees issuer calls; no mapping there changes.

### 5.8 Crash and retry analysis (both sides)

| Crash point | State after restart | Retry | Invariant |
|---|---|---|---|
| Client, before the `RequestInvoice` response is persisted | purchase `prepared` (claim key, seed, base week; credits reserved in the same transaction as the first attempt) | the identical request; the issuer answers from `claim_index` | no orphan invoice is ever shown; credits never burned twice |
| Client, after persisting the invoice | `invoiced` | continue | MS-6 |
| Client, after sending `BlindSign`, before persisting tokens | `invoiced`/`signing`, seed and layout frozen | Rust recomputes the identical request → identical signatures | MS-1 (RP E1) |
| Client, during finalization | one transaction: tokens + `finalized` + secrets wiped | redo from the seed | atomic |
| Issuer, signed, before journal | CONFIRMED | re-sign identically | MS-1 |
| Issuer, journaled, before commit | startup replay → ISSUED(D) | identical retry served, different refused | MS-1 |
| Issuer, committed, before response | ISSUED(D) | re-serve | MS-1 |
| Issuer, restored from an hourly snapshot | snapshot + journal replay (§6.3), including every invoice created after the snapshot (`INVOICE` entries); the whole `address_pool` is discarded and refilled above the wallet's subaddress count (§19.5) | as above | MS-1, MS-3, MS-6 |
| Issuer, pool refill after `create_address`, before commit | index burned, not in the pool | none needed; startup reconciles `highest_minor` | RM §3.3 |
| Wallet or daemon down | scanner makes no progress | `BlindSign` answers `AWAITING_*`, never "unpaid" | RM §8 |
| Client lost the device | purchase gone | none | declared (E11) |

### 5.9 Abuse limits (issuer)

- Onion service with `HiddenServicePoWDefensesEnabled 1` (relay precedent).
- At most 20 000 open unpaid invoices; unpaid invoices are purged after grace.
- Request size caps: `RequestInvoice` ≤ 8 KiB; `BlindSign` ≤ 2 563 × 256 bytes ≈ 641 KiB; tonic max decode 1 MiB.
- CPU is spent only for CONFIRMED invoices, valid invites and valid credits; `InvoiceStatus` is a database read; signing runs on `spawn_blocking` behind a semaphore sized to the core count, so a burst cannot starve the scanner.
- A global token bucket of 2 `RequestInvoice`/s (burst 40); beyond it `RESOURCE_EXHAUSTED`.
- A refresh budget per credit epoch (§19.27 point 1): new `RefreshCredit`s of epoch e stop at 64 plus the XMR packs of the credit epochs e − 1, e and e + 1; beyond it `RESOURCE_EXHAUSTED`, counted in `REFRESH_REFUSED`. No global bucket: it would let the same holder starve every epoch's honest refreshes.

---

## 6. Issuer service: storage, journal, retention, logging, operations (I11)

### 6.1 redb schema (`issuer.redb`, `SCHEMA_VERSION = 1`; any other version is refused; `Durability::Immediate`)

| Table | Key | Value | Deleted |
|---|---|---|---|
| `meta` | `&str` | `u64`: `schema_version`, `highest_minor`, `scan_final_height`, `restore_height`, `es_seq`, `journal_applied`, `closed_through_invite_epoch`, `closed_through_credit_epoch` (§19.10) | never |
| `es_memory` | `u8` fact kind (1 key, 2 slot set, 3 price) ‖ `u64` epoch | `[u8; 32]` key id, SHA-256 of the week's slot numbers, or SHA-256 of the price (ES rule 5, §19.2) | never |
| `address_pool` | `u32` minor | `[u8; 95]` validated subaddress (target 32 entries) | when assigned |
| `invoice` | `[u8; 16]` | fixed row: `state u8, pay_with u8, minor u32, amount u64, claim_hash [32], request_digest [32], base_week u64, es_seq u64, created_height u64, seen_deadline u64, grace_height u64, confirmed_height u64, credited u64, seen u64, issued_digest [32] (0 = none), issued_height u64, purge_height u64` | at `purge_height` |
| `claim_index` | `[u8; 32]` claim hash | invoice id | with the invoice |
| `minor_index` | `u32` | invoice id | with the invoice (minors of purged invoices become "unattributed") |
| `credited_tx` | `[u8; 48]` invoice id ‖ txid | `u64` height | with the invoice |
| `invite_nullifier` | `[u8; 40]` epoch ‖ N | `[u8; 32]` trial digest | at the start of invite epoch + 2 |
| `credit_nullifier` | `[u8; 40]` epoch ‖ N | `u8` use (1 discount, 2 payout, 3 refresh) ‖ `[u8; 16]` ref (refresh: the first 16 bytes of the blinded digest) | at the start of credit epoch + 5 (§19.8) |
| `claim` | `[u8; 16]` claim id | `state u8, amount u64, credits u8, digest [32], address [95], batch_id [16]` (no time column, §19.15) | batch paid + 7 d |
| `batch` | `[u8; 16]` | `state u8, week u64, total u64, entries u16` | paid + 30 d |
| `counter` | `[u8; 9]` week ‖ counter id | `u64` | 400 d (aggregates only, §6.9) |

`RequestInvoice` is idempotent by `claim_hash`; `BlindSign` by `(invoice_id, D)`; `RedeemInvite` by `(epoch, N_inv, D_t)`; `ClaimPayout` by `claim_id`.

### 6.2 Concurrency

redb has one writer. Signing happens outside transactions; state is re-read and compared-and-set inside the commit. The scanner and the pool refill are single tasks with short transactions. The tonic server runs on the tokio multi-thread runtime; CPU-bound signing on `spawn_blocking` with a semaphore (§5.9).

### 6.3 `issued.journal` (G-6, fixes E-3)

A snapshot restore alone would revert an invoice ISSUED after the snapshot to CONFIRMED, and a client still holding the claim key could then obtain a second, different signature set (MS-1 broken). The same holds for invite and credit nullifiers recorded after the snapshot (MS-3, MS-4 broken). Therefore:

- **Entries** (§19.5; one entry per decided transition, length-prefixed, `seq u64`, checksum = SHA-256 over the entry, from `sha2`, already in the issuer graph; no CRC crate): `INVOICE(invoice_id, claim_hash, R, pay_with, minor, amount, base_week, created_height, grace_height, credit nullifiers[0..20])`, `ISSUE(invoice_id 16, D 32)`, `INVITE(epoch 8, N 32, D_t 32)`, `CLAIM(claim_id 16, digest 32, amount 8, address 95, credit nullifiers[10..50])`, `REFRESH(epoch 8, N 32, digest 32)`, `BATCH(batch_id, week, claim ids)`, `BATCH_PAID(batch_id)`, and the data-free weekly `ANCHOR()` (Q32, §19.25 point 5).
- **Write rule (decide, then journal):** inside the redb write transaction, after the handler has re-checked the state it depends on (redb has one writer, so no other transition interleaves), the entry is appended and fsynced, then the transaction commits. Only decided outcomes are journaled, and journal order equals commit order. An entry whose commit never happened (crash between fsync and commit) is the outcome that had already won, so replaying it is correct.
- **Startup:** replay every entry with `seq > meta.journal_applied` in order, applying the transition exactly as the handler would (idempotent: "apply if not yet applied", counters included), then advance `journal_applied`. A torn final entry (bad checksum or short) is discarded: its commit cannot have happened.
- **Restore (runbook B1):** latest encrypted snapshot of `issuer.redb` + replay of the journal since that snapshot; then `address_pool` is emptied, `highest_minor := max(highest_minor, wallet subaddress count − 1)` and the pool is refilled from there, so no minor is ever handed out twice (§19.5).
- **Pruning:** weekly segments `issued.journal.<week>`; a segment is deleted when every entry is older than the 7-day re-serve window **and** a verified snapshot newer than the segment exists. The command is `ghost-issuer-ops journal-prune`, run hourly by the host cron after the newest verified snapshot; the segment that holds the last entry always stays (§19.24 point 11, §19.25). An idle issuer still gets a newer segment every week, holding its `ANCHOR` entry (§19.25 point 5), so the segment of its last transition goes at `start(w + 2)` too.
- **Snapshots (§19.15):** hourly snapshots are kept 48 h, one daily snapshot 7 days; older ones are deleted (runbook B1). They are part of the retention table and of the T2 issuer view.
- **Privacy:** the journal holds invoice ids, claim hashes, subaddress minors, digests of blinded messages, invite and credit nullifiers, claim ids, amounts and payout addresses for at most about 14 days (7 days plus the weekly segment) while the issuer's scanner runs, also when it makes no transition (the weekly `ANCHOR`, §19.25 points 2 and 5); a wallet or daemon outage outside a maintenance window stops the scanner (§19.25 point 5 (c)), and a forward clock step that outlasts the anchor's settle window adds its length (point 5 (d)). It is part of the T2 issuer view (§13.4) and of the retention table (§6.4). No timestamps.

### 6.4 Retention (issuer)

| Data | Kept until | Why at all |
|---|---|---|
| invoice row, claim hash, minor mapping, credited txids | ISSUED: the later of issuance + ≈ 7 d and confirmation + ≈ 30 d (§19.27 point 4); EXPIRED + ≈ 7 d; CONFIRMED-unissued ≈ 30 d (counted) | re-serve window, final status, MS-6 |
| signatures, blinded messages | never stored | — |
| invite nullifiers | start of invite epoch + 2 (whole acceptance window) | MS-3 |
| credit nullifiers | start of credit epoch + 5 (§19.8) | MS-3, MS-4 |
| claims, payout addresses | batch paid + 7 d | payout |
| `issued.journal` | ≈ 7–14 d (§6.3), pruned hourly after a verified snapshot (§19.24 point 11); also for an idle issuer while its scanner runs (the weekly `ANCHOR`, §19.25 point 5; E31 closed) | restore safety |
| `issuer.redb` snapshots | hourly for 48 h, daily for 7 d (§19.15) | restore |
| counters (no identifiers) | 400 d | S2 reconciliation, spec C-06 |
| private signing keys in memory | from `end(epoch) + 8 d` until no open invoice references the key, at most `end(epoch) + 42 d` (§19.1) | re-serve window, MS-6 |
| workstation ledger | per entry: batch id, claim id hash, txid, amount, state, salted address hash; cumulative totals; 400 d. Batch files: acknowledgement + 7 d. The workstation wallet runs with `store-tx-info` off (§19.15) | cumulative cap (§19.7) |
| view-wallet history | inherent to a view wallet (the wallet file) | AD-3 already assumes it; the T2 issuer view includes the full `get_transfers` dump (RM Q-M9) |

No wall-clock time finer than a week, no IP addresses, circuit ids or request logs exist anywhere in issuer storage (§19.15: the former `created_day` columns are removed).

### 6.5 Logging policy and status

- **The issuer writes no log lines.** `no-logging.sh` is extended (§14.1) to ban `tracing::`, `log::` and the macros `info!`, `warn!`, `error!`, `debug!`, `trace!`, `event!`, `span!` in `ghost/issuer/**/src`, and `common.sh` stops exempting `main.rs` under `ghost/issuer/` (each `main.rs` stays ≤ 60 lines).
- Operators get `status.json`, rewritten atomically every 60 s by `status.rs`, the only file-writing module besides the store, the journal and the payout export (checked by the new `issuer-output.sh` gate). It contains only fixed enum codes and per-week counters: `SCANNER_OK | SCANNER_STALLED | WALLET_UNREACHABLE | REORG_DEPTH`, `KEYS_READY_UNTIL_WEEK`, `ES_HORIZON_WEEKS`, `POOL_SIZE` (bucketed), `OPEN_INVOICES` (bucketed to 100s), `RECONCILIATION_OK | MISMATCH`, `REORG_AFTER_ISSUE`, `CONFIRMED_UNISSUED`, `SIGN_FAULT`, `PAYOUT_BATCH_READY`. A unit test serialises every reachable status and proves no field outside the enum appears (ops-status fixed vocabulary, G-11).
- Monero processes run at `--log-level 0` on tmpfs, outside the gate (runbook).

### 6.6 Configuration (TOML; `toml` already in the lockfile)

`listen` (loopback), `data_dir`, `schedule_file`, `sealed_keys_dir`, `ops_key_file`, `export_dir`, `wallet_rpc_url`, `wallet_rpc_login_file`, `network` (must equal `ES.network`), `max_open_invoices`, `scan_interval_seconds` (30), `pool_target` (32), `reply_quantum_ms` (2 000). Startup refuses to run if the ES is invalid or its network mismatches; any held key does not match its ES entry; the wallet is not watch-only (`query_key spend_key` must fail with −29, RM §3.1); the wallet's primary address differs from the configured treasury; the journal has a gap in sequence numbers.

### 6.7 Infrastructure (`ghost/infra/issuer/`)

- **Dockerfile:** multi-stage, builds only `ghost-issuer`; runtime Debian slim plus Tor; Monero binaries from the pinned tarball, checked with `sha256sum -c` against `monero-release.pin`.
- **entrypoint.sh:** starts Tor, waits for the hostname, starts the issuer on loopback.
- **torrc:** `HiddenServicePort 443 127.0.0.1:7444`, `HiddenServicePoWDefensesEnabled 1`, `SafeLogging 1`.
- **`docker-compose.stagenet.yml`:** `issuer` + `wallet-rpc` (`network_mode: service:issuer`, loopback only, `--wallet-file`, `--rpc-login` from a secret) + `monerod` (same namespace, `--proxy socks5://127.0.0.1:9050 --tx-proxy tor,socks5://127.0.0.1:9050,16 --pad-transactions`, RPC on loopback with `--rpc-login`, not restricted). No published ports. Volumes: `issuer-data` (redb, journal, sealed keys; encrypted disk), `wallet`, `tor-keys`, `export` (payout batches). The 3 staging relays get the same ES.
- `monero-release.pin` and `scripts/monero-pin-bump.sh` (human-run; verifies `hashes.txt` with the committed `binaryfate.asc`, fingerprint `81AC591F…DF92`, RM §9.1).

### 6.8 Runbooks (`ghost/infra/issuer/RUNBOOK.md`, Romanian; each a checklist with the expected output)

| Id | When | Summary |
|---|---|---|
| K1–K4 | §3.3 | key ceremony; ES publication ≥ 8 weeks ahead; biweekly key load; destruction |
| C1 | price change | a new ES with a price entry for a future price epoch only |
| R1 | daily | read `status.json`: wallet reachable and synced, pool ≥ 16, scanner not stalled, no `REORG_AFTER_ISSUE` or `SIGN_FAULT` increment |
| R2 | weekly | reconciliation (§6.9), including the workstation view and relay aggregates |
| R3 | `CONFIRMED_UNISSUED` > 0 | expected after client loss; nothing to do (blind); counted in revenue |
| R4 | `SCANNER_STALLED` | deep reorg or daemon desync: resync monerod; never force expiry |
| R5 | wallet loss | view-wallet restore with the lookahead replay (§7.5) |
| B1 | hourly (automatic), restore on demand | encrypted redb snapshot, hourly kept 48 h and daily kept 7 d, older deleted; restore = snapshot + journal replay + pool reset (§6.3, §19.5) |
| P1 | weekly | payout export → workstation check → build → cold sign → random broadcast → acknowledge (§9.5) |
| M1 | Monero release | pin bump PR; the regtest job must pass |
| M2 | before a hard fork | pin bump to the fork release; the regtest scenario must prove view-only and cold signing work; flush pending payout batches; else maintenance (`UNAVAILABLE` for new invoices) |
| O1 | relay operators, every ES | install the ES ≥ 8 weeks ahead; keep `nullifiers.redb` on the encrypted disk; **never restore it from an old backup** (an old set reopens replay). After a loss, start with `--nullifiers-reset`: the relay itself refuses redemptions (`UNAVAILABLE`) for every period whose acceptance window was open at the time of the reset, i.e. through `start(week(now) + 2) + 1 h` when the reset falls in the last 24 h of a week, else through `start(week(now) + 1) + 1 h` (§19.10) |
| I1 | issuer compromise suspected | stop the issuer (relays keep working); new ceremony for the weeks after the window; the next ES revokes the leaked future access weeks and every INVITE and CREDIT epoch whose key was in memory; the issuer refuses those invites and credits at once; reconciliation over the exposure window; announce (§19.1) |

### 6.9 Reconciliation (THREAT_MODEL S2, spec C-06)

Per-week counters, updated in the transaction of the event: `packs_xmr`, `packs_credit`, `xmr_credited_atomic`, `overpaid_atomic`, `unattributed_atomic`, `trials`, `signed[kind][epoch]`, `credits_discount`, `credits_discount_atomic`, `credits_payout`, `credits_refreshed`, `payout_queued_atomic`, `payout_paid_atomic`, `reorg_after_issue`, `confirmed_unissued`.

Invariants (`ghost-issuer-ops reconcile-check`, exit code ≠ 0 on violation):

- `signed[ACCESS][w] = 16·|slots(w)|·(packs covering w) + 8·|slots(w)|·(trials covering w)`;
- `signed[INVITE] = 2·(packs_xmr + packs_credit)`; `signed[CREDIT] = packs_xmr + credits_refreshed`;
- per credit epoch c: `credits_discount + credits_payout + credits_refreshed ≤ signed[CREDIT][c]`;
- `payout_paid_atomic ≤ payout_queued_atomic ≤ Σ_c credits_payout[c] · price(c)/10`; `credits_discount_atomic ≤ Σ_c credits_discount[c] · price(c)/10` (§19.8);
- `xmr_credited_atomic ≥ price · packs_xmr` for each price epoch;
- incoming to minors ≥ 1 = credited + overpaid + unattributed (§19.6).

Independent checks a compromised issuer cannot fake:

1. The payout workstation's **own** view wallet sums incoming value to minors ≥ 1 per height range; the total must be ≥ `packs_xmr · price` (RM §4.7); cumulative payouts ≤ 10 % of the cumulative incoming it measured (§19.7).
2. Each relay operator reports per-week redemption counts for its slot (an aggregate the operator knows anyway); for every week w, **the sum over all slots** ≤ `16·|slots(w)|·(packs covering w) + 8·|slots(w)|·(trials covering w)` (§19.3; the per-slot split is a blinded client choice the issuer cannot enforce). Together with the ≤ 6-week key window this bounds free access minting by a compromised issuer.

### 6.10 Failure modes

| Failure | Effect | Users affected |
|---|---|---|
| Issuer down | no new invoices, trials, claims | existing tokens and relays keep working (offline verification; ES keys ≥ 26 weeks ahead; spec §6.3, RC G29) |
| Wallet or monerod down or unsynced | invoices stay AWAITING/SEEN; no EXPIRED decisions; new XMR invoices get `UNAVAILABLE` until a synced scanner tick less than 2 min old exists (§19.6) | purchases wait within grace; alarm |
| Deep reorg (> 100 blocks) | scanner stops negative decisions; `REORG_DEPTH` | as above |
| Keys for a needed epoch not loaded | `UNAVAILABLE` on affected `BlindSign` | fail closed; the client retries at its next due time |
| Client ES horizon < 5 weeks | the client refuses to buy (`UPDATE_REQUIRED`) | fail closed |
| redb corruption or host loss | issuer refuses to start | restore = snapshot + journal (B1); no double issuance |
| Relay restart | persisted nullifiers survive; identical retries re-minted identically | none |
| FCMP++ fork with broken view-only wallets | new purchases stop (maintenance) | runbook M2; tokens and relays unaffected |

---

## 7. Monero rail (I4)

R-monero is the normative basis (cited RM §n); this section records the decisions and the GHOST-specific rules.

### 7.1 Deployment and authentication

| Item | Decision | Rejected alternative (reason) |
|---|---|---|
| monerod | self-hosted in the issuer's network namespace; p2p via Tor (`--proxy socks5://…`, `--tx-proxy tor,socks5://…,16`, `--pad-transactions`); RPC on loopback with `--rpc-login`; not restricted (it is the trusted daemon); `--prune-blockchain` allowed | a remote node (sees the wallet's queries; cannot be trusted for key-image import) |
| wallet-rpc | v0.18.5.1 pinned by SHA-256 (`22a7dda7…c9958`, linux x64, `monero-release.pin`); `--wallet-file` (never `--wallet-dir`, which would let a caller swap the wallet); `--rpc-login` from a Docker secret or `RPC_LOGIN`; `--log-level 0` to tmpfs; `network_mode: service:issuer`, loopback only | `--restricted-rpc` (blocks `get_transfers`, `refresh`, error −7, RM §0.3); `--disable-rpc-login` (any co-located process could call `query_key` and read the view key, RM §0.4) |
| RPC client | in-house JSON-RPC over `hyper-util` + `http-body-util` + `serde_json`, RFC 2617 digest (`qop=auth`, MD5 via `md-5`, nonce caching, retry on `stale=true`); typed errors `Transport`, `Auth`, `Rpc{code}`, `Decode`, no catch-all; amounts `u64` end to end (clippy `float_arithmetic` denied in the rail module); long timeout only for `refresh` | `monero-rpc` (depends on the banned `reqwest`, RM §0.5) |
| Network | `ES.network`: stagenet for the private alpha (Phase 16), mainnet later, regtest (mainnet prefixes) in CI | taking the network from issuer responses |

### 7.2 Subaddress pool and invoice creation (G-8)

- **Pool refill** (background, every 60 s while fewer than 32 entries): `create_address {"account_index":0,"count":1}` → `(address_index m, address)`; validate locally (§7.7: subaddress prefix of the ES network, Keccak-256 checksum, both keys decompress) and require `m = highest_minor + 1`; on a mismatch (a lost response of an earlier call) run the `get_address` reconciliation in the process (`highest_minor := count − 1`), count `POOL_RECONCILED` and continue (§19.6); one write transaction `address_pool[m] = address`, `highest_minor = m`. A crash between the call and the commit only burns an index.
- **Startup reconciliation:** `get_address {"account_index":0}` gives the wallet's subaddress count; `highest_minor := max(highest_minor, count − 1)`. The restore replay count is therefore always an upper bound (RM §3.3).
- **`RequestInvoice`** takes the lowest-minor pool entry inside its write transaction, so it never waits on wallet-rpc. Minor 0 is never handed out; `label` stays empty (the mapping lives only in redb).
- Invoice heights: `created_height` = the daemon height of the scanner's last tick, which must be synced and less than 2 minutes old (else `UNAVAILABLE`, §19.6), `seen_deadline = created + ES.invoice_blocks (720)`, `grace_height = seen_deadline + ES.grace_blocks (2 160)`.

### 7.3 Scanner and crediting rule (normative; stateless recomputation)

```
scan_tick_at(now):                                    // every 30 s ± 10 s, independent of client calls
  refresh; h = rail.height() -> {wallet, daemon, synced}          // any error: no progress, no state change
  open = invoices in {CREATED, SEEN, CONFIRMED} ∪ {ISSUED, not purged}
  from = min(created_height over open) − 20                        // reorg margin
  xs   = get_transfers {"in":true,"pool":true,"account_index":0,"filter_by_height":true,
                        "min_height":from,"max_height":h.wallet}  // one call per tick for the whole account
  for inv in open:
      credited = Σ amount over `in` entries with subaddr_index == {0, inv.minor}, confirmations ≥ ES.confirmations (10),
                 unlock_time == 0, double_spend_seen == false, height ≥ inv.created_height − 20, and either
                 height ≤ inv.grace_height or (txid already in credited_tx for inv and height ≤ inv.grace_height + 100)
      seen     = Σ amount over `pool` entries (not double_spend_seen, unlock_time 0) and `in` entries below 10 confirmations
      apply the §5.4 transition table; EXPIRED only if h.synced; record credited txids in credited_tx
      ISSUED invoice whose credited txid vanished or changed height -> reorg_after_issue += 1
  unattributed += Σ qualifying amounts mined in (scan_final_height, h.wallet − C] to minors ≥ 1 that have no invoice,
                  or whose invoice is EXPIRED, or that were not credited to their invoice (height > grace rule); minor 0
                  (treasury, payout change) is never counted
  one write transaction: changed invoices, credited_tx, counters, scan_final_height = h.wallet − C (if synced)
```

- A tick is idempotent: running it twice on the same wallet view changes nothing. Reorgs within the wallet's 100-block window are handled by recomputation, not by special cases.
- Client calls never reach the wallet: `BlindSign` and `InvoiceStatus` read the database only (timing side channel and DoS, RM §4.2).
- The wallet's `suggested_confirmations_threshold` is ignored: a per-amount N would vary per invoice and become a tagging vector.

### 7.4 Edge cases (each is a regtest step, §13.3)

| Case | Behaviour | Disclosure (Phase 13 text, FR-6.8 screen) |
|---|---|---|
| Underpayment | UNDERPAID; the client shows `amount − credited − seen` and builds a top-up URI to the same subaddress; transfers sum | "pay the exact amount; a shortfall can be topped up within the window" |
| Overpayment | CONFIRMED; the excess only in `overpaid_atomic` | "no refunds" |
| `unlock_time ≠ 0` | never credited | "payments with a lock time are not accepted" |
| Pool double spend | a `double_spend_seen` pool entry never counts | — |
| Pool eviction | `seen` can drop back to 0 | — |
| Reorg below 10 confirmations | credit reverts through recomputation; a txid already credited stays timely if re-mined at most 100 blocks above `grace_height` (§19.6) | — |
| Reorg deeper than 100 blocks | wallet `reorg_depth_error` → `REORG_DEPTH`; no negative decisions until the operator acts | — |
| Reorg after ISSUED | tokens stay valid (blind, no claw-back); counted | — |
| Paid after `seen_deadline`, mined before `grace_height` | credited | "24 h to pay, up to 72 h more to confirm" |
| Mined after `grace_height` (never credited before) | EXPIRED (from a synced view), purged; the funds are counted as unattributed | "a late payment cannot be matched; pay well before the deadline shown" |
| Paid from a KYC exchange | outside GHOST | FR-6.8 warning with explicit acknowledgement before the URI |

### 7.5 Restore procedure (runbook R5, RM §3.3)

1. `generate_from_keys` (treasury address + view key, no spend key) with the original `restore_height` (in `meta`).
2. `create_address count = highest_minor` in chunks of at most 65 536, or `set_subaddress_lookahead` to `highest_minor + 200`.
3. `rescan_blockchain`.
4. Start the issuer; the first tick recomputes every open invoice. Regtest step 9 proves the replay is necessary (the negative control misses invoice #240).

### 7.6 `PaymentRail` trait (FCMP++ contingency, RM §10)

```rust
pub trait PaymentRail: Send + Sync {
    fn new_address(&self) -> Result<(u32, Subaddress), RailError>;            // create_address, validated by the caller
    fn address_count(&self) -> Result<u32, RailError>;                         // get_address, startup reconciliation
    fn height(&self) -> Result<RailHeight, RailError>;                         // {wallet, daemon, synced}
    fn transfers(&self, from: u64, to: u64) -> Result<Vec<IncomingEntry>, RailError>; // in + pool
    fn transfer_by_txid(&self, txid: &[u8; 32]) -> Result<Option<IncomingEntry>, RailError>;
}
pub struct IncomingEntry { pub minor: u32, pub amount_atomic: u64, pub height: Option<u64> /* None = pool */,
                           pub confirmations: u64, pub unlock_time: u64, pub double_spend_seen: bool, pub txid: [u8; 32],
                           pub timestamp: u64 /* get_transfers `timestamp`: never read by the issuer logic; exported to
                                                 the T2 wallet view, where the operator has it anyway (§19.11) */ }
```

Production uses `MoneroWalletRpc`; tests use `ChainPort` in `tests/chain_port.rs` with exactly these fields (the regtest job checks the real wallet exposes no other field the issuer reads, RP §6.8). Before the FCMP++ fork (runbook M2) the pin is bumped and the regtest scenario must pass on the fork release; otherwise `RequestInvoice` answers `UNAVAILABLE` and existing tokens keep working (spec §6.3).

### 7.7 Address validation and URI (issuer and client share one implementation)

Implemented once in `ghost-entitlement::monero` on `sha3::Keccak256` and `curve25519-dalek` (both already in the lockfile and the Android allowlist), used by the issuer, the ops tools and the client (through JNI, §11.7):

1. length 95 (integrated addresses, 106, are refused); every character in the Monero Base58 alphabet;
2. block-wise decode (8 × 11 characters + a final 7-character block → 69 bytes); non-canonical blocks refused;
3. prefix: subaddress for invoices (mainnet and regtest 42, stagenet 36); standard or subaddress for payouts (mainnet 18/42, stagenet 24/36);
4. `Keccak-256(bytes[0..65])[0..4] == bytes[65..69]` (original Keccak padding, **not** SHA3-256);
5. both 32-byte keys decompress to Ed25519 points.

Vectors `protocol/test-vectors/monero_addresses.txt` (RM §7.1 sources plus mutated cases); regtest step 12 compares 1 000 verdicts with wallet-rpc `validate_address`. The URI is `monero:<subaddress>?tx_amount=<amount as a decimal with 12 places>`, nothing else (no `tx_description`, `recipient_name` or `tx_payment_id`), built in Rust from validated values.

### 7.8 Price and URI integrity (the Monero-side key tagging)

The issuer's only chance to link a payment to a relay redemption would be a per-client value it chooses: an amount, a confirmation count, an expiry or URI text. All of these are ES constants or client computations here; the client refuses an invoice whose amount differs from the ES price (`malformed_response`, flag `ISSUER_MISMATCH`), and the subaddress is per invoice by design and never reaches a relay.

---

## 8. Invites and trials (I7)

### 8.1 What redemption grants

The spec requires onboarding with "a signed invite or an explicitly configured genesis policy" and that "tampered, expired and replayed invites are rejected" and "inactive inviter and revoked invite fail closed" (FR-1.x). ADR-05: "Redeem la issuer: doar token + nullifier. Eligibilitatea inviter-ului = token valid, verificat offline".

| Option | What `RedeemInvite` grants | Privacy under AD-1 | Verdict |
|---|---|---|---|
| A. Activation gate only | the right to activate; the first pack is a normal purchase | the invitee's first payment is followed by brand-new identity namespaces (worst link, RP T-b) | rejected |
| B. Client-only prerequisite | nothing (no issuer call) | no link, but replays would be caught only per device | rejected (weakens replay protection) |
| **C. Trial** | blind access tokens for the current and next week, 8 per slot per week, under the ordinary access keys | onboarding funded by the invite, not a payment; relays cannot tell trial tokens from paid ones; the invitee's later pack enters use through renewal timing | **chosen** |

**Abuse bound for C (fixes E-7).** Invites come only from packs (2 per pack), and a trial yields no invites and no credits. A self-inviting ring therefore gets at most 2 trials × (2 weeks × 8) = 32 tokens per slot per pack, against 5 weeks × 16 = 80 paid: at most **40 %** extra usage by token count, less in practice (the current week of a pack is partial). `trial_per_slot` and `invites_per_pack` are ES constants (Q4).

### 8.2 Invite v2 (`:identity`, ADR-24)

```
version(1) = 2 || invite_token(354) || nonce(16) || expiry_day(4, BE, days since 1970-01-01)
|| drop_namespace(32) || drop_slots(3, ES slot numbers, distinct) || drop_key(32, X25519 public)
|| invite_signing_public_key(32) || signature(64, Ed25519 over everything before it)            = 538 bytes
Wire: "ghost://invite/" + z-base-32(538 bytes) = 15 + 861 = 876 characters.
QR: byte mode, version 21-L (capacity 929 bytes; 20-L holds only 858).
```

- **Parse order** (fail closed, as v1): scheme; no URL structure; exact-length decode; version = 2; token structure; signature; `expiry_day` ≤ start of invite epoch + 2; nonce replay (`invite_nonces`). Then, before any network call, the token is verified offline against the ES INVITE keys (JNI `nativeVerifyToken`), so an invite for an unknown or expired epoch is refused locally.
- **Migration:** version 1 is refused ("invite version unsupported"); no v1 invite ever carried a real token (RC §5).
- **Against ADR-05 and the spec:** no web host, no identity key (T16); `referral_commitment` replaced by the drop (ADR-24); the "inviter public key" of FR-1.x is the per-invite key, as ADR-05 intended; the optional encrypted contact card becomes Invite v3 in Phase 9. **No payout address in the link** (C-6).

### 8.3 Activation sequence (invitee; normative)

1. `Entitlement.activate(inviteText)`: `Invite.parseAndVerify` (local) and the offline token check.
2. One transaction: a trial purchase `prepared` {invite token, seed, base week, ES seq}; `ent_drop_target` from the invite (`waiting`); the invite nonce recorded.
3. `IdentityManager.create(ViaInvite(invite))` (local). The identity is **not active** while a trial purchase is pending: `activationState()` reports `PENDING`, and the app registers no namespace.
4. `RedeemInvite` in the foreground via `runUserIssuerCall` (the user is present; the identity has no relay traffic yet), on a fresh `IssuerFlow`; retries are byte-identical (the seed).
   - `OK` → Rust finalizes and verifies 16·S tokens; one transaction stores them (eligible at once in STANDARD, at the next activation slot in HIGH, §12.3) and marks the trial `finalized`. The identity becomes `ACTIVE`; its prekey and inbox namespaces are registered and first written with trial tokens.
   - `REPLAYED` or `unauthorized` → the trial is `failed` and `IdentityManager.wipe()` runs: no identity survives ("revoked invite fails closed").
   - `WRONG_PERIOD` → re-prepare (new seed and base week, same invite token: the issuer recorded nothing); with the ±4 h tolerance only a device clock more than 4 h off reaches this (§19.4).
   - transient → the identical retry at the next foreground attempt.
5. **Crash recovery:** a pending trial with no identity resumes at step 3, with an identity at step 4. The sequence ends either active with tokens or with no identity.

### 8.4 Per-invite derivation (fixes RP F3; ADR-24)

| Output | Derivation (invite index i, u16) |
|---|---|
| Invite signing key | Ed25519 seed = `HKDF(root, info = DerivationLabels.INVITE_SIGNING ‖ u16_be(i))` |
| Drop namespace | `HKDF(root, info = "ghost/v1/invite-drop-namespace" ‖ u16_be(i), 32)`, new label `INVITE_DROP_NAMESPACE` |
| Drop key (X25519 secret) | `HKDF(root, info = "ghost/v1/invite-drop-key" ‖ u16_be(i), 32)`, clamped, new label `INVITE_DROP_KEY` |

- The bare-label `inviteSigningKeyPair()` (one per identity, `KeyDerivation.kt:37`) is no longer used; `REFERRAL_SECRET` and `referralCommitment()` are retired. Both labels stay reserved in `DerivationLabels.ALL` (compatibility contract).
- The suffix is fixed-length, so the encoding is injective and differs in length from the bare label (no collision). New entries in `derivation_vectors.txt`.
- **Restore:** `next_invite_index` is not recoverable from the seed; after a restore the client listens to the drops of indices 0..7 for 5 weeks (`restore_scan_until_day`), then stops. Credits sent to other drops are lost (E11).

### 8.5 Invite creation (inviter)

In one transaction: reserve one fresh INVITE token; take `i = next_invite_index++`; choose 3 distinct drop slots uniformly (client randomness) among the ES slots valid from now until `listen_until_day` whose onions are active in `relay_directory`, subject to the three relays spanning at least two distinct `operator_id`s (ADR-11 quorum of `Outbox.enqueue`; re-drawn otherwise; no invite if impossible, §19.12); register the drop namespace with sync as listening (`Consumer.IDENTITY`; the CHECK already allows `identity`, `Schema.kt:192`) on those directory relays; build and sign the invite; store `ent_invite(i, created, payload, listen_until_day = expiry_day + 56)` (the drop write falls in weeks 3–7 after activation, §19.12); delete the token row. The drop needs a READ capability (interim: a redeemed write capability, §10.7).

### 8.6 Revocation, genesis, and what the issuer does not enforce

- **Revocation:** the inviter redeems its own invite (`RedeemInvite` with a trial layout) and keeps the tokens as spares; the invitee's later redemption gets `REPLAYED` and fails closed. This is inside the 40 % bound. The revocation call is automatic quiet-run work (`QuietRunWork`, one call per quiet run, its own `IssuerFlow`), never a foreground call (§19.14).
- **Genesis** is unchanged (`Activation.Genesis(policyAcknowledged)`): no trial; the first pack is bought in quiet runs and its tokens become eligible at an activation slot; the small early partition is declared (E6).
- **Invite-only is not enforced at the issuer.** Gating purchases on an invite would link the invite to the invoice. A modified client can activate without an invite, but gets no trial and no inviter; channels stay invite-scoped by MLS (Phase 10) and DMs need a `ghost1…` identifier. Declared (Q11).

### 8.7 Issuer-side invite state

`invite_nullifier[(invite_epoch, N)] → trial digest`, kept until the start of epoch + 2 (the whole acceptance window, MS-3), journaled (§6.3); counter `trials(w)`. Nothing else.

### 8.8 T16 extended

- Parser: v2 happy path; every field tampered; every length other than 538; expired; replayed (nonce store); unknown epoch; an ACCESS or CREDIT token in the invite field; wrong challenge origin; a v1 string refused; no web host; no identity key; two invites of one inviter carry different public keys and drops.
- Redeem: the issuer accepts once; an identical retry is re-served; a different blinded set → `REPLAYED`; a burned invite → `REPLAYED`; the previous epoch accepted, epoch − 2 refused; activation fails closed with no identity left.
- Derivation: per-invite keys distinct across i and stable across restore (vectors).

---

## 9. Referral and payouts (I8)

### 9.1 Options

| Option | Issuer learns | Relays learn | Cap by construction | Verdict |
|---|---|---|---|---|
| ADR-02 as written: one commitment per identity, credited at every payment, preimage claim | every invitee's invoices grouped under the inviter; a long-lived pseudonym; the claim links all of them (RP F2, G1) | nothing | yes | rejected |
| A. Per-invite commitment, first payment only, claimed per commitment | commitment ↔ the invitee's first invoice; payout address ↔ that invoice | nothing | yes | fallback if the owner rejects B (Q5) |
| Credit tokens redeemed by the payer toward an inviter address carried in the invite (delivery variant) | the payout address groups one invitee's credits; the address travels in every copy of the link | nothing | yes | rejected (C-6) |
| **B. Blind credit tokens delivered end to end through a sealed drop** | only aggregates: how many credits a claim or discount presents, and when | an edge "cluster X wrote one blob into a namespace cluster Y lists", the same kind of edge every DM creates (L2.1) | yes (§9.6) | **chosen** |

### 9.2 Credit issuance

- Exactly one CREDIT position in every **XMR-paid** pack (§4.2), worth `pack_price(price_epoch) / 10`. A credits-paid pack carries none (no compounding).
- Credit epochs are 13 weeks; a credit is accepted in its epoch and the four following (52–65 weeks of validity, §19.8). With 13 weeks a continuous single-pack user (one pack per 4 weeks, ≈ 3.25 credits per epoch) holds at most about 7 valid credits and would never reach a discount; with 52–65 weeks it reaches 10 after about 40 weeks (§19.8).
- Every paying client receives its credit; what happens next is invisible to the issuer:
  - if the identity was activated via an invite and this is its **first** XMR-paid pack bought before its pre-drawn drop time, the credit goes to the inviter's drop at that time (§9.3, §19.12);
  - otherwise the client keeps it; kept credits covering the price (10 at an unchanged price) pay for a pack (the self-referral discount ADR-02 anticipates).
- **Economics change (ADR-02 deviation, Q5):** the inviter is rewarded once per invitee (10 % of one pack), not "la fiecare plată". Every-payment credit without a link would need the invitee to keep sending credits to the inviter for years, which makes the drop a long-lived edge.

### 9.3 Delivery through the drop

**Sealing** (`:identity`, BouncyCastle `X25519Agreement` and `ChaCha20Poly1305`, HKDF on the existing platform-based `Hkdf.kt`; no new dependency; this extends the BouncyCastle surface approved by ADR-17 (Ed25519 only) and is recorded as deviation X15 in ADR-24, §19.12):

```
eph  <- X25519 key pair (fresh)
key  = HKDF-SHA256(ikm = X25519(eph, drop_key), salt = drop_namespace, info = "ghost/v1/drop-seal", L = 32)
blob = eph_pub(32) || ChaCha20-Poly1305(key, nonce = 0^12, aad = drop_namespace,
                                        plaintext = 0x01 || credit_token(354) || zero padding to 976 bytes)
     = 32 + 976 + 16 = 1 024 bytes: exactly one 1 KiB bucket (T9)
```

- **Invitee (§19.12):** at activation the client draws `t_drop` uniformly in `[start(base + 3), start(base + 8))` (client randomness, persisted in `ent_drop_target.until_day` and a minute column), independent of any purchase. At `t_drop` it writes **exactly one** blob: the credit of its first XMR pack if one exists and was not used, else a dummy (plaintext `0x00` ‖ zeros, sealed identically, indistinguishable). The drop namespace is registered write-only (`Consumer.IDENTITY`) on the three drop-slot relays; write capabilities come from the identity's current tokens; an identity without coverage at `t_drop` writes nothing (relays already see it inactive). *(§19.28 point 3: coverage is an ACCESS token of the week or later, fresh or reserved, or a write capability, usable or exhausted, reaching the end of the week; an identity that redeemed every token of the week is covered.)* A credit minted after `t_drop` stays with the payer. After a `sent`/`degraded` outcome the namespace is removed.
- **Inviter:** `Inbox.claim(Consumer.IDENTITY)`; for each blob: open it; a dummy is consumed and dropped; a credit is verified against the ES (JNI), then in one transaction stored as the input of a new `refresh` purchase row (`ent_purchase.kind = 'refresh'`, `input_token` = the received credit, a fresh seed; §19.8), `markConsumed`, the invite set `credited`, listening stopped. A received credit is never presented in `RequestInvoice` or `ClaimPayout`; it is first exchanged by `RefreshCredit` in its own quiet run, on its own `IssuerFlow`, at one of two times drawn when the invite was created, never at a time the read sets (§19.26) *(§19.29: at the one time drawn when the drop is registered, 1–14 days after its listening ends, after every read; the read decides nothing)*. An invalid blob is consumed and dropped. The drop stops being listened at `listen_until_day` in any case, and nothing is taken from it from that day on (§19.26). In Phase 8 only drop namespaces are registered under `Consumer.IDENTITY`; a later IDENTITY consumer (Phase 9) must route by the entitlement module's known drop namespaces.

### 9.4 Redemption

- **Discount (default):** `RequestInvoice` with the smallest set of credits covering the price (10 at an unchanged price; §4.6, §19.8), in a quiet run like any purchase; auto-renewal with credits needs no user presence. Received credits are refreshed first (§9.3).
- **XMR payout (`ClaimPayout`, optional):** at most one claim per week, in a quiet run, on its own `IssuerFlow`, at a PRF time, never in the same quiet run as another issuer call (J9, mutant M12); `min_claim_credits` (10, equal to the discount's floor, so the payout is never the easier path, §19.8) to `max_claim_credits` (50); the payout address is typed by the user, validated locally (Rust, §7.7), must be a standard address or subaddress of the ES network, and is refused if its salted hash is in `ent_payout_used` (RP V11); write-ahead of `claim_id`, address and reserved credits; identical retries by `claim_id`.
- **Disclosure:** "use a fresh subaddress of your own wallet, never an exchange deposit address"; "do not pay GHOST with referral payouts before churning them" (EAE, RP G5); "no receipt acknowledgement" (Janus, RP G6).

### 9.5 Payout pipeline (option B of RM §6; ADR-26)

1. **Issuer (weekly, at a uniformly random time):** assigns every queued claim to a new `batch_id` (journaled `BATCH` entry, §19.5) and writes `batch-<id>.ghpb` = `{batch_id, week, entries shuffled [(claim_id, address, amount_atomic)], total_atomic, cumulative_credited_atomic}`, signed with the Ed25519 ops key. Re-export of an unacknowledged batch rewrites the identical file.
2. **Operator workstation** (separate host; its own view-only wallet-rpc and trusted monerod over Tor) runs `ghost-issuer-ops payout-check`: the signature; **cumulative** `paid_so_far + total ≤ 10 % × Σ incoming to minors ≥ 1 measured by its own view wallet since the treasury's restore height` (independent of the issuer database, S2; §19.7); every address (§7.7); no repeated address; no `batch_id` and no `claim_id` processed before (local ledger). *(§19.22 point 2 and §19.27 point 3: a repeated address or a `claim_id` of an earlier batch refuses its entry, not the batch; a repeated `batch_id`, or one `claim_id` twice in a batch, refuses the batch.)*
3. **Per entry, with a ledger state machine** `built → signed → submitted → confirmed` (txid and input key images recorded, §19.7): entry k+1 is built only after entry k has been submitted by the workstation (`submit_transfer` marks its inputs spent in the workstation wallet), so no two entries select the same inputs (a watch-only `transfer` reserves nothing); one recipient plus change (ring size 16) → one `unsigned_txset`; on the air-gapped cold wallet `describe_transfer` (recipient and amount must match the batch; change must go to the treasury) and `sign_transfer`; `submit_transfer` at a uniformly random moment within 72 h of the previous submission, through `--tx-proxy tor`; afterwards the key-image refresh (RM §6.1 steps 1–4 and 9). Freezing a built entry's inputs with `freeze` (to sign several entries in one cold session) is allowed only once S6 regtest proves it. An entry is rebuilt only after its old inputs are proven unspent and its old signed transaction destroyed.
4. **Acknowledge per entry:** after 10 confirmations of its txid `ghost-issuer-ops` acknowledges the entry; when every entry is acknowledged the batch is paid (`BATCH_PAID`); the issuer deletes the addresses and keeps only `payout_paid_atomic`.

No step puts a spend key online (MS-5). Rejected: the issuer builds unsigned transactions (needs key images and a trusted daemon on the internet-facing host); a hot payout wallet (contradicts ADR-02); 16-output batch transactions (co-payees learn about each other; rare on-chain shape, RM §6.3).

### 9.6 Cap proof (MS-4)

1. Credits signed ≤ XMR-paid packs: exactly one CREDIT position per XMR invoice (layout), counted in `signed[CREDIT]`.
2. Each credit is redeemed at most once: credit nullifiers kept and journaled for the whole acceptance window.
3. The value of a redeemed credit = 10 % of the price of the pack that produced it: credit epoch = price epoch of its pack, value = price(credit epoch) / 10, whatever the epoch of redemption (§19.8). A refresh consumes one credit and mints one of the same epoch (net zero).
4. Payout = Σ value of the credits presented (per-credit epoch price); a discount pack is granted only if Σ value of the presented credits ≥ its price, so discount value ≤ Σ value of the credits presented. Hence payout + discount value ≤ Σ value of redeemed credits ≤ 10 % × Σ XMR revenue, across price changes. The workstation independently bounds cumulative XMR payouts by 10 % of cumulative incoming (§19.7).

Self-referral is at most a 10 % discount. Cycles cannot arise: an identity is invited once, at activation.

### 9.7 Deferrable scope

If the schedule must be cut (§15.3), two parts can move to Phase 9 without weakening a gate property, because the Invite v2 drop fields are frozen now:

- (i) **XMR payouts** (S6 minus the discount path): credits accumulate as a self-discount; MS-4 and P-6 are unchanged.
- (ii) **Drop delivery** (parts of S8/S9): credits stay with the payer until Phase 9 adds delivery; the inviter's reward waits.

---

## 10. Relay redemption (I6)

### 10.1 `relay.proto` additions

```proto
enum RedeemResult {
  REDEEM_RESULT_UNSPECIFIED = 0;
  REDEEM_RESULT_OK = 1;
  REDEEM_RESULT_REPLAYED = 2;       // nullifier already bound to another namespace
  REDEEM_RESULT_WRONG_PERIOD = 3;   // outside the acceptance window; nothing recorded, the token stays spendable
}

message RedeemTokenRequest {
  uint32 version = 1;               // MUST be 1
  bytes token = 2;                  // 354 bytes, Privacy Pass type 0x0002, kind ACCESS for this relay's slot
  bytes namespace_id = 3;           // 32 bytes: the namespace the write capability is for
  bytes request_id = 4;             // 16 random bytes; identical on an identical retry (T1 field)
}

message RedeemTokenResponse {
  RedeemResult result = 1;
  Capability capability = 2;        // OK only: write capability v2 (98 bytes, §10.3)
  uint64 relay_period_id = 3;       // always: the relay's current week (R9 clock source)
  uint64 relay_minute = 4;          // always: the relay's unix time / 60 (R9 clock source)
}

service RelayService {
  // ... the existing five RPCs ...
  rpc RedeemToken(RedeemTokenRequest) returns (RedeemTokenResponse);
}
```

### 10.2 Verification order (normative; `Relay::redeem_at(req, now)`, exactly one capture event)

1. Redeem disabled (no `--schedule`) → `UNIMPLEMENTED`, result `rejected_capability`.
2. Global token bucket (default 50 redeems/s, burst 500) → `RESOURCE_EXHAUSTED`, `rejected_capability`.
3. `version == 1`, `len(token) == 354`, `len(namespace_id) == 32`, `len(request_id) == 16` → else `INVALID_ARGUMENT`, `rejected_size`.
4. `token_type == 0x0002`; `token_key_id` is an ES ACCESS key of week p, not revoked; the ES lists this relay's onion for its slot **in week p** → else `PERMISSION_DENIED`, `rejected_token`.
5. `p > closed_through_period` (persisted high-water, never lowered; §19.10) **and** `start(p) − early_window ≤ now < start(p+1) + 1 h` → else `OK` with `WRONG_PERIOD`, `rejected_period`; nothing recorded. After a `--nullifiers-reset`, periods up to `refuse_through_period` → `UNAVAILABLE`, `rejected_capability`.
6. `challenge_digest == SHA-256(challenge(ACCESS, p, my_slot))` → else `rejected_token`.
7. `ring` PSS verification → else `rejected_token`.
8. `N = nullifier(token_input)`; binding tag `b = HMAC-SHA256(relay_key, "ghost/v1/redeem-binding" ‖ period ‖ N ‖ 0x02 (write) ‖ namespace_id)[0..16]`.
9. `NullifierStore::record_or_get(p, N, b)` in one redb write transaction, **committed (fsync) before minting**: absent → insert; present with the same `b` → idempotent retry; present with another `b` → `OK` with `REPLAYED`, `rejected_nullifier`.
10. **Deterministic mint:** capability v2 `{Write, namespace_id, quota = ES.capability_quota_bytes, expiry = start(p+1) + 3600, serial = HMAC-SHA256(relay_key, "ghost/v1/cap-serial" ‖ period ‖ N)[0..16]}`; respond `OK`; result `ok`, `capability_scope` = hash of the minted capability.

Every response carries `relay_period_id` and `relay_minute`. Every error message is a constant (`node/src/lib.rs:56-59`). Invalid tokens are rejected before any disk write; the relay offers no oracle distinguishing forged, wrong-kind and wrong-slot tokens (all `rejected_token`).

### 10.3 Capability v2 (X9)

```
version(1) = 2 || kind(1) || namespace(32) || quota_bytes(8, BE) || expiry_unix(8, BE) || serial(16) || mac(32)   = 98 bytes
mac = HMAC-SHA256(relay_key, bytes 0..66)
```

- **Why a serial, and why deterministic** (C-3, fixes E-8). Without a serial, every writer redeeming for the same namespace in the same week would receive byte-identical capabilities and share one quota ledger, so one member could exhaust a channel's writes. A per-nullifier serial gives each token its own capability and ledger entry; deriving it with the relay key makes an identical retry, even after a restart, receive identical bytes (MS-8) without storing capabilities.
- **Parsing.** `ghost_relay_api::capability_header` parses v1 and v2 (the serial is not part of the header struct); `RelayKey::verify` checks the MAC over either body. The sync store is unaffected (tokens are opaque, ≤ 512 bytes). v1 stays for CLI-minted capabilities.
- **Expiry is week-aligned for everyone**, so it is not a per-client value; the client checks it equals `start(p+1) + 3600` exactly.

### 10.4 Nullifier storage (X1, ADR-25; G-7)

- A separate `<data-dir>/nullifiers.redb`, `SCHEMA_VERSION = 1`; the blob store stays at v2 (RC §3.6).
- Tables: `nullifiers`: `period(8) ‖ nullifier(32)` → binding tag (16); `es_keys`: `(kind, epoch)` → key id (append-only memory for ES rule 5); `redemption_counts`: period → the number of rows the sweep deleted for it, the final redemption count of a closed week, kept for the last 13 closed weeks (§19.24 point 10); `meta` (`closed_through_period`, `refuse_through_period`, `sweep_high_water_minute`). No times of events, no namespaces, no request ids.
- **Sweep** (every 60 s, the existing loop): in one write transaction, first raise `closed_through_period` to p, then delete every period p whose window has closed (`now ≥ start(p+1) + 1 h`). The sweep never runs while `now` is below the persisted `sweep_high_water_minute` (a backward clock step), and a closed period is refused whatever the clock says (§19.10). At most two periods are live (§3.4). This replaces `current_period` = UTC day (`node/src/lib.rs:122-125`, RC G1).
- **Restart:** the persisted set survives, so no replay (RC G2 closed); identical retries are re-minted identically. The `QuotaLedger` stays in memory (RC G4 accepted): a writer may exceed its quota once per restart, bounded by the week-aligned expiry; declared in ADR-25.
- **Privacy at rest (AD-12):** random 32-byte values and 16-byte tags, stored in key order (no insertion order). They reveal the redemption count per week, which the operator knows anyway. With the relay key also seized, a tag lets the holder test candidate namespaces, linking a nullifier to a namespace for at most two weeks; the relay's own blob store already implies which namespaces redeemed. Declared.
- Rejected: memory only with a refusal window after restart (does not stop replay of tokens redeemed before the restart; costs availability); persisting inside `blobs.redb` (a blob-schema v3 migration coupling two concerns).

### 10.5 Relay configuration

- `RelayConfig` gains `entitlement: Option<EntitlementPolicy { schedule: Arc<Schedule>, slot: u8 }>`, default `None` (redeem disabled), so the three existing callers of `Relay::open` compile unchanged (RC G26).
- Flags `--schedule <file>`, `--slot <n>`, `--onion-hostname-file <path>` (Tor's `HiddenServiceDir/hostname`; the binary cannot learn its own onion otherwise, `main.rs:4-7`; §19.10), and `--nullifiers-reset` (runbook O1), and `--redemption-counts <file>` (runbook R2, §19.24 point 10). At start: verify the ES with the pinned key, check rule 5 against `es_keys`, read the onion from the hostname file and check that it is listed for this slot in the current week, enforce `revoked`; refuse to start otherwise (negative tests for each). A missing `nullifiers.redb` next to an existing `relay.key` without `--nullifiers-reset` (or the one-time `--nullifiers-init` of the Phase 8 upgrade) is a refusal to start. An ES update is a restart; persisted nullifiers survive it.
- Runbook O1 for relay operators (§6.8).

### 10.6 Capture and T1 (X10)

- `capture::Event` gains `nullifier: Option<String>` (hex 64) and `period_id: Option<String>` (hex 16), both already allowed by `allowed-observables.json`.
- The redeem event carries `op = "redeem"`, `protocol_version`, `namespace_id`, `nullifier`, `period_id`, `capability_scope` (the hash of the minted capability, `ok` only), `request_id`, `time_bucket`, `result`.
- `result` values used: `ok`, `rejected_size`, `rejected_capability`, `rejected_nullifier` (existing) and **`rejected_token`, `rejected_period` (new, ADR-25)**. No `key_id` is added: with one key per (kind, week) it is a function of `period_id`.
- `two_nodes.rs` gets redemptions (ok, identical retry, replay to another namespace, wrong slot, wrong week, forged) and asserts that neither the token, the authenticator nor the minted capability appears in the capture, only its scope hash.

### 10.7 Read capabilities: the Phase 8 decision (D11, LIMITE L2.1 #2)

1. Access tokens buy only write capabilities.
2. Reads use **shared read keys**: for each (namespace, epoch) a 32-byte bearer secret derived from material the legitimate readers already share: `HKDF(MLS exporter, "ghost/v1/read-cap", epoch)` for channels (Annex B, Phase 10); the recipient's identity-derived inbox read secret (Phase 9); public read, or a bearer derived from `ghost1…`, for prekeys (decided in Phase 9, Annex B).
3. A write-capability holder registers `SHA-256("ghost/v1/read-verifier" ‖ read_secret)` with a new relay RPC `RegisterReadKey(namespace, epoch, verifier, write_capability)`, specified here and implemented in Phase 9 with its first consumer. `list`, `get` and `check` then accept either a registered read secret or a write capability.
4. All readers of a namespace present the **same** secret, so the relay can no longer tell readers apart (closes L2.1 #2 for reads; cursor cookies stay a Phase 12 item).

**Interim (Phase 8):** a READ MISSING need is fulfilled by redeeming a *write* capability for that namespace, since write grants read (`capability/src/lib.rs:85-87`). The only listening-only namespaces before Phase 9 are the client's own inbox and invite drops. **Rejected:** token-bought per-client read capabilities (they multiply the relay-visible "firsts" that follow purchases, spend tokens on every listened namespace and make reader linkability permanent); free reads for anyone who knows a namespace id (contacts could watch an inbox's volume).

### 10.8 Conformance vectors `redeem.txt` (G-4)

About 30 cases in `protocol/test-vectors/redeem.txt`: ok; identical retry → identical capability; identical retry after a simulated restart → identical capability; retry for another namespace → `REPLAYED`; wrong slot; slot mapped to another relay in that week; invite- and credit-key tokens; weeks p−2 and p+2; window edges (`start − 24 h`, `start − 24 h − 1 s`, `end + 1 h − 1 s`, `end + 1 h`); a flipped byte in each of the five token fields; an unknown key id; lengths 353 and 355; a revoked epoch; redeem disabled; the sweep boundary. Replayed by the Rust relay (`tests/redeem_vectors.rs` through `redeem_at`) and by the Kotlin `ModelRedeemRelay` in the entitlement harness. `relay_semantics.txt` and its two pinned replayers stay unchanged (RC G19).

### 10.9 Client side (`client-core`)

`NamespaceClient::redeem(&self, token: &[u8; 354], request_id: [u8; 16], deadline) -> Result<RedeemOutcome>`:

- Runs on the namespace's own circuit (`IsolationScope::Namespace`, T21); the relay links the redemption to the namespace anyway by minting for it.
- **Before any I/O:** token length and type; the token's challenge names the slot the ES assigns to *this* relay's onion in the token's week. A token bound elsewhere never leaves the device (0 requests, 0 connections; mutant M6).
- **After the response:** `OK` → the capability parses as v2, kind Write, namespace = the bound namespace, quota = ES value, `expiry == start(p+1) + 3600`; any response → `relay_period_id` within ±1 of the client's week. Otherwise `malformed_response`. `relay_period_id` and `relay_minute` feed only relay-facing decisions, never `base_week` or issuer scheduling (§19.4).
- JNI returns `result(1) ‖ relay_period(8) ‖ relay_minute(8) ‖ expiry(8) ‖ capability(98 | 0)`, which is what `Capabilities.put` needs (RC G11). Kotlin never parses the capability.

### 10.10 Abuse

Invalid tokens are rejected before any disk write; `ring` verification is cheap (tens of µs); every valid token was paid for and costs one fsync; the onion keeps `HiddenServicePoWDefensesEnabled 1`. No per-client rate limit is possible or needed beyond PoW and the global bucket.

---

## 11. Android `:entitlement` module (I10)

### 11.1 Layout (`ghost/android/entitlement/src/main/kotlin/org/ghost/entitlement/`)

```
api/     Entitlement.kt (facade for Phase 13) EntitlementStatus.kt PaymentInstructions.kt Disclosure.kt Types.kt
engine/  EntitlementEngine.kt PurchaseSteps.kt TrialSteps.kt RedeemPlanner.kt RedeemLane.kt DropSteps.kt ClaimSteps.kt
         QuietRunWork.kt Slots.kt (activation slots) Grid.kt (weeks, epochs) ClockEstimate.kt RetryPolicy.kt Gc.kt
store/   PurchaseStore.kt TokenStore.kt InviteStore.kt ClaimStore.kt KeyStore.kt StateStore.kt Sql.kt
port/    IssuerPort.kt RedeemPort.kt TokenCryptoPort.kt EntitlementClock.kt EntitlementRandom.kt SealPort.kt
android/ TorIssuerPort.kt TorRedeemPort.kt NativeTokenCrypto.kt EntitlementParticipant.kt EntitlementWiring.kt
```

- The engine is pure JVM (no `android.*`, `java.net.*`, `javax.net.*`); only `android/` touches the platform.
- Project dependencies: `:sync` (`Capabilities`, `Namespaces`, `Outbox`, `Inbox`, `SyncDatabase`, the new `SessionParticipant`), `:storage`, `:network`, `:identity`. **No new Maven coordinate** (Gradle allowlist unchanged).
- Gates: `kotlin-clearnet.sh`, `anti-placeholder.sh`, `no-logging.sh` as for every module; **`sync-no-catch-all.sh` extended to `android/entitlement/src/main`** (RC G17), with a fixture and a new count in `self-test.sh`.

### 11.2 Facade for Phase 13 (UI-less; counts and enums only; `toString()` redacted)

```kotlin
interface Entitlement {
    fun status(): EntitlementStatus                           // coverage-end week, fresh tokens per week (counts), credits, flags
    fun startPurchase(payWith: PayWith): PurchaseId?          // local only; null if the ES horizon < 5 weeks or own fresh credits do not cover the price
    fun requiredDisclosures(id: PurchaseId): Set<Disclosure>  // KYC_EXCHANGE (FR-6.8), NO_REFUND, EXACT_AMOUNT, NO_LOCK_TIME, WINDOWS
    fun acknowledge(id: PurchaseId, disclosures: Set<Disclosure>)
    fun paymentInstructions(id: PurchaseId): PaymentInstructions?  // null until invoiced AND all disclosures acknowledged
    fun requestInvoiceNow(id: PurchaseId)                     // optional; declared L3 sample; STANDARD mode only
    fun checkNow(id: PurchaseId)                              // optional; declared L3 sample; STANDARD mode only
    fun cancel(id: PurchaseId): Boolean                       // only while no payment instructions were ever shown
    fun activate(inviteText: String): ActivationResult         // onboarding (§8.3); foreground
    fun activationState(): ActivationState                    // NONE, PENDING, ACTIVE, FAILED
    fun createInvite(expiryDay: Int): String?                 // ghost://invite/...; null without a fresh invite token
    fun revokeInvite(index: Int): Boolean
    fun claimPayout(address: String): ClaimId?                // validated locally; runs in a quiet run
    fun setAutoRenewWithCredits(enabled: Boolean)
    fun paymentScreenShown(id: PurchaseId)                    // §19.11: closes the relay session and holds relay sessions off
}
class PaymentInstructions(val subaddress: String, val amountAtomic: Long, val outstandingAtomic: Long,
                          val deadlineMinute: Long, val uri: String)   // uri for the outstanding amount; null after the deadline
```

`EntitlementStatus.flags ⊆ {ENTITLEMENT_NEEDED, UPDATE_REQUIRED, SCHEDULE_CONFLICT, ISSUER_MISMATCH, REFUSED_BY_RELAY, PAYMENT_READY, PAYMENT_EXPIRED, PAYMENT_LOST, CLOCK_UNTRUSTED}`. Local notifications are Phase 13; Phase 8 exposes `PAYMENT_READY`, surfaced only at the first natural foreground at least U[1 h, 6 h] after the invoice arrived, never as an immediate notification (§19.11). `ENTITLEMENT_NEEDED` is surfaced at a client-random time within U[0, 12 h] after it arises (§19.13).

### 11.3 Schema v3 (exact SQL; `Migration(version = 3, statements = listOf(...))`, append-only, fail-closed)

```sql
-- (0) Fail-closed guard: the v1 `entitlement` and `referral` tables never had a writer (RC G15).
CREATE TABLE v3_migration_guard (row_count INTEGER NOT NULL CHECK (row_count = 0));
INSERT INTO v3_migration_guard(row_count) SELECT count(*) FROM entitlement;
INSERT INTO v3_migration_guard(row_count) SELECT count(*) FROM referral;
DROP TABLE v3_migration_guard;
DROP TABLE entitlement;
DROP TABLE referral;

-- (1) Accepted ES keys: the device's append-only memory of (kind, epoch) -> key id (ES rule 5).
CREATE TABLE ent_key (
    kind    TEXT    NOT NULL CHECK (kind IN ('access', 'invite', 'credit')),
    epoch   INTEGER NOT NULL CHECK (epoch >= 0),
    key_id  BLOB    NOT NULL CHECK (length(key_id) = 32),
    PRIMARY KEY (kind, epoch)
) WITHOUT ROWID;

-- (1b) Accepted ES layout and price facts (ES rule 5, §19.2): the slot-number set of every covered week and the
--      price of every covered price epoch, as SHA-256 digests. Append-only like ent_key.
CREATE TABLE ent_schedule_fact (
    fact    TEXT    NOT NULL CHECK (fact IN ('slots', 'price')),
    epoch   INTEGER NOT NULL CHECK (epoch >= 0),
    digest  BLOB    NOT NULL CHECK (length(digest) = 32),
    PRIMARY KEY (fact, epoch)
) WITHOUT ROWID;

-- (2) Singleton. payout_salt is created with the row (SecureRandom) and never leaves the device.
CREATE TABLE ent_state (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    schedule_seq           INTEGER NOT NULL CHECK (schedule_seq >= 1),
    schedule_digest        BLOB    NOT NULL CHECK (length(schedule_digest) = 32),
    next_invite_index      INTEGER NOT NULL DEFAULT 0 CHECK (next_invite_index BETWEEN 0 AND 65535),
    payout_salt            BLOB    NOT NULL CHECK (length(payout_salt) = 32),
    restore_scan_until_day INTEGER CHECK (restore_scan_until_day IS NULL OR restore_scan_until_day >= 0),
    auto_renew_credits     INTEGER NOT NULL DEFAULT 0 CHECK (auto_renew_credits IN (0, 1)),
    alarm_flags            INTEGER NOT NULL DEFAULT 0 CHECK (alarm_flags BETWEEN 0 AND 7)  -- SCHEDULE_CONFLICT | ISSUER_MISMATCH | REFUSED_BY_RELAY
);

-- (3) Issuance flows (packs, the trial, and refreshes of received credits, §19.8). Live rows carry their secrets;
--     terminal rows carry none and are deleted by GC at terminal_day + 7. `sent` = the current request has left
--     the device at least once.
CREATE TABLE ent_purchase (
    purchase_id     BLOB    PRIMARY KEY NOT NULL CHECK (length(purchase_id) = 16),   -- local only, never sent
    kind            TEXT    NOT NULL CHECK (kind IN ('pack', 'trial', 'refresh')),
    pay_with        TEXT    NOT NULL CHECK (pay_with IN ('xmr', 'credits', 'invite', 'credit')),
    state           TEXT    NOT NULL CHECK (state IN ('prepared', 'invoiced', 'finalized', 'expired', 'failed', 'lost')),
    seed            BLOB    CHECK (seed IS NULL OR length(seed) = 32),
    claim_key       BLOB    CHECK (claim_key IS NULL OR length(claim_key) = 32),
    invoice_id      BLOB    CHECK (invoice_id IS NULL OR length(invoice_id) = 16),
    subaddress      TEXT    CHECK (subaddress IS NULL OR length(subaddress) = 95),
    amount_atomic   INTEGER CHECK (amount_atomic IS NULL OR amount_atomic >= 0),
    input_token     BLOB    CHECK (input_token IS NULL OR length(input_token) = 354),  -- invite (trial) or received credit (refresh)
    base_week       INTEGER CHECK (base_week IS NULL OR base_week >= 0),
    schedule_seq    INTEGER CHECK (schedule_seq IS NULL OR schedule_seq >= 1),
    layout_digest   BLOB    CHECK (layout_digest IS NULL OR length(layout_digest) = 32),
    sent            INTEGER NOT NULL DEFAULT 0 CHECK (sent IN (0, 1)),
    disclosed       INTEGER NOT NULL DEFAULT 0 CHECK (disclosed IN (0, 1)),
    shown           INTEGER NOT NULL DEFAULT 0 CHECK (shown IN (0, 1)),             -- payment instructions ever shown
    prev_state      INTEGER NOT NULL DEFAULT 0 CHECK (prev_state BETWEEN 0 AND 6),   -- latest InvoiceState (UX, lost vs expired)
    created_hour    INTEGER CHECK (created_hour IS NULL OR created_hour % 3600 = 0),  -- NULL in terminal states (§19.15)
    receipt_minute  INTEGER CHECK (receipt_minute IS NULL OR receipt_minute % 60 = 0), -- invoice receipt; deadline = +24 h
    outstanding_atomic INTEGER CHECK (outstanding_atomic IS NULL OR outstanding_atomic >= 0), -- amount − credited − seen
    next_due_minute INTEGER CHECK (next_due_minute IS NULL OR next_due_minute % 60 = 0),
    attempt         INTEGER NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 40),
    terminal_day    INTEGER CHECK (terminal_day IS NULL OR terminal_day >= 0),
    CHECK ((kind = 'trial') = (pay_with = 'invite')),
    CHECK ((kind = 'refresh') = (pay_with = 'credit')),
    CHECK (kind = 'pack' OR (claim_key IS NULL AND invoice_id IS NULL AND subaddress IS NULL AND amount_atomic IS NULL
                             AND receipt_minute IS NULL AND outstanding_atomic IS NULL)),
    CHECK (kind <> 'pack' OR input_token IS NULL),
    CHECK (kind = 'pack' OR state <> 'invoiced'),
    CHECK (state IN ('finalized', 'expired', 'failed', 'lost')
           OR (terminal_day IS NULL AND seed IS NOT NULL AND base_week IS NOT NULL AND schedule_seq IS NOT NULL
               AND layout_digest IS NOT NULL AND created_hour IS NOT NULL AND (kind <> 'pack' OR claim_key IS NOT NULL)
               AND (kind = 'pack' OR input_token IS NOT NULL))),
    CHECK (state NOT IN ('finalized', 'expired', 'failed', 'lost')
           OR (terminal_day IS NOT NULL AND seed IS NULL AND claim_key IS NULL AND invoice_id IS NULL
               AND subaddress IS NULL AND amount_atomic IS NULL AND input_token IS NULL AND next_due_minute IS NULL
               AND created_hour IS NULL AND receipt_minute IS NULL AND outstanding_atomic IS NULL)),
    CHECK (state <> 'invoiced' OR (invoice_id IS NOT NULL AND amount_atomic IS NOT NULL AND receipt_minute IS NOT NULL
           AND ((amount_atomic = 0) = (subaddress IS NULL))))
) WITHOUT ROWID;

-- (4) Tokens. Keyed by the (random) nullifier: no insertion order, no purchase link at rest. A token leaves
--     the table when spent, lost or out of its window; it is never marked "spent".
CREATE TABLE ent_token (
    nullifier          BLOB    PRIMARY KEY NOT NULL CHECK (length(nullifier) = 32),
    kind               TEXT    NOT NULL CHECK (kind IN ('access', 'invite', 'credit')),
    epoch              INTEGER NOT NULL CHECK (epoch >= 0),
    slot               INTEGER CHECK (slot IS NULL OR slot BETWEEN 0 AND 31),
    token              BLOB    NOT NULL CHECK (length(token) = 354),
    state              TEXT    NOT NULL CHECK (state IN ('fresh', 'reserved')),
    eligible_minute    INTEGER NOT NULL CHECK (eligible_minute % 60 = 0),
    reserved_for       TEXT    CHECK (reserved_for IS NULL OR reserved_for IN ('relay', 'purchase', 'claim')),
    reserved_relay     INTEGER,                              -- relay_directory.relay_id (no FK: Phase 7 GC of retired relays)
    reserved_namespace BLOB    CHECK (reserved_namespace IS NULL OR length(reserved_namespace) = 32),
    request_id         BLOB    CHECK (request_id IS NULL OR length(request_id) = 16),
    reserved_ref       BLOB    CHECK (reserved_ref IS NULL OR length(reserved_ref) = 16),
    CHECK ((kind = 'access') = (slot IS NOT NULL)),
    CHECK ((state = 'reserved') = (reserved_for IS NOT NULL)),
    CHECK (reserved_for IS NULL OR reserved_for <> 'relay'
           OR (kind = 'access' AND reserved_relay IS NOT NULL AND reserved_namespace IS NOT NULL
               AND request_id IS NOT NULL AND reserved_ref IS NULL)),
    CHECK (reserved_for IS NULL OR reserved_for = 'relay'
           OR (kind = 'credit' AND reserved_ref IS NOT NULL AND reserved_relay IS NULL
               AND reserved_namespace IS NULL AND request_id IS NULL))
) WITHOUT ROWID;
CREATE UNIQUE INDEX idx_ent_token_one_reservation
    ON ent_token(reserved_relay, reserved_namespace, epoch) WHERE reserved_for = 'relay';

-- (5) Invites this identity created (inviter side), with the refresh time of a credit sent to
-- the drop, drawn at creation (§19.29; the late_refresh_minute of §19.26 is removed).
CREATE TABLE ent_invite (
    invite_index        INTEGER NOT NULL PRIMARY KEY CHECK (invite_index BETWEEN 0 AND 65535),
    state               TEXT    NOT NULL CHECK (state IN ('created', 'credited', 'closed')),
    payload             BLOB    CHECK (payload IS NULL OR length(payload) = 538),
    drop_namespace      BLOB    NOT NULL CHECK (length(drop_namespace) = 32),
    listen_until_day    INTEGER NOT NULL CHECK (listen_until_day >= 0),
    refresh_minute      INTEGER NOT NULL CHECK (refresh_minute % 60 = 0),
    CHECK (state = 'created' OR payload IS NULL)
) WITHOUT ROWID;

-- (6) The inviter's drop this identity owes its first XMR-pack credit to (invited identities only).
CREATE TABLE ent_drop_target (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    drop_namespace BLOB    NOT NULL CHECK (length(drop_namespace) = 32),
    drop_key       BLOB    NOT NULL CHECK (length(drop_key) = 32),
    drop_slots     BLOB    NOT NULL CHECK (length(drop_slots) = 3),
    state          TEXT    NOT NULL CHECK (state IN ('waiting', 'enqueued')),
    operation_id   BLOB    CHECK (operation_id IS NULL OR length(operation_id) = 16),
    drop_minute    INTEGER NOT NULL CHECK (drop_minute % 60 = 0),   -- t_drop, drawn at activation (§19.12)
    until_day      INTEGER NOT NULL CHECK (until_day >= 0),
    CHECK ((state = 'enqueued') = (operation_id IS NOT NULL))
);

-- (7) Payout claims (write-ahead).
CREATE TABLE ent_claim (
    claim_id        BLOB    PRIMARY KEY NOT NULL CHECK (length(claim_id) = 16),
    state           TEXT    NOT NULL CHECK (state IN ('prepared', 'queued', 'failed')),
    payout_address  TEXT    CHECK (payout_address IS NULL OR length(payout_address) = 95),
    queued_atomic   INTEGER CHECK (queued_atomic IS NULL OR queued_atomic > 0),
    sent            INTEGER NOT NULL DEFAULT 0 CHECK (sent IN (0, 1)),
    next_due_minute INTEGER CHECK (next_due_minute IS NULL OR next_due_minute % 60 = 0),
    attempt         INTEGER NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 20),
    terminal_day    INTEGER CHECK (terminal_day IS NULL OR terminal_day >= 0),
    CHECK ((state = 'prepared') = (payout_address IS NOT NULL AND next_due_minute IS NOT NULL AND terminal_day IS NULL)),
    CHECK ((state = 'queued') = (queued_atomic IS NOT NULL)),
    CHECK (state = 'prepared' OR terminal_day IS NOT NULL)
) WITHOUT ROWID;
CREATE UNIQUE INDEX idx_ent_claim_one_open ON ent_claim(state) WHERE state = 'prepared';

-- (8) Salted hashes of payout addresses already used (refuse reuse, RP V11): HMAC-SHA256(payout_salt, address).
CREATE TABLE ent_payout_used (
    address_hash BLOB    PRIMARY KEY NOT NULL CHECK (length(address_hash) = 32),
    until_day    INTEGER NOT NULL CHECK (until_day >= 0)
) WITHOUT ROWID;

-- ===== State machines and write-once rules enforced in SQL (Phase 7 D8 precedent; G-12) =====
CREATE TRIGGER ent_key_append_only BEFORE UPDATE ON ent_key
BEGIN SELECT RAISE(ABORT, 'ent_key is append-only'); END;

CREATE TRIGGER ent_key_no_delete BEFORE DELETE ON ent_key
BEGIN SELECT RAISE(ABORT, 'ent_key is append-only'); END;

CREATE TRIGGER ent_schedule_fact_append_only BEFORE UPDATE ON ent_schedule_fact
BEGIN SELECT RAISE(ABORT, 'ent_schedule_fact is append-only'); END;

CREATE TRIGGER ent_schedule_fact_no_delete BEFORE DELETE ON ent_schedule_fact
BEGIN SELECT RAISE(ABORT, 'ent_schedule_fact is append-only'); END;

CREATE TRIGGER ent_purchase_transitions BEFORE UPDATE OF state ON ent_purchase
WHEN NOT ((OLD.state = NEW.state)
       OR (OLD.state = 'prepared' AND NEW.state IN ('invoiced', 'finalized', 'failed'))
       OR (OLD.state = 'invoiced' AND NEW.state IN ('finalized', 'expired', 'failed', 'lost')))
BEGIN SELECT RAISE(ABORT, 'illegal purchase transition'); END;

-- Seed, claim key, layout and base week may change only while nothing has been sent (prepared, sent = 0);
-- `sent` never goes back; kind and pay_with never change. Wiping at a terminal state is allowed.
CREATE TRIGGER ent_purchase_frozen BEFORE UPDATE ON ent_purchase
WHEN NEW.kind IS NOT OLD.kind OR NEW.pay_with IS NOT OLD.pay_with
  OR (NEW.state NOT IN ('finalized', 'expired', 'failed', 'lost')
      AND (NEW.sent < OLD.sent
           OR ((OLD.sent = 1 OR OLD.state <> 'prepared')
               AND (NEW.seed IS NOT OLD.seed OR NEW.claim_key IS NOT OLD.claim_key
                    OR NEW.base_week IS NOT OLD.base_week OR NEW.schedule_seq IS NOT OLD.schedule_seq
                    OR NEW.layout_digest IS NOT OLD.layout_digest OR NEW.input_token IS NOT OLD.input_token))))
BEGIN SELECT RAISE(ABORT, 'issuance secrets and layout are frozen once sent'); END;

CREATE TRIGGER ent_purchase_invoice_frozen BEFORE UPDATE OF invoice_id, subaddress, amount_atomic ON ent_purchase
WHEN NEW.state NOT IN ('finalized', 'expired', 'failed', 'lost') AND OLD.invoice_id IS NOT NULL
 AND (NEW.invoice_id IS NOT OLD.invoice_id OR NEW.subaddress IS NOT OLD.subaddress
      OR NEW.amount_atomic IS NOT OLD.amount_atomic)
BEGIN SELECT RAISE(ABORT, 'an invoice is recorded once'); END;

CREATE TRIGGER ent_purchase_delete_terminal_only BEFORE DELETE ON ent_purchase
WHEN OLD.state NOT IN ('finalized', 'expired', 'failed', 'lost')
BEGIN SELECT RAISE(ABORT, 'a live purchase is never deleted'); END;

-- A reservation ends only by deletion, except that credits of a failed flow return to fresh.
CREATE TRIGGER ent_token_state BEFORE UPDATE OF state ON ent_token
WHEN NOT ((OLD.state = NEW.state)
       OR (OLD.state = 'fresh' AND NEW.state = 'reserved')
       OR (OLD.state = 'reserved' AND NEW.state = 'fresh' AND OLD.kind = 'credit' AND
           ((OLD.reserved_for = 'purchase'
             AND (SELECT state FROM ent_purchase WHERE purchase_id = OLD.reserved_ref) = 'failed')
         OR (OLD.reserved_for = 'claim'
             AND (SELECT state FROM ent_claim WHERE claim_id = OLD.reserved_ref) = 'failed'))))
BEGIN SELECT RAISE(ABORT, 'a reservation ends only by deletion'); END;

-- R8 in SQL: a token never changes, and a reserved token keeps its relay, namespace, request id and reference.
CREATE TRIGGER ent_token_binding BEFORE UPDATE ON ent_token
WHEN NEW.nullifier IS NOT OLD.nullifier OR NEW.kind IS NOT OLD.kind OR NEW.epoch IS NOT OLD.epoch
  OR NEW.slot IS NOT OLD.slot OR NEW.token IS NOT OLD.token OR NEW.eligible_minute IS NOT OLD.eligible_minute
  OR (OLD.state = 'reserved' AND NEW.state = 'reserved'
      AND (NEW.reserved_for IS NOT OLD.reserved_for OR NEW.reserved_relay IS NOT OLD.reserved_relay
           OR NEW.reserved_namespace IS NOT OLD.reserved_namespace OR NEW.request_id IS NOT OLD.request_id
           OR NEW.reserved_ref IS NOT OLD.reserved_ref))
BEGIN SELECT RAISE(ABORT, 'a token and its reservation keep their binding'); END;

CREATE TRIGGER ent_invite_transitions BEFORE UPDATE OF state ON ent_invite
WHEN NOT ((OLD.state = NEW.state)
       OR (OLD.state = 'created'  AND NEW.state IN ('credited', 'closed'))
       OR (OLD.state = 'credited' AND NEW.state = 'closed'))
BEGIN SELECT RAISE(ABORT, 'illegal invite transition'); END;

CREATE TRIGGER ent_claim_guard BEFORE UPDATE ON ent_claim
WHEN NOT ((OLD.state = NEW.state AND (NEW.payout_address IS OLD.payout_address) AND NEW.sent >= OLD.sent)
       OR (OLD.state = 'prepared' AND NEW.state IN ('queued', 'failed')))
BEGIN SELECT RAISE(ABORT, 'a claim keeps its address and is decided once'); END;

CREATE TRIGGER ent_drop_target_transitions BEFORE UPDATE ON ent_drop_target
WHEN NOT ((OLD.state = NEW.state AND NEW.operation_id IS OLD.operation_id)
       OR (OLD.state = 'waiting' AND NEW.state = 'enqueued'))
BEGIN SELECT RAISE(ABORT, 'illegal drop target transition'); END;
```

Result: **9 tables and 13 triggers** (§19.2 added `ent_schedule_fact` and its two triggers). Updated in the same commit: `Schema.CURRENT_VERSION = 3`; `expectedTables` (− `entitlement`, `referral`; + the 9 `ent_*` tables); `expectedTriggers` (+ 13); `SchemaAndMigrationTest` versions `[1, 2, 3]` (RC G16), including the guard failing on non-empty v1 tables and interruption at every statement; a new **`EntitlementSchemaIntrospectionTest`** pinning the exact time columns (`created_hour`, `receipt_minute`, `next_due_minute` ×2, `terminal_day` ×2, `eligible_minute`, `drop_minute`, `listen_until_day`, `until_day` ×2, `restore_scan_until_day`), their granularity CHECKs and "no other time-named column" under the Phase 7 regex (`SchemaIntrospectionTest.kt:60`), with the explicit exemption of the `epoch` columns of `ent_key`, `ent_schedule_fact` and `ent_token` (week and epoch indices, not times); the former `last_state` is named `prev_state` so that the regex's `last_` does not match (§19.17). The sync `SchemaIntrospectionTest` scans only sync tables and stays unchanged (checked in S8).

**Never persisted:** PRF keys and quiet-run draws (per process), flow ids, clock offsets, any issuer response other than the listed fields, times finer than a minute, blinded messages, blind signatures, r, inverses.

### 11.4 State machines (client)

| Machine | States and transitions | Guard (every UPDATE is `WHERE state = <expected> AND …`, `execUpdate == 1`) |
|---|---|---|
| Pack (XMR) | `prepared` (base week refreshed while `sent = 0`) →(`RequestInvoice` OK, validated) `invoiced` →(`SIGNED`, all tokens verified) `finalized`; `invoiced` →(EXPIRED) `expired`; `invoiced` →(`unauthorized` after purge, last state not EXPIRED) `lost`; live →(`malformed_response` twice, `OTHER_REQUEST_ISSUED`, `CLAIM_CONFLICT`, `WRONG_PERIOD` re-prepare, user cancel before `shown`) `failed` | frozen trigger; invoice written once |
| Pack (credits) | as above; the smallest set of own (never received, §19.8) fresh credits covering the price is reserved (`reserved_for = 'purchase'`) in the transaction that sets `sent = 1` for the first `RequestInvoice`, and deleted in the finalizing transaction; `CREDITS_SPENT` deletes the masked credits and releases the rest (`failed`) | reservation trigger |
| Trial | `prepared` →(`RedeemInvite` OK) `finalized`; →(`REPLAYED`, `unauthorized`) `failed` + identity wipe; `WRONG_PERIOD` → `failed` + a new `prepared` trial with the same invite token | frozen trigger |
| Pack attempt plan (§19.11) | at most 5 `BlindSign` attempts per invoice at due times derived from the seed and `receipt_minute` (3 planned, 2 slow); after the fifth non-final answer → `lost` | `attempt` column, J9 cap |
| Refresh (§19.8) | `prepared` (received credit in `input_token`, seed) →(`RefreshCredit` OK) `finalized` (one fresh credit inserted in `ent_token`); →(`REPLAYED`, `unauthorized`) `failed` (the received credit is dropped) | frozen trigger |
| Token | `fresh` →(reserve) `reserved` →(OK / `REPLAYED` / `unauthorized` / window over) **deleted**; `fresh` →(window over) **deleted**; credit `reserved` → `fresh` only for a failed flow | state and binding triggers (R8 in SQL) |
| Invite | `created` →(credit received) `credited` →(`listen_until_day`) `closed` → GC | payload dropped when leaving `created` |
| Drop target | `waiting` →(enqueue at `eligible_minute` + PRF) `enqueued` →(outcome released) **deleted** | transition trigger |
| Claim | `prepared` (+ `ent_payout_used` row in the write-ahead of each send, §19.28 point 2) →(`QUEUED`) `queued` (credits deleted) or `failed` (credits deleted per mask or released; the `ent_payout_used` row stays) | claim guard |

### 11.5 Crash safety (client)

Phase 7 rules carry over: **no network call inside a transaction**; each step is a short transaction, the call, a short transaction; every mutating statement is guarded by its expected state; a crash is treated like an ambiguous timeout; retries send identical bytes.

| Crash point | State after restart | Recovery |
|---|---|---|
| after `startPurchase`, before any send | `prepared`, `sent = 0` | normal: refresh base week and layout if the week changed, send |
| after setting `sent = 1` (credits reserved), before or after the send | `prepared`, `sent = 1` | the identical `RequestInvoice` (idempotent by claim hash) |
| after the invoice was persisted | `invoiced` | continue; the URI is shown only from persisted fields |
| after a `BlindSign` send, before persisting | `invoiced` | Rust recomputes the identical request from the seed; MS-1 |
| inside the finalizing transaction | atomic: tokens + `finalized` + wipe, or nothing | redo |
| after reserving a token, before or after the redeem call | `reserved` with `request_id` | the identical redeem at the same relay and namespace (trigger-enforced R8) |
| inside the redeem result transaction | atomic: `Capabilities.put` + token delete, or nothing | redo (identical capability, MS-8) |
| drop blob enqueue | `waiting` or `enqueued` with the Outbox op in the same transaction | normal Outbox semantics (Phase 7) |
| claim after `sent = 1` | `prepared` | identical retry by `claim_id` |

### 11.6 Integration with sync: `SessionParticipant` (new public API in `:sync`; ADR-23 amends ADR-20)

```kotlin
package org.ghost.sync.api

/** One slot (like the consumer listener). The entitlement engine is the only implementer in Phase 8. */
interface SessionParticipant {
    /** A relay session (foreground, or a normal background run) is READY. Own thread, until the session ends. */
    fun onRelaySession(session: ParticipantSession)
    /** A quiet run started (1/8 of background runs, drawn independently). Must return before the deadline. */
    fun onQuietRun(session: ParticipantSession)
}
enum class SessionKind { FOREGROUND, BACKGROUND, QUIET, USER_ISSUER_CALL }
interface ParticipantSession {
    val kind: SessionKind
    val relayRedeem: RelayRedeemAccess?   // FOREGROUND and BACKGROUND only
    val issuer: IssuerAccess?             // QUIET and USER_ISSUER_CALL only
    fun clockTrusted(): Boolean
    val deadlineMonotonicMillis: Long
    val closed: Boolean                   // lease closed: every call fails `closed` (retryable)
}
interface RelayRedeemAccess {
    fun redeem(relay, namespace, token, requestId, deadlineMillis): RedeemAnswer
    fun stepDone()                        // one redeem-lane step has run; ends a redeem hold (§19.23 point 5, Q29)
}
// SyncController (existing interface) gains:
//   fun setParticipant(p: SessionParticipant?)
//   fun runUserIssuerCall(block: (ParticipantSession) -> Unit)   // ensures READY on the one transport
```

- **Why an API change in `:sync` and not a second transport:** two Arti clients must not share a state directory, and a second bootstrap per purchase would be a timing fingerprint (LIMITE L4, RC G9). The one transport stays owned by `SyncRuntime`; `RelayRedeemAccess` and `IssuerAccess` are leases on it.
- **Quiet runs (§19.14):** the decision lives in a pure-JVM component `QuietRunScheduler` in the `:sync` engine, drawing from the injected `RandomSources` (never a bare `SecureRandom`); `SyncRuntime` calls it at job start and the Phase 7 harness and the NI-K/J9 worlds drive the same component. One run in 8 is quiet, whether or not entitlement work is due; the decision takes no entitlement state as input (its signature has none), so it cannot depend on pending work (mutant M20). The transport is made READY, `onQuietRun` is called, the transport is aborted, the job finishes. A quiet run touches no relay pair. Foreground sessions are never quiet. The periodic job, its extras and its schedule are unchanged (T20).
- **Quiet-run work** (`QuietRunWork`): **at most one issuer call per quiet run** (J9), the most overdue of: a purchase step (`RequestInvoice` or a planned `BlindSign`), an auto-renewal step (if enabled, coverage ends within 2 weeks, enough fresh credits to cover the price exist and no credits pack that sent its `RequestInvoice` and failed is still kept, §19.28 point 1), a due claim, a due `RefreshCredit` of a received credit (§19.8), an invite revocation (§19.14). It runs on a fresh `IssuerFlow` and ends with `nativeEndFlow`. A transient failure waits for a later quiet run.
- **Redeem lane** (relay sessions), one thread per session:
  1. At READY + U[0, 30 s] and then every 60 s ± 50 %, read `Capabilities.needed()` (its own transaction; polling, because there is one listener slot, RC G10).
  2. Plan each need (§12.4) and execute due items in time order: **tx1** reserve a fresh, eligible token of the right (week, slot) with a new random `request_id` (guard `state = 'fresh' AND eligible_minute <= now`); **call** `nativeRedeem` on the namespace's circuit; **tx2**, one `SyncDatabase.transaction`:

     | Result | Effect |
     |---|---|
     | `OK` | if the relay and namespace are still registered: `Capabilities.put(tx, relay, ns, WRITE, capability, expiry)` and delete the token (guard `state = 'reserved' AND request_id = ?`); otherwise delete the token |
     | `REPLAYED` | delete the token (counter `tokens_replayed`; impossible without a bug or a restored database) |
     | `unauthorized` | delete the token; flag `REFUSED_BY_RELAY` (a key or configuration inconsistency, possibly tagging) |
     | `WRONG_PERIOD` | token week > relay week: keep the reservation, retry after `start(week) − 23 h`; token week < relay week: delete |
     | transient (`transport`, `timeout`, `relay_unavailable`, `closed`, `tor_*`) | keep the reservation; identical retry at the next lane step |
     | the reservation outlives the token's window | delete the token |

  3. `relay_period_id` and `relay_minute` update the in-memory **relay-facing** clock estimate (§12.5); they never reach issuer-facing decisions (§19.4).
  4. A need on a directory relay that is listed in no ES slot for the token week is never redeemed and never raises `ENTITLEMENT_NEEDED`; it is counted `NO_SLOT` (§19.12).
- **Redeem hold (§19.23 point 5, Q29):** a BACKGROUND session that starts, with a participant installed, while `Capabilities.needed()` holds a WRITE need of any reason stays the activity after its lanes have ended (transport READY, the participant's lease open) until the redeem lane reports its first step (`RelayRedeemAccess.stepDone()`), the job's deadline, or a stop (a foreground wanted, the payment screen, onStopJob, a wipe). The decision is the pure `:sync` component `RedeemHold`, whose only inputs are the pending write-need count read at the session's start and the deadline; a session whose transport failed or went offline is not held. The hold starts only after the lanes have finished, so the read lane is unchanged (T19). Declared residue E30.
- **User calls:** onboarding (`activate`) and the optional buttons use `runUserIssuerCall`.
- **Drops:** consumption in relay sessions (`Inbox.claim(Consumer.IDENTITY)`); sending through `Outbox.enqueue`. Both are ordinary sync consumer operations.
- **`SessionParticipantTest`** (G-10): T19 holds with a participant that fails every call and with one that runs until the deadline; a quiet run issues zero `RelayPort` calls; a relay session exposes no `IssuerAccess`; a held session ends at the lane's first step, at its deadline, and at once on each of its four stops (after onStopJob no job end is reported; after a wipe `awaitIdle` returns). The Phase 7 exit-gate suites stay green unchanged.

### 11.7 JNI surface (`client-core`; only `String`, `ByteArray`, `Int`, `Long` cross; fixed-layout results; strict decoders)

| Kotlin class (`:network`) | Native function | Returns |
|---|---|---|
| `EntitlementCrypto` (stateless; the ES is built into the library) | `nativeScheduleSummary()` | ES digest (32) ‖ seq ‖ network ‖ first/last week ‖ constants ‖ slot table ‖ prices ‖ key ids per (kind, epoch) ‖ revoked list |
| | `nativeLayoutDigest(product, baseWeek)` (layouts no longer depend on the ES seq, §19.2; product ∈ pack-xmr, pack-credits, trial, refresh(epoch)) | `digest(32) ‖ N(4)` |
| | `nativeVerifyToken(token, kind)` | `kind(1) ‖ epoch(8) ‖ slot(1) ‖ nullifier(32)`, or `rejected` |
| | `nativeValidateAddress(address, purpose)` / `nativePaymentUri(subaddress, amountAtomic)` | network/type code / `String` |
| `TorIssuerTransport` (same `jlong` handle registry as `TorRelayTransport`, RC §4.3) | `nativeRequestInvoice(h, flow16, claimHash, credits, baseWeek, deadlineMs)` | `result(1) ‖ invoice_id(16) ‖ amount(8) ‖ subaddress(0 or 95) ‖ spent_mask(4)`, **validated in Rust** against the ES |
| | `nativeBlindSign(h, flow16, invoiceId, claimKey, seed, product, baseWeek, layoutDigest, deadlineMs)` | `state(1) ‖ credited(8) ‖ seen(8) ‖ N × (nullifier(32) ‖ token(354))` on `SIGNED`; Rust recomputes the request from the seed, checks the layout digest, checks every `s'^e ≡ B`, finalizes and verifies with `ring` |
| | `nativeInvoiceStatus(h, flow16, invoiceId, claimKey, deadlineMs)` | `state(1) ‖ credited(8) ‖ seen(8)` |
| | `nativeRedeemInvite(h, flow16, inviteToken, seed, baseWeek, layoutDigest, deadlineMs)` | `result(1) ‖ N_t × (nullifier ‖ token)` |
| | `nativeClaimPayout(h, flow16, claimId, credits, address, deadlineMs)` | `result(1) ‖ queued(8) ‖ spent_mask(4)` |
| | `nativeRefreshCredit(h, flow16, receivedCredit, seed, layoutDigest, deadlineMs)` (§19.8) | `result(1) ‖ nullifier(32) ‖ token(354)` on `OK` |
| | `nativeEndFlow(h, flow16)` | drops the flow's isolation token |
| `TorRelayTransport` | `nativeRedeem(h, relay, namespace, token, requestId, deadlineMs)` | §10.9 layout |

- The Rust `IssuerClient` uses the hyper-over-Arti connector of `RelayClient` (tonic `codegen` only): fixed origin `ES.issuer_onion`, HTTP/2, no user agent, deadline `min(deadlineMs, 60 s)` and 120 s for `BlindSign`/`RedeemInvite` (up to 161 KiB each way over Tor).
- `IsolationScope::Issuer` (unit) is replaced by `IssuerFlow([u8; 16])`: Rust maps a flow id to a fresh `IsolationToken` in a bounded map cleared when the transport closes; the `compile_fail` doctest (`lib.rs:38-43`) is updated (it runs only on nightly, §18 F5). A `client-core` unit test (stable, every PR) asserts distinct tokens per `IssuerFlow`, the token dropped by `nativeEndFlow`, and no reuse after the transport closes; mutant M4 is implemented against it (§19.17).
- Kotlin never parses protobuf, tokens or capabilities; the (kind, epoch, slot) stored next to a token come from the layout order. R8 keep rules go into `android/network/consumer-rules.pro`.

### 11.8 Secrets and T3

Canaries (the `PrivacyHarnessTest.kt:225-295` pattern) for: `seed`, `claim_key`, `invoice_id`, subaddress, amount, tokens, nullifiers, `request_id`, the invite token, drop key and namespace, payout address, `claim_id`. Each is grepped across everything the process emits (exceptions, `toString()`, status, JNI error categories). Every holder class has a redacted `toString()` (the `OpaqueId` convention). Blinded messages, blind signatures and r never reach Kotlin, so no canary is needed for them outside Rust, where the `client-core` T3 test covers JNI error strings.

### 11.9 What is JVM-provable, and what is device-only

- **JVM-provable:** every state machine and trigger; crash enumeration over every SQL statement of every flow; the redeem planner, slots and quiet-run work against `entitlement_policy.txt`; NI-K twin worlds (§13.4); drop sealing vectors; Invite v2 and T16; T3 canaries; a new `:entitlement` harness world where the real entitlement engine feeds the real sync engine through `ModelRedeemRelay` and `ModelIssuer` (conformance-pinned by `redeem.txt` and `issuer_semantics.txt`), proving the liveness premise: every `CapabilityNeed` is fulfilled while eligible tokens exist. The Phase 7 stand-in `Runner.renewNeeded` stays unchanged in the `:sync` harness, whose `sync-exit-gate` keeps its tail renewal; `:entitlement` depends on `:sync`, so the real engine can only run in `:entitlement` tests (§19.17). JVM tests use `TestTokenCrypto` (BigInteger + JCA, test sources only) checked against `blind_rsa_pp2.txt`.
- **Device-only (manual until the Phase 13 emulator CI):** SQLCipher v2 → v3 on a real database; quiet runs under Doze; JNI on both ABIs; real Tor to a staging issuer and relays; an 876-character QR scan.

---

## 12. Linkability rules, client scheduling and residues (I9)

### 12.1 Rules (normative; R1–R10 of RP, adapted; each is checked by a named test)

| Rule | Statement | Checked by |
|---|---|---|
| R1 Non-interference | Nothing issuer-supplied reaches a relay. Token bytes depend only on client randomness and the ES. No relay-visible time depends on an issuer response, except through the declared activation slot (L1). | NI-1, NI-K, J1–J4 |
| R2 Keys | Keys only from the ES, verified with their proofs; key ids computed locally; every signature verified (`s'^e ≡ B`, then `ring`). | J7, J10, ES negative tests |
| R3 Grid | One product, fixed counts, public price; coverage ends on a global week boundary; the client chooses the base week. | NI-2, J7 |
| R4 Activation | Pack tokens become eligible at an activation slot (§12.3); trial tokens at once (STANDARD) or at a slot (HIGH). | NI-1, S1, S2, M3, M13 |
| R5 Isolation | `IssuerFlow(random 16 bytes)` per flow instance (a purchase step, a trial, a claim, a refresh, a revocation), dropped at the end of the call; the unit variant `Issuer` is removed. | J6, T2c, M4 (`client-core` unit test), `live-tor` |
| R6 Contacts | Automatic issuer calls only in quiet runs, **at most one per quiet run**, at most 5 `BlindSign` per invoice whatever the issuer answers; exceptions: `RedeemInvite` at onboarding and the optional user buttons (STANDARD mode only). | J9, S3, S4, NI-2, NI-K, M9, M12, M16, M20 |
| R7 Referral | No referral identifier ever reaches the issuer (credit tokens). | T2c, M10 |
| R8 Retries | Identical bytes; the same relay, namespace and `request_id`; a token that got `REPLAYED` or `unauthorized` is deleted and never shown elsewhere. | T2b, SQL triggers, M6, EM1, EM2, EM4 |
| R9 Clock | Two clocks (§19.4): issuer-facing decisions (`base_week`, issuer-call due times) use only the device wall clock under `clockTrusted()`, never relay-supplied values, and the issuer tolerates ±4 h at week boundaries; relay-facing decisions use the relay-corrected estimate (§12.5) and no redeem happens within ±1 h of a week boundary; **the issuer's clock is never used**; no client timestamp in any request. | J8, NI-3, M11, M17 |
| R10 Retention | Client issuance secrets (seed, claim key, invoice id, subaddress, amount, invite token) are wiped in the terminal transaction (CHECK-enforced); issuer retention per §6.4. | schema CHECKs, T3, retention tests |

### 12.2 Quiet runs and the issuer contact policy

Each periodic-job run (ADR-20: 15 min, flex 5 min) independently draws **quiet** with probability q = 1/8 from a per-process CSPRNG, whether or not entitlement work is due. A quiet run opens the one Tor transport, performs at most one due issuer call on a fresh flow scope, closes the transport and touches no relay pair; a normal run syncs as in Phase 7 and makes no issuer call.

| Issuer call | When | Session | Typical count per purchase |
|---|---|---|---|
| `RequestInvoice` (XMR) | first quiet run after the intent; "get invoice now" = foreground, declared L3 | quiet (default) | 1 |
| `BlindSign` | first quiet run after each planned due time (§5.3, §19.11) | quiet | 1 (≤ 5 in every case) |
| `RequestInvoice` + `BlindSign` with credits | quiet runs, no user presence needed | quiet | 2 |
| `InvoiceStatus` | "check now" button only (STANDARD) | foreground, declared L3 | 0 |
| `RedeemInvite` | onboarding | foreground, before any relay traffic of the identity, declared L3 | 1 per identity |
| `ClaimPayout` | PRF time, at most weekly | quiet | — |
| `RefreshCredit` | one of two times drawn at the invite's creation, never set by the read (§19.26) | quiet | — (1 per received credit) |
| `RedeemInvite` (revocation) | when the user revokes an invite | quiet (§19.14) | — |
| payment (not a GHOST call; seen by the operator's wallet) | when the user pays | the payment screen holds relay sessions off (§19.11); declared L6 | — |

Why this is the best available against AD-1 (RP T-c):

- **Co-presence in a relay session** (background runs of about 2 min every 15 min) gives the attacker about 3 bits per call; **in the foreground** about 5 bits per call.
- **A quiet run** is invisible to relays except as a gap in the cadence of a clustered client. It is drawn independently of purchases, so NI-1 and NI-2 hold exactly. A gap is ambiguous with Doze deferrals and with quiet runs that had no work; the residue is at most log2(1/q_eff) ≤ 3 bits per call, much less under Doze.
- **One call per quiet run** prevents the issuer from linking two of a client's flows by co-timing inside one run (J9, M12).
- Cost: 1/8 fewer background syncs (ADR-23 amends ADR-20 point 1), and an expected quiet-run spacing of about 2 h at the nominal cadence.

### 12.3 Activation slots

For a batch of pack tokens finalized at time t_f: `eligible_minute = floor_minute(first UTC-day boundary ≥ t_f + 4 h) + U[0, 6 h)` from client randomness; in HIGH mode, plus `Geometric(1/2)` whole days. Trial tokens: `eligible_minute = t_f` in STANDARD mode; in HIGH mode the pack rule, with its extra days capped at the last day of the trial's last week, `start(base + 2) − 1 day`, never below 0 (§19.23 point 5, Q30; a slot that itself falls after that day is kept, never moved earlier). A token is never used before its `eligible_minute`. A renewal bought ahead is eligible before the week it covers begins, so it adds no signal (RP T-a, T-d, T-e). Until the slot, a new identity's first stores (genesis only) wait in the Phase 7 outbox (`wait_capability`) and relays see nothing.

### 12.4 Redemption timing per need (redeem lane)

| Need (`Capabilities.needed()`) | Token week | When |
|---|---|---|
| WRITE or READ EXPIRING | p+1 | `PRF(pair, p) ∈ [start(p+1) − 23 h, start(p+1) − 1 h]`, at the first session moment after it (RP T-f) |
| WRITE MISSING (outbox has work) | p | as soon as an eligible token exists (activity-driven at the relay only: the relay sees the redeem, then the store; no issuer link) |
| READ MISSING (listening namespace) | p | `PRF(pair, p) ∈ [now, now + 6 h]` |
| EXHAUSTED, REJECTED | p | as soon as an eligible token exists |
| any, within ±1 h of a week boundary or without a trusted clock | — | deferred |
| any, on a relay listed in no ES slot for the week | — | never; counted `NO_SLOT` (§19.12) |

The PRF is HMAC-SHA-256 with a per-process random key (never persisted) over `relay_id ‖ namespace ‖ kind ‖ week`. A need with no eligible token raises `ENTITLEMENT_NEEDED` (counts only), surfaced to the user at a client-random time within U[0, 12 h]; a purchase started while it is set sends its `RequestInvoice` no earlier than U[0, 24 h] after `startPurchase` (the "get invoice now" button stays available as a declared L3 sample; §19.13). Tokens never move between relays or slots.

### 12.5 Clock estimate (R9)

- **Relay-facing only (§19.4).** The redeem lane's week and ±1 h guard use `now_est = wall + δ`, where δ is the median of `(relay_minute − local_minute)` over the latest response of each of ≥ 2 distinct relays in this process (in memory only). Before two relays have answered, `now_est = wall` under `clockTrusted()`. `relay_period_id` in a `WRONG_PERIOD` answer is adopted for that relay at once.
- **Issuer-facing.** `base_week` and issuer-call due times use `wall` under `clockTrusted()` only. Under AD-1 every relay is the adversary, so letting relay time move `base_week` or the guards would let relays make one chosen client's issuer requests recognisable (a relay → issuer covert channel). The issuer's ±4 h tolerance makes `WRONG_PERIOD` unreachable for a client within 4 h of true time. Optionally (if Arti exposes it, checked in S7) the client refuses issuer calls while `wall` lies outside the current consensus lifetime ± 10 min (flag `CLOCK_UNTRUSTED`), so a badly skewed device never reveals its skew.
- The issuer's time is never an input (R1): it would select keys and relay-visible behaviour.

### 12.6 Declared residue (new LIMITE section L6; Romanian text in Appendix B)

| ID | Residue | Why it remains | Mitigation, and the state after Phase 8 |
|---|---|---|---|
| E1 | Activation slot of a pack's first eligible use (L1) | blurs, does not remove, the purchase → first-use timing for resumes and genesis | slots, HIGH extra days; renewals bought ahead: no signal; invitees: onboarding funded by the trial, and the drop write at a time pre-drawn at activation, independent of purchases (§19.12). A HIGH-mode trial's extra days stop at the last day of base + 1 (Q30): a trial finalized late in base + 1 has less blur, none when finalized in (Friday 20:00, Saturday 20:00] UTC; an issuer that fails `RedeemInvite` until a late foreground can make the cap apply (E8 × E1); the cap at most doubles the chance of the last day (§19.23 point 5) |
| E2 | Coverage-end week (L2) | a partition by design | one product |
| E3 | User-requested immediate calls and the trial start (L3) | the user asked for speed; onboarding needs an issuer call | buttons optional, hidden in HIGH |
| E4 | Purchase type (L4) | the issuer must know how it was paid | — |
| E5 | Quiet-run gaps (L5), **cumulative per invoice** | an issuer call must happen at some time; the calls of one invoice are linked by `invoice_id` | q = 1/8, independent draws; ≤ 3 bits per call; usually 2 calls per purchase, never more than 6 (1 `RequestInvoice` + 5 `BlindSign`) whatever the issuer answers (§19.11), so ≤ 18 bits in the worst case against a lying issuer; measured bits per invoice recorded in the T2 report and bounded by S4 |
| E6 | Genesis onboarding is linkable at alpha volume | small anonymity sets (RP §5: 2 onboardings a day with daily slots → expected set 3, alone 13.5 %) | genesis is a bootstrap mode for few users |
| E7 | Paying from a KYC exchange links a person to an invoice | outside GHOST | FR-6.8 disclosure; E1–E5 still hold on their own |
| E8 | An active issuer can deny or delay service to isolate a client (n−1) | it controls the service | quiet runs; a fixed cap of 5 `BlindSign` attempts per invoice at pre-drawn times bounds the samples it can force (§19.11) |
| E9 | Relays see a drop edge (writer cluster → lister cluster), like every DM | relay-mediated delivery | shared read keys (D11) reduce reader separation from Phase 9 |
| E10 | EAE and Janus if referral is paid in XMR | Monero | discount by default, reachable no later than a payout (both need credits covering 10 × credit value, §19.8); disclosure |
| E11 | Tokens and unused credits are not recoverable from the seed; drops beyond index 7 are lost on restore | bearer value is device-local | disclosed in the UI (Phase 13); seed-derived recovery as a P1 item (Q13) |
| E12 | A reorg after issuance; honest users' tokens of revoked epochs after an issuer compromise, including every unspent invite and credit of the INVITE and CREDIT epochs whose keys were in memory (§19.1) | tokens are blind and cannot be clawed back or reissued | counters; exchange RPC left to Phase 15 (§18 F3) |
| E13 | A relay seized with its key links nullifiers to namespaces for ≤ 2 weeks (binding tags) | idempotent redemption needs the binding | nullifiers remain unlinkable to payments (blindness) |
| E14 | A client whose device clock is more than 4 h off true time gets `WRONG_PERIOD` on an issuer call carrying `base_week`, which reveals its skew to the issuer; relays cannot cause this, because relay time never reaches issuer-facing decisions (§19.4) | issuer-facing time must come from a source AD-1 does not control | trusted-clock check; the issuer's ±4 h tolerance; the optional consensus-lifetime check suppresses the call entirely (`CLOCK_UNTRUSTED`); nothing recorded on `WRONG_PERIOD` |
| E15 | Payment co-presence (L6): the operator's wallet sees a payment in its pool within seconds to minutes; if the payer's GHOST runs a relay session at that moment, the payment time selects the ≈ 1/32 of clusters in a session (≈ 5 bits), and combined with L5 can link the invoice, and a KYC payment, to a cluster | the user pays from an external wallet, often on the same phone | `PAYMENT_READY` never an immediate notification; the payment screen closes relay sessions and holds them off U[20, 60] min; advice to pay from another device or later without GHOST open; modelled in T2 (S3d) (§19.11) |
| E16 | Exhaustion-triggered purchases (L7): relays see a cluster run out of tokens; a user who then buys produces a `RequestInvoice` some hours later | the trigger is relay-observable | the flag is surfaced at a random time within 12 h and the `RequestInvoice` waits U[0, 24 h] more; tokens of the new pack are eligible only from an activation slot; modelled in T2 (§19.13) |
| E17 | The refresh of a received credit is linkable to the invitee who sent it (who knows the credit, and under AD-1 may be the operator posing as an invitee): the issuer learns one quiet-run time of the inviter; whether the drop read, a relay-visible moment, came before the first of the invite's two pre-drawn refresh times (one bit, only for a read in the last days of the listening, §19.26) *(§19.29: the bit is removed; the refresh has one time, after every read, and a credit whose refresh window closes before the listening ends is dropped whatever the read)* | the invitee finalized that credit; the refresh must follow the read | the refresh runs alone, in its own quiet run and `IssuerFlow`, at a time drawn when the invite was created, never at a time the read sets; the fresh credit is blind, so later spends and payout addresses stay unlinked (§19.8, §19.26) |
| E18 | A slot whose onion changes for an already-published week (emergency relay move) partitions clients by ES version: old-ES clients try the old onion, new ones the new relay | a lost relay cannot be replaced in old releases | only after the relay has been unreachable ≥ 48 h; slot sets, prices and keys never change (§19.2) |
| E19 | On a seized device (AD-8, AD-12), a fresh token's `eligible_minute` encodes its batch's finalization day for up to 5 weeks | eligibility must be enforced locally | declared in LIMITE L1.1; terminal purchase rows keep no hour (§19.15) |
| E30 | Redeem-hold length (Q29): a background session that started with a pending write need stays open after its lanes until the redeem lane's first step (READY + U[0, 30 s] plus the step) or the job's deadline, so the Tor guard and the local network see a longer connection, and every relay whose circuit the lanes left open sees it close later; this shows that a write need was pending at the start (outbox work with no capability, an expiring, exhausted or rejected capability), also when no eligible token exists and the step redeems nothing | recovering a client whose capabilities lapsed without opening the app needs a session that outlives its sync work | the input is the pending write-need count at the session's start only, never issuer state, token counts or a later need (R1); never past the job's deadline; ends at once on a foreground, the payment screen (E15 unchanged), onStopJob or a wipe; not held when the transport failed (§19.23 point 5); measured in the T2 world and reported (§19.26) |

---

## 13. Test and exit-gate plan (I12)

### 13.1 Negative tests (the plan's list first: reuse, expired, forged, wrong period)

| Case | Relay (`relay/crates/node/tests/redeem.rs`, `redeem.txt`) | Issuer (`issuer/crates/service/tests/negative.rs`, `issuer_semantics.txt`) | Client (Rust `client-core` / Kotlin) |
|---|---|---|---|
| **Reuse** | the same token for the same namespace → identical capability; **after a relay restart** → identical capability (MS-8); for another namespace → `REPLAYED`, `rejected_nullifier`, also after a restart; concurrent duplicates → exactly one nullifier row | invite redeemed with a different request → `REPLAYED`; a credit used twice (discount then payout, both orders) → `CREDITS_SPENT` with the right mask; the same `claim_id` with another body → `CLAIM_CONFLICT`; `BlindSign` with another digest after ISSUED → `OTHER_REQUEST_ISSUED`, identical → identical bytes; **after a snapshot restore + journal replay** the same outcomes | a reserved token is never offered to another relay or namespace (trigger test); after `REPLAYED` the token is deleted |
| **Expired** | week p at `start(p+1) + 1 h` → `WRONG_PERIOD`, nothing recorded; p+2 now → `WRONG_PERIOD`; a revoked epoch → `rejected_token` | invite of epoch e−2 → `PERMISSION_DENIED`; credit of epoch c−2 → refused; `BlindSign` after grace → `EXPIRED`, nothing signed; after purge → `PERMISSION_DENIED` | tokens past their window are GC'd; no redeem within ±1 h of a boundary |
| **Forged** | every byte of a valid token flipped (354 cases); random authenticator; authenticator ≥ n, 0, 1, n−1; `token_type` 0x0001 and 0x0003; truncated or extended; a correct signature under a **non-ES** key with a self-consistent key id; a correct signature under the INVITE key of the same week | a forged invite or credit (same cases); a forged claim key; blinded values 0, n, > n | finalize rejects a tampered blind signature (`malformed_response`); `s'^e ≢ B` detected in Rust before return |
| **Wrong period** | week p+1 before `start(p+1) − 24 h`; week p−1 after `start(p) + 1 h`; exact edges accepted | `base_week` mismatch → `WRONG_PERIOD`, nothing recorded; an idempotent retry of a recorded request still succeeds after the week changed | the client never sends within ±1 h of a boundary; a `WRONG_PERIOD` re-prepare leaves no reserved credit behind |
| Wrong kind | INVITE or CREDIT token at a relay → `rejected_token` | ACCESS token as invite or credit → `PERMISSION_DENIED` | layout positions carry kinds; a mismatch is impossible by construction (test) |
| Wrong slot | a slot-2 token at the slot-3 relay → `rejected_token`; a token for a week in which this relay does not hold the slot → `rejected_token` | — | `NamespaceClient::redeem` refuses before I/O (0 requests, 0 connections) |
| Wrong key / ES | ES tampered (1 byte), rolled back (seq), a changed key for an accepted epoch, a non-permutation key (65537 \| p−1), a duplicate (kind, epoch), one SPKI listed under two (kind, epoch) entries, a gap in the horizon → the relay refuses to start; a changed slot-number set or price of a covered week → client `SCHEDULE_CONFLICT`, issuer refuses to start, `entitlement-schedule.sh` fails (§19.2) | the issuer refuses to start (ES, key files, network, watch-only, journal gap) | `SCHEDULE_CONFLICT`, `UPDATE_REQUIRED`; `ent_key` triggers |
| Issuer tagging | — | — | amount ≠ ES price; subaddress of another network or type or with a bad checksum; signature count ≠ N; an invoice id or amount changed on retry → `malformed_response`, one identical retry, then `failed` + `ISSUER_MISMATCH`, never re-blinding |
| Money | — | `BlindSign` before CONFIRMED signs nothing; UNDERPAID never signs; a credit set that does not cover the price, or is not the smallest covering set, refused; claim below minimum or above maximum refused; the open-invoice cap; an empty pool, a stale or unsynced scanner tick, or a missing layout key → `UNAVAILABLE`; a refreshed credit reused → `REPLAYED` | the drop only ever carries the first XMR-pack credit (or a dummy); a credits-paid pack yields no credit; a received credit is never spent before its refresh |
| Clock regression (§19.10) | the clock stepped back across a swept boundary → the closed period stays refused; no sweep below the high-water minute | the same for invite and credit epochs (`closed_through_*`) | — |

### 13.2 Crash safety (fault injection on both sides; G-10)

**Client (JVM, `:entitlement` tests).** The Phase 7 `FaultySqlExecutor` (via `storage/src/testShared`) enumerates every statement, pre-commit and post-commit point of every flow: E-A pack XMR happy path; E-B underpay, top-up, confirm; E-C expiry and the `lost` variant; E-D credits pack; E-E trial with activation and wipe; E-F redeem needs across a week boundary with EXHAUSTED and REJECTED; E-G drop send and receive; E-H claim; E-I `WRONG_PERIOD` re-prepare. `FaultyIssuerPort` and `FaultyRedeemPort` add three call events each (fail before, succeed but lose the response, succeed). Single crashes everywhere; double crashes (a crash during recovery) for E-A, E-D and E-F; both journal modes. After every crash: restart, run to quiescence with an honest issuer and relays, then assert:

- **MS-1:** every request the model issuer ever received for one invoice has the same digest;
- **MS-6:** a paid invoice ends with its N tokens when retries are allowed;
- **R8 / RED-2:** no token is presented at two (relay, namespace) pairs;
- **R10:** no secret column is non-null in a terminal state;
- capability installed ⇔ token deleted, in one transaction;
- tokens: fresh + reserved + spent = finalized;
- in the new `:entitlement` liveness world, the Phase 7 sync invariants and liveness hold with the real redeem lane (the `:sync` harness keeps its stand-in `Runner.renewNeeded` unchanged, §19.17);
- T3 canaries never appear in anything emitted.

Seeded worlds: 1 000 in the `android` job, 20 000 in `entitlement-exit-gate`. **JVM harness ES (§19.17):** S = 3, `access_per_slot = 4`, `trial_per_slot = 2` (N = 63 per XMR pack), as in T2; `ModelIssuer` caches the blind signature per (key, B), which is legitimate because signing is deterministic; the job budget is measured in S9 from a per-world cost and every new job has `timeout-minutes`.

**Issuer (Rust, `issuer/crates/service/tests/crash.rs`).** `FaultyStore` (an event before every write transaction, pre-commit, post-commit), `FaultyRail` (before the call, after its effect but before the response, after the response) and `FaultyJournal` (before and after fsync, a torn last record). A crash drops every in-memory object, **reopens the same redb file and journal**, runs startup reconciliation (`highest_minor`, journal replay) and lets the client retry. Scenarios: I-A request → pay → confirm → sign → re-serve; I-B underpay and top-up; I-C expiry with a stale, then a synced view; I-D reorg before and after issuance; I-E invite redeem and revoke; I-F credits pack; I-G claim, payout export and acknowledgement; I-H restore from a snapshot plus journal replay, **with invoices (XMR and credits-paid) created after the snapshot** and a pool that must be reset (§19.5); **I-I** a CONFIRMED invoice signed in week base + 2 and later (§19.1); **I-J** issued late in week base + 1, re-served 6 days later (§19.1); **I-K** races then restart and races then restore: two concurrent `BlindSign`, `ClaimPayout`, credits `RequestInvoice` and `RedeemInvite` requests where the loser must never be replayed (§19.5); **I-L** a clock step back across a swept epoch boundary (§19.10); **I-M** a lost `create_address` response without a crash (in-process reconciliation, §19.6). Every event of every scenario is crashed once; double crashes for I-A, I-D, I-H and I-K. Invariants after every reboot and at quiescence: MS-1 (at most one digest per invoice over all responses ever produced); MS-2; MS-3 (no committed nullifier lost); invoice state equals a pure recomputation from the chain port; `claim_index`/`minor_index` consistent; no pool entry assigned; reconciliation invariants (§6.9); RET (no row outlives its rule). Plus 3 process-level kills against real files to validate redb and fsync durability.

**Relay (`redeem.rs`).** A crash between the nullifier commit and the response → the identical retry after restart gets the identical capability (MS-8). A crash before the commit → the retry mints normally.

**Conformance models.** `protocol/test-vectors/issuer_semantics.txt` (request idempotency, states, `BlindSign` results, invite and claim results) is replayed by the real issuer (`tests/semantics_vectors.rs`) and by the Kotlin `ModelIssuer`; `redeem.txt` by the real relay and `ModelRedeemRelay`.

### 13.3 Live Monero CI job (`monero-regtest`)

- Pinned v0.18.5.1 tarball (`sha256sum -c` against `monero-release.pin`, cached by hash); `monerod --regtest --offline --fixed-difficulty 1`; three wallet-rpc processes with digest auth on (payer, issuer view-only, treasury as the cold signer); `generateblocks 80` first (coinbase unlock 60).
- **Triggers (ADR-26):** automatic on PRs touching `ghost/issuer/**` or `ghost/infra/issuer/**`; nightly; `workflow_dispatch`. Run time: a few minutes.
- **Scenario** (`issuer/crates/service/tests/monero_regtest.rs`, env-gated by `GHOST_MONERO_REGTEST=1`, production rail): RM §9.3 steps 1–13 — view-only proof (`query_key spend_key`, `sign_transfer` → −29); happy path with SEEN at 9 and CONFIRMED at exactly 10 confirmations and an identical re-serve; underpay and top-up; overpay; lock time (the pinned wallets refuse to make one, §19.22 point 1); expiry with a late payment counted as unattributed; a reorg below 10 through `/pop_blocks` and `flush_txpool`; a 250-invoice lookahead restore with its negative control; the option-B payout through the cold wallet with `describe_transfer` assertions; the cap guard; 1 000-address differential validation against `validate_address`; digest-auth failure mapped to `Auth` — plus:
  14. end to end: invoice → pay → confirm → `BlindSign` (production issuer) → finalize with the production client crypto → redeem at an in-process relay → a capability for a namespace;
  15. a credits-paid pack (credits from earlier packs covering the price, including a set that needs 11 after a price increase) → amount 0 → signed; a received credit refreshed by `RefreshCredit` first;
  16. `ClaimPayout` → weekly batch export → `payout-check` with the workstation's view dump → cold sign → the payee receives it; **16b** a 5-entry batch built entry by entry (§19.7): no two entries share an input, each entry acknowledged with its own txid; two consecutive batches over the same revenue refused by the cumulative cap;
  17. an issuer restart with a pool refill interrupted after `create_address` → startup reconciliation → no minor handed out twice; **17b** an invoice requested while the wallet lags the daemon → `UNAVAILABLE` (§19.6);
  18. reconciliation invariants hold at the end (incoming to minors ≥ 1 = credited + overpaid + unattributed; payout change to minor 0 not counted), and the field set the issuer reads from the real wallet equals the `ChainPort` field set used by T2 (RP §6.8), plus `timestamp`, which only the T2 view uses.
- Money mutants MM4–MM9 and MM19 are caught here (§13.5).

### 13.4 T2: the unlinkability exit gate

**Placement.** `ghost/issuer/crates/service/tests/t2_unlinkability.rs` (the location INVARIANTS.md:8 names) drives the real issuer handlers (`*_at(now)`, the real redb store and journal, a `ChainPort` emitting exact `get_transfers` fields), **3 real relays** (`Relay::*_at` including `redeem_at`, capture on), and N reference clients on the production Rust crypto (`ghost-blind-rsa`, `ghost-entitlement`) with a Rust **reference policy** that mirrors the Kotlin engine. The Kotlin engine and the reference replay the same `protocol/test-vectors/entitlement_policy.txt` (redemption planning, slot eligibility, quiet-run work selection, retries); the real Kotlin engine is also tested directly by NI-K. A loopback transport labels every connection with `H(isolation token id ‖ service)`, the circuit label a server would observe. Analyzer: `ghost-t2-join`.

**World (gate).**

| Parameter | Value |
|---|---|
| Duration | 84 virtual days |
| Paid packs | 2 000: 600 first packs of invitees, 1 300 renewals, 100 resumes after a lapse |
| Warm-up (§19.16) | 40 virtual weeks before the scored window with the 150 future credit spenders, run through the same real issuer, relays and clients and fully exported; the credits it mints are protocol-issued |
| Other activity | 700 trials; 20 genesis identities; 100 credits-paid packs and 30 payout claims, funded only by credits minted in the warm-up or the window (harness assertion; achieved counts reported); 40 Sybil invitees controlled by the attacker, whose credits the inviters must refresh; payments made from the payment screen (70 %) or during a relay session (30 %); 5 % of extra packs triggered by `ENTITLEMENT_NEEDED` |
| Relays | 3, all adversarial (the AD-1 worst case, with the relay-side clustering oracle of RP §1.2) |
| Test ES | S = 3, `access_per_slot = 4`, `trial_per_slot = 2` (counts scaled for run time; NI-2 proves count independence of the policy; production constants are exercised by the unit and regtest suites) |
| Namespaces per client | 1 + Poisson(4), capped at 16 |
| Cadence | 15-minute periodic job with a Doze-like mixture of deferrals; quiet runs with q = 1/8; foreground sessions sampled per user |
| Faults | 5 % of `BlindSign` calls crash the client after sending; 5 % of redeems time out after processing; 2 % of issuer calls answer `UNAVAILABLE` once; one restart per relay; one issuer restore from snapshot + journal |
| Clocks | 10 % of devices with an offset U[−3 d, +3 d] (relay-facing decisions neutralise it, §12.5; those beyond 4 h make no successful issuer call carrying `base_week` until corrected); relays answer chosen clients with shifted `relay_minute`/`relay_period_id` (NI-3) |
| Worlds | `W_train` (the attacker learns the policy; the code is open source) and `W_test` |
| PR variant | N = 300 packs, 21 days; nightly: 10 seeds |

**Exported views.**

| File | Contents |
|---|---|
| `issuer_view.ndjson` | every request and response in full (hex) plus decoded fields: exact t, circuit label, op ∈ {`request_invoice`, `blind_sign`, `invoice_status`, `redeem_invite`, `claim_payout`}; includes claim hashes and keys, invoice ids, subaddresses, amounts, blinded blocks, blind signatures, invite and credit tokens, nullifiers, payout addresses |
| `wallet_view.ndjson` | every `ChainPort` call and answer: txid, height, amount, minor, confirmations and the pool-first-seen `timestamp` (L6) |
| `issuer_db/*.json`, `issuer_journal/*` | every redb table and every journal segment at every day boundary and at the end, deleted rows included |
| `payout_batches/*.bin` | the exported batches |
| `relay_<k>_view.ndjson` | every relay request and response in full plus exact t, circuit label and capture event (nullifier, `period_id`, `namespace_id`, `capability_scope`, `request_id`, result) |
| `relay_<k>_db/*.json` | blob store, `nullifiers.redb` (tags included), quota ledger |
| `public.json` | Z: the ES, grid, slot boundaries, constants, enum values, labels |
| `ground_truth.json` | client ↔ invoice ↔ seeds and nonces ↔ nullifiers ↔ namespaces ↔ drops; used only for scoring and completeness |

**Completeness:** request counters wrap every handler entry point; every received request appears in a view; every ground-truth nullifier appears in some relay view.

**Deterministic join search (any hit fails T2).** W = Z values and all their substrings.

| Check | What it searches |
|---|---|
| J1 | exact equality ≥ 4 bytes between V_I and V_R, outside W |
| J2 | common windows ≥ 8 bytes (Bloom filter + exact verification; random-coincidence expectation ≈ 2·10⁻⁴, RP §6.4) |
| J3 | transforms of every issuer field of 8–64 bytes and of SHA-256 of 256-byte values, searched in V_R and vice versa: identity; SHA-256/384/512, SHA3-256, BLAKE2b-256; HMAC-SHA256 and HKDF (L ∈ {16, 32}) keyed or salted with every GHOST label (`DerivationLabels.ALL` and every Phase 8 label, including `ghost/v1/blind-batch`, `ghost/v1/cap-serial`, `ghost/v1/redeem-binding`); `SHA-256(label ‖ v)`; counter suffixes and prefixes (u8, u32 BE/LE, u64 BE); 8- and 16-byte truncations; byte reversal; hex, base32, z-base-32 and base64 text |
| J4 | XOR of equal-length fields within records, and with constants |
| J5 | RSA: (a) `em = s^e mod n` for every relay-seen token, added to V_R (catches unblinded submission); (b) Jacobi symbols of every B and every em as S2 features; (c) every blind signature checked against the ES key of its position |
| J6 | circuits: (a) every issuer circuit label belongs to exactly one flow instance; (b) no relay circuit carries two namespaces (T21 extended to redeem); (c) issuer labels ∩ relay labels = ∅ |
| J7 | keys: key ids at relays ⊆ ES; exactly one key id per (kind, epoch) across all clients; the issuer signed each position with the ES key only |
| J8 | periods: every accepted redemption lies in its window; no action of a relay-corrected client lies within ±1 h of a true boundary; uncorrected actions of skewed clients ≤ 1 per process start (E14) |
| **J9** | contact schedule, per flow (G-4): exactly one `RequestInvoice` byte string (retries identical); every automatic issuer call lies in a quiet run (a run with zero relay calls); at most one issuer call per quiet run; `BlindSign` attempts inside their due windows; user-initiated calls = the world's scripted user actions; `ClaimPayout` at most weekly and never in a run with another issuer call; `RedeemInvite` only before the identity's first relay call |
| **J10** | well-formedness: every ES key's proof verifies; every relay-seen authenticator is the unique root (`s < n`, `s^e = em`) |
| T2b | relay ↔ relay: J1/J2 between different relays, excluding only `namespace_id` and `blob_hash` (ADR-11 replication); a shared nullifier, token or capability fails |
| T2c | a client's own flows at the issuer: two invoices, trials or claims of one client share no value outside Z (claim hashes, credits, seeds' outputs, addresses, circuits) |

**Non-interference (exact equality, every seed).**

- **NI-1 (full system).** Worlds A and B share client and user randomness and differ in issuer randomness (invoice ids, pool minors, response latencies up to 30 s), chain timing (payment and confirmation heights shifted within the same activation-slot cell) and issuer availability (one extra `UNAVAILABLE` per purchase, an issuer restore in one world only), all within the same L-cell. **Every relay view and relay DB snapshot must be byte-identical.** Catches M1, M2, M2b, M3, M7, M13 and any future derivation from issuer data.
- **NI-2 (full system).** The worlds share issuer seeds and scheduling randomness and differ in token-level client randomness (seeds) and in each client's namespace set and relay activity. **The issuer views must be identical modulo the blinded and signature bytes, compared by position.** Catches M8, M9 and any issuer call timed by relay activity.
- **NI-1d (drop timing, §19.12).** Worlds that differ in an invitee's first-purchase time across activation-slot cells produce identical drop-write events (time, relay, length). Catches M18.
- **NI-3 (relay → issuer, §19.4).** Worlds that differ only in the `relay_minute` and `relay_period_id` the relays send to chosen clients produce identical issuer views. Catches M17.
- **NI-K (real Kotlin engine, JVM).** The same two comparisons on `EntitlementEngine` plus the `QuietRunScheduler` and the Phase 7 sync harness (§19.14): NI-1 — the sequence of `RedeemPort` and `RelayPort` calls (time, relay, namespace, bytes) is identical when the model issuer's responses vary within the L-cell; NI-2 — the sequence of `IssuerPort` calls (time, flow, sizes) is identical when namespaces and relay activity vary. The token-crypto port is `TestTokenCrypto`. This makes the *production* scheduler, not only the reference, satisfy R1 and R6 exactly.

**Statistical tests** (on `W_test`, the attacker trained on `W_train`; α = 0.001 per test; seeds pinned):

- **S1, learned matching vs declared attacker.** Pairs (invoice, relay cluster). Full features: Δ(first use, `BlindSign`), Δ(first use, `RequestInvoice`), Δ(first use, confirmation height), quiet-gap coincidence, purchase type, counts, redemptions per week, first and last week, namespace count, clock offset, S3 co-occurrence, Jacobi fraction. The declared attacker gets L1–L7 only (§19.11, §19.13). Naive Bayes (log2 bins) with argmax and Hungarian assignment; exact one-sided McNemar; **fail if p < 0.001**; the lift is reported. Power (RP §6.6): with about 600 onboardings an absolute lift of 0.10 is detected with power ≈ 0.97; the 10-seed nightly sweep detects 0.05 with power > 0.99.
- **S2, max-T mutual information** (Westfall–Young, B = 999, permutations within L-strata). **Fail if the observed maximum exceeds all 999 permuted maxima.**
- **S3, presence.** (a) co-presence: the rate at which the true cluster has a relay session covering an issuer event, against other clusters of the same stratum, must not be higher (one-sided, p < 0.001; a correct implementation gives ≈ 0, M9 gives ≈ 1); (b) session-start and session-end coincidence within [−120 s, +30 s], same test; (c) quiet-gap coincidence is **reported only**: it is the declared L5, and its measured bits per invoice go into the T2 report and LIMITE L6; (d) payment co-presence for payments made from the payment screen: same test on the wallet's first-seen times (M19 gives ≈ 1; §19.11).
- **S4, absolute bound (§19.16).** The declared-leak attacker of S1 (L1–L7 only) must reach a top-1 invoice → cluster accuracy ≤ 0.25 (Q21) over XMR packs of non-genesis clients in `W_test`, with the model issuer answering honestly; and ≤ 0.25 in a world where it lies `AWAITING_*` to force the maximum number of attempts (M16 must exceed it or break the J9 cap). The value is always reported.

**Determinism and seed policy:** every seed is pinned; a failure on a correct implementation is investigated and a seed is never changed silently (Phase 7 policy). **Run time (recomputed, §19.17):** the gate runs at least four full worlds (`W_train`, `W_test` = NI world A, the NI-1 and NI-2 variants, plus the NI-3 variant at PR scale), each about 150 k window signatures plus about 95 k warm-up signatures, so about 1 M signatures at 2–3 ms on 4 cores ≈ 10–12 min in the **release** profile, join search 2–4 min per world pair, mutants at PR scale ≈ 5 min: an estimate of 25–35 min, measured in S10, `timeout-minutes: 60`; the PR variant (N = 300, four worlds, release profile) ≈ 5 min. Measured in S10 (§19.24 point 9, Q35): on 24 local cores the PR variant takes 675–718 s and the mutants 788–867 s, and seed pair 0 of the gate scale took 4 233 s; the timeouts are 150 min for the `rust` job, 240 min for the gate job and 120 min for the mutants job.

### 13.5 Mutants (each must be detected; `MutantDetectionTest` pattern; implemented only in `tests/`)

**Privacy (T2 world or the named test)**

| # | Mutant | Side | Caught by |
|---|---|---|---|
| M1 | `NonceFromInvoice`: nonce = HKDF(invoice id, "nonce" ‖ i) | client | J3, NI-1 |
| M2 | `PerInvoiceKey`: the issuer signs with a fresh key and the client accepts keys from a response | issuer + client | J7, NI-1, ES negative tests |
| M2b | `ServerKeyId`: the client copies a key id from the issuer | client | J1, NI-1 |
| M3 | `ImmediateEligible`: pack tokens usable at finalization | client | S1, S2, NI-1, NI-K |
| M4 | `SharedIssuerScope`: one `Issuer` scope for all flows (today's code), implemented against `client-core`'s isolation map (§19.17) | client | the `client-core` `IssuerFlow` unit test; J6a and T2c for the reference client |
| M5a | `NoBlinding`: r = 1 | client | J5a + J1 |
| M5b | `SquareBlinding`: r = x² | client | S2 (Jacobi) |
| M6 | `CrossRelayRetry` / an unbound challenge | client | T2b, relay negative test, `NamespaceClient` pre-I/O test |
| M7 | `IssuerBaseWeek`: the client takes its base week from an issuer hint | client | NI-1 |
| M8 | `VariableCounts`: token counts depend on namespaces | client | NI-2, NI-K |
| M9 | `SessionIssuerCalls`: `BlindSign` inside relay sessions | client | S3a, J9, NI-2 |
| M10 | `ReferralIdAtIssuer`: a drop or invite identifier sent with `RequestInvoice` or derived into a nonce | client | T2c, J3 |
| M11 | `DeviceClockPeriod`: the week from the raw device clock, no relay correction | client | J8 |
| M12 | `ClaimInPurchaseRun`: a claim on the purchase's flow or in the same quiet run | client | J6a, J9, T2c |
| M13 | `PaidOnboarding`: invitee identity namespaces funded by its first pack immediately | client | S1, NI-1 |
| M14 | `NonPermutationKey`: the proof check skipped and a key with 65537 \| p−1 used | issuer + client | J10, S2, ES negative tests |
| M15 | `SeedReuseAcrossFlows`: one blinding seed used for two purchases | client | T2c (identical blinded blocks at the issuer) |
| M16 | `IssuerForcesRetries`: no attempt cap; the model issuer lies `AWAITING_*` | client | J9 (≤ 5 `BlindSign` per invoice), S4 |
| M17 | `RelayClockDrivesBaseWeek`: relay-corrected time used for `base_week` and issuer guards | client | NI-3 |
| M18 | `DropAtEligibleMinute`: the drop blob written at the first pack's eligible minute | client | NI-1d |
| M19 | `PayInsideSession`: the payment screen keeps the relay session | client | S3d |
| M20 | `QuietWhenWorkDue`: a quiet run forced when a `BlindSign` is overdue | client | NI-K, NI-2 |
| M21 | `SpendReceivedCredit`: a received credit presented without `RefreshCredit` | client | T2c (Sybil-invitee world: the attacker recognises its credit) |

**Issuer and relay money/operations (Rust)**

| # | Mutant | Caught by |
|---|---|---|
| MM1 | `NoDigestGuard`: the issuer signs a different blinded set after ISSUED | issuer negative test, crash harness (MS-1) |
| MM2 | `NoCasOnIssue`: commit without re-reading the state; two different concurrent requests both signed | concurrency test, MS-1 |
| MM3 | `NoJournal`: restore from a snapshot allows a second digest or a second credit spend | crash scenario I-H |
| MM4 | `CreditPoolEntries`: pool counted as credited | regtest step 3, scanner unit test |
| MM5 | `IgnoreUnlockTime` | regtest step 6 |
| MM6 | `ConfirmationsOffByOne` | regtest step 3 |
| MM7 | `FloatAmounts` | regtest step 4 |
| MM8 | `Sha3Checksum`: SHA3-256 instead of Keccak-256 in address checksums | regtest step 12, address vectors |
| MM9 | `RestoreWithoutReplay` | regtest step 9 |
| MM10 | `ExpireFromStaleView` | crash scenario I-C |
| MM11 | `CreditOnCreditsPack`: a credit issued on a credits-paid pack | layout unit test, reconciliation invariant |
| MM12 | `CountOnReserve`: counters incremented on a re-serve | reconciliation invariant in the crash harness |
| MM13 | `NullifierMemoryOnly`: relay nullifiers not persisted | relay restart test |
| MM14 | `RandomMint`: a random capability serial | relay restart test (identical retry must get identical bytes) |
| MM15 | `PoolNotResetOnRestore`: the snapshot's pool reused after a restore | crash scenario I-H (a minor handed out twice) |
| MM16 | `JournalBeforeDecision`: entries appended before the in-transaction re-check | crash scenario I-K (a loser replayed) |
| MM17 | `KeyDestroyedAtFixedTime`: keys destroyed at `end(epoch) + 8 d` while an open invoice references them | crash scenarios I-I, I-J (MS-6) |
| MM18 | `ClosedPeriodReopened`: no persisted high-water | clock-regression tests (relay, issuer), I-L |
| MM19 | `PayoutInputReuse`: all entries built from one wallet state | regtest step 16b |
| MM20 | `CreditValueAtCurrentPrice`: credits valued at the redemption epoch's price | reconciliation test across a price change |

**Client (JVM)**

| # | Mutant | Caught by |
|---|---|---|
| EM1 | `NewSeedOnRetry` (re-blinding) | frozen trigger, crash harness (two digests), `OTHER_REQUEST_ISSUED` test |
| EM2 | `ReleaseReservation`: a reserved access token returned to fresh and used elsewhere | state/binding triggers, harness RED-2 |
| EM3 | `PutOutsideTx`: token deletion and `Capabilities.put` in separate transactions | crash harness |
| EM4 | `RedeemOtherRelayOnTimeout` | harness RED-2, T2b |
| EM5 | `SendBeforeWriteAhead`: the seed or claim key persisted after the first send | crash harness (retry differs) |
| EM6 | `WipeBeforeFinalize`: secrets wiped before the tokens are stored | delete/CHECK triggers, crash harness (MS-6) |
| EM7 | `LayoutChangedAfterSend` | frozen trigger, layout-digest check in Rust |
| EM8 | `TrustIssuerAmount` | hostile-issuer mode test |
| EM9 | `ClaimAddressChangedOnRetry` | claim guard trigger, claim harness |

That is 52 mutants (23 + 20 + 9). *§19.26 point 7 adds the privacy mutant M22: 53 (24 + 20 + 9).*

### 13.6 CI jobs

| Job | Adds | Trigger |
|---|---|---|
| `static-gates` | the new and extended gates of §14.1 with their self-tests | every PR |
| `rust` | new crates' tests; vectors; relay redeem suite and `redeem.txt`; issuer negative, crash and semantics suites; T1 two-node with redeem; **T2 PR variant** (N = 300); MM1–MM3, MM10–MM18, MM20. The crypto crates are optimised in the dev profile (`[profile.dev.package.*] opt-level = 3` for `crypto-bigint`, `num-bigint-dig`, `blind-rsa-signatures`, `ghost-blind-rsa`, `ghost-entitlement`), and the T2 PR variant and the crash suites run with `--release` (§19.17) | every PR |
| `android` | `:entitlement`, `:identity` (Invite v2, drop sealing), `:storage` v3, `:sync` (`SessionParticipantTest`) JVM tests, NI-K, crash enumeration with 1 000 seeds, EM1–EM9 | every PR |
| `android-native`, `reproducible` | unchanged (the library changes; two identical builds) | every PR |
| **`monero-regtest`** (new workflow file `monero-regtest.yml`) | §13.3; MM4–MM9, MM19 | `on.pull_request.paths` (`ghost/issuer/**`, `ghost/infra/issuer/**`), `on.schedule` (nightly), `workflow_dispatch`; required for merge on those paths; `timeout-minutes: 45` |
| **`t2-exit-gate`** (new workflow file `t2-exit-gate.yml`) | N = 2 000 gate world with warm-up, `--release`, plus M1–M21; closing the phase requires a recorded green run | `on.push` to main, `on.pull_request` on the paths of §19.24 point 9, `on.schedule` (nightly), `workflow_dispatch`; `timeout-minutes: 60` (as built: 240 for the gate job, 120 for its mutants job; §19.24 point 9, Q35) |
| **`entitlement-exit-gate`** (new workflow file `entitlement-exit-gate.yml`, like `sync-exit-gate`) | 20 000 seeds of the client crash harness with the real redeem lane (split into 2 × 10 000 if the measured budget exceeds 40 min) | `on.push` to main, `on.schedule` (nightly), `workflow_dispatch`; `timeout-minutes` from the S9 measurement |
| `live-tor` (manual) | two `IssuerFlow` scopes use distinct real circuits; an issuer call to a staging onion; a redeem over Tor | manual |
| **`signer-timing`** (workflow file `signer-timing.yml`, §19.27 point 2) | the Welch t-test of §2.8 point 6 (`tests/signer_timing.rs`, `--release`); a failure opens an issue | `on.schedule` (nightly), `workflow_dispatch`; not required; `timeout-minutes: 60` |

### 13.7 Evidence map

| Evidence | Where | Automatic |
|---|---|---|
| Crypto correctness, RFC and GHOST vectors, differential test | `cargo test` | yes |
| Relay and issuer negatives, crash safety, journal restore | `cargo test` | yes |
| Monero behaviour (confirmations, reorg, lock time, restore, payouts, address validation) | `monero-regtest` | yes (path-triggered, nightly) |
| T2 J/NI/S on the full system | `rust` (PR variant), `t2-exit-gate` | yes |
| Kotlin engine: state machines, triggers, crash enumeration, NI-K, policy vectors, T3, T16 | Gradle JVM | yes |
| Real Tor isolation per issuer flow | `live-tor` | manual |
| SQLCipher v3 on a device, quiet runs under Doze, JNI on both ABIs, QR scan | device checklist | manual until Phase 13 |
| Kotlin scheduler equals the Rust reference policy beyond the vectors | shared vectors + NI-K | yes for R1/R6 properties; full equivalence **assumed** |
| Constant-time signing | nightly dudect evidence (`signer-timing.yml`, §19.27 point 2) + §2.8 mitigations | not part of the gate |

### 13.8 Exit-gate argument

1. **"Teste negative: reuse, expirat, forjat, perioadă greșită."** The first four rows of §13.1, with every verifier as a column, complemented by wrong kind, slot and key, ES tampering, clock regression, and the crash suites showing the same results after restarts, races and restores (persisted nullifiers, closed-period high-water, decided-outcome journal). MS-1 to MS-4, MS-6 and MS-8 follow from §5.5, §6.3, §9.6, §10.2, §19 and the crash invariants; each has a mutant the suites catch (MM1–MM20, EM1–EM9).
2. **"Test de unlinkability: jurnalul issuer-ului nu se poate uni cu nullifier-ele relay-urilor."** Stated precisely in §1.3: (a) J1–J8 over complete views, journal, snapshots and wallet history included, not only journals and nullifiers; (b) NI-1, NI-1d, NI-2, NI-3 and NI-K make "no join" exact for everything outside L, on the full system and on the real Kotlin engine; (c) S1–S3 bound what is left at α = 0.001 relative to L, and S4 bounds what L alone allows; (d) J9 and J10 pin the contact schedule (with the per-invoice attempt cap) and key well-formedness. The 23 privacy mutants (24 with M22, §19.26 point 7) show the tests have teeth.
3. **What the proof assumes:** A3–A5; the correctness of `ring`'s PSS verification and of the signer's arithmetic (the RFC vectors, the differential test and the independent `s'^e` check reduce but do not remove this); the PRF security of HMAC-SHA-256 for seed-derived blinding; that the ES in the release is the one users run (T12, Phase 14); that the Kotlin scheduler matches the reference policy beyond the vectors (NI-K covers R1/R6 directly).
4. **What stays open after the gate:** the device checks of §13.7; the manual live-Tor circuit check; the measured L5 bits per call (reported and declared).

---

## 14. Gates, CI changes and dependency approvals

### 14.1 Gates (each change has a negative fixture and a `self-test.sh` entry)

| Gate | Change |
|---|---|
| `common.sh` | `rust_src_files` keeps its roots (`relay`, `issuer`, `client-core`), which now cover `ghost/issuer/crates/*`; `main.rs` is no longer exempt under `ghost/issuer/`. Fixtures: a nested crate `test-harness/gates/negative/issuer/crates/blind-rsa/src/lib.rs` and an issuer `main.rs` with forbidden content must make anti-placeholder and no-logging fail (E-2) |
| `no-logging.sh` | Rust also bans `tracing::`, `log::` and bare `info!/warn!/error!/debug!/trace!/event!/span!` in `ghost/issuer/**`; extended to `relay` and `client-core` if the S1 scan finds no hits there (otherwise §18 F8). One exemption (§19.17): `ghost/issuer/crates/ops/src/report.rs`, the only module of the operator tools that writes to stdout, with a fixed vocabulary and a fixture |
| `issuer-output.sh` (new) | in `ghost/issuer/crates/service` only `status.rs`, `store.rs`, `journal.rs` and `payout.rs` may open files for writing and nothing writes to stdout or stderr; in `ghost/issuer/crates/ops` only `report.rs` writes to stdout and only the named output modules (`keygen` public entries and sealed key files, `schedule-sign` output, `payout-check` ledger) open files for writing (§19.17, ADR-26) |
| `anti-placeholder.sh` | patterns unchanged; covers the new crates by path; test doubles live in `tests/` only (RC G23) |
| `rust-feature-policy.sh` | `rsa` queried per version (G-11): `-i rsa@0.9.10` dependents ⊆ {`tor-llcrypto`, `tor-key-forge`, `ssh-key-fork-arti`}; `-i rsa@0.10.0-rc.18` dependents ⊆ {`blind-rsa-signatures`}; `blind-rsa-signatures`, `crypto-bigint@0.7.5`, `md-5` and `ghost-issuer` must not appear in the `-p ghost-client-net` graphs (both Android targets) nor in `-p ghost-relay-node` (normal and build edges); self-test for each rule |
| `rust-crypto-pins.sh` (new) + `rust-crypto-pins.txt` | exact versions per graph: client {`rsa` 0.9.10, `num-bigint-dig` 0.8.6, `ring` 0.17.14}; relay {`num-bigint-dig` 0.8.6, `ring` 0.17.14}; issuer {`rsa` 0.10.0-rc.18, `crypto-bigint` 0.7.5, `blind-rsa-signatures` 0.17.2, `ring` 0.17.14}. The name-based allowlist cannot see a second `rsa` version; this gate can. Self-test on a mutated copy of `Cargo.lock` |
| `rust-dependency-allowlist.txt` | + `ghost-blind-rsa`, `ghost-entitlement`, `ghost-issuer-api` (ADR-22); `rust-client-allowlist.sh` then fails on any other new name, `md-5` included |
| `deny.toml` / `ci.yml:80` | the RUSTSEC-2023-0071 ignore keeps its id; its reason becomes: "rsa 0.9.10: verification only, inside Arti (client). rsa 0.10.0-rc.18: only through blind-rsa-signatures in ghost-issuer and ghost-issuer-ops (constant-time crypto-bigint path; payment-gated, independently fault-checked, 2 s reply quantum). A blind signer returns B^d by design, so the Marvin decryption-oracle class adds nothing; the residual exponent-timing risk is mitigated as stated in ADR-22. rust-feature-policy.sh and rust-crypto-pins.sh enforce both scopes. Re-review when rsa 0.10.0 is final." |
| `proto-check.sh` | every `message *Request { … }` block must contain `uint32 version = 1;` (RC G18) |
| `sync-no-catch-all.sh` | scope + `android/entitlement/src/main`, fixture and hit count |
| `entitlement-schedule.sh` (new) | `ghost/protocol/entitlement/schedule.ghes` verifies under the pinned key (`ghost-issuer-ops schedule-verify`); horizon ≥ 26 weeks from its first week (no build-date dependence, T12); rule 5 against its predecessor in git (keys, slot sets, prices unchanged for covered weeks; key ids and moduli distinct, §19.2); every slot onion of the current and next week is in the release's relay directory manifest and any three slots can be chosen spanning ≥ 2 operators (§19.12); `infra/relay` references the same path (no second copy); negative fixtures (a tampered ES, a changed slot set, a duplicated key) |
| `monero-pin.sh` (new) | `ghost/infra/issuer/monero-release.pin` is well-formed, and the Dockerfile, the compose file and the CI job read only it (no second hash anywhere) |
| `privacy-capture.sh` / `two_nodes.rs` | redeem events in the real capture with the new result values; token, authenticator and capability hex never appear |
| `self-test.sh`, `run-all.sh` | list the new gates, fixtures and counts |

### 14.2 CI workflow changes

- New jobs in **separate workflow files** (`ci.yml` has no `schedule` trigger and GitHub Actions has no job-level `paths` filter; §19.17): `monero-regtest.yml` (`on.pull_request.paths` `ghost/issuer/**`, `ghost/infra/issuer/**`; `on.schedule`; `workflow_dispatch`; required for merge on those paths), `t2-exit-gate.yml` and `entitlement-exit-gate.yml` (`on.push` to main, `on.schedule`, `workflow_dispatch`); each with `timeout-minutes`; `live-tor` extended (§13.6). No path-filter action is needed.
- Every new third-party action is pinned by commit SHA (`ci.yml:5-8` rule); the Monero tarball cache is keyed by its SHA-256.
- `ghost/Cargo.toml` gains `[profile.dev.package.*] opt-level = 3` for the crypto crates; the `rust` job gains the T2 PR variant (release profile) and the new suites; the `android` job the new modules' tests. The time budget of `entitlement-exit-gate` is measured in S9 with the JVM harness ES of §13.2 (the Phase 7 figure of 31 min had no cryptography).

### 14.3 Dependencies and their approvals

| Dependency | Version | Where | New to the lockfile | New to the Android library | Approval |
|---|---|---|---|---|---|
| `ghost-blind-rsa`, `ghost-entitlement`, `ghost-issuer-api` | workspace | client, relay, issuer, ops | yes | yes (workspace crates) | **ADR-22** + allowlist lines |
| `num-bigint-dig` | 0.8.6 | client, relay (now direct) | no | no (allowlisted) | pin gate |
| `ring` | 0.17.14 | client, relay, issuer (now direct; verification, sealed key files) | no | no (allowlisted) | pin gate |
| `sha2`, `hkdf`, `hmac`, `sha3`/`keccak`, `ed25519-dalek` 2.2.0, `curve25519-dalek` 4.1.3 | existing | ES verification, derivation, address validation | no | no (allowlist lines 58, 82, 127–128, 163, 262–263) | — |
| `blind-rsa-signatures` and its tree (`rsa` 0.10.0-rc.18, `crypto-bigint` 0.7.5, `crypto-primes` =0.7.0, `digest` 0.11, `hmac-sha256`, `hmac-sha512`, `ct-codecs`, `derive-new`, `derive_more`, `rand` 0.10; S1 records the exact `cargo tree`) | =0.17.2 | issuer, ops; dev-dependency of `ghost-blind-rsa` | yes | **no** (gate-enforced) | **ADR-22**, cargo-deny licences (MIT/Apache-2.0), Q8 |
| `md-5` (RustCrypto) | 0.10 line (on `digest` 0.10) | issuer (wallet-rpc digest auth) | yes | no | **ADR-26**, cargo-deny |
| `redb` 4.2.0, `tonic` (server), `prost`, `tokio`, `hyper-util` 0.1.20, `http-body-util` 0.1.5, `serde_json`, `toml` | existing | issuer | no | no | — |
| BouncyCastle (X25519, ChaCha20-Poly1305; HKDF stays on the platform `Hkdf.kt`) | existing | `:identity` (drop sealing) | — | no | **ADR-24 amends ADR-17** (deviation X15, §19.12); R8 keep rules; vector tests |
| CRC-32C | not used: journal entries carry SHA-256 from `sha2` (§19.5) | — | — | — | — |
| Gradle coordinates | none | — | — | — | — |

Not added anywhere: `rsa` as a direct dependency of a GHOST crate, `reqwest`, `monero-rpc`, `openssl`, `aws-lc-*`, `chacha20poly1305`, a JVM crypto library.

---

## 15. Implementation slices and exit-gate checklist

### 15.1 Slices (each ends green in CI)

| Slice | Content | Depends on |
|---|---|---|
| **S0** | The owner decides ADR-22 … ADR-26 and the Q1–Q24 defaults (§17) | — |
| **S1** | **Crypto and format core.** Workspace move of the stub to `ghost/issuer/crates/service`; `ghost-blind-rsa` (EMSA-PSS, blind, finalize, `ring` verification, permutation-proof verification) and `ghost-entitlement` (grid, challenge, token, nullifier, ES parse/verify, seed batch derivation, Monero address validation, URI); `Signer`, `CheckedSigner` and the reference signer; vectors `blind_rsa_pp2.txt` (RFC 9474 A through the raw path, RFC 9578 A.2 through the production path, GHOST), `monero_addresses.txt`, ES vectors; the differential test; gates `rust-feature-policy.sh` per version, `rust-crypto-pins.sh`, `deny.toml` reason, `common.sh` fixtures; a signer benchmark (budget ≤ 5 ms per blind signature on the CI runner, else fallback 1 before S4); confirmation of the `blind-rsa-signatures` 0.17.2 API assumptions (Appendix D) | S0 |
| **S2** | **Ops tools and test ES.** `ghost-issuer-ops keygen`, `keys-seal`, `schedule-sign`, `schedule-verify`, `report.rs`; a committed test ES and test keys under `tests/fixtures` (never loaded by production code); `entitlement-schedule.sh` with its fixtures | S1 |
| **S2b** | **First ES (§19.17, Q20 as revised).** A **stagenet-only** schedule key is generated with `ghost-issuer-ops` on the owner's machine, outside the repository (`%USERPROFILE%\.ghost-stagenet-keys\`, never committed); it signs `ghost/protocol/entitlement/schedule.ghes` (network stagenet, ≥ 26 weeks); the stagenet schedule public key is pinned in `ghost-entitlement` per network (a mainnet build pins the K1 key instead and refuses a stagenet ES); the sealed key files and `k_seal` values go to the staging issuer. `entitlement-schedule.sh`, S7's native build and S11's staging deployment depend on it. The K1 ceremony with the real offline key is a precondition of the first mainnet ES (Phase 16/17), not of Phase 8 | S2 |
| **S3** | **Relay redemption.** `relay.proto` `RedeemToken`; `capability_header` v2; `RelayKey` v2 mint and verify; `redeem_at`; `nullifiers.redb` (tags, `es_keys`); the week sweep; `--schedule/--slot`; capture fields; `allowed-observables.json`; `two_nodes.rs` with redeem; `redeem.txt` (Rust replayer); `redeem.rs` negatives including restarts | S1, S2 |
| **S4** | **Issuer core.** `issuer.proto` and `ghost-issuer-api`; `proto-check.sh` per message; `Store` + redb schema 1; `issued.journal`; invoice state machine; custody (sealed keys, window, destruction); the five handlers `*_at`; `ChainPort`, `FaultyStore`, `FaultyRail`, `FaultyJournal` in `tests/`; negative and crash suites I-A…I-H; `issuer_semantics.txt` (Rust replayer); `status.json` and its vocabulary test; `no-logging.sh` extension; `issuer-output.sh` | S1, S2 |
| **S5** | **Monero adapter.** JSON-RPC with digest auth (`md-5`); pool refill and startup reconciliation; stateless scanner; restore procedure; `monero-release.pin`, `monero-pin.sh`; job `monero-regtest` (steps 1–13, 17, 18) | S4 |
| **S6** | **Credits and payouts, server side.** Credit layout and discount path (covering set, per-epoch value); `ClaimPayout`; `RefreshCredit`; batch export with claim ids; `payout-check` (cumulative cap, per-entry ledger, sequential build); `reconcile-check` with relay aggregates; regtest steps 14–16b | S4, S5 (S3 for step 14) |
| **S7** | **client-core.** `IsolationScope::IssuerFlow`, the doctest and the stable `IssuerFlow` unit test (M4); `IssuerClient` over Arti; `EntitlementCrypto` and `TorIssuerTransport` JNI (incl. `nativeRefreshCredit`); `NamespaceClient::redeem` with pre- and post-checks; `for_issuer` and the README note; allowlist lines (ADR-22); T3 canaries for JNI errors; whether Arti exposes the consensus lifetime (optional `CLOCK_UNTRUSTED` check, §19.4) | S1, S2b, S3, S4 |
| **S8** | **Android storage and identity.** Migration v3, triggers, `expectedTables`/`expectedTriggers`, migration tests, `EntitlementSchemaIntrospectionTest`; Invite v2, per-invite derivations and vectors, the new labels; drop sealing with vectors; T16 extended | S0 (S1 for vectors) |
| **S9** | **Sync participation and the entitlement engine.** `SessionParticipant`, `QuietRunScheduler` (pure JVM, injected `RandomSources`) used by `SyncRuntime`, `runUserIssuerCall`, `SessionParticipantTest`; the `:entitlement` engine, stores, ports and Android adapters; redeem lane; purchase (fixed attempt plan), trial, refresh, drop (pre-drawn time) and claim steps; payment screen; two clocks; GC. JVM harness: crash enumeration, NI-K, `entitlement_policy.txt`, `ModelIssuer`/`ModelRedeemRelay` conformance, a new `:entitlement` liveness world (`Runner.renewNeeded` stays in `:sync`); `sync-no-catch-all.sh` extended; job `entitlement-exit-gate` | S7, S8 |
| **S10** | **T2.** `t2_world` (reference policy, loopback transport with circuit labels, warm-up, Sybil invitees, payment and need-triggered purchase models), `ghost-t2-join` (J1–J10, T2b, T2c, S1–S4), NI-1, NI-1d, NI-2 and NI-3, mutants M1–M21; PR variant and `t2-exit-gate` (release profile, own workflow file) | S3, S4, S6, S7, S9 (policy vectors) |
| **S11** | **Infrastructure and docs.** `infra/issuer` (Dockerfile, stagenet compose, torrc, `RUNBOOK.md`), relay configuration with the ES; ADR-22 … ADR-26 files and README rows; the text changes of Appendix B (INVARIANTS T2, T16, T22, T23; THREAT_MODEL §6, S2, R-14; LIMITE L6 and L2.1 #2; READMEs; `Invite.kt` doc) | S5, S6, S9 |
| **S12** | **Adversarial review** (Phase 6/7 style: crypto, money, privacy, Android, operations); fixes with failing-first tests; recorded CI runs; STATUS records the gate | all |

**Critical path:** S1 → S4 → S5 → S6 → S10 → S12. S3 and S8 run in parallel with S4; S7 and S9 in parallel with S5 and S6.

**Size.** Larger than the plan's 3–5 weeks: the estimate is **7–9 weeks**. The deferrable parts that keep every gate property are listed in §9.7 (XMR payouts; drop delivery). The trial, quiet runs, the ES, the journal and T2 cannot be cut without losing a property the exit gate claims.

### 15.2 Exit-gate checklist (all on the closing commit)

- [ ] §13.1 negative matrix green on the real relay, the real issuer and the client ("reuse, expirat, forjat, perioadă greșită").
- [ ] Issuer crash enumeration I-A … I-H (single and double) with MS-1 … MS-3 and the reconciliation invariants; relay restart tests (MS-8).
- [ ] Client crash enumeration E-A … E-I; 1 000 seeds in `android`; a recorded green `entitlement-exit-gate` (20 000 seeds).
- [ ] `monero-regtest` steps 1–18 green on the pinned binaries.
- [ ] A recorded green `t2-exit-gate`: J1–J10, T2b, T2c, NI-1, NI-1d, NI-2, NI-3, NI-K, S1–S3 at α = 0.001, S4 within its bound; all 52 mutants detected (53 with M22, §19.26 point 7).
- [ ] The first ES (S2b) committed, verified by `entitlement-schedule.sh`, and loaded by the staging issuer and relays.
- [ ] T1 two-node capture with redemptions green; `allowed-observables.json` changed only as ADR-25 records.
- [ ] Phase 7 suites (`sync-exit-gate`) green unchanged with the participant installed; `SessionParticipantTest` green.
- [ ] Every gate of §14.1 and its self-test green; `reproducible` and `android-native` produce identical builds.
- [ ] A recorded manual `live-tor` run with two `IssuerFlow` scopes on distinct circuits.
- [ ] The device checklist of §11.9 recorded as manual evidence (not blocking, as Phase 7 §8.9).
- [ ] Appendix B text changes applied; ADR-22 … ADR-26 in `docs/adr`; STATUS row.
- [ ] S12 review with no open confirmed finding.

---

## 16. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| R1 A bug in the public-side blind RSA code | invalid tokens, lost blindness | RFC vectors (2048 and 4096 bits); differential test against the reference crate; `ring` verifies every signature; `CheckedSigner`; S12 review |
| R2 A pre-release `rsa` (0.10.0-rc.18) in the issuer | issuer key exposure through a library bug | confined to the issuer graph and pinned (§14.1); independent fault check; payment gate; 2 s quantum; fallbacks (Q8); re-pin when 0.10.0 is final |
| R3 The `blind-rsa-signatures` 0.17.2 API differs from the assumptions (Deterministic variant, raw `blind_sign`, keygen) | S1 rework | S1 confirms first; fallback 1 (in-house `crypto-bigint`) is specified |
| R4 The signer is too slow | long `BlindSign`, slow T2 | S1 benchmark (≤ 5 ms); semaphore; T2 on 4 cores |
| R5 FCMP++ breaks view-only or cold wallets | the issuer cannot run on the new chain | `PaymentRail`; pin gate; runbook M2; `UNAVAILABLE` for new purchases only |
| R6 UX latency: invoice at the next quiet run (~2 h expected), tokens hours after payment | user friction | optional buttons (declared); renewals bought ahead; auto-renew with credits; Q7 |
| R7 Quiet-run starvation (always-foreground or heavily Doze'd devices) | purchases wait | the user buttons; attempts for 30 days; `PAYMENT_READY`/status flags; Phase 13 prompt mode |
| R8 Low volume makes L1/L5 identifying | declared links become real at alpha scale | trial funding removes onboarding from payments; LIMITE L6 with numbers; UI copy (CP-10) |
| R9 The ES horizon forces app updates about every 20 weeks | clients without updates cannot buy | horizon alarm; Phase 14 release cadence; existing tokens keep working |
| R10 Schedule (7–9 weeks) | slip | slices; deferrable parts (§9.7) |
| R11 ADR-25 (persisted nullifiers) rejected | replay after relay restarts | fallback recorded in ADR-25: memory only plus a refusal window after restart (large availability cost) |
| R12 Fixed counts too low for heavy users | unmet needs | a second pack; `ENTITLEMENT_NEEDED` counts; tune `access_per_slot` in the ES (global, no partition) |
| R13 Issuer database loss | double issuance or lost purchases | snapshot + decided-outcome journal with `INVOICE` entries and a pool reset on restore (B1, §19.5); only losing both loses paid-but-unissued invoices (declared) |
| R14 Kotlin/Rust policy drift | T2 proves the wrong scheduler | shared vectors + NI-K on the real engine |
| R15 Local timing leak of r on the device (variable-time `num-bigint-dig`) | none beyond AD-8 | r never leaves Rust; seed wiped at finalization |
| R16 A statistical T2 false positive | a blocked gate | pinned seeds; α = 0.001 per test; investigate, never re-seed silently |
| R17 Operational burden of air-gapped payouts | delays, errors | weekly cadence; hardware wallet allowed as signer; deferrable (§9.7) |

---

## 17. Open questions for the owner (the proposed default applies unless the owner objects)

| # | Question | Proposed default |
|---|---|---|
| Q1 | Approve ADR-22 … ADR-26 (Appendix A)? | yes |
| Q2 | Access epoch: ISO week (fewer keys and tokens) or day (7× tokens and keys, smaller capability clusters)? | week |
| Q3 | Pack: current week + 4, 16 access tokens per slot per week, 2 invites, 1 credit per XMR pack; alpha slot cap S ≤ 8; price per 13-week epoch in XMR, no fiat feed | yes; the owner sets the stagenet and mainnet prices in the first ES |
| Q4 | Trial via invite: current + next week, 8 per slot per week; worst-case abuse ≤ 40 % extra usage by token count | yes |
| Q5 | Referral option B (blind credit tokens; the inviter is credited once per invitee, from the first XMR pack bought before the invitee's pre-drawn drop time; all other credits are the payer's 10 % discount) instead of ADR-02's commitment "la fiecare plată"; option A is the fallback. Revised (§19.8): a credit is valued at its own epoch's price and accepted for 52–65 weeks (5 credit epochs), so a one-pack-per-4-weeks user reaches the discount after about 40 weeks; `min_claim_credits = 10` | B, with the revised validity and minimum |
| Q6 | Relays persist nullifiers with binding tags (ADR-25) instead of memory only | yes |
| Q7 | Issuer calls only in quiet runs (1/8 of background runs), one call per run; optional "get invoice now" and "check now" in STANDARD mode as declared samples, hidden in HIGH | yes |
| Q8 | Issuer signer: `blind-rsa-signatures` =0.17.2 on the pre-release `rsa` 0.10.0-rc.18 (issuer graph only), or fallback 1 (in-house constant-time `crypto-bigint`), or fallback 2 (`rsa` 0.9.10 hazmat, variable time)? | 0.17.2; re-evaluate when `rsa` 0.10.0 is final and RUSTSEC-2023-0071 lists it as patched |
| Q9 | Monero: stagenet for the alpha; 10 confirmations; 24 h to pay + 72 h grace (in blocks); no refunds; lock-time payments refused | yes |
| Q10 | Retention: issuer invoices 7 days after issuance or expiry, confirmed-unissued 30 days, journal ≈ 7–14 days, snapshots hourly 48 h and daily 7 days, credit nullifiers until the start of credit epoch + 5, counters 400 days; the client wipes issuance secrets and the creation hour at the terminal state; payout-address hashes 365 days | yes |
| Q11 | Invite-only is **not** enforced at the issuer (a modified client can buy without an invite, without a trial or an inviter); declared | yes |
| Q12 | T2: α = 0.001 per test, N = 2 000 in the gate, N = 300 per PR, 10 seeds nightly; L5 bits reported, not tested | yes |
| Q13 | Tokens and credits are not recoverable from the seed (E11); seed-derived recovery as a P1 item | accept for P0 |
| Q14 | Capability quota 256 MiB per token per week (the plan's example is 200 MiB); claims of 10 to 50 credits; trial tokens usable at once in STANDARD, at a slot in HIGH | yes |
| Q15 | Early acceptance window: 24 h or 48 h before a week starts? | 24 h |
| Q16 | If the schedule slips, may XMR payouts and then drop delivery move to Phase 9 (§9.7)? | implement in Phase 8; drop delivery is deferred first if S9 runs late |
| Q17 | ES built into the native library (`include_bytes!`) or shipped as an APK asset? | native library |
| Q18 | Reply quantum 2 s; keys loaded ahead through current + 6 by a biweekly K3 (at least current + 4 at any time, so a pack's layout is always covered); past keys kept while an open invoice references them, at most `end(epoch) + 42 d` (§19.1). Alternative: weekly K3 with at most 5 weeks ahead | yes (biweekly, 6 weeks) |
| Q19 | Received credits are exchanged by `RefreshCredit` (new RPC) before any use, so an invitee (or the operator posing as one) cannot recognise the inviter's spend or payout address; fallback: declare the link (residue) and forbid received credits in `ClaimPayout` | refresh |
| Q20 | Who produces the first ES (S2b), and with which key? | **revised 2026-09-12:** the first ES is stagenet and is signed with a stagenet-only schedule key generated in S2b on the owner's machine, outside the repository; the schedule public key is pinned per network, so a stagenet key can never validate a mainnet ES; the K1 ceremony with the real offline key is required before the first mainnet ES (Phase 16/17). Reason: a ceremony with the production key is an owner action that should not block the implementation of Phase 8, and the alpha runs on stagenet anyway (Q9) |
| Q21 | The absolute T2 bound S4: top-1 invoice → cluster accuracy of the declared-leak attacker over XMR packs of non-genesis clients | ≤ 0.25 in the gate world, always reported; the owner may tighten it |
| Q22 | `BlindSign` attempt plan: 3 planned attempts (≈ 4 h, ≈ 48 h, ≈ 106 h after the invoice) + at most 2 slow ones (≈ 7 d, ≈ 21 d), then `lost`; a payment made a few hours after the invoice yields tokens after about 2 days | yes |
| Q23 | Payment UX: `PAYMENT_READY` never an immediate notification; the payment screen closes relay sessions and holds them off U[20, 60] min; the UI advises paying from another device | yes |
| Q24 | Emergency slot move (a new onion for an already-published week) after the relay has been unreachable ≥ 48 h, declared as E18; or forbidden (that slot's tokens are lost until the horizon) | allowed, declared |
| Q25 (new, §19.21) | A relay that loses its whole data directory (relay key, marker, nullifier store) but keeps its onion keys restarts like a new relay and would accept a second redemption of tokens already redeemed in the open weeks. Runbook-only mitigation (`--nullifiers-reset` required after any data loss) and a declared residue, or a technical rule (every new relay needs an explicit init and refuses redemptions for its first open week)? | runbook + declared residue (ADR-25) |
| Q26 (new, §19.22) | A payout entry the workstation refuses (for example an invalid or reused address) closes the claim unpaid; its credits stay spent, because no refund path exists (§0.6) | yes, declared in ADR-24/26 and in the UI copy (Phase 13) |
| Q27 (new, §19.22) | Should ES rule 4 refuse the same exact `onion:port` under two slots in the same week (one of them could never be served, so its tokens would be refused and deleted)? | yes: added to `Schedule::verify` with a vector (the committed ES already satisfies it) |
| Q28 (new, §19.23) | A credits-paid pack whose two capped `RequestInvoice` answers are both lost after the issuer recorded the invoice loses its credits (MS-6 holds across one retry). Accept and declare, or add a seed-derived slow tail like `BlindSign`'s (restores MS-6, gives up the 6-call bound E5)? | accept and declare (LIMITE L6) |
| Q29 (new, §19.23) | Keep a background session open while a write need is pending, until one redeem-lane step has run (so a client with lapsed capabilities recovers without opening the app)? | yes |
| Q30 (new, §19.23) | Cap a trial's activation-slot extra days at the trial's last week, so HIGH mode can always use the trial? | yes |
| Q31 (new, §19.24) | The refresh of a received credit is due 1–14 days after the inviter's client read it from the drop, a relay-visible moment: an issuer call timed by relay activity that no L-cell declares (the NI-2 and NI-3 twins replay the read times). Declare it (E17 extended to the read → refresh delay, LIMITE L6), or draw the refresh time independently of the read (for example at a PRF time pre-drawn when the inviter hands out the invite)? | **decided (2026-09-14) and implemented (§19.26 points 1, 7 and 16):** two refresh times drawn when the invite is created; a credit read before the first waits for it, one read after it is refreshed at the second; the §19.8 cut kept; a scanned drop has only the second; the twins read at their own times and the T2 report names no exemption. **Decision revised (2026-09-14, §19.29):** one refresh time, 1–14 days after the listening ends, which the read never decides; the declared bit and the twins' exemption are gone, and NI-2 and NI-3 compare the issuer and wallet views as a whole |
| Q32 (new, §19.25) | An issuer that makes no transition keeps the journal segment of its last entry (claim hashes, nullifiers, claim payout addresses) past the ≈ 7–14-day retention, until its next transition. Accept and declare, or have the issuer decide a data-free `ANCHOR` entry into a new segment at each week change (a new journal entry kind; the old segment then goes at `start(w + 2)` as before)? | **decided (2026-09-14): the `ANCHOR` entry**, implemented as §19.25 point 5 (§19.26 point 8) |
| Q33 (new, §19.24) | J8 as checked (§19.24 point 2): an uncorrected client may be refused a period at most once per process start **and relay** (the "≤ 1 per process start" of §13.4 read per relay, since adoption is per relay and one relay's answer must not move the decisions about the others, §12.5), and the refused periods of devices more than 24 h off (beyond the clip) are reported, not asserted. Confirm this reading, or require ≤ 1 per process start over all relays and assert the devices beyond the clip too (which needs a clock correction past one day, against §19.23 point 2)? | **decided (2026-09-14): confirmed**, the per-relay reading and the report-only clip |
| Q34 (new, §19.24) | The Q29 redeem hold is armed by pending WRITE needs only, so a listen-only client whose capabilities all lapsed (READ MISSING needs only) still recovers only at a foreground or in a longer session. Extend the hold to read needs (E30 would then also show a pending read need; a READ MISSING redemption is PRF-timed within 6 h, §12.4, so one held step often redeems nothing), or keep write needs only? | **decided (2026-09-14): yes, write needs only** in Phase 8, declared (LIMITE L5); revisit with the shared read keys of Phase 9 (D11) |
| Q35 (new, §19.24) | T2 budgets (§13.4, §13.6): the PR variant takes 675–718 s locally and runs in the `rust` job (timeout 150 min); the gate job's timeout is 240 min and the mutants job's 120 min, against the design's ≈ 5 min and 60 min. Accept the measured budgets, or shrink the PR variant (fewer worlds, smaller N) and run the mutants nightly only? | **decided (2026-09-14): accept the measured budgets**, and reset every timeout after the first measured run on the CI runner class |
| Q36 (new, §19.26) | The post-restore scan listens to each of its 8 drops on every ES slot relay of its window (8 read capabilities per slot relay per week for 5 weeks, half of a pack's access tokens per slot) and resumes new invites at index 8 (an identity that created more than 8 invites before the restore reuses their signing keys and drops, E32). Keep, or listen on S − 1 slots per drop (a blob stored at 2 of its 3 relays is still seen) and resume new invites at a randomly drawn index? | keep in Phase 8, declared (E32); revisit with the shared read keys of Phase 9 (D11), which make the scan's reads free |

---

## 18. Findings outside Phase 8 (proposed as separate tasks)

- **F1.** ADR-11 still says "RocksDB TTL 90 zile" although ADR-18 moved relays to redb; it needs a documentation fix (ADR-25 amends the nullifier sentence anyway).
- **F2.** THREAT_MODEL R-14 ("issuer compromis … fără impact pe confidențialitate") is too strong: a compromised issuer can attempt n−1 and presence attacks (E8). S11 corrects the row.
- **F3.** No exchange path exists for honest tokens under a revoked epoch key after an issuer compromise (§3.3); proposed as a Phase 15 RPC.
- **F4.** Spec FR-1.x lists "inviter public key, referral commitment" in invites; ADR-05 already diverges and ADR-24 diverges further. The spec delta should cite both.
- **F5.** `client-core/net/src/lib.rs:38-43` is a `compile_fail` doctest that runs only on nightly; no CI job runs it, so the variant rename is not proved by CI until one does.
- **F6.** Phase 14: fold the ES into the signed release manifest; consider a public transparency log of ES and APK digests (key consistency against a malicious release key, A7).
- **F7.** The optional encrypted contact card of ADR-05 becomes Invite v3 in Phase 9.
- **F8.** If the S1 scan finds `tracing`/`log` uses in `relay` or `client-core`, extending the no-logging ban there is a separate task.

---

## 19. Normative corrections after review

The adversarial review of this design (four lenses: crypto, privacy, money, build; 49 findings) was checked against this document, the three research reports and the repository at `fa6a048` (gates, CI, `Runner.kt`, `SchemaIntrospectionTest.kt`, `OutboxStore.kt`, `relay/crates/node/src/main.rs`, ADR-17, `Cargo.toml`/`Cargo.lock`). **Every finding was confirmed.** Five pairs were duplicates and are merged below. For five findings part of the proposed fix is declined, with the reason. **This section is normative: where it and an earlier section disagree, this section wins.** Earlier sections were corrected in place where the change is local; those places cite "(§19.n)".

### 19.0 Finding → correction map

| Correction | Findings | Corrected in place |
|---|---|---|
| 19.1 Key custody follows obligations; corrected compromise bound | CR-1 = F-03, CR-5 (in part) | §3.3, §5.6, §6.4, §6.8 I1, ADR-26 point 4, Appendix B S2 |
| 19.2 ES immutability of keys, slot sets and prices; distinct keys; no `schedule_seq` on the wire | CR-2, CR-4 = F-09, LNK-09 (in part) | §2.2, §3.1, §4.2, §5.2, §11.3, §11.7, §13.1, §14.1, ADR-22, T22 |
| 19.3 Reconciliation per week over all slots | CR-3 | §0.2 MS-7, §4.2, §6.9 |
| 19.4 Two clocks; issuer tolerance ±4 h | LNK-03 (in part) | §1.4, §4.1, §5.3, §5.6, §8.3, §10.9, §12.1 R9, §12.5, E14 |
| 19.5 Decide, then journal; `INVOICE` entries; pool reset on restore | F-01, F-02, IMPL-10 | §5.4, §5.5, §5.6, §5.8, §6.1, §6.3, §14.3, §16 R13, ADR-26 point 3 |
| 19.6 Monero rail: fresh synced height, unattributed revenue, timely reorgs, in-process pool reconciliation | F-04, F-11, F-12, F-14 | §6.9, §6.10, §7.2, §7.3, §7.4 |
| 19.7 Payouts: sequential per-entry build, cumulative cap | F-05, F-06 | §6.9, §9.5, ADR-26 point 6 |
| 19.8 Credits: value per epoch, covering count, 52–65-week validity, refresh of received credits | CR-10 = F-07, LNK-06, CR-6 = LNK-05 | §0.1 D13, §0.2 P-6, §3.4, §4.6, §5.2, §5.6, §9.2–§9.6, ADR-24 |
| 19.9 Idempotency before validity in every handler | F-13 | §5.6 |
| 19.10 Relay periods: closed-period high-water, store reset, own onion | CR-7, F-10, IMPL-12 | §3.1, §6.8 O1, §10.2, §10.4, §10.5, ADR-25 |
| 19.11 Purchase attempt plan with a cap, deadline and outstanding amount, payment co-presence | LNK-02 (in part), F-08 (in part), LNK-01 | §1.2, §5.3, §7.6, §11.2, §11.3, §11.4, §12.2, E5, E8, E15 |
| 19.12 Drop timing, drop relays and operators, sealing primitives | LNK-04, IMPL-05, IMPL-07 | §1.4, §8.5, §9.2, §9.3, §11.6, §12.4, §14.3, ADR-24, E1 |
| 19.13 Exhaustion-triggered purchases | LNK-08 | §1.2, §11.2, §12.4, E16 |
| 19.14 Quiet-run decision in a JVM component; revocation as quiet-run work | LNK-10 = IMPL-06, LNK-12 | §8.6, §11.6, §12.2, ADR-23 |
| 19.15 Retention: snapshots, no day columns, device residues | LNK-11, LNK-13 | §6.1, §6.3, §6.4, §11.3, Appendix B L1.1, E19 |
| 19.16 T2: feasible world, absolute bound S4, new twin worlds and mutants | LNK-07, LNK-01/02/03/04/08, CR-6 | §13.4, §13.5, §13.8, §15.2 |
| 19.17 Build, CI and gates | IMPL-01, IMPL-02, IMPL-03, IMPL-04, IMPL-08, IMPL-09, IMPL-11 | §11.3, §11.7, §11.9, §13.2, §13.6, §14.1, §14.2, §15.1 |
| 19.18 Crypto wording | CR-8, CR-9 | §2.9, ADR-22 |
| 19.19 Bookkeeping: counts, deviation X15, questions | all | §0.1, §13.5, §17 |

### 19.1 Key custody follows obligations (CR-1, F-03; CR-5 in part)

**Defect.** The window held access weeks `[current − 1, current + 5]` and K4 destroyed a key at `end(epoch) + 8 d`, while `BlindSign` retries ran for 30 days, CONFIRMED-unissued invoices were kept 30 days and ISSUED re-serves 7 days. A paid invoice confirmed in week `base` whose client came back in week `base + 2` got `UNAVAILABLE` until purge (then `lost`); a set issued late in week `base + 1` could not be re-served. `RequestInvoice` also did not check that `base + 4` was loaded, while a biweekly K3 left only `current + 3` loaded before the next load.

**Rules.**

1. **Destruction.** The private key of (kind, epoch) is destroyed when `now ≥ end(epoch) + 8 d` **and** no invoice in CREATED, SEEN, CONFIRMED or ISSUED (not purged) has a layout referencing it. An invoice is purged at most 21 600 blocks after confirmation, which is at most `grace_height` (≈ 96 h after creation), or 5 040 blocks after issuance, so every key is gone by `end(epoch) + 42 d`. *(§19.27 point 4: an ISSUED invoice now goes at the later of the two, which issuance before `confirmed + 21 600` keeps within the same bound.)* The CREDIT key of epoch c is additionally kept until `end(c + 1) + 8 d` for `RefreshCredit` (§19.8).
2. **Trials.** A trial's keys (weeks `base`, `base + 1`) are held until at least `end(base + 1) + 8 d`, so a trial re-serve works for ≥ 8 days; afterwards `RedeemInvite` with the stored digest answers `REPLAYED` (declared; an invitee who crashed mid-activation and does not retry within 8 days loses the invite).
3. **Ahead.** K3 at week w loads keys through access week `w + 6` (and the invite and credit epochs they touch), so keys through `current + 4` are always loaded. `RequestInvoice` answers `UNAVAILABLE` (alarm `KEYS_MISSING`) unless every key of its layout is loaded; near a week boundary, a base week of `current + 1` may need `current + 5` and wait for the next load (transient).
4. **Compromise bound (corrected text).** A key thief can mint access tokens for at most 6 weeks ahead. Past keys kept for open invoices add no access forging power (relays refuse week p after `start(p + 1) + 1 h`). Invite and credit forgeries under any held INVITE or CREDIT key (the current ones, the previous CREDIT epoch, any retained past one) stay acceptable until runbook I1 revokes those epochs; the issuer is their only verifier, so the revocation takes effect when the restored issuer starts. Until the next epoch the issuer keeps signing the layout positions of revoked epochs with the leaked key (layouts, N and clients unchanged); those invites and credits are worthless. Honest unspent invites and credits of revoked epochs are lost (E12). With an honest issuer database (theft of keys only) the per-epoch counters show forgeries (`credits … ≤ signed[CREDIT][c]`, §6.9).
5. **Declined part of CR-5.** Short (weekly) CREDIT and INVITE signing epochs with long acceptance were not adopted: a credit's key would then reveal the week its pack was bought, and ten credits presented together would show the issuer a client's purchase cadence (a partition and a fingerprint). Issuer-local, immediate revocation gives the same containment without that leak.
6. **Tests.** Crash scenarios I-I (CONFIRMED signed in week `base + 2` and later) and I-J (issued late in `base + 1`, re-served 6 days later); mutant MM17; a negative test that `RequestInvoice` refuses when a layout key is missing.

### 19.2 ES immutability; distinct keys; no `schedule_seq` on the wire (CR-2, CR-4, F-09; LNK-09 in part)

1. **Distinct keys (rule 2).** Every key id and every modulus n is distinct across all ES entries and from every key id remembered from earlier schedules. RFC 9474 §6.2 requires a distinct key per encoding option, and a key shared by two (kind, epoch) entries would let a malicious client blind a CREDIT challenge in an ACCESS position (unbounded payouts). The §2.2 sentence claiming that `redemption_context` protects against key reuse is withdrawn (it protects honest tokens against replay only).
2. **Immutable layout and price facts (rule 5).** For every week covered by a previously accepted schedule, the set of slot numbers valid in that week is identical, and for every covered price epoch the price is identical. Memory: client `ent_schedule_fact` (§11.3, 2 new triggers), issuer `es_memory` (§6.1), relay `es_keys` (relays use neither prices nor other slots). `entitlement-schedule.sh` compares the committed ES with its predecessor in git.
3. **Consequences.** The layout is a function of (base week, product) only, identical under every ES version covering the base week, so an app update or an issuer restart between `RequestInvoice` and `BlindSign` can no longer break a paid purchase. `schedule_seq` is removed from `RequestInvoiceRequest` (field 6 reserved), from the idempotency digest R and from the JNI; `invoice.es_seq` records only the issuer's own ES seq. The ES version is no longer visible at the issuer.
4. **Onions.** A slot's onion may change for an already-covered week only as an emergency move, after the relay has been unreachable ≥ 48 h (runbook, Q24). Old-ES clients then try the old onion: a version partition, declared as E18. **Declined part of LNK-09:** making onions immutable too, because a lost relay would strand its slot for the whole horizon of every released ES (≥ 26 weeks).
5. **Tests.** Negative ES tests: one SPKI under two entries; a changed slot set of a covered week; a changed price; each also against the predecessor in the gate.

### 19.3 Reconciliation per week (CR-3)

The slot of an access position appears only in the client-built challenge inside the blinded message; keys are per (kind, epoch). The issuer cannot enforce 16 per slot, and a modified client may put all its positions on one slot. The invariant is therefore, for every week w, `Σ_slots redemptions(w) ≤ 16·|slots(w)|·packs(w) + 8·|slots(w)|·trials(w)`; per-slot counts are reported, never an alarm. MS-7, §4.2 and §6.9 are restated accordingly. Per-slot limits would need per-(week, slot) keys (S times the keys) and are not adopted.

### 19.4 Two clocks (LNK-03; the consensus anchor made optional)

**Defect.** Under AD-1 every relay is the adversary. Relay-supplied `relay_minute`/`relay_period_id` moved the client's week and its boundary guards, so relays could push one chosen client into `WRONG_PERIOD` at the issuer (a request no honest client produces) or suppress its issuer calls: a relay → issuer covert channel.

**Rules.**

1. Issuer-facing decisions (`base_week`, issuer-call due times) use the device wall clock under `clockTrusted()` only. Relay-supplied time never enters them.
2. The issuer accepts `base_week ∈ {week(t − 4 h), week(t + 4 h)}` in `RequestInvoice` and `RedeemInvite`, so a client within 4 h of true time never gets `WRONG_PERIOD` and needs no boundary guard for issuer calls (the former ±1 h and ±6 h issuer-call guards are removed). The key window of §19.1 covers `base = current + 1`.
3. Relay-facing decisions (redeem planning, the ±1 h redeem guard) keep the relay-corrected estimate of §12.5, which is harmless there: relays already decide what they accept.
4. Optional, if Arti exposes it (checked in S7): the client makes no issuer call while `wall` lies outside the current consensus lifetime ± 10 min (flag `CLOCK_UNTRUSTED`).
5. **Declined part:** making the Tor consensus the primary issuer-facing time source; the Arti API is unverified, and rules 1–2 close the channel without it.
6. **Tests.** Twin world NI-3 (relays shift chosen clients' time; issuer views identical); mutant M17; E14 corrected (only a device more than 4 h off, which relays cannot cause, reveals its skew).

### 19.5 Decide, then journal (F-01, F-02, IMPL-10)

**Defects.** (a) Invoice creation and subaddress assignment were not journaled: a restore lost every invoice created after the snapshot, burned the credits of credits-paid ones and handed a paying user's minor to another invoice. (b) Records were appended before the database decided; a race loser's record (a second `CLAIM` for spent credits, an `ISSUE` with the losing digest) could be applied by replay, especially after a restore. (c) CRC-32C has no implementation in the lockfile.

**Rules.**

1. **One entry per decided transition**, length-prefixed, with `seq` and a SHA-256 checksum (`sha2`; no CRC crate): `INVOICE` (with the credit nullifiers of a credits-paid invoice), `ISSUE`, `INVITE`, `CLAIM` (with its credit nullifiers), `REFRESH`, `BATCH` (batch id, week, claim ids), `BATCH_PAID`. A torn entry is discarded whole.
2. **Write rule.** Inside the redb write transaction (one writer), after re-checking the state the handler depends on, append and fsync the entry, then commit. Only winners are journaled; journal order equals commit order. Handlers that sign (`BlindSign`, `RedeemInvite`, `RefreshCredit`) sign before the transaction; a loser drops its signatures.
3. **Replay** applies entries in `seq` order, idempotently. **Restore** (B1): snapshot + replay, then the whole `address_pool` is discarded and `highest_minor := max(highest_minor, wallet count − 1)` before refilling, so no minor is reused. `BATCH` entries mean a restore never re-queues a claim into a new batch, and batch entries carry claim ids that the workstation refuses to pay twice (§19.7).
4. Crediting counts only transfers at `height ≥ created_height − 20` (defence in depth; with the pool reset, a minor is never shared).
5. **Tests.** I-H with invoices (XMR and credits-paid) created after the snapshot; I-K races then restart and races then restore for `BlindSign`, `ClaimPayout`, credits `RequestInvoice` and `RedeemInvite`; mutants MM15, MM16. R13 now reads: only losing both the database and the journal loses paid-but-unissued invoices.

### 19.6 Monero rail (F-04, F-11, F-12, F-14)

1. **Fresh, synced height (F-04).** `RequestInvoice` (XMR) answers `UNAVAILABLE` unless the scanner's last tick was synced (daemon synchronized, wallet ≥ daemon − 1) and is less than 2 minutes old; `created_height` is that tick's daemon height. Before the first tick of a process, no XMR invoice is created. Regtest step 17b; a `ChainPort` test with a stale height.
2. **Unattributed revenue (F-11).** Qualifying amounts count as unattributed when their minor ≥ 1 has no invoice, or its invoice is EXPIRED, or the transfer was not credited under the grace rule; minor 0 (treasury, payout change) is never counted. Invariant: incoming to minors ≥ 1 = credited + overpaid + unattributed.
3. **Timely reorgs (F-12).** A txid already recorded in `credited_tx` for an invoice stays timely if re-mined at a height ≤ `grace_height + 100` (the wallet's reorg window). A transaction first seen in the pool before `grace_height` but mined after it for the first time stays uncredited; this is declared in the disclosure ("pay well before the deadline").
4. **Pool refill (F-14).** A `create_address` result with `m ≠ highest_minor + 1` triggers the `get_address` reconciliation in the process (`highest_minor := count − 1`) and refilling continues; counter `POOL_RECONCILED`; crash scenario I-M (lost response, no crash).

### 19.7 Payouts (F-05, F-06)

1. **No input conflicts (F-05).** A watch-only `transfer` only dumps the unsigned transaction; inputs are marked spent by `commit_tx`, which `submit_transfer` reaches. So payout entries are built **sequentially**: entry k + 1 only after entry k was submitted by the workstation. The workstation ledger keeps per entry `built → signed → submitted → confirmed` with txid and input key images; an entry is rebuilt only after its old inputs are proven unspent and its old signed transaction destroyed; acknowledgement is per entry (txid, 10 confirmations). Building several entries in one cold session with `freeze` on their inputs is allowed only after S6 regtest proves it on the watch-only wallet. Regtest step 16b; mutant MM19.
2. **Cumulative cap (F-06).** `payout-check` keeps a cumulative total and requires `paid_so_far + batch_total ≤ 10 % × Σ incoming to minors ≥ 1 measured by its own view wallet since the treasury's restore height`. The undefined "covered weeks" basis is removed. It also refuses any `batch_id` or `claim_id` seen before. Regtest: two consecutive batches over the same revenue; the second is refused.

### 19.8 Credits: value, validity, refresh (CR-10 = F-07, LNK-06, CR-6 = LNK-05)

1. **Value (CR-10).** `credit_value(token) = price(epoch of its key) / 10`. `ClaimPayout` pays `Σ credit_value` per credit. A credits-paid pack needs the smallest set (≥ 10, ≤ 20) of accepted credits whose values sum to at least `price(price_epoch(base))`; the excess is kept. MS-4 then holds across price changes: discount value ≤ Σ value of the credits presented. Counter `credits_discount_atomic`; reconciliation test across a price change; mutant MM20.
2. **Validity (LNK-06).** With 13–26 weeks of validity, a user renewing one pack every 4 weeks (≈ 3.25 credits per 13-week epoch) never held 10 valid credits, so the "self-referral discount" was unreachable and only the XMR payout (5 credits) was, which removed the EAE/Janus mitigation "discount by default". Now a credit is accepted in its epoch and the four following (52–65 weeks); credit nullifiers are kept until the start of epoch + 5; `min_claim_credits = 10`. Such a user reaches the discount after about 40 weeks, and a payout is never easier than the discount (Q5).
3. **Refresh (CR-6, LNK-05).** The invitee finalizes the credit it sends, so it knows the token and its nullifier; under AD-1 the operator can also mint a credit and seal it to a drop it learned from an invite link. A received credit is therefore **never** presented in `RequestInvoice` or `ClaimPayout`. The inviter exchanges it with `RefreshCredit(credit, blinded)` (§5.2, §5.6): one call per received credit, alone, in its own quiet run and `IssuerFlow`, at a PRF time 1–14 days after receipt (§19.26: at one of two times drawn when the invite is created, never set by the read), for one fresh blind credit of the **same** epoch (value unchanged, net zero for the cap). The issuer keeps the CREDIT key of `c_now − 1` for this purpose (§19.1). A received credit's epoch is at most about 10 weeks old at refresh (pack within the trial, drop in weeks 3–7, refresh within 14 days), so `c_now` or `c_now − 1`; an older one is dropped (counted). Client: a `refresh` row in `ent_purchase` holds the received credit in `input_token` and the seed; finalization inserts the fresh credit into `ent_token`. The refresh call itself stays linkable to the sender (E17). P-6 is qualified accordingly; T2 gets Sybil invitees and mutant M21.
4. **Reachability of the inviter reward.** The inviter is credited only if the invitee's first XMR pack precedes the invitee's pre-drawn drop time (§19.12).

### 19.9 Idempotency before validity (F-13)

`RedeemInvite` verifies the token under any INVITE key the ES lists, looks up `invite_nullifier` first and re-serves an identical request whatever the epoch (subject to §19.1 rule 2); the acceptance window applies to new redemptions only. `ClaimPayout` looks up `claim_id` before any address or credit check. A committed request whose response was lost is thus never answered `PERMISSION_DENIED` after an epoch boundary (which wiped the invitee's identity, or released credits that were spent at the issuer). Retry-across-boundary tests for both.

### 19.10 Relay periods: closed-period high-water, store reset, own onion (CR-7, F-10, IMPL-12)

1. **High-water (CR-7).** `nullifiers.redb` `meta` holds `closed_through_period` and `sweep_high_water_minute`; the sweep raises the first in the same transaction that deletes a period's rows and never runs while `now` is below the second. Redeem refuses any `p ≤ closed_through_period` (`WRONG_PERIOD`, nothing recorded) whatever the clock says. The issuer keeps `closed_through_invite_epoch` and `closed_through_credit_epoch` in `meta` with the same rule before deleting invite and credit nullifiers. Clock-regression negative tests in `redeem.rs` and in the issuer suite; crash scenario I-L; mutant MM18.
2. **Store reset (F-10).** During the last 24 h of week p, weeks p and p + 1 are both open, and p + 1 stays open until `start(p + 2) + 1 h`. After losing `nullifiers.redb`, the operator starts the relay with `--nullifiers-reset`; the relay sets `refuse_through_period` to every period whose window was open at the reset (p + 1 if the reset falls in the last 24 h of p, else p) and answers `UNAVAILABLE` for them. Clients keep those reservations and retry; tokens of the refused weeks at that relay are lost when the week ends (declared; replication covers the data path). A missing store next to an existing `relay.key` without the flag is a refusal to start; the Phase 8 upgrade uses a one-time `--nullifiers-init`. Runbook O1 is corrected; relay test.
3. **Own onion (IMPL-12).** The relay binary binds to loopback and cannot learn its onion. It gains `--onion-hostname-file <path>` (Tor's `HiddenServiceDir/hostname`), read at start and compared with the ES slot table (§10.2 step 4, §10.5); negative tests for a missing file, an unlisted onion and a wrong slot.

### 19.11 Purchase attempt plan, deadline, payment co-presence (LNK-02 in part, F-08 in part, LNK-01)

1. **Cap independent of issuer answers (LNK-02).** All calls of one invoice are linked at the issuer by `invoice_id`, and the client cannot verify `AWAITING_CONFIRMATIONS`, so a lying issuer could harvest many linked quiet-run samples. Per invoice the client makes **at most 5 `BlindSign` attempts**: three planned at `receipt + U[3 h, 5 h]`, `+ U[44 h, 52 h]`, `+ U[100 h, 112 h]` (after the grace window, when an honest synced issuer's answer is final), then at most two slow ones at `+ U[7 d, 8 d]` and `+ U[20 d, 22 d]` if the last answer was not final; then `lost`. Due times are derived from the seed (`HKDF(seed, "ghost/v1/attempt" ‖ k)`) and `receipt_minute`, so no new column is needed and a restart keeps them. `SIGNED` or `EXPIRED` ends the plan early; stopping only removes samples. J9 checks the cap; S4 bounds what the declared leak allows; mutant M16. **Declined part:** identical cover calls after `SIGNED`: the seed and claim key are wiped at finalization (R10), and the cap alone bounds what an issuer can force.
2. **Deadline and outstanding amount (F-08).** The purchase row stores `receipt_minute` and `outstanding_atomic` (`amount − credited − seen` from the latest answer), both wiped at the terminal state (§11.3). `PaymentInstructions` carries the deadline (receipt + 24 h) and the outstanding amount, with a URI for the outstanding amount; after the deadline no instructions are returned. **Declined part:** retrying without bound while the answer is `AWAITING_*`/`UNDERPAID` (it would reopen LNK-02); the third planned attempt falls after the grace window instead, and the slow tail covers an issuer whose wallet was lagging.
3. **Payment co-presence (LNK-01).** The user pays after reading the instructions in GHOST, often from the same phone, and the operator's wallet sees the transaction in its pool within seconds to minutes; a relay session covering that moment selects about 1/32 of clusters. New declared cell L6 and residue E15. Mitigations: `PAYMENT_READY` is surfaced at the first natural foreground at least U[1 h, 6 h] after the invoice arrived, never as an immediate notification; the payment screen (`paymentScreenShown`) closes any running relay session, and no relay session starts while it is shown and for U[20 min, 60 min] after it was last shown; the UI advises paying from another device or later without GHOST open. T2 models the payment as a user action (70 % from the payment screen, 30 % during a relay session), exports the wallet's pool-first-seen `timestamp` (`IncomingEntry.timestamp`, read only by the T2 view), and S3d tests co-presence for screen payments; mutant M19.

### 19.12 Drops (LNK-04, IMPL-05, IMPL-07)

1. **Timing (LNK-04).** Writing the drop blob at the first pack's eligible minute told relays the activation day of the invitee's first XMR pack, and so its finalization time, for exactly the population the trial was meant to protect. Now each invited identity draws `t_drop` uniformly in `[start(base + 3), start(base + 8))` at activation (`ent_drop_target.drop_minute`) and writes exactly one blob then: the credit if its first XMR pack exists by then, otherwise a dummy (`0x00` plaintext, sealed identically). An identity without coverage at `t_drop` writes nothing, which relays already see from its silence *(§19.28 point 3: an identity that redeemed every token of the week holds its capabilities, is not silent, and writes its blob)*. The inviter listens until `expiry_day + 56`. Twin world NI-1d; mutant M18; §1.4 and E1 corrected.
2. **Relays and operators (IMPL-05).** `Outbox.enqueue` needs relays of at least two operators (`OutboxStore.kt:143`), and operators live only in `relay_directory`. Drop slots are drawn among ES slots whose onions are active in `relay_directory` and whose three relays span at least two `operator_id`s (redrawn otherwise; no invite if impossible). Every ES slot onion of the current and next week must be in the release's relay directory manifest (checked by `entitlement-schedule.sh`; a client finding otherwise raises `REFUSED_BY_RELAY`). A `CapabilityNeed` on a directory relay that holds no ES slot in the token week is never redeemed and never raises `ENTITLEMENT_NEEDED` (counter `NO_SLOT`). JVM test: a single-operator drop choice is redrawn.
3. **Sealing primitives (IMPL-07).** ADR-17 approves BouncyCastle for Ed25519 only and keeps HKDF on the platform. Drop sealing uses BouncyCastle `X25519Agreement` and `ChaCha20Poly1305` and the existing platform `Hkdf.kt`; this is deviation **X15**, recorded in ADR-24 as an amendment of ADR-17, with R8 keep rules and vector tests.

### 19.13 Exhaustion-triggered purchases (LNK-08)

Relays count a cluster's redemptions and see when it runs out; a user who then buys produces a `RequestInvoice`. This coupling was neither in L nor in the T2 world. Declared as L7 and E16. Mitigations: `ENTITLEMENT_NEEDED` is surfaced at a client-random time within U[0, 12 h]; a purchase started while it is set sends `RequestInvoice` no earlier than U[0, 24 h] after `startPurchase` (the "get invoice now" button remains a declared L3 sample); the new pack's tokens become eligible only from an activation slot, as before. T2 models 5 % of extra packs as need-triggered with a human delay, and S1/S3 run over that coupling.

### 19.14 Quiet runs and revocation (LNK-10 = IMPL-06, LNK-12)

1. The quiet-run decision moves out of `SyncRuntime` into a pure-JVM `QuietRunScheduler` in the `:sync` engine that draws from the injected `RandomSources` (which `SyncRuntime` already receives) and takes no entitlement state as input. `SyncRuntime`, the Phase 7 harness and the NI-K/J9 worlds use this one component, and the gating of `ParticipantSession` (issuer access only in QUIET and USER_ISSUER_CALL) is part of it. NI-K therefore exercises the production decision; mutant M20 (`QuietWhenWorkDue`) must be caught by NI-K. Until this lands, §13.7 claims R6 only for the component, not for `SyncRuntime`.
2. Invite revocation (a self-redemption of one's own invite) is automatic quiet-run work: one call per quiet run, its own `IssuerFlow`, listed in `QuietRunWork`, J9 and the T2 world. It is never a foreground call.

### 19.15 Retention (LNK-11, LNK-13)

1. **Snapshots.** Hourly encrypted `issuer.redb` snapshots are kept 48 h and one daily snapshot 7 days; older ones are deleted by B1. *(§19.27 point 6: the newest snapshot is never deleted, so in a maintenance window longer than 7 days it lives as long as the window.)* They are listed in §6.4 and included in the T2 issuer view; the RET crash invariant covers snapshot sets.
2. **No day columns.** `claim.created_day` is removed; `batch.created_day` becomes `batch.week`. Issuer storage holds no wall-clock time finer than a week.
3. **Workstation.** The workstation ledger keeps per entry batch id, claim id hash, txid, amount, state and a salted address hash, and cumulative totals, for 400 days; batch files are deleted 7 days after acknowledgement; the workstation's view wallet runs with `store-tx-info` off (checked in S6).
4. **Device (LNK-13).** `ent_purchase.created_hour` is nullable and nulled in the terminal transaction together with `receipt_minute` and `outstanding_atomic` (CHECK-enforced); GC uses `terminal_day` only. A fresh token's `eligible_minute` still encodes its batch's finalization day for up to 5 weeks; declared as E19 and in LIMITE L1.1 (the former "only while open" wording is corrected).

### 19.16 T2 changes (LNK-07; LNK-01/02/03/04/08 and CR-6 modelled)

1. **Feasible credits (LNK-07).** The old world asked for 250 × 10 + 120 × 5 = 3 100 credits from 2 000 minted, and no client could hold 10 within 84 days. The world now starts with a 40-week warm-up of the 150 future credit spenders through the same real issuer, relays and clients, fully exported and included in the join search (S1–S4 score the last 84 days), and scripts 100 credits-paid packs and 30 claims. A harness assertion checks that every scripted spend uses protocol-issued credits; achieved counts are reported.
2. **New behaviour in the world.** Payments from the payment screen or during a session (§19.11); need-triggered purchases (§19.13); 40 Sybil invitees controlled by the attacker, whose credits inviters must refresh (§19.8); relays shifting chosen clients' time (§19.4); invite revocations as quiet-run work (§19.14).
3. **New checks.** NI-1d (drop timing), NI-3 (relay → issuer time), S3d (payment co-presence), and **S4**: the declared-leak attacker's top-1 invoice → cluster accuracy over XMR packs of non-genesis clients ≤ 0.25 (Q21), also in a world where the model issuer lies `AWAITING_*`; always reported. J9 gains the per-invoice cap of 5 `BlindSign`.
4. **New mutants.** Privacy M16–M21; issuer and relay MM15–MM20. The total is 52 (23 + 20 + 9). *M22 (§19.26 point 7) makes it 53 (24 + 20 + 9).*

### 19.17 Build, CI and gates (IMPL-01, IMPL-02, IMPL-03, IMPL-04, IMPL-08, IMPL-09, IMPL-11)

1. **First ES (IMPL-01).** New slice S2b (Q20 as revised 2026-09-12): a stagenet-only schedule key generated on the owner's machine outside the repository signs `schedule.ghes` (stagenet, ≥ 26 weeks); the schedule public key is pinned in `ghost-entitlement` per network (a mainnet ES needs the K1 key and the K1 ceremony, Phase 16/17); the sealed keys go to the staging issuer; the staging relays' onion keys are generated in the same step, outside the repository, so the slot table names real onions. `entitlement-schedule.sh`, S7 (the native library embeds the file) and S11 depend on it; it is on the exit-gate checklist (Q20). No test key is ever committed at the production path (T8).
2. **Profiles (IMPL-02).** `ghost/Cargo.toml` gains `[profile.dev.package.<crate>] opt-level = 3` for `crypto-bigint`, `num-bigint-dig`, `blind-rsa-signatures`, `ghost-blind-rsa` and `ghost-entitlement`; the T2 PR variant, the gate and the issuer crash suites run with `--release`. The §13.4 budget is recomputed as worlds × signatures per world (at least four full worlds plus the warm-up), measured in S10, with `timeout-minutes` on every new job.
3. **JVM harness (IMPL-03).** The JVM worlds use the T2 test ES (S = 3, `access_per_slot = 4`, `trial_per_slot = 2`); `ModelIssuer` caches blind signatures per (key, B); the `entitlement-exit-gate` budget is measured in S9.
4. **Operator tools output (IMPL-04).** `issuer-output.sh` and the stricter no-logging rules apply to `crates/service`. In `crates/ops` only `report.rs` writes to stdout, with a fixed vocabulary and one `no-logging.sh` exemption with a fixture, and only the named output modules write files. Recorded in ADR-26 point 7.
5. **Phase 7 stand-in (IMPL-08).** `Runner.renewNeeded` stays unchanged in the `:sync` harness, and `sync-exit-gate` stays green unchanged. The liveness world with the real redeem lane is a new `:entitlement` harness run by `entitlement-exit-gate`.
6. **Introspection and M4 (IMPL-09).** `last_state` is renamed `prev_state`, and the `epoch` columns are explicit exemptions of the time-name regex. M4 is implemented against a new stable `client-core` unit test of the `IssuerFlow` → `IsolationToken` map (distinct per flow, dropped by `nativeEndFlow`, not reused after the transport closes), not against the T2 reference client.
7. **Workflows (IMPL-11).** `monero-regtest`, `t2-exit-gate` and `entitlement-exit-gate` live in separate workflow files with their own `on.pull_request.paths`, `on.push`, `on.schedule` and `workflow_dispatch`; `monero-regtest` is required for merge on issuer and infra paths. No path-filter action is needed.
8. **Journal checksum (IMPL-10).** See §19.5 rule 1.

### 19.18 Crypto wording (CR-8, CR-9)

1. The production `Signer` takes and returns 256-byte blocks, so it cannot replay the 4096-bit RFC 9474 Appendix A vector. That vector is replayed through the generic raw functions of `ghost-blind-rsa` and directly through `blind-rsa-signatures` =0.17.2. The five 2048-bit RFC 9578 A.2 vectors are the RFC evidence for the production `Signer` (§2.9).
2. Blindness is perfect for uniform r and computational (the PRF security of HMAC-SHA-256, with the seed deleted at finalization) for the seed-derived r that is actually used. Signature uniqueness under the permutation proof is unconditional. ADR-22 point 5 and D6 are read in that sense.

### 19.19 Bookkeeping

- **Counts.** Mutants 52 (23 privacy, 20 issuer and relay, 9 client; *53 and 24 privacy with M22, §19.26 point 7*); schema v3 has 9 tables and 13 triggers; `issuer.proto` has 6 RPCs; declared leak L1–L7; residues E1–E19 in §12.6 at review time. Reconciled with LIMITE L6 by §19.24 point 14: the residues are E1–E31 (§12.6 lists E1–E19 and E30; E20–E29 and E31 are declared in LIMITE L6 from the sections that §19.24 point 14 names). *E32, the restore scan's residue, is added by §19.26 point 13.*
- **Deviation X15** (ADR-17 BouncyCastle surface) is recorded in ADR-24 (§0.5 lists X1–X14; X15 is added by this section).
- **Questions.** Q5, Q10, Q14 and Q18 are revised; Q19–Q24 are new (§17).
- **Evidence** (Appendix D): new assumptions are checked in S6 (watch-only `transfer` and `freeze`, `store-tx-info`), S7 (Arti consensus lifetime) and S10 (T2 budget).

### 19.20 Corrections found during implementation (wave A: S1, S2, S8; normative)

1. **Schema v3 SQL (S8).** `ent_token_state` compares with `IS 'failed'`; `ent_purchase_frozen` and `ent_claim_guard` compare `sent` NULL-safely (a NULL written by `UPDATE OR REPLACE` must not skip them); every v3 time and grid-index CHECK (including `epoch` and `base_week`) adds `typeof(x) = 'integer'`; both SQL executors refuse bind types outside the `SqlExecutor` contract. The exact SQL of §11.3 is read with these changes; the code (`Schema.kt`, migration 3) is the reference.
2. **Revocations are append-only (S1-FG-3).** Rule 5 of §3.1 also covers `revoked`: a later ES must keep every (kind, epoch) revoked by an earlier accepted ES. Remembered revocations are stored by every verifier: the client in `ent_schedule_fact` (new fact kind `revoked`; v3 is unreleased and is amended in place), the issuer in `es_memory` (fact kind 4), the relay next to `es_keys` in `nullifiers.redb`. `entitlement-schedule.sh` checks each committed version against the whole first-parent history.
3. **Encodings fixed by vectors (S1).** Permutation-proof hashes encode n as I2OSP(n, 256) and e as I2OSP(e, 4); the seed derivation's HKDF-SHA256 uses `ring::hkdf` (standard RFC 5869); `Schedule::verify_token(&token, Expect)` with `Expect ∈ {AccessAtSlot(s), AccessAnySlot, Invite, Credit}` is the one verification entry point; the pinned schedule key table is per network and `Schedule::verify` refuses every ES until a key is pinned (S2b).
4. **Relay directory file (S2).** Until the Phase 14 signed manifest exists, `ghost/protocol/entitlement/relay-directory.txt` (`relay <onion:port> <16-byte operator id hex>`, the client's `RelayEntry` pair) is committed next to the ES; `entitlement-schedule.sh` requires every week to have ≥ 3 slots whose relays span ≥ 2 operators. S2b commits it with the ES and the pinned key in one change.
5. **Ops tools (S2).** One binary `ghost-issuer-ops` with subcommands; `keys-seal` is the K3 load tool (per-epoch `k_seal` values into a `GHKL` load file); only `ops/src/report.rs` prints and only `ops/src/output.rs` writes files.
6. **Invite v2 (S8).** The offline token check is injected into `:identity` (`Invite.TokenCheck`, adapter over `nativeVerifyToken` in S7/S9); an invite is usable on days before `expiry_day`; an invite whose token epoch has not started is refused; drop slots are 0..31; drop keys and ephemeral keys must be canonical, non-small-order X25519 points; the invite nonce is recorded inside the activation transaction through a transaction-bound `NonceStore` (S9).

### 19.21 Corrections found during implementation (wave B: S2b, S3, S4; normative)

1. **First ES (S2b).** Pinned schedule keys form a per-network table; today it holds only the stagenet key (`8b95a751…7dad`). Build-time network selection (a mainnet build refuses a stagenet ES) is deferred to Phase 16/17. ES seq 1: access weeks 2957…2989 (2026-W37 … 2027-W16), `issuer_name = "ghost-issuer-stagenet-v1"`, `min_claim_credits = 10` (§19.8 wins over the "=5" in §3.1), onion port 443 for relays (→ 7443) and issuer (→ 7444). **Release rule:** a release embedding seq 1 ships by week 2964 (Monday 2026-10-26); seq 2 reaches releases and every relay operator by week 2982 (Monday 2027-03-01). `ghost-issuer-ops onion-keygen` writes Tor v3 `HiddenServiceDir` key sets; `entitlement-schedule.sh` refuses committed onion secret keys by name and by header. Staging operator ids are labels (one party runs all three staging relays; ADR-11 independence is not claimed for staging).
2. **Relay (S3).** The relay matches its own onion to the slot table by service key (Tor's `hostname` file has no port). `EntitlementPolicy` carries `{schedule, slot, onion, nullifiers: Existing | Create | Reset, rate}`; `RelayConfig` gains an injectable clock. `nullifiers.redb` (schema 1, in `ghost-relay-storage`) holds bindings, `es_keys`, `es_revoked`, the closed-period high-water, `es_max_seq` and an 8-byte `relay_key_check`; a `redemption.marker` file makes `--nullifiers-init` one-time; `relay.key` is created only after every start-up check passes; a key that does not match the store is refused. The in-memory quota ledger refuses capabilities that had expired by its latest prune time, so a clock excursion cannot restore a spent quota. The capture carries the nullifier only once the token verified and its binding was decided. Nullifier-store errors answer `UNAVAILABLE` (capture `rejected_capability`). **Residue (Q25):** a relay that loses its whole data directory but keeps its onion keys cannot tell itself from a new relay; runbook O1 requires `--nullifiers-reset` in that case, and the residue is declared in ADR-25.
3. **Issuer (S4).** `es_memory` keys are `fact ‖ token kind ‖ epoch`. The invoice row keeps its 95-byte subaddress (byte-identical `RequestInvoice` re-serve after restore). ACCESS private keys are destroyed no earlier than `end(p+1) + 8 d` (§19.1 rule 2 without a per-trial base week). Invite-nullifier rows of an epoch closed at the start of `e + 2` are deleted 22 days later (trial re-serve, §19.1 rule 2 wins over §6.4); no redemption week is stored. The scanner and the pool refill live in S4 over `PaymentRail`; S5 adds the wallet-rpc adapter. A failed journal append or commit halts the issuer (`HALTED`, every call `UNAVAILABLE`) until a restart replays the journal. Torn journal tail: zeros or garbage at the end count as torn only when no valid frame follows. `credit_nullifier` rows store no reference to the invoice or claim (no grouping of credits at rest). `ClaimPayoutResponse.spent_mask` is `uint64`. The reply quantum releases at the first positive multiple of Q. `status.json` adds `KEYS_MISSING`, `POOL_RECONCILED`, `HALTED`.
4. **Client schema (S8 amendment).** Remembered revocations are stored as facts `revoked_access`, `revoked_invite`, `revoked_credit` (access weeks, invite epochs and credit epochs are separate index spaces) with digest = the revoked key id. Append-only tables must also refuse `INSERT OR REPLACE` (SQLite fires no delete trigger on REPLACE without `recursive_triggers`): BEFORE INSERT refusal triggers are added for `ent_key` and `ent_schedule_fact`, so the trigger count exceeds the 13 of §19.19.

### 19.22 Corrections found during implementation (wave C: S5, S6, S7; normative)

1. **Monero rail and server (S5).** The §6.6 configuration adds `key_load_file`, `daemon_rpc_url`, `daemon_rpc_login_file` (wallet-rpc exposes neither the daemon height nor its sync state), `treasury_address` and `restore_height` (recorded at first start; a different value later refuses the start). Start-up also requires the daemon's nettype to equal the ES network. The synced view of §5.4 additionally requires wallet height ≤ daemon height + 1; a wallet that holds fewer subaddresses than `highest_minor` is `WALLET_INCOMPLETE` and decides nothing. Runbook R5 runs only through `ghost-issuer --restore-wallet` (replay through `highest_minor`, then `rescan_blockchain`). Start-up refusals are exit statuses 1–6; the issuer prints nothing. wallet-rpc leaves `confirmations` out of a `transfer_entry` when it is 0 (epee `KV_SERIALIZE_OPT`; every pool entry): the rail reads it absent as 0, every other field it reads must be present and strictly typed, and fields it does not read are ignored. The pinned wallets cannot make a lock-time payment (wallet-rpc answers −50 `NONZERO_UNLOCK_TIME` to a `transfer` with a non-zero `unlock_time`, and wallet2 refuses to sign one), while consensus still accepts one made by other software: regtest step 6 checks the refusal, and the §7.4 rule is covered by the `ChainPort` world (`money_lock_time_and_double_spend_never_credit`). The signing semaphore is held until the signature is produced even if the client cancels. The regtest tests are `#[ignore]` and need `GHOST_MONERO_BIN`; `monero-regtest.yml` also triggers on `ghost/Cargo.lock`, `ghost/Cargo.toml` and `ghost/protocol/**`. The issuer crash suites run with `--release` in CI (ignored in debug).
2. **Credits and payouts (S6).** The workstation refuses a payout **entry**, not a batch; the acknowledgement carries a paid/refused byte per entry and `BATCH_PAID` journals the refused claim ids. **A claim whose entry is refused closes unpaid and its credits stay spent** (no refund path, §0.6; Q26). `ClaimPayout` answers `ADDRESS_REJECTED` also for the address of a queued or batched claim (one pending claim per address; declared residue: a holder of enough unspent credits can test whether a known address has a pending claim); the client releases its credits on that answer (S9). `credit_nullifier` rows of a refresh keep the whole 32-byte request digest. Batches are exported once per week at a random hour drawn per week, at most 200 claims per batch. Retention is a maximum on the week grid: claims deleted at the start of the week after the acknowledgement (≤ 7 d), batch rows 4 weeks after it (≤ 30 d); credit-epoch counters are kept 58 weeks from the start of epoch c + 5, plus never-deleted totals (`xmr_credited`, `payout_queued`, `payout_paid`). `reconcile-check --database` runs on the issuer host only; the workstation runs `reconcile-check --counters` on a `counters-export` file that is deleted after the check. The acknowledgement file is unsigned (it moves no value). Crash scenarios I-K, I-L, I-M and the issuer mutants are implemented.
3. **Client core (S7).** `IssuerClient` and `NamespaceClient::redeem` dial and bind only through the ES embedded in the library; the generic seams that take a schedule open no connection. Product codes: 1 pack-xmr, 2 pack-credits, 3 trial, 4 refresh. An issuer answer that is oversized, undecodable or `OUT_OF_RANGE` is `malformed_response` (a stricter reading of the §5.7 row). A token is bound to the slots listed under the relay's exact `onion:port` first, otherwise to the single slot under its service key; a key holding several slots in the week with an unlisted port is refused before I/O. The `IssuerFlow` map is bounded at 64 flows (eviction only gives fresh circuits). The optional `CLOCK_UNTRUSTED` check is not implemented: Arti 0.46 exposes the consensus lifetime only under `experimental-api`. `redeem` is on `TorRelayTransport`, not on the `:sync` `RelayTransport` interface (S9 decides the port).
4. **Client schema (REPLACE guards).** Every v3 table with write-once, frozen or state rules, and the v2 `outbox_op` (guards created by migration 3), refuses an insert that conflicts on any of its keys; v3 creates 20 triggers. The `:entitlement` engine uses plain INSERT after a read on these tables (INSERT OR IGNORE and UPSERT are refused there).

### 19.23 Corrections found during implementation (wave D: S9, S11 infra; normative)

1. **Sync participation (S9a).** Quiet runs happen only while a participant is installed; every job still consumes its draw, so the quiet pattern stays a pure function of the process key and the job index (`RandomSources.quietRun`, PRF domain 5; the payment hold draws from domain 6). Each participant session, including a `USER_ISSUER_CALL`, allows one issuer call on a fresh flow that `:sync` ends itself; a participant call made inside a sync transaction is refused. A user issuer call gets a session only while the app is visible (otherwise it fails `closed` at once). The payment-screen hold survives a process start through `SyncController.restorePaymentHold(lastShownMinute)` and the v3 column `ent_state.payment_shown_minute` (v3 amended in place, GC nulls it after 60 min); the new process redraws the hold from the saved moment (never below 20 min), which slightly favours shorter holds across repeated restarts (added to residue E15).
2. **Engine (S9b).** Activation resumes a pending trial in a new process (`IdentityManager.Activation.ResumedInvite`). The drop sends any fresh own credit of an accepted epoch (credits are fungible; no purchase link is kept at rest). Linked automatic issuer calls are capped: `BlindSign` 5 (Q22), `RequestInvoice` and `RefreshCredit` 2 each with client-drawn retry times, claims 2; the foreground onboarding trial keeps up to 40 retries (a declared L3 sample). E5 stays at 6 linked automatic calls per purchase; E17 may show two linked refresh times when the first attempt fails. The relay-corrected clock is bounded (adoption clipped to one day), and the redeem lane may spend tokens of `week(wall) − 1`. The client's ES rule 5 check is the same comparison over remembered facts as the Rust `Schedule::check_memory`. **MS-6 for credits-paid packs** holds across one `RequestInvoice` retry: if the issuer recorded the invoice but both answers were lost, the reserved credits come back `CREDITS_SPENT` (Q28).
3. **Harness and exit gate (S9c).** The `:entitlement` JVM harness enumerates E-A … E-I in both journal modes (default: double crashes for every 8th class, WAL only), runs 1 000 seeded worlds by default, NI-K on the real engine, the conformance replays (issuer semantics, redeem, blind-RSA GHOST vectors, `entitlement_policy.txt`) and 16 client mutants. `entitlement-exit-gate.yml` runs the full enumeration and 20 000 seeds in 12 shards with `--rerun`, a report check and uploaded reports. Harness worlds use a model Monero address checksum and a stagenet-labelled test schedule.
4. **Infrastructure (S11).** Tor runs in its own container that owns the network namespace (monerod, wallet-rpc and the issuer join it); state and secrets are bind-mounted from one host directory `GHOST_ISSUER_HOST_DIR` and copied into a tmpfs inside the containers; R5 step 1 regenerates the view-only wallet with `monero-wallet-cli --generate-from-view-key`; B1 snapshots are taken by a host cron (stop, copy, start, inside a maintenance window that I1, K2, K3, M2, R5 open) and read through a private copy; the relay's `--onion-hostname-file` is the file Tor writes. **Open (next wave):** an ops command that prunes `issued.journal` after a verified snapshot (6.3 retention is not enforced yet), a relay export of per-week redemption counts for R2, and an ops command that prints the ES `issuer_onion` (all three delivered in wave E: §19.24 points 10–12).
5. **Findings that change behaviour (decided by Q29, Q30).** A background session with no read pair ends before the redeem lane's first step, so a client whose capabilities all lapsed can redeem only in the foreground. In HIGH mode, the geometric extra days of an activation slot can push a trial's eligibility past both of its weeks. **Resolution (implemented):**
   - **Q29, the redeem hold.** A BACKGROUND session that starts, while a participant is installed, with at least one pending WRITE need (any reason: MISSING, EXPIRING, EXHAUSTED, REJECTED) stays the activity after its lanes have ended, transport READY and the participant's lease open, until the redeem lane reports its first step, the job's deadline, or a stop (a foreground wanted, the payment screen, onStopJob, a wipe), whichever comes first. The decision is the pure `:sync` component `RedeemHold`: its only inputs are the pending write-need count, read in its own transaction at the session's start, and the deadline; never entitlement state, token counts, an issuer answer, or a need that appears or is met later. `SyncRuntime` and the `:entitlement` harness both use it. A session whose transport failed or went offline, or whose runner failed, is not held. The hold starts only once the lanes have finished, so the read lane's events, calls and end are those of the session without it (T19). Public API additions (§11.6; ADR-23 amends ADR-20 again): `RelayRedeemAccess.stepDone()` (abstract), `QuietRunScheduler.session(…, onStep)`, and `RedeemPort.stepDone()` in `:entitlement`; the redeem lane reports each step, and an inert engine reports its empty step at once. Declared residue **E30** (§12.6; LIMITE L6 continues after the rows E20–E29 added by the documentation review): the hold's length, seen by the Tor guard and the local network and by any relay whose circuit the lanes left open, shows that a write need was pending at the start (local write activity, or a lapsed capability, also with no token to replace it); its input is never issuer state (R1). E15 is unchanged: the payment screen ends a hold at once.
   - **Q30, the trial slot cap.** An onboarding trial's HIGH-mode slot keeps the pack rule's draws (the Geometric(1/2) days first, then the U[0, 6 h) offset) and caps the extra days at `c = max(0, ⌊(start(base + 2) − 1 day − boundary) / 1 day⌋)`, where `boundary` is the first UTC-day boundary ≥ t_f + 4 h; a slot that itself falls after that day is kept, never moved earlier. Vectors: `entitlement_policy.txt` (`eligible … base=<week>`). **Effect on E1 (declared):** a trial's extra-day blur shrinks as t_f nears the end of base + 1, down to none for t_f ∈ (Friday 20:00, Saturday 20:00] UTC of base + 1, whose first eligible use is then always Sunday 00:00 + U[0, 6 h) of base + 1. t_f (the start of the attempt that succeeds) is not only the user's foreground moment (E3): the base week is frozen at the first send, and an issuer that answers `RedeemInvite` with transient failures until a foreground late in base + 1 (within the 40 onboarding attempts) chooses which attempt finalizes, so it can make the cap apply and pin a targeted invitee's first relay use to the last day of base + 1 (an **E8 × E1** interaction). Bound: with cap c, the cap moves only the mass P(extra days > c) = 2^−(c+1) onto the last day, so the chance that the first use falls in that day's window at most doubles (2^−(c+1) → 2^−c); without the cap the same mass left the trial unusable, which the same issuer action forced with probability ≥ 1/2 (a denial of service, E8). In STANDARD mode trial tokens are eligible at t_f anyway (E3).

### 19.24 Corrections found during implementation (wave E: S10, ops completions, Q29, Q30; normative)

Points 1–8 are the corrections of the S10 review; the client engine, the vectors, the T2 world and `ghost-t2-join` cite them by number. Points 9–14 record what wave E delivered: S10 itself (point 9), the ops completions of §19.23 point 4 (points 10–12; the review corrections of the journal prune are §19.25), Q29 and Q30 as implemented (point 13; their rules are §19.23 point 5), and the residue, question and document bookkeeping (point 14).

1. **The relay-facing clock per relay (§12.5; J8).** The decisions about one relay (the redeem lane's week, the ±1 h guard, the renewal lead and due check, the retry time of a kept reservation) run on that relay's own time, `wall + δ_relay` (its latest offset, clipped to ±24 h), once it answered in the process, and on `now_est` before; an adopted `WRONG_PERIOD` period never holds a relay behind the week of its own clock (`week = max(adopted, week(wall + δ_relay))`). A relay that answered `WRONG_PERIOD` in a lane step gets no further redemption in that step: its needs are planned again at the next step, on the period and minute it answered. The estimate forgets every offset and adoption when `wall − monotonic` moves by 2 min or more between two observations (the device clock was set). The lane's reservation rules (`reserve`: retry, wait, drop after the week's window, covered, fresh) and the `WRONG_PERIOD` rule (keep and retry from `start(week) − 23 h` when the token's week is after the relay's period, delete otherwise) are pure functions pinned by `entitlement_policy.txt` (`estimate relaynow`, `estimate observe`, `reserve`, `wrongperiod`) and replayed by `PolicyVectorsTest.kt` and `t2_policy_vectors.rs`. The T2 reference world mirrors `RedeemLane` beyond the vectors too: reservations by (relay, namespace, week), a fresh token by the smallest nullifier (`TokenStore.freshEligibleAccess`), needs on the device wall clock (`CapabilityStore.needed`), transient failures kept for the identical retry and other failures deleted. Reason: with the median alone, a device 1–24 h ahead near the end of a week re-sent its next-week token at every step on its uncorrected clock (the T2 PR variant failed J8 on seed pair 0), and a device clock set right mid-process kept stale offsets (the gate failed J8 the same way).
2. **J8 as checked.** Every accepted redemption lies in its window; a relay-corrected client (two relays answered since the device clock was last set) within the clip never redeems within ±(1 h − 60 s) of a true week boundary (relay answers carry whole minutes, so the corrected clock is exact to the minute) and is never refused a period; an uncorrected client is refused a period at most once per process start **and relay**, identical retries counted. The design's "≤ 1 per process start" is read per relay because adoption is per relay and one relay's answer must not move the decisions about the others before two relays answered (§12.5). Devices beyond the clip are corrected only to within a day (§19.23 point 2): their refused periods are counted and reported, not asserted.
3. **J3.** The targets are every value of the other side, whatever its length (blob data, addresses, database rows, journal segments), every 8-byte window in the Bloom filter. The counter family adds HKDF with a GHOST label and a position counter (0..63) as info (the counter suffixes of labels). The generic info words (`nonce`, `salt`, `seed`, `key`, `id`, `r`, `n`, empty) are a heuristic extension beyond the design's family.
4. **Mutant detectors (§13.5).** Every mutant test runs a control (the unmutated world at the same scale, seeds and issuer, with the same twins) on which the named check passes, and asserts the mutant's failure reason (the failing line's text). M3 and M13 are asserted by NI-1 across activation-slot cells, M3 also by S1 at the PR scale; M13's S1 is reported (the few invitee first packs of a PR-scale world give S1 no power, and the gate world runs no mutant). M20 is asserted by J9's quiet-run independence: the share of automatic `BlindSign` calls served by the first job run at or after their due minute, one-sided binomial against q = 1/8 at α = 0.001, read from the job runs' times and the issuer view (never from a run's quiet label); NI-K on the real engine stays the design's detector, and NI-2 cannot see a forced quiet run in the T2 world. M1 also runs as M1b (a GHOST label and the position as the HKDF info), so J3's detection does not rest on the mutant's own string. M5b's S2 feature is the Jacobi symbols' z-score in seven bins (the pack's blocks of weeks b+1..b+3 against the cluster's tokens of those weeks), detected with no permuted maximum reaching it.
5. **S1 and S2.** Each of the two S1 assignments (argmax, Hungarian) is a test at α = 0.001. The declared attacker also gets the relays' own view of the cluster: its namespace count, its redemptions in the pack's first covered week (L2 gives the base week) and the hours from the activation-slot boundary to its next redemption (L1 at the relays' resolution). The adversary holds these whatever the issuer leaks, so S1 measures issuer-side information beyond L1–L7 rather than the declared attacker's missing relay features. The full attacker adds Δ(first use, confirmation), the clock offset (E14 at the issuer, refused periods at the relays) and the first redeemed week. S2 permutes within the declared cells the issuer side holds (the base week, L2; the activation-slot day, L1), in a fixed order, so a pinned seed reproduces its verdict.
6. **Completeness, exports, floors, population.** Completeness compares the views with counts kept outside the recorder (each issuer handler call counted at its entry, the relays' capture events counted in their files) and requires every ground-truth nullifier (every token a client presented) in some relay view. Every table of both relay databases is exported, the schema's meta rows included (a table the harness does not know fails the world), with the in-memory quota ledger (`Relay::quota_snapshot`, read-only). A world writes `public.json` and `ground_truth.json` with `GHOST_T2_EXPORT` or `GHOST_T2_TRUTH`; the gate job uploads them with the report, and the complete NDJSON views (several GB at the gate scale) are exported and uploaded on request (`workflow_dispatch`). A statistical or twin check fails below a floor (S1, S2, S3a, S3b: n ≥ 100; S3d, S4: n ≥ 50; the NI-1 twins: ≥ 10 moved flows; NI-1d: ≥ 3 drop writes, its twin now moving every invitee's first purchase), and the report check refuses a PASS on an empty sample. The harness asserts that every scripted spend presents credits minted by the world's issuer. The world's need-triggered extra packs are 5 % of N (need buyers drawn from the population, one extra pack each) and its renewal cadence is three weeks (spenders renew every two weeks in the warm-up only); the report's `population` line checks the achieved counts (window packs within ±30 % of N, need-triggered starts about 5 % of N).
7. **NI-1 moves finalization inside the cell.** The NI-1 twin also delays every signing `BlindSign` answer by up to 30 s across minute boundaries, so packs finalize at other times inside their activation-slot cells, and the relay views and database snapshots must stay identical; a client with a flow pushed across a cell boundary (a finalization within 30 s before one) is compared before it. NI-1 across cells also compares a client before its first process start that differs between the worlds (a client crash after an extra attempt that only one world made, the 5 % fault, re-draws the process's quiet pattern).
8. **Open (Q31).** The twins NI-2 and NI-3 replay the base world's drop-read times of received credits, which set the `RefreshCredit` due times: the read → refresh timing (a relay-visible drop read, an issuer call 1–14 days later) is in no L-cell (Q31). *Closed by §19.26 point 1.*
9. **What S10 delivered, and its deviations (§13.4–§13.6, §15.1).** The T2 world is `ghost/issuer/crates/service/tests/t2/` (`world.rs`, `client.rs`, `policy.rs` with the Rust reference policy, `population.rs`, `chain.rs`, `es.rs`, `transport.rs`, `views.rs`, `gate.rs`, `config.rs`, `rng.rs`), run by `t2_unlinkability.rs` (`t2_pr_variant`: N = 300 packs, 21 days; `t2_exit_gate`: N = 2 000, 84 days, run by the workflow), with its mutants in `t2_mutants.rs` (the 23 privacy mutants M1–M21 with M2b, M5a and M5b; M1 also as M1b; point 4; *M22 added by §19.26 point 7*), the Rust replay of `entitlement_policy.txt` in `t2_policy_vectors.rs`, and a generated test ES and keys (`t2_fixture_gen.rs`, `tests/fixtures/t2_schedule.ghes`, `t2_keys.txt`). The analyzer is the crate `ghost-t2-join` (`ghost/test-harness/privacy/t2-join/`). `scripts/gates/t2-report-check.sh <report> gate|pr|mutants` refuses a report without a PASS line for every check (the population line included), of the wrong scale, or with a PASS on an empty sample (fixtures in `test-harness/gates/t2-report/`, cases in `self-test.sh`). Seeds are pinned (`gate.rs` `SEEDS`, ten pairs). CI: the `rust` job of `ci.yml` runs the PR variant in the release profile and checks its report; `t2-exit-gate.yml` runs the gate scale (seed pair 0 on a push to main and on pull requests touching `ghost/issuer`, `ghost/relay`, `ghost/client-core`, `ghost/test-harness/privacy`, `ghost/protocol`, the workspace manifest or lockfile, or the workflow; all ten pairs nightly as a matrix) and the mutants, and uploads every report (the complete NDJSON views only on `workflow_dispatch`). Deviations: (a) the world tests are ignored in the debug profile (release only, §19.17 point 2), so `rust-gates.sh` and a debug `cargo test` never run T2: a broken world is caught only by the CI `rust` job and `t2-exit-gate` (the wave E integration found the unexported `redemption_counts` table this way, point 10); (b) the budgets of §13.4 and §13.6 are not met (measured locally on 24 cores: PR variant 675–718 s, mutants 788–867 s; seed pair 0 of the gate scale 4 233 s before the review), and the timeouts are 150 min (`rust` job), 240 min (gate job) and 120 min (mutants job), none measured on the runner class (Q35); (c) the world adds one read-only method to the production relay, `Relay::quota_snapshot` (point 6); (d) the world does not model the Q29 redeem hold (its only session hold is the payment screen's), so T2 does not measure E30, and it draws the slot of a revocation's spares with the capped trial rule where `TrialSteps.kt` uses the pack rule (at most 2^−9 of HIGH-mode revocations differ); both are open items of the world (*both closed by §19.26 points 2 and 3; the trial rule also differed in every STANDARD-mode revocation, at once against a slot*). **State at the wave E integration:** the PR variant passes every check (population 314 window packs for N = 300; S1 p = 0.978 argmax and 0.933 Hungarian; S2 p = 0.122; S4 0.120, and 0.144 against the lying issuer) and the 23 mutants are detected, both in local release runs; no gate-scale run has passed on the reviewed code, and closing the phase requires a recorded green `t2-exit-gate` (§15.2).
10. **Relay redemption counts (R2, §6.9 check 2; amends §10.4 and §10.5).** `nullifiers.redb` gains the table `redemption_counts` (period u64 → count u64). The sweep that closes a period deletes its rows and, in the same write transaction, records their number: the final count of that week's redemptions at this relay. The counts of the last 13 closed periods are kept (`REDEMPTION_COUNT_WEEKS`); older ones are deleted in the same transaction. A period closed without redemptions has no row (its count is 0). The schema version stays 1: a store written before the table existed gets it, empty, at its next open, and the periods it closed before then have no count. Export: `ghost-relay serve … --redemption-counts <file>` (redemption only) makes the running relay write `<file>` at start (a failure refuses the start) and again after every sweep that closed a week, only when the content changed, through a temporary file renamed into place, in the format `ghost-issuer-ops reconcile-check --relay-counts` reads: the header `# ghost-relay redemption counts, closed weeks only (runbook R2)`, then `week <w> slot <s> redemptions <n>` lines ascending by week. No subcommand opens the store: redb holds an exclusive lock on a live store, and a copy of a live file can be torn. Runbook O1 has a weekly export step, and R2 reads the files. The file and the table hold aggregates only (§10.4 already declares the per-week count visible at rest); losing the store (`--nullifiers-reset`) loses its counts. The T2 world exports the table with the other relay tables (point 6).
11. **Journal prune (§6.3 "Pruning", runbook B1).** `ghost-issuer-ops journal-prune --database <snapshot> --journal <dir> --schedule <es> --now <t>` reads the snapshot through the recovered private copy (as `reconcile-check` does) and verifies it as B1 defines "verified": it opens as schema 1 and the reconciliation invariants hold at `--now`. Only then does `ghost_issuer::journal::prune_dir` remove, in ascending order, the segments before the one that holds the journal's last entry (§19.25 point 1), each only if its week ended at least 7 days before `--now` (at `start(w + 2)`) and its last entry is at or below the snapshot's `journal_applied`; it stops at the first segment that is not both. It removes nothing, answering `PRUNE_REFUSED reason=<r>`, when the snapshot is unverified (`snapshot-unverified`, after one `RECONCILIATION_MISMATCH` line per violated invariant), applied entries the journal does not hold (`snapshot-ahead`), or no longer continues the journal (`snapshot-behind`: the journal lost the entry after its last applied one, so a restore from it would refuse the start), or when the journal does not read (`journal-io`, `journal-corrupt`, `journal-format`, `journal-gap`). It prints `SEGMENT_PRUNED week=<w>` per removed segment, then `JOURNAL_PRUNED removed=… kept=… first_seq=… last_seq=… applied=…`. No segment is opened for writing, so the issuer may append meanwhile (a reader and a concurrent prune: §19.25 point 3); the files are removed only by `service/src/journal.rs` (the `issuer-output` gate), and `FileJournal::prune` delegates to `prune_dir`. `ghost/infra/issuer/journal-prune.sh` runs it hourly at minute 37 from the host cron on the newest snapshot, under `snapshot.lock`, never in a maintenance window, silent unless it refuses; the ops container gets `data/journal` at `/journal` and `DAC_OVERRIDE` for that run only. Retention: the segment of week w goes at the first run after `start(w + 2)` in which a later segment holds an entry, so an entry lives at most 14 days and one hour while the issuer makes transitions; nothing is pruned while no verified snapshot exists (restore safety first); an idle issuer is §19.25 point 2 (E31, Q32). Not yet verified on a real Docker host: that `DAC_OVERRIDE` is enough to delete the issuer-owned files, and whether compose writes to stderr on each run (cron-mail noise). The Unix-only reader test with a dangling symlink runs only on Linux CI.
12. **`schedule-onions` (runbooks "Instalare" and O1).** `ghost-issuer-ops schedule-onions --schedule <es> [--schedule-public-key <hex>] [--now <t>]` verifies the ES and prints `ISSUER_ONION onion=<56 base32>.onion port=<p>` and, with `--now`, one `SLOT_ONION week=<w> slot=<s> onion=… port=…` line per slot of the current and of the next week. The onion host name is a report value rendered from the 32-byte service key, so no runtime string reaches the console (`report_vocabulary.rs` allows it only in the `onion` field). New report codes `SEGMENT_PRUNED`, `JOURNAL_PRUNED`, `PRUNE_REFUSED`, `ISSUER_ONION`, `SLOT_ONION`; new fields `removed`, `kept`, `first_seq`, `last_seq`, `applied`, `onion`, `port`. The install check greps the exact `ISSUER_ONION` line (a test proves it matches the issuer's onion once and never a relay's), replacing the search for `<onion>:443` in the ES bytes, which a relay onion listed with the same port also matched.
13. **Q29 and Q30 as implemented (their rules: §19.23 point 5).** Q29: `RedeemHold` (`ghost/android/sync/src/main/kotlin/org/ghost/sync/engine/RedeemHold.kt`), decided by `SyncRuntime` before a background session starts and by the `:entitlement` harness; `RelayRedeemAccess.stepDone()` (`SessionParticipant.kt`), `QuietRunScheduler.session(…, onStep)` and `RedeemPort.stepDone()`. Tests: `RedeemHoldTest`; `SessionParticipantTest` (held until the step, ended at the deadline, decided at start, ended at once by each of the four stops); `RedeemLaneTest` (the step report, including an inert engine); `EntitlementScenarioTest.q29_aClientWhoseCapabilitiesAllLapsedRecoversInTheBackground` (`ScenarioLapsed`, background jobs only, fault-free; the hold under crashes is exercised by the seeded worlds, not by the crash enumeration). **Read-only needs are not covered:** only WRITE needs arm the hold, so a listen-only client (nothing to send) whose capabilities all lapsed has only READ MISSING needs; its background sessions still end before the lane's first step, and it recovers only at a foreground or in a longer session (the harness keeps a daily foreground for it, `dailyForegroundJobs = 96`). Extending the hold is Q34. Q30: `Slots.trialEligibleMinute(now, base, …)`, which `TrialSteps.kt` calls with the trial's base week for onboarding trials only; a revocation's spares (§8.6) keep the uncapped pack rule (`Slots.packEligibleMinute`), so in HIGH mode they can still become eligible after their weeks and be lost. `eligible … base=<week>` in `entitlement_policy.txt` is required on trial lines and refused on pack lines by both replayers (`PolicyVectorsTest.kt`, `t2_policy_vectors.rs`); the T2 reference policy's `policy::trial_eligible_minute` takes the base week. Tests: `GridPolicyTest`, `EntitlementScenarioTest.q30_seed3819_aHighModeTrialIsEligibleWithinItsLastWeek`.
14. **Residues, questions and documents (reconciles §19.19).** §12.6 lists E1–E19 and E30; the Romanian LIMITE L6 holds E1–E31 (*E1–E32 since §19.26 point 13*). E20–E29 are residues this design declares elsewhere, numbered by the documentation review: E20 Q25 (§19.21 point 2); E21 Q26 (§19.22 point 2); E22 Q28 (§19.23 point 2); E23 the pending-claim address test (§19.22 point 2); E24 the 8-day trial re-serve (§19.1 rule 2, §19.21 point 3); E25 a payment first mined after grace (§19.6); E26 two packs linkable by timing (§4.4); E27 invite-only not enforced at the issuer (Q11); E28 losing both `issuer.redb` and `issued.journal` (§16 R13, §19.5); E29 the quota exceeded once per relay restart (§10.4, Appendix C G4). E30 is the redeem-hold length (§19.23 point 5) and E31 the journal retention of an idle issuer (§19.25 point 2; closed by the `ANCHOR` entry of Q32, §19.25 point 5). LIMITE E1 carries the Q30 cap and E17 the Q31 exemption. Questions: Q31 stays open (the owner decides; until then the NI-2 and NI-3 twins replay the read times and the T2 report names the exemption; *decided and implemented by §19.26*); the ops review's `ANCHOR` entry is Q32 (§19.25; the S10 review had already taken Q31), with its default; Q33–Q35 are new (*decided 2026-09-14, §19.26 point 17*). Documents: ADR-23, ADR-25 and ADR-26 in `docs/adr` carry points 1–13 and §19.25; INVARIANTS T2 names the delivered code and its CI jobs; LIMITE L5 closes the rows of the three ops gaps, Q29 and Q30 and keeps what stays open (the gate-scale T2 run, Q31, the read-only needs of Q34, the revocation spares, the Docker-host checks); Appendix A keeps the review-time drafts.

### 19.25 Corrections found during implementation (ops completions: journal prune; normative)

1. **The prune keeps the last entry (review OPS-PRUNE-1).** `journal::prune_dir` removes only segments before the one that holds the journal's last entry; that segment and every later one stay (the newest by week is always among them). A newest segment may hold no entry: an append that created the segment of a new week died before its first frame was durable (empty), or a write failed halfway (a torn frame, which a halted issuer keeps until its restart). Keeping only the newest segment by week then removed the segment of the last entry, and neither the issuer's restart nor a restore from the verified snapshot could continue the sequence (a gap refuses the start, §6.6).
2. **Journal retention of an idle issuer (review OPS-PRUNE-2; qualifies §6.3 "Privacy", the `issued.journal` row of §6.4 and Q10).** Since the segment of the last entry stays until a later segment holds an entry, the ≈ 7–14-day journal retention holds only while the issuer makes transitions: an issuer with no transition keeps the segment of its last active week (claim hashes, nullifiers, claim payout addresses) until its next transition. Declared in runbook §13 until Q32 was decided. Remedy (Q32, decided and implemented: point 5): at the first scanner tick of a week whose segment does not exist yet, the issuer decides a data-free `ANCHOR` entry (a new tag, applied as a no-op that advances `journal_applied`) into the new week's segment; the old segment then no longer holds the last entry and goes at `start(w + 2)`, and the anchor segments hold no identifiers.
3. **A reader and a concurrent prune (review OPS-PRUNE-3).** A segment listed but gone at its read ends a removed prefix: the prune removes segments in ascending order, so every segment read before it is being removed too and is dropped from the read (before, the reader kept them and refused a false sequence gap). A segment missing from a listing is still a gap, and the replay's continuity check (§6.3 "Startup") still refuses a journal that no longer continues the database.
4. **Bookkeeping.** The three open items of §19.23 point 4 are delivered: `ghost-issuer-ops journal-prune` (hourly from the host cron, runbook B1), `ghost-relay serve --redemption-counts` (R2) and `ghost-issuer-ops schedule-onions`.
5. **Q32 as implemented (decided 2026-09-14; closes E31 while the scanner runs).** `ANCHOR` is journal tag 8 with an empty body (a 45-byte frame: `len = 9`, `seq`, the tag, the SHA-256 checksum); it carries no identifier, amount, height or time, and its week is only the name of the segment it lands in. `Journal::last_entry_week` is the week of the segment that holds the last durable entry. Every scanner tick starts, before any rail call, with `anchor_at`: when that week is before `week(now)` and the process's ticks have seen `week(now)` without a break for `ANCHOR_SETTLE_SECS` = 600 s (the settle window of reading (d)), the tick checks it again with the store's one write transaction held (every append happens inside one) and decides `ANCHOR` through `decide`, like every transition (append and fsync, `journal_applied`, commit; any failure from the append on halts the issuer). Applying it, live or on replay, changes nothing but `journal_applied`. So the first settled tick of a week anchors it unless a transition already wrote into the week's segment, later ticks find nothing to do, and a wallet or daemon outage does not stop it while the process runs (reading (c) says how long that is; `TickReport.anchored` reports the decision). Readings of point 2, each with its reason: (a) the condition is the week of the last entry, not the absence of the week's segment, because a newest segment can exist without an entry (point 1: an append that died), and an anchor into that segment is exactly what lets the older one go; (b) an empty journal gets no anchor: it retains nothing; (c) an issuer that does not tick (stopped, `HALTED`, or kept from starting) writes no anchor, so the segment of its last entry stays until the first settled tick after its restart and its retention exceeds 7–14 days by the length of the stop (runbook §13; without new verified snapshots nothing is pruned then anyway). A wallet or daemon outage is such a stop outside a maintenance window (review finding Q32-DOC-1): the issuer does not start without the wallet and the daemon (§6.6, exit status 5), and runbook B1's hourly snapshot stops and starts it, so an outage that lasts past the next snapshot restart keeps it down, writing no anchor, until they answer again; only inside a maintenance window, where the snapshot does not restart it (and nothing is pruned), does the running process anchor through the outage. (d) An append goes to the latest segment when that is later than `week(now)` (a clock step back keeps appending there), so an anchor decided while the clock is stepped forward across a week boundary would put every entry decided after the correction into the stepped week's segment, kept until `start(stepped week + 2)`, with no anchor meanwhile (review finding Q32-CLOCK-1: a step of k weeks kept the entries of k + 2 weeks). The anchor therefore waits for a settle window: the process's ticks must have seen `week(now)` without a break for 600 s (about 20 scan intervals, well inside the hour between two snapshot restarts); a tick of another week, or one earlier than the first of the run, starts the window again, and a restart forgets it. A step shorter than that decides no anchor. The wait changes no retention: the anchor of week w + 1 comes at most 600 s plus one scan interval after the week starts or the process restarts, long before `start(w + 2)`, when the segment of week w goes. What stays, declared: a step that outlasts the window, or a transition decided during a step (a client call, the payout job; also before Q32), puts the entries decided after the correction into the stepped week's segment, so they live at most 14 days, one hour and the length of the step (runbook §13, LIMITE E31). The segment file's modification time shows the anchoring tick, a function of the week boundary or the process's start, the settle window and the scanner's schedule only. Crash safety: a crash before the append, or an entry lost or torn, leaves the condition true, and the restarted process's first settled tick decides the anchor again under the same sequence number; a durable entry whose commit did not happen is applied by the restart's replay, which makes the condition false; neither can produce a second anchor for the week. Tests: `journal_anchor.rs` (each fault site of the anchor with the exact journal and database state before the restart; when an anchor is due and when not, the settle window included, which a restart, a tick of another week and a clock step back start again; a brief forward clock step that decides no anchor, after which the prune leaves only anchor segments as without the step, and one that outlasts the window, the residue of reading (d); an idle issuer pruned after a verified snapshot down to segments that hold only anchors, then restarted and restored from that snapshot, the client's pack still re-served byte for byte), crash scenario I-N in `crash.rs` (single and double crashes at every site of the settling ticks, the anchoring one included, then a restart and a restore), `journal_store.rs` (the frame, a tag-8 frame with a body refused, `last_entry_week`), `service/tests/journal_prune.rs` (the OPS-PRUNE-1 scenario now ends with the restarted issuer anchoring the empty or torn segment, after which the older segment goes) and `ops/tests/journal_prune.rs` (one week of transitions followed by three anchors). The T2 world's issuer view now contains the anchor frames of its journal (issuer side only; the relay views are unchanged).

### 19.26 Corrections found during implementation (wave F; normative)

Wave F integrates three slices and the lead's decisions of 2026-09-14: Q31 and the T2 open items of §19.24 (points 1–7), Q32 (point 8; its rule is §19.25 point 5), the post-restore drop scan of §8.4 (points 9–15; before the integration they were points 1–7 of a section of their own, so "§19.26 point 7" in the restore-scan commits is point 15 here), the corrections their integration needed (point 16), and the decisions on Q31–Q35 with the bookkeeping (point 17). Point 18 records the state measured on the integrated code.

1. **Q31 decided: the refresh time of a received credit does not follow the drop read.** *(Revised by §19.29: one time, 1–14 days after the listening ends; the two times, the declared bit and the exemption of points 1 and 7 are gone.)* The read is a relay-visible moment (the inviter's cluster fetching the drop blob), so an issuer call 1–14 days after it was an issuer call timed by relay activity in no L-cell. Now the inviter's client draws two refresh times from client randomness when it creates an invite and registers its drop as listening (§8.5), and stores them in `ent_invite` (`refresh_minute`, `late_refresh_minute`; schema v3 amended in place, as in §19.20 point 2 and §19.23 point 1):
   - the first, `ceil_minute(start(week(expiry − 1 s) + 8) + U[1 d, 14 d])`: 1–14 days after the end of the latest drop window an invitee of this invite can draw (it activates before the expiry day, and `t_drop < start(base + 8)`, §19.12), so it lies less than 7 days before `listen_until` and often after it;
   - the second, `ceil_minute(listen_until + U[1 d, 14 d])`: after the listening ends.

   A credit read at or before the first time is refreshed then, one read after it at the second. Nothing is taken from a drop from `listen_until_day` on, also before GC closes the invite, so every read precedes the second time. Either time is cut at `start(first week of credit epoch c + 2) − 2 d` (§19.8, unchanged), and a credit whose due time would precede its read is dropped and counted (`CREDIT_DROPPED`), never refreshed at the read. An honest invitee's blob, written from `t_drop` and kept 30 days, reaches its reader before the cut (at least `start(base + 14) − 2 d`) unless its delivery waits more than ten days after the latest drop window. The rule is pinned by `entitlement_policy.txt` (`refresh`, `refreshdue`), replayed by `PolicyVectorsTest.kt` against `RefreshPlan.kt` and by `t2_policy_vectors.rs` against `policy::refresh_times` and `policy::refresh_due`; `DropStepsTest` shows the same due time for two reads before the first time, the second for a read after it, a read after the cut dropped, and a blob after the listening not taken.
   - **What the read still decides (declared, E17 extended):** whether it came before the first time. One bit of a relay-visible moment reaches the issuer's refresh time, and only for a read in the last days before the listening ends, which an honest invitee's credit reaches only when its delivery or the inviter's read comes more than a day after the latest drop window; relays that hold a drop blob back can set this bit, and nothing else of the read time. Both times are functions of the invite's expiry and client randomness, so the refresh stays linkable to the invitee who sent the credit, as E17 already declares.
   - **Latency.** The refresh comes 7–10 weeks after the invite's expiry (or at the cut, if earlier) instead of 1–14 days after the read. Credits are accepted for 52–65 weeks and the refresh keeps the epoch, so the inviter loses nothing but time.
   - **T2.** The world draws the two times when an invitee takes an invite (the world's invite creation), from scheduling randomness keyed on the invite's identity. The twins NI-2 and NI-3 no longer replay the base world's read times (`UserScript::receipts` is removed): every world reads each credit at its own times, and the report counts the credits read in both worlds and those read at another time. The twins compare the issuer view as a whole; when a read falls on the other side of the first time in one world (the declared bit), that inviter's issuer calls are compared before the earlier of the two due times, and the report names how many inviters were compared so. The report names no Q31 exemption. *(Point 7 restricts the exemption to the declared bit and has the twins' relays move the reads.)*
2. **The Q29 redeem hold in the T2 world (§19.24 point 9 (d); E30 measured).** A background session of the world runs as `SyncRuntime` does: its lanes sync every pair holding a usable capability from READY; the redeem lane's first step comes at READY + U[0, 30 s] (a draw per run, `RedeemLane.firstWait`); the step runs if the lanes still run then, or if a pending WRITE need at the session's start armed the hold (`RedeemHold`), and the capabilities it installs serve from the next session. An unarmed session whose lanes end first redeems nothing, so a listen-only client whose capabilities lapsed recovers at a foreground (Q34 in the world). *(Point 7: the lanes last until their pairs' events at READY + 90 s·u, the lane steps again every 60 s ± 50 % while they run, and an unsent drop arms nothing.)* The world's needs follow `CapabilityStore.needed`: a capability is deleted a day after its expiry, an EXPIRING need has the capability's kind (WRITE: every redemption installs a write capability, §10.7), a pair without a capability needs WRITE MISSING when it has something to write and READ MISSING otherwise. Foreground sessions redeem as each pair comes, as before. The report's line `E30 (reported, …)` gives the background sessions, the armed ones, those held past their lanes with the median, 90th percentile and maximum of the hold, the held steps that redeemed nothing, and the unarmed sessions whose lanes ended before their step. `t2-report-check.sh` requires the line and refuses one with no held session (fixtures `missing-e30.txt`, `vacuous-e30.txt`; cases in `self-test.sh`).
3. **Revocation spares (§19.24 point 9 (d)).** The design keeps the uncapped pack rule for a revocation's spares (§19.24 point 13), so the world follows `TrialSteps.kt`: `policy::revocation_eligible_minute`, pinned by `eligible batch=revocation` vectors that `PolicyVectorsTest.kt` replays against `Slots.revocationEligibleMinute` (which `TrialSteps.kt` now calls) and `t2_policy_vectors.rs` against the world's function. The world had used the capped trial rule, which in STANDARD mode made the spares eligible at once, at the answer of a quiet-run call (an issuer response time reaching a relay-visible first use, R1); the correction removes that signal from the world.
4. **Bookkeeping.** §19.24 point 8 and the open items of point 9 (d) are closed and Q31 is decided (§17). LIMITE L5 and L6 (E17, E30), INVARIANTS T2 and ADR-23 carry the change. The residues stay E1–E31; E17 gains the bit of point 1. *(E32 is added by point 13; a scanned drop's credit carries no bit, point 16.)*
5. **State after this wave (local release run, seed pair 0, PR variant, 1 196 s with another world running on the same host; *superseded by point 7's measurements*).** Every check passes (population 314 window packs; S1 p = 0.999 argmax and 0.916 Hungarian; S2 p = 0.017; S4 0.123, and 0.144 against the lying issuer). E30: 74 079 background sessions, 27 285 armed, 22 359 held past their lanes (median 12 s, 90th percentile 24 s, maximum 41 s; 18 523 held steps redeemed nothing), 35 325 unarmed sessions ended before their step. NI-2: 3 received credits read in both worlds, 1 at another time, issuer views identical; NI-3: 3 read, none moved. At the PR scale few credits are read in the 21-day window and almost none refreshed there (the first refresh time lies 7–10 weeks after the invite's expiry), so the refresh path is exercised mainly by the gate scale, `DropStepsTest` and the vectors. No gate-scale run has been made on this wave.
6. **Mutant detectors after the hold (amends §19.24 point 4; *re-checked by point 7*).** With the hold of point 2 a background session redeems only in its redeem lane's step, and an unarmed one whose lanes end first redeems nothing, so a client whose capabilities lapsed and that has nothing to write redeems only at a foreground or in an armed session (Q34, as the client does). Two detectors lost their power in the mutant suite, while their controls passed:
   - **M11 (`DeviceClockPeriod`)**: fewer clients hear two relays within one process (the "corrected" state J8 asserts on), and the small world no longer holds a corrected skewed client's redemption near a true week boundary. M11 now runs at the PR scale against the PR control, still asserted by J8.
   - **M3 (`ImmediateEligible`)** *(S1 asserted again by point 7: the loss below came from the world's short lanes)*: an immediately eligible pack's first use now follows the user rather than its finalization, and at the PR scale S1 no longer separates the mutant (lift +0.011, p = 0.38); S2 does not flag it either (two of the 999 permuted maxima reach the observed one, p = 0.003). M3's S1 is reported, as M13's already is; M3 stays asserted by NI-1 across activation-slot cells (exact, §19.24 point 4) and by NI-K on the real Kotlin engine (`EntitlementMutantDetectionTest`). This is a weaker statistical detector for M3, not a weaker property: the exact detectors still catch it.

   The other 21 mutants keep their scales and detectors.
7. **Review corrections of the T2 world (review T2GAPS-1 … T2GAPS-4; amends points 1, 2, 5 and 6).**
   - **The declared bit only (T2GAPS-1).** *(§19.29: no exemption remains; any difference of a due time fails the twin.)* NI-2 and NI-3 exempted every inviter whose credit's due time differed between the twins, so a refresh timed by the read passed them (and the report called each such case a read across the first refresh time). Every read is now logged with the invite's two refresh times, the cut of the credit's epoch, the blob's first write and the end of the listening (`world::Receipt`, dropped credits included). An inviter is compared before the earlier due time only when both reads carry the same two times and cut, one lies at or before the first time and is due then (or at the cut), and the other lies after it and is due at the second time (or at the cut). Any other difference of the due times fails the twin ("refresh due time follows the read"), whether or not the refresh falls inside the world; so does a credit refreshed in one world and dropped after its cut in the other, which is no declared bit. A credit read in one world only gets no exemption: the views decide. Tests: `gate::tests` on hand-made outcomes (debug profile, so `rust-gates.sh` runs them; failing first on the old comparison), and mutant **M22** (`RefreshAtRead`: the refresh due 1–14 days after the read, the rule Q31 replaced), asserted by NI-2 at the small scale against its control. The mutants are now 53 (24 privacy, 20 issuer and relay, 9 client).
   - **Twins that move the reads (T2GAPS-2).** The twins changed token randomness and namespaces (NI-2) or relay-told clock offsets (NI-3) only, so a read moved by seconds at most, and nothing required it to move. Now the relays of both twins hold back every drop blob whose credit world A read (`Config::drop_holds`, built by `gate::drop_holds` from A's reads): until 1–12 h after the invite's first refresh time where A read at or before it and that changes the due time, otherwise by 2 h to 3 days; always releasing six hours before the listening ends, the blob expires (30 days after its write), the cut or the world ends, since holding a blob longer suppresses the credit, which is not a question of the refresh's timing. The reader gets an empty page that keeps its cursor; the relay view records the relay's real answer, and NI-2 and NI-3 compare the issuer and wallet views only. Each twin must move at least one read by an hour or more (`FLOOR_READS_MOVED`); the report counts the reads moved by an hour or more and those across the first time; `t2-report-check.sh` refuses an NI-2 or NI-3 PASS with no read moved by an hour (fixture `vacuous-reads.txt`, case in `self-test.sh`). **Short of the review's request:** it asked for a floor of reads across the first refresh time too. At the PR and small scales that time lies 7–10 weeks after the invite's expiry, beyond the 21-day window, so no read can cross it there (the small run crossed none); the crossing path is proven by `gate::tests` and reported by the twins, and whether the gate scale crosses one stays open until a gate-scale run.
   - **Lane events as the engine schedules them (T2GAPS-3; amends point 2).** In a background session every pair holding a usable capability at READY gets one lane event at READY + 90 s·u (`PairSchedule.backgroundTime`, `TrafficPolicy.backgroundWindowMillis`), and the session's lanes end after the last one (`Session.maybeFinish` waits for `ReadLane.allConsumed` and an idle work lane). The redeem lane steps at READY + U[0, 30 s] and then 60 s ± 50 % after each step (`RedeemLane.run`) while an event is still to come or a lane call still runs; only a session whose lanes ended before its first step depends on the hold, and a held session ends at that step. The world had ended the lanes one second per call after READY, so about half of its unarmed background sessions missed their step, which point 6 then took as the client's behaviour. The lanes' calls never move with the steps (T19); a capability a step installs still serves from the next session. Tests: `world::tests` (`Background`).
   - **The drop is a need from its tick (T2GAPS-4).** `SyncRuntime` reads the pending write needs before the session starts (`RedeemHold.pendingWriteNeeds`), and `DropSteps.sendDue` registers the drop namespace and enqueues the blob only in the tick that runs before each redeem step, so a due but unsent drop cannot arm a session. The world had armed the first session after `t_drop` on it. Now the blob is enqueued by the tick of the first step at or after its time (a foreground session's at its start) and is a pair and a WRITE need only from then (`DropOut::tick`, `DropOut::pending_write`; test `client::tests`).
   - **Measured after the corrections (local release runs, seed pair 0).** Small variant (254 s): every check passes; E30: 31 665 background sessions, 11 084 armed, 3 402 held past their lanes (median 15 s, 90th percentile 27 s, maximum 40 s; 3 297 held steps redeemed nothing), 1 229 unarmed sessions ended before their step, 27 034 stepped while their lane events ran; NI-2 moved 1 read by an hour or more, NI-3 3, none across the first refresh time; NI-1d 9 drop writes identical. PR variant (739 s, with the mutant suite running on the same host): every check passes (population 314 window packs; S1 p = 0.82 argmax and 0.34 Hungarian; S2 p = 0.020; S4 0.080, and 0.087 against the lying issuer); E30: 74 079 background sessions, 27 206 armed, 8 275 held past their lanes (median 15 s, 90th percentile 27 s, maximum 41 s; 8 024 held steps redeemed nothing), 3 395 unarmed sessions ended before their step (35 325 before the correction), 62 409 stepped while their lane events ran, 107 130 redeem steps in all; NI-2 and NI-3 each moved 3 reads by an hour or more, none across the first refresh time. Mutants (848 s): all 24 detected, M22 by NI-2 ("refresh due time follows the read") while its control passes. No gate-scale run has been made on this correction.
   - **Point 6 re-checked.** M11 at the small scale is still not detected: the mutant world passes J8 (0 hits), so M11 stays at the PR scale. M3's S1 at the PR scale separates the mutant again (lift +0.089, p = 5.6 × 10⁻⁵ argmax and 1.3 × 10⁻⁵ Hungarian, against the control's p = 0.82), so its S1 is asserted again, as §19.24 point 4 had it; the loss point 6 recorded came from the world's short lanes, not from the client.
8. **Q32 decided (2026-09-14): the weekly `ANCHOR` entry (the rule and its readings: §19.25 point 5; closes E31 while the scanner runs).** `ANCHOR` is journal tag 8 with an empty body: no identifier, amount, height or time, and its week is only the name of the segment it lands in. It is decided through `decide`, like every transition, by the first scanner tick of a week whose journal's last entry lies in an earlier week's segment, once the process's ticks have seen that week without a break for `ANCHOR_SETTLE_SECS` = 600 s (review Q32-CLOCK-1: a brief forward clock step decides no anchor). Applying it, live or on replay, changes nothing but `journal_applied`. An idle issuer's last-transition segment then goes at `start(w + 2)`. What stays is declared in §19.25 point 5 (c) and (d), runbook §13 and LIMITE E31:
   - an issuer that does not tick (stopped, `HALTED`, or kept from starting, which a wallet or daemon outage outside a maintenance window does at the next hourly snapshot restart, review Q32-DOC-1) writes no anchor until its first settled tick after the restart;
   - a forward clock step that outlasts the window, or a transition decided during a step, keeps the entries decided after the correction for at most 14 days, one hour and the length of the step.

   Tests: `journal_anchor.rs`, crash scenario I-N in `crash.rs`, `journal_store.rs`, and `journal_prune.rs` in the service and ops crates. The T2 world's issuer view contains the anchor frames of its journal (issuer side only; the relay views are unchanged), and the integrated PR variant and mutant suite pass with them (point 18).
9. **Facade and crash safety (§8.4, §11.2, §11.5).** Phase 13 restores an identity through `Entitlement.restore(mnemonic)` (new; `RestoreResult` ∈ {RESTORED, ALREADY_ACTIVE, REFUSED_MNEMONIC, UNAVAILABLE}), never through `IdentityManager.restore` directly. The engine checks the mnemonic, records the scan as owed for the restored root (`ent_state.restore_scan_root`, no end yet) and reserves invite indices 0..7 in one transaction, then stores the identity (`IdentityPort.restore`). The next relay session whose device clock the sync engine trusts installs the scan, once per process: in one transaction it fixes the end (`restore_scan_until_day` = that day + 35) and records the drops from the stored identity's derivations (point 15). A crash anywhere in the restore therefore ends with the scan owed for the restored root or with no identity (the user restores again). A restore is refused (ALREADY_ACTIVE) while an identity exists or an onboarding trial is pending. An identity of another root created after such a crash (an invite activation, a genesis) scans nothing (point 15).
10. **Representation.** Each scanned drop is an `ent_invite` row: state `created`, `payload` NULL (the invite's bytes are unknown), the drop namespace re-derived from the root entropy, `listen_until_day` = the scan's end; it is registered with `:sync` as listened (`Consumer.IDENTITY`). The receive path, the refresh flow of a received credit (§19.8) and the invite GC apply unchanged; `revokeInvite` refuses a scanned index (there is no token to self-redeem). The install is idempotent: rows of this root are kept (a scanned one is listened on the current relay set and extended to the current end), a closed one is replaced, rows of another root (an earlier identity of the same database) are closed, their drops retired, and replaced; `next_invite_index` becomes at least 8. *(Its refresh times: point 16.)*
11. **Relays.** A pre-restore invite's drop slots are unknown, so its drop is listened on the active directory relays of every ES slot valid in some week from one drop-blob lifetime (30 days, the blob's TTL) before the install through the scan's last listened day: a superset of the three relays its invitee wrote to at `t_drop` (§19.12) for every blob still stored at the install and for every blob written until the scan's end. The set is recomputed at each process start while the scan runs (directory or schedule changes, weeks leaving the blob lifetime).
12. **GC.** The pass that closes the scanned drops at their `listen_until_day` also nulls `restore_scan_until_day` (`≤ today`) and `restore_scan_root`.
13. **Residue E32 (new, LIMITE L6; Q36).** For 5 weeks after a restore every ES slot relay sees one cluster start listing 8 new namespaces within one 6-hour window (READ MISSING timing, §12.4), and the scan costs 8 read capabilities per slot relay per week (interim, one redeemed write capability each, §10.7: half of a pack's 16 access tokens per slot and week). Invites created after the restore start at index 8, so an identity that had created more than 8 invites before its restore reuses the signing keys and drops of its old invites 8, 9, … (T16's "different keys and drops" then holds only among the invites created since the restore). §19.24 point 14 is extended accordingly: LIMITE L6 holds E1–E32.
14. **Tests.** `RestoreScanTest` (the scan and its registration, the lane's read needs, a received credit, index 8 also before the install, refusals, a crash before the identity is stored and one inside the install, the install only in a trusted relay session, a device clock 400 days ahead or behind at the restore, a crashed restore followed by an invite activation or by an identity of another root, rows of another root, relays per slot week and of the blob lifetime before the install, a relay added to the directory later, the GC end); `IdentityAdaptersTest` (restore through `IdentityManager`); harness scenario **E-J** (a restore in the foreground, a credit sent before it to drop 2 at relay A, its refresh, the scan's end), in the fault-free suite and in the crash enumeration (both journal modes, single crashes, no double crashes, like E-G; the enumeration is now E-A … E-J and `entitlement-exit-gate` counts 24 lines). The harness identity bumps the records version on a restore, so a crash after the identity was stored classifies apart from one before it. **Budget:** E-J has K = 13 510 events and 982 crash classes with the corrections of point 15 (13 554 and 983 before; E-G: 2 743 and 202), because the read lane lists each of its 24 listened drop pairs about every 35 s in a foreground; its foregrounds are therefore kept to 4–5 minutes. In the default build on a 16-thread workstation it took 669 s of the 1 198 s of the whole enumeration (833 s of 1 642 s before point 15); the exit-gate shards grow accordingly (not yet measured on the CI runner class, Q35). *(E-J's schedule and budget after the integration: points 16 and 18.)*
15. **Review corrections (restore-scan review RS-1 … RS-4).**
   - **Bound to the restored root (RS-1).** A scan owed by a crash was installed for whatever identity existed next, also an invitee's whose trial was still pending: against §8.3 step 3, 8 identity namespaces were registered and listened, the trial's tokens were spent on read capabilities of drops that can hold nothing, and the namespaces outlived a refused trial's wipe. `ent_state` gains `restore_scan_root` (v3 is unreleased and amended in place, as in §19.23 point 1): SHA-256 of `"ghost/v1/restore-scan-root" ‖` the restored root's invite-0 drop namespace, with `CHECK (restore_scan_until_day IS NULL OR restore_scan_root IS NOT NULL)`. The install runs only when the stored identity's invite-0 drop namespace matches and otherwise drops the owe (a genesis after a crash); the activation transaction (§8.3 step 2) drops it as well, so no namespace is registered while a trial is pending. Point 9's former sentence that an identity created by another path scans its own drops is withdrawn.
   - **End fixed under a trusted clock (RS-2).** The end was computed once, at the facade call, on the device wall clock with no trust check: a clock 400 days ahead kept the drops listened (8 read capabilities per slot relay and week) for 435 days, and one behind let the first GC end the scan and lose the credits it exists for. The owe now carries no end; the install runs only in a relay session's tick, which runs only while the sync engine trusts the device clock (a READY in this process, no step since, as for GC and the drop time), and fixes the end at that day + 35 in its transaction. `onForeground` and `createInvite` no longer install; the restore reserves indices 0..7 itself, so an invite created before the install still starts at 8. The 5 weeks count from the install: a device offline after its restore starts them later, and blobs written meanwhile are still found (point 11).
   - **Relays of the blob lifetime before the install (RS-3).** The week range started at the restore's week, so a drop-slot relay whose slot moved to another onion in the 30 days before was never listened, although it still stores a blob written then; the superset was claimed for blobs written after the restore only. Point 11 now starts the range one blob TTL (`DropSteps.BLOB_TTL`) before the install, keeping only relays active in the directory.
   - **Harness (RS-4).** E-J's crash enumeration did not check that the pre-restore credit is received and refreshed, nor that the scan ends: the credit was minted outside the accounted tokens and the outcome check ran fault-free only. The harness now accounts every credit a scenario seals into a drop of its subject (`EntWorld.dropCredit`, E-G and E-J): in every run it must end refreshed at the issuer. Quiescence waits until a scan owed with an identity is installed and one past its end is forgotten, so every crash run of E-J also exercises the install and the end. Negative fixture `LoseReceivedDropCredit` (a listened drop's blob consumed as a closed one's), detected in E-J; `entitlement-exit-gate` counts 17 mutants.
16. **Integration corrections (wave F).** Merging points 1–7 with points 9–15 needed three corrections; neither slice's rule changes.
   - **The refresh times of a scanned drop (Q31 with §8.4).** *(§19.29 draws every drop's time this way.)* Point 1 made `ent_invite.refresh_minute` and `late_refresh_minute` NOT NULL, and point 10's scanned rows set neither, so every install of a scan would have failed its insert. The first time of point 1 needs the invite's expiry, which a restored device no longer knows, so a scanned drop gets only the second time: both columns hold one draw, `ceil_minute(start(until) + U[1 d, 14 d])`, 1–14 days after the scan's last listened day (`RefreshPlan.scanned`). It is drawn from client randomness in the install's transaction, and drawn again when a later restore extends the scan; a scanned drop that is still `created` holds no received credit, so nothing was due at the old time. Every read precedes it, since nothing is taken from a drop from `listen_until_day` on, so the read decides nothing, not even E17's bit. The §19.8 cut applies as for any credit.
     - Cost: a credit the scan finds is refreshed 1–14 days after the scan ends, so at most about 7 weeks after the install, instead of at its invite's own times, which the device no longer knows.
     - Test: `RestoreScanTest.aScannedDropIsRefreshedAfterTheScanEndsWhateverTheRead`. Reads at the install and on the scan's last day are due at the same time; extending the scan draws new times for the drops without a credit and keeps the credited ones.
     - It has no vector in `entitlement_policy.txt`: the T2 world models no restore (point 14), so no Rust replayer would read one.
   - **E-J's schedule.** E-J's refresh now falls 1–14 days after the scan's end. Its daily scripted quiet runs therefore move from days 2–17 to days 36–50 (the scan's end, the refresh and an identical retry), plus one on day 58 so that GC deletes the terminal row within the script, as the fault-free check expects. K and the enumeration time change accordingly (point 18).
   - **Mutant `LoseReceivedDropCredit`.** It rewrites the statement of `InviteStore.byNamespace` matched by its exact text, which point 1 extended with the two refresh columns; its pattern follows.

   On the merged code before these corrections (test sources made to compile), 16 tests failed, all on `NOT NULL constraint failed: ent_invite.refresh_minute`: 14 of the 18 `RestoreScanTest` cases, the E-J scenario and `EntitlementMutantDetectionTest.loseReceivedDropCredit`. That failure hid the stale mutant pattern, so its own evidence is a separate run (point 18).
17. **The lead's decisions (2026-09-14) and bookkeeping.**
   - **Q31:** the refresh time of a received credit is independent of the drop read (points 1, 7 and 16).
   - **Q32:** the `ANCHOR` entry (point 8).
   - **Q33:** confirmed; J8 is read per process start and relay, and the refused periods of devices more than 24 h off are reported, not asserted.
   - **Q34:** yes; the Q29 hold covers write needs only, declared (LIMITE L5).
   - **Q35:** the measured T2 budgets are accepted, and every timeout is reset after the first measured CI run on the runner class.
   - **Q36** (point 13) stays with the owner, its default applied.

   §17 records these decisions. Residues: LIMITE L6 holds E1–E32; E31 is closed while the scanner runs and E32 is new; E17 carries the bit of point 1, and a scanned drop's credit carries none (point 16). Documents: ADR-23 (point 14 and its Q31, Q33, Q34 and Q35 rows), ADR-24 (point 4, the restore scan and a scanned drop's refresh), ADR-26 (Q32), INVARIANTS T2 (no Q31 exemption, E30 measured), and LIMITE L5 and L6.
18. **State on the integrated code (local runs, 2026-09-14).** The Kotlin suite and the T2 runs shared one 16-thread host, so their times are not representative.
   - **Rust gates.** `rust-gates.sh` passes (fmt, clippy, workspace tests, the release crash suite with I-N, cargo-deny and the policy gates).
   - **T2 PR variant** (release, seed pair 0; 1 021 s): every check passes, and `t2-report-check.sh … pr` is OK. The world is deterministic per seed, so the report equals point 7's PR run: population 314 window packs; S1 p = 0.82 argmax and 0.34 Hungarian; S2 p = 0.020; S4 0.080, and 0.087 against the lying issuer; NI-2 and NI-3 each moved 3 reads by an hour or more, none across the first refresh time; NI-1d 9 drop writes identical. The E30 line is the same too: 74 079 background sessions, 27 206 armed, 8 275 held past their lanes (median 15 s, 90th percentile 27 s, maximum 41 s; 8 024 held steps redeemed nothing), and 3 395 unarmed sessions ended before their step. The issuer view now holds the anchor frames of point 8; no relay statistic moved.
   - **T2 mutants:** 24 of 24 detected (999 s); `t2-report-check.sh … mutants` is OK.
   - **Kotlin** (`./gradlew --offline testDebugUnitTest --rerun`): 679 tests, 0 failures (entitlement 190, sync 285, storage 113, identity 63, network 22, app 6). The crash enumeration injected 68 865 crashes and caught all of them (E-A … E-J in both journal modes, 1 653 s on 16 threads). E-J now has K = 13 499 events and 983 crash classes (692 s in DELETE mode, 218 s in WAL), against 13 510 and 982 before point 16. The 1 000 seeded worlds pass, the 17 client mutants are detected, and the NI-K twins are identical.
   - **Failing first for point 16.** The mutant pattern: with the pattern of the merged code restored, `EntitlementMutantDetectionTest.loseReceivedDropCredit` fails ("LoseReceivedDropCredit was not detected"). The scanned drop's refresh times: the 16 failures listed in point 16.
   - **Gates:** `run-all.sh` and `GHOST_SELFTEST_OPS=1 GHOST_SELFTEST_CLIPPY=1 self-test.sh` pass.
   - **Not run:** a gate-scale T2 run (N = 2 000, 84 days) on the integrated code, and the `entitlement-exit-gate` shards on the CI runner class (their timeouts are reset after the first measured CI run, Q35).

### 19.27 Corrections after the S12 review (normative)

The S12 review of Phase 8 (fa6a048..main) confirmed eight findings in the Rust, CI and documentation scope: CR-RF-1, CR-CT-1, MONEY-CLAIMID-1, MONEY-RESERVE-1, P8-PRIV-2 (with its engine finding P8-PRIV-1), P8-J8-1, OPS-B1-RETENTION-MAINT and GATE-ISSUER-OUTPUT-BRACE. Each point below says what changes, the text it corrects, and how it is tested; every code change was first shown by a test that failed (or, for P8-PRIV-2, a mutant that no check detected).

1. **A refresh budget per credit epoch (CR-RF-1; corrects §2.8 point 1, §5.9 and ADR-22 point 7).** A refreshed credit is an ordinary credit of the same epoch, so a holder of one credit could refresh it in a chain for free, one link per 2 s quantum, each link journaling and syncing an entry, keeping a `credit_nullifier` row for 52–65 weeks, and signing under the CREDIT key: unbounded durable writes with no alarm (reconciliation cannot see it, since `signed[CREDIT][c]` and `credits_refreshed[c]` grow together) and a non-adaptive signing oracle outside the payment gate of §2.8 point 1. **Rule:** a new `RefreshCredit` of credit epoch e is accepted only while `credits_refreshed[e] < refresh_floor + Σ packs_xmr[b]` over the base weeks b of credit epochs e − 1, e and e + 1 (`credit::refresh_budget`; `refresh_floor` = `REFRESH_BUDGET_FLOOR` = 64, an `IssuerParams` field). The sum is the honest maximum: every honest refresh consumes one received drop credit; an invitee writes one blob, which carries a credit only when it paid its first XMR pack before its drop time (§9.3); that pack's credit epoch is within one of e, because a refresh of e happens while `c_now ∈ {e, e + 1}`, after its drop, and a drop comes at most 8 weeks after the invitee's base week. The check runs after the epoch, revocation, closed-through and range checks and before signing, and again inside the decided transaction (a concurrent refresh that took the last budget). Beyond it the answer is `RESOURCE_EXHAUSTED`, which the client maps to `quota` (a transient retry within its two attempts), and the new status key `REFRESH_REFUSED` counts the refusals since the process started (§6.5 gains the key; runbook §3). A recorded refresh (the same digest) is re-served whatever the budget. The week counters it sums are kept 58 weeks, longer than an epoch stays refreshable. **Not a global token bucket** (the review's first proposal): it would let the same holder starve every epoch's honest refreshes; the per-epoch budget confines that to one epoch and to the packs around it. **Declared residue E34** (LIMITE L6): a credit holder can spend an epoch's budget at no cost, after which honest refreshes of that epoch are refused and an inviter's received credit of that epoch is lost after the client's two attempts, until new XMR packs raise the budget; the chain's durable writes and free CREDIT signatures are bounded by 64 plus three epochs' paid packs. Adaptive, chosen-B queries still cost one credit each (a chosen B finalizes into no new credit). Test: `refresh.rs` `a_refresh_chain_stops_at_the_epoch_budget` (failing first: the third link of one credit's chain was signed), `status_vocabulary.rs`.
2. **Timing evidence implemented (CR-CT-1; §2.8 point 6, §13.7).** `issuer/crates/service/tests/signer_timing.rs`: a dudect-style Welch t-test on `CheckedSigner<ReferenceSigner>::blind_sign`, the production signing path, 10⁵ samples (`GHOST_TIMING_SAMPLES` overrides), one class a fixed blinded value and the other a fresh random value per sample, the classes interleaved in a seeded random order and the inputs drawn before the measurement; it fails when |t| > 4.5 on all samples or on those below the pooled 90th percentile (dudect's cropping of scheduler outliers). The statistic is unit-tested (`welch_t_separates_shifted_classes_and_not_equal_ones`, debug profile). The new workflow `signer-timing.yml` runs it nightly in the release profile and, on a failure, opens an issue (`issues: write`); it is not a gate and nothing requires it (§13.6 gains its row; §19.17 point 7 gains the file). ADR-22 point 7 and the RUSTSEC-2023-0071 reason in `deny.toml` now cite the evidence and state that `RefreshCredit` is bounded, not payment-gated (point 1). A local run of 3 000 samples on a loaded 16-thread host gave |t| = 0.80 (all samples) and 2.02 (cropped); the 10⁵-sample evidence comes from the nightly job.
3. **A repeated claim id refuses its entry, not the batch (MONEY-CLAIMID-1; corrects §9.5 step 2, extends §19.22 point 2).** The client draws the claim id and the issuer forgets it one week after the batch is acknowledged (`sweep_paid`), so a claim id paid in an earlier batch can come back with fresh credits; the workstation refused the whole batch (`claim-seen`), the batch could not be acknowledged, and up to 199 honest claims stayed `batched` with their credits spent, with no recovery. Now the workstation ledger records such an entry `refused` (never built or paid, not counted in `paid_so_far`), pays the rest, and `payout-ack` reports it refused, so the issuer closes it unpaid (its credits stay spent, Q26). A refused-for-its-claim entry's address was never paid, so it does not count as seen (`LedgerEntry::repeated_claim`): otherwise a claimant could burn someone else's address for 10 credits. On replay an entry is `refused` exactly when its claim is in an earlier batch or its address is repeated so; an unmarked one answers `claim-repeated`. A repeated `batch_id`, and one claim id twice in one batch (the issuer's claim table is keyed by it, so only a faulty issuer writes that), still refuse the batch. Tests: `ledger.rs` `a_claim_paid_in_an_earlier_batch_refuses_its_entry_and_the_batch_is_paid`, `payout_tools.rs` `a_claim_id_paid_in_an_earlier_batch_refuses_its_entry_and_the_batch_is_paid` (failing first on the old ledger: the batch was refused `claim-seen`); runbook P1 and ADR-26 point 6 follow.
4. **An ISSUED invoice is kept as long as a CONFIRMED-unissued one (MONEY-RESERVE-1; corrects the §5.4 purge row, the §6.4 invoice row and ADR-26 point 5).** The client's fifth and last `BlindSign` attempt is due 20–22 days after receipt (§19.11), but an ISSUED invoice was purged 5 040 blocks (≈ 7 days) after issuance, so a pack first signed at the attempt of days 7–8 (the issuer's wallet lagging, or earlier attempts failing transiently) whose answer was lost, or whose client crashed after the issuer committed `ISSUE`, was gone at the last attempt: `PERMISSION_DENIED`, and the client ended the paid pack `lost` (against MS-6). Now an ISSUED invoice is purged at `max(issued + 5 040, confirmed + 21 600)` blocks (`invoice::purge_due`), which covers the whole 22-day plan. The key bound of §19.1 rule 1 is unchanged: issuance precedes `confirmed + 21 600`, so an invoice still goes by `confirmed + 26 640` blocks, as before. The JVM `ModelIssuer` purges by the same rule. Tests: `custody_window.rs` `an_invoice_signed_a_week_after_confirmation_is_reserved_at_the_last_attempt` (failing first: `PERMISSION_DENIED` at the last attempt) and I-I updated (its keys now stay until `confirmed + 21 600`), `invoice::tests`. **Open:** the JVM harness mines blocks only when a payment happens, so no harness scenario lets the chain advance with wall time (the review's second test); the Rust test covers the rule.
5. **A `WRONG_PERIOD` re-prepare continues the purchase's attempt plan (P8-PRIV-1 and P8-PRIV-2; amends §5.3 and §19.23 point 2, whose caps now hold per purchase, trial or revocation, not per flow row).** `WRONG_PERIOD` records nothing at the issuer, so the engine closes the flow and starts a new one (a new id, claim key and seed, the base week of its first send; a credits pack's credits return to fresh and a covering set is chosen again; a trial or revocation keeps its invite token). **Rule (normative for the engine and the T2 reference client):** the new flow keeps the old one's lineage, its write-ahead attempt count and the retry time drawn at its first send, so a purchase makes at most `CALL_ATTEMPTS` (2) `RequestInvoice` calls, a revocation 2 `RedeemInvite` calls and an onboarding trial 40, whatever the answers; a `WRONG_PERIOD` at the cap fails the purchase (its credits released) or ends the revocation. Before, the engine started each re-prepared row at attempt 0 and due at once, so an issuer answering `WRONG_PERIOD` made a client re-present the same credits (a revocation its invite token) in new flows without bound (P8-PRIV-1; the Kotlin engine's `PurchaseSteps.rePrepare` and `TrialSteps` follow this rule), and no T2 check could see it: the world kept one flow instance, reset its count and retried a day later, J9 exempted base-week changes, T2c keyed on the instance, and no liar answered `WRONG_PERIOD`. **T2 (as implemented):**
   - The world re-prepares as the rule says: a new instance, seed and claim key, the old flow `Failed` and its credits back with the client; the ground truth's `IssuerTruth` gains `lineage` (the lineage's first instance).
   - J9 caps the calls per lineage (`j9_lineages`: `RequestInvoice` 2 per purchase, `RedeemInvite` 2 per revocation and 40 per onboarding trial), and every retry within one flow instance must be byte-identical (the base-week exemption is gone).
   - T2c counts a credit or invite token re-presented by a re-prepared flow of the same lineage as an exemption while the lineage has at most its cap of flows (reported on the T2c line) and refuses one beyond it; the Q28 release exemption also covers a credits flow that ended on `WRONG_PERIOD` (no invoice recorded), whose released credits the next credits pack presents.
   - A lying issuer mode answers a fraction of `RequestInvoice` and `RedeemInvite` calls `WRONG_PERIOD` by a PRF of the request bytes (`Config::liar_wrong_period`); mutant **M23** (`UnboundedRePrepare`: the re-prepared flow's count starts at zero and it is due at once) runs in that world at the small scale with p = 1/2 and is detected by J9 ("RequestInvoice calls in one purchase (cap 2)") and T2c ("beyond its cap"), while the control passes both (control: 75 re-presentations within their caps; mutant: J9 106 hits, T2c 10 hits).
   - Unit tests: `checks::tests::j9_caps_calls_per_lineage`, `t2c_counts_a_re_prepare_within_its_cap_and_refuses_one_beyond_it`.
   - The mutants are now 54 (25 privacy, 20 issuer and relay, 9 client); `t2-report-check.sh … mutants` requires 25. Effect on honest worlds: a device whose clock is off at a week boundary now fails a purchase after its second `WRONG_PERIOD` instead of retrying daily, which the world's population line absorbs (point 10).
6. **The newest snapshot is never deleted (OPS-B1-RETENTION-MAINT; amends §19.15 point 1, runbook B1 and §13).** The B1 deletion lines ran in maintenance windows, where `snapshot.sh` takes none while M2 keeps the issuer deciding transitions; after about 7 days of such a window `$H/snapshots` was empty, and the journal cannot stand in (its prefix was pruned after the last snapshot, so an empty database refuses the start with a gap): losing `issuer.redb` alone then gave the E28 outcome, which runbook §13 said could not happen. Both deletion lines now exclude the newest `issuer-*.redb` (`! -name "$(cd /srv/ghost-issuer/snapshots && ls -t issuer-*.redb 2>/dev/null | head -n 1)"`), so in a window longer than 7 days that snapshot outlives its retention by the window's length (restore safety first, as for the journal prune). **Declared residue E33** (LIMITE L6). Test: `infra_operations.rs` `snapshot_deletion_keeps_the_newest_snapshot` (failing first); the retention bound test is unchanged.
7. **J8 counts only refusals the client received (P8-J8-1; amends §19.24 point 2).** The open gate-scale J8 failure of CI run 34788951925 (client 447 at relay 2, two fresh week-3003 tokens refused 2 s apart) came from the world's own 5 % lost-answer fault: the relay answered `WRONG_PERIOD`, the answer was lost (`Err(Timeout)`, so no refusal, adoption or offset reached the client), and the client, as designed and as the Kotlin `RedeemLane` does, presented its next fresh token at that relay on its still uncorrected clock. §19.24 point 2 now reads: an uncorrected client is refused a period at most once per process start and relay, **counting the answers it received**, identical retries counted. `RelayTruth` gains `answer_lost` (set when the relay answered and the link lost it); `j8_of` skips those for the bound, and `j8_lost_refusals` reports them on the J8 line, so a relay that withholds its answer on purpose (AD-1) stays visible. Test: `checks::tests::j8_counts_only_refusals_the_client_received` (failing first with the CI hit's shape). The gate-scale run that confirms it on seed pair 0 is still to be recorded (§15.2).
8. **`issuer-output.sh` sees imports (GATE-ISSUER-OUTPUT-BRACE; §19.17 point 4).** The gate matched only qualified paths, so a brace-group import (`use std::fs::{read, write}`, `use std::io::{stdout as out}`), a multi-line group, a module rename (`use std::fs as f`) or a glob hid a write or console output from it. Every `use` declaration under std or tokio `fs`/`io`, joined across lines, is now checked: a group, glob or rename that brings in a writing `fs` function (or renames `fs`, `self` or `File`) is a file write, one that brings in `stdout`/`stderr` or globs `io` is console output, reported at the `use` line; read-only imports (`use std::fs::{self, File}`, `use std::io::{self, BufRead}`) pass. Fixture `negative-issuer-output/issuer/crates/service/src/scanner.rs` and seven new `self-test.sh` cases (five reported, two allowed; the old gate reported none of them).
9. **Bookkeeping.** LIMITE L6 holds E1–E34 (E33 point 6, E34 point 1). Documents: ADR-22 point 7 (point 1 and point 2), ADR-23 (M23), ADR-26 points 5–7 (points 3, 4, 6, 1 and 8), INVARIANTS T2 (M1–M23), `RUNBOOK.md` (§3 `REFRESH_REFUSED`, B1 cron and retention text, P1, §13), `deny.toml`, `t2-exit-gate.yml` (mutant names). The client-side rule of point 5 binds the `:entitlement` engine (P8-PRIV-1 is an Android finding of this review, fixed outside this Rust slice); the T2 world, J9 and T2c already hold the reference client to it, and the policy vectors do not cover it.
10. **State (local runs, 2026-09-14, on a shared 16-thread host).**
   - **T2 PR variant** (release, seed pair 0; 972 s with M23's worlds running on the same host): every check passes and `t2-report-check.sh … pr` is OK. Population 318 window packs for N = 300 (314 before point 5: skewed devices now fail a purchase at its cap instead of retrying daily); S1 p = 0.916 argmax and 0.820 Hungarian; S2 p = 0.067; S4 0.090, and 0.106 against the lying issuer; J8 0 hits, with 3 refusals whose answer never reached the client reported (point 7); J9 0 hits; T2c 0 hits, with 3 re-presentations by a re-prepare within its cap (point 5); E30: 74 065 background sessions, 26 282 armed, 7 115 held past their lanes (median 15 s, 90th percentile 27 s, maximum 41 s), 3 408 unarmed sessions ended before their step; NI-2 and NI-3 each moved 3 reads by an hour or more; NI-1d 9 drop writes identical.
   - **M23** (small scale, liar p = 1/2; 431 s): detected by J9 and T2c, its control passing both (point 5).
   - **Issuer and ops suites:** `refresh.rs`, `custody_window.rs`, `status_vocabulary.rs`, `infra_operations.rs`, `invoice::tests`, the ops ledger tests and `payout_tools.rs` pass; each new test failed first on the old code. Point 4 also changed two tests that had pinned the old purge: `negative.rs` `retention_spent_credits_keep_no_invoice_or_claim_reference` (now mines 21 600 blocks) and regtest step 18 (`monero_regtest.rs`, now mines 21 601 blocks; run by `monero-regtest`, not locally).
   - **T2 mutants:** 25 of 25 detected (1 130 s); `t2-report-check.sh … mutants` is OK.
   - **Gates:** `rust-gates.sh` (fmt, clippy, workspace tests, the release crash suite, cargo-deny, the policy gates), `run-all.sh` and `GHOST_SELFTEST_OPS=1 self-test.sh` pass; `ModelIssuerConformanceTest` passes with the new purge rule.
   - **Not run:** a gate-scale T2 run (N = 2 000, 84 days), which closes P8-J8-1 on seed pair 0 (§15.2), and the 10⁵-sample timing run on an idle host (the nightly job's).

### 19.28 Corrections after the S12 review, Android scope (normative)

The S12 review also confirmed six findings in the Android scope: P8-PRIV-1 (found again by a second lens as AND-P8-1), MONEY-CLAIM-2, AND-P8-2, AND-P8-3, AND-P8-4 and AND-P8-5. They are fixed in the `:entitlement`, `:sync` and `:app` modules (commit 46ae26c, merged into the Rust slice by 113d3c7); each fix was first shown by a failing JVM test.

1. **A `WRONG_PERIOD` re-prepare is the flow's retry (P8-PRIV-1, AND-P8-1; the engine side of §19.27 point 5).** `PurchaseSteps.rePrepare` inserts the new row with the old row's attempt count and pre-drawn retry time (`PurchaseStore.insert` takes the attempt), and `applyInvoice` and `TrialSteps` fail a flow whose cap is spent instead of re-preparing it. **Renewal back-off (new rule):** `QuietRunWork.renewalDue` is false while a credits pack that sent its `RequestInvoice` and failed is still kept (`terminal_day` + 7, §11.3), because the next automatic renewal would present the same credits; a stalling or `WRONG_PERIOD` issuer therefore gets at most the two capped calls of one renewal per week, not two per failed renewal. A purchase the user starts is not held back. The T2 world mirrors the back-off (`Purchase.failed_day`, integration commit after the merge); at the PR scale and in M23's lying world no credits pack fails and renews within 7 days, so no T2 run exercises it and the T2 numbers are unchanged. **Open:** T2c's Q28 release exemption counts a credit re-presented by a later credits pack after a flow that ended unanswered or on `WRONG_PERIOD` with no bound per week, so no T2 check would detect an engine without the back-off; the JVM test pins it. Tests: `PurchaseStepsTest` `wrongPeriodClosesTheFlowAndItsSuccessorIsTheFlowsOneRetry`, `anIssuerThatAlwaysAnswersWrongPeriodGetsAtMostTwoRequestInvoicesPerPack`, `aFailedAutoRenewalPresentsItsCreditsAgainOnlyAWeekLater`; `TrialStepsTest` `anIssuerThatAlwaysAnswersWrongPeriodGetsAtMostTwoRevocationCalls`, `anOnboardingTrialKeepsItsFortyAttemptsAcrossWrongPeriodAnswers`; harness scenario E-I follows the new retry timing.
2. **The payout address is used from its first send (MONEY-CLAIM-2; corrects the §11 Claim row and §9.4).** The salted address hash joins `ent_payout_used` in the write-ahead of every `ClaimPayout` send (`ClaimSteps.prepare`), not on `QUEUED`: a claim whose answers were all lost may still be queued and paid, and the workstation refuses a repeated address (E21). Test: `ClaimAndGcTest` `anAddressStaysUsedOnceAClaimCarryingItWasSentWhateverTheAnswers`.
3. **Drop coverage (AND-P8-5; §9.3, §19.12 point 1).** Coverage at `t_drop` is an ACCESS token of the week or a later week, fresh or reserved (`TokenStore.hasAccessFrom`), or a write capability, usable or exhausted, whose expiry reaches the end of the week (`SyncTables.writeCapabilityReaching`). A token leaves `ent_token` when redeemed, so the old test (an ACCESS row of the week) deleted the drop target of an identity that had redeemed them all, although it is active and not silent. The T2 world already wrote every invitee's drop at its time. Test: `DropStepsTest` `anIdentityThatRedeemedEveryTokenOfTheWeekIsCoveredAndWritesItsDrop`.
4. **`awaitIdle` waits for every callback thread (AND-P8-2; the Phase 7 `AndroidSyncController` contract).** `SyncRuntime` counts the participant threads of relay sessions and quiet runs and the threads of user issuer calls; `awaitIdle`, the wait of the wipe flow before it closes the database, returns only once they have returned; `awaitNoActivity` keeps the old meaning for tests. Test: `SessionParticipantTest` `awaitIdleWaitsForEveryParticipantAndUserCallThread`.
5. **The payment hold is restored on the runtime thread (AND-P8-3; §19.23 point 1).** The saved `payment_shown_minute` is read in the command's turn on the sync runtime thread (`restorePaymentHoldFrom`), before any job or foreground command, never in `Application.onCreate` (no Keystore, SQLCipher or migration work on the main thread). Tests: `SessionParticipantTest` `aRestoredHoldIsReadOnTheRuntimeThreadBeforeTheForegroundAfterIt`, `SyncWiringTest` `aProcessStartWithAKeyInstallsTheParticipantPostsTheHoldRestoreThenEnsuresTheJob`.
6. **The foreground hook of a pending onboarding trial runs with the stores open (AND-P8-4; §8.3 steps 4–5).** `EntitlementWiring.onVisible` runs the hook through `runWhenStoresOpen`, which opens the database for the foreground first (also under a payment hold) and starts no session, so the retry at a cold-start foreground no longer races the runtime's creation of the stores. Test: `SessionParticipantTest` `foregroundWorkRunsWithTheStoresOpenAlsoUnderAPaymentHold`.
7. **Policy vectors.** `entitlement_policy.txt` is unchanged, and `PolicyVectorsTest` (Kotlin) and `t2_policy_vectors` (Rust) replay it identically. None of these rules is a pure decision the file pins: the `work` operation pins `QuietRunWork.pick`, not `renewalDue`.
8. **Verification** of the merged tree: `docs/reviews/2026-09-14-faza8-review.md`.

### 19.29 Q31 simplified: one refresh time (normative)

The lead's decision of 2026-09-14, after the first gate-scale run of wave F (CI run 34807737126, on 63e7876) failed NI-2 (and J8, which §19.27 point 7 corrects). It replaces the two refresh times of §19.26 points 1, 7 and 16; §9.3, §11.3, §12.6 (E17), §17 (Q31) and §19.26 carry markers.

1. **What NI-2 showed.** At the gate scale the NI-2 twin moved 403 received-credit reads, 25 of them across their invite's first refresh time. Each such read moved one refresh by one pre-drawn time (the declared bit), and the change reached every client through shared issuer state: the world's scanner ticked lazily before client calls (a tick's time, and the confirmations the next calls saw, followed whoever called first), the issuer's sequential random invoice ids and the global subaddress pool order. For 7 inviters the moved refresh also moved the next automatic renewal between a credits pack and an XMR payment (the refreshed credit existed earlier or later), a real consequence of the bit, which the wallet view shows. The exemption of §19.26 point 7 compared a crossing inviter's issuer calls only before its horizon and covered neither those consequences nor the wallet view. Widening it would have turned the declared bit into a declared channel into the whole issuer state; the bit is removed instead.
2. **Rule (engine: `RefreshPlan.kt`, `DropSteps.kt`, `RestoreScan.kt`).** A drop has one refresh time, drawn from client randomness when the inviter registers the drop as listened (an invite it creates, §8.5, or a drop a restore scans, §8.4, at its install or extension): `at = ceil_minute(start(listen_until_day) + 1 d + u × 13 d)`, 1–14 days after the listening ends (the rule §19.26 point 16 gave a scanned drop, now every drop's). Nothing is taken from a drop from `listen_until_day` on (device day), also before GC closes the invite (§9.3), so every read precedes `at`. The due time of a received credit of credit epoch c is a function of `at`, the listening's end and c only (`RefreshPlan.due`; no read time enters), with `cut(c) = start(first week of c + 2) − 2 d` (§19.8, unchanged):
   - `at` when `at ≤ cut(c)`;
   - otherwise, when `cut(c)` lies at or after the listening's end, the same draw placed inside [listening end, cut]: `ceil_minute(end + ⌊(at − end − 1 d) × (cut − end) / 13 d⌋)`;
   - otherwise the credit is dropped and counted (`CREDIT_DROPPED`), whatever the read.

   The engine's epoch check moves from the read to the due time: a credit of an epoch after the due time's credit epoch is dropped (no credit the issuer signed is), and `c ≥ c_now(due) − 1` holds by the cut. Before, the check used the read's week.
3. **Why this variant for an empty window.** A read may come at any moment until the listening ends, so a due time before the end could precede a later read of the same blob: the credit would then be refreshed at the read (what Q31 excluded) or its refresh would depend on whether the read came first (the removed bit). Every candidate due time therefore lies at or after the listening's end, and when the issuer's refresh window closes before it no candidate exists: dropping is the only rule the read cannot move. Its condition, `cut(c) < end`, is a function of the credit's epoch and the invite. For an honest invitee c is at least the credit epoch of its base week, so `cut(c) ≥ start(base + 14) − 2 d`, while the listening ends at `expiry + 56 d`: a credit is dropped only when the invite expires more than about six weeks after the invitee's activation and the invitee's first pack falls in the last weeks of its credit epoch. Before, such a credit read before the cut was refreshed at the cut. A scanned drop's credit, whose pack can be older (its blob was written up to 30 days before the restore), meets the condition more often. Declared in E17.
4. **What the read still decides: nothing about the refresh**, neither its time nor whether it happens. Relays that withhold a drop blob until the listening ends suppress the credit, as any relay can drop a blob (E9); that is no timing. E17 keeps the refresh's linkability to the invitee who sent the credit and loses the bit. **Latency:** the refresh comes 8 weeks and 1–14 days after the invite's expiry (a scanned drop's 1–14 days after the scan ends), about a week later than the removed first time; credits are accepted for 52–65 weeks, so the inviter loses nothing but time.
5. **Schema v3 (amended in place, unreleased, as in §19.26 point 15).** `ent_invite.refresh_minute` stays (the one time); `late_refresh_minute` is removed (`Schema.kt`, §11.3, `InviteStore`, the storage tests). No other column changes.
6. **Vectors (same grammar).** `refresh listen_until=<time> uniforms=<u> -> <time>` and `refreshdue at=<time> listen_until=<time> epoch=<c> -> <time>|drop`, which takes no read: 4 and 8 lines, among them the time at the cut, a draw placed inside a 12-day and inside a one-day window, the cut at the listening's end, and two drops. `PolicyVectorsTest` replays them against `RefreshPlan.time` and `RefreshPlan.due`, `t2_policy_vectors.rs` against `policy::refresh_time` and `policy::refresh_due`.
7. **T2 (world and gate).** The world draws one time per invite; a blob read from the listening's last day on (the reader's device time) is not taken, as in `DropSteps.take`; a refresh flow is numbered by its drop (the order the client's invites were taken), never by the order its credits are read (the world derives a flow's circuit label from its number; a real client draws its `IssuerFlow` at random per call). NI-2 and NI-3 compare the issuer view (NI-2 masked) and the wallet view as a whole, with no exemption: the horizons of §19.26 point 7 are gone, and any difference of a credit's due time between the twins fails ("refresh due time follows the read"), a credit refreshed in one twin and dropped in the other included. The twins' relays hold every drop blob of a credit world A refreshed back by 2 h to 3 days, until at most six hours before the listening ends on the reader's clock, the blob expires or the world ends; `FLOOR_READS_MOVED` stays. A PASS line reads "issuer view (… calls) identical … and wallet view (… calls) identical, no exemption"; a failing one names the first differing wallet call (`Digests::wallet_seq`). `t2-report-check.sh` refuses an NI-2 or NI-3 PASS line without "no exemption" (fixture `exempt-twin.txt`, case in `self-test.sh`; the other fixtures' NI lines say it). M22 (`RefreshAtRead`) stays, detected by NI-2; the privacy mutants stay 25.
8. **The issuer's scanner on its own timer (world fidelity; amends §19.24 point 9).** The world's scanner ticked before a client's issuer call whenever the last tick was 60 s old or more, so the tick times, the confirmations a call saw and the wallet view's `get_height`, `get_address_count` and `get_transfers` calls followed other clients' calls. Now it ticks as production does (`server.rs`: every `scan_interval_seconds` = 30 s ± 10 s, §7.3): every tick due at or before an event, or before an issuer call inside one, runs first, each at its own time, so nothing a call sees depends on another client's call times. The jitter is a world constant, like the block schedule (`chain.rs`), so every twin shares the tick times: NI-1's chain jitter (a payment kept 120 s before its payer's next attempt) needs no change, and a restart (snapshot, restore) adds its start-up tick (the pool refill and one tick, `server.rs`) without moving the timer's phase. The pool refill still runs before every issuer call (its size is what the NI-1 twin varies). Cost: a tick is a write transaction over the invoice rows (§7.3); a world of the PR or small scale makes about 0.87 M ticks and a gate-scale world about 1.05 M (40-week warm-up included); locally each took 0.39 ms (the small smoke world ran 410 s instead of 73 s, with identical payments, packs and issuer calls); the CI jobs keep the world stores on `/dev/shm`.
9. **Tests failing first.** Kotlin, on the engine before this section: `DropStepsTest` `oneRefreshTimeAfterTheListeningAndTheReadDecidesNothing`, `aCreditWhoseRefreshWindowClosesBeforeTheListeningEndsIsDroppedWhateverTheRead` and `aTimeAfterTheCutIsPlacedInsideTheWindowWhateverTheRead` failed (the last at its fixture: the removed first time lay after the cut), and `PolicyVectorsTest` failed on the new vectors; `RefreshPlanTest` is new. Rust, on the comparison before this section: `gate::tests` `the_retired_declared_bit_fails_the_twins`, `an_issuer_difference_after_the_retired_horizon_fails` and `a_passing_twin_names_no_exemption` failed (`a_wallet_difference_fails_the_twins`, a guard, passed on both), and `t2_policy_vectors` failed on the new vectors. The tests of the two times are replaced (`theRefreshTimeIsDrawnWithTheInviteNeverAtTheRead`, `aCreditReceivedNearTheEndOfItsRefreshWindowIsRefreshedInsideIt`, `a_read_across_the_first_time_is_the_declared_bit`). Harness scenario E-G keeps its scripted refresh on day 12 (its invite row sets the time; the credit's epoch is current, so the time is due as set).
10. **Documents.** LIMITE L5 (the Q31 row) and L6 (E17: the bit removed, the dropped credit declared), ADR-23 (point 14, the Q31 row, the tests), ADR-24 (point 4), INVARIANTS T2 (NI-2 and NI-3 with identical issuer and wallet views and no Q31 exemption; the scanner's timer).

---

## Appendix A: ADR drafts (Romanian)

> # ADR-22 — Protocolul de entitlement: token Privacy Pass 0x0002, chei per (tip, epocă) în Programul de Entitlement semnat, implementare separată client/issuer
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-12 (aplicat în designul Fazei 8, `docs/design/faza8-issuer.md`) |
> | Sursă | Design Faza 8 (§2, §3, §14) |
> | Modifică | ADR-02 (precizează schema: RFC 9578 tip 0x0002 = RSABSSA-SHA384-PSS-Deterministic, RSA-2048; perioada de acces = săptămâna ISO); `issuer.proto` (fără `IssuerKeys`, `issuer_key_id`, `period_days`, `payment_uri`); ADR-19 (`IsolationScope::IssuerFlow`; trei crate-uri noi de workspace în biblioteca Android); `deny.toml` (motivul excepției RUSTSEC-2023-0071); `rust-feature-policy.sh`; poartă nouă `rust-crypto-pins.sh`; allowlist-ul Rust al clientului |
>
> ## Context
> Semnătura blind protejează doar octeții token-ului. Un issuer care poate alege cheia, perioada, prețul sau constantele pentru un singur client îl poate marca și regăsi la relay-uri (key tagging, RFC 9576 §6.2). Semnarea blind este exact operația cu cheia privată pe intrări alese de atacator, iar crate-ul `rsa` are o vulnerabilitate de timing fără versiune corectată (RUSTSEC-2023-0071). Biblioteca de referință `blind-rsa-signatures` 0.17.2 depinde de un `rsa` pre-release (0.10.0-rc.18) și de circa zece crate-uri noi.
>
> ## Decizie
> 1. **Token:** formatul Privacy Pass tip 0x0002 (354 octeți). Semnătura este RSABSSA-SHA384-PSS-Deterministic, RSA-2048, e = 65537.
> 2. **Provocarea** o construiește clientul. Pentru un token de acces, `origin_info` numește slotul unui relay din program, deci token-ul e valabil la un singur relay. `redemption_context` leagă tipul și epoca. Nullifier-ul este SHA-256(„ghost/v1/nullifier” ‖ primii 98 de octeți) și îl calculează fiecare verificator.
> 3. **Chei:** câte una pentru fiecare (tip, epocă): acces = săptămâna ISO, invitații = 4 săptămâni, credite = 13 săptămâni.
> 4. **Programul de Entitlement (ES):** conține cheile, dovezile lor, prețurile, constantele și tabela de sloturi; e semnat offline, doar se completează: cheile, prețurile și mulțimea numerelor de slot ale oricărei săptămâni deja acoperite nu se mai schimbă (deci structura unui pachet depinde doar de săptămâna de bază, iar `schedule_seq` nu se mai trimite issuer-ului); fiecare cheie apare o singură dată (id și modul distincte față de toate intrările și de cheile deja acceptate); adresa onion a unui slot se poate schimba doar într-o mutare de urgență (reziduu declarat). Acoperă cel puțin 26 de săptămâni, e inclus în biblioteca nativă reproductibilă și în configurația relay-urilor. **Nu există nicio cale de rețea pentru chei sau configurație.**
> 5. **Dovadă de bună formare:** fiecare cheie are 8 rădăcini e ale unor valori derivate prin hash, verificate de clienți și relay-uri. Chiar față de un issuer care și-a ales singur cheia, semnătura finală e unică, iar anonimatul (blindness) e perfect pentru un r uniform și computațional pentru r-ul derivat din sămânța fluxului (securitatea PRF a HMAC-SHA-256; sămânța se șterge la finalizare), care e cel folosit efectiv.
> 6. **Implementare separată:** clienții și relay-urile fac doar operații cu cheia publică, pe crate-uri deja aprobate (`sha2`, `num-bigint-dig`, `ring`), deci niciun crate extern nou nu intră în APK. Issuer-ul semnează printr-o trăsătură `Signer`; implicit `blind-rsa-signatures` =0.17.2, limitat la graful issuer-ului și fixat pe versiuni. Orice semnătură e verificată independent (`s'^e ≡ B`) înainte de răspuns; răspunsurile pleacă pe un cuantum de 2 s; se semnează doar pentru facturi plătite sau invitații valide. Rezerve: un semnătar propriu pe `crypto-bigint` 0.7.5, apoi `rsa` 0.9.10 hazmat.
> 7. **Blinding derivat dintr-o sămânță** de 32 de octeți per flux (HKDF per poziție), deci orice reîncercare trimite exact aceiași octeți.
> 8. **Porți:** `rust-feature-policy.sh` verifică `rsa` pe versiuni; `rust-crypto-pins.sh` fixează versiunile exacte per graf; motivul excepției din `deny.toml` și din `ci.yml` se rescrie (un semnătar blind întoarce oricum B^d, deci clasa de oracol de decriptare Marvin nu adaugă nimic; riscul rămas, recuperarea exponentului prin timing, e atenuat ca mai sus).
>
> ## Consecințe
> (+) Nu se pot aplica etichete prin cheie, preț, perioadă sau constante. APK-ul nu primește niciun crate extern nou. Reîncercările sunt identice prin construcție. O spargere viitoare a RSA-2048 nu leagă retroactiv token-urile de plăți.
> (−) Issuer-ul folosește un crate RSA pre-release (izolat și fixat). Un ES nou cere o versiune nouă a aplicației. ES crește cu circa 160 KiB pe an. Blinding-ul pe client nu e constant-time (risc doar față de un observator local, în AD-8).
>
> ## Alternative respinse
> `rsa` 0.9 ca semnătar implicit (Marvin; rămâne rezerva 2); `blind-rsa-signatures` în APK (crate pre-release plus circa zece crate-uri noi pe Android); OpenSSL (lanț C pe issuer); RSA parțial blind (nu e RFC); chei sau configurații primite de la issuer, inclusiv un `GetConfig` care acceptă versiuni mai noi (tagging per client).
>
> ## Teste
> Vectorii RFC 9474 Anexa A (cheie de 4096 de biți, prin funcțiile generice și direct prin `blind-rsa-signatures`, nu prin `Signer`-ul de producție, fixat la 2048 de biți) și RFC 9578 A.2 (2048 de biți, prin calea de producție și prin `Signer`); test diferențial cu `blind-rsa-signatures`; teste negative pe fiecare octet; ES alterat, revenit, cu cheie schimbată, cu aceeași cheie sub două intrări, cu mulțimea de sloturi sau prețul unei săptămâni acoperite schimbate, sau cu cheie care nu e permutare; T22; mutanții M2, M2b, M14, M15.

> # ADR-23 — Nelegabilitate issuer ↔ relay: reguli R1–R10, trial prin invitație, rulări liniștite, sloturi de activare, testul T2
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-12 (aplicat în designul Fazei 8) |
> | Sursă | Design Faza 8 (§1, §8, §11.6, §12, §13.4), R-privacy |
> | Modifică | Anexa A (fără Poll și IssuerKeys; URI construit de client; BlindSign cu structură fixă; token-uri folosibile de la un slot); ADR-05 (ce acordă răscumpărarea invitației); **ADR-20 punctul 1** (1/8 dintre rulările jobului periodic sunt „liniștite”) și API-ul `:sync` (`SessionParticipant`); ADR-02, consecințe (cumpărarea se încheie în fundal); INVARIANTS T2, T23; THREAT_MODEL §6; LIMITE (nou L6) |
>
> ## Context
> Sub AD-1 (operatorul are issuer-ul și relay-urile), după semnătura blind rămân legături de timp și de prezență: prima folosire după cumpărare, namespace-urile noi de identitate imediat după plată, apelurile către issuer care coincid cu sesiunile văzute de relay-uri, circuitele comune, graful invitațiilor.
>
> ## Decizie
> 1. **Non-interferență:** nimic din ce trimite issuer-ul nu ajunge la un relay; ce vede un relay depinde doar de aleatorul clientului, de ES și de starea relay-ului. Ceasul issuer-ului nu se folosește niciodată.
> 2. **Invitația acordă un trial:** `RedeemInvite` întoarce token-uri de acces blind pentru săptămâna curentă și cea următoare (8 per slot per săptămână), semnate cu cheile obișnuite. Onboarding-ul e finanțat de invitație, nu de o plată. Abuzul e mărginit la 40 % din utilizarea plătită.
> 3. **Rulări liniștite:** 1/8 dintre rulările jobului periodic sunt alese aleator, independent de cumpărări, și nu ating niciun relay. Toate apelurile automate către issuer au loc numai în ele, **cel mult un apel per rulare**, fiecare cu un scop de izolare Tor nou (`IssuerFlow`). Excepții declarate: răscumpărarea invitației la onboarding și butoanele opționale „factură acum” și „verifică acum” (numai în modul standard).
> 4. **Sloturi de activare:** token-urile unui pachet devin folosibile la prima graniță de zi UTC aflată la cel puțin 4 ore după emitere, plus U[0, 6 h); în high-privacy mode se adaugă zile distribuite geometric. Reînnoirile se răscumpără la momente PRF per pereche, în ultima zi a săptămânii.
> 5. **Produs unic, cantități fixe, preț public;** acoperirea se termină la o graniță de săptămână comună; săptămâna de bază o alege clientul, issuer-ul doar o validează.
> 6. **Reîncercări identice; două ceasuri:** deciziile către issuer (săptămâna de bază, momentele apelurilor) folosesc doar ceasul dispozitivului (cu verificarea de încredere), niciodată timpul trimis de relay-uri, iar issuer-ul acceptă ±4 ore la granița de săptămână; ceasul corectat de relay-uri (mediana a cel puțin două) servește doar deciziile către relay-uri, cu gardă de ±1 oră. Secretele cumpărării se șterg la finalizare.
> 7. **`SessionParticipant`:** modulul de entitlement folosește singurul transport Tor al procesului prin `:sync`; nu blochează și nu amână niciodată evenimentele de citire (T19). Decizia „rulare liniștită” stă într-o componentă JVM pură (`QuietRunScheduler`) cu aleator injectat, fără nicio intrare din starea de entitlement, folosită și de producție și de testele NI-K.
> 8. **Plafonul de apeluri per factură:** cel mult 5 apeluri `BlindSign` per factură (3 planificate, 2 lente), la momente trase la primirea facturii, oricare ar fi răspunsurile issuer-ului; apoi cumpărarea e pierdută.
> 9. **Plata:** ecranul de plată închide sesiunea cu relay-urile și nu permite alta 20–60 de minute; `PAYMENT_READY` nu e o notificare imediată; UI-ul recomandă plata de pe alt dispozitiv. Scrierea în drop-ul celui care invită are loc o singură dată, la un moment tras la activare (săptămânile 3–7), cu creditul sau cu un blob fals, independent de cumpărări.
> 10. **Decizii după implementare (Q29, Q30; design §19.23 punctul 5):** o sesiune de fundal care pornește, cât un participant e instalat, cu o nevoie de scriere în așteptare (orice motiv) rămâne deschisă după ce benzile ei s-au încheiat, până la primul pas al benzii de răscumpărare (`RelayRedeemAccess.stepDone()`, API nou în `:sync`), la termenul jobului sau la o oprire (prim-plan, ecranul de plată, onStopJob, ștergere); decizia (`RedeemHold`) are ca intrări doar numărul nevoilor de scriere citit la pornirea sesiunii și termenul, iar o sesiune al cărei transport a eșuat nu se ține. Zilele suplimentare ale slotului unui trial în high-privacy mode se opresc la ultima zi a săptămânii base + 1, niciodată sub 0.
>
> ## Consecințe
> (+) Plata nu mai precede apariția unei identități noi. Relay-urile nu văd clientul online când acesta vorbește cu issuer-ul. T2 devine verificabil exact (NI-1, NI-2, NI-K, J9) și statistic (S1–S3).
> (−) Factura sosește la următoarea rulare liniștită (în medie ~2 ore), token-urile de obicei la ~2 zile după plată (planul fix de încercări); în fundal se sincronizează cu 1/8 mai rar. Rămân reziduurile declarate E1–E19 (LIMITE L6), inclusiv golurile rulărilor liniștite (≤ 3 biți per apel, cumulat per factură, cel mult 6 apeluri) și momentul plății (E15). T2 verifică și o limită absolută (S4) pentru ce permite scurgerea declarată. Reținerea pentru răscumpărare lungește o sesiune de fundal cât o nevoie de scriere așteaptă, iar gărzile Tor și relay-urile cu circuite deschise văd lungimea ei (E30). Plafonul trialului reduce estomparea E1 pentru un trial finalizat târziu în base + 1, iar un issuer care întârzie `RedeemInvite` poate provoca plafonul (E8 × E1; plafonul cel mult dublează șansa ultimei zile).
>
> ## Alternative respinse
> Apeluri în sesiunile cu relay-uri (co-prezență, ~3–5 biți per apel); token-uri de pornire incluse în invitație (invitația nu mai încape într-un cod QR); invitația doar ca poartă de activare (păstrează legătura plată → identitate nouă); pachet de pornire de 2 săptămâni × 96 de token-uri (abuz nemărginit, ~+150 %).
>
> ## Teste
> T2 (J1–J10, T2b, T2c, NI-1, NI-1d, NI-2, NI-3, NI-K, S1–S4, mutanții M1–M21); T23; `SessionParticipantTest`; vectorii `entitlement_policy.txt`.

> # ADR-24 — Referral prin token-uri blind de credit; Invitație v2 cu cheie per invitație și „drop”
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-12 (aplicat în designul Fazei 8) |
> | Sursă | Design Faza 8 (§8, §9) |
> | Modifică | ADR-02 („Referral 10 %: creditat pe referral commitment la fiecare plată; revendicare prin preimagine”); ADR-05 (payload-ul invitației); **ADR-17** (suprafața BouncyCastle aprobată se extinde de la Ed25519 la X25519 și ChaCha20-Poly1305, pentru sigilarea drop-ului; HKDF rămâne pe platformă, `Hkdf.kt`; abaterea X15); Spec FR-6.7 și formularea FR-1.x; Anexa A (`referral_commitment`); THREAT_MODEL S2 (reziduul „factură ↔ commitment”); `DerivationLabels` (etichete noi; `REFERRAL_SECRET` retrasă și rezervată) |
>
> ## Context
> Un commitment de referral per identitate îi permite issuer-ului să grupeze toți invitații aceleiași persoane și devine un pseudonim de lungă durată. Cheia de invitație derivată o singură dată per identitate leagă între ele toate invitațiile aceluiași om. O adresă de plată pusă în linkul invitației ar fi văzută de oricine vede linkul.
>
> ## Decizie
> 1. **Credit:** fiecare pachet plătit integral în XMR primește exact un token blind de credit, în valoare de 10 % din prețul pachetului. Un pachet plătit cu credite nu primește credit.
> 2. **Livrare:** un client invitat trimite creditul **primului** său pachet plătit în XMR, sigilat (X25519 + HKDF + ChaCha20-Poly1305, 1 KiB), în namespace-ul „drop” al invitației, prin relay-uri. Celelalte credite rămân la plătitor, ca discount de 10 % (self-referral).
> 3. **Folosire:** un credit valorează 10 % din prețul epocii în care a fost emis și e acceptat 52–65 de săptămâni (5 epoci de credit); un pachet se plătește cu cel mai mic set de credite (cel puțin 10) a cărui valoare acoperă prețul curent. Opțional, creditele se schimbă pe XMR (`ClaimPayout`): subadresă nouă a utilizatorului, între 10 și 50 de credite, suma = valoarea fiecărui credit la prețul epocii sale, un destinatar per tranzacție, difuzare la moment aleator, semnare la rece (ADR-26). Un credit primit printr-un drop se schimbă întâi, singur, într-o rulare liniștită proprie, pe un credit blind nou (`RefreshCredit`), pentru că cel care l-a trimis îl cunoaște. Issuer-ul nu primește niciun identificator de referral.
> 4. **Invitație v2 (538 de octeți, 876 de caractere, un cod QR versiunea 21-L):** token de invitație real; nonce; expirare la zi; drop (namespace, 3 sloturi, cheie X25519); cheie de semnare per invitație; semnătură. Cheile se derivă din seed cu indexul invitației. Versiunea 1 e refuzată. Linkul nu conține nicio adresă de plată.
>
> ## Consecințe
> (+) Plafonul de 10 % rămâne prin construcție. Issuer-ul nu mai cunoaște graful invitațiilor.
> (−) Cel care invită e recompensat o singură dată per invitat, nu la fiecare plată, și doar dacă primul pachet XMR al invitatului precede momentul tras al drop-ului. Relay-urile văd o muchie „scrie o dată ↔ listează”, ca la orice DM (LIMITE L2.1 și L6 E9). Apelul `RefreshCredit` e legabil de invitatul care a trimis creditul (E17). Creditele trimise în drop-uri cu index peste 7 se pierd la restaurare. Plata în XMR aduce riscurile EAE și Janus (avertismente; implicit se folosește discountul, accesibil nu mai târziu decât plata).
>
> ## Alternativă de rezervă
> Commitment-uri per invitație, creditate doar la prima plată și revendicate separat (varianta A).
>
> ## Teste
> T16 extins; vectori de derivare și de sigilare; plafonul (MS-4, mutanții MM11 și MM20, reconciliere peste o schimbare de preț); T2c cu invitați Sybil și mutanții M10, M21.

> # ADR-25 — Răscumpărarea la relay: `RedeemToken`, capabilitate v2 cu serial determinist, nullifier-e persistate cu etichetă de legare, capabilități de citire partajate
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-12 (aplicat în designul Fazei 8) |
> | Sursă | Design Faza 8 (§10) |
> | Modifică | ADR-11 și ADR-02 („nullifier set în memorie”, „doar perioada curentă”); addendum-ul ADR-19 (format nou de capabilitate); `allowed-observables.json` (rezultatele `rejected_token`, `rejected_period`); LIMITE L2.1 #2 (decizia despre capabilitățile de citire) |
>
> ## Decizie
> 1. **RPC nou** `RedeemToken(token, namespace_id, request_id)`. Ordinea verificării: lungimi; cheia ES a săptămânii și slotul relay-ului în acea săptămână; fereastra [început − 24 h, sfârșit + 1 h); provocarea pentru slotul propriu; semnătura (verificată cu `ring`); nullifier-ul. Rezultatele `OK`, `REPLAYED`, `WRONG_PERIOD` sunt în răspuns, împreună cu `relay_period_id` și `relay_minute`.
> 2. **Nullifier-ele** se scriu în `nullifiers.redb` ca (perioadă ‖ nullifier) → etichetă de 16 octeți = HMAC(cheia relay-ului, etichetă ‖ perioadă ‖ nullifier ‖ tip ‖ namespace), cu commit înainte de emiterea capabilității. Cel mult două săptămâni sunt păstrate simultan. O perioadă ștearsă e marcată închisă printr-un prag persistat care nu scade niciodată, deci un ceas dat înapoi nu o redeschide; după pierderea fișierului (`--nullifiers-reset`) relay-ul refuză singur perioadele care erau deschise în momentul pierderii. Relay-ul își citește adresa onion din fișierul `hostname` al Tor (`--onion-hostname-file`).
> 3. **Capabilitate de scriere v2 (98 de octeți)** cu serial determinist = HMAC(cheia relay-ului, „ghost/v1/cap-serial” ‖ perioadă ‖ nullifier)[0..16]: fiecare token are propria cotă, iar o cerere repetată identic primește aceeași capabilitate, **și după repornire**. Cota: 256 MiB; expirarea: sfârșitul săptămânii + 1 oră, aceeași pentru toți.
> 4. **T1:** evenimentul de redeem emite `nullifier` și `period_id` (deja permise); rezultatele noi `rejected_token` și `rejected_period`.
> 5. **Citirea:** token-urile nu cumpără capabilități de citire. Ținta sunt chei de citire partajate per (namespace, epocă), înregistrate la relay prin hash (`RegisterReadKey`), implementate în Fazele 9 și 10. Până atunci, citirea se face cu capabilitatea de scriere.
>
> ## Consecințe
> (+) Nicio reutilizare după o repornire; nicio dublă cheltuire între relay-uri; scriitorii aceluiași namespace nu împart cota; relay-ul nu mai poate separa cititorii unui namespace din Faza 9.
> (−) Pe discul relay-ului rămân valori aleatoare și etichete, din care se vede doar numărul de răscumpărări pe săptămână; cu cheia relay-ului confiscată, o etichetă leagă un nullifier de un namespace timp de cel mult două săptămâni (E13). Ledger-ul de cotă rămâne în memorie (o depășire posibilă per repornire). Un `nullifiers.redb` nu se restaurează niciodată dintr-un backup vechi (runbook O1).
>
> ## Alternative respinse
> Nullifier-e doar în memorie, cu refuzul răscumpărărilor o perioadă după repornire (nu oprește reutilizarea token-urilor răscumpărate înainte; disponibilitate mică); persistare în `blobs.redb` (migrare de schemă pentru blob-uri); emitere deterministă fără serial (scriitorii împart cota).
>
> ## Teste
> Teste negative pe relay (reutilizare, inclusiv după repornire, expirat, falsificat, perioadă greșită, slot greșit, tip greșit); `redeem.txt` rulat de relay-ul Rust și de modelul Kotlin; T1 cu redeem; mutanții MM13, MM14.

> # ADR-26 — Operarea issuer-ului: Monero view-only, jurnal de emitere, custodia cheilor, plăți de referral cu semnare la rece, fără jurnalizare, job CI regtest automat
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-12 (aplicat în designul Fazei 8) |
> | Sursă | Design Faza 8 (§6, §7, §9.5, §13.3), R-monero |
> | Modifică | ADR-02 (detalii de operare); planul §6.2 rândul 8 (jobul Monero rulează automat); `deny.toml` (crate nou `md-5`, doar pe issuer) |
>
> ## Decizie
> 1. **Portofel:** `monero-wallet-rpc` v0.18.5.1 fixat prin SHA-256, doar cu cheia de vizualizare; `--wallet-file`, autentificare digest (`md-5`), în namespace-ul de rețea al issuer-ului, fără `--restricted-rpc`; `monerod` propriu, cu p2p prin Tor.
> 2. **Facturi:** subadrese create dinainte într-un pool validat local, deci `RequestInvoice` nu așteaptă portofelul; scanner fără stare, care recalculează fiecare factură deschisă la fiecare pas; plata se creditează numai la cel puțin 10 confirmări, cu `unlock_time = 0` și fără `double_spend_seen`; termenele se țin în înălțimi de bloc (720 ≈ 24 h pentru plată, plus 2 160 ≈ 72 h); expirarea se decide numai dintr-o vedere sincronizată; fără rambursări; plata incompletă se completează la aceeași subadresă; surplusul se păstrează.
> 3. **Jurnal de emitere** `issued.journal`: se scrie numai rezultatul decis. În tranzacția redb de scriere (un singur scriitor), după reverificarea stării, intrarea (factură nouă, emitere, nullifier de invitație, set de credite, revendicare, reîmprospătare de credit, lot) se adaugă cu fsync, apoi urmează commit-ul. Fiecare intrare are sumă de control SHA-256. Restaurarea = instantaneu + jurnal + golirea pool-ului de subadrese; astfel o restaurare nu permite nici dublă emitere, nici dublă cheltuire, nici refolosirea unei subadrese, iar un perdant al unei curse nu e reluat niciodată.
> 4. **Custodia cheilor:** fișiere sigilate per (tip, epocă) (ChaCha20-Poly1305 din `ring`); issuer-ul ține în memorie cheile până la săptămâna curentă + 6 (încărcare la 2 săptămâni); cheia privată a unei epoci se distruge la sfârșitul epocii + 8 zile, dar nu înainte ca ultima factură deschisă care o folosește să fie ștearsă (cel mult sfârșitul epocii + 42 de zile). `RequestInvoice` refuză (temporar) dacă lipsește vreo cheie a pachetului.
> 5. **Retenție:** facturile se șterg la 7 zile după emitere sau expirare (cele confirmate și neemise la 30 de zile, numărate); jurnalul ≈ 7–14 zile; instantaneele orare 48 de ore, cele zilnice 7 zile; nicio coloană de timp mai fină decât săptămâna; doar agregate săptămânale 400 de zile, verificate independent de portofelul de vizualizare al stației operatorului și de numărătorile relay-urilor (suma pe toate sloturile, per săptămână).
> 6. **Plăți de referral:** un lot semnat Ed25519 e verificat pe stația operatorului (plafon **cumulat** de 10 % din tot ce a primit propriul portofel de vizualizare; adrese; niciun lot sau revendicare procesate de două ori); tranzacțiile se construiesc acolo una după alta (următoarea abia după trimiterea celei anterioare, ca să nu folosească aceleași intrări), fiecare cu stare proprie și confirmare proprie, se semnează pe portofelul offline, câte un destinatar per tranzacție, difuzate prin Tor la momente aleatoare. Cheia de cheltuire nu e niciodată online.
> 7. **Fără jurnalizare:** serviciul issuer nu scrie nicio linie de jurnal (poarta `no-logging` interzice și `tracing`/`log`; poarta nouă `issuer-output.sh`). Operatorul primește doar `status.json`, cu vocabular fix. Uneltele de operare (`ghost-issuer-ops`) scriu pe ecran doar prin modulul `report.rs`, cu vocabular fix, și doar fișierele lor numite.
> 8. **CI:** jobul `monero-regtest` (monerod regtest offline, 3 wallet-rpc, binare fixate prin hash) rulează automat la modificările issuer-ului și noaptea, într-un fișier de workflow separat; T2 și suitele de crash rulează în profilul optimizat.
>
> ## Consecințe
> (+) Pierderile posibile sunt mărginite și detectabile; comportamentul Monero e testat pe binarele care ajung în producție; o restaurare nu redeschide dubla emitere.
> (−) Operatorul are pași manuali: încărcarea cheilor la 2 săptămâni, plățile săptămânal, ceremonia trimestrial. La hard fork-ul FCMP++ trebuie reverificate portofelul view-only și semnarea la rece (runbook M2). Istoricul portofelului de vizualizare rămâne inerent (AD-3; inclus în vederea issuer-ului din T2).
>
> ## Teste
> Scenariul regtest (18 pași, plus 16b și 17b); scenariile de crash I-A…I-M cu `FaultyStore`, `FaultyRail`, `FaultyJournal`, inclusiv curse urmate de repornire sau restaurare; mutanții MM1–MM20; reconcilierea.

---

## Appendix B: Text changes in other documents (Romanian; applied in S11)

**`ghost/test-harness/privacy/INVARIANTS.md`**

- **T2:** „Jurnalul issuer-ului și vederile relay-urilor nu au nicio cheie de join și nicio corelație peste scurgerea declarată L (L1–L7) | test de integrare Rust: issuer real (redb + `issued.journal`), 3 relay-uri reale adversariale (AD-1), clienți de referință pe criptografia de producție, o perioadă de încălzire de 40 de săptămâni, 2 000 de pachete plătite, 700 de trialuri, invitați Sybil, 84 de zile virtuale; export complet (cereri, răspunsuri, momente exacte, circuite, instantanee DB, jurnal, istoricul portofelului de vizualizare cu momentul primei apariții a plății); căutare deterministă J1–J10 (inclusiv plafonul de 5 încercări `BlindSign` per factură), T2b, T2c; lumi gemene NI-1, NI-1d, NI-2, NI-3 (sistemul complet) și NI-K (motorul Kotlin real); S1 (McNemar exact), S2 (MI max-T, 999 permutări pe straturi), S3 (prezență, inclusiv la plată), α = 0,001, și limita absolută S4; mutanții M1–M21 detectați | **Faza 8** | `issuer/crates/service/tests/t2_unlinkability.rs`, `test-harness/privacy/t2-join/`, testele `android/entitlement`”.
- **T16**, se adaugă: „Invitația v2 (token real, cheie de semnare per invitație, drop, fără adresă de plată) e verificată offline pe ES; issuer-ul acceptă o singură răscumpărare per nullifier; o invitație arsă sau rejucată e refuzată, iar activarea eșuează fără să rămână vreo identitate | Faza 3/8”.
- **T22 (nou):** „Clientul și relay-urile acceptă exact o cheie per (tip, epocă), din ES-ul semnat și cu dovada de permutare validă; nicio cheie nu apare sub două intrări; o cheie, un preț sau mulțimea de sloturi a unei săptămâni deja acoperite nu se mai poate schimba | teste pe ES (alterare, revenire, cheie schimbată sau dublată, slot sau preț schimbat, cheie care nu e permutare), `entitlement-schedule.sh` față de versiunea anterioară, J7, J10 | Faza 8 | `ghost-entitlement`, `android/storage` (`ent_key`, `ent_schedule_fact`), relay (`es_keys`), issuer (`es_memory`)”.
- **T23 (nou):** „Fiecare flux către issuer are propriul scop de izolare; apelurile automate către issuer au loc numai în rulări liniștite, cel mult unul per rulare; niciun apel către issuer în timpul unei sesiuni cu relay-uri, în afara excepțiilor declarate; vederea relay-urilor nu depinde de intrările issuer-ului | J6, J9, S3a, NI-1, NI-K, `SessionParticipantTest`, `live-tor` (manual) | Faza 8 | `client-core/net`, `android/sync`, `android/entitlement`”.

**`ghost/test-harness/privacy/allowed-observables.json`:** `result.values` += `"rejected_token"`, `"rejected_period"` (ADR-25).

**`docs/THREAT_MODEL_v2.1.md`**

- §6, „Cumpărare abonament”, coloana Issuer: „subadresă, sumă, înălțimi, istoricul portofelului de vizualizare, momentul fiecărui apel (în rulări liniștite), numărul fix de token-uri, tipul plății”; se șterge „commitment referral”; Test: „T2, T22, T23”.
- §6, „Redeem token la relay”: „nullifier, perioadă (săptămână), namespace, moment, hash-ul capabilității emise; token-ul e legat de slotul relay-ului; nullifier-ele persistate cu etichetă de legare cel mult două săptămâni” | T1, T2.
- §6, „Invitație acceptată”, coloana Issuer: „nullifier-ul invitației, momentul, un trial; nicio legătură cu factura celui care invită” | T16, T2.
- §6, rânduri noi: „Revendicare credit”: Issuer — „numărul de credite, adresa de plată, momentul”; Relay — „—”. „Livrare credit (drop)”: Relay — „un blob de 1 KiB într-un namespace nou, listat de alt client”.
- **S2:** reziduul devine „token-uri de acces falsificate pentru cel mult 6 săptămâni înainte; invitații și credite falsificate sub cheile epocilor curente până când runbook-ul I1 revocă acele epoci la issuer (imediat); creditele și invitațiile oneste nefolosite ale epocilor revocate se pierd; issuer-ul nu mai are commitment-uri de referral; reconciliere independentă prin portofelul de vizualizare al stației operatorului (plafon cumulat) și numărătorile relay-urilor (suma pe sloturi, per săptămână)”.
- **R-14:** „pierdere financiară per perioadă; confidențialitate: atacuri active de tip n−1 și de prezență (LIMITE L6); niciun key tagging datorită ES fixat”.
- §5, rândul „Token-uri de acces/invitație”: generare „ceremonie offline, per (tip, epocă), cu dovadă de permutare”; rotire „săptămânal (acces), 4 săptămâni (invitații), 13 săptămâni (credite)”; revocare „listă în ES; nullifier la relay și issuer”.

**`docs/LIMITE_REZIDUALE_SI_MITIGARI.md`**

- Secțiune nouă **L6. Entitlement (Faza 8)**:

  | ID | Reziduu | De ce rămâne | Atenuare |
  |---|---|---|---|
  | E1 | Ziua slotului de activare al primei folosiri a unui pachet | slotul estompează, nu elimină, legătura cumpărare → prima folosire pentru reluări și genesis | sloturi; zile suplimentare în high-privacy; reînnoirile cumpărate din timp nu dau semnal; invitații: trial și scrierea în drop la un moment tras la activare. Trialul în high-privacy mode: zilele suplimentare se opresc la ultima zi a săptămânii base + 1 (Q30), deci un trial finalizat târziu în base + 1 are mai puțină estompare, deloc pentru o finalizare între vineri 20:00 și sâmbătă 20:00 UTC (prima folosire: duminică 00:00 + U[0, 6 h)); un issuer care răspunde `RedeemInvite` cu eșecuri trecătoare până la un prim-plan târziu (cel mult 40 de încercări) poate provoca plafonul (E8 × E1); plafonul cel mult dublează șansa ultimei zile, iar fără el aceeași masă făcea trialul nefolosibil |
  | E2 | Săptămâna de sfârșit a acoperirii | partiție prin design | un singur produs |
  | E3 | Apelurile imediate cerute de utilizator și începutul trialului | utilizatorul a cerut viteză; onboarding-ul cere un apel | butoane opționale, ascunse în high-privacy |
  | E4 | Tipul cumpărării (XMR, credite, trial) | issuer-ul trebuie să știe cum s-a plătit | — |
  | E5 | Golurile rulărilor liniștite, cumulate per factură | un apel către issuer trebuie să aibă loc cândva; apelurile unei facturi sunt legate prin `invoice_id` | q = 1/8, extrageri independente; ≤ 3 biți per apel; de obicei 2 apeluri, niciodată peste 6; măsurat în raportul T2 și mărginit de S4 |
  | E6 | Onboarding-ul genesis e legabil la volumul alpha | seturi mici (2 activări pe zi, slot zilnic: set așteptat 3, singur 13,5 %) | genesis e doar pentru bootstrap |
  | E7 | Plata de la un exchange cu KYC leagă o persoană de o factură | în afara GHOST | avertisment FR-6.8 |
  | E8 | Un issuer activ poate refuza sau întârzia serviciul pentru a izola un client (n−1) | controlează serviciul | rulări liniștite; cel mult 5 încercări `BlindSign` per factură, la momente trase dinainte |
  | E9 | Relay-urile văd muchia drop (scriitor → cititor), ca la orice DM | livrare prin relay | chei de citire partajate din Faza 9 |
  | E10 | EAE și Janus la plata referral-ului în XMR | Monero | discount implicit; avertismente |
  | E11 | Token-urile și creditele nu se recuperează din seed; drop-urile peste indexul 7 se pierd la restaurare | valoarea la purtător e locală | anunțat în UI; recuperare din seed ca P1 |
  | E12 | Reorg după emitere; token-urile epocilor revocate după compromiterea issuer-ului | token-urile blind nu se pot retrage sau reemite | contoare; RPC de schimb în Faza 15 |
  | E13 | Un relay confiscat împreună cu cheia sa leagă nullifier-e de namespace-uri cel mult două săptămâni | răscumpărarea idempotentă cere legătura | nullifier-ele rămân nelegabile de plăți |
  | E14 | Un client cu ceasul dispozitivului decalat cu peste 4 h primește `WRONG_PERIOD` și își dezvăluie decalajul issuer-ului; relay-urile nu pot provoca asta | timpul pentru issuer trebuie să vină dintr-o sursă pe care operatorul nu o controlează | ceas de încredere; toleranța de ±4 h a issuer-ului; verificarea opțională față de consensul Tor; nimic înregistrat la `WRONG_PERIOD` |
  | E15 | Momentul plății: portofelul operatorului vede plata în câteva secunde sau minute; dacă GHOST are atunci o sesiune cu relay-urile, momentul plății îngustează grupul de clienți (≈ 5 biți) | utilizatorul plătește dintr-un portofel extern, adesea pe același telefon | ecranul de plată închide sesiunea cu relay-urile 20–60 de minute; `PAYMENT_READY` nu e notificare imediată; recomandarea de a plăti de pe alt dispozitiv |
  | E16 | Cumpărarea declanșată de epuizarea token-urilor: relay-urile văd epuizarea, issuer-ul vede factura câteva ore mai târziu | declanșatorul e vizibil la relay-uri | semnalul apare la un moment aleator în 12 h, factura se cere după încă U[0, 24 h] |
  | E17 | Reîmprospătarea unui credit primit e legabilă de invitatul care l-a trimis (sau de operatorul care se dă drept invitat) | invitatul a finalizat creditul | apel singur, în rulare liniștită proprie, la 1–14 zile după primire; creditul nou e blind |
  | E18 | Mutarea de urgență a unui slot pe o altă adresă onion împarte clienții după versiunea ES | un relay pierdut nu se poate înlocui în versiunile vechi | doar după 48 h de indisponibilitate; sloturile, prețurile și cheile nu se schimbă |
  | E19 | Pe un dispozitiv confiscat, `eligible_minute` al unui token nefolosit arată ziua finalizării lotului, până la 5 săptămâni | eligibilitatea se verifică local | declarat în L1.1 |
  | E30 | Durata reținerii pentru răscumpărare (Q29): o sesiune de fundal pornită cu o nevoie de scriere în așteptare rămâne deschisă după benzile ei până la primul pas al benzii de răscumpărare (READY + U[0, 30 s] plus pasul) sau până la termenul jobului; garda Tor și rețeaua locală văd o conexiune mai lungă, iar un relay al cărui circuit a rămas deschis îl vede închis mai târziu; asta arată că exista o nevoie de scriere la pornire (lucru în outbox fără capabilitate, o capabilitate care expiră, epuizată sau refuzată), și când nu există niciun token eligibil | recuperarea fără deschiderea aplicației a unui client ale cărui capabilități au expirat cere o sesiune care trăiește mai mult decât sincronizarea ei | intrarea e doar numărul nevoilor de scriere de la pornirea sesiunii, niciodată starea issuer-ului sau numărul de token-uri (R1); niciodată după termenul jobului; se încheie imediat la prim-plan, la ecranul de plată (E15 neschimbat), la onStopJob și la ștergere; nu se ține când transportul a eșuat |

  plus tabelul seturilor de anonimat pentru onboarding-ul fără invitație (R-privacy §5).
- L2.1 #2, se adaugă: „Decizie în Faza 8 (ADR-25): capabilități de citire partajate per (namespace, epocă), înregistrate prin hash, implementate în Fazele 9 și 10; până atunci citirea folosește capabilitatea de scriere; token-urile nu cumpără capabilități de citire”.
- L1.1, rânduri noi (AD-8 cu baza de date deschisă): token-uri nefolosite (valoare la purtător, nelegabile de plată prin octeți, dar `eligible_minute` arată ziua finalizării lotului până la 5 săptămâni, E19); o cumpărare deschisă (factură, subadresă, ora creării: leagă dispozitivul de o plată **cât timp e deschisă**; la finalizare se șterg și ora creării, și minutul primirii facturii); indici de invitație; hash-uri sărate ale adreselor de plată.

**`docs/STATUS.md`:** rândul Fazei 8 la închidere (S12).

**READMEs:** `client-core/README.md` (`for_issuer`, nota la `relay_unavailable`, JNI nou); `android/sync/README.md` (`SessionParticipant`, rulări liniștite); `android/entitlement/README.md` (nou); `infra/issuer/RUNBOOK.md` (nou); documentația din `Invite.kt` (v2).

---

## Appendix C: R-code gaps G1–G29, where each is closed

| Gap | Closed by |
|---|---|
| G1 period mismatch (UTC days) | ISO weeks, acceptance window, week sweep (§3.4, §10.4) |
| G2 nullifier persistence | `nullifiers.redb` with binding tags (ADR-25) |
| G3 cross-relay double spend | slot-bound challenge (D2) |
| G4 quota ledger in memory | declared (ADR-25); week-aligned expiry bounds it |
| G5 redeem error mapping | in-band results; no new category (§5.7, §10.2) |
| G6 capture fields | §10.6 |
| G7 rsa / Marvin | split implementation; issuer-only pre-release `rsa`; gates rewritten together (§2.7, §14.1, ADR-22) |
| G8 issuer circuits | `IssuerFlow` per flow instance (§11.7) |
| G9 transport access | `SessionParticipant` leases on the one transport (§11.6) |
| G10 one listener slot | the redeem lane polls `needed()` (§11.6) |
| G11 `put` preconditions | the redeem JNI returns expiry and capability (§10.9) |
| G12 READ MISSING | D11 decision; interim write capability (§10.7) |
| G13 Invite v1 | Invite v2 (§8.2) |
| G14 referral and invite-key linkability | credit tokens; per-invite derivation (§8.4, §9) |
| G15, G16 v1 tables, pinned versions | schema v3 with guard; tests updated (§11.3) |
| G17 gate gaps | §14.1 |
| G18 proto-check, codegen | per-message check; `ghost-issuer-api` (§5.2) |
| G19 pinned vector grammar | separate `redeem.txt` (§10.8) |
| G20 `issuer.proto` gaps | the new schema (§5.2) |
| G21 Gradle T7 | no new Gradle coordinate |
| G22 secrets across JNI | only the seed and claim key cross; canaries (§11.8) |
| G23 anti-placeholder vocabulary | doubles in `tests/`, neutral names (`ChainPort`, `FaultyRail`) |
| G24 capture forbidden substrings | `origin_info` names a slot, never an onion; no free text in events (§2.2) |
| G25 constant error messages | §5.7, §10.2 |
| G26 `Relay::open`, `RelayConfig` | default `entitlement: None` (§10.5) |
| G27 the client library grows | three workspace crates only; allowlist and pin gates (§14) |
| G28 spec vs ADR-05 invite contents | ADR-05 followed, ADR-24 records the rest; §18 F4 |
| G29 issuer outage | offline verification; ES keys ≥ 26 weeks ahead (§6.10) |

---

## Appendix D: Evidence, verified vs assumed

**Verified in this session (2026-09-12, repository at `fa6a048`)**

- `scripts/gates/common.sh:27-31`: `rust_src_files` finds `*.rs` under `relay`, `issuer` and `client-core`, `-path '*/src/*'`, `-not -name main.rs`, so crates under `ghost/issuer/crates/*` are scanned and a top-level `ghost/crypto` or `ghost/entitlement` would not be (E-2).
- `client-core/net/src/categories.rs:9-28`: 20 category constants, including `not_found`, `unauthorized`, `rejected`, `quota`, `relay_unavailable`, `malformed_response` (G-3 needs no new one).
- `client-core/rust-dependency-allowlist.txt`: contains `curve25519-dalek` (58), `digest` (74), `ed25519-dalek` (82), `hkdf` (127), `hmac` (128), `keccak` (163), `num-bigint` (186), `num-bigint-dig` (187), `rand`, `rand_core`, `ring` (237), `rsa` (238), `sha2` (262), `sha3` (263), `subtle`, `x25519-dalek` (378), `zeroize`; no `crypto-bigint`.
- `test-harness/privacy/allowed-observables.json`: `op` includes `redeem`; `nullifier` hex 64; `period_id` hex 16; `result` ∈ {`ok`, `rejected_hash`, `rejected_capability`, `rejected_size`, `rejected_ttl`, `rejected_nullifier`, `not_found`}; `forbidden_substrings` include `.onion` and `monero:`.
- `INVARIANTS.md:8` (T2 wording, "Faza 8", `issuer/` tests) and `:22` (T16).
- ADR-02 text ("nullifier-e doar pentru perioada curentă"; "Referral 10 %: creditat pe referral commitment la fiecare plată; revendicare prin preimagine"); ADR-05 text (payload list; "Redeem la issuer: doar token + nullifier"); ADR-20 approved 2026-09-12; STATUS lists Phase 8 as next; ADR README ends at ADR-20.

**Verified by the research reports and the judge (cited, not re-run here)**

- R-code (at `fa6a048`): relay periods are UTC days with today + yesterday kept (`node/src/lib.rs:93-99,122-125`); `NullifierSet` and `QuotaLedger` in memory (`capability/src/lib.rs:121-189`); the capture `Event` lacks `nullifier`/`period_id` (`capture.rs:14-33`); `relay.proto` has no redeem (`:87-93`); `IsolationScope::Issuer` is a unit variant (`isolation.rs:14,26-37`); `TorTransportHolder` is internal to `:sync`; `CapabilityStore.needed()` semantics and the 24 h EXPIRING threshold (`CapabilityStore.kt:97-148`); Invite v1 185 bytes with a 32-byte token (`Invite.kt:10,29,64`); per-identity invite key and referral commitment (`KeyDerivation.kt:37,42-46`); unused v1 `entitlement`/`referral` tables (`Schema.kt:138-149`); the `rsa` gate (`rust-feature-policy.sh:88-97`), the `deny.toml:9-22` ignore and `ci.yml:80`; `ErrorPolicyTest` pins 21 categories; the vector op sets pinned at `semantics_vectors.rs:447` and `ModelRelayConformanceTest.kt:180`; lockfile versions `rsa` 0.9.10, `num-bigint-dig` 0.8.6, `crypto-bigint` 0.5.5, `ring` 0.17.14, `redb` 4.2.0, `sha3` 0.10.9, `curve25519-dalek` 4.1.3, `ed25519-dalek` 2.2.0, `hyper-util` 0.1.20, `http-body-util` 0.1.5; no `md-5`.
- Judge: `crypto-bigint` 0.7.5 (2026-06-22) is not yanked, 0.7.0–0.7.4 are; **the RFC 9474 Appendix A modulus is 4096-bit** (1 024 hex characters); RFC 9578 Appendix A.2 has 5 type-0x0002 vectors with 2048-bit keys; the `sync_namespace.consumer` CHECK allows `identity` (`Schema.kt:192`); `SyncEngine.clockTrusted()` exists (internal); `rust-feature-policy.sh` uses `-e normal,build` (dev edges excluded); `blind-rsa-signatures` 0.17.2's dependency list (`rsa ^0.10.0-rc.18` hazmat, `crypto-bigint ^0.7.3`, `crypto-primes =0.7.0`, `digest ^0.11.3`, `rand ^0.10.1`, `hmac-sha256`, `hmac-sha512`, `ct-codecs`, `derive-new`, `derive_more`).
- Delivery design (local registry): `rsa` 0.9.10 `hazmat::rsa_decrypt_and_check` blinds with an RNG and re-encrypts to check (`algorithms/rsa.rs:34-70,135-150`). RUSTSEC-2023-0071 lists no patched version.
- R-monero: v0.18.5.1, linux x64 tarball SHA-256 `22a7dda7b0cb699fdd6b7674c3b4a4465b337cc98a54983523b759e1e7cc9958` (84 575 716 bytes), `hashes.txt` signed by binaryFate `81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92` ("Good signature"); `--restricted-rpc` blocks `get_transfers`, `refresh`, `sign/describe/submit_transfer`, `import_key_images` (−7); `query_key view_key` has no watch-only guard; `monero-rpc` depends on the banned `reqwest`; digest auth is MD5 only; subaddress lookahead 50/200 and the restore hazard; regtest uses mainnet prefixes; `generateblocks` works only in regtest; coinbase unlock 60; the wallet handles reorgs up to 100 blocks; FCMP++ v0.19 betas list watch-only and cold wallets as not functional; address prefixes (mainnet 18/19/42, stagenet 24/25/36, testnet 53/54/63); Keccak-256 not SHA3-256; the cold-signing RPC sequence of `cold_signing.py`.
- R-privacy: the anonymity-set table for onboarding under slots; S1 power figures; Lysyanskaya (PKC 2023) on malicious keys.

**Assumed (checked in the named slice)**

| Assumption | Checked in |
|---|---|
| `blind-rsa-signatures` 0.17.2 exposes the Deterministic PSS-SHA384 variant, a raw `blind_sign` on a blinded message and key generation; its `crypto-bigint` path is constant-time | S1 (API), S12 (review) |
| The signer takes ≤ 5 ms per 2048-bit blind signature on the CI runner | S1 benchmark |
| `ring` 0.17.14 `RSA_PSS_2048_8192_SHA384` via `RsaPublicKeyComponents` verifies type-0x0002 tokens (sLen = 48) and 4096-bit RFC 9474 signatures | S1 vectors |
| `num-bigint-dig` 0.8.6 `modpow` and `ModInverse` suffice for blinding and proof verification | S1 |
| The permutation-proof soundness argument matches GRSB19 for prime e, including the trial-division and gcd side conditions | S12 review |
| QR version 21-L holds the 876-character link; phones scan it reliably | S8, device |
| Quiet runs under Doze behave as modelled; 1/8 fewer background syncs keep Phase 7 liveness | S9 harness, device |
| The added pairs (drops, own inbox on each slot) fit Phase 7 budgets | S9 harness |
| BouncyCastle 1.85.2 X25519 and ChaCha20-Poly1305 APIs as used for drop sealing (HKDF on the platform `Hkdf.kt`) | S8 vectors |
| A watch-only `transfer` reserves no inputs (inputs are marked spent only by `commit_tx`, reached through `submit_transfer`), so payout entries are built sequentially; whether `freeze` works on the workstation's watch-only wallet with imported key images | S6 regtest step 16b |
| `store-tx-info` can be disabled on the workstation's view wallet | S6 |
| Arti exposes the current consensus lifetime (valid-after, valid-until) to `client-core` for the optional `CLOCK_UNTRUSTED` check | S7 |
| The warm-up T2 world and four full worlds fit the 60-minute budget in the release profile | S10 measurement |
| wallet-rpc `get_address` count semantics used for startup reconciliation | S5, regtest step 17 |
| The Kotlin scheduler equals the reference policy beyond the shared vectors | NI-K covers R1/R6; full equivalence assumed |

---

## Appendix E: Sources

- RFC 9474 (RSA Blind Signatures), RFC 9576 (Privacy Pass architecture), RFC 9577 (HTTP authentication scheme, TokenChallenge), RFC 9578 (issuance protocols, type 0x0002): https://www.rfc-editor.org/rfc/rfc9474.html, …/rfc9576.html, …/rfc9577.html, …/rfc9578.html
- RUSTSEC-2023-0071: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
- crates.io: `rsa`, `blind-rsa-signatures` (0.17.2 and its dependency list), `crypto-bigint`, `md-5`
- A. Lysyanskaya, *Security Analysis of RSA-BSSA*, PKC 2023 (IACR ePrint 2022/895); S. Goldberg, L. Reyzin, O. Sagga, F. Baldimtsi, *Efficient Noninteractive Certification of RSA Moduli and Beyond*, ASIACRYPT 2019 (IACR ePrint 2018/057)
- Monero v0.18.5.1 sources and monero-docs as cited in R-monero; https://www.getmonero.org/downloads/hashes.txt; the seraphis-migration release notes (FCMP++); the Carrot specification
- Research inputs (session scratchpad): `phase8/R-monero.md`, `phase8/R-code.md`, `phase8/R-privacy.md`; candidate designs `phase8/D-security.md` (base), `phase8/D-delivery.md`, `phase8/D-operations.md`; the judge verdict (scores, grafts, conflicts, errors)
- The GHOST repository at `fa6a048`, as cited inline; `docs/design/faza7-sync-engine.md` (format and harness precedents)
