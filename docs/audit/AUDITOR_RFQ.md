# GHOST external audit: request for quotation (template) and market notes

| Field | Value |
|---|---|
| Purpose | **Part A** is for the owner only (remove it before sending): the market shortlist, a budgeting method and the decisions to take. **Part B** is the RFQ text the owner can send to the firms chosen from Part A. |
| Base commit | `a0f3f58ef76bfd4e45f73fd0f1eaf9a89d5750e5` (2026-10-03). Sizes and statuses come from `AUDIT_SCOPE.md`, `EVIDENCE_INDEX.md`, `KNOWN_ISSUES.md`. |
| Sources | Every external fact has a URL and an access date (all accessed 2026-10-03 unless stated; the research tool summarised pages, and the PDFs of the Least Authority, SRLabs, Cure53 and Wire reports were read in extracted text). Everything the preparer derived is marked **(inferred)**. **No price in this document is a quote or a fact about any firm**: none of the firms below publishes prices. |
| Status | A draft prepared by an AI agent for the owner. Re-check the external facts and have counsel review Part B before sending. |

---

# Part A. Owner notes (not for the firms)

## A1. What the market looks like for this stack

GHOST needs five kinds of expertise in one engagement: applied cryptography and protocol analysis (Olm, X-Wing/ML-KEM composition, MLS, RFC 9474 blind signatures), Rust code review, Android application security, Tor/onion-service knowledge, and Monero integration (view-only wallet, payouts). No firm in the table below has published work on all five. The public record points to a **crypto-protocol specialist plus an application-security firm**, either one prime with subcontractors or two parallel engagements (A = cryptography/protocols; B, C, D = application, services, supply chain). Firms' public reports differ in how much of the engagement is stated: the "shape" column gives what the report itself states.

### Shortlist (public work relevant to this stack)

| Firm | Relevant public work (link, date) | Engagement shape as publicly stated | Fit (tiers) | Caveats |
|---|---|---|---|---|
| **Least Authority** (Berlin) | **vodozemac** audit for Matrix, final report 2022-03-30: https://leastauthority.com/static/publications/LeastAuthority-Matrix_vodozemac_Final_Audit_Report.pdf ; Matrix blog 2022-05-16: https://matrix.org/blog/2022/05/16/independent-public-audit-of-vodozemac-a-native-rust-reference-implementation-of-matrix-end-to-end-encryption/ | Code review 2021-12-20 to 2022-01-25, initial report 2022-01-28, verification of fixes 2022-03-28/29, final 2022-03-30; five named researchers (three titled cryptography researchers and engineers, two security researchers and engineers); 10 issues (A-J) and 8 suggestions; funded by the Matrix.org Foundation and gematik. Person-days not stated. | **A1**, A3, B1 (Rust crypto, Olm/Megolm internals) | The only audit of the library GHOST wraps is theirs, from 2022; they know the code's history. The report is 4+ years old and predates 0.11.0. Person-days not stated. |
| **Security Research Labs (SRLabs)** (Berlin) | **OpenMLS** security assurance assessment, report v1.2 2026-03-11 (41 pages), sponsored by the Sovereign Tech Agency: https://blog.openmls.tech/SRL-OpenMLS_security_assurance_assessment.pdf ; summary https://blog.phnx.im/openmls-independent-security-audit/ . **Phoenix** messenger architecture audit (protocol documentation; one high finding concerned Privacy Pass token linking), June-October 2024, arranged by the Open Technology Fund Security Lab: https://www.opentech.fund/security-safety-audits/phoenix-architecture-security-audit/ | OpenMLS: kick-off 2025-10-16, "12 weeks" of analysis, preliminary report 2025-12-22, draft 2026-02-03, final 2026-03-03 including mitigation checks; four named assessors; threat-model driven (STRIDE) with manual review, static analysis, three fuzzers; 8 findings (1 high, 3 medium, 2 low, 2 info). Phoenix: design review, 3 high and 4 medium/low findings. | **A2 (MLS)**, A1, A3 (Privacy Pass-like tokens) | Known to the OpenMLS code GHOST will use; **the OpenMLS report excluded crypto providers, storage and PQ suites** (as read in design `faza10-forum.md` §3.1): the libcrux provider and GHOST's adapter remain unreviewed. Elapsed time kick-off to final report was about 20 weeks. |
| **Cure53** (Berlin) | **Tor VPN for Android and the Tunnel Interface for Arti**, report dated 2025-07-04: https://blog.torproject.org/code-audit-tor-vpn/ (PDF: https://blog.torproject.org/code-audit-tor-vpn/torvpn_cure53_audit.pdf). **Nym** (mixnet, VPN, mobile apps, backend and Coconut/zk-nym credential cryptography), July 2024: https://nym.com/trust-center/Cure53-security-audit-2024 (report https://cure53.de/audit-report_nym.pdf). **Threema** mobile apps, October 2020 with fix verification in November 2020: https://cure53.de/pentest-report_threema.pdf ; Threema Desktop 2024-01; Noble crypto libraries 2024-08 (list at https://cure53.de/) | Tor VPN + Arti interface: requested October 2024, performed in a two-week window (calendar weeks 25-26), **24 work days allocated**, six specialists, 18 findings. Nym: **56 working days**, six senior experts, five work packages (apps, desktop, backend, VPN, cryptography), 43 findings (7 critical/high). Threema: fix verification round, report updated. | **B** (Android, native boundary), A3 (blind-signature credentials), D | Team composition varies by engagement (ask for named individuals; the Tor VPN team included cryptographers); capacity is booked months ahead (the Tor audit was requested 8 months before it ran). The Tor audit did not audit Arti itself. |
| **Trail of Bits** | **SimpleX Chat**: code/library assessment 2022-11-08 (two engineers, one calendar week, 4 findings): https://simplex.chat/blog/20221108-simplex-chat-v4.2-security-audit-new-website.html ; protocol design review July 2024 (one week, 3 medium, 1 low, 3 informational): https://simplex.chat/blog/20241014-simplex-network-v6-1-security-review-better-calls-user-experience.html . **Monero FCMP++** cryptography review, completed July 2026, **two engineer-weeks**, six informational findings: https://magicgrants.org/2026/08/17/Monero-FCMP-Cryptography-Implementation-ToB . Their report index states each engagement's length in weeks (e.g. 5 to 12 weeks for cryptography-library reviews): https://trailofbits.com/reports/ | One to twelve weeks across the examples; team size is stated only for SimpleX 2022 (two engineers). | **A** (design and crypto review), C2, D | Public messenger work is design-level or short; GHOST would be the largest of their published messenger engagements. |
| **NCC Group** (Cryptography Services) | **Olm/Megolm** cryptographic review for Matrix, report 2016-11-01, funded by the Open Technology Fund: https://www.nccgroup.com/research-blog/public-report-matrix-olm-cryptographic-review/ | Two consultants, 2016-09-19 to 09-30, **15 person-days**, Olm 1.3.0 | **A1** | The report is 10 years old and about a different code base (libolm). |
| **Quarkslab** (Paris) | **Session** messenger audit (Android, iOS, desktop), report 2021-04-29: https://blog.quarkslab.com/audit-of-session-secure-messaging-application.html . **Monero** Bulletproofs (2018) and RandomX (2019) audits with OSTIF: https://ostif.org/the-quarkslab-and-kudelski-security-audits-of-monero-bulletproofs-are-complete/ | Session: **42 days, two engineers**, spread March 2020 to April 2021 across three code bases | **B**, A (applied crypto of an app protocol), C2 (Monero) | Spread over a year in three phases; the protocol was redesigned before the third (desktop) phase, per the report. |
| **7ASecurity** | **Tor Project** network-health tools including Arti, July-August 2025 (six vulnerabilities, eleven hardening recommendations): https://blog.torproject.org/code-audit-network-health-tools/ ; Tor privacy impact report 2024-08; Android privacy apps (K-9 Mail 2023-04, Noghteha 2026-02): https://7asecurity.com/publications | Engagement length not stated in the articles read. | **B**, D (supply chain, threat modelling), A4 (Tor) | Public titles show threat-model, fuzzing and supply-chain scope; Rust-cryptography depth is not evident from what was read (inferred). |
| **Kudelski Security and X41 D-Sec** | **Wire Proteus** review (Rust, Signal-style double ratchet), 2016-11-23 to 2017-01-09: https://wire-docs.wire.com/download/Wire+Audit+Report.pdf ; Monero Bulletproofs (Kudelski, 2018) | **14 person-days** for about 6,100 lines (3,300 Rust, 2,400 CoffeeScript, 400 C), two reviewers | A1, A3 | Dated (2016-17); a small Rust code base by today's standards. The named individuals may no longer work at these firms (not checked). |
| **Radically Open Security** (NL, non-profit) | **Briar** (Android and desktop), initial audit September-October 2023, retest February-March 2024, arranged by the OTF Security Lab: https://www.opentech.fund/security-safety-audits/briar-security-audit/ | About six months in two phases; 1 moderate and 5 low issues | B (a retest model) | Capacity and cryptographic depth not evidenced publicly. |
| **Symbolic Software** | Research on libcrux and hpke-rs: "Verification Theatre", ePrint 2026/192, received 2026-02-05, revised 2026-06-25: https://eprint.iacr.org/2026/192 ; an applied-cryptography research firm | Not an audit report | **A1** (ProVerif models M-4/M-5 gap; libcrux wrappers), A3 | **The libcrux vendor disputed parts of this publicly** (secondary reporting; read both sides before choosing); a small firm; ask for capacity and independence. |
| **Cypher Stack** | CARROT address scheme audit for Monero FCMP++: https://github.com/cypherstack/carrot-audit | Date and effort not stated on the page | C2 (Monero cryptography review only) | Protocol-level Monero cryptography, not wallet integration or mobile. |
| **Cryspen** (libcrux, hpke-rs vendor) | Formal-methods and libcrux authors | n/a | **Do not use for the audit**: GHOST depends on its libraries; conflict of interest (ask every other bidder to declare relations with it) | |

The *Fit* column is the preparer's judgement **(inferred)** from the public record read, not a statement by the firms. "No firm has published work on all five" is likewise inferred from the sources read, not from an exhaustive search.

**Funding and intermediary programmes** (inferred to be unavailable for a closed-source product; ask them, do not assume): OSTIF ("100+ projects audited, 20,000 hours of coordinated security review, $3,000,000+ raised": https://ostif.org/audits/); the Open Technology Fund Security Lab and Red Team Lab (arranged the Briar and Phoenix audits; eligibility rules not stated on https://www.opentech.fund/security-safety-audits/); the Sovereign Tech Agency (sponsored the OpenMLS audit). All three work with open-source or internet-freedom projects in the cases above.

**Not evaluated:** Doyensec, Include Security, Bishop Fox, Zellic, others. No public report relevant to this stack was found for them in the searches run (inferred; not exhaustive).

**Gaps in the public record:** no public independent audit found for `blind-rsa-signatures`, for Privacy Pass-style issuance (other than the RFC security analysis and Nym's Coconut review), for libcrux or hpke-rs (apart from the 2026 research above), or for the Arti client as an Android library. **For three areas GHOST is the first public case:** an Olm session layer under an X-Wing sealing layer, MLS channels with commit ordering without a server, and a Monero-funded blind-signature issuer.

## A2. Budgeting method (person-days, not prices)

**Formula (inferred method):** `cost = person-days x blended day rate`, with `person-days = sum over components of (production lines / lines reviewed per person-day at the chosen depth) + fixed items`, then a project-overhead factor and a retest factor. Lines are **measured** (`AUDIT_SCOPE.md` section 2); the rates are **assumptions** anchored on the public data points below; day rates are not published by any firm in the shortlist, so they must come from quotes.

**Public calibration points** (all [X], see links in A1; "lines per person-day" are the preparer's arithmetic, **inferred**):

| Engagement | Effort stated | Size | Lines per person-day | Reading |
|---|---|---|---|---|
| Wire Proteus, Kudelski/X41, 2016-17 | 14 person-days | about 6,100 lines | about **435** | Mostly manual review of a small Rust + JS + C code base |
| OpenMLS, SRLabs, 2025-26 | 4 assessors, "12 weeks" (person-days not stated; 240 if full-time) | `openmls` + `traits` + `basic_credential` crates: 86,295 + 2,409 + 390 lines measured in the 0.9.0 registry sources, inline tests included | about **370** (a bit higher on production lines) | Threat-model-driven baseline assurance with fuzzing |
| vodozemac, Least Authority, 2021-22 | 5 named researchers, 5 weeks of code review plus later verification (person-days not stated; about 125 if full-time) | vodozemac 0.11.0 is 14,452 lines today; the 2022 version was smaller (not measured) | below **116** (the deepest datum) | Line-by-line cryptographic review |
| Olm, NCC Group, 2016 | 15 person-days | Olm 1.3.0 (C; lines not measured) | n/a | Two weeks, two consultants |
| Session, Quarkslab, 2020-21 | 42 days | Three apps (lines not measured) | n/a | Breadth over three code bases |
| Tor VPN + Arti interface, Cure53, 2025 | 24 work days | Android app + Rust interface (not measured) | n/a | Penetration test and source audit |
| Nym, Cure53, 2024 | 56 working days | Apps, desktop, backend, VPN, cryptography (not measured) | n/a | Broad |
| OSTIF aggregate (open source) | 20,000 hours for "$3,000,000+ dollars raised" over 100+ projects | | Ratio about **USD 150 per reviewed hour**, i.e. about USD 1,200 per 8-hour day | **Inferred and weak**: non-profit mediated, funds raised are not audit invoices, rates for closed-source commercial work are probably higher. Use only as a floor for the order of magnitude. |

**Depth bands used below (assumptions):** deep (cryptography and protocol code) 100-200 lines per person-day; standard 300-500; sampled/light 800-1,500. Anchors: Least Authority (deep, below 116), Wire and OpenMLS (standard, 370-435).

**GHOST's measured production lines by tier** (physical lines at the base commit; code counted once under its primary tier; the sum is 76,159 lines, equal to the Rust plus Kotlin production totals):

| Tier | Components | Production lines | Depth | Person-days (low-high) |
|---|---|---|---|---|
| A1, A3 | `ghost-client-dm` 12,308 + `dm-host` 35; `ghost-blind-rsa` 490 + `ghost-entitlement` 2,199 + `ghost-issuer-api` 44 | 15,076 | deep | **75 - 151** |
| B1 | `ghost-client-net` 3,929; `:network` 1,264; `:crypto-bridge` 3,674 | 8,867 | standard | 18 - 30 |
| B2 | `:identity` 3,290; `:storage` 1,883 | 5,173 | deep-standard (200-400) | 13 - 26 |
| B3 | `:sync` 8,645; `:entitlement` 4,767; `:messaging` 15,309 | 28,721 | standard | 57 - 96 |
| B4 | `:app` 880 (+40 release) and manifests | 920 | standard | 3 |
| B5 | Dynamic testing on emulator and two devices (no line count) | n/a | fixed | 10 - 20 |
| C1 | Relay 4,387 | 4,387 | deep-standard | 11 - 22 |
| C2 | Issuer service 9,456 + ops 3,559 | 13,015 | deep-standard (150-300) | 43 - 87 |
| C3 | `ghost/infra` 571 lines + RUNBOOK 883 lines | n/a | fixed | 5 - 10 |
| D | Gates and scripts about 10,000, CI 2,217, policy files; clean-room rebuild; dependency and runner trust review | about 13,000 sampled | light + fixed | 20 - 36 |
| All | Onboarding on 19,000 lines of design and 600 KB of Romanian text (unless translated) | n/a | fixed | 10 - 15 |
| | **Subtotal** | | | **265 - 496** |
| | Project overhead 15-25 % (kick-off, reporting, meetings, triage) | | | 305 - 620 |
| | Retest (fix verification) 8-12 % | | | **329 - 694 person-days, i.e. 66 - 139 person-weeks** |

**Scenarios (inferred):**

| Scenario | What it buys | Person-weeks | Auditors needed for 8 weeks / 12 weeks |
|---|---|---|---|
| **S0 Baseline assurance** (SRLabs-style, about 370 lines per person-day over all 76,159 production lines, plus dynamic testing, supply chain, onboarding, overhead, retest) | Broad coverage at moderate depth | about **50 - 90** (central 65: 205 person-days of line review at 370 lines per person-day plus about 50 of dynamic testing, supply chain, infrastructure and onboarding, then 20 % overhead and 10 % retest; range from 435 to 300 lines per person-day) | 6-11 / 4-7 |
| **S1 Focused** (deep on A1 + A3, 5,000 lines of the issuer money path, 2,000 of relay authorisation, 3,500 of the JNI boundary, 5,000 sampled engine lines, light supply chain) | The riskiest 20 % in depth (`AUDIT_SCOPE.md` section 4 ranks 1, 3, 4, 6) | about **36 - 76** | 5-10 / 3-6 |
| **S2 Plan scope** (the table above) | All four tiers at the stated depths | **66 - 139** | 8-17 / 6-12 |
| **+ MLS (A2)** once merged | Deep review of `ghost-client-mls`: 13,123 source lines on branch `p10-s2b` today (unmerged, work in progress) plus the Kotlin channel engine (not written; size unknown) at 100-200 lines per person-day | +66 - 131 person-days (+13 - 26 person-weeks) for the Rust crate alone | |

**Reading the result:**

1. **The plan's "6-8 weeks" is a calendar figure that nobody sized.** At the plan's scope (S2) it requires 8-17 auditors in parallel for 8 weeks; the public engagements above ran with 2-6 (SRLabs OpenMLS: 4 for 12 weeks; Cure53: 6 for 2 weeks to 56 days; Least Authority: 5). **Plan for 10-14 weeks with 6-8 auditors, or split the tiers across two firms, or accept S1** (inferred).
2. **Test code is not review effort.** There are 74,430 lines of Kotlin unit tests and 46,000 lines of Rust integration tests; the table does not charge for them, assuming the auditor judges the oracles (T1, T2, T32) by sampling and by the mutants.
3. **The uncertainty is at least +-50 %** on each line (two or three data points per band, unmeasured sizes of the comparison code, unknown full-time ratios). Ask each bidder to price **per tier and per sub-tier** (section B8) and compare their person-days to this table: a bid far below it for tier A1 should be questioned, not welcomed.
4. **Price** = person-days x day rate x risk/rush margin. The OSTIF-derived USD 1,200/day would put the plan scope at roughly USD 0.4 - 0.8 million and S1 at roughly USD 0.2 - 0.5 million **before** commercial margins; treat it as a lower bound for the order of magnitude, not as an estimate of any firm's rate (inferred, weak).

**Two-stage option (inferred):** a pre-audit review of A1 (the DM composition, ranks 1 and 3 of the priority list) and C can start before Phases 9-14 finish, because the Rust crates are stable in structure; the exit gate of the master plan (row 15) is then closed by a smaller second stage covering what changed (MLS, UI, media, distribution) and the retest. This lowers the schedule risk of one 6-8-week block and finds design-level problems before more code depends on them. The cost is two kick-offs and a rework risk if the DM crate changes materially after stage 1.

## A3. Decisions only the owner can take (also in `README-RO.md`)

1. **Which tiers** (A, B, C, D, options A2 MLS, A5 threat-model review, B6 UI) and **which scenario** (S0, S1, S2) to request; whether to **split** between a cryptography firm and an application-security firm.
2. **Publication policy:** ADR-38 point 1 says audit reports are published in full, with retests, before the first public distribution. The RFQ asks for that by default (B5, B6) and for a **public-summary-only** alternative to be priced; choosing the alternative contradicts ADR-38 and its "rejected alternative" note (a summary alone is insufficient; the Threema analysis at USENIX Security 2023 is cited there). Decide before sending.
3. **Source access terms:** NDA and limited-use licence text (the root `LICENSE` grants nothing); whether the auditor gets full git history or a snapshot; no GitHub collaborator access (`BUILD_AND_REVIEW_GUIDE.md` section 1.2).
4. **Scope freeze date** and which of Phases 9-14 must be closed or explicitly waived before kick-off (`AUDIT_SCOPE.md` section 0).
5. The open decisions of `KNOWN_ISSUES.md` section 2 and 4 that change code under audit (decide before the freeze, not during the audit).
6. Budget ceiling and whether the retest is included in a fixed price.
7. Whether to commission **English versions** of THREAT_MODEL, INVARIANTS and LIMITE (192 KB of Romanian text) before the audit.

---

# Part B. Request for quotation: external security audit of GHOST

*(Send Part B only. Replace `[…]`. Attach: the audit package (`AUDIT_SCOPE.md`, `EVIDENCE_INDEX.md`, `KNOWN_ISSUES.md`, `BUILD_AND_REVIEW_GUIDE.md`) after the NDA is signed; before the NDA, send Part B alone.)*

## B0. Cover

| | |
|---|---|
| Issuer | Mihai Voicu, owner of the GHOST project, `[address, jurisdiction, contact e-mail]` |
| Single point of contact for this RFQ | `[name, e-mail, phone]`; technical contact after contract: `[name]`, answers within one business day |
| RFQ issued | `[date]` |
| Questions accepted until | `[date + 10 days]`; answers sent to all bidders |
| Proposals due | `[date + 21 days]`, in English, as PDF, with the price sheet of B8 as a separate file |
| Decision | `[date + 35 days]`; contract and NDA `[date + 42 days]` |
| Earliest fieldwork start | `[date]`; the project needs at least four weeks between contract and kick-off (B3) |
| Confidentiality | This document contains no source code. Source and detailed documents are released only under the NDA and licence of B6. Please do not forward it. |

## B1. Project summary

GHOST is a private, closed-source Android forum and messenger designed so that the operators cannot read content, learn identities or IP addresses, or link payments to users. The design uses Tor onion services only (Arti 0.46), blind capability tokens (RFC 9474 RSA blind signatures, Privacy Pass type 0x0002) bought with Monero through an issuer service, direct messages with Olm from vodozemac under a GHOST-built sealed-sender layer with an X-Wing (ML-KEM-768 + X25519) post-quantum layer, forum channels on OpenMLS (planned), SQLCipher at rest, and a Rust relay run by independent operators. The code base is about 76,000 production lines (36,400 Rust, 39,750 Kotlin) with about 1.8 times that in test code; the design is documented in about 19,000 lines of design text and was reviewed by AI agents only; **no external review has taken place**.

The project is a developer preview. **It makes no privacy or security claims to users** and will not make any before the audit. The audit is a release gate in the project's plan: "0 open Critical or High findings" after retest.

**Honest status** (details in the package): the DM stack, relay and issuer are implemented; Phase 9 (DM) has open exit-gate items; the MLS channel crate exists only on unmerged branches; media, UI and distribution are designs; there is no physical-device evidence, no deployed staging, and no cross-environment reproducible build. We would rather you know now: `AUDIT_SCOPE.md` section 0 and `KNOWN_ISSUES.md` list every precondition not met and every known open finding. A first-stage review of the finished parts is acceptable (B3).

## B2. Scope

Four tiers; bid per tier and sub-tier (B8). Component paths, sizes and specification pointers are in `AUDIT_SCOPE.md` (after NDA); sizes below are measured production lines at commit `a0f3f58`.

| Tier | Sub-tier | Content | Size (production lines) | Status |
|---|---|---|---|---|
| **A** Cryptographic composition and protocols | A1 | DM composition: four-mode sealed-sender envelope, binding v3, provisional mode, PQ-B/PQ-C, session selection rules, vodozemac usage including a recorded pickle-layout deviation, state wrapping, safety numbers, ProVerif models (M-1, M-2, M-3, M-6, M-7 exist; M-4 and M-5 do not); this is the "external cryptographic review of the DM composition" the project committed to | 12,343 Rust | Implemented |
| | A2 | MLS channels: OpenMLS 0.9.0 as configured, libcrux provider, storage adapter with value semantics, commit arbitration without a server, generations, committer anchors, password-sealed invites | 13,000+ Rust on an unmerged branch, plus a Kotlin engine | **Option**: price separately; included only if merged before the freeze |
| | A3 | Entitlement cryptography: RFC 9474 split implementation, key permutation proofs, deterministic blinding, offline-signed append-only schedule, nullifiers, the unlinkability argument and its evidence | 2,733 Rust (+ signing path in C2) | Implemented |
| | A4 | Relay authorisation scheme and metadata claims: capabilities, bearer credentials, hash-registered keys, list cursors, TTL tiers, the observable set (T1) | in C1 | Implemented |
| | A5 | **Option:** independent review of the threat model and claims register, closing the project's Phase 2 gate; review of the metadata capture | documents | Open |
| **B** Android client including the native boundary | B1 | JNI and native boundary (51 entry points), handle registry, panic containment, zeroisation, Arti configuration | 8,867 | Implemented |
| | B2 | Identity, key management and storage: BIP-39, HKDF, Ed25519, Keystore wrappers, SQLCipher integration, schema triggers and migrations | 5,173 | Implemented |
| | B3 | Engines: sync (exactly-once outbox/inbox), entitlement client, DM engine (crash consistency, ephemeral deletion, key change) | 28,721 | Implemented |
| | B4 | Platform hardening: manifest, R8, backup rules, jobs/alarms, notifications | about 920 | Implemented (no UI yet) |
| | B5 | Dynamic testing on a physical device and emulators | fixed effort | Never done |
| | B6 | **Option:** UI security review (screen/text protection, app lock, clipboard) | not built | Phase 13 design only |
| **C** Relay and issuer services | C1 | Relay | 4,387 | Implemented |
| | C2 | Issuer: money safety, journal and snapshot restore, Monero view-only rail, payout flow, key custody, signer timing, reconciliation | 13,015 | Implemented |
| | C3 | Infrastructure and runbooks (containers, Tor config, key ceremonies) | 571 + 883 lines of runbook | Staging definitions |
| | C4 | Abuse and resource-exhaustion behaviour of both services | fixed effort | |
| **D** Supply chain and build | D1 | Dependency governance (633 third-party Rust packages in the lock, shipped graphs of 455, 113 and 136 components; 332 Gradle components), pinning and gates | policy files | |
| | D2 | Build reproducibility (clean-room rebuild at a fixed path) | fixed effort | Same-path only |
| | D3 | CI/CD trust model (self-hosted runners, workflow trust, secrets) | 13 workflows | |
| | D4 | **Option:** release signing and distribution (offline keys, manifest, transparency log, updater) | not built | Phase 14 design only |

**Out of scope:** upstream libraries' source (vodozemac, libcrux, OpenMLS, hpke-rs, Arti, redb, SQLCipher, BouncyCastle, AndroidX, Monero) except their selection, pinning, configuration and use; the quarantined `legacy/` prototypes; test code except as evidence; operator physical security; usability and legal review; performance and load measurement. Defects you find in upstream code are to be reported (B6).

**Scope freeze:** the audit is performed on a tagged commit (`audit-rc1`) delivered as a verified bundle. Components marked Option or "not built" are priced as options and included only if they exist at the freeze. **A change of scope after the freeze is a change order.**

## B3. Timeline and what the project provides

| When | Event |
|---|---|
| T-6 weeks | NDA and licence signed; source bundle delivered; the project has closed or explicitly waived the open exit gates and decided the open items of its known-issues list |
| T-4 weeks | **Environment ready**: the frozen tag builds in the auditor's environment (they confirm with the build guide), the evidence at the tag is fresh (gate and test counts), staging or the in-repo worlds are available as agreed, two physical Android devices (API 29 or higher) and emulator images are available, the technical contact is named, English versions of the three Romanian claim documents or a glossary are delivered |
| T0 | Kick-off (half a day): threat model walk-through, priorities, access check |
| T+1 week | Auditor's test plan and priority ranking (they may re-rank `AUDIT_SCOPE.md` section 4) |
| T+3 weeks | Interim findings report: every Critical and High immediately on discovery (B5) |
| T+`[6-14]` weeks | End of fieldwork; **the plan assumes 6-8 weeks of fieldwork** (master plan phase 15). Please state the calendar length and team size you recommend for the tiers you bid; the project's own sizing suggests 10-14 weeks with six to eight auditors for the full scope; we do not disclose our person-day estimate (compare B8 item 7) |
| +1 to 2 weeks | Draft report; factual-accuracy review by the project (2 business days) |
| +2 to 3 weeks | Remediation window (the project fixes; the auditor answers questions) |
| +1 to 2 weeks | **Retest** of every finding (fix verification), final report |
| After | Public report or summary per B6; optional second stage for options not available at the freeze |

## B4. Required skills and team

Please name the people who will do the work, with relevant public output (reports, papers, CVEs, talks), their planned time commitment, and a senior lead who stays on the project. We require demonstrated capability in each of:

1. Applied cryptography and protocol analysis, including double-ratchet protocols (Olm/Signal) or MLS, KEMs and hybrid constructions (X-Wing, ML-KEM), and symbolic or computational proofs (ProVerif or Tamarin);
2. Rust code review and unsafe-free memory-hygiene review (zeroisation, residue), `cargo`-ecosystem supply-chain review, fuzzing;
3. Android application security (Keystore/StrongBox, SQLCipher, JNI, R8, manifest and backup surfaces, dynamic testing on devices);
4. Tor and onion services (Arti configuration, circuit isolation, onion-service operation);
5. Blind signatures and anonymous credentials (RFC 9474/9578), payment systems and, for tier C2, Monero (view-only wallet RPC, subaddress handling, payout flows).

If no single firm covers all five, bid with named subcontractors or for a subset of tiers; say which.

## B5. Deliverables

1. **Interim notice** of every Critical or High finding within 24 hours of confirmation (phone or encrypted message to the technical contact), then in the next interim report.
2. **Reports** in English: interim (T+3 weeks), draft, **final report including retest results**. Each finding: identifier, title, tier and component, affected commit and path, severity, **the claim it affects** (identifiers from the project's claims register, e.g. T26, F9 P-1), preconditions, impact, reproduction or proof of concept, recommended fix, status after retest (fixed, partially fixed, accepted risk, not fixed). A summary of what was **not** covered and why. The test plan and a list of the artefacts used (inputs, fuzz targets, scripts) returned to the project.
3. **Severity scale:** Critical / High / Medium / Low / Informational as defined in annex B11, **plus** a CVSS v4.0 base score and vector (or v3.1 if you cannot use 4.0) for every finding that has a conventional vulnerability form. The project's release gate is "0 open Critical or High after retest"; the definitions in B11 govern, CVSS is a cross-check.
4. **Retest:** one included round of fix verification for all findings (state whether more rounds are included and at what price); a second retest for findings not fixed in the first.
5. **Remediation support:** up to `[N]` person-days of questions, design review of fixes and a debrief workshop with the team.
6. **Publication package** (B6): the full report in a form suitable for publication and, as a separate priced option, a public summary of at most four pages.
7. **Attestation statement** for the project's records: scope, dates, commit, method, and a statement of what the audit does *not* establish. The project will not describe itself as "audited" in any user-facing text without naming the report and its scope (ADR-38 point 11).

## B6. Confidentiality, access, disclosure and publication

* **NDA** one-way (project to auditor) before any source is released; **limited-use licence** for the audit only (the project's code is proprietary: "All rights reserved"). No copies outside the audit environment, deleted at the end of the engagement and certified in writing; findings and proofs of concept stay under the NDA until the publication step below.
* **Access:** a signed source bundle with a separately communicated hash (no repository account is created for you; the project's CI executes workflow code on the owner's own machines). No production secrets, keys or wallets exist or will be provided; test keys for the stagenet are provided on request.
* **Use of AI and external services:** state your policy. Source and findings must not be sent to third-party AI or cloud services without written consent.
* **Responsible disclosure:** findings are reported to the project only. Defects in third-party components (vodozemac, libcrux, OpenMLS, Arti, SQLCipher, others) are reported upstream by you **after** the project's written consent, following the upstream's disclosure policy; the project may ask for a delay to ship fixes. Default embargo for any finding: until the project has shipped a fix or 90 days after the final report, whichever is earlier, extendable by agreement; no embargo applies to your right to report to authorities if legally required.
* **Publication policy (the project's policy ADR-38):** the project intends to publish the **full final report with the retest results** before the first public distribution, with redaction only of unfixed vulnerability details until fixed. Please confirm you accept this, state any redaction you require, and price separately the alternative of a **public summary only** (the full report stays with the project). Your name may be used only together with a link to the report and its scope statement.
* **Contract law and jurisdiction:** `[owner's jurisdiction]`; state your registered entity and any export-control constraints that apply to cryptographic source code.

## B7. Independence and conflicts of interest

Answer each question in writing; a false or missing answer disqualifies a bid.

1. Do you or any person who will work on this engagement have a financial, employment, advisory or consulting relationship with Cryspen / CE Labs (libcrux, hpke-rs), the Matrix.org Foundation or Element (vodozemac, Olm), Phoenix R&D / the OpenMLS maintainers, the Tor Project, the Monero project or MAGIC Grants, or any competitor of GHOST (a secure messenger)?
2. Have you audited, or been paid for work on, any component GHOST uses (list the engagements and dates)? Do you intend to rely on those results?
3. Have you published, or do you intend to publish, vulnerabilities, criticism or marketing material about the libraries GHOST depends on? Are you party to a public dispute with any of their authors?
4. Will any subcontractor or reviewer work for a government or intelligence service, or has any been funded by one in the last three years?
5. Do you provide commercial products or services (vulnerability brokerage, exploit sales) that could be affected by the findings?
6. Do you do, or plan to do, work for a company that may acquire or compete with GHOST?
7. Have you been compromised, or suffered a data breach affecting customer material, in the last three years?
8. Will any person working on GHOST be employed at the same time by a firm bidding for another tier?
9. Where are your staff and your data stored (countries)? Do you use sub-processors?
10. Describe how you separate this engagement's material from your other clients' and from your own research publications.

## B8. Pricing structure requested

Send the price sheet as a separate file. Do not reveal prices in the technical proposal.

1. **Per sub-tier price** for A1, A2 (option), A3, A4, A5 (option), B1-B5, B6 (option), C1-C4, D1-D3, D4 (option): person-days and the price for each, with the depth you propose (deep line-by-line, standard, sampled).
2. **Fixed price or time-and-materials with a cap** for each tier; if T&M, the daily rate by seniority (lead, senior, mid, junior) and the cap.
3. What the fixed price assumes (lines of code, number of findings expected, number of retest rounds) and **what triggers a change order**.
4. The cost of: the retest round (included? number of findings covered?); additional retest rounds; remediation-support days beyond `[N]`; the publication package (full report); the public-summary option; the interim critical-finding hotline (if charged); travel (if any); rush or out-of-window scheduling.
5. Currency, VAT treatment, payment schedule (suggested: 30 % at contract, 40 % at the draft report, 30 % at the final report after retest), price validity (at least 90 days), cancellation and rescheduling terms.
6. A **two-stage variant** if you recommend one: stage 1 for the finished parts now, stage 2 for what changes (separate prices).
7. Your own person-day estimate against the lines of code in B2 (state lines per person-day by depth). Bids will be compared to the project's own estimate; large deviations will be questioned.

## B9. Evaluation criteria and weights

| # | Criterion | Weight |
|---|---|---|
| 1 | Technical competence and relevant references: public reports or papers on E2EE messengers (Olm/Signal/MLS), Rust cryptography, Tor/Arti, blind signatures or anonymous credentials, Android privacy apps | 30 % |
| 2 | Proposed approach: how depth is allocated to the riskiest components, use of the project's evidence (threat model, claims register, models, fuzz targets, mutants), test plan, treatment of the options | 20 % |
| 3 | Team: named people, seniority, continuity, availability inside the window | 15 % |
| 4 | Reporting, retest and communication: report quality (sample or published reports), disclosure handling, speed of critical notification, willingness to publish the full report | 10 % |
| 5 | Price and commercial terms (compared at equal scope and depth) | 15 % |
| 6 | Independence and conflict-of-interest answers (B7), including how a dispute with a dependency's authors would be handled | 10 % |
| | **Total** | 100 % |

**Pass/fail conditions** (a bid failing any is not scored): acceptance of the NDA and licence terms of B6; complete answers to B7; a named senior cryptographer for A1/A3 if those tiers are bid; acceptance of the 24-hour Critical/High notice; ability to start within `[window]`.

## B10. Proposal format

Maximum 15 pages plus annexes: executive summary; understanding of the project and of the preconditions in B1; approach per tier; team and CVs; schedule and effort; assumptions and dependencies on the project; publication and disclosure terms; conflict-of-interest answers; two public sample reports; references (two clients you may contact, ideally for a cryptographic or messaging engagement); the price sheet as a separate file.

## B11. Annex: severity definitions for this project

The project's claims register (`AUDIT_SCOPE.md` section 7) names the properties GHOST says it has; severity is relative to those claims and to the threat model's adversaries (AD-1 operator, AD-2 relay, AD-3 issuer, AD-4 local network, AD-5 global passive, AD-6 group member, AD-7 DM correspondent, AD-8 device, AD-9 supply chain, AD-10 active network).

| Level | Definition for GHOST | Examples |
|---|---|---|
| **Critical** | Without device compromise, an adversary of class AD-1/2/3/4/10 (or a remote attacker) can recover message content, long-term identity or protocol secrets; forge tokens or steal funds at scale; execute code in the app or on a service; or compromise the build or update chain; or a core, exact claim fails deterministically for all users. | Recover pair roots from relay-stored bytes; accept forged blind-signed tokens; remote code execution via a parser; signing-key extraction through the signer |
| **High** | A registered privacy or integrity claim fails for a realistic adversary without device compromise, or authorisation fails: deanonymise a user to a relay, link a payment to a relay-side activity cluster beyond the declared leak (T2), identify the author or recipient of DMs (T26-T35), bypass relay/issuer authorisation, lose paid-for value with low preconditions, an unrecoverable data-loss or state-corruption bug, a denial of service operators cannot mitigate. A flaw exploitable by one honest-but-curious operator. | Cross-session chaining of a sender by every relay of an inbox (cf. MD-1) if confirmed in a form beyond the declared leak; double issuance |
| **Medium** | Weakening that needs additional preconditions (malicious contact, active timing adversary, authenticated abuse), partial metadata leak beyond the declared residue, crash-consistency loss without a confidentiality impact, resource exhaustion by an authenticated party, defence-in-depth failures. | A parser accepting a non-canonical encoding with local impact (cf. CRY-P9-01); secret residue in memory reachable only with process access |
| **Low** | Minor leak, hardening gap, harness or gate that can be bypassed without a product impact. | |
| **Informational** | Observation, documentation inconsistency, improvement. | |

**Claim-violation floor:** a violation of a claim listed as exact (T1, T26, T28, T29, T35 and the equality twins NI-*) is at least Medium; a violation of T2 or T32 achievable by AD-1 without device access is at least High. If you disagree with a classification, say so in the report; the project's gate uses the level you assign after discussion in the factual-accuracy review.

## B12. Annex: finding template

`ID | Title | Tier/component/path:line | Commit | Severity (B11) and CVSS 4.0 vector | Claim(s) affected (register ids) | Preconditions and adversary | Description and impact | Reproduction / proof of concept | Recommendation | Status after retest (fixed / partial / accepted / open) | Reference to upstream issue (if any)`
