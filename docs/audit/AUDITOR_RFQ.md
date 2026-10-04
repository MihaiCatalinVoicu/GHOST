# Request for quotation: external security audit of GHOST

> **Owner: delete this block before sending.** This file is the text that goes to the firms, from "B0. Cover" on. It is self-contained: it can be sent before any NDA, and it holds no source code, no unfixed weakness and no budget. Replace every `[…]`. Send **this text alone** with the invitation. After a bidder has signed the NDA (B0), send the audit package: `README.md`, `AUDIT_SCOPE.md`, `EVIDENCE_INDEX.md`, `KNOWN_ISSUES.md`, `BUILD_AND_REVIEW_GUIDE.md`, `ci-runs.tsv`, `ci-log-facts.tsv` and `tools/`. The package contains no source code, but it lists unfixed weaknesses. Never attach any other file of `docs/audit/`. Revised 2026-10-04 after two adversarial reviews; have counsel read it before it goes out.

## B0. Cover

| | |
|---|---|
| Issuer | Mihai Voicu, owner of the GHOST project, `[address, jurisdiction, contact e-mail]` |
| Single point of contact for this RFQ | `[name, e-mail, phone]`; technical contact after contract: `[name]`, answers within one business day |
| RFQ issued | `[date]` |
| Questions accepted until | `[date + 10 days]`; answers sent to all bidders |
| Proposals due | `[date + 21 days]`, in English, as PDF, with the price sheet of B8 as a separate file |
| NDA and audit package | A one-way NDA (project to bidder) is signed by `[date + 5 days]`. The audit package (documents, no source code) is released to each bidder who has signed, so proposals are priced with the package in hand. A bidder who has not signed by then bids on this text alone and must list the assumptions it made |
| Decision | `[date + 35 days]` |
| Contract | `[date + 42 days]`: contract and the limited-use source licence of B6 (the NDA is already signed) |
| Earliest fieldwork start | `[date]`; the project needs at least four weeks between contract and kick-off (B3) |
| Confidentiality | This document contains no source code and no unfixed vulnerability. The audit package is released only under the NDA, and source code only under the NDA and the licence of B6. Please do not forward this document. |

## B1. Project summary

GHOST is a private, closed-source Android forum and messenger designed so that the operators cannot read content, learn identities or IP addresses, or link payments to users. The design uses Tor onion services only (Arti 0.46), blind capability tokens (RFC 9474 RSA blind signatures, Privacy Pass type 0x0002) bought with Monero through an issuer service, direct messages with Olm from vodozemac under a GHOST-built sealed-sender layer with an X-Wing (ML-KEM-768 + X25519) post-quantum layer, forum channels on OpenMLS (planned), SQLCipher at rest, and a Rust relay run by independent operators. The code base is about 73,000 production lines (33,500 Rust, 39,700 Kotlin; test-only code is not counted) with about 1.8 times that in test code; the design is documented in about 19,000 lines of design text and was reviewed by AI agents only; **no external review has taken place**.

The project is a developer preview. **It makes no privacy or security claims to users** and will not make any before the audit. The audit is a release gate in the project's plan: "0 open Critical or High findings" after retest.

**Honest status** (details in the audit package): the DM stack, relay and issuer are implemented; Phase 9 (DM) has open exit-gate items; the MLS channel crate exists only on unmerged branches; media, UI and distribution are designs; there is no physical-device evidence, no deployed staging, and no cross-environment reproducible build. We would rather you know now: the audit package lists every precondition not met and every known open finding, and it reaches every bidder who signs the NDA (B0) before the price sheet is due. A first-stage review of the finished parts is acceptable (B3).

## B2. Scope

Four tiers; bid per tier and sub-tier (B8). Component paths, sizes and specification pointers are in the audit package (after the NDA); sizes below are measured production lines at commit `a0f3f58`, test-only code excluded (test code is about 1.8 times the production code and is not charged).

| Tier | Sub-tier | Content | Size (production lines) | Status |
|---|---|---|---|---|
| **A** Cryptographic composition and protocols | A1 | DM composition: four-mode sealed-sender envelope, binding v3, provisional mode, PQ-B/PQ-C, session selection rules, vodozemac usage including a recorded pickle-layout deviation, state wrapping, safety numbers, formal models written by the project (ProVerif: M-1, M-2 and M-3 exist; M-6 covers one step of its argument and M-7 only the derivation structure; M-4 and M-5 do not exist); this is the "external cryptographic review of the DM composition" the project committed to | 9,578 Rust | Implemented |
| | A2 | MLS channels: OpenMLS 0.9.0 as configured, libcrux provider, storage adapter with value semantics, commit arbitration without a server, generations, committer anchors, password-sealed invites | about 13,600 Rust on an unmerged branch (moving), plus a Kotlin engine | **Option**: price separately; included only if merged before the freeze |
| | A3 | Entitlement cryptography: RFC 9474 split implementation, key permutation proofs, deterministic blinding, offline-signed append-only schedule, nullifiers, the unlinkability argument and its evidence | 2,733 Rust (+ signing path in C2) | Implemented |
| | A4 | Relay authorisation scheme and metadata claims: capabilities, bearer credentials, hash-registered keys, list cursors, TTL tiers, the observable set (T1) | in C1 | Implemented |
| | A5 | **Option:** independent review of the threat model and claims register, closing the project's Phase 2 gate; review of the metadata capture | documents | Open |
| **B** Android client including the native boundary | B1 | JNI and native boundary (51 entry points), handle registry, panic containment, zeroisation, Arti configuration | 8,728 | Implemented |
| | B2 | Identity, key management and storage: BIP-39, HKDF, Ed25519, Keystore wrappers, SQLCipher integration, schema triggers and migrations | 5,173 | Implemented |
| | B3 | Engines: sync (exactly-once outbox/inbox), entitlement client, DM engine (crash consistency, ephemeral deletion, key change) | 28,721 | Implemented |
| | B4 | Platform hardening: manifest, R8, backup rules, jobs/alarms, notifications | about 900 | Implemented (no UI yet) |
| | B5 | Dynamic testing on a physical device and emulators | fixed effort | Never done |
| | B6 | **Option:** UI security review (screen/text protection, app lock, clipboard) | not built | Phase 13 design only |
| **C** Relay and issuer services | C1 | Relay | 4,387 | Implemented |
| | C2 | Issuer: money safety, journal and snapshot restore, Monero view-only rail, payout flow, key custody, signer timing, reconciliation | 13,015 | Implemented |
| | C3 | Infrastructure and runbooks (containers, Tor config, key ceremonies) | 713 lines + 883 lines of runbook | Staging definitions |
| | C4 | Abuse and resource-exhaustion behaviour of both services | fixed effort | |
| **D** Supply chain and build | D1 | Dependency governance (633 third-party Rust packages in the lock, shipped graphs of 455, 113 and 136 components; 332 Gradle components), pinning and gates | policy files | |
| | D2 | Build reproducibility (clean-room rebuild at a fixed path) | fixed effort | Same-path only |
| | D3 | CI/CD trust model (runners, workflow trust, secrets) | 13 workflows | |
| | D4 | **Option:** release signing and distribution (offline keys, manifest, transparency log, updater) | not built | Phase 14 design only |

**Out of scope:** upstream libraries' source (vodozemac, libcrux, OpenMLS, hpke-rs, Arti, redb, SQLCipher, BouncyCastle, AndroidX, Monero) except their selection, pinning, configuration and use; the quarantined `legacy/` prototypes; test code except as evidence; operator physical security; usability and legal review; performance and load measurement. Defects you find in upstream code are to be reported (B6).

**Scope freeze:** the audit is performed on a tagged commit (`audit-rc1`) delivered as a verified bundle. Components marked Option or "not built" are priced as options and included only if they exist at the freeze. **A change of scope after the freeze is a change order.**

## B3. Timeline and what the project provides

| When | Event |
|---|---|
| T-6 weeks | Contract and source licence signed; source bundle delivered; the project has closed or explicitly waived the open exit gates and decided the open items of its known-issues list |
| T-4 weeks | **Environment ready**: the frozen tag builds in the auditor's environment (they confirm with the build guide), the evidence at the tag is fresh (gate and test counts), staging or the in-repo worlds are available as agreed, two physical Android devices (API 29 or higher) and emulator images are available, the technical contact is named, English versions of the three Romanian claim documents or a glossary are delivered |
| T0 | Kick-off (half a day): threat model walk-through, priorities, access check |
| T+1 week | Auditor's test plan and priority ranking (they may re-rank the risk list of the audit package) |
| T+3 weeks | Interim findings report: every Critical and High immediately on discovery (B5) |
| T+`[6-14]` weeks | End of fieldwork. The project's plan assumed 6-8 weeks of fieldwork, but nobody has sized that figure: please state the calendar length and team size you recommend for the tiers you bid. We do not disclose our own person-day estimate (compare B8 item 7) |
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
2. **Reports** in English: interim (T+3 weeks), draft, **final report including retest results**. Each finding: identifier, title, tier and component, affected commit and path, severity, **the claim it affects** (an identifier from the project's claims register, which is part of the audit package, or a one-sentence statement of the property if no register entry fits), preconditions, impact, reproduction or proof of concept, recommended fix, status after retest (fixed, partially fixed, accepted risk, not fixed). A summary of what was **not** covered and why. The test plan and a list of the artefacts used (inputs, fuzz targets, scripts) returned to the project.
3. **Severity scale:** Critical / High / Medium / Low / Informational as defined in annex B11, **plus** a CVSS v4.0 base score and vector (or v3.1 if you cannot use 4.0) for every finding that has a conventional vulnerability form. The project's release gate is "0 open Critical or High after retest"; the definitions in B11 govern, CVSS is a cross-check.
4. **Retest:** one included round of fix verification for all findings (state whether more rounds are included and at what price); a second retest for findings not fixed in the first.
5. **Remediation support:** up to `[N]` person-days of questions, design review of fixes and a debrief workshop with the team.
6. **Publication package** (B6): the full report in a form suitable for publication and, as a separate priced option, a public summary of at most four pages.
7. **Attestation statement** for the project's records: scope, dates, commit, method, and a statement of what the audit does *not* establish. The project will not describe itself as "audited" in any user-facing text without naming the report and its scope (point 11 of the project's decision record ADR-38, part of the audit package).

## B6. Confidentiality, access, disclosure and publication

* **NDA** one-way (project to auditor), signed before the audit package (B0) and before any source is released; **limited-use licence** for the audit only (the project's code is proprietary: "All rights reserved"). No copies outside the audit environment, deleted at the end of the engagement and certified in writing; findings and proofs of concept stay under the NDA until the publication step below.
* **Access:** a signed source bundle with a separately communicated hash (no repository account is created for you). No production secrets, keys or wallets exist or will be provided; test keys for the stagenet are provided on request.
* **Use of AI and external services:** state your policy. Source and findings must not be sent to third-party AI or cloud services without written consent.
* **Responsible disclosure:** findings are reported to the project only. Defects in third-party components (vodozemac, libcrux, OpenMLS, Arti, SQLCipher, others) are reported upstream by you **after** the project's written consent, following the upstream's disclosure policy; the project may ask for a delay to ship fixes. Default embargo for any finding: until the project has shipped a fix or 90 days after the final report, whichever is earlier, extendable by agreement; no embargo applies to your right to report to authorities if legally required.
* **Publication policy (the project's own policy, recorded in its decision record ADR-38):** the project intends to publish the **full final report with the retest results** before the first public distribution, with redaction only of unfixed vulnerability details until fixed. Please confirm you accept this, state any redaction you require, and price separately the alternative of a **public summary only** (the full report stays with the project). Your name may be used only together with a link to the report and its scope statement.
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

The project's claims register (part of the audit package) names the properties GHOST says it has; severity is relative to those claims and to the threat model's adversaries: the operator of the service (AD-1), a relay (AD-2), the issuer (AD-3), a local network observer (AD-4), a global passive observer (AD-5), a malicious group member (AD-6), a malicious direct-message correspondent (AD-7), a person holding the unlocked device (AD-8), a supply-chain attacker (AD-9) and an active network attacker (AD-10).

| Level | Definition for GHOST | Examples |
|---|---|---|
| **Critical** | Without device compromise, an adversary of class AD-1/2/3/4/10 (or a remote attacker) can recover message content, long-term identity or protocol secrets; forge tokens or steal funds at scale; execute code in the app or on a service; or compromise the build or update chain; or a core, exact claim fails deterministically for all users. | Recovering the secrets that protect stored message envelopes from the bytes a relay stores; accepting forged blind-signed tokens; remote code execution through a parser; extracting a signing key through the signer |
| **High** | A registered privacy or integrity claim fails for a realistic adversary without device compromise, or authorisation fails: deanonymise a user to a relay, link a payment to a relay-side activity cluster beyond the declared leak, identify the author or recipient of direct messages, bypass relay or issuer authorisation, lose paid-for value with low preconditions, an unrecoverable data-loss or state-corruption bug, a denial of service operators cannot mitigate. A flaw exploitable by one honest-but-curious operator. | Linking all of one sender's messages across sessions at every relay of a recipient's inbox, in a form beyond the declared leak; issuing tokens twice for one payment |
| **Medium** | Weakening that needs additional preconditions (malicious contact, active timing adversary, authenticated abuse), partial metadata leak beyond the declared residue, crash-consistency loss without a confidentiality impact, resource exhaustion by an authenticated party, defence-in-depth failures. | A parser that accepts a non-canonical encoding of a public value with local impact; secret residue in memory reachable only with process access |
| **Low** | Minor leak, hardening gap, harness or gate that can be bypassed without a product impact. | |
| **Informational** | Observation, documentation inconsistency, improvement. | |

**Claim-violation floor.** A violation of a claim that the project states as exact is at least Medium. Examples of exact claims (register identifiers in brackets; the register is in the audit package): a relay observes only a fixed set of fields and no source address, identity, plaintext or unpadded size [T1]; direct-message addressing is blind, so that no value a relay sees can be computed from public identity material alone [T26]; receiving a message causes no network traffic [T28]; every direct-message envelope and bundle is exactly 4, 16 or 64 KiB, with the size class a function of the body length only [T29]; every byte a relay stores is sealed under keys that are never shown to a relay [T35]; and the equality twins of the privacy world, which must produce identical relay views [NI-*]. A violation that an operator can achieve without access to the device, of the unlinkability of payments from relay-side activity [T2] or of the direct-message privacy world, in which the project's own joins must find nothing beyond the declared leak [T32], is at least High. If you disagree with a classification, say so in the report; the project's gate uses the level you assign after discussion in the factual-accuracy review.

**Known issues.** The audit package lists the project's known open issues and its declared residues. They are **not** excluded from the gate. If you rate a known issue Critical or High, report it with your own evidence: it counts as open until it is fixed, or until the owner accepts it in writing after the factual-accuracy review. If you rate a listed item lower than the project's own note suggests, say why. A declared residue (a risk the project states and accepts) is a finding only if you show that it is worse than declared.

## B12. Annex: finding template

`ID | Title | Tier/component/path:line | Commit | Severity (B11) and CVSS 4.0 vector | Claim(s) affected (register ids) | Preconditions and adversary | Description and impact | Reproduction / proof of concept | Recommendation | Status after retest (fixed / partial / accepted / open) | Reference to upstream issue (if any)`
