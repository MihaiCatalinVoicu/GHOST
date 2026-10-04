# GHOST external audit package: index

| Field | Value |
|---|---|
| Handling | **Confidential, for auditors under NDA.** The package lists unfixed weaknesses and the trust model of the build infrastructure. Do not publish it or forward it. |
| Base commit | `a0f3f58ef76bfd4e45f73fd0f1eaf9a89d5750e5` (`main`, 2026-10-03); CI facts re-read on 2026-10-04; revised 2026-10-04 after two adversarial reviews. |
| What it is | What a security auditor needs to scope, price, plan and start an audit of GHOST (a private, closed-source Android forum and messenger with a Rust relay and issuer): what exists and how big it is, what it claims, what is already verified and what is known to be open, and how to get the source and build it. |
| What it is not | A statement that GHOST is ready for audit or for release. `AUDIT_SCOPE.md` section 0 lists the preconditions that are **not** met. Nothing here is a privacy or security claim for users. |

## Reading order for the first day

1. `AUDIT_SCOPE.md` section 0 (the honest state), section 1 (system, assets and secrets, entry points, data flows) and section 4 (the risk-ranked list of where to spend the first weeks).
2. `KNOWN_ISSUES.md` (what is already known, so that effort goes to unknowns).
3. `EVIDENCE_INDEX.md` (what has been verified, how to reproduce it, and section 10: what has **not** run).
4. `BUILD_AND_REVIEW_GUIDE.md` (getting the source, toolchains, building, tests and gates, the reading order of the design documents, the component to specification index).
5. `AUDIT_SCOPE.md` section 5 (cryptographic inventory with exact versions), section 7 (claims register: the properties to try to falsify) and section 8 (what the project does not claim).

## Files

| File | Content |
|---|---|
| `AUDIT_SCOPE.md` | Components with measured sizes, in and out of scope, risk-ranked priorities, assets, entry points and data flows, cryptographic inventory, assumptions and trust boundaries, claims register, non-claims; Appendix A is the measurement script |
| `EVIDENCE_INDEX.md` | Re-run results, test and gate counts, CI picture, crash-injection and mutant registries, formal models, fuzzing, reviews already done, external assessments of upstream components, what has not run |
| `KNOWN_ISSUES.md` | Open findings, open owner decisions, declared residues, unverified assumptions, inconsistencies in the project's own documents |
| `BUILD_AND_REVIEW_GUIDE.md` | Source hand-over, toolchains and pins, build and test commands, reading list, component to specification index |
| `AUDITOR_RFQ.md` | The request for quotation (scope, timeline, deliverables, confidentiality, independence questions, severity annex) |
| `ci-runs.tsv`, `ci-log-facts.tsv` | Static copies of the CI results the package cites: each run with its jobs, and the facts read from the logs. The repository is private and GitHub keeps job logs for 90 days |
| `tools/measure.sh` | The size and test-count measurement of `AUDIT_SCOPE.md` section 2 (nothing is built; only tracked files are read) |
| `tools/check-package.sh` | Fails if a number, a recipe or a handling rule of this package no longer matches the tree; run it on the frozen tag |

## Conventions

* Evidence labels: **[R]** re-run for the package, **[D]** documented in the repository, **[C]** a CI run on the project's runners (see the two `.tsv` files), **[X]** an external source with URL and access date. Anything the preparer inferred is marked **(inferred)**.
* Severities in `KNOWN_ISSUES.md` are the ones recorded by the project's own reviews (all by AI agents; **no human external review has taken place**), not the preparer's.
* In the design documents, later dated `§22.x` notes win over earlier sections; `docs/STATUS.md` is stale in places (`KNOWN_ISSUES.md` KI-DOC-1).
