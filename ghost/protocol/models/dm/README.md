# ProVerif models of the DM protocol

Phase 9 design `docs/design/faza9-dm.md` §9.5 ("Model in CI") and §16.2 (`pq-model`); slice S13.
Run by `scripts/gates/pq-model.sh` (the `pq-model` workflow), which compares every query's result
with `expected.txt`. Each model has a control query or a mutant that must **fail**, so a green run
shows the model can fail and did not; and where the honest flow could stop silently — which would
make every secrecy query above it vacuously `true` — a **reachability query** (`query event(X)`,
expected `false`, i.e. reachable) shows that it completes.

**First real run: 2026-09-24** (design §22.31). ProVerif 2.05, built from the pinned release in a
Debian container: 48 queries in 8 models, every one matching `expected.txt`. The run found two
defects of the models' text, not of their claims (a `phase 1;` nested inside another in `m6`, and
the `attacker_p1(...)` spelling ProVerif prints for phase-1 facts in `expected.txt`), fixed in the
same change; the secrecy results, controls, mutants and reachability queries were right as
written. What a green run covers is unchanged (below).

| Model | Obligation (§9.5) | What it checks | Control, mutant, reachability |
|---|---|---|---|
| `m1_m3_pqb.pv` | M-1, M-3 | HNDL secrecy of the intro inner layer (card, binding v3, `reply_seed`, first L1) against a card holder with X25519 broken; PQ-B by induction: B's root (under `K_prov`), A's root and pair content (under B's root). One session, no replication; a card holder is given `KIO_B` but deposits no intro of its own | control `outerOnly`; three reachability events |
| `m1_m3_pqb_mutant_no_kem` (generated) | M-1, M-3 | `k_in` without the X-Wing secret (PM-32's shape) | every secrecy query must fail |
| `m2_binding.pv` | M-2 | binding v3: non-injective agreement on (OI_A, base key, ct, namespace, minute, OI_B) with **two** recipients, each with its full state public (KCI) — so a binding transferred to the other inbox is a violation | control: an identity whose signing key leaked; reachability `AcceptedHonest` |
| `m2_binding_mutant_unbound_recipient` (generated) | M-2 | neither the namespace nor OI_B signed | the agreement query must fail |
| `m6_pqc_healing.pv` | M-6, **step (3) only** | after a leak of the complete state at t (A's generation secret, the week key live at t), envelopes under a `seal_root_pq` that B made to the key A announced in band for a generation **created after the leak** stay secret, a week later too. Steps (1), (2) and (4) of §9.4 — a fresh generation, its announcement and choice by the peer, both directions acknowledged — are the PQ3 world's (`PqHealingWorldTest`), not this model's | controls: the week key live at t, a classical root after t, a PQ root to the leaked generation; reachability `SealedHealed` |
| `m7_erasure.pv` | M-7, derivation structure | a seizure after week w's erasure — every later week key with its recognition key, and the seed with what it derives — reaches neither week w's key, its recognition key (`recogProbe`) nor its envelope. That the implementation erases, and that roots are random, is T34's | control `msgLive` |
| `m7_erasure_mutant_invertible` (generated) | M-7 | an invertible week ratchet | the week-w queries must fail |
| `m7_erasure_mutant_seed_root` (generated) | M-7 | week w's root derived from the seed | the week-w queries must fail |

**Mutants are generated, not copied.** A mutant `<original>_mutant_<name>` is not a file: the gate
builds it from `<original>.pv` with `<original>_mutant_<name>.patch` (GNU patch, fuzz 0), so an
edit to the original carries into the mutant, and an edit that touches the mutated lines' context
fails the job until the patch is renewed. To change a mutation, edit the original, apply the
mutation to a copy, and regenerate the patch with `diff -u`.

**Not modelled here (design §22.18):** M-4 is a written argument by the design's own table; M-5
(session selection R-SS0 … R-SS4) is covered by the exhaustive state model EM-1 and has no ProVerif
model; M-8 is vectors, differential tests and fuzzing. M-7 uses key secrecy as the proxy for
unlinkability; an equivalence model is future work. A green `pq-model` run is therefore **not**
"M-1 … M-7 green": it is M-1, M-2, M-3, M-6's step (3) and M-7's structure.

**Abstractions, stated where they matter:** "a quantum adversary" is X25519 broken and ML-KEM-768
intact, so X-Wing is an ideal IND-CCA KEM and every classical layer (Olm) is transparent; HNDL and
healing are passive-adversary properties, modelled by reliable delivery on private channels with
every message copied to the public one; binding v3 is classical authentication (PQ-R1) against the
active Dolev-Yao attacker. HKDF, HMAC and the AEADs are ideal functions.

The ProVerif release is pinned by version in `.github/workflows/pq-model.yml` and by SHA-256 in
`proverif.sha256`; ProVerif is a CI tool and is never shipped.
