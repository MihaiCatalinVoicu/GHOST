# ProVerif models of the DM protocol

Phase 9 design `docs/design/faza9-dm.md` §9.5 ("Model in CI") and §16.2 (`pq-model`); slice S13.
Run by `scripts/gates/pq-model.sh` (the `pq-model` workflow), which compares every query's result
with `expected.txt`. A control query or a mutant model that must **fail** sits beside every
property, so a green run shows that the model can fail and did not.

| Model | Obligation (§9.5) | Properties | Control |
|---|---|---|---|
| `m1_m3_pqb.pv` | M-1, M-3 | HNDL secrecy of the intro inner layer (sender card, `reply_seed`, first L1) against a card holder with X25519 broken; PQ-B by induction: B's root (under `K_prov`), A's root and pair content (under B's root) | `outerOnly` (the card-keyed layer is open to a card holder) |
| `m1_m3_pqb_mutant_no_kem.pv` | M-1, M-3 | mutant: `k_in` without the X-Wing secret (PM-32's shape) | every query must fail |
| `m2_binding.pv` | M-2 | binding v3: non-injective agreement on (OI_A, base key, ct, namespace, minute, OI_B) with the recipient's full state public (KCI) | an identity whose signing key leaked |
| `m6_pqc_healing.pv` | M-6 | PQ-C healing: after a leak of both devices at t, envelopes under a `seal_root_pq` to a generation created after t stay secret, a week later too | the leak's live root, a classical root after t, a PQ root to a leaked generation |
| `m7_erasure.pv` | M-7 | P-7/T34 as key erasure: after the seizure, the erased week key and its envelope stay out of reach (one-way ratchet) | the live week the seizure does read |
| `m7_erasure_mutant_invertible.pv` | M-7 | mutant: an invertible week ratchet | every query must fail |

**Not modelled here (design §22.18):** M-4 is a written argument by the design's own table; M-5
(session selection R-SS0 … R-SS4) is covered by the exhaustive state model EM-1 and has no ProVerif
model yet. M-7 uses key secrecy as the proxy for unlinkability; an equivalence model is future work.

**Abstractions, stated where they matter:** "a quantum adversary" is X25519 broken and ML-KEM-768
intact, so X-Wing is an ideal IND-CCA KEM and every classical layer (Olm) is transparent; HNDL and
healing are passive-adversary properties, modelled by reliable delivery on a private channel with
every message copied to the public one; binding v3 is classical authentication (PQ-R1) against the
active Dolev-Yao attacker. HKDF, HMAC and the AEADs are ideal functions.

The ProVerif release is pinned by version in `.github/workflows/pq-model.yml` and by SHA-256 in
`proverif.sha256`; ProVerif is a CI tool and is never shipped.
