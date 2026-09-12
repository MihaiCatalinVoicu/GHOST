# Entitlement Schedule

The one Entitlement Schedule of this repository (Phase 8 design §3.1, §19.17 point 1) and the
relay directory it is checked against (§19.12 point 2, §19.20 point 4).

| File | What |
|---|---|
| `schedule.ghes` | ES seq 1, network **stagenet**, access weeks 2957..2989 (ISO 2026-W37 .. 2027-W16, 33 weeks), invite epochs 739..747, credit and price epochs 227..229, 3 relay slots, pack price 0.05 stagenet XMR (50 000 000 000 atomic units), constants at the design defaults. Signed by the stagenet schedule key of slice S2b. |
| `relay-directory.txt` | Every slot onion with its operator id. Staging: one party runs all three relays; the three operator ids are labels for the ">= 2 operators" rule, not independent operators. |

The stagenet schedule public key, pinned for the stagenet network only in
`ghost-entitlement` (`schedule.rs`, `PINNED_SCHEDULE_KEYS`):

```text
8b95a751974352372733718e49358be2f28bbc5c45d1bf4a4dd7b6c1664b7dad
```

`Schedule::verify` chooses the key by the schedule's signed network byte, so this key never
verifies a mainnet or regtest schedule. No mainnet key is pinned: the first mainnet ES needs the
K1 ceremony with the real offline key (Phase 16/17). The schedule key, the custody secret, the
sealed RSA keys and the onion service keys were generated with `ghost-issuer-ops` outside the
repository and are never committed (`entitlement-schedule.sh` refuses `*.ghks` and `*.ghkl`
files).

Verify (what `scripts/gates/entitlement-schedule.sh` runs, plus the git history for rule 5):

```sh
cargo run -p ghost-issuer-ops -- schedule-verify --schedule protocol/entitlement/schedule.ghes \
  --relay-directory protocol/entitlement/relay-directory.txt --now "$(date +%s)"
```

Runbook K2: the next version (seq 2) must reach an app release and every relay operator at least
8 weeks before week 2990, that is by week 2982 (Monday 2027-03-01). A later version keeps every
key, slot set, price and revocation of the weeks this one covers (rule 5).
