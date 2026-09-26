# Fixtures for G-DM3's Kotlin half (dm-derivation-inputs.sh)

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing at each directory (Phase 9 design
§22.33 item 17). Each tree carries its own `scripts/gates/dm-derivation-inputs.allow`.

- `positive/`: a listed site written across lines with a trailing comma, a listed label, and a seed
  branch whose one `DerivationLabels` argument is on its own line (the abandoned gate read that as a
  violation). Passes.
- `negative-split-call/`: the evasion of a line-by-line reading — an HMAC keyed by a public key,
  its `SecretKeySpec(` call split across three lines. Exactly one violation, line 11.
- `negative-rules/`: one violation per rule, each in its own file, and an allowlist with a stale
  entry, an entry outside the DM modules and a malformed one — 13 violations, listed in
  `negative-rules/README.md`.
