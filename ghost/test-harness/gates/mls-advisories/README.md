# Fixtures for scripts/ci/mls-advisories.sh (the GHSA watch of G-M1)

Used by `scripts/gates/self-test.sh` (Phase 10 design faza10-forum.md §13.1 G-M1, S0-2; slice S2a),
offline, through the script's hooks: `lock.toml` pins openmls 0.9.0, hpke-rs 0.7.0 and libcrux-aes
0.0.9 (`GHOST_ADV_LOCK`). `clean/` has GitHub advisories fixed before the pins (one published, one
draft that must not count), a RustSec entry fixed at the pin, and an entry filed under the former
name `libcrux-aesgcm` with `patched = []` that `clean/reviewed.txt` accounts for: it passes, and with
`empty-reviewed.txt` it fails. `open-ghsa/` has an OpenMLS advisory whose range contains 0.9.0;
`former-ghsa/` a GitHub advisory under the former name whose range contains libcrux-aes 0.0.9.
