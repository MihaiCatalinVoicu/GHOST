# ch-derivation fixtures (gate G-M3, `scripts/gates/ch-derivation-inputs.sh`)

Each directory is a `GHOST_ROOT` for the gate (`client-core/mls/src`, and Android sources where a
case needs them). `positive` passes (typed inputs, a declaration split over lines, a declaration
inside a comment and inside a string that must not count, the two exports, `:identity`'s pseudonym
label, and the hint label `ghost/v1/ch-hint`, the one channel label Kotlin may hold, CS-S5, CS-S6);
every other directory breaks one rule: `raw-key` (a `&[u8]` key, the signature split over lines),
`public-elsewhere` (`OpenInviteSalt` keying another derivation), `outside` (a `derive_*` function and
an HKDF outside `derive.rs`, the HKDF path split over lines), `exporter` (an export under another
label, and one outside `group.rs`), `kotlin` (two channel labels in Kotlin literals, beside the hint
label, which must not count). Added by the review of S2a (F6, rules 2 and 5): `helper-untyped`
(`expand_untyped(ikm: &[u8])` calling the HKDF helper), `second-param` (a `derive_*` function keyed by
its second, untyped parameter), `macro` (a derivation a `macro_rules!` generates), `other-names`
(`hkdf::SimpleHkdf` in `seal.rs` and the provider's `hkdf_expand` in `group.rs`), `from-bytes` (T36's
scenario: `EpochExport::from_bytes(*channel_id)` in `seal.rs`, which no `typed-key-sites.txt` pins).
`scripts/gates/self-test.sh` checks the violation count and text of each.
