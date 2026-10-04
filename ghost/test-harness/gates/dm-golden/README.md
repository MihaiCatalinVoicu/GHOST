# Fixtures: dm-golden-lock.sh --library (G-R7 (c))

Used by `scripts/gates/self-test.sh` (Phase 9 design §16.1 G-R7, §2.9, §22.33). Each `.bin` file stands
in for a stripped `libghost_client_net.so`: the gate only searches its bytes for strings.
`hpke-dropped.bin` holds Olm's two KDF labels and nothing of HPKE (passes); `hpke-linked.bin` also
holds the two strings only RustCrypto's `hpke` and vodozemac's HPKE and QR-login code carry
(`HPKEXXYYZZ`, `MATRIX_QR_CODE_LOGIN`: two violations); `hpke-rs-linked.bin` is the shape of the
library from Phase 10 slice S2b on — Olm's labels and OpenMLS's `hpke-rs` RFC 9180 labels
(`HPKE-v1`, `psk_id_hash`), which no longer count as RustCrypto's `hpke` (passes; faza10-forum.md
§19.32); `no-olm.bin` holds neither Olm label (two violations: the check would pass vacuously).
Nothing here is compiled or shipped.
