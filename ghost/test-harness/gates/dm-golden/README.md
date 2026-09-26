# Fixtures: dm-golden-lock.sh --library (G-R7 (c))

Used by `scripts/gates/self-test.sh` (Phase 9 design §16.1 G-R7, §2.9, §22.33). Each `.bin` file stands
in for a stripped `libghost_client_net.so`: the gate only searches its bytes for strings.
`hpke-dropped.bin` holds Olm's two KDF labels and nothing of HPKE (passes); `hpke-linked.bin` also
holds two of the HPKE strings V-9 found only when the linker kept `hpke` (two violations);
`no-olm.bin` holds neither label (two violations: the check would pass vacuously). Nothing here is
compiled or shipped.
