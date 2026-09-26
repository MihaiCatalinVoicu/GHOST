# Fixtures for the libcrux-portable gate (G-R3)

Used by `scripts/gates/self-test.sh` (Phase 9 design §16.1 G-R3, §22.33). `*.json` stand in for a host
build's `cargo --message-format=json` stream: `portable.json` (the three packages without SIMD cfgs,
and a longer package name with one, which must not count), `simd.json` (`simd256` on all three) and
`missing.json` (no `libcrux-intrinsics`). `dir-*` stand in for a cargo-ndk profile directory:
`dir-portable` (one empty output per package, a build-script directory with no output, a decoy),
`dir-simd` (`simd128` in both directive syntaxes), `dir-stale` (two outputs of one package) and
`dir-empty` (no libcrux build). The repository ignores `build/`: the files under `dir-*/build/` were
added with `git add -f`. Nothing here is compiled or shipped.
