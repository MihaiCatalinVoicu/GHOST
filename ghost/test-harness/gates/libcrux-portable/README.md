# Fixtures for the libcrux-portable gate (G-R3)

Used by `scripts/gates/self-test.sh` (Phase 9 design §16.1 G-R3, §22.33). `*.json` stand in for a host
build's `cargo --message-format=json` stream: `portable.json` (the three packages without SIMD cfgs,
and a longer package name with one, which must not count), `simd.json` (`simd256` on all three) and
`missing.json` (no `libcrux-intrinsics`); `portable-path.json` and `simd-path.json` are the same
streams in upstream's workspace layout, where `libcrux-ml-kem`'s id is `path+file:///…/libcrux-ml-kem#0.0.10`
(the libcrux suites of `scripts/ci/vendor-tests.sh`, §22.35), without and with `simd256` on it. `dir-*` stand in for a cargo-ndk profile directory:
`dir-portable` (one empty output per package, a build-script directory with no output, a decoy),
`dir-simd` (`simd128` in both directive syntaxes), `dir-stale` (two outputs of one package) and
`dir-empty` (no libcrux build). The repository ignores `build/`: the files under `dir-*/build/` were
added with `git add -f`. Nothing here is compiled or shipped.

G-M9 (Phase 10 design §13.1, S0-8; slice S2a) adds `libcrux-aes`, required with `--with-aes`:
`aes-portable.json` (the three packages and `libcrux-aes` portable, plus `libcrux-aesgcm` with
`simd256`, a different name that must not count), `aes-simd.json` (`simd256` on `libcrux-aes` only,
checked with or without `--with-aes`) and `dir-aes-simd` (`simd128` in `libcrux-aes`'s output). Run with
`--with-aes`, `portable.json` and `dir-portable` must fail for the missing `libcrux-aes`.
