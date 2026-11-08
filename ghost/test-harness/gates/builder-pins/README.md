# Fixture roots for `builder-pins.sh` (G-D2)

Each directory mirrors the layout G-D2 scans: `infra/builder/{Dockerfile,pins.txt}`,
`rust-toolchain.toml`, `android/gradle/wrapper/gradle-wrapper.properties`,
`scripts/install-protoc.sh`, `scripts/build-native.sh`,
`scripts/release/build-release.sh`. The `clean` tree is a copy of the real files at
slice time; each negative is one clause's violation. Run by `scripts/gates/self-test.sh`
through the GHOST_BP_ROOT hook (fixture roots only).

| Root | Expected |
|---|---|
| `clean` | passes (a copy of the real tree) |
| `from-drift` | fails: the Dockerfile's FROM is not the pinned image digest |
| `unpinned-download` | fails: a Dockerfile layer downloads without a digest check |
| `wrong-rust` | fails: rust-toolchain.toml's channel disagrees with the pins |
| `native-flag` | fails: `-march=native` enters a build file |
