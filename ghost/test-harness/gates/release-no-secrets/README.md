# Fixture roots for `release-no-secrets.sh` (G-D1)

Each root mirrors the scanned layout (`android/app/build.gradle.kts`, `scripts/`,
`infra/mirror/`, a carve-out under `protocol/test-vectors/apk/` proving the carve-out).
Run by `scripts/gates/self-test.sh` through the GHOST_D1_ROOT hook.

| Root | Expected |
|---|---|
| `clean` | passes (a copy of the real signing-free tree) |
| `pem-key` | fails: an OpenSSH private-key header outside the carve-outs |
| `keystore-magic` | fails: a JKS keystore by magic, no extension |
| `signed-release` | fails: the release build type gains a signingConfig |
| `signer-script` | fails: a script invokes apksigner |
