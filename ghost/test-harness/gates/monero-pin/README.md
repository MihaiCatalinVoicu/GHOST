# monero-pin.sh fixtures

Each directory is a fixture root that mirrors the repository: `<case>/ghost` is `GHOST_ROOT`, the
workflows are in `<case>/.github/workflows`. `scripts/gates/self-test.sh` runs the gate on each
root and requires the named outcome and reason. The hashes are synthetic. Every root but
`missing-job` carries the complete job (pull-request paths; download, `sha256sum -c`, then
extraction), so each fails only for its own reason.

| case | outcome | reason |
|---|---|---|
| positive | pass | a well-formed pin; the job and a Dockerfile read it and check the archive between download and extraction |
| no-pin | fail | `monero-release.pin missing` |
| malformed | fail | `malformed SHA-256` (63 digits) |
| no-linux | fail | `no linux-x64 archive` |
| second-hash | fail | `second copy of a pinned SHA-256` (a compose file, in upper case) |
| unpinned-fetch | fail | `fetches Monero binaries without reading` |
| own-archive | fail | `a Monero archive name of its own` |
| missing-job | fail | `the regtest workflow is missing` |
| job-no-check | fail | `does not check the archive with sha256sum -c` |
| job-comment-check | fail | `does not check the archive with sha256sum -c` (the check only in a comment; S5-SEC-2) |
| job-check-after-extract | fail | `checks the archive with sha256sum -c only before its download or after its extraction` (S5-SEC-2) |
| job-paths | fail | `pull_request paths miss ghost/Cargo.lock` (S5-SEC-4) |
| dlsrc-templated | fail | `fetches Monero binaries without reading` (dlsrc.getmonero.org, an archive name built from a variable, a hash of its own; S5-MON-3, S5-SEC-3) |
| dockerfile-no-check | fail | `fetches Monero binaries without checking them with sha256sum -c` (an issuer Dockerfile reads the pin, never checks; S5-MON-3) |
| monero-image | fail | `a Monero image not built from` (a compose service runs a Monero image of its own; S5-SEC-3) |
