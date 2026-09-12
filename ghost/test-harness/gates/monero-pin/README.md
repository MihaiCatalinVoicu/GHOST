# monero-pin.sh fixtures

Each directory is a fixture root that mirrors the repository: `<case>/ghost` is `GHOST_ROOT`, the
workflows are in `<case>/.github/workflows`. `scripts/gates/self-test.sh` runs the gate on each
root and requires the named outcome and reason. The hashes are synthetic.

| case | outcome | reason |
|---|---|---|
| positive | pass | a well-formed pin; the job and a Dockerfile read it |
| no-pin | fail | `monero-release.pin missing` |
| malformed | fail | `malformed SHA-256` (63 digits) |
| no-linux | fail | `no linux-x64 archive` |
| second-hash | fail | `second copy of a pinned SHA-256` (a compose file, in upper case) |
| unpinned-fetch | fail | `fetches Monero binaries without reading` |
| own-archive | fail | `a Monero archive name of its own` |
| missing-job | fail | `the regtest workflow is missing` |
| job-no-check | fail | `does not check the archive with sha256sum -c` |
