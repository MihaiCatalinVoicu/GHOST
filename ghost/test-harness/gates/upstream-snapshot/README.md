# Upstream snapshot fixture (`scripts/license-upstream-snapshot.sh`)

`scripts/gates/self-test.sh` copies `scripts/license-upstream-snapshot.sh` and
`scripts/gates/licenses.pl` into a scratch `GHOST_ROOT`, puts `bin/` on `PATH` (stubs for `gh` and
`cargo`, so nothing reaches the network) and runs the snapshot tool with
`GHOST_LICENSE_PACKAGES=lists/candidates.tsv`. The tool must record `none` only when the listing
really came back empty, and must stop when a listing fails (ADR-37; Phase 9 design §22.8.10 point 3:
a `none` entry is what lets G-L1 accept an Apache-2.0 package with no NOTICE reproduced).

| File | Role |
|---|---|
| `deny.toml` | the fixture allow list (MIT, Apache-2.0, ISC, MPL-2.0) |
| `packages/apache-vcs` | one package used under Apache-2.0, with a `.cargo_vcs_info.json` whose `path_in_vcs` is a directory, so both listings run |
| `lists/candidates.tsv` | the package list that stands in for cargo |
| `bin/gh` | the GitHub CLI stub; `GHOST_FIXTURE_GH` picks its behaviour |
| `bin/cargo` | a `cargo fetch` stub |

`GHOST_FIXTURE_GH` values: `empty` (both listings succeed with no NOTICE: the entry is `none`),
`dir-error` (the root listing succeeds, the package-directory listing fails: the tool must stop),
`root-error` (the root listing fails: the tool must stop).
