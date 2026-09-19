# Licence gate fixtures (G-L1, G-L2, G-L4, G-R5)

This directory is a fixture `GHOST_ROOT` for `scripts/gates/license-notices.sh`,
`rust-license-headers.sh` and `mpl-sources.sh` (ADR-37; Phase 9 design §2.10.2, §22.8.10).
`scripts/gates/self-test.sh` runs them with `GHOST_LICENSE_PACKAGES` pointing at a package list in
`lists/` instead of cargo, and requires the named outcome and reason. Nothing here is compiled or
shipped; the licence texts under `licenses/spdx` are copies of `ghost/licenses/spdx`.

| File | Role |
|---|---|
| `deny.toml` | the fixture allow list: MIT, Apache-2.0, ISC, MPL-2.0 (no ISC text in `licenses/spdx`) |
| `Cargo.lock`, `registry/cache/fixture/*.crate` | checksums of the two MPL-2.0 packages and their archives (`CARGO_HOME` = this directory for `--bundle`) |
| `Cargo.toml` | a `[patch]` of `mpl-patched` without a published diff |
| `licenses/graphs.txt` | one graph, `fixture` |
| `licenses/THIRD_PARTY_NOTICES-fixture.txt` | the notices of `lists/positive.tsv` |
| `licenses/THIRD_PARTY_NOTICES-android.txt` | the Gradle notices of the component that `self-test.sh` builds (a POM, a classes jar with a NOTICE and a published AAR whose root carries a licence text the classes jar does not) |
| `licenses/spdx/SOURCE.txt` | the SHA-256 of each fixture text: an edited text, one it does not record, or one it records and the tree has not, fails G-L1 |
| `licenses/upstream/` | an upstream NOTICE of `apache-pkg`, and an entry of `apache-dropped` whose file is missing |
| `licenses/vendored-licences.txt` | `vendored-pkg`'s `third_party/zlib/LICENSE` included |
| `licenses/mpl-sources*.txt` | MPL-2.0 manifests: correct, wrong checksum, empty, patched package |
| `packages/`, `headers/` | package sources |

| Gate | List | Outcome | Reason |
|---|---|---|---|
| license-notices rust | `positive.tsv` | pass | notices equal; the upstream NOTICE and the vendored licence are carried, `dual-pkg`'s LICENSE-APACHE is not |
| license-notices rust | `differs.tsv` | fail | `differs from the regenerated notices` |
| license-notices rust | `no-text.tsv` | fail | `no text for licence ISC` |
| license-notices rust | `dropped-notice.tsv` | fail | `dropped NOTICE` |
| license-notices rust | `no-snapshot.tsv` | fail | `without an upstream NOTICE snapshot entry` |
| license-notices rust | `undecided-vendored.tsv` | fail | `a licence file of vendored sources` not decided |
| license-notices rust | `copyleft.tsv` | fail | `no alternative of 'GPL-3.0-only' is an allowed licence` |
| rust-license-headers | `headers.tsv` with `headers-exceptions.txt` | fail, exactly 5 lines | AGPL header, Signal Messenger copyright, GPL notice across comment lines, GPL text, no allowed alternative; `excepted` (an LGPL header with an exception) and `clean` pass |
| rust-license-headers | `headers-own.tsv` with `headers-exceptions-unused.txt` | fail | GHOST's own crates are scanned; an exception that matches nothing fails |
| mpl-sources | `mpl.tsv` (manifests as named in `self-test.sh`) | pass, then fail | missing line, wrong checksum; `mit-only.tsv`: stale line; `mpl-patched.tsv`: `[patch]` without a diff; `--bundle` copies `mpl-pkg-1.0.0.crate` |
| license-notices rust | `positive.tsv` on a copy with an edited `licenses/spdx` | fail | `does not match the SHA-256 that SOURCE.txt records`, `SOURCE.txt records no SHA-256 for it`, `is missing; SOURCE.txt records it` |
| license-notices android | the component `self-test.sh` builds | pass, then fail | the notices carry the AAR-root licence text; without the published AAR in the cache: `no aar or jar of the component in the Gradle cache` |
