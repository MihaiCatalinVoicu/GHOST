# Fixture release outputs for `public-identity-scrub.sh`

Each directory is a fake release output (`GHOST_ROOT`), run by
`scripts/gates/self-test.sh`.

| Root | Expected |
|---|---|
| `clean` | passes: binaries and notices carry no identity pattern |
| `infested` | fails: a binary carries the private repository's URL |

The `--committed` mode is intentionally not fixture-tested: by the design's
own note (D25) the committed files it checks name the owner today, so it must
fail until the S3 project-identity slice changes them.
