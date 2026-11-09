# Fixture A/B trees for `release-sums.sh` (G-D3)

Each `pair-*` directory holds an A/ and a B/ release-output tree (SHA256SUMS, apk/, lib/,
symbols/ — the ELFs are hand-built fixtures carrying .note.gnu.build-id notes). Run by
`scripts/gates/self-test.sh`. The gate takes the directories as arguments, so no env hook
is needed.

| Pair | Expected |
|---|---|
| `pair-equal` | passes: byte-equal trees |
| `pair-diff` | fails: the SHA256SUMS differ |
| `pair-missing` | fails: B's tree misses the symbols (incomplete sums) |
| `pair-libmismatch` | fails: the APK's lib entries differ from lib/ |
| `pair-buildid` | fails: the symbol file's build-id is not the library's |
