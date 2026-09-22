# Fixtures for the merged-manifest gate (T15m)

`scripts/gates/self-test.sh` passes these files to `scripts/gates/merged-manifest-lint.sh`:

- `AndroidManifest.xml` is a merged-manifest-shaped file with 16 violations, each marked by a
  comment (a permission outside the allowlist, a foreign permission declaration, the three
  application flags, a second launcher, an implicit export, the sync job exported and unprotected,
  exported library components, the two permissions the sync job needs left out, and — since Phase 9
  slice S12, gate G-DM7 — the DM expiry alarm's receiver left out). The gate must report exactly 16
  lines.
- `positive/AndroidManifest.xml` is the merged release manifest of `:app` as built at Phase 7, with
  the DM expiry alarm's receiver Phase 9 slice S12 declares; the gate must accept it, so a gate that
  fails on everything is caught too.
- `dm-receiver/AndroidManifest.xml` is the positive file with that receiver exported and given an
  intent filter: G-DM7 reports both, and T15m reports the unlisted export — exactly 3 lines.

Nothing here is compiled or shipped.
