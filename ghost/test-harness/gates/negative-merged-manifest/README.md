# Fixtures for the merged-manifest gate (T15m)

`scripts/gates/self-test.sh` passes these files to `scripts/gates/merged-manifest-lint.sh`:

- `AndroidManifest.xml` is a merged-manifest-shaped file with 15 violations, each marked by a
  comment (a permission outside the allowlist, a foreign permission declaration, the three
  application flags, a second launcher, an implicit export, the sync job exported and unprotected,
  exported library components, and the two permissions the sync job needs left out). The gate
  must report exactly 15 lines.
- `positive/AndroidManifest.xml` is the merged release manifest of `:app` as built at Phase 7; the
  gate must accept it, so a gate that fails on everything is caught too.

Nothing here is compiled or shipped.
