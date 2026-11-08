#!/usr/bin/env bash
# selfcheck-android.sh — S4 verification of the builder image's Android half, run INSIDE the
# image (docs/design/faza14-distribution.md §6, gate G-D2). Two build-release-android.sh runs
# from the same image must produce byte-identical unsigned APKs and native libraries; this is
# the image-level half of the A/B equality (the other half is the independent machine, RK1).
#
# Expects: repo at /repo (read-only), writable /out, cargo registry seed at
# $CARGO_HOME/registry, a current sparse index (mounted read-only by the launcher),
# env JAVA_HOME/ANDROID_* baked into the image, tag refs/tags/builder-selfcheck already
# present in the mounted repo (created on the host — the mount is read-only).
# Gradle downloads its dependencies from google()/mavenCentral(); digests are enforced by
# gradle/verification-metadata.xml (run 1 populates $GRADLE_USER_HOME inside its work dir —
# run 2 downloads again; the digests, not the cache, are the pin).
set -euo pipefail
cd /repo/ghost
echo "=== selfcheck-android start $(date -u) $(git rev-parse --short HEAD)"

rm -rf /out/AA /out/AB
echo "--- android recipe run 1"
bash scripts/release/build-release-android.sh builder-selfcheck --out /out/AA
echo "--- android recipe run 2"
bash scripts/release/build-release-android.sh builder-selfcheck --out /out/AB

echo "--- compare"
ok=1
# The android subset in §6.1's layout: the zip-aligned unsigned APK, the stripped libraries
# with their checksum record, and the split debug info. Everything byte-compares.
for f in /out/AA/apk/*-unsigned.apk; do
  name="$(basename "$f")"
  if cmp -s "$f" "/out/AB/apk/$name"; then
    echo "EQUAL apk/$name $(sha256sum "$f" | cut -c1-16)"
  else
    echo "DIFFER apk/$name"
    ok=0
  fi
done
for dir in lib symbols; do
  if diff -r "/out/AA/$dir" "/out/AB/$dir" >/dev/null 2>&1; then
    echo "EQUAL $dir/ $(find "/out/AA/$dir" -type f | wc -l) files"
  else
    echo "DIFFER $dir/"
    diff -r "/out/AA/$dir" "/out/AB/$dir" || true
    ok=0
  fi
done
# The unsigned APK must carry the exact native bytes the checksum record lists.
(cd /out/AA/lib && sha256sum -c native-libs.sha256) || ok=0

if [ "$ok" = 1 ]; then
  echo "ANDROID_SELFCHECK_EQUAL apk=$(sha256sum /out/AA/apk/*-unsigned.apk | cut -c1-16)"
  echo "=== selfcheck-android PASS $(date -u)"
else
  echo "=== selfcheck-android FAIL $(date -u)"
  exit 1
fi
