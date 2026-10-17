#!/usr/bin/env bash
# Gate G-T2 (design faza12-transports.md §13): the reproducible double build, applied to
# lyrebird — two full BUILD.sh harness runs at the same paths must produce byte-identical
# binaries (the native library's rule). BUILD.sh already double-builds internally (same-path
# A/B per target, failing on any difference); this gate proves the property independently
# across two separate invocations, and — when the android outputs exist (the android job
# builds them) — that they still match the recorded SHA256SUMS.
# Build-dependent and network-dependent (first run fetches the pinned Go toolchain and
# source): the dispatch/weekly loopback job runs this; a host without the caches needs
# network. Usage: pt-double-build.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
LB="$GHOST_ROOT/third_party/lyrebird"

[ -f "$LB/BUILD.sh" ] || { fail "third_party/lyrebird/BUILD.sh missing"; finish pt-double-build; }

echo "[pt-double-build] run 1 (harness targets, same-path double build inside BUILD.sh)"
if ! (cd "$LB" && SKIP_ANDROID=1 HARNESS=1 bash BUILD.sh) >/tmp/pt-dbl-1.log 2>&1; then
  tail -10 /tmp/pt-dbl-1.log >&2 || true
  fail "BUILD.sh run 1 failed (see /tmp/pt-dbl-1.log)"
  finish pt-double-build
fi
h1="$(sha256sum "$LB"/out/SHA256SUMS.har | cut -d' ' -f1)"
cp "$LB/out/SHA256SUMS.har" /tmp/pt-dbl-sums-1.txt

echo "[pt-double-build] run 2"
if ! (cd "$LB" && SKIP_ANDROID=1 HARNESS=1 bash BUILD.sh) >/tmp/pt-dbl-2.log 2>&1; then
  tail -10 /tmp/pt-dbl-2.log >&2 || true
  fail "BUILD.sh run 2 failed (see /tmp/pt-dbl-2.log)"
  finish pt-double-build
fi
h2="$(sha256sum "$LB"/out/SHA256SUMS.har | cut -d' ' -f1)"

[ "$h1" = "$h2" ] || fail "the two harness builds differ (SHA256SUMS.har $h1 != $h2): lyrebird is not reproducible across runs"
echo "[pt-double-build] harness builds byte-identical across runs:"
cat "$LB/out/SHA256SUMS.har"

# The in-run double builds (A/B inside BUILD.sh) are asserted by BUILD.sh itself; prove they
# ran: the log of each run must carry the harness target line.
for n in 1 2; do
  grep -q 'lyrebird-windows-amd64\|lyrebird-linux-amd64' /tmp/pt-dbl-$n.log \
    || fail "run $n built no harness target (the double-build recipe did not run)"
done

# Android outputs, when present (the android job built them), must match the recorded sums.
if [ -f "$LB/out/lyrebird-android-arm64" ] && [ -f "$LB/out/lyrebird-android-amd64" ]; then
  (cd "$LB/out" && sha256sum -c <(grep 'lyrebird-android' "$LB/SHA256SUMS")) \
    || fail "the android outputs drifted from the recorded SHA256SUMS"
  echo "[pt-double-build] android outputs match the recorded SHA256SUMS"
else
  echo "[pt-double-build] android outputs absent: the recorded-sums half is the android job's (BUILD.sh runs there)"
fi

finish pt-double-build
