#!/usr/bin/env bash
# dm-fuzz (Phase 9 design §16.2 `dm-fuzz`, §9.5 M-8, §22.8.10 point 9 = IMPL-12, §22.35): runs every
# cargo-fuzz target of client-core/dm/fuzz for a fixed time, each from its committed seeds
# (client-core/dm/fuzz/corpus-seeds/<target>), on the dated nightly of that crate's
# rust-toolchain.toml, with AddressSanitizer and debug assertions (an arithmetic overflow on an
# attacker length panics), and fails the run on a crash, a timeout, an out-of-memory, or a target
# that executed nothing or printed no statistics.
#
# Usage: dm-fuzz.sh <seconds per target> <work dir> [target...]
#        dm-fuzz.sh --verdict <libFuzzer log> <exit code>
# The first form writes <work dir>/<target>.log, <work dir>/corpus/<target> (the seeds plus what
# the run added) and <work dir>/artifacts/<target>/ (a failing input, if any), and prints one line
# per target: "<target>: <seconds> s, <executions> executions, <exec/s> exec/s, cov <n>, <verdict>".
# The second prints the verdict of one run ("PASS <executions>" or "FAIL <reason>") and exits 0 on
# PASS, 1 on FAIL: the decision the first form applies, alone, for scripts/gates/self-test.sh.
# Requires: cargo-fuzz on PATH (the workflow installs the pinned version), a C++ compiler.
set -euo pipefail

TARGETS=(card bundle intro_inner l0 tlvs olm_message)

# The last value of libFuzzer's final statistic `stat::<name>:` in a log, or nothing.
stat_of() {
  { grep -oE "^stat::$1: +[0-9]+" "$2" || true; } | tail -1 | awk '{print $2}'
}

# The verdict of one libFuzzer run, from its log and the exit code of `cargo fuzz run`.
verdict() {
  local log="$1" code="$2" executions
  if [ ! -r "$log" ]; then
    echo "FAIL no log"
    return 1
  fi
  if grep -q 'ERROR: libFuzzer: timeout' "$log"; then
    echo "FAIL timeout"
    return 1
  fi
  if grep -qE 'ERROR: libFuzzer: (out-of-memory|malloc limit)|allocation-size-too-big|ERROR: AddressSanitizer: (out of memory|allocator is out of memory|requested allocation size)' "$log"; then
    echo "FAIL out-of-memory"
    return 1
  fi
  if grep -qE "ERROR: libFuzzer: (deadly signal|fuzz target exited|crash|leak)|ERROR: (Address|Undefined|Leak)Sanitizer|^SUMMARY: [A-Za-z]+Sanitizer|panicked at" "$log"; then
    echo "FAIL crash"
    return 1
  fi
  executions="$(stat_of number_of_executed_units "$log")"
  if [ -z "$executions" ]; then
    echo "FAIL no statistics (the run did not finish: exit $code)"
    return 1
  fi
  if [ "$executions" -eq 0 ]; then
    echo "FAIL zero executions"
    return 1
  fi
  if [ "$code" != 0 ]; then
    echo "FAIL exit $code"
    return 1
  fi
  echo "PASS $executions"
}

if [ "${1:-}" = "--verdict" ]; then
  [ "$#" -eq 3 ] || { echo "usage: dm-fuzz.sh --verdict <log> <exit code>" >&2; exit 2; }
  verdict "$2" "$3"
  exit $?
fi

SECONDS_PER_TARGET="${1:?usage: dm-fuzz.sh <seconds per target> <work dir> [target...]}"
WORK_ARG="${2:?usage: dm-fuzz.sh <seconds per target> <work dir> [target...]}"
shift 2
[ "$#" -gt 0 ] && TARGETS=("$@")
case "$SECONDS_PER_TARGET" in '' | *[!0-9]* | 0) echo "seconds per target: a positive integer" >&2; exit 2 ;; esac
GHOST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FUZZ_DIR="$GHOST_ROOT/client-core/dm/fuzz"
mkdir -p "$WORK_ARG"
WORK="$(cd "$WORK_ARG" && pwd)"
command -v cargo-fuzz >/dev/null || { echo "cargo-fuzz not found" >&2; exit 2; }

# The longest input each target reads: a card link, a bundle envelope, the intro inner layer of
# the 4 096-byte bucket, an L0, a TLV list at the receiving cap, an Olm message in an envelope.
max_len() {
  case "$1" in
    card) echo 300 ;;
    bundle | intro_inner | olm_message) echo 4200 ;;
    l0) echo 8192 ;;
    tlvs) echo 2600 ;;
    *) echo 4096 ;;
  esac
}

failures=0
cd "$FUZZ_DIR"
cargo fuzz build --debug-assertions 1>&2
for target in "${TARGETS[@]}"; do
  [ -d "corpus-seeds/$target" ] || { echo "$target: no seeds in corpus-seeds/$target" >&2; failures=$((failures + 1)); continue; }
  corpus="$WORK/corpus/$target"
  artifacts="$WORK/artifacts/$target"
  log="$WORK/$target.log"
  mkdir -p "$corpus" "$artifacts"
  for seed in "corpus-seeds/$target/"*; do
    [ -e "$corpus/${seed##*/}" ] || cp "$seed" "$corpus/"
  done
  code=0
  cargo fuzz run --debug-assertions "$target" "$corpus" -- \
    -max_total_time="$SECONDS_PER_TARGET" -timeout=10 -rss_limit_mb=2048 \
    -max_len="$(max_len "$target")" -print_final_stats=1 \
    -artifact_prefix="$artifacts/" > "$log" 2>&1 || code=$?
  result="$(verdict "$log" "$code" || true)"
  rate="$(stat_of average_exec_per_sec "$log")"
  cov="$({ grep -oE ' cov: [0-9]+' "$log" || true; } | tail -1 | awk '{print $2}')"
  executions="$(stat_of number_of_executed_units "$log")"
  echo "$target: $SECONDS_PER_TARGET s, ${executions:-0} executions, ${rate:-0} exec/s, cov ${cov:-0}, $result"
  case "$result" in PASS*) ;; *) failures=$((failures + 1)); ls "$artifacts" >&2 || true ;; esac
done
[ "$failures" -eq 0 ] || { echo "dm-fuzz: $failures target(s) failed" >&2; exit 1; }
