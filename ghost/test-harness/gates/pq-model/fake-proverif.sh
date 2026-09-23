#!/usr/bin/env bash
# The self-test's stand-in for ProVerif (scripts/gates/pq-model.sh): it replays the output recorded
# beside the model as <model>.out, exits with <model>.rc when that exists, and sleeps
# <model>.sleep seconds first when that exists — the three ways a real run can end. A mutant the
# gate generated from a patch lives in the gate's work directory, so its recordings are looked up
# by name in the fixture directory ($PQ_MODEL_DIR) instead.
model="$1"
base="${model%.pv}"
if [ ! -f "$base.out" ] && [ ! -f "$base.rc" ] && [ -n "${PQ_MODEL_DIR:-}" ]; then
  base="$PQ_MODEL_DIR/$(basename "$base")"
fi
[ -f "$base.sleep" ] && sleep "$(cat "$base.sleep")"
[ -f "$base.out" ] && cat "$base.out"
if [ -f "$base.rc" ]; then exit "$(cat "$base.rc")"; fi
exit 0
