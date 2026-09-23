#!/usr/bin/env bash
# The self-test's stand-in for ProVerif (scripts/gates/pq-model.sh): it replays the output recorded
# beside the model as <model>.out, exits with <model>.rc when that exists, and sleeps
# <model>.sleep seconds first when that exists — the three ways a real run can end.
model="$1"
base="${model%.pv}"
[ -f "$base.sleep" ] && sleep "$(cat "$base.sleep")"
[ -f "$base.out" ] && cat "$base.out"
if [ -f "$base.rc" ]; then exit "$(cat "$base.rc")"; fi
exit 0
