#!/usr/bin/env bash
# Gate: **every GitHub Actions workflow parses as YAML and has the shape GitHub needs.**
#
# Why this gate exists. Phase 9's S10b merge left a header comment of `messaging-exit-gate.yml`
# wrapped onto a second line that had lost its `#`. That is not a YAML file any more, GitHub answers
# "this run likely failed because of a workflow file issue", and the run never starts — not a red
# job, no job at all. The DM exit gate therefore did not run on three consecutive merges to `main`,
# and nothing local noticed, because no local step parsed a workflow: the other gates read shell,
# Kotlin and Rust. A CI file that cannot start is the one failure a CI file cannot report itself.
#
# What it checks, per `.github/workflows/*.yml|*.yaml`:
#   - the file parses (PyYAML `safe_load`);
#   - it is a mapping with a trigger (`on:`; PyYAML reads that key as the boolean `True`, which
#     is accepted) and a non-empty `jobs:` mapping;
#   - every job is a mapping with `runs-on` or `uses` (a reusable-workflow call);
#   - every job that is not a reusable-workflow call has a non-empty `steps:` list in which every
#     step has `uses` or `run`.
# This is a structural lint, not actionlint: it does not check expressions, action inputs or
# permissions. It exists to catch "the file cannot start", which is the case that costs the most.
#
# Vacuity: no workflow file at all fails. The parser is python3 with PyYAML, present on the
# self-hosted runners and on GitHub's Ubuntu images. Where it is not (a Windows workstation), name a
# WSL distribution that has it with GHOST_YAML_VIA_WSL=<distro>; only as a last resort set
# GHOST_YAML_SKIP=1, which prints SKIPPED and passes — CI must never set it, and no CI file does.
#
# Usage: workflow-yaml.sh   (scans $GHOST_WORKFLOWS_DIR, default: <repo>/.github/workflows)
# Self-test: scripts/gates/self-test.sh points GHOST_WORKFLOWS_DIR at test-harness/gates/workflow-yaml/*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

WF_DIR="${GHOST_WORKFLOWS_DIR:-$GHOST_ROOT/../.github/workflows}"

PY='
import sys, yaml
try:
    d = yaml.safe_load(sys.stdin.read())
except Exception as e:
    print("unparseable: " + str(e).splitlines()[0][:160]); sys.exit(1)
if not isinstance(d, dict):
    print("not a mapping"); sys.exit(1)
if d.get("on", d.get(True)) is None:
    print("no `on:` trigger"); sys.exit(1)
jobs = d.get("jobs")
if not isinstance(jobs, dict) or not jobs:
    print("no jobs"); sys.exit(1)
for name, j in jobs.items():
    if not isinstance(j, dict):
        print("job %s is not a mapping" % name); sys.exit(1)
    if "runs-on" not in j and "uses" not in j:
        print("job %s has neither runs-on nor uses" % name); sys.exit(1)
    if "uses" in j:
        continue
    steps = j.get("steps")
    if not isinstance(steps, list) or not steps:
        print("job %s has no steps" % name); sys.exit(1)
    for i, s in enumerate(steps):
        if not isinstance(s, dict) or ("uses" not in s and "run" not in s):
            print("job %s step %d has neither uses nor run" % (name, i + 1)); sys.exit(1)
print("ok")
'
# The script travels as base64 so that no quoting layer (wsl.exe in particular) can alter it; the
# workflow travels on stdin.
PY_B64="$(printf '%s' "$PY" | base64 | tr -d '\n')"
LOADER="import base64,sys;exec(base64.b64decode(sys.argv[1]))"

validator=""
if python3 -c 'import yaml' >/dev/null 2>&1; then
  validator="python3"
elif [ -n "${GHOST_YAML_VIA_WSL:-}" ] && MSYS_NO_PATHCONV=1 wsl -d "$GHOST_YAML_VIA_WSL" -u runner -- python3 -c 'import yaml' >/dev/null 2>&1; then
  validator="wsl"
fi

if [ -z "$validator" ]; then
  if [ "${GHOST_YAML_SKIP:-}" = "1" ]; then
    echo "[workflow-yaml] SKIPPED: no YAML parser here (GHOST_YAML_SKIP=1). CI must not set this." >&2
    exit 0
  fi
  fail "no YAML parser: python3 with PyYAML is required (on a Windows workstation set GHOST_YAML_VIA_WSL=<a WSL distro that has it>)"
  finish workflow-yaml
fi

validate() { # $1 = file; prints the verdict, exits with the parser's status
  if [ "$validator" = "python3" ]; then
    python3 -c "$LOADER" "$PY_B64" < "$1"
  else
    MSYS_NO_PATHCONV=1 wsl -d "$GHOST_YAML_VIA_WSL" -u runner -- python3 -c "$LOADER" "$PY_B64" < "$1"
  fi
}

checked=0
if [ -d "$WF_DIR" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    checked=$((checked + 1))
    if ! verdict="$(validate "$f" 2>&1)"; then
      fail "$f: $verdict"
    fi
  done < <(find "$WF_DIR" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)
fi
[ "$checked" -gt 0 ] || fail "no workflow file found under $WF_DIR (a gate that scans nothing passes for the wrong reason)"
finish workflow-yaml
