#!/usr/bin/env bash
# Gate G-DM2 (Phase 9 design §16.1, §21.7, §21.9; invariants T28 "no reflex" and T31 "read
# confinement"): **the calls that cause relay-visible behaviour are made only from the steps that
# are allowed to cause it.**
#
#   Outbox.enqueue, Registrations.request, Registrations.rearm, Namespaces.register,
#   Namespaces.setListening and Capabilities.put
#       only from SEND, RESEND, EST-START, EST-READY, EST-END, OWNER-WEEK, ACTIVATE, KEEPER,
#       REGROWS
#   Namespaces.remove
#       the same, and also from SWEEP
#
# and from none of RECV, BUNDLE, HELD, the apply code or the store layer.
#
# **Why this is a gate and not only a test.** T28 says relay-visible behaviour is identical
# whatever arrives in the inbox: no store, redemption, registration or reschedule may be *caused*
# by a blob. `NoReflexTest` is the behavioural half — it compares two worlds — but a world only
# finds the reflex it happens to exercise, and a new call site added under a new condition is
# exactly what it would not exercise. This half reads the source instead: a call from a file that
# is not on the allowlist fails before the world is ever built.
#
# **What it reads.** Every Kotlin and Java source on the Android production path (`*/src/main/*`)
# of `android/messaging` and `android/app`, which are the two modules §13.1 lets drive the DM
# engine. `android/sync` is deliberately **not** scanned: it *defines* these functions, and its own
# engine calls them for the Phase 7 reasons (a capability arriving from the entitlement layer, a
# namespace the directory repairs), which T19 and the Phase 7 gates cover. `android/entitlement`
# is not scanned either: it installs the capabilities it redeems, which is its whole job.
#
# **The allowlist is by file, not by function.** A Kotlin file holds one step in this codebase, the
# DM engine's files are named after the transactions of §7.2, and matching a call to the enclosing
# function would need a parser — with a parser's blind spots around lambdas, local functions and
# expression bodies. A file named after a step, holding that step, is the unit the design itself
# uses ("`SendStep`, `ReceiveStep`, `BundleStep`, …", §13.1).
#
# **Slice S6 (2026-09-20).** The mechanism is built and armed now; the corpus is partial, because
# S7 has not landed. What exists today and is really checked: `OwnerSteps.kt`, which holds
# ACTIVATE, OWNER-WEEK, KEEPER and REGROWS and calls five of the six restricted functions. What is
# **not** exercisable yet: the forbidden side of the rule, since no RECV, BUNDLE or HELD file
# exists to call one of these functions wrongly. The gate is written so that the day those files
# land they are refused unless they are added to the allowlist deliberately — the allowlist names
# the files that MAY call, so a new file is refused by default. The self-test proves the forbidden
# side against fixtures. Recorded in the design as §22.11.
#
# Usage: dm-enqueue-callers.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/negative-dm-enqueue-*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# The restricted calls, as they are written at a call site. Each is matched as `.name(` after a
# receiver, or as a bare `name(` on a line that also names the interface — the DM engine writes
# `sync.namespaces.register(...)` and `Namespaces.register` never appears bare.
RESTRICTED='\.(enqueue|request|rearm|register|setListening|put)[[:space:]]*\('
# `remove` is the one call SWEEP may make as well, so it is matched separately.
REMOVE='\.(remove)[[:space:]]*\('

# A receiver that makes the match a **DM** call rather than any `.put(` on a map. The call sites of
# this codebase always go through a named port; a call on something else is not one of these six.
RECEIVERS='outbox|registrations|namespaces|capabilities'

# Files that MAY make the restricted calls: the steps of §7.2 that §16.1 names. A file not on this
# list is refused, which is what makes a new step arrive deliberately rather than by accident.
# Every entry names the transactions it holds.
ALLOWED_FILES='
OwnerSteps.kt          ACTIVATE, OWNER-WEEK, KEEPER, REGROWS (slice S6)
SendStep.kt            SEND, RESEND (slice S7)
EstablishmentSteps.kt  EST-START, EST-READY, EST-END (slice S7)
Sweeper.kt             SWEEP; may call Namespaces.remove only (slices S7, S9)
MessagingWiring.kt     the app wiring: registers nothing itself, named so :app can hold the port
'
# Of those, the files that may call `Namespaces.remove`.
REMOVE_ALLOWED='OwnerSteps.kt SendStep.kt EstablishmentSteps.kt Sweeper.kt MessagingWiring.kt'

allowed_file() { # $1 = basename
  local name
  while read -r name _; do
    [ -n "$name" ] || continue
    [ "$name" = "$1" ] && return 0
  done <<< "$ALLOWED_FILES"
  return 1
}

remove_allowed() { # $1 = basename
  case " $REMOVE_ALLOWED " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

# The production sources of the two modules that drive the DM engine. `find` at any depth, like
# dm-no-fts.sh: a nested module must not go unscanned while the others satisfy the vacuity floor.
dm_caller_files() {
  find "$GHOST_ROOT/android/messaging" "$GHOST_ROOT/android/app" \
    -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) -path '*/src/main/*' -print 2>/dev/null || true
}

SCANNED=0
WITH_CALL=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  rel="${file#"$GHOST_ROOT"/}"
  base="${file##*/}"
  SCANNED=$((SCANNED + 1))

  # Each hit is read from a variable and matched with a here-string, never `producer | grep -q`:
  # under `set -o pipefail` such a pipeline fails whenever grep stops reading early (EPIPE), the
  # race the static-gate sweep of 2026-09-20 removed from five other gates.
  hits="$(grep -nE -- "$RESTRICTED" "$file" || true)"
  restricted_hits=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    [[ "$line" =~ ($RECEIVERS)\.[a-zA-Z] ]] || continue
    restricted_hits+="$line"$'\n'
  done <<< "$hits"

  hits="$(grep -nE -- "$REMOVE" "$file" || true)"
  remove_hits=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    [[ "$line" =~ ($RECEIVERS)\.[a-zA-Z] ]] || continue
    remove_hits+="$line"$'\n'
  done <<< "$hits"

  if [ -n "$restricted_hits" ] || [ -n "$remove_hits" ]; then
    WITH_CALL=$((WITH_CALL + 1))
  fi

  if [ -n "$restricted_hits" ] && ! allowed_file "$base"; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      fail "$rel:$line (G-DM2: only the SEND, RESEND, EST-*, OWNER-WEEK, ACTIVATE, KEEPER and REGROWS steps may enqueue, register, listen or install)"
    done <<< "$restricted_hits"
  fi
  if [ -n "$remove_hits" ] && ! remove_allowed "$base"; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      fail "$rel:$line (G-DM2: only those steps and SWEEP may call Namespaces.remove)"
    done <<< "$remove_hits"
  fi
done < <(dm_caller_files)

# Vacuity, twice over, because a gate that scans nothing passes. At least one production source of
# the DM modules must be found, and at least one of them must really make one of the restricted
# calls — the day `OwnerSteps.kt` moves or is renamed, this gate must fail rather than go quiet.
[ "$SCANNED" -gt 0 ] || fail "no DM production sources found under $GHOST_ROOT/android (the gate would pass vacuously)"
[ "$WITH_CALL" -gt 0 ] || \
  fail "none of the $SCANNED scanned DM sources makes a restricted call (the gate would pass vacuously; see the S6 note in this script)"

finish dm-enqueue-callers
