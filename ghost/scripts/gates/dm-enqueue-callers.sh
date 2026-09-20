#!/usr/bin/env bash
# Gate G-DM2 (Phase 9 design §16.1, §21.7, §21.9; invariants T28 "no reflex" and T31 "read
# confinement"): **the calls that cause relay-visible behaviour are made only from the steps that
# are allowed to cause it.**
#
#   Outbox.enqueue, Outbox.cancel, Registrations.request, Registrations.keep, Registrations.rearm,
#   Registrations.forget, Namespaces.register, Namespaces.setRelays, Namespaces.setListening,
#   Namespaces.setSendDelay and Capabilities.put
#       only from SEND, RESEND, EST-START, EST-READY, EST-END, OWNER-WEEK, ACTIVATE, KEEPER,
#       REGROWS
#   Namespaces.remove
#       the same, and also from SWEEP
#   Messaging.runOwnerMaintenance, Messaging.onActivated, Messaging.onRestored
#       only from the app wiring and the DM actor — the actor timer, a database open, a relay
#       session start and the K20 hook of §21.9 rule 1 and §13.4
#
# and from none of RECV, BUNDLE, HELD, the apply code or the store layer.
#
# **Why the third rule** (added by the review of S6). The first two say which files may make a
# relay-visible call. Without the third, a file that may not could still *reach* one through the
# facade: `engine.runOwnerMaintenance()` on an inbound blob walks into OWNER-WEEK and
# `Outbox.enqueue` while the restricted call itself stays inside the allowlisted `OwnerSteps.kt`,
# so a card holder with AD-1 who deposits a probe makes a bundle appear a minute later whenever
# `t_pub(w)` has passed. That is mutants PM-11 and PM-30 exactly, and the behavioural half that
# would catch it (`NoReflexTest`) is S7's.
#
# **Why these names.** §22.11 item 8 lists six; the set here is wider, because the review of S6
# found three more that are as relay-visible as the six and that S6's own owner steps already make:
# `setRelays` "replaces the relay set and repairs deliveries" (`:sync` `Namespaces`), `forget`
# deletes registration rows the work lane would otherwise run, and `setSendDelay` moves the ADR-15
# delay that keeps a store from naming the moment the user pressed send. `cancel` withdraws a
# delivery. `keep` is `request` with the slot-change replacement (§5.2), added by the same review.
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
# **How a call site is recognized, and what still escapes.** A physical line is joined with the
# lines that follow it while they begin with `.`, so a receiver and its call may sit on separate
# lines (the violation is reported at the receiver's line). A line is a call site when it names one
# of the four ports beside a restricted call, when it calls one through a **local alias** of a port
# (`val ob = sync.outbox; ob.enqueue(…)`), or when the file scopes over a port with `with(…)`,
# `run`, `apply`, `also` or `let` and then makes a **bare** call. What is still not seen: an alias
# that travels through a function parameter, a field or a collection, and a call reached by
# reflection. The behavioural half (NI-DM3/JD7, `NoReflexTest`, S7) is what covers those; this half
# is the one that fails before a world is ever built.
#
# **Slice S6 (2026-09-20).** The mechanism is built and armed now; the corpus is partial, because
# S7 has not landed. What exists today and is really checked: `OwnerSteps.kt`, which holds
# ACTIVATE, OWNER-WEEK, KEEPER and REGROWS and calls eight of the restricted functions. What is
# **not** exercisable yet: the forbidden side of the rule, since no RECV, BUNDLE or HELD file
# exists to call one of these functions wrongly. The gate is written so that the day those files
# land they are refused unless they are added to the allowlist deliberately — the allowlist names
# the files that MAY call, so a new file is refused by default. The self-test proves the forbidden
# side against fixtures. Recorded in the design as §22.11.
#
# Usage: dm-enqueue-callers.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/negative-dm-enqueue-*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# The restricted calls, as they are written at a call site.
RESTRICTED='enqueue|cancel|request|keep|rearm|forget|register|setRelays|setListening|setSendDelay|put'
# `remove` is the one call SWEEP may make as well, so it is matched separately.
REMOVE='remove'

# A receiver that makes the match a **DM** call rather than any `.put(` on a map. The call sites of
# this codebase always go through a named port; a call on something else is not one of these.
RECEIVERS='outbox|registrations|namespaces|capabilities'
# The scope functions that turn a port into an implicit receiver, so a call inside can be bare.
SCOPES='run|apply|also|let'

# Files that MAY make the restricted calls: the steps of §7.2 that §16.1 names. A file not on this
# list is refused, which is what makes a new step arrive deliberately rather than by accident.
# Every entry names the transactions it holds.
ALLOWED_FILES='
OwnerSteps.kt          ACTIVATE, OWNER-WEEK, KEEPER, REGROWS (slice S6)
SendStep.kt            SEND, RESEND (slice S7)
EstablishmentSteps.kt  EST-START, EST-READY, EST-END (slice S7)
'
# Files that may call `Namespaces.remove` and nothing else. `Sweeper.kt` is deliberately **not** in
# ALLOWED_FILES: §21.12 point 3 gives SWEEP the removal of an orphaned namespace and nothing more,
# and an entry in both lists would have made the rule this comment states unenforceable (found by
# the review of S6).
REMOVE_ONLY='Sweeper.kt'

# **Who may start an owner pass** (added by the review of S6). The rule above says which files may
# make a relay-visible call; without this one, a file that may not could still *reach* those calls
# through the facade — `engine.runOwnerMaintenance()` on an inbound blob walks into OWNER-WEEK and
# `Outbox.enqueue` while the restricted call itself stays inside the allowlisted `OwnerSteps.kt`,
# which is exactly mutants PM-11 and PM-30. §21.9 rule 1 gives these entry points three triggers —
# the actor timer, a database open and a relay session start — and the K20 hook (§13.4).
TRIGGERS='runOwnerMaintenance|onActivated|onRestored'
# The two files that declare and implement them, and the two that may call them: the app wiring
# (database open, the K20 hook) and the DM actor (its timer and the relay session start, slice S7).
TRIGGER_ALLOWED='Messaging.kt MessagingEngine.kt MessagingWiring.kt DmActor.kt'

allowed_file() { # $1 = basename
  local name
  while read -r name _; do
    [ -n "$name" ] || continue
    [ "$name" = "$1" ] && return 0
  done <<< "$ALLOWED_FILES"
  return 1
}

remove_allowed() { # $1 = basename
  allowed_file "$1" && return 0
  case " $REMOVE_ONLY " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

trigger_allowed() { # $1 = basename
  case " $TRIGGER_ALLOWED " in
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

# `<first line number>:<text>`, with every continuation line (one that begins with `.`) folded into
# the line that carries its receiver. `sync.namespaces` on one line and `.register(` on the next is
# one call site, reported where the receiver is.
joined_lines() { # $1 = file
  awk '
    { t = $0; sub(/^[[:space:]]+/, "", t)
      if (have && substr(t, 1, 1) == ".") { buf = buf t; next }
      if (have) print bufno ":" buf
      buf = $0; bufno = NR; have = 1 }
    END { if (have) print bufno ":" buf }
  ' "$1"
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
  text="$(joined_lines "$file")"

  # Local aliases of a port (`val ob = sync.outbox`) and scope functions over one (`with(sync.outbox)`,
  # `sync.outbox.run { … }`), both of which let a call site drop the receiver.
  alias_alt=""
  scoped=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [[ "$line" =~ (val|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*(:[^=]*)?=[^=]*($RECEIVERS) ]]; then
      alias_alt="${alias_alt:+$alias_alt|}${BASH_REMATCH[2]}"
    fi
    if [[ "$line" =~ with[[:space:]]*\([^\)]*($RECEIVERS) ]] ||
       [[ "$line" =~ ($RECEIVERS)[[:space:]]*\.[[:space:]]*($SCOPES)[[:space:]]*[\{\(] ]]; then
      scoped=1
    fi
  done <<< "$text"

  # $1 = the joined line, $2 = the call names this pass looks for.
  is_call_site() {
    [[ "$1" =~ \.[[:space:]]*($2)[[:space:]]*\( ]] && [[ "$1" =~ ($RECEIVERS)[[:space:]]*\.[[:space:]]*[a-zA-Z] ]] && return 0
    [ -n "$alias_alt" ] && [[ "$1" =~ (^|[^A-Za-z0-9_])($alias_alt)[[:space:]]*\.[[:space:]]*($2)[[:space:]]*\( ]] && return 0
    [ "$scoped" = 1 ] && [[ "$1" =~ (^|[^.A-Za-z0-9_])($2)[[:space:]]*\( ]] && return 0
    return 1
  }

  restricted_hits=""
  remove_hits=""
  trigger_hits=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if is_call_site "$line" "$RESTRICTED"; then restricted_hits+="$line"$'\n'; fi
    if is_call_site "$line" "$REMOVE"; then remove_hits+="$line"$'\n'; fi
    # The facade's entry points are matched by name, with or without a receiver: they are unique to
    # this facade, so a line that writes one either declares it or calls it.
    if [[ "$line" =~ (^|[^A-Za-z0-9_])($TRIGGERS)[[:space:]]*\( ]]; then trigger_hits+="$line"$'\n'; fi
  done <<< "$text"

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
  if [ -n "$trigger_hits" ] && ! trigger_allowed "$base"; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      fail "$rel:$line (G-DM2: an owner pass starts from the actor timer, a database open, a relay session start or the K20 hook, and from nothing else)"
    done <<< "$trigger_hits"
  fi
done < <(dm_caller_files)

# Vacuity, twice over, because a gate that scans nothing passes. At least one production source of
# the DM modules must be found, and at least one of them must really make one of the restricted
# calls — the day `OwnerSteps.kt` moves or is renamed, this gate must fail rather than go quiet.
[ "$SCANNED" -gt 0 ] || fail "no DM production sources found under $GHOST_ROOT/android (the gate would pass vacuously)"
[ "$WITH_CALL" -gt 0 ] || \
  fail "none of the $SCANNED scanned DM sources makes a restricted call (the gate would pass vacuously; see the S6 note in this script)"

finish dm-enqueue-callers
