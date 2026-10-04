#!/usr/bin/env bash
# Gate G-M5 (Phase 10 design faza10-forum.md §13.1, §7.7; invariant T40, the channel's "no reflex"): **the calls
# that cause relay-visible behaviour for a channel namespace are made only from the channel transactions that may
# cause them, each only the calls it needs.**
#
#   Outbox.enqueue          CH-ACCEPT (the join request), CH-POST (posts, reactions and CH-INVITE's INVITE_ISSUED,
#                           through ChannelPostStep.compose), CH-PASS (the commit), CH-SETTLE (the Welcomes of the
#                           member's own winning commit only, §19.2)
#   Namespaces.register     CH-CREATE, CH-ACCEPT
#   Capabilities.put        CH-CREATE, CH-ACCEPT (the READ and DEPOSIT credentials of every slot)
#   Registrations.keep      CH-CREATE (the funder's READ and DEPOSIT registrations of the week)
#   Funding.set             CH-CREATE (the creator is the default funder, §7.4)
#   Namespaces.remove,
#   Namespaces.setListening CH-SWEEP (an expired join's namespace, §6.2.2 step 4)
#
# and **never from `CH-RECV` or `CH-JOIN`** (a blob that arrives causes no store, registration, funding or
# listening change; a joiner's newer generation is switched by `CH-SWITCH` at its next session start, §19.8).
# Every other restricted call — `Outbox.cancel`, `Registrations.request`/`rearm`/`forget`, `Namespaces.setRelays`/
# `setSendDelay` — is made by no channel file in slice S4. The transactions §13.1 lists beyond these (`CH-SWITCH`,
# `CH-REJOIN`, `CH-REVEAL`, `CH-LEAVE`, the funder renewal step and the rest of `CH-SWEEP`) are slices S5 … S9's: each
# joins the table below deliberately, with the calls it makes, when it is built — a new file, or a new call in a
# listed file, is refused until then, which is what makes it arrive on purpose.
#
# **A second rule, one frame lower** (the S8 review's `STEP_TRIGGERS` of G-DM2, for the channel steps): the entry
# points that reach those calls — `ChannelPostStep.compose`/`encryptPending`/`retryPost`, `ChannelPassStep.admit`/
# `runScheduledPasses`/`scheduleAtSessionStart`, `ChannelSettleStep.settleDue`, `ChannelSweepStep.sweepJoins` — are
# written only in the files that declare them, in `ChannelEngine.kt` (the user actions and the actor's pass, whose
# time-triggered steps it gates) and in `ChannelInviteStep.kt` (CH-INVITE's post). A receive or join step that held a
# step object and called one would reach `Outbox.enqueue` without writing a restricted call; this rule refuses it,
# and it reads **every** production source of `:messaging` and `:app`, not only the channel package.
#
# **How the work is split with G-DM2** (`dm-enqueue-callers.sh`, which reads all of `:messaging` and `:app`). G-DM2's
# own allowlist is the DM steps', shared by every restricted call; a channel step that may enqueue must not thereby
# be allowed to fund, which a shared list cannot say. So G-DM2 leaves the restricted-call rules of the channel
# engine's files (`…/messaging/channel/engine/`) to this gate and keeps its facade and step rules for them; it
# refuses `Funding.set` in every DM file, the allowed ones included (§19.37, the S1a review's F-7, option (c)); and the
# channel **stores** (`…/messaging/channel/store/`) stay G-DM2's (no store makes a port call) and are read here too.
#
# **How a call site is recognized** is G-DM2's recognizer, copied (not shared, so that the older gate's behaviour and
# its pinned fixtures stay exactly as they were): a line folded with its `.`-continuations, comments dropped, a port
# by its conventional name (`outbox`, `registrations`, `namespaces`, `capabilities`, `funding`) or its type, a local
# alias, a scope function (`with`, `run`, `apply`; `also`/`let` through the lambda's receiver), a safe call, a callable
# reference and a parenthesized receiver. What escapes it escapes G-DM2 too (an alias through a parameter or a
# collection, reflection); the behavioural half of T40 is the channel privacy world's (slice S11).
#
# Usage: ch-enqueue-callers.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/negative-ch-enqueue-*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Every restricted call, as written at a call site (G-DM2's list; `remove` is matched with them here).
RESTRICTED='enqueue|cancel|request|keep|rearm|forget|register|setRelays|setListening|setSendDelay|put|set|remove'
RECEIVERS='outbox|registrations|namespaces|capabilities|funding'
RECEIVER_TYPES='Outbox|Registrations|Namespaces|Capabilities|Funding'
SCOPES='run|apply'
LAMBDA_SCOPES='also|let'

# The channel files that MAY make a restricted call, and the calls each may make. One line per file:
# `<basename>|<calls, space-separated>|<the transaction it holds>`. A call is named by its method; the names are
# unique to their port (enqueue → Outbox, register/remove/setListening → Namespaces, put → Capabilities,
# keep → Registrations, set → Funding).
ALLOWED='
ChannelCreateStep.kt|register put keep set|CH-CREATE (§6.1)
ChannelAcceptStep.kt|register put enqueue|CH-ACCEPT (§6.2.2)
ChannelPostStep.kt|enqueue|CH-POST and the INVITE_ISSUED of CH-INVITE (§6.3.1, §6.2.1)
ChannelPassStep.kt|enqueue|CH-PASS (§6.2.3)
ChannelSettleStep.kt|enqueue|CH-SETTLE, the own winning commit'"'"'s Welcomes (§19.2)
ChannelSweepStep.kt|remove setListening|CH-SWEEP, an expired join (§6.2.2 step 4)
'
# The two steps §13.1 names as never allowed: an entry for either is itself a violation, so the table cannot grow one.
NEVER='ChannelReceiveStep.kt ChannelJoinStep.kt'

# The second rule's entry points and the files that may write them.
CH_STEP_TRIGGERS='compose|encryptPending|retryPost|admit|runScheduledPasses|scheduleAtSessionStart|settleDue|sweepJoins'
CH_STEP_ALLOWED='ChannelEngine.kt ChannelInviteStep.kt ChannelPostStep.kt ChannelPassStep.kt ChannelSettleStep.kt ChannelSweepStep.kt'

# Sets ALLOWED_CALLS to the calls the file [$1] may make, or to nothing. (A variable, not a command substitution: a
# subshell per file or per line is a fork, and forks are what made this gate slow on Windows' Git Bash.)
allowed_calls() { # $1 = basename
  local line name calls
  ALLOWED_CALLS=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    name="${line%%|*}"
    calls="${line#*|}"
    calls="${calls%%|*}"
    if [ "$name" = "$1" ]; then ALLOWED_CALLS="$calls"; return 0; fi
  done <<< "$ALLOWED"
  return 0
}

# The table itself must not name a step that is never allowed.
while IFS= read -r line; do
  [ -n "$line" ] || continue
  name="${line%%|*}"
  case " $NEVER " in
    *" $name "*) fail "ch-enqueue-callers.sh: the allowlist names $name (G-M5: CH-RECV and CH-JOIN make no relay-visible call)" ;;
  esac
done <<< "$ALLOWED"

step_allowed() { # $1 = basename
  case " $CH_STEP_ALLOWED " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

# The channel package's production sources (engine and stores), at any depth, `src/release` too.
channel_files() {
  find "$GHOST_ROOT/android/messaging" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) \
    \( -path '*/src/main/*' -o -path '*/src/release/*' \) -path '*/messaging/channel/*' -print 2>/dev/null || true
}
# Every production source of the two modules that drive the messaging engines (the second rule's corpus).
caller_files() {
  find "$GHOST_ROOT/android/messaging" "$GHOST_ROOT/android/app" \
    -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) \
    \( -path '*/src/main/*' -o -path '*/src/release/*' \) -print 2>/dev/null || true
}

# G-DM2's fold: `<first line number>:<text>` with every `.`/`?.` continuation joined to its receiver's line,
# comment lines and trailing `//` comments dropped.
joined_lines() { # $1 = file
  awk '
    { line = $0
      t = line; sub(/^[[:space:]]+/, "", t)
      if (t ~ /^(\*|\/\/|\/\*)/) next
      sub(/\/\/.*$/, "", line)
      t = line; sub(/^[[:space:]]+/, "", t)
      if (t == "") next
      if (have && (substr(t, 1, 1) == "." || substr(t, 1, 2) == "?.")) { buf = buf t; next }
      if (have) print bufno ":" buf
      buf = line; bufno = NR; have = 1 }
    END { if (have) print bufno ":" buf }
  ' "$1"
}

# Sets CALLS to the call names a line makes on a port (G-DM2's `is_call_site`, applied to each restricted name in
# turn). $1 = the joined line; uses the file's `alias_alt` and `scoped`.
calls_on_line() {
  local name ports found=""
  CALLS=""
  # A line that names no restricted call at all is no call site: the common case, decided without the loop.
  [[ "$1" =~ ($RESTRICTED) ]] || return 0
  ports="$RECEIVERS${alias_alt:+|$alias_alt}"
  for name in ${RESTRICTED//|/ }; do
    if { [[ "$1" =~ \.[[:space:]]*($name)[[:space:]]*\( ]] && [[ "$1" =~ ($RECEIVERS)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($name)[[:space:]]*\( ]]; } ||
       { [ -n "$alias_alt" ] && [[ "$1" =~ (^|[^A-Za-z0-9_])($alias_alt)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($name)[[:space:]]*\( ]]; } ||
       { [ "$scoped" = 1 ] && [[ "$1" =~ (^|[^.A-Za-z0-9_])($name)[[:space:]]*\( ]]; } ||
       [[ "$1" =~ (^|[^A-Za-z0-9_])($ports)[[:space:]]*\??[[:space:]]*::[[:space:]]*($name)([^A-Za-z0-9_]|$) ]] ||
       [[ "$1" =~ (^|[^A-Za-z0-9_])($ports)[[:space:]]*\)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($name)[[:space:]]*\( ]]; then
      found="$found $name"
    fi
  done
  CALLS="${found# }"
}

SCANNED=0
WITH_CALL=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  rel="${file#"$GHOST_ROOT"/}"
  base="${file##*/}"
  SCANNED=$((SCANNED + 1))
  text="$(joined_lines "$file")"

  alias_alt=""
  scoped=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [[ "$line" =~ (val|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*(:[^=]*)?=[^=]*($RECEIVERS) ]]; then
      alias_alt="${alias_alt:+$alias_alt|}${BASH_REMATCH[2]}"
    fi
    rest="$line"
    while [[ "$rest" =~ (val|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*:[[:space:]]*($RECEIVER_TYPES)([^A-Za-z0-9_]|$) ]]; do
      alias_alt="${alias_alt:+$alias_alt|}${BASH_REMATCH[2]}"
      rest="${rest#*"${BASH_REMATCH[0]}"}"
    done
    if [[ "$line" =~ with[[:space:]]*\([^\)]*($RECEIVERS) ]] ||
       [[ "$line" =~ ($RECEIVERS)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($SCOPES)[[:space:]]*[\{\(] ]]; then
      scoped=1
    fi
    if [[ "$line" =~ ($RECEIVERS)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($LAMBDA_SCOPES)[[:space:]]*[\{\(] ]]; then
      alias_alt="${alias_alt:+$alias_alt|}it"
      if [[ "$line" =~ \{[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*-\> ]]; then
        alias_alt="$alias_alt|${BASH_REMATCH[1]}"
      fi
    fi
    if [ -n "$alias_alt" ] && [[ "$line" =~ ^[[:space:]]*\{[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*-\> ]]; then
      alias_alt="$alias_alt|${BASH_REMATCH[1]}"
    fi
  done <<< "$text"

  allowed_calls "$base"
  allowed="$ALLOWED_CALLS"
  file_has_call=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    calls_on_line "$line"
    [ -n "$CALLS" ] || continue
    file_has_call=1
    for call in $CALLS; do
      case " $allowed " in
        *" $call "*) ;;
        *)
          if [ -z "$allowed" ]; then
            fail "$rel:$line (G-M5: $base may make no relay-visible call — $call; CH-RECV and CH-JOIN never, and a new channel step joins the table on purpose)"
          else
            fail "$rel:$line (G-M5: $call is not one of $base's calls ($allowed))"
          fi
          ;;
      esac
    done
  done <<< "$text"
  [ "$file_has_call" = 1 ] && WITH_CALL=$((WITH_CALL + 1))
done < <(channel_files)

STEP_SCANNED=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  rel="${file#"$GHOST_ROOT"/}"
  base="${file##*/}"
  STEP_SCANNED=$((STEP_SCANNED + 1))
  step_allowed "$base" && continue
  text="$(joined_lines "$file")"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [[ "$line" =~ (^|[^A-Za-z0-9_])($CH_STEP_TRIGGERS)[[:space:]]*\( ]]; then
      fail "$rel:$line (G-M5: a channel step that enqueues, admits, settles or sweeps is driven by the channel engine, and by nothing else)"
    fi
  done <<< "$text"
done < <(caller_files)

# Vacuity: the channel package must be found, and at least one of its files must make one of the calls — the day
# the steps move or are renamed, this gate must fail rather than go quiet.
[ "$SCANNED" -gt 0 ] || fail "no channel production sources found under $GHOST_ROOT/android/messaging (the gate would pass vacuously)"
[ "$WITH_CALL" -gt 0 ] || \
  fail "none of the $SCANNED scanned channel sources makes a restricted call (the gate would pass vacuously)"

finish ch-enqueue-callers
