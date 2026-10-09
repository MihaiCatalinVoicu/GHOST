#!/usr/bin/env bash
# Gate G-M5 (Phase 10 design faza10-forum.md §13.1, §7.7; invariant T40, the channel's "no reflex"): **the calls
# that cause relay-visible behaviour for a channel namespace are made only from the channel transactions that may
# cause them, each only the calls it needs.**
#
#   Outbox.enqueue          CH-ACCEPT (the join request), CH-POST (posts, reactions and CH-INVITE's INVITE_ISSUED,
#                           through ChannelPostStep.compose, and CH-LEAVE's LEAVE post), CH-PASS (the commit),
#                           CH-SETTLE (the Welcomes of the member's own winning commit only, §19.2)
#   Namespaces.register     CH-CREATE, CH-ACCEPT, CH-SWITCH (§6.5, §19.8)
#   Capabilities.put        CH-CREATE, CH-ACCEPT (the READ and DEPOSIT credentials of every slot), CH-SWITCH
#   Registrations.keep      CH-CREATE (the funder's READ and DEPOSIT registrations of the week), CH-SWITCH
#                           (the rotating committer's week rows), the funder renewal step (§7.5 item 7)
#   Funding.set             CH-CREATE (the creator is the default funder, §7.4), CH-SWITCH (the rotating
#                           committer), the funder renewal step
#   Namespaces.remove,
#   Namespaces.setListening CH-SWEEP (an expired join's namespace, §6.2.2 step 4; a drained generation's, §6.5)
#
# and **never from `CH-RECV` or `CH-JOIN`** (a blob that arrives causes no store, registration, funding or
# listening change; a joiner's newer generation is switched by `CH-SWITCH` at its next session start, §19.8).
# Every other restricted call — `Outbox.cancel`, `Registrations.request`/`rearm`/`forget`, `Namespaces.setRelays`/
# `setSendDelay` — is made by no channel file in slices S4 … S6. The transactions §13.1 lists beyond these
# (`CH-REJOIN`, `CH-REVEAL`, the rest of `CH-SWEEP`) are slices S7 … S9's: each joins the table below
# deliberately, with the calls it makes, when it is built — a new file, or a new call in a listed file, is
# refused until then, which is what makes it arrive on purpose. **An entry is a file of the channel engine's
# own directory** (`android/messaging/src/<set>/kotlin/org/ghost/messaging/channel/engine/`, §19.38): a file
# of the same name anywhere else has no entry.
#
# **A second rule, one frame lower** (the S8 review's `STEP_TRIGGERS` of G-DM2, for the channel steps): the entry
# points that reach those calls — `ChannelPostStep.compose`/`encryptPending`/`retryPost`, `ChannelPassStep.admit`/`removeMember`/
# `runScheduledPasses`/`scheduleAtSessionStart`, `ChannelSettleStep.settleDue`, `ChannelSweepStep.sweepJoins` — are
# written only in the files that declare them, in `ChannelEngine.kt` (the user actions and the actor's pass, whose
# time-triggered steps it gates) and in `ChannelInviteStep.kt` (CH-INVITE's post). A receive or join step that held a
# step object and called one would reach `Outbox.enqueue` without writing a restricted call; this rule refuses it,
# and it reads **every** production source of `:messaging` and `:app`, not only the channel package.
#
# **A third rule: who may hold a step** (§19.38, the review of S4, which reached `Outbox.enqueue` from CH-RECV through
# `postStep.post`, `settleStep.settle`, `acceptStep.accept`, `inviteStep.invite`, `createStep.create` and
# `ChannelEngine.post`, none of them on the second rule's list). The classes of the steps that may make a restricted
# call, the engine that holds them all and the actor's view of its pass are named — as a type, a constructor call, an
# import or a property — only in the files that hold them: `ChannelPostStep` (and a property `postStep`) in
# `ChannelEngine.kt`, `ChannelInviteStep.kt` and `ChannelPassStep.kt`; every other step class (and its property) in
# `ChannelEngine.kt`; `ChannelEngine` in `MessagingRuntime.kt`, which assembles the stack; `ChannelPassSteps` in
# `ChannelEngine.kt`, `DmActor.kt` and `MessagingRuntime.kt`; each in its own file. A file that cannot name a step
# cannot hold one, whatever it calls it. A companion constant (`ChannelPostStep.KIND_POST`) is not a mention.
#
# **How the work is split with G-DM2** (`dm-enqueue-callers.sh`, which reads all of `:messaging` and `:app`). G-DM2's
# own allowlist is the DM steps', shared by every restricted call; a channel step that may enqueue must not thereby
# be allowed to fund, which a shared list cannot say. So G-DM2 leaves the restricted-call rules of the channel
# engine's files (`android/messaging/…/messaging/channel/engine/`, that directory and no other: §19.38) to this gate
# and keeps its facade and step rules for them; it refuses `Funding.set` in every DM file, the allowed ones included
# (§19.37, the S1a review's F-7, option (c)); and the channel **stores** (`…/messaging/channel/store/`) stay G-DM2's (no
# store makes a port call) and are read here too.
#
# **What it reads** (§19.38): every production source set of `:messaging` and `:app` — `src/main`, `src/release`,
# `src/debug`, `src/gate` and any other build type or flavour, every set but the test ones — and, for the first rule,
# every file of them under a `messaging/channel/` package path.
#
# **How a call site is recognized** is G-DM2's recognizer, copied (not shared, so that the older gate's behaviour and
# its pinned fixtures stay exactly as they were) and widened by the review of S4: a line folded with its
# `.`-continuations, and with the line before it when that one ends with a `.`; comments dropped, block comments
# included, wherever they sit in a line; backticks dropped; a port by its conventional name (`outbox`, `registrations`,
# `namespaces`, `capabilities`, `funding`), by **any property name a production source declares with a port type**
# (so `ChannelSyncPorts.funding` renamed `fund` is still a port), or by its type — written plainly, qualified, or
# through a `typealias` of it — on a local alias, a property or a function parameter; a destructuring declaration
# over a port; a scope function (`with`, `run`, `apply`; `also`/`let` through the lambda's receiver); a safe call; a
# callable reference, bound (`sync.outbox::enqueue`) or not (`Outbox::enqueue`); and a parenthesized receiver.
#
# **What still escapes it** (declared; the behavioural half of T40 is the channel privacy world's, slice S11): a port
# put in a collection and taken out (`listOf(sync.outbox).forEach { it.enqueue(…) }`), a helper function written in a
# file the table allows and called from one it does not (the helper's restricted call is its file's), a lambda that
# makes the call built in an allowed file and handed on, and reflection.
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
# A type as a declaration may write it: plainly or qualified by its package.
QUALIFIER='([a-z][A-Za-z0-9_]*[[:space:]]*\.[[:space:]]*)*'

# The channel files that MAY make a restricted call, and the calls each may make. One line per file:
# `<basename>|<calls, space-separated>|<the transaction it holds>`. A call is named by its method; the names are
# unique to their port (enqueue â†’ Outbox, register/remove/setListening â†’ Namespaces, put â†’ Capabilities,
# keep â†’ Registrations, set â†’ Funding). An entry holds for that file in the channel engine's directory only.
ALLOWED='
ChannelCreateStep.kt|register put keep set|CH-CREATE (§6.1)
ChannelAcceptStep.kt|register put enqueue|CH-ACCEPT (§6.2.2)
ChannelPostStep.kt|enqueue|CH-POST and the INVITE_ISSUED of CH-INVITE (§6.3.1, §6.2.1), CH-LEAVE (§6.6)
ChannelPassStep.kt|enqueue|CH-PASS (§6.2.3)
ChannelSettleStep.kt|enqueue remove setListening|CH-SETTLE, the own winning commit'"'"'s Welcomes (§19.2); a removed member'"'"'s older drain ended at once (§6.5)
ChannelSweepStep.kt|remove setListening|CH-SWEEP, an expired join (§6.2.2 step 4) and a drained generation (§6.5)
ChannelSwitchStep.kt|register put keep set remove setListening|CH-SWITCH (§6.5, §19.8; a switch ends an older drain at once)
ChannelFunderStep.kt|register keep set|the funder renewal step (§7.5 item 7)
ChannelRejoinStep.kt|enqueue|CH-REJOIN (§6.7) and the CH-SWEEP re-send of an unanswered rejoin
'
# The two steps §13.1 names as never allowed: an entry for either is itself a violation, so the table cannot grow one.
NEVER='ChannelReceiveStep.kt ChannelJoinStep.kt'
# The directory the table's entries are files of (relative to GHOST_ROOT; the source set is any).
ENGINE_DIR_GLOB='android/messaging/src/*/org/ghost/messaging/channel/engine/*'

# The second rule's entry points and the files that may write them.
CH_STEP_TRIGGERS='compose|encryptPending|retryPost|admit|removeMember|runScheduledPasses|scheduleAtSessionStart|settleDue|sweepJoins|sweepDrains|sweepRequests|switchDue|renewDue|resync|sweepRejoins'
CH_STEP_ALLOWED='ChannelEngine.kt ChannelInviteStep.kt ChannelPostStep.kt ChannelPassStep.kt ChannelSettleStep.kt ChannelSweepStep.kt ChannelSwitchStep.kt ChannelFunderStep.kt ChannelRejoinStep.kt'

# The third rule: `<the names that refer to a step>|<the files that may write them>`. A class's own file may always.
CH_HOLDERS='
ChannelPostStep postStep|ChannelEngine.kt ChannelInviteStep.kt ChannelPassStep.kt
ChannelPassStep passStep|ChannelEngine.kt
ChannelSettleStep settleStep|ChannelEngine.kt
ChannelSweepStep sweepStep|ChannelEngine.kt
ChannelSwitchStep switchStep|ChannelEngine.kt
ChannelFunderStep funderStep|ChannelEngine.kt
ChannelCreateStep createStep|ChannelEngine.kt
ChannelAcceptStep acceptStep|ChannelEngine.kt
ChannelRejoinStep rejoinStep|ChannelEngine.kt
ChannelInviteStep inviteStep|ChannelEngine.kt
ChannelEngine|MessagingRuntime.kt
ChannelPassSteps|ChannelEngine.kt DmActor.kt MessagingRuntime.kt
'
HOLDER_NAMES=''
while IFS= read -r line; do
  [ -n "$line" ] || continue
  for n in ${line%%|*}; do HOLDER_NAMES="${HOLDER_NAMES:+$HOLDER_NAMES|}$n"; done
done <<< "$CH_HOLDERS"

# Sets ALLOWED_CALLS to the calls the file [$1] (basename) may make, or to nothing. (A variable, not a command
# substitution: a subshell per file or per line is a fork, and forks are what made this gate slow on Git Bash.)
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

# Whether the file [$1] (basename) may write the step name [$2] (the third rule).
holder_allowed() { # $1 = basename, $2 = name
  local line names files n
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    names="${line%%|*}"
    files="${line#*|}"
    for n in $names; do
      [ "$n" = "$2" ] || continue
      # a class's own file, and the files of its row
      [ "$1" = "${names%% *}.kt" ] && return 0
      case " $files " in *" $1 "*) return 0 ;; esac
      return 1
    done
  done <<< "$CH_HOLDERS"
  return 0
}

# Every production source of the two modules that drive the messaging engines: every source set but the test ones.
caller_files() {
  find "$GHOST_ROOT/android/messaging" "$GHOST_ROOT/android/app" \
    -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) -path '*/src/*' \
    ! -path '*/src/test/*' ! -path '*/src/test[A-Z]*' ! -path '*/src/androidTest*' ! -path '*/src/testFixtures*' \
    -print 2>/dev/null || true
}

# `<first line number>:<text>`: a line with its comments removed (`//` to the end, `/* … */` wherever it sits and
# however many lines it spans) and its backticks dropped, folded with every following line that begins with `.` or
# `?.`, and a line that ends with `.` or `?.` folded with the one after it. Empty lines go.
joined_lines() { # $1 = file
  awk '
    { line = $0; out = ""
      while (length(line) > 0) {
        if (inblock) {
          i = index(line, "*/")
          if (i == 0) { line = ""; break }
          line = substr(line, i + 2); inblock = 0
        } else {
          i = index(line, "/*"); j = index(line, "//")
          if (j > 0 && (i == 0 || j < i)) { out = out substr(line, 1, j - 1); line = ""; break }
          if (i == 0) { out = out line; line = ""; break }
          out = out substr(line, 1, i - 1) " "; line = substr(line, i + 2); inblock = 1
        }
      }
      gsub(/`/, "", out)
      t = out; sub(/^[[:space:]]+/, "", t); sub(/[[:space:]]+$/, "", t)
      if (t == "") next
      if (have && (dot || substr(t, 1, 1) == "." || substr(t, 1, 2) == "?.")) { buf = buf t; dot = (t ~ /\.$/); next }
      if (have) print bufno ":" buf
      buf = out; bufno = NR; have = 1; dot = (t ~ /\.$/) }
    END { if (have) print bufno ":" buf }
  ' "$1"
}

# Read every production source once (the folded text, by file).
declare -A TEXT
FILES=()
while IFS= read -r file; do
  [ -n "$file" ] || continue
  FILES+=("$file")
  TEXT["$file"]="$(joined_lines "$file")"
done < <(caller_files)

# The pre-pass over the whole corpus: a `typealias` of a port type is a port type, and a property declared with a port
# type is a port whatever its name — in every file, since a port reaches a step as a property of something else
# (`sync.fund`). Run twice, so an alias of an alias is one too.
TYPES="$RECEIVER_TYPES"
for pass in 1 2; do
  for file in "${FILES[@]}"; do
    rest="${TEXT[$file]}"
    while [[ "$rest" =~ typealias[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*$QUALIFIER($TYPES)([^A-Za-z0-9_.]|$) ]]; do
      case "|$TYPES|" in *"|${BASH_REMATCH[1]}|"*) ;; *) TYPES="$TYPES|${BASH_REMATCH[1]}" ;; esac
      rest="${rest#*"${BASH_REMATCH[0]}"}"
    done
  done
done
PORTS="$RECEIVERS"
for file in "${FILES[@]}"; do
  rest="${TEXT[$file]}"
  while [[ "$rest" =~ (val|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*:[[:space:]]*$QUALIFIER($TYPES)([^A-Za-z0-9_.]|$) ]]; do
    case "|$PORTS|" in *"|${BASH_REMATCH[2]}|"*) ;; *) PORTS="$PORTS|${BASH_REMATCH[2]}" ;; esac
    rest="${rest#*"${BASH_REMATCH[0]}"}"
  done
done

# Sets CALLS to the call names a line makes on a port (G-DM2's `is_call_site`, applied to each restricted name in
# turn). $1 = the joined line; uses the file's `alias_alt` and `scoped`.
calls_on_line() {
  local name ports found=""
  CALLS=""
  # A line that names no restricted call at all is no call site: the common case, decided without the loop.
  [[ "$1" =~ ($RESTRICTED) ]] || return 0
  ports="$PORTS${alias_alt:+|$alias_alt}"
  for name in ${RESTRICTED//|/ }; do
    if { [[ "$1" =~ \.[[:space:]]*($name)[[:space:]]*\( ]] && [[ "$1" =~ (^|[^A-Za-z0-9_])($PORTS)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($name)[[:space:]]*\( ]]; } ||
       { [ -n "$alias_alt" ] && [[ "$1" =~ (^|[^A-Za-z0-9_])($alias_alt)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($name)[[:space:]]*\( ]]; } ||
       { [ "$scoped" = 1 ] && [[ "$1" =~ (^|[^.A-Za-z0-9_])($name)[[:space:]]*\( ]]; } ||
       [[ "$1" =~ (^|[^A-Za-z0-9_])($ports|$TYPES)[[:space:]]*\??[[:space:]]*::[[:space:]]*($name)([^A-Za-z0-9_]|$) ]] ||
       [[ "$1" =~ (^|[^A-Za-z0-9_])($ports)[[:space:]]*\)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($name)[[:space:]]*\( ]]; then
      found="$found $name"
    fi
  done
  CALLS="${found# }"
}

SCANNED=0
WITH_CALL=0
for file in "${FILES[@]}"; do
  rel="${file#"$GHOST_ROOT"/}"
  case "$rel" in */messaging/channel/*) ;; *) continue ;; esac
  base="${file##*/}"
  SCANNED=$((SCANNED + 1))
  text="${TEXT[$file]}"

  alias_alt=""
  scoped=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [[ "$line" =~ (val|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*(:[^=]*)?=[^=]*(^|[^A-Za-z0-9_])($PORTS)([^A-Za-z0-9_]|$) ]]; then
      alias_alt="${alias_alt:+$alias_alt|}${BASH_REMATCH[2]}"
    fi
    # A declaration with a port type — a property, a local, or a function or constructor parameter — names a port.
    rest="$line"
    while [[ "$rest" =~ (^|[^A-Za-z0-9_.])([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*:[[:space:]]*$QUALIFIER($TYPES)([^A-Za-z0-9_.]|$) ]]; do
      alias_alt="${alias_alt:+$alias_alt|}${BASH_REMATCH[2]}"
      rest="${rest#*"${BASH_REMATCH[0]}"}"
    done
    # A destructuring declaration over a port: every name it binds. (The names are read before the second match, which
    # overwrites BASH_REMATCH.)
    if [[ "$line" =~ (val|var)[[:space:]]*\(([^\)]*)\)[[:space:]]*=(.*) ]]; then
      names="${BASH_REMATCH[2]//,/ }"
      if [[ "${BASH_REMATCH[3]}" =~ (^|[^A-Za-z0-9_])($PORTS${alias_alt:+|$alias_alt})([^A-Za-z0-9_]|$) ]]; then
        for n in $names; do
          n="${n%%:*}"
          [[ "$n" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && [ "$n" != "_" ] && alias_alt="${alias_alt:+$alias_alt|}$n"
        done
      fi
    fi
    if [[ "$line" =~ with[[:space:]]*\([^\)]*($PORTS) ]] ||
       [[ "$line" =~ ($PORTS)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($SCOPES)[[:space:]]*[\{\(] ]]; then
      scoped=1
    fi
    if [[ "$line" =~ ($PORTS)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($LAMBDA_SCOPES)[[:space:]]*[\{\(] ]]; then
      alias_alt="${alias_alt:+$alias_alt|}it"
      if [[ "$line" =~ \{[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*-\> ]]; then
        alias_alt="$alias_alt|${BASH_REMATCH[1]}"
      fi
    fi
    if [ -n "$alias_alt" ] && [[ "$line" =~ ^[0-9]+:[[:space:]]*\{[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*-\> ]]; then
      alias_alt="$alias_alt|${BASH_REMATCH[1]}"
    fi
  done <<< "$text"

  # An entry of the table holds for the channel engine's own directory only (§19.38).
  allowed=""
  # shellcheck disable=SC2254
  case "$rel" in $ENGINE_DIR_GLOB) allowed_calls "$base"; allowed="$ALLOWED_CALLS" ;; esac
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
done

STEP_SCANNED=0
for file in "${FILES[@]}"; do
  rel="${file#"$GHOST_ROOT"/}"
  base="${file##*/}"
  STEP_SCANNED=$((STEP_SCANNED + 1))
  text="${TEXT[$file]}"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if ! step_allowed "$base" && [[ "$line" =~ (^|[^A-Za-z0-9_])($CH_STEP_TRIGGERS)[[:space:]]*\( ]]; then
      fail "$rel:$line (G-M5: a channel step that enqueues, admits, settles or sweeps is driven by the channel engine, and by nothing else)"
      continue
    fi
    # The third rule. A companion constant is not a mention: `ChannelPostStep.KIND_POST` is dropped before the test.
    [[ "$line" =~ (^|[^A-Za-z0-9_])($HOLDER_NAMES)([^A-Za-z0-9_]|$) ]] || continue
    probe="$line"
    while [[ "$probe" =~ (^|[^A-Za-z0-9_])($HOLDER_NAMES)[[:space:]]*\.[[:space:]]*[A-Z][A-Z0-9_]*([^A-Za-z0-9_]|$) ]]; do
      probe="${probe/"${BASH_REMATCH[0]}"/ }"
    done
    named=""
    rest="$probe"
    while [[ "$rest" =~ (^|[^A-Za-z0-9_])($HOLDER_NAMES)([^A-Za-z0-9_]|$) ]]; do
      n="${BASH_REMATCH[2]}"
      holder_allowed "$base" "$n" || named="$named $n"
      rest="${rest#*"${BASH_REMATCH[0]}"}"
    done
    if [ -n "$named" ]; then
      fail "$rel:$line (G-M5: $base names a step that may make a relay-visible call —${named}; only the files that hold it may, §19.38)"
    fi
  done <<< "$text"
done

# Vacuity: the channel package must be found, and at least one of its files must make one of the calls — the day
# the steps move or are renamed, this gate must fail rather than go quiet.
[ "$SCANNED" -gt 0 ] || fail "no channel production sources found under $GHOST_ROOT/android/messaging (the gate would pass vacuously)"
[ "$WITH_CALL" -gt 0 ] || \
  fail "none of the $SCANNED scanned channel sources makes a restricted call (the gate would pass vacuously)"

finish ch-enqueue-callers
