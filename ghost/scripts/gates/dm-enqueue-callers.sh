#!/usr/bin/env bash
# Gate G-DM2 (Phase 9 design §16.1, §21.7, §21.9; invariants T28 "no reflex" and T31 "read
# confinement"): **the calls that cause relay-visible behaviour are made only from the steps that
# are allowed to cause it.**
#
#   Outbox.enqueue, Outbox.cancel, Registrations.request, Registrations.keep, Registrations.rearm,
#   Registrations.forget, Namespaces.register, Namespaces.setRelays, Namespaces.setListening,
#   Namespaces.setSendDelay, Capabilities.put and Funding.set
#       only from SEND, RESEND, EST-START, EST-READY, EST-END, OWNER-WEEK, ACTIVATE, KEEPER,
#       REGROWS
#   Namespaces.remove
#       the same, and also from SWEEP
#   Messaging.runOwnerMaintenance, Messaging.onActivated, Messaging.onRestored
#       only from the app wiring and the DM actor — the actor timer, a database open, a relay
#       session start and the K20 hook of §21.9 rule 1 and §13.4
#   SendStep.sendControl, SendStep.flushPending, SendStep.resend, EstablishmentSteps.estStart,
#   EstablishmentSteps.estReady, EstablishmentSteps.estEnd
#       only from the files that declare them and from the four that drive them
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
# lines (the violation is reported at the receiver's line). Comment lines are dropped first, so a
# KDoc sentence such as "…are a request (§12.3)…" is not read as a call to `Registrations.request`.
# A line is a call site when it names one of the four ports beside a restricted call, when it calls
# one through a **local alias** of a port (`val ob = sync.outbox; ob.enqueue(…)`), when the file
# scopes over a port with `with(…)`, `run` or `apply` and then makes a **bare** call, or when it
# scopes over one with `also`/`let` and calls through the **lambda's own receiver** (`it`, or the
# name the lambda binds).
#
# `also` and `let` needed that last clause and did not have it (found by the review of S7): they
# bind the port to `it` rather than to `this`, so they can never produce the bare call the third
# branch looks for, and when the receiver and the call sit on different physical lines `joined_lines`
# does not fold them either (the continuation only folds lines starting with `.`). Listing them in
# `SCOPES` while matching only bare calls meant `sync.outbox.let { it.enqueue(tx) }` across two
# lines passed a gate whose header claimed to catch it.
#
# A **callable reference** to a restricted call (`sync.funding::set`, `ob::enqueue`) and a
# **parenthesized receiver** (`(sync.funding).set(…)`) are seen too, since the Phase 10 review of S1a
# (see `is_call_site`); before it both passed for every restricted call, `Outbox.enqueue` included.
#
# What is still not seen: an alias that travels through a function parameter, a field or a
# collection, a reference taken to a function that wraps the call, an `import … as` alias of a port
# type, and a call reached by reflection. The behavioural half (NI-DM3/JD7, `NoReflexTest`, S7) is
# what covers those; this half is the one that fails before a world is ever built.
#
# **Slice S6 (2026-09-20).** The mechanism was built and armed then, with a partial corpus:
# `OwnerSteps.kt` alone, and no RECV, BUNDLE or HELD file to exercise the forbidden side. The gate
# was written so that the day those files landed they would be refused unless added to the
# allowlist deliberately — the allowlist names the files that MAY call, so a new file is refused
# by default. Recorded in the design as §22.11 item 8.
#
# **Slice S7 (2026-09-21).** The corpus is now the real one, and the forbidden side is exercised by
# production code rather than by fixtures alone. `SendStep.kt` (SEND, RESEND),
# `EstablishmentSteps.kt` (EST-START, EST-READY, EST-END) and `ContactKeeper.kt` (the contact half
# of KEEPER) joined the allowlist deliberately; `ReceiveStep.kt`, `BundleStep.kt`, `PeekOrder.kt`,
# `OutcomeStep.kt`, `ContactSteps.kt`, `PairKeySteps.kt`, `DmActor.kt` and the store layer did
# **not**, and each of them handles inbound blobs or contact state without making a restricted
# call. `NoReflexTest`, the behavioural half §16.1 names, arrived with the same slice: it compares
# two worlds that differ only in what arrived.
#
# **Slice S8 (2026-09-21).** HELD landed, which is the third of the three steps line 17 forbids,
# and with it the key-change and scheduled-control files. **None of them joined `ALLOWED_FILES`**,
# and that is the record this convention asks each slice to leave: `HeldReplay.kt` (HELD itself),
# `KeyDecision.kt` (KEYDEC), `HeldStore.kt` (the `dm_held`/`dm_scheduled` DAO) and
# `ScheduledSteps.kt` (the due control) make no restricted call — `ScheduledSteps` asks `SendStep`,
# whose file is the one allowed for it. `ALLOWED_FILES` and `REMOVE_ONLY` are byte-identical to
# S7's. The fourth rule below (`STEP_TRIGGERS`) arrived with this slice's review, because
# `ScheduledSteps` is the first file to reach a relay through a step object rather than a port.
#
# **Slice S9 (2026-09-22).** `Sweeper.kt` landed, and it is the file `REMOVE_ONLY` was written for
# three slices ago: SWEEP calls `Namespaces.remove` for each `dm_orphan_namespace` row (§21.12
# point 3) and makes no other restricted call. `ALLOWED_FILES` is byte-identical to S7's and
# `REMOVE_ONLY` to S6's — the entry was made deliberately then, before the file existed, so that
# the day it arrived it would be permitted for exactly one call and refused for every other. The
# one this gate now really enforces is **`Outbox.cancel`**: §10.6 and §21.10 point 2 say SWEEP must
# never cancel a DM op ("ops run to their outcome or deadline"), mutant **ME-21** is that call
# being made at expiry, and `cancel` is on `RESTRICTED` while `Sweeper.kt` is not on
# `ALLOWED_FILES` — so the mutant cannot be written in the file that would want to write it.
#
# **The S9 review then wrote it anyway, and this gate passed.** `RECEIVERS` matches the four
# conventional property *names*, and the alias rule needed an initialiser; a constructor-injected
# `private val ops: Outbox` matched neither, so `ops.cancel(tx, id)` in `Sweeper.kt` was invisible.
# The file's own header had always said that "an alias that travels through a field" was unseen —
# but §22.14 item 9 read that caveat as a corner and it was the main road: `Sweeper.kt` is the one
# production file that takes a port as a bare constructor property. `RECEIVER_TYPES` closes it by
# matching the port **types** as well, which a Kotlin declaration must write out.
# `DisplayStep.kt`, `UnreadNotices.kt`, `PairKeySteps.kt` and the `…messaging.android` alarm files
# joined the tree in the same slice and are on neither list, because none of them makes a
# restricted call either.
#
# **The BUNDLE transaction moved out of `EstablishmentSteps.kt`** in the S7 review, and the reason
# is this file's own rationale. The allowlist is by file because a file holds one step; while
# `EstablishmentSteps.kt` held four — `estStart`, `bundle`, `estReady`, `estEnd` — allowlisting it
# silently granted BUNDLE, the one establishment transaction driven by an arriving blob, the
# permission §21.7 point 7 denies it. `BundleStep.kt` restores the invariant the gate depends on.
#
# **Phase 10, slice S1a (2026-10-03): `Funding.set`.** `Funding` (Phase 10 design §7.5 item 1) marks a
# namespace as one this client funds. It moves nothing by itself, but it is the switch that makes the
# planner redeem registration capabilities and the registration step run for the namespace, so a
# call made because a blob arrived would make a funder's redemptions and registrations depend on the
# inbox (T40, design §7.5 item 7: `Funding.set` for a new generation is called by the rotating
# committer's CH-SWITCH and by the funder renewal step, never by CH-SETTLE or CH-RECV). It joins
# the restricted calls under the same rule as `Capabilities.put`: `funding` is a receiver name,
# `Funding` a receiver type (a constructor-injected `private val ledger: Funding` is a port whatever
# it is called), `set` a restricted call. `ALLOWED_FILES` is unchanged: no DM file funds anything
# (and `Funding.set` throws for a namespace that is not a channel's, so none could).
#
# **What this does not do, and who does** (Phase 10 review of S1a). The allowlist is shared by every
# restricted call, so `Funding.set` is accepted in the four files that may enqueue: harmless while no
# DM file calls it, but it would be wrong for a channel step in this module — CH-SETTLE is allowed
# to enqueue its own Welcomes and must never fund (design §7.5 item 7). The channel's counterpart of this
# gate is **G-M5** (`ch-enqueue-callers.sh`, design §13.1), which lists the funding call per step; the
# review assigned it to slice S4 (§14), the first slice with a channel step that calls a restricted
# port. Until it exists this gate must not grow channel files: S4 either gives `Funding.set` a file
# list of its own here or builds G-M5, and says which. `Inbox.reofferDeferred` is **not** restricted:
# it writes the re-offer time of local rows and makes no relay call (design §7.5 item 6), which
# `ChannelSyncNoTrafficTest` pins — it can only delay a GET while the fetched cap binds.
#
# **Phase 10, slice S4 (2026-10-04): both, and the split.** S4 builds G-M5 (`ch-enqueue-callers.sh`) and
# answers the S1a review's question with both of its options (design §19.37, the review's F-7 option (c)):
#  - **`Funding.set` has a file list of its own here, and it is empty** ([FUNDING_FILES]): no DM file funds a
#    namespace, the four allowed ones included, so the shared allowlist can no longer let an enqueueing step
#    fund. `negative-dm-enqueue-funding`'s allowed `OwnerSteps.kt` that funds is now refused too (3 → 4).
#  - **The restricted and the removal rules of the channel engine's files** (`…/messaging/channel/engine/`) are
#    G-M5's, which lists each channel step's calls one by one (CH-SETTLE may enqueue its own Welcomes and must
#    never fund — a shared list could not say it). This gate keeps its **facade and step rules** for those files
#    (a channel step that drove `sendControl` or `runOwnerMaintenance` is refused here), and keeps every rule for
#    the channel **stores** (`…/channel/store/`, which make no port call: `negative-dm-enqueue-channel`).
#    `negative-dm-enqueue-channel-engine` pins the boundary. A channel engine file does not count towards the
#    vacuity floor, which stays the DM steps'.
#
# **The review of S4 (2026-10-05, design §19.38).** Three holes, each now closed and pinned by
# `negative-dm-enqueue-placement`: (a) the boundary above matched `*/messaging/channel/engine/` anywhere, so an `:app`
# file under such a package path enqueued unseen by both gates (G-M5 read `:messaging` alone) — it is now the channel
# engine's own directory in `:messaging` and nothing else; (b) only `src/main` and `src/release` were read, so a file of
# the `debug` or `gate` build type passed — every source set but the test ones is read now (the `gate` set ships on the
# gate devices, `debug` on every debug build); (c) an allowed file was allowed by its name wherever it sat, so an
# `OwnerSteps.kt` in a new directory could enqueue — `ALLOWED_FILES`, `REMOVE_ONLY` and `STEP_ALLOWED` name files of the
# DM engine's directory (`android/messaging/src/<set>/kotlin/org/ghost/messaging/engine/`) now. `TRIGGER_ALLOWED` still
# goes by name: its files sit in four directories of two modules (declared).
#
# Usage: dm-enqueue-callers.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/negative-dm-enqueue-*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# The restricted calls, as they are written at a call site.
RESTRICTED='enqueue|cancel|request|keep|rearm|forget|register|setRelays|setListening|setSendDelay|put|set'
# `remove` is the one call SWEEP may make as well, so it is matched separately.
REMOVE='remove'

# A receiver that makes the match a **DM** call rather than any `.put(` on a map. The call sites of
# this codebase always go through a named port; a call on something else is not one of these.
RECEIVERS='outbox|registrations|namespaces|capabilities|funding'
# The **types** of those five ports. A property declared with one of them is a port whatever it is
# called, which is what closes the hole the S9 review found: the alias rule below needs an
# initialiser (`val ob = sync.outbox`), so a constructor-injected `private val ops: Outbox` was
# invisible and `ops.cancel(tx, id)` passed. That is not a hypothetical shape — `Sweeper.kt` is the
# one production file that takes a port as a bare constructor property rather than through `sync.`,
# so the evading shape is the shape that file already uses.
RECEIVER_TYPES='Outbox|Registrations|Namespaces|Capabilities|Funding'
# The funding port alone, by name and by type (Phase 10, slice S4): the funding rule must tell `funding.set(…)`
# from the `set` or `put` of another port in a file that may make those.
FUNDING_RECEIVER='funding'
FUNDING_TYPE='Funding'
# The scope functions that turn a port into `this`, so a call inside can be bare.
SCOPES='run|apply'
# The scope functions that bind the port to a lambda **parameter** instead: the call inside is
# `it.enqueue(` or `<name>.enqueue(`, never bare, so they feed the alias list and not `scoped`.
LAMBDA_SCOPES='also|let'

# Files that MAY make the restricted calls: the steps of §7.2 that §16.1 names. A file not on this
# list is refused, which is what makes a new step arrive deliberately rather than by accident.
# Every entry names the transactions it holds.
ALLOWED_FILES='
OwnerSteps.kt          ACTIVATE, OWNER-WEEK, KEEPER, REGROWS (slice S6)
SendStep.kt            SEND, RESEND (slice S7)
EstablishmentSteps.kt  EST-START, EST-READY, EST-END (slice S7; BUNDLE is BundleStep.kt, not here)
ContactKeeper.kt       KEEPER, the contact half of §7.2 KEEPER row (slice S7)
'
# Files that may call `Funding.set` (Phase 10 slice S4): none. The check applies to the files of ALLOWED_FILES,
# which the restricted rule would otherwise let fund; every other file is refused the call by that rule already.
FUNDING_FILES=''
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
# The two files that declare and implement them, and the two that may call them by name: the app
# wiring (database open, the K20 hook) and the DM actor.
#
# **What this rule does and does not see** (stated precisely after the review of S7, which found
# the comment claiming more than the code does). It matches the three entry points **by name**, so
# a file that writes `engine.runOwnerMaintenance()` is refused wherever it sits. `DmActor.kt` is on
# the list because it is the actor, but it does not in fact write any of the three names: S7 injects
# the trigger as a `() -> Unit` constructor parameter, invoked as `ownerMaintenance()`. A lambda
# that closes over the facade therefore still trips the rule **where the lambda is written** — that
# file contains the name — which is the case that matters, because an inbound path would have to
# write it somewhere. What the rule cannot see is an already-built `() -> Unit` handed on from an
# allowed file to one that may not have it; `NoReflexTest` is what covers that, since an owner
# pass publishes a bundle and shows up as a `store` line in the noisy world only.
#
# **Slice S12 (2026-09-22)** adds `MessagingRuntime.kt`, deliberately and for one line. Every step
# of `:messaging` is `internal`, so the stack `:app`'s `MessagingWiring.kt` runs has to be assembled
# inside the module, by one public class — and that assembly is where the actor's `ownerMaintenance`
# lambda is bound to `engine.runOwnerMaintenance()`, exactly as `DmDevice` binds it in the test
# worlds. The lambda is handed to the actor and to nothing else; the file makes no restricted call
# and drives no step. `MessagingWiring.kt`, on the list since S6, now exists: it is the K20 hook's
# `onActivated()`/`onRestored()` (§13.4) and nothing more.
TRIGGER_ALLOWED='Messaging.kt MessagingEngine.kt MessagingWiring.kt MessagingRuntime.kt DmActor.kt'

# **Who may start a relay-visible step** (added by the review of S8, and the same shape as the rule
# above one frame lower). The third rule closed the facade road into OWNER-WEEK; it left the
# **step-object** road open, and S8 is the slice that first drives down it: `ScheduledSteps` holds
# `SendStep` and `EstablishmentSteps` as constructor properties and calls `sendControl` and
# `estStart` on them. That is correct there — the due step is gated behind `if (timeTriggered)` in
# `DmActor.runPass` — but with no rule naming these entry points an inbound path could have reached
# `Outbox.enqueue` without writing a single restricted call, and the static half whose stated
# purpose is "a new call site added under a new condition is exactly what NoReflexTest would not
# exercise" would have passed it.
#
# The names are matched the way `TRIGGERS` are: by name, with or without a receiver, because they
# are unique to these two step objects. `resend` is included even though OUTCOME's use of it is the
# one §7.5 requires, for the same reason `DmActor.kt` is on the trigger list — the allowlist says
# where the call may be *written*.
#
# **No vacuity floor, deliberately.** The restricted-call floor below already refuses a tree the
# gate would scan without reading any DM code, and a second floor would make each of the
# single-purpose negative fixtures report an extra violation, which their exact hit counts in
# `self-test.sh` exist to pin. `negative-dm-enqueue-step` is the fixture that keeps this rule
# honest instead.
STEP_TRIGGERS='sendControl|flushPending|resend|estStart|estReady|estEnd'
# The two files that declare them, and the four that drive them: the actor's time-triggered and
# establishment passes, the facade's user actions, OUTCOME's resend, and the due scheduled control.
STEP_ALLOWED='SendStep.kt EstablishmentSteps.kt DmActor.kt MessagingEngine.kt OutcomeStep.kt ScheduledSteps.kt'

# The DM engine's own directory (relative to GHOST_ROOT; the source set is any): the files the allowlists below name
# are files of it, and of no other directory (the review of S4, §19.38).
DM_ENGINE_GLOB='android/messaging/src/*/org/ghost/messaging/engine/*'

in_dm_engine() { # $1 = path relative to GHOST_ROOT
  # shellcheck disable=SC2254
  case "$1" in $DM_ENGINE_GLOB) return 0 ;; esac
  return 1
}

allowed_file() { # $1 = basename, $2 = path relative to GHOST_ROOT
  local name
  in_dm_engine "$2" || return 1
  while read -r name _; do
    [ -n "$name" ] || continue
    [ "$name" = "$1" ] && return 0
  done <<< "$ALLOWED_FILES"
  return 1
}

funding_allowed() { # $1 = basename
  case " $FUNDING_FILES " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

remove_allowed() { # $1 = basename, $2 = path relative to GHOST_ROOT
  allowed_file "$1" "$2" && return 0
  in_dm_engine "$2" || return 1
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

step_allowed() { # $1 = basename, $2 = path relative to GHOST_ROOT
  in_dm_engine "$2" || return 1
  case " $STEP_ALLOWED " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

# The production sources of the two modules that drive the DM engine. `find` at any depth, like
# dm-no-fts.sh: a nested module must not go unscanned while the others satisfy the vacuity floor.
# `src/release` too: it ships beside `src/main` (Phase 9 review GATES-2); and since the review of S4 (§19.38) every
# other source set but the test ones — `debug`, `gate`, a build type or flavour added later.
dm_caller_files() {
  find "$GHOST_ROOT/android/messaging" "$GHOST_ROOT/android/app" \
    -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) -path '*/src/*' \
    ! -path '*/src/test/*' ! -path '*/src/test[A-Z]*' ! -path '*/src/androidTest*' ! -path '*/src/testFixtures*' \
    -print 2>/dev/null || true
}

# `<first line number>:<text>`, with every continuation line (one that begins with `.`) folded into
# the line that carries its receiver. `sync.namespaces` on one line and `.register(` on the next is
# one call site, reported where the receiver is.
#
# Comment lines are dropped before the fold, and so is the tail of a line after `//`. Prose is not
# code: a KDoc line that happens to contain `request (` matched the bare-call branch of
# `is_call_site` in any file that also scoped over a port, so the gate could report a violation at
# a sentence. Dropping them costs nothing — a restricted call inside a comment is not a call.
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

SCANNED=0
WITH_CALL=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  rel="${file#"$GHOST_ROOT"/}"
  base="${file##*/}"
  SCANNED=$((SCANNED + 1))
  # A channel engine file: its restricted and removal calls are G-M5's (see the S4 note above); the facade
  # and step rules below still read it. The channel engine's own directory in `:messaging`, and no other (§19.38).
  channel_engine=0
  case "$rel" in
    android/messaging/src/*/org/ghost/messaging/channel/engine/*) channel_engine=1 ;;
  esac

  # Each hit is read from a variable and matched with a here-string, never `producer | grep -q`:
  # under `set -o pipefail` such a pipeline fails whenever grep stops reading early (EPIPE), the
  # race the static-gate sweep of 2026-09-20 removed from five other gates.
  text="$(joined_lines "$file")"

  # Local aliases of a port (`val ob = sync.outbox`) and scope functions over one (`with(sync.outbox)`,
  # `sync.outbox.run { … }`), both of which let a call site drop the receiver.
  alias_alt=""
  scoped=0
  # The same two lists for the funding port alone, which the funding rule reads (Phase 10, slice S4).
  funding_alt=""
  funding_scoped=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [[ "$line" =~ (val|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*(:[^=]*)?=[^=]*($RECEIVERS) ]]; then
      alias_alt="${alias_alt:+$alias_alt|}${BASH_REMATCH[2]}"
    fi
    if [[ "$line" =~ (val|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*(:[^=]*)?=[^=]*($FUNDING_RECEIVER) ]]; then
      funding_alt="${funding_alt:+$funding_alt|}${BASH_REMATCH[2]}"
    fi
    rest="$line"
    while [[ "$rest" =~ (val|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*:[[:space:]]*($FUNDING_TYPE)([^A-Za-z0-9_]|$) ]]; do
      funding_alt="${funding_alt:+$funding_alt|}${BASH_REMATCH[2]}"
      rest="${rest#*"${BASH_REMATCH[0]}"}"
    done
    if [[ "$line" =~ with[[:space:]]*\([^\)]*($FUNDING_RECEIVER) ]] ||
       [[ "$line" =~ ($FUNDING_RECEIVER)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($SCOPES)[[:space:]]*[\{\(] ]]; then
      funding_scoped=1
    fi
    if [[ "$line" =~ ($FUNDING_RECEIVER)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($LAMBDA_SCOPES)[[:space:]]*[\{\(] ]]; then
      funding_alt="${funding_alt:+$funding_alt|}it"
      if [[ "$line" =~ \{[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*-\> ]]; then
        funding_alt="$funding_alt|${BASH_REMATCH[1]}"
      fi
    fi
    if [ -n "$funding_alt" ] && [[ "$line" =~ ^[[:space:]]*\{[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*-\> ]]; then
      funding_alt="$funding_alt|${BASH_REMATCH[1]}"
    fi
    # The same property declared by its **type** and with no initialiser: a constructor parameter
    # (`private val ops: Outbox,`) or a field assigned elsewhere. The name is then free, so only the
    # type identifies the port (S9 review).
    #
    # The loop is not decoration: `=~` reports the **first** match of a line, and a whole primary
    # constructor is one joined line, so a single test would see `ops` and miss the `registry`
    # beside it. Each round eats the match it consumed.
    rest="$line"
    while [[ "$rest" =~ (val|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*:[[:space:]]*($RECEIVER_TYPES)([^A-Za-z0-9_]|$) ]]; do
      alias_alt="${alias_alt:+$alias_alt|}${BASH_REMATCH[2]}"
      rest="${rest#*"${BASH_REMATCH[0]}"}"
    done
    if [[ "$line" =~ with[[:space:]]*\([^\)]*($RECEIVERS) ]] ||
       [[ "$line" =~ ($RECEIVERS)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($SCOPES)[[:space:]]*[\{\(] ]]; then
      scoped=1
    fi
    # `also` / `let` over a port: the receiver is the lambda's parameter, so it joins the alias
    # list. `it` is the implicit name; `{ ob ->` names it explicitly.
    if [[ "$line" =~ ($RECEIVERS)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($LAMBDA_SCOPES)[[:space:]]*[\{\(] ]]; then
      alias_alt="${alias_alt:+$alias_alt|}it"
      if [[ "$line" =~ \{[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*-\> ]]; then
        alias_alt="$alias_alt|${BASH_REMATCH[1]}"
      fi
    fi
    # The same, with the lambda's parameter named on a later line than the receiver.
    if [ -n "$alias_alt" ] && [[ "$line" =~ ^[[:space:]]*\{[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*-\> ]]; then
      alias_alt="$alias_alt|${BASH_REMATCH[1]}"
    fi
  done <<< "$text"

  # $1 = the joined line, $2 = the call names this pass looks for.
  # A `?` between a receiver and its `.` is a Kotlin safe call and nothing else: `sync.outbox?.
  # cancel(tx, id)` is the same call site as `sync.outbox.cancel(tx, id)`. It is admitted
  # everywhere a `.` is, because the first version of this gate matched only the bare dot and a
  # safe call therefore passed — found by the S9 review while checking that the file SWEEP lives in
  # really cannot write `Outbox.cancel` (mutant ME-21). `joined_lines` folds a continuation that
  # begins with `?.` for the same reason.
  #
  # Two shapes more (found by the Phase 10 review of S1a, which tried them on `Funding.set`; both were
  # equally open for `Outbox.enqueue`): a **callable reference** to a restricted call, which makes the
  # call later and elsewhere (`val fund = sync.funding::set; fund(tx, ns, true)`), reported at the
  # reference, and a **parenthesized receiver** (`(sync.funding).set(…)`), where the `)` kept the
  # receiver off the `.` the first rule looks for.
  is_call_site() {
    [[ "$1" =~ \.[[:space:]]*($2)[[:space:]]*\( ]] && [[ "$1" =~ ($RECEIVERS)[[:space:]]*\??[[:space:]]*\.[[:space:]]*[a-zA-Z] ]] && return 0
    [ -n "$alias_alt" ] && [[ "$1" =~ (^|[^A-Za-z0-9_])($alias_alt)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($2)[[:space:]]*\( ]] && return 0
    [ "$scoped" = 1 ] && [[ "$1" =~ (^|[^.A-Za-z0-9_])($2)[[:space:]]*\( ]] && return 0
    local ports="$RECEIVERS${alias_alt:+|$alias_alt}"
    [[ "$1" =~ (^|[^A-Za-z0-9_])($ports)[[:space:]]*\??[[:space:]]*::[[:space:]]*($2)([^A-Za-z0-9_]|$) ]] && return 0
    [[ "$1" =~ (^|[^A-Za-z0-9_])($ports)[[:space:]]*\)[[:space:]]*\??[[:space:]]*\.[[:space:]]*($2)[[:space:]]*\( ]] && return 0
    return 1
  }

  # The funding rule's recognizer (Phase 10, slice S4): `is_call_site` for the one call `set`, with the funding
  # port as the only receiver and its own aliases and scopes. Bash scopes `local` dynamically, so the call below
  # reads these three values in place of the file's, every shape above included (a line break, an alias, a typed
  # port, a scope function, a safe call, a callable reference, a parenthesized receiver).
  is_funding_call() {
    local RECEIVERS="$FUNDING_RECEIVER" alias_alt="$funding_alt" scoped="$funding_scoped"
    is_call_site "$1" 'set'
  }

  restricted_hits=""
  remove_hits=""
  funding_hits=""
  trigger_hits=""
  step_hits=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [ "$channel_engine" = 0 ]; then
      if is_call_site "$line" "$RESTRICTED"; then restricted_hits+="$line"$'\n'; fi
      if is_call_site "$line" "$REMOVE"; then remove_hits+="$line"$'\n'; fi
      if is_funding_call "$line"; then funding_hits+="$line"$'\n'; fi
    fi
    # The facade's entry points are matched by name, with or without a receiver: they are unique to
    # this facade, so a line that writes one either declares it or calls it.
    if [[ "$line" =~ (^|[^A-Za-z0-9_])($TRIGGERS)[[:space:]]*\( ]]; then trigger_hits+="$line"$'\n'; fi
    # The step objects' relay-visible entry points, matched the same way.
    if [[ "$line" =~ (^|[^A-Za-z0-9_])($STEP_TRIGGERS)[[:space:]]*\( ]]; then step_hits+="$line"$'\n'; fi
  done <<< "$text"

  if [ -n "$restricted_hits" ] || [ -n "$remove_hits" ]; then
    WITH_CALL=$((WITH_CALL + 1))
  fi

  if [ -n "$restricted_hits" ] && ! allowed_file "$base" "$rel"; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      fail "$rel:$line (G-DM2: only the SEND, RESEND, EST-*, OWNER-WEEK, ACTIVATE, KEEPER and REGROWS steps may enqueue, register, listen, install or fund)"
    done <<< "$restricted_hits"
  fi
  # A file the rule above lets enqueue may still not fund: `Funding.set` has a list of its own (FUNDING_FILES).
  # Every other file is refused the call by the rule above already, and is not reported twice.
  if [ -n "$funding_hits" ] && allowed_file "$base" "$rel" && ! funding_allowed "$base"; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      fail "$rel:$line (G-DM2: no DM step funds a namespace; Funding.set has a file list of its own, and it is empty)"
    done <<< "$funding_hits"
  fi
  if [ -n "$remove_hits" ] && ! remove_allowed "$base" "$rel"; then
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
  if [ -n "$step_hits" ] && ! step_allowed "$base" "$rel"; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      fail "$rel:$line (G-DM2: a send, a resend, a control or an establishment step is driven by the actor, the facade, OUTCOME or the due scheduled control, and by nothing else)"
    done <<< "$step_hits"
  fi
done < <(dm_caller_files)

# Vacuity, twice over, because a gate that scans nothing passes. At least one production source of
# the DM modules must be found, and at least one of them must really make one of the restricted
# calls — the day `OwnerSteps.kt` moves or is renamed, this gate must fail rather than go quiet.
[ "$SCANNED" -gt 0 ] || fail "no DM production sources found under $GHOST_ROOT/android (the gate would pass vacuously)"
[ "$WITH_CALL" -gt 0 ] || \
  fail "none of the $SCANNED scanned DM sources makes a restricted call (the gate would pass vacuously; see the S6 note in this script)"

finish dm-enqueue-callers
