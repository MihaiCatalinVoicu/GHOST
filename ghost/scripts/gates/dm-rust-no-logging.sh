#!/usr/bin/env bash
# Gate G-R4, dependency-graph half (Phase 9 design §16.1 G-R4 as corrected by S0′, evidence V-8;
# invariant T3; S0′ gate slice, §22.33): **the DM crate brings no logging into the library.**
#
#   1. `ghost-client-dm`'s normal graph **without** the `jni-bridge` feature (its `default` is empty)
#      contains no `log`, no `tracing*` crate and no logger implementation;
#   2. **with** `jni-bridge` — the graph `ghost-client-net` links — `log` is present only because
#      `jni` 0.21.1 depends on it: `jni` is its one direct dependent in the graph (`cargo tree -i`),
#      and there is still no `tracing*` crate and no logger implementation;
#   3. no crate of that graph calls `log::set_logger`, `log::set_boxed_logger` or
#      `log::set_max_level` (the `log` crate itself, which defines them, excepted): the facade calls
#      `jni` makes go nowhere unless something installs a logger, and nothing in GHOST's graph may;
#   4. both graphs contain `ghost-client-dm` and `vodozemac`, and the second `jni`, or the gate
#      fails rather than pass over a query that selected the wrong package.
# A logger implementation is any of: env_logger, pretty_env_logger, android_logger, android_log-sys,
# simple_logger, simplelog, fern, log4rs, flexi_logger, stderrlog, syslog, systemd-journal-logger,
# slog* and tracing* (tracing, tracing-core, tracing-subscriber, tracing-log, tracing-android, …).
# The graphs are read for every target (`--target all`), so a platform-only edge counts too.
#
# The source half of G-R4 — no `println!`, `eprintln!`, `dbg!`, `log::` or `tracing::` in the crate's
# own sources, and since the evasion review of these gates (design §22.33 item 16) no standard stream
# handle either (`writeln!(std::io::stderr(), …)` names no print macro) — is `no-logging.sh`, which
# reads every `client-core` source already. What the linked
# code of the *other* crates of the graph contains (jni's 23 `log::` sites, the re-exports of
# `serde_core`) is G-R8's (`dm-vendored-clock-log.sh`), against its justified baseline.
#
# Runs in the CI `rust` job and in `rust-gates.sh` (it needs cargo and the lock, not a build).
# Self-test hooks (scripts/gates/self-test.sh): GHOST_DMLOG_FORBID_EXTRA adds a crate name to the
# forbidden list; GHOST_DMLOG_LOG_VIA replaces the allowed direct dependents of `log` (default
# `jni`); GHOST_DMLOG_REQUIRED replaces the packages both graphs must contain; GHOST_DMLOG_BAD_SPEC
# makes the query of the named package fail; GHOST_DMLOG_INSTALLER adds a function name to the
# logger-installing calls searched for.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
# cargo tree's text is parsed below: plain output whatever the job exports (CARGO_TERM_COLOR=always
# colours the `(*)` markers into a pipe; see dm-vendored-clock-log.sh).
export CARGO_TERM_COLOR=never
cd "$GHOST_ROOT"
err="$(mktemp)"
trap 'rm -f "$err"' EXIT

DM="${GHOST_DMLOG_BAD_SPEC:+$GHOST_DMLOG_BAD_SPEC@0.0.0-no-such-version}"
DM="${DM:-ghost-client-dm}"
LOGGERS='^(log|env_logger|pretty_env_logger|android_logger|android_log-sys|simple_logger|simplelog|fern|log4rs|flexi_logger|stderrlog|syslog|systemd-journal-logger|slog.*|tracing.*)$'
[ -z "${GHOST_DMLOG_FORBID_EXTRA:-}" ] || LOGGERS="${LOGGERS%)\$}|${GHOST_DMLOG_FORBID_EXTRA})\$"
LOG_VIA="${GHOST_DMLOG_LOG_VIA:-jni}"
REQUIRED="${GHOST_DMLOG_REQUIRED:-ghost-client-dm vodozemac}"
INSTALLERS='set_logger|set_boxed_logger|set_max_level'
[ -z "${GHOST_DMLOG_INSTALLER:-}" ] || INSTALLERS="$INSTALLERS|$GHOST_DMLOG_INSTALLER"

tree() { # args passed to cargo tree; on error: print cargo's stderr and fail the gate
  if ! cargo tree --locked -q "$@" 2>"$err"; then
    cat "$err" >&2
    fail "cargo tree $* failed"
    finish dm-rust-no-logging
  fi
}
names() { sed -E 's/ \(\*\)$//; s/ \(proc-macro\)$//' | awk '{print $1}' | sort -u; }

without="$(tree -p "$DM" -e normal --target all --prefix none -f '{p}')"
with="$(tree -p "$DM" -e normal --features jni-bridge --target all --prefix none -f '{p}')"
without_names="$(names <<< "$without")"
with_names="$(names <<< "$with")"

for want in $REQUIRED; do
  grep -qx -- "$want" <<< "$without_names" || fail "$want is not in ghost-client-dm's graph without jni-bridge (the gate would pass vacuously)"
  grep -qx -- "$want" <<< "$with_names" || fail "$want is not in ghost-client-dm's graph with jni-bridge (the gate would pass vacuously)"
done
grep -qx jni <<< "$with_names" || fail "jni is not in ghost-client-dm's graph with jni-bridge (the query did not select the JNI surface)"

# 1. Without jni-bridge: no logging crate at all, `log` included.
while IFS= read -r name; do
  [ -n "$name" ] || continue
  fail "ghost-client-dm without jni-bridge links '$name' (G-R4: no log, tracing or logger crate in the DM graph)"
done < <(grep -E -- "$LOGGERS" <<< "$without_names" || true)

# 2. With jni-bridge: `log` only through `jni`, nothing else of the list.
while IFS= read -r name; do
  [ -n "$name" ] || continue
  [ "$name" = log ] && continue
  fail "ghost-client-dm with jni-bridge links '$name' (G-R4: no tracing or logger crate in the DM graph)"
done < <(grep -E -- "$LOGGERS" <<< "$with_names" || true)
if grep -qx log <<< "$with_names"; then
  inverse="$(tree -p "$DM" -e normal --features jni-bridge --target all -i log --prefix depth -f '{p}')"
  dependents="$(sed -nE 's/^1([^ ]+) .*/\1/p' <<< "$inverse" | sort -u)"
  [ -n "$dependents" ] || fail "cargo tree -i log listed no dependent of log (the check would pass vacuously)"
  while IFS= read -r dep; do
    [ -n "$dep" ] || continue
    ok=0
    for allowed in $LOG_VIA; do [ "$dep" = "$allowed" ] && ok=1; done
    [ "$ok" = 1 ] || fail "'$dep' depends on log directly in ghost-client-dm's graph (G-R4: log is reached only through jni)"
  done <<< "$dependents"
fi

# 3. Nothing installs a logger. The sources of every package of the jni-bridge graph but `log`, from
# `cargo metadata` (the registry sources are unpacked on any machine that resolved the lock).
meta="$(cargo metadata --locked --format-version 1 2>"$err")" || {
  cat "$err" >&2; fail "cargo metadata failed"; finish dm-rust-no-logging; }
# Keyed by name and version: a second version of a name elsewhere in the lock is not in the graph.
keys="$(sed -E 's/ \(\*\)$//; s/ \(proc-macro\)$//' <<< "$with" | awk '{sub(/^v/, "", $2); print $1 " " $2}' | sort -u)"
dirs="$(GRAPH="$keys" perl -MJSON::PP -e '
  my %want = map { $_ => 1 } grep { length && !/^log / } split /\n/, $ENV{GRAPH};
  local $/; my $m = JSON::PP->new->decode(<STDIN>);
  for my $p (@{ $m->{packages} }) {
    next unless $want{"$p->{name} $p->{version}"};
    # On Windows cargo writes the path with backslashes; a directory not found here would fail
    # every package as having no source (the gate first ran on Windows at the integration).
    (my $dir = $p->{manifest_path}) =~ tr{\\}{/};
    $dir =~ s{/Cargo\.toml$}{};
    print "$p->{name} $p->{version} $dir\n";
  }' <<< "$meta")"
scanned=0
while read -r name version dir; do
  [ -n "$name" ] || continue
  scanned=$((scanned + 1))
  [ -d "$dir/src" ] || { fail "$name $version: no source directory at $dir/src (cannot check for a logger)"; continue; }
  hits="$(grep -rnE --include='*.rs' -- "\\b($INSTALLERS)[[:space:]]*\\(" "$dir/src" || true)"
  [ -z "$hits" ] || while IFS= read -r line; do
    fail "$name $version: ${line#"$dir"/} (G-R4: no crate of the DM graph installs a logger)"
  done <<< "$hits"
done <<< "$dirs"
[ "$scanned" -gt 0 ] || fail "no package source of ghost-client-dm's graph was found (the logger check would pass vacuously)"

echo "[dm-rust-no-logging] $(wc -l <<< "$without_names") packages without jni-bridge, $(wc -l <<< "$with_names") with it; log's dependents: ${dependents:-none}; $scanned package sources read"
finish dm-rust-no-logging
