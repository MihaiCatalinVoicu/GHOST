#!/usr/bin/env bash
# Runbook B1 (Phase 8 design §6.3, §6.4, §19.15; RUNBOOK.md section 6): prunes issued.journal after
# the newest snapshot, run hourly by cron on the issuer host, as root, half an hour after the
# snapshot of the hour:
#   37 * * * * root GHOST_ISSUER_HOST_DIR=/srv/ghost-issuer /srv/ghost-src/ghost/infra/issuer/journal-prune.sh
# ghost-issuer-ops journal-prune, in the ops container (no network), verifies the newest snapshot as
# B1 does (schema 1, the reconciliation invariants) and only then removes the journal segments
# whose entries are all older than the 7-day re-serve window and applied in that snapshot; the
# latest segment, the one the issuer writes, stays, and no segment is opened for writing, so the
# issuer keeps running. The journal directory is mounted for this run only, with DAC_OVERRIDE for
# this run only (its files belong to the issuer's user; the ops service drops every capability).
#   - while $H/maintenance exists an operator procedure holds the host directory: nothing is done
#     and nothing is printed;
#   - $H/snapshot.lock is held for the run, so no snapshot and no procedure starts meanwhile;
#   - a run that pruned (or found nothing to prune) prints nothing: the tool's report goes to
#     /dev/null and only its failure lines (standard error) reach cron's mail.
# Exit status 0: pruned or nothing to prune, or a maintenance window skipped the run.
set -euo pipefail

H="${GHOST_ISSUER_HOST_DIR:?name the issuer host directory}"
COMPOSE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/docker-compose.stagenet.yml"

exec 9> "$H/snapshot.lock"
if ! flock -n 9; then
  echo "journal-prune: skipped, $H/snapshot.lock is held" >&2
  exit 1
fi
[ ! -e "$H/maintenance" ] || exit 0

# The newest snapshot by name: issuer-<YYYYMMDDHH>.redb (UTC) sorts by time.
newest=
for f in "$H"/snapshots/issuer-*.redb; do
  name="${f##*/}"
  if [[ "$name" =~ ^issuer-[0-9]{10}\.redb$ ]] && [[ "$name" > "$newest" ]]; then
    newest="$name"
  fi
done
if [ -z "$newest" ]; then
  echo "journal-prune: skipped, no snapshot in $H/snapshots (RUNBOOK.md, section 6)" >&2
  exit 1
fi

docker compose -f "$COMPOSE_FILE" run --rm --cap-add DAC_OVERRIDE -v "$H/data/journal:/journal" \
  ops journal-prune --database "/snapshots/$newest" --journal /journal \
  --schedule /etc/ghost/schedule.ghes --now "$(date +%s)" > /dev/null
