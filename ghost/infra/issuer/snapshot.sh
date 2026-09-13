#!/usr/bin/env bash
# Runbook B1 (Phase 8 design §6.3, §19.15; RUNBOOK.md section 6): one snapshot of issuer.redb, run
# hourly by cron on the issuer host, as root, with GHOST_ISSUER_HOST_DIR naming the host directory:
#   7 * * * * root GHOST_ISSUER_HOST_DIR=/srv/ghost-issuer /srv/ghost-src/ghost/infra/issuer/snapshot.sh
# The copy is taken with the issuer stopped for a few seconds (a copy during a write can be torn);
# tor, monerod and wallet-rpc keep running. The stopped issuer was ended by a signal and closed
# nothing; the ops tools read the snapshot through a recovered private copy of their own
# (RedbSnapshot in issuer/crates/service/src/store.rs), and the snapshot keeps its bytes.
#
# The script starts only an issuer it stopped itself:
#   - while $H/maintenance exists an operator procedure holds the containers (I1, R5, B1 restore,
#     K2, K3, M2): nothing is touched and nothing is printed;
#   - an issuer that is not running (stopped by an operator, or restarting after a refused start) is
#     left alone, with a fixed message for cron's mail;
#   - $H/snapshot.lock is held from the check of $H/maintenance until the issuer runs again; a
#     procedure creates $H/maintenance and then takes the lock once (flock "$H/snapshot.lock" true),
#     so no snapshot is in flight when it starts.
# Exit status 0: a snapshot was written, or a maintenance window skipped it.
set -euo pipefail

H="${GHOST_ISSUER_HOST_DIR:?name the issuer host directory}"
COMPOSE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/docker-compose.stagenet.yml"

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

exec 9> "$H/snapshot.lock"
if ! flock -n 9; then
  echo "snapshot: skipped, $H/snapshot.lock is held" >&2
  exit 1
fi
[ ! -e "$H/maintenance" ] || exit 0
if [ -z "$(compose ps --status running --quiet issuer)" ]; then
  echo "snapshot: skipped, the issuer is not running (RUNBOOK.md, section 3)" >&2
  exit 1
fi

rc=0
if compose stop issuer > /dev/null 2>&1; then
  install -m 0600 "$H/data/issuer.redb" "$H/snapshots/issuer-$(date -u +%Y%m%d%H).redb" || rc=1
else
  rc=1
fi
# This run stopped the issuer (or tried to): it starts it again whatever the copy did.
compose start issuer > /dev/null 2>&1 || rc=1
if [ "$rc" != 0 ]; then
  echo "snapshot: failed, no snapshot written; the issuer was started again (RUNBOOK.md, section 6)" >&2
fi
exit "$rc"
