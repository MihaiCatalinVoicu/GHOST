#!/usr/bin/env bash
# V10-14: the measured nightly occupancy of the existing scheduled workflows (design §13.2, R-7,
# Q20): for every run started by `schedule` in the last N days, every job's runner, start and end,
# summed per night (runner-minutes) and spanned per night (first job start to last job end).
# Evidence tooling, not product code. Needs `gh` authenticated for the repository.
#   v10-14-nightly.sh [days (default 14)] [repo (default MihaiCatalinVoicu/GHOST)]
set -euo pipefail
DAYS="${1:-14}"
REPO="${2:-MihaiCatalinVoicu/GHOST}"
since="$(date -u -d "-$DAYS days" +%Y-%m-%dT%H:%M:%SZ)"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
for wf in dm-emulator dm-privacy-gate dm-state-models entitlement-exit-gate messaging-exit-gate monero-regtest signer-timing t2-exit-gate; do
  gh api --paginate "repos/$REPO/actions/workflows/$wf.yml/runs?event=schedule&per_page=100&created=>=$since" \
    --jq '.workflow_runs[] | [.id, .created_at, .status, (.conclusion // "-")] | @tsv' |
  while IFS=$'\t' read -r id created status conclusion; do
    gh api --paginate "repos/$REPO/actions/runs/$id/jobs?per_page=100&filter=all" \
      --jq ".jobs[] | [\"$wf\", \"$id\", \"$created\", .name, (if (.runner_name // \"\") == \"\" then \"-\" else .runner_name end), (.started_at // \"-\"), (.completed_at // \"-\"), (.conclusion // .status // \"-\")] | join(\"|\")" >> "$tmp" || true
  done
done
# night = the UTC date of the run's creation (all crons fire between 02:00 and 04:15 UTC).
printf 'workflow\trun\tcreated\tjob\trunner\tstarted\tcompleted\tresult\tminutes\n'
while IFS='|' read -r wf id created name runner started completed result; do
  if [ "$started" != "-" ] && [ "$completed" != "-" ] && [ "$result" != "skipped" ]; then
    m=$(( ( $(date -u -d "$completed" +%s) - $(date -u -d "$started" +%s) ) / 60 ))
  else
    m=0
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$wf" "$id" "$created" "$name" "$runner" "$started" "$completed" "$result" "$m"
done < "$tmp"
