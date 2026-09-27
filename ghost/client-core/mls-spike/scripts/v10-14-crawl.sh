#!/usr/bin/env bash
# V10-14 (review pass): every workflow run of the repository since a date, **whatever its trigger**
# (schedule, push, pull_request, workflow_dispatch), and every job of every attempt with its runner,
# creation, start and end. The first crawl (v10-14-nightly.sh) read scheduled runs only and so
# attributed to the nightly load the queues that push-triggered runs build on the same runners
# (docs/design/faza10-s0-evidence.md §14 and Appendix C). Aggregation: v10-14-aggregate.awk.
# Evidence tooling, not product code. Needs `gh` authenticated for the repository. Crawl only
# after the last night of interest has finished: a job still queued has no start or end.
#   v10-14-crawl.sh <since, e.g. 2026-09-16> [repo (default MihaiCatalinVoicu/GHOST)] > jobs-all.tsv
set -euo pipefail
SINCE="${1:?usage: v10-14-crawl.sh <since YYYY-MM-DD> [repo]}"
REPO="${2:-MihaiCatalinVoicu/GHOST}"
runs="$(mktemp)"
trap 'rm -f "$runs"' EXIT
gh api --paginate "repos/$REPO/actions/runs?per_page=100&created=>=$SINCE" \
  --jq '.workflow_runs[] | [.id, (.path | sub("^\\.github/workflows/"; "") | sub("\\.ya?ml$"; "")), .event, .created_at, (.run_started_at // "-"), .run_attempt, .status, (.conclusion // "-"), .head_branch] | @tsv' > "$runs"
printf 'workflow\tevent\trun\tattempt\tbranch\trun_created\trun_started\tjob\trunner\tjob_created\tstarted\tcompleted\tstatus\tresult\n'
while IFS=$'\t' read -r id wf ev created started attempt status conclusion branch; do
  gh api --paginate "repos/$REPO/actions/runs/$id/jobs?per_page=100&filter=all" \
    --jq ".jobs[] | [\"$wf\", \"$ev\", \"$id\", (.run_attempt|tostring), \"$branch\", \"$created\", \"$started\", (.name | gsub(\"\\t\"; \" \")), (if (.runner_name // \"\") == \"\" then \"-\" else .runner_name end), (.created_at // \"-\"), (.started_at // \"-\"), (.completed_at // \"-\"), .status, (.conclusion // \"-\")] | @tsv" || true
done < "$runs"
