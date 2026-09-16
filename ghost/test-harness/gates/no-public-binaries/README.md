# no-public-binaries.sh fixtures (gate G-L5)

Each directory is a fixture root that mirrors the repository: `<case>/ghost` is `GHOST_ROOT` (with
the declaration `ghost/scripts/gates/repository-visibility.txt`), the workflows are in
`<case>/.github/workflows`. `scripts/gates/self-test.sh` runs the gate on each root with no event
payload (`GHOST_VISIBILITY_EVENT` set and empty), except `event-mismatch`, which also runs with its
`event.json`, and requires the named outcome and reason. Every root but the one under test carries
a well-formed workflow, so each fails only for its own reason.

| case | outcome | reason |
|---|---|---|
| positive-private | pass | private; the native hand-off with `retention-days: 1`, downloaded by a later job; a text report kept 3 days |
| positive-public | pass | public; only a text report is uploaded |
| public-apk | fail | `uploads binaries (APK, AAR, .so, jniLibs or an image) while the repository is not declared private` (an APK) |
| public-handoff | fail | the same reason for the native hand-off: hand-offs are allowed only in a private repository |
| private-handoff-retention | fail | `must set retention-days: 1` (the hand-off kept 3 days) |
| private-apk | fail | `is not an internal native hand-off` (an APK upload in a private repository) |
| private-handoff-unconsumed | fail | `no job of this workflow downloads it` |
| no-retention | fail | `sets no retention-days (1 to 7)` (a report upload) |
| release-publish | fail | `publishes outside the repository (gh release upload)` |
| event-mismatch | pass without the event; fail with it | `the event payload says the repository is public` |
| no-declaration | fail | `repository-visibility.txt missing` |
