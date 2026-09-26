# dm-fuzz verdict fixtures

libFuzzer logs for `scripts/ci/dm-fuzz.sh --verdict <log> <exit code>` (Phase 9 design §16.2
`dm-fuzz`, §22.35), the decision the nightly job applies to each target's run. `pass.txt` is the
tail of a real run (the `card` target, 31 s); every other file is that log with one failure.

| Fixture | Exit | Verdict |
|---|---|---|
| `pass.txt` | 0 | `PASS 503141` |
| `pass.txt` | 1 | `FAIL exit 1` (a clean log from a run that did not exit 0) |
| `crash.txt` | 1 | `FAIL crash` (a panic: libFuzzer's deadly signal) |
| `asan.txt` | 1 | `FAIL crash` (an AddressSanitizer report) |
| `timeout.txt` | 70 | `FAIL timeout` (one input over `-timeout`) |
| `oom.txt` | 71 | `FAIL out-of-memory` (over `-rss_limit_mb`) |
| `zero.txt` | 0 | `FAIL zero executions` |
| `truncated.txt` | 137 | `FAIL no statistics` (the run was killed before its final statistics) |
