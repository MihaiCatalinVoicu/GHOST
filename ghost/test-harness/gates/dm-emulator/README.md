# Fixtures for the emulator report check (`scripts/gates/dm-emulator-check.sh`)

Phase 9 design §15.9 (slice S12). `pass/` is what `scripts/device/dm-emulator-run.sh` writes for a
green run on API 29 and API 35, in the raw `am instrument -r -w` shape: the result bundle's
`stream` printed as `INSTRUMENTATION_RESULT: stream=<first line>` followed by its other lines, then
`INSTRUMENTATION_CODE: -1`. `cases.txt` stands in for `protocol/test-vectors/dm_equivalence.txt`
(`GHOST_DM_EQUIVALENCE_CASES`), so the fixture's equivalence line counts 3 cases.

`self-test.sh` accepts `pass/` for API 29 and 35 and derives every negative case from a copy of it,
one change each: an API level with no directory (not run), a suite file missing (not run), a
skipped test, one test fewer than the slice runs, the control not detected, an equivalence line
over fewer cases than the case file holds, a result code of 0, a crashed process, an emulator of
the wrong API level or ABI, and the SCN-D logcat line missing.

Nothing here is a device's output: it is the check's counterpart for its own self-test.
