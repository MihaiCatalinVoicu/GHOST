# vendor-tests suite verdict fixtures

`cargo test` logs for `scripts/ci/vendor-tests.sh --suite-verdict <log> <exit code>` (Phase 9 design
§16.2 `vendor-tests`, §22.35): the decision the libcrux mode applies to each crate's own suite.

| Fixture | Exit | Verdict |
|---|---|---|
| `suite-pass.txt` | 0 | `PASS 3` (unit, integration and doc-tests summed) |
| `suite-pass.txt` | 101 | `FAIL exit 101` |
| `suite-failed.txt` | 101 | `FAIL a test failed` |
| `suite-zero.txt` | 0 | `FAIL zero tests ran` (a suite that runs nothing proves nothing) |
| `suite-build-error.txt` | 101 | `FAIL the suite did not build` |
