# Positive fixture for no-logging.sh: near misses that must pass

Used by `scripts/gates/self-test.sh` (Phase 9 design §22.33 item 16). `write!` to a `Formatter` and
`writeln!` to a buffer are not the process's streams, and the words stdout and stderr in a comment
or a string are not handles.
