# Fixtures for G-DM5 (`scripts/gates/apk-no-debug-hooks.sh`)

Phase 9 design §16.1 G-DM5, §21.13 points 5 and 7 (slice S12). `self-test.sh` runs the gate on each
tree below with `GHOST_ROOT` pointed at it (and the release-source floor lowered to 1), and on each
mapping with `GHOST_ROOT` at the real tree:

- `release-ref/`: a release source set imports and calls the debug key-change hook. Two lines (the
  import and the call); the comment that names the hook is prose and is not counted.
- `harness-package/`: a release source set declares a `harness` package. One line.
- `equivalence/`: the equivalence-test entry point is declared on `DmNative` in `src/main`. One line.
- `no-gate/`: release sources and no `gate` or `androidTest` source set. One line (vacuity).
- `mapping/positive.txt`: R8's shape with `-keepnames` over `org.ghost.**`; accepted. Its last two
  lines are the two shapes the first real release mapping showed that carry an `org.ghost.` name
  without being a shipped source class: a desugared lambda (`$$ExternalSyntheticLambda1 -> …j`, a
  synthesized class -keepnames has no source name for) and a class R8 removed
  (`-> R8$$REMOVED$$CLASS$$344`). Both are exempt from the identity rule only.
- `mapping/renamed.txt`: one `org.ghost.` class renamed. One line.
- `mapping/debug-class.txt`: the key-change hook and a lambda class of the gate instrumentation
  shipped. Two lines.
- `mapping/harness.txt`: a class of a harness package shipped. One line.
- `mapping/entry.txt`: the equivalence-test entry point shipped. One line.
- `mapping/no-ghost.txt`: no `org.ghost.` class at all. One line (vacuity).

Nothing here is compiled or shipped.
