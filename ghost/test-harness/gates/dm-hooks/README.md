# Fixtures for G-DM5 (`scripts/gates/apk-no-debug-hooks.sh`)

Phase 9 design §16.1 G-DM5, §21.13 points 5 and 7 (slice S12). `self-test.sh` runs the gate on each
tree below with `GHOST_ROOT` pointed at it (and the release-source floor lowered to 1), and on each
mapping with `GHOST_ROOT` at the real tree:

- `release-ref/`: a release source set imports and calls the debug key-change hook. Two lines (the
  import and the call); the comment that names the hook is prose and is not counted.
- `harness-package/`: a release source set declares a `harness` package. One line.
- `equivalence/`: the equivalence-test entry point is declared on `DmNative` in `src/main`. One line.
- `no-gate/`: release sources and no `gate` or `androidTest` source set. One line (vacuity).
- `srcdir/` (S12 review): a `build.gradle.kts` that adds `src/deviceRunner/kotlin` to `main` in a
  `getByName("main") { }` block and `src/gate/java` to `release` on a `sourceSets["release"]` line.
  Two lines; the `test` set's `srcDir` is allowed.
- `declarations/` (S12 review): an `androidTest` class declared with its annotation on the same
  line, named by a release source in an import, in plain code and in code after an inline
  `/* … */`; a block comment that names it in prose; and `BuildTwin`, declared in both `src/debug`
  and `src/release` (a build-type twin, like `DmBranch`), named without a violation. Three lines.
- `mapping/positive.txt`: R8's shape with H-01 obfuscation over `org.ghost.**` (v2.2, design
  `docs/design/h0-apk-hardening.md` §2): non-whitelist GHOST classes renamed (`GhostApp -> a.a`),
  only the tree's `-keep` JNI classes keep their names (`DmNative` identity, whitelisted by
  `:crypto-bridge`'s consumer rules). Accepted. Its last two lines are the two shapes the first
  real release mapping showed that carry an `org.ghost.` name without being a shipped source
  class: a desugared lambda (`$$ExternalSyntheticLambda1`, a synthesized class with no source name
  to keep) and a class R8 removed (`-> R8$$REMOVED$$CLASS$$344`).
- `mapping/renamed.txt`: the inverse drill — in the H-01 world a non-whitelist class that KEEPS its
  source name (`MessagingRuntime -> MessagingRuntime`, no `-keep` rule justifies it) is refused,
  while the whitelisted `DmNative` (JNI) and `GhostApp` (manifest component) keeping their names
  are fine. One line.
- `mapping/debug-class.txt`: the key-change hook and a lambda class of the gate instrumentation
  shipped (with their source names — debug-only classes, renaming would not make them acceptable).
  Two lines.
- `mapping/harness.txt`: a class of a harness package shipped. One line.
- `mapping/device-runner.txt` (S12 review): `org.ghost.device.DeviceRunner`, the device suites'
  `Instrumentation` from `crypto-bridge/src/deviceRunner`, shipped. One line; the first version of
  the gate read `src/gate` and `src/androidTest` only and passed it.
- `mapping/entry.txt`: the equivalence-test entry point shipped. One line.
- `mapping/no-ghost.txt`: no `org.ghost.` class at all. One line (vacuity).

Nothing here is compiled or shipped.
