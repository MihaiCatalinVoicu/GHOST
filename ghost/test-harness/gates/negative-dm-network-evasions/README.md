# Negative fixture for G-DM1 (messaging-no-network.sh): the evasions of a line-by-line reading

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 9 design §22.33 item 16,
the evasion review of the S0′ gates). Each file under `android/messaging/src/main/…/evasion/` holds
exactly **one** violation, on the line its comment names; the gate that read one physical line at a
time passed all eight. `:crypto-bridge` is clean and only keeps the gate from failing as vacuous.

| File | Evasion | Line |
|---|---|---|
| `SuspendFun.kt` | a `suspend fun` (no coroutine import at all) | 4 |
| `SuspendFunctionType.kt` | a suspending function type with a receiver | 5 |
| `SuspendSplit.kt` | `suspend` and `fun` on two lines | 5 |
| `SplitQualifiedName.kt` | a qualified name written across lines, in code | 5 |
| `SplitImport.kt` | the same in an import | 3 |
| `QuotedName.kt` | Kotlin backtick quoting of each part | 5 |
| `CommentInName.kt` | a comment between two parts | 5 |
| `StdlibCoroutines.kt` | the standard library's own coroutine package | 3 |
