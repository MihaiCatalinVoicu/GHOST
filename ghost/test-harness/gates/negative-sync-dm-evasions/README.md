# Negative fixture for sync-no-catch-all.sh: the evasions of a line-by-line reading

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 9 design §22.33 item 16).
Each file holds exactly **one** catch-all the gate reading one physical line at a time passed; this
tree has no `sync-no-catch-all.allow`, so every DM hit is refused. `:entitlement` and
`:crypto-bridge` are clean and only keep the gate from failing as vacuous.

| File | Evasion | Line |
|---|---|---|
| `android/sync/…/evasion/SplitCatch.kt` | `catch (` with the parameter on the next line, in the sync engine | 6 |
| `CommentInCatch.kt` | a comment inside the parentheses | 5 |
| `AnnotatedCatch.kt` | an annotation on the parameter | 5 |
| `TrailingComma.kt` | a trailing comma | 5 |
| `QuotedCatch.kt` | a backtick-quoted parameter name | 5 |
| `SplitType.kt` | the qualified type written across lines | 5 |
| `TypeAlias.kt` | a type alias of Throwable (the catch that names it is unseen) | 4 |
| `ImportAlias.kt` | an import alias of Exception | 3 |
| `SplitJava.java` | a Java catch whose parameter name is on the next line | 5 |
