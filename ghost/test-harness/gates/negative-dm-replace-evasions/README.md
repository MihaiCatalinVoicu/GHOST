# Negative fixture for G-DM4 (dm-no-replace.sh): a REPLACE no literal shows

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 9 design §22.33 item 16).
Each file under `android/messaging/src/main/…/evasion/` holds exactly **one** violation; the gate that
read whole statements only in string literals passed all nine. `Schema.kt` keeps the gate from
failing as vacuous.

| File | Evasion | Line |
|---|---|---|
| `InsertWithOnConflictFive.kt` | `insertWithOnConflict(…, 5)`: 5 is CONFLICT_REPLACE | 6 |
| `ConflictReplaceConstant.kt` | the named constant | 5 |
| `ReplaceOrThrow.kt` | `replaceOrThrow` | 6 |
| `ContentValuesRow.kt` | `ContentValues`, the row every conflict API (and `replace`) takes | 5 |
| `VerbInAValue.kt` | `REPLACE` in a literal of its own | 5 |
| `OrFollowedByValue.kt` | `INSERT OR ` followed by a value | 5 |
| `ActionInAValue.kt` | `DO UPDATE` in a literal of its own | 5 |
| `ConflictFollowedByValue.kt` | `ON CONFLICT(…)` followed by a value | 6 |
| `TemplateVerb.kt` | the algorithm as a template | 5 |
