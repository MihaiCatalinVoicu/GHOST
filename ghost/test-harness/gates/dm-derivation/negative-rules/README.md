# G-DM3 negative fixture: one violation per rule

| Where | Rule | Line(s) |
|---|---|---|
| `messaging/…/HkdfSite.kt` | 1: a KDF keyed by a card's public key, not listed | 7 |
| `messaging/…/RootFromRaw.kt` | 1: a seed built from raw bytes, not listed | 8 |
| `messaging/…/BranchFromString.kt` | 2: `deriveBranch` with a String | 7 |
| `messaging/…/LabelOutsideBranch.kt` | 2: a `DerivationLabels` constant outside `deriveBranch` | 7 |
| `messaging/…/ExtensionBranch.kt` | 2: a `deriveBranch` declared outside RootEntropy | 4 |
| `messaging/…/NewLabel.kt` | 3: a DM label not listed | 5 |
| `sync/…/MovedLabel.kt` | 3: a DM label outside the DM modules | 5 |
| `crypto-bridge/…/Twice.kt` | 1: a listed call found twice, allowed once (both lines) | 10, 14 |
| `crypto-bridge/…/Renamed.kt` | 1: a listed call whose key declaration changed | 11 |
| the allowlist | a stale entry, an entry outside the DM modules, a malformed entry | — |

13 violations in all.
