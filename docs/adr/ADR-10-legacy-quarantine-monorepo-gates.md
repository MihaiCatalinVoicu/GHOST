# ADR-10 — Carantina codului legacy, monorepo ghost/, git și gates de CI

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Starea repo la 2026-09-10 (fără git, prototipuri simulate) |

## Decizie
- `app/` (cu fișierele Gradle de la rădăcină) → `legacy/ghostforum-app/`; `ghost-forum/` → `legacy/ghost-forum/`. Nu se reutilizează nimic.
- Șterse: `openjdk-17.zip`, `tmp/`, `tools/`, `SOLUTION_SUMMARY.md` (ambele copii), `ghost-forum/gradle/wrapper/gradle-wrapper.jar` (132 MB, distribuție mascată).
- `git init`, `.gitignore`, commit-uri semnate (FR-8.1) — cheia de semnare este a proprietarului.
- `ghost/` = singurul cod activ, structura din plan §6.6.
- Gates CI active din Faza 1: anti-placeholder (T8), allowlist dependențe (T7), lint logging, lint manifest (T15), build reproductibil (T12), cargo audit/deny. Fiecare gate are contra-exemple în `test-harness/gates/` care trebuie să îl facă să eșueze.
