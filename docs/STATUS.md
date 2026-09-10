# GHOST — Status

**Stadiu: Developer preview. Nicio afirmație de confidențialitate.** (Spec v2.0 §3.1: „Local/test infrastructure; no privacy claim; synthetic payments.”)

| Element | Stare (2026-09-10) |
|---|---|
| Specificație | v2.0 FINAL (`output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf`) + delta v2.1 (`docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`) |
| ADR-uri | ADR-01 … ADR-16 **aprobate** 2026-09-10 (`docs/adr/`) |
| Faza 0 (baseline, carantină, git) | **închisă** — legacy în `legacy/`, repo git, STATUS, ADR-uri |
| Faza 1 (monorepo `ghost/`, CI, gates) | **închisă** — build Android + Rust verde local; gates statice verzi și dovedite pe fixture-uri negative; schema proto validată; build reproductibil verificat local; CI în `.github/workflows/ci.yml` |
| Faza 2 (threat model v2.1, harness privacy) | **livrabile complete**: `docs/THREAT_MODEL_v2.1.md`, `ghost/test-harness/privacy/` (schema observabile, validator `capture-check`, T1 în CI); **gate deschis**: review independent al threat model-ului |
| Faza 3 (identitate și onboarding) | următoarea, poate începe în paralel cu review-ul |
| Faze 3–18 | neîncepute |
| Cod de produs | schelet fără logică de produs; `legacy/` conține prototipuri simulate, în carantină |
| Gap cunoscut | commit-urile nu sunt încă semnate (FR-8.1): proprietarul trebuie să configureze cheia (`git config commit.gpgsign true`) |
| Afirmații permise în marketing/UI | niciuna (CP-10, FR-8.7) |

Regula de actualizare: acest fișier se modifică în același commit cu orice schimbare de fază sau de gate.
