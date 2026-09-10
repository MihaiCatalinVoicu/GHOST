# ADR-04 — Pseudonim derivat per canal

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 §3 Identity (o singură identitate ghost1…) |

## Decizie
Din ramura identity: `HKDF(label = "ghost/v1/channel-pseudonym", channel_id)` → cheie Ed25519 per canal = credențialul MLS al membrului. Identitatea de bază (`ghost1…`) apare doar în invitații și DM. Legarea pseudonim ↔ identitate de bază se face numai printr-un mesaj MLS explicit „reveal to member”, opt-in.

## Consecințe
(+) participarea unei persoane nu poate fi corelată între canale; compromiterea unui canal nu expune identitatea globală. (−) model de contacte mai complex. Afectează schema DB, credențialele MLS, UI-ul de profil — de aceea se decide acum (FR-3.9, P0 pentru schemă/derivare).
