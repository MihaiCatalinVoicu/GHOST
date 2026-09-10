# ADR-08 — Igienă de endpoint (completări P0 la §4.7)

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 §4.7 |

## Decizie
- Strip metadata media înainte de criptare (EXIF/XMP/GPS; video remuxat fără atomi de locație/dispozitiv) — FR-7.10, test T5.
- `IME_FLAG_NO_PERSONALIZED_LEARNING` pe toate câmpurile; avertisment unic despre tastaturi terțe.
- Fără link previews.
- Read receipts, delivery status, typing: opționale, off în high-privacy mode.
- Timestamps de autor rotunjite la minut (T13).
- Auto-lock + PIN de aplicație (P0); duress wipe (P2); FLAG_SECURE și clipboard auto-clear (FR-7.8).
- Fără locale/model/OS în mesajele de protocol; doar `protocol_version`.
