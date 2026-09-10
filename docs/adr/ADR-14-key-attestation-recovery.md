# ADR-14 — Atestare hardware a cheilor și recuperare după compromitere

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-10 (neaprobat) |
| Sursă | `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` §L1 |
| Faze | 3 (identitate), 9 (DM); P1 (revocarea rămâne P0) |

## Decizie propusă
Chei de identitate și DB în Keystore hardware-backed/StrongBox, neexportabile. Lanț Android Key Attestation publicat în prekey bundle; safety view arată dacă cheia contactului este în hardware. Certificat de revocare semnat, publicat ca blob; re-verificare safety number după recuperare din mnemonic. Duress PIN (P2) cu disclosure best-effort.
