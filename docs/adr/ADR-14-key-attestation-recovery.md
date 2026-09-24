# ADR-14 — Atestare hardware a cheilor și recuperare după compromitere

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` §L1 |
| Faze | 3 (identitate), 9 (DM); P1 (revocarea rămâne P0) |

## Decizie propusă
Chei de identitate și DB în Keystore hardware-backed/StrongBox, neexportabile. Lanț Android Key Attestation publicat în prekey bundle; safety view arată dacă cheia contactului este în hardware. Certificat de revocare semnat, publicat ca blob; re-verificare safety number după recuperare din mnemonic. Duress PIN (P2) cu disclosure best-effort.

## Notă (Faza 9, 2026-09-16)
Modificat de ADR-30′ și ADR-33′ (propuse și aplicate în Faza 9, în așteptarea deciziei proprietarului): atestarea se amână și nu apare niciodată în bundle, pe care îl pot citi toți deținătorii cardului (ADR-30′ punctul 8; eventual mai târziu doar în sesiunea E2E și opțional); certificatul de revocare e v2 (timp la minut) și se trimite contactelor ca mesaj E2E în inbox-urile lor, nu ca blob într-un namespace de identitate (ADR-33′); după restaurarea din mnemonic numărul de siguranță rămâne același (ADR-33′). Keystore-ul și duress PIN-ul rămân cum sunt decise mai sus.
