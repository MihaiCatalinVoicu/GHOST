# ADR-05 — Invitații prin token-uri blind; nicio cheie a inviter-ului către operator

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 FR-1.5, FR-1.6 |

## Decizie
- La activare, clientul primește și N invite tokens (tip distinct, aceeași emitere blind).
- Payload invitație: `version`, `invite_token`, `referral_commitment`, `nonce`, `expiry`, semnătură cu cheie de invitație efemeră; opțional contact card criptat pentru invitat.
- Redeem la issuer: doar token + nullifier. Eligibilitatea inviter-ului = token valid, verificat offline.
- Deep link exclusiv `ghost://invite/<payload>`; niciun host web; QR recomandat.
- Rămân: parser strict, respingere expirat/rejucat/revocat, mod genesis explicit.
