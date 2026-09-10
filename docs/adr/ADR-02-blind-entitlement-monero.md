# ADR-02 — Entitlement prin credențiale blind-signed; rail P0 = Monero; fără blockchain în P0

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 §10, FR-6.1–6.10, Fazele 11–12 |

## Context
USDC pe Base expune adresa portofelului public, implică on-ramp KYC și un RPC blockchain din client (TB-4). Circuitul ZK protejează doar modelul de date intern.

## Decizie
- Serviciu Entitlement Issuer (Rust, onion service, control plane) emite token-uri de acces prin RSA Blind Signatures (RFC 9474) sau Privacy Pass (RFC 9576–9578), cu metadate publice = perioada de valabilitate.
- Rail P0 = Monero. Issuer-ul deține doar view key; spend key offline/multisig.
- Flux: factură (subadresă XMR unică) → plată din wallet extern → cerere blind (token-uri de acces + invitație, referral commitment) → semnare → deblindare locală.
- Relay-urile verifică token-urile offline și țin nullifier-e doar pentru perioada curentă.
- Referral 10%: creditat pe referral commitment la fiecare plată; revendicare prin preimagine, payout în loturi. Plafon 10% prin construcție.
- Eliminate din P0: contracte Base, circuit Noir, verificator ZK, IdentityAnchor, ContentNotary, RPC blockchain din client. USDC/Base: P2 opțional. Lightning: P1, aceeași emitere.

## Consecințe
(+) TB-4 dispare; nicio adresă publică; audit fără Solidity/circuite.
(−) issuer = componentă centrală fără chei de conținut și fără identități; Monero ~20 min confirmări; risc de reglementare XMR (mitigare: Lightning P1); avertisment în UI: nu plăti direct de la un exchange cu KYC.
