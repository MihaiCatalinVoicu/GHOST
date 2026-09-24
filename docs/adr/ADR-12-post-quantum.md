# ADR-12 — Post-quantum

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect); **clauza DM modificată de [ADR-36](ADR-36-dm-post-quantum.md)** (2026-09-16, propus și aplicat în Faza 9: fără libsignal; X-Wing în plicul GHOST, transport doar PQ al cheilor de sigilare, reîmprospătare PQ rară a rădăcinilor; clauza MLS și „niciun KEM standalone de bifat” rămân) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 §7.5 (păstrat) |

## Decizie
DM: PQXDH și ratchet-ul post-quantum așa cum sunt expuse de libsignal. MLS: suita hibridă OpenMLS când e stabilă. Niciun KEM standalone „de bifat”.

## Modificare (2026-09-16, ADR-36)
Proprietarul a exclus libsignal (AGPL-3.0). Clauza DM de mai sus e înlocuită de [ADR-36](ADR-36-dm-post-quantum.md): plicul GHOST folosește X-Wing (X25519 + ML-KEM-768) pentru primul contact și transportă doar sub chei post-cuantice cheile de sigilare; ratchet-ul Olm rămâne clasic; rădăcinile de pereche se reîmprospătează rar cu X-Wing (PQ-C). Spec §7.5 se aplică prin a doua ramură (design propriu, model formal, revizie externă); până la rularea modelului și la revizia externă nu se face nicio afirmație despre rezistența cuantică (CP-10), iar reziduurile PQ-R1 … PQ-R8 sunt declarate (LIMITE L7-D24).
