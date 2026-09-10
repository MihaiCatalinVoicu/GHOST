# GHOST — Status

**Stadiu: Developer preview. Nicio afirmație de confidențialitate.** (Spec v2.0 §3.1: „Local/test infrastructure; no privacy claim; synthetic payments.”)

| Element | Stare (2026-09-10) |
|---|---|
| Specificație | v2.0 FINAL (`output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf`) + delta v2.1 (`docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`) |
| ADR-uri | ADR-01 … ADR-16 **aprobate** 2026-09-10 (`docs/adr/`) |
| Faza 0 (baseline, carantină, git) | **închisă** — legacy în `legacy/`, repo git, STATUS, ADR-uri |
| Faza 1 (monorepo `ghost/`, CI, gates) | **închisă** — build Android + Rust verde local; gates statice verzi și dovedite pe fixture-uri negative; schema proto validată; build reproductibil verificat local; CI în `.github/workflows/ci.yml` |
| Faza 2 (threat model v2.1, harness privacy) | **livrabile complete**: `docs/THREAT_MODEL_v2.1.md`, `ghost/test-harness/privacy/` (schema observabile, validator `capture-check`, T1 în CI); **gate deschis**: review independent al threat model-ului |
| Faza 3 (identitate și onboarding) | **nucleu livrat** în `ghost/android/identity`: entropie 256 bit, BIP-39 24 cuvinte (vectori Trezor), HKDF RFC 5869 (vectori RFC), ramuri separate, Ed25519 din seed (ADR-17), identitate `ghost1…` cu checksum, pseudonime per canal (T14), invitații semnate cu tamper/expiry/replay (T16), certificat de revocare, IdentityManager (create/restore/unlock/wipe/backup challenge), Keystore wrapper StrongBox→TEE, stocare no-backup. **Rămân**: test instrumentat pe dispozitiv pentru Keystore (emulator/device matrix), UI onboarding (Faza 13), redeem invite la issuer (Faza 8) |
| Faza 4 (storage SQLCipher) | **nucleu livrat** în `ghost/android/storage`: schema v1 (19 tabele din §8 + pseudonime, nonce-uri invitații, revocări; doar coloane-envelope, timpi la minut impuși de CHECK, FK/CASCADE, plafon 64 KiB pe payload), MigrationRunner tranzacțional cu recuperare după întrerupere și downgrade fail-closed, cheie DB învelită în Keystore, GhostDatabase peste SQLCipher (no-backup dir, cipher_memory_security, secure_delete), repository-uri pentru identitate, nonce-uri (replay persistent), pseudonime, revocări; 11 teste JVM pe SQLite. **Rămân**: test instrumentat pe dispozitiv (deschidere SQLCipher reală + T4 inspecție backup) |
| Faza 5 (relay v1 Rust + onion services) | **nucleu livrat** în `ghost/relay`: tipuri generate din proto (tonic), blob store redb (ADR-18 propus) cu hash recalculat, bucket-uri impuse, TTL, cursoare opace, prune; capabilități HMAC locale cu cotă, nullifier-e; gossip de inventar (oprit implicit); nod gRPC `ghost-relay` cu mod captură; suita cu două noduri (abuz, quota, failover) + captura validată T1 pe trafic real; imagine Docker + torrc onion v3 + compose cu 3 relay-uri pentru staging. **Rămân**: deploy efectiv pe 3 operatori de staging, autentificare Noise între relay-uri și convergență de date (Faza 10), test de sarcină NFR-3 |
| Faza 6 (client Tor + network) | **nucleu livrat**: `ghost/client-core/net` (Rust, ADR-19 propus): Arti embedded cu suport onion-service client și bridges, tip `OnionAddress` strict (fără DNS/IP/URL — fail-closed prin tip), izolare de circuite per namespace/scop, client gRPC relay tunelat prin Tor cu padding și verificare de hash, JNI pentru `android/network` (`TorRelayTransport`, categorii de eroare constante). Test live (ignorat implicit; job manual `live-tor` în CI) de bootstrap Tor + stream către un onion public — pe Windows bootstrap-ul se oprește după handshake-urile cu fallback-uri (de investigat în Faza 12), rezultatul de referință este cel de pe Linux. Cross-compilare NDK arm64-v8a/x86_64 prin `cargo-ndk`. **Rămân**: T6 pe emulator (captură tcpdump cu Tor blocat), măsurare latență pe două dispozitive (NFR-1/2), bridges implicite în manifest (ADR-16, Faza 12) |
| Faza 7 (sync engine) | următoarea |
| Faze 3–18 | neîncepute |
| Cod de produs | schelet fără logică de produs; `legacy/` conține prototipuri simulate, în carantină |
| Gap cunoscut | commit-urile nu sunt încă semnate (FR-8.1): proprietarul trebuie să configureze cheia (`git config commit.gpgsign true`) |
| Afirmații permise în marketing/UI | niciuna (CP-10, FR-8.7) |

Regula de actualizare: acest fișier se modifică în același commit cu orice schimbare de fază sau de gate.
