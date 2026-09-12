# ADR-uri GHOST

Toate ADR-urile de mai jos au fost aprobate de proprietarul proiectului pe 2026-09-10 și modifică *GHOST Technical Specification v2.0* conform `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`.

| ADR | Titlu |
|---|---|
| [ADR-01](ADR-01-tor-transport.md) | Transport anonim: Tor (Arti) și relay-uri ca onion services |
| [ADR-02](ADR-02-blind-entitlement-monero.md) | Entitlement blind-signed; rail P0 = Monero; fără blockchain în P0 |
| [ADR-03](ADR-03-no-integrated-wallet.md) | Fără portofel integrat în P0 |
| [ADR-04](ADR-04-per-channel-pseudonyms.md) | Pseudonim derivat per canal |
| [ADR-05](ADR-05-blind-invite-tokens.md) | Invitații prin token-uri blind |
| [ADR-06](ADR-06-no-third-party-sdks.md) | Zero SDK-uri terțe; allowlist dependențe |
| [ADR-07](ADR-07-open-source-reproducible.md) | Open-source, build reproductibil, distribuție verificabilă |
| [ADR-08](ADR-08-endpoint-hygiene.md) | Igienă de endpoint |
| [ADR-09](ADR-09-traffic-metadata-p0.md) | Metadate de trafic ca P0 |
| [ADR-10](ADR-10-legacy-quarantine-monorepo-gates.md) | Carantină legacy, monorepo, git, gates |
| [ADR-11](ADR-11-independent-relay-operators.md) | Independența operatorilor de relay |
| [ADR-12](ADR-12-post-quantum.md) | Post-quantum |

Un ADR nou primește următorul număr, status „Propus”, și se leagă de cerința FR/NFR pe care o modifică.

## Aprobate ulterior (2026-09-10, a doua rundă)

| ADR | Titlu |
|---|---|
| [ADR-13](ADR-13-in-channel-governance.md) | Guvernanță în canal: flag-uri, prag, carantină, strike pe sponsor |
| [ADR-14](ADR-14-key-attestation-recovery.md) | Atestare hardware a cheilor și recuperare după compromitere |
| [ADR-15](ADR-15-traffic-shaping.md) | Traffic shaping: polling constant, trimitere întârziată, bucketizare |
| [ADR-16](ADR-16-censorship-resistance.md) | Rezistență la cenzură: bridges, WebTunnel, mod auto |
| [ADR-17](ADR-17-bouncycastle-ed25519.md) | Ed25519 prin BouncyCastle pentru identitate (aprobat) |
| [ADR-18](ADR-18-redb-relay-storage.md) | Stocare relay pe redb în loc de RocksDB (aprobat) |
| [ADR-19](ADR-19-rust-client-core.md) | Nucleu de client în Rust expus prin JNI (aprobat) |
| [ADR-20](ADR-20-sync-jobscheduler.md) | Sincronizare: JobScheduler în loc de WorkManager, program per (relay, namespace), reziduuri declarate (aprobat 2026-09-12, cu valorile implicite Q1–Q7) |
