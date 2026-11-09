# ADR-uri GHOST

Toate ADR-urile de mai jos au fost aprobate de proprietarul proiectului pe 2026-09-10 și modifică *GHOST Technical Specification v2.0* conform `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`.

| ADR | Titlu |
|---|---|
| [ADR-01](ADR-01-tor-transport.md) | Transport anonim: Tor (Arti) și relay-uri ca onion services |
| [ADR-02](ADR-02-blind-entitlement-monero.md) | Entitlement blind-signed; rail P0 = Monero; fără blockchain în P0 |
| [ADR-03](ADR-03-no-integrated-wallet.md) | Fără portofel integrat în P0 |
| [ADR-04](ADR-04-per-channel-pseudonyms.md) | Pseudonim derivat per canal |
| [ADR-05](ADR-05-blind-invite-tokens.md) | Invitații prin token-uri blind (cardul de contact opțional din invitație: amânat în Faza 13, ADR-30′) |
| [ADR-06](ADR-06-no-third-party-sdks.md) | Zero SDK-uri terțe; allowlist dependențe |
| [ADR-07](ADR-07-open-source-reproducible.md) | Open-source, build reproductibil, distribuție verificabilă (revizuit parțial de ADR-37 și ADR-38 la 2026-09-16: sursă închisă) |
| [ADR-08](ADR-08-endpoint-hygiene.md) | Igienă de endpoint |
| [ADR-09](ADR-09-traffic-metadata-p0.md) | Metadate de trafic ca P0 |
| [ADR-10](ADR-10-legacy-quarantine-monorepo-gates.md) | Carantină legacy, monorepo, git, gates |
| [ADR-11](ADR-11-independent-relay-operators.md) | Independența operatorilor de relay |
| [ADR-12](ADR-12-post-quantum.md) | Post-quantum (clauza DM modificată de ADR-36 la 2026-09-16) |

Un ADR nou primește următorul număr, status „Propus”, și se leagă de cerința FR/NFR pe care o modifică.

## Aprobate ulterior (2026-09-10, a doua rundă)

| ADR | Titlu |
|---|---|
| [ADR-13](ADR-13-in-channel-governance.md) | Guvernanță în canal: flag-uri, prag, carantină, strike pe sponsor |
| [ADR-14](ADR-14-key-attestation-recovery.md) | Atestare hardware a cheilor și recuperare după compromitere (atestarea amânată și revocarea prin inbox-urile contactelor: ADR-30′, ADR-33′) |
| [ADR-15](ADR-15-traffic-shaping.md) | Traffic shaping: polling constant, trimitere întârziată, bucketizare |
| [ADR-16](ADR-16-censorship-resistance.md) | Rezistență la cenzură: bridges, WebTunnel, mod auto |
| [ADR-17](ADR-17-bouncycastle-ed25519.md) | Ed25519 prin BouncyCastle pentru identitate (aprobat; Ed25519 și în biblioteca nativă, `ed25519-dalek` 2.2.0 al GHOST și 3.0.0 al vodozemac, în `ghost-client-dm`: ADR-35) |
| [ADR-18](ADR-18-redb-relay-storage.md) | Stocare relay pe redb în loc de RocksDB (aprobat) |
| [ADR-19](ADR-19-rust-client-core.md) | Nucleu de client în Rust expus prin JNI (aprobat) |
| [ADR-20](ADR-20-sync-jobscheduler.md) | Sincronizare: JobScheduler în loc de WorkManager, program per (relay, namespace), reziduuri declarate (aprobat 2026-09-12, cu valorile implicite Q1–Q7) |
| [ADR-27](ADR-27-screen-text-ephemeral.md) | Protecția ecranului și a textului; mesaje efemere (aprobat 2026-09-13; de implementat în Fazele 9, 10, 11 și 13) |

## Propuse (aplicate, în așteptarea deciziei proprietarului)

Propuse 2026-09-12 și aplicate în Faza 8 (design `docs/design/faza8-issuer.md`, cu corecțiile normative §19), ca ADR-17 … ADR-20 înaintea aprobării lor. Decizia proprietarului (Q1) și valorile implicite Q2–Q35 ale designului (§17; Q31 nu are valoare implicită, decide proprietarul) se înregistrează aici și în fiecare ADR. ADR-21 e rezervat sarcinii paralele despre classpath-ul rezolvat.

| ADR | Titlu |
|---|---|
| [ADR-22](ADR-22-entitlement-protocol.md) | Protocolul de entitlement: token Privacy Pass 0x0002, chei per (tip, epocă) în Programul de Entitlement semnat, implementare separată client/issuer |
| [ADR-23](ADR-23-issuer-relay-unlinkability.md) | Nelegabilitate issuer ↔ relay: reguli R1–R10, trial prin invitație, rulări liniștite, sloturi de activare, testul T2 |
| [ADR-24](ADR-24-referral-credit-tokens-invite-v2.md) | Referral prin token-uri blind de credit; Invitație v2 cu cheie per invitație și „drop” |
| [ADR-25](ADR-25-relay-redemption.md) | Răscumpărarea la relay: `RedeemToken`, capabilitate v2, nullifier-e persistate, capabilități de citire partajate |
| [ADR-26](ADR-26-issuer-operations.md) | Operarea issuer-ului: Monero view-only, jurnal de emitere, custodia cheilor, plăți cu semnare la rece, fără jurnalizare, job regtest automat |

## Propuse (aplicate în Faza 9)

**Aprobate de proprietar 2026-09-27** (propuse 2026-09-16) și aplicate în Faza 9 (design `docs/design/faza9-dm.md`, cu corecturile normative §21, §22 și §22.8, care au prioritate), ca ADR-17 … ADR-26 înaintea aprobării lor. Revizia din 2026-09-16 urmează decizia proprietarului: fără libsignal (licența AGPL-3.0 e inacceptabilă) și distribuție cu sursă închisă. Valorile implicite ale întrebărilor proprietarului (§19; Q4 cere aprobarea acestor ADR-uri) se aplică dacă proprietarul nu obiectează; consemnarea lor este în `docs/design/faza9-s0-hygiene.md`. ADR-30′ … ADR-34′ sunt schițele rundei 9 modificate de revizie (marcate ′); ADR-32 a rămas neschimbat. Fișierele (și nota de revizuire a ADR-07) au fost depuse în slice-ul S0′ (2026-09-16); notele ADR-05, ADR-12, ADR-14 și ADR-17, aici și în fișierele lor, în S14 (2026-09-24). „Aplicate” înseamnă implementate în cod; **Faza 9 nu e închisă** (`docs/STATUS.md`), iar ADR-36 descrie un design a cărui validare (modelul formal, revizia externă) nu s-a făcut încă.

| ADR | Titlu |
|---|---|
| [ADR-30′](ADR-30-dm-blind-addressing.md) | Adresare și autorizare DM oarbe pentru relee: card de contact, namespace-uri statice derivate din secrete, `RegisterKey`, chei de depunere și de citire, bundle-uri sigilate |
| [ADR-31′](ADR-31-dm-envelope-sealed-sender.md) | Plicul DM: sealed sender fără server în patru moduri, padding în AEAD cu prag de 4 KiB, fără trafic reflex, implementare în Rust |
| [ADR-32](ADR-32-dm-ephemeral-ttl-seconds.md) | Mesaje efemere în DM: trepte TTL în secunde, acceptare exactă, termene, numărătoare, ștergere (precizează ADR-27) |
| [ADR-33′](ADR-33-dm-sessions-key-change.md) | Sesiuni DM: identitatea Olm derivată și legătura ei, selecția sesiunilor, schimbarea cheii, numărul de siguranță, revocarea v2, restaurarea, cererile, modelul local |
| [ADR-34′](ADR-34-dm-sync-entitlement-schema-ci.md) | Extensiile `:sync` și `:entitlement`, schemele v4 și v5, coada de consum, joburi CI și modificările testului T2 pentru DM |
| [ADR-35](ADR-35-dm-library-vodozemac.md) | Biblioteca DM: Olm din vodozemac în `client-core`, doar prin API public, cu stare criptată |
| [ADR-36](ADR-36-dm-post-quantum.md) | Post-quantum pentru DM: X-Wing în plicul GHOST, transport doar PQ al cheilor de sigilare, reîmprospătare PQ rară a rădăcinilor |
| [ADR-37](ADR-37-closed-source-licences.md) | Distribuție cu sursă închisă și conformitatea licențelor terților; revizuiește ADR-07 |
| [ADR-38](ADR-38-verifiability-without-source.md) | Verificabilitate fără sursă publică |
| [ADR-39](ADR-39-private-repository.md) | Depozitul devine privat; artefactele CI; istoricul deja public |
| [ADR-44](ADR-44-media-object-format.md) | Formatul obiectului media: STREAM pe chunk-uri de 256 KiB, manifest cu angajament de cheie, clase de dimensiune (**aprobat** 2026-10-04) |
| [ADR-45](ADR-45-media-namespace-transfer.md) | Transferul media: namespace-ul media al destinatarului, descărcare automată, banda media din sync (**aprobat** 2026-10-04) |
| [ADR-46](ADR-46-media-hygiene.md) | Igiena media: re-encodare obligatorie, decodare izolată, fără plaintext pe disc (**aprobat** 2026-10-04) |
| [ADR-47](ADR-47-ephemeral-view-once-media.md) | Media efemeră și „vezi o singură dată” (precizează ADR-27 punctele 10 și 12) (**aprobat** 2026-10-04) |
| [ADR-48](ADR-48-cheile-distributiei-roluri-custodie-hardware-ceremonii.md) | Cheile distribuției: roluri, custodie hardware, ceremonii, rădăcina de încredere (**aprobat** 2026-10-05) |
| [ADR-49](ADR-49-manifestul-semnat-jurnalul-de-transparenta-binara.md) | Manifestul semnat, jurnalul de transparență binară și actualizările legate de atestări (**aprobat** 2026-10-05) |
| [ADR-50](ADR-50-build-reproductibil-din-doua-medii-reteta.md) | Build reproductibil din două medii: rețeta cu căi fixe, setul de artefacte, simboluri și SBOM (**aprobat** 2026-10-05) |
| [ADR-51](ADR-51-actualizatorul-din-aplicatie-rulari-de-actualizare.md) | Actualizatorul din aplicație: rulări de actualizare, anti-rollback, lansare în trepte, instalare, directorul de relee (**aprobat** 2026-10-05) |
| [ADR-52](ADR-52-canalele-de-distributie-si-identitatea-aplicatiei.md) | Canalele de distribuție și identitatea aplicației (**aprobat** 2026-10-05) |
| [ADR-53](ADR-53-stratul-de-interfata-modulul-ui-porti.md) | Stratul de interfață: modulul `:ui`, porți de acces, flux unidirecțional, coroutines doar în interfață, navigare proprie, sesiuni la deblocare (**aprobat** 2026-10-05) |
| [ADR-54](ADR-54-protectia-ecranului-si-a-textului-implementata.md) | Protecția ecranului și a textului, implementată (precizează ADR-27 punctele 1–6) (**aprobat** 2026-10-05) |
| [ADR-55](ADR-55-blocarea-aplicatiei-stergerea-locala-copia-si.md) | Blocarea aplicației, ștergerea locală, copia și restaurarea cuvintelor (blocarea strictă amânată) (**aprobat** 2026-10-05) |
| [ADR-56](ADR-56-afirmatii-si-disclosure-uri-in-interfata.md) | Afirmații și disclosure-uri în interfață (CP-10) (**aprobat** 2026-10-05) |
| [ADR-57](ADR-57-componente-si-permisiuni-noi-notificari-camera.md) | Componente și permisiuni noi: notificări, camera pentru QR, zxing, legături `ghost://` (**aprobat** 2026-10-05) |
| [ADR-58](ADR-58-ci-local.md) | CI-ul rulează local, nu prin GitHub Actions (regulă oficială a proprietarului) |
| [ADR-59](ADR-59-wallet-sync.md) | Wallet Sync fără issuer: seed-ul wallet-ului local în Keystore + blob criptat client-side din seed pe relay-uri (**aprobat** 2026-10-04; varianta cu issuer respinsă) |
| [ADR-60](ADR-60-version-migration-wipe.md) | Migrare între versiuni: `kill_flag` în manifestul semnat comandă ștergerea locală automată și, opțional, dezinstalarea (**aprobat** 2026-10-04; reziduu acceptat) |

## Propuse (Faza 10)

Propuse 2026-09-25 (design `docs/design/faza10-forum.md`, Anexa A; rundele 10d și 10e din §19.27 … §19.29 le-au corectat), aplicate în Faza 10 și depuse aici de felia S12 (2026-10-11), în așteptarea deciziei proprietarului (Q1 a designului; valorile implicite s-au aplicat cu aprobarea proprietarului 2026-09-27). Notele rundei 10e sunt deja în textele de mai jos. **Notă la ADR-13:** punctul „primul client care observă pragul" e retras de ADR-42; primitivele Fazei 10 sunt rolurile, scoaterea, evacuarea, evidența sponsorilor și simularea pragului. **Notă la ADR-04:** pseudonimul e stabil pe viața canalului (ADR-43). **Notă la ADR-12:** canalele rămân pe suita clasică 0x0003 până la îndeplinirea condițiilor din design Faza 10 §4.4.

| ADR | Titlu |
|---|---|
| [ADR-40](ADR-40-forum-openmls-client-core.md) | Forumul pe OpenMLS 0.9.0 în `client-core`: bibliotecă, furnizor, adaptor de stocare, suita clasică, JNI închis |
| [ADR-41](ADR-41-canale-oarbe-pentru-relee.md) | Canale oarbe pentru relee: sigiliu exterior pe epocă, generații, chei comune de citire și depunere, rotație la scoatere, finanțatori |
| [ADR-42](ADR-42-ordinea-commiturilor-fara-server.md) | Ordinea commit-urilor fără server și guvernanța minimă |
| [ADR-43](ADR-43-invitatii-dezvaluire-istoric-pseudonim.md) | Invitații în canal, dezvăluire opt-in, istoric „none", pseudonim stabil |

## Propuse (Faza 12)

Propuse 2026-10-17 (design `docs/design/faza12-transports.md`, revizia 4, aprobat prin directiva proprietarului de a implementa integral Faza 12; valorile implicite Q1–Q11 se aplică până la o contrazicere scrisă a proprietarului — Q11 e exact aprobarea acestor ADR-uri) și **aplicate** în Faza 12 (feliele S0–S4 de pe `p12-s4`: binarul lyrebird prune-at construit reproductibil cu hash-uri fixate și verificare la runtime, cablarea ptmgr cu execuție prin linker-ul sistemului, extragerea și stocarea liniilor, modul auto redus, porțile G-T1 … G-T8, invarianții T58–T60), în așteptarea deciziei proprietarului. Nota de revizuire a rundei adversariale de închidere (corectura rețetei din ADR-61, amendamentul T58, constatările înregistrate) e în `docs/design/faza12-s4-notes.md`.

| ADR | Titlu |
|---|---|
| [ADR-61](ADR-61-transporturi-pluggable-lyrebird.md) | Transporturi pluggable: obfs4 și WebTunnel prin lyrebird, proveniență din sursă fixată, build reproductibil, execuție prin tor-ptmgr |
| [ADR-62](ADR-62-liniile-de-bridge.md) | Liniile de bridge: doar de la utilizator, stocare învelită, fără listă încorporată, mod auto redus |

## Amendamente documentare v2.2 (2026-10-31)

Cererea proprietarului pentru mesh opțional, voce E2EE și protecția APK este documentată în [spec v2.2](../GHOST_Technical_Specification_v2.2.md) și [roadmap v2.2](../GHOST_Roadmap_v2.2.md). [ADR-01](ADR-01-tor-transport.md) primește excepția locală strict delimitată, iar [ADR-38](ADR-38-verifiability-without-source.md) pct. 9 înlocuiește keepnames/simbolurile publice cu obfuscare și mapări/simboluri private auditorilor. Aceste amendamente nu aprobă un protocol wire încă nescris, nu certifică implementarea și nu închid T6/T12b. Designurile detaliate și probele sunt livrabile M1/H0/B2.

## Retrase

| ADR | Titlu | Stare |
|---|---|---|
| ADR-28 | Integrarea libsignal | **Retras** 2026-09-16, înainte de aprobare (numărul nu se refolosește); înlocuit de ADR-35 și ADR-36. Consemnarea retragerii: `docs/design/faza9-dm.md`, Anexa A |
| ADR-29 | Licența clientului sub consecința AGPL | **Retras** 2026-09-16, înainte de aprobare (numărul nu se refolosește); înlocuit de ADR-37, ADR-38 și ADR-39. Consemnarea retragerii: `docs/design/faza9-dm.md`, Anexa A |
