# ADR-34′ — Extensiile `:sync` și `:entitlement`, schemele v4 și v5, coada de consum, joburi CI și modificările testului T2 pentru DM (modificat de revizia din 2026-09-16)

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-16, aplicat în Faza 9 (în așteptarea deciziei proprietarului, Q4) |
| Sursă | Design Faza 9 (`docs/design/faza9-dm.md`: §4.8–§4.9, §10.4, §10.7, §13.3–§13.7, §16.2), R-code F1–F8, R-envelope F3–F5 |
| Modifică | ADR-20 punctul 1 (o alarmă inexactă în stratul de mesagerie; punctul 8 rămâne respectat după revizie, încadrarea E2E fiind în Rust, ADR-31′); ADR-23 punctul 9 (slotul de participant rămâne unul; se adaugă coada de consum, care nu e participant); API-ul `:sync` (Faza 7 §9); INVARIANTS T20 (setul coloanelor de timp); `Schema.kt` (migrarea 4); designul Fazei 8 §19.24 punctul 6 și ADR-25 (exportul T2 include `keys.redb`); CI (joburi noi, o acțiune terță fixată prin SHA) |

## Decizie
1. `TtlBucket.HOUR_1`; regulile ferestrei Fazei 7 re-derivate pentru 1 oră și 1 zi; scenariile S-F rulează și cu aceste trepte și cu ferestre offline de 30 de minute, 3 ore și 3 zile.
2. `InboundBlob.relayExpiryHour` (coloana `inbox_blob.relay_expiry_hour`, nenulă doar în starea `fetched`) și `InboundBlob.offers`; un blob oferit de trei ori se consumă neprocesat (fără buclă de crash).
3. `CapabilitySource {REDEEM, LOCAL}` pe namespace și pe nevoie; planificatorul entitlement nu răscumpără niciodată o nevoie LOCAL.
4. `Registrations`: operațiile `RegisterKey` rulează pe banda de lucru, cu lease, reîncercări și breakere, ca stocările; un rând în așteptare contează ca nevoie de scriere, deci un inbox nou sau restaurat se răscumpără la prima sesiune, iar reținerea Q29 îl acoperă (Q31). Un credențial de citire propriu refuzat readuce înregistrările în așteptare.
5. `ConsumerTail`: rulează pe firul jobului după benzile unei sesiuni de fundal și după reținerea de răscumpărare, și după apelul către issuer al unei rulări liniștite, în ambele cazuri după închiderea transportului, cu termenul jobului minus 20 s; actorul DM rămâne singurul care scrie.
6. Citirile preferă un credențial de citire utilizabil; `SendDelay.OFF` e refuzat pentru namespace-urile DM; `Gc.checkpoint` verifică `busy = 0`; executoarele mapează `SQLITE_FULL` la o excepție tipizată.
7. Migrarea 4 (după revizie, doar pașii de sincronizare și entitlement): gardă și eliminarea tabelelor DM v1; reconstruirea `outbox_op`/`outbox_delivery` cu liste explicite de coloane, `rowid` păstrat, `legacy_alter_table` oprit, `foreign_key_check` gol; triggere și indecși identici înainte și după, iar tabelele egale ca structură, cu singura diferență CHECK-ul TTL (§21.13); coloanele noi; `relay_key_registration`. **Migrarea 5** (nouă): tabelele `dm_*` și `olm_*`, cu triggerele și gărzile lor.
8. CI: **JDK 17** (fără trecerea la JDK 21 după revizie); compilarea `ghost-dm-host` pentru testele JVM; joburile noi `messaging-exit-gate.yml`, `dm-privacy-gate.yml`, `dm-emulator.yml` (emulator API 29 și 35 cu relee-model locale, acțiunea `reactivecircus/android-emulator-runner` fixată prin SHA, testul de echivalență gazdă/Android), `vendor-tests`, `dm-fuzz` și `pq-model`; niciun artefact binar public.
9. Testul T2 al Fazei 8: exportul și verificarea completitudinii includ `keys.redb` și registrul de depuneri; clienții lumii își înregistrează namespace-urile DM proprii; valorile de referință se reînregistrează.
10. **(după revizie)** `Inbox.peek` (doar citire, fără contor de oferte) și `Inbox.claimOne` (preia un rând numit, cu regulile de ofertă ale `claim`), pentru ordonarea mesajelor înaintea decriptării.

## Consecințe
(+) Niciun client nu poate cheltui un token pe inbox-ul altcuiva; consumul DM și ștergerile rulează și în fundal fără să influențeze momentele issuer-ului sau durata sesiunilor de relay; T2 rămâne fidel clientului real. (−) API mai mare; o migrare care reconstruiește tabelele outbox; o alarmă în plus; joburi CI mai lungi; poarta T2 se schimbă.

## Alternative respinse
Consumatorul pe firul unei benzi (blochează banda); mai mulți participanți (amestecă I/O de rețea cu munca locală); doar listener-ul (mesajele aduse în fundal așteaptă prim-planul); coada de consum cu transportul deschis (durata sesiunii ar depinde de volumul primit); renunțarea la treapta de 1 oră (abatere de la ADR-27); modificarea pe loc a CHECK-ului din v2; relee pe Tor public în jobul emulator.

## Teste
`SchemaAndMigrationTest` (toate căile de migrare, testul setului de obiecte), `SchemaIntrospectionTest` (15 coloane de timp în sync), testele planificatorului pentru LOCAL și pentru înregistrări, `SessionParticipantTest` (coada de consum), T19 cu înregistrări, NI-DM1 (momentul închiderii sesiunii), `sync-exit-gate`, `entitlement-exit-gate` și `t2-exit-gate` verzi, `dm-emulator.yml` verde pe API 29 și 35; mutanții MC-1, MC-2, MC-12 … MC-15, MC-17, MC-25, PM-14, PM-25, PM-30.

## Corecturi după revizie (§21; au prioritate)
1. Migrarea 4 intră în S3 cu pașii de sincronizare și entitlement, iar migrarea 5 (tabelele `dm_*` și `olm_*`) intră în S4b (după revizia din 2026-09-16; în runda 9 migrarea 4 conținea tot), ca fiecare felie să lase o schemă consistentă; tabele noi: `dm_outbound_item`, `dm_bundle_candidate`, `dm_orphan_namespace` (în migrarea 5).
2. API-ul `:sync` primește `Inbox.forgetConsumed` (doar pentru namespace-urile PREKEYS).
3. Pașii temporizați (publicarea și re-sigilarea bundle-ului, controalele programate, `EST-READY`, `EST-END`, părțile săptămânale din KEEPER și REGROWS) rulează doar din timerul actorului, la deschiderea bazei și la începutul unei sesiuni de relay, niciodată dintr-un hint de primire sau dintr-o trimitere a utilizatorului (§21.9).
4. Paza de „otravă” numără doar morțile procesului: fără preluări cât biblioteca nativă sau cheile lipsesc, câte un blob în coada de consum, `Inbox.defer` după `SQLITE_FULL` (§21.12).
5. Varianta de build `gate` (hook-ul de schimbare a cheii și exportul digest-urilor) se construiește fără nicio încărcare, se semnează cu o cheie de unică folosință și se instalează doar pe dispozitivele porții; hook-ul stă în `crypto-bridge/src/gate`; G-DM5 verifică seturile de surse și `mapping.txt`, nu nume de clase ofuscate.
6. Testul de fum al variantei release nu folosește transport; lumea T2 enumeră toate fișierele `*.redb`, iar exportul `keys.redb` intră în S1; NDK-ul se fixează prin `android.ndkVersion`; CI nu mai încarcă APK-uri sau biblioteci native cât timp depozitul e public (G-L5, ADR-39; după revizie, Q1 nu mai există); RUNBOOK O1 și releele de staging se actualizează.
7. Mutanți: 96 (40 de confidențialitate, 32 de corectitudine, 24 efemere și de plic); 97 dacă S0′ adoptă limita de vârstă a cheilor sărite (Q67). Runda 9 declara 79, dar definea 78 (MC-19 lipsea); revizia din 2026-09-16 ajunsese la 91; recenzia reviziei adaugă PM-38, PM-39, MC-31 … MC-33 (§22.8.11).

## Revizia din 2026-09-16 (are prioritate; ADR-34′)
1. Schema se împarte: migrarea 4 (sincronizare și entitlement, S3) și migrarea 5 (DM și Olm, S4b); tabelele `sig_*` și coloana `registration_id` nu se mai creează.
2. CI rămâne pe JDK 17; testele JVM folosesc compilarea nativă `ghost-dm-host`; se adaugă joburile `vendor-tests`, `dm-fuzz` și `pq-model`, iar jobul `rust` rulează modelele de stare EM-1 și EM-2.
3. API-ul `:sync` primește `Inbox.peek` și `Inbox.claimOne`.
4. Jobul emulator adaugă testul de echivalență între compilarea pentru gazdă și cea Android.
5. Mutanții devin 96 (97 cu MC-30; §22.8.11).
6. **Corecturi după recenzia reviziei (§22.8.9, §22.8.10):** cât depozitul e public, joburile `android`, `reproducible` și `dm-emulator` își construiesc singure bibliotecile native și compară sumele publicate ca ieșire text de `android-native`; după trecerea pe privat, artefactele interne de predare au `retention-days: 1`. Porțile de ieșire, lumea de confidențialitate și emulatorul rulează nocturn și la cerere; planul CI se recalculează în S0′ pentru runnere private de 2 CPU și 8 GB. Porțile dependente de build rulează în joburile care au toolchain-ul (G-R1, G-R2, G-R4, G-R5, G-R7, G-R8 în `rust`; G-R3 și G-R6 în `android-native`), nu în `static-gates`. `dm-fuzz` folosește un nightly datat, cu crate-ul de fuzz în afara workspace-ului.
