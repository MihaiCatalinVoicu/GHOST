# client-core/ — nucleul de client în Rust (ADR-19)

Logica de rețea și, în fazele următoare, de protocol a clientului Android trăiește în Rust și este expusă modulelor Kotlin prin JNI. Kotlin-ul validează tipuri și afișează; nu implementează protocol (spec §6.1).

| Crate | Rol | Modul Android |
|---|---|---|
| `net` | Tor embedded (Arti) cu onion-service client, vanguards-lite și bridges simple (`IP:PORT FINGERPRINT`; transporturile obfs4/webtunnel/snowflake vin în Faza 12); `OnionAddress` strict cu checksum v3; izolare de circuite per namespace/scop și per flux de issuer (`IsolationScope::IssuerFlow`); client gRPC relay prin Tor legat de un namespace (`NamespaceClient`: HTTP/2 fără `user-agent`, deadline pe fiecare RPC, validarea răspunsurilor, capabilitate verificată față de namespace înainte de orice I/O, răscumpărarea tokenurilor de entitlement); client gRPC al issuer-ului prin Tor (`IssuerClient`, `issuer_flow`); Entitlement Schedule (ES) inclus în bibliotecă și verificat la încărcare; JNI `org.ghost.network.TorRelayTransport`, `TorIssuerTransport`, `EntitlementCrypto` | `android/network` |

## Contractul de date către relay

Clientul relay transportă doar blob-uri **deja criptate și de dimensiune exactă de bucket** (1/4/16/64 KiB). Padding-ul se aplică *în interiorul* plaintext-ului AEAD de stratul care criptează (`ghost_relay_transport::pad_plaintext`), niciodată pe ciphertext: un prefix de lungime în clar i-ar da relay-ului dimensiunea exactă. TTL-ul este rotunjit la bucket-urile permise (1/7/30/90 zile).

## Apelurile relay (JNI `TorRelayTransport`)

Fiecare apel construiește un `NamespaceClient` pentru namespace-ul apelului: circuitele folosesc izolarea `IsolationScope::Namespace(ns)`, iar înainte de orice I/O antetul capabilității (`ghost_relay_api::capability_header`: formatul v1 `version‖kind‖namespace‖quota‖expiry‖mac`, 82 bytes, emis din CLI-ul relay-ului, sau v2 cu un serial de 16 bytes înaintea MAC-ului, 98 bytes, emis de `RedeemToken`) trebuie să numească același namespace și un tip potrivit: write pentru `store`; read sau write pentru `get`, `list`, `check` (la relay, write include read). Altfel apelul eșuează cu `invalid_argument` fără să deschidă o conexiune (invariant T21); un token într-un format pe care build-ul nu îl cunoaște e refuzat la fel. `RelayClient` nu are constructor public.

Argumentele și rezultatul (bytes) fiecărui apel:

- **store** (`nativeStore`): relay, namespace (32), capabilitate, ciphertext (un bucket), TTL, `deadlineMs` → `blob_hash(32) ‖ expiry(8, BE)`.
- **get** (`nativeGet`): relay, namespace, capabilitate, `blob_hash` (32), `deadlineMs` → `expiry(8, BE) ‖ ciphertext`: expirarea declarată de relay (cel mult acum + 90 zile + 3 zile toleranță de ceas; una mai mare e `malformed_response`), apoi ciphertext-ul verificat (hash, bucket).
- **list** (`nativeList`): relay, namespace, capabilitate, cursor (0 sau 8 bytes), limită (1..256), `deadlineMs` → `cursor_len(1) ‖ cursor ‖ hash-uri (32 fiecare)`.
- **check** (`nativeCheck`): relay, namespace, capabilitate, hash-uri distincte concatenate (32 fiecare, cel mult 256; un hash repetat dă `invalid_argument`), `deadlineMs` → hash-urile deținute de relay, concatenate: un subset al cererii, fiecare cel mult o dată (verificat nativ și în Kotlin).
- **redeem** (`nativeRedeem`, Faza 8, design §10.9): relay, namespace (32), token de entitlement (354), `requestId` (16, identic la fiecare reîncercare), `deadlineMs` → `result(1) ‖ relay_period(8) ‖ relay_minute(8) ‖ expiry(8) ‖ capabilitate(98 sau 0)`, `result` 1 OK (cu capabilitatea), 2 REPLAYED, 3 WRONG_PERIOD. Pe circuitele namespace-ului (T21). **Înainte de orice I/O** tokenul trebuie să fie un token ACCESS al ES-ului inclus, a cărui provocare numește slotul pe care ES-ul îl atribuie onion-ului *acestui* relay (comparat după cheia serviciului) în săptămâna tokenului, cu semnătura verificată de `ring` și cheia nerevocată; un token legat în altă parte nu părăsește dispozitivul (0 cereri, 0 conexiuni; mutantul M6). **După răspuns:** OK are o capabilitate v2, de tip write, pentru exact acest namespace, cu cota din ES și expirarea `start(p+1) + 1 h` a săptămânii p a tokenului; REPLAYED și WRONG_PERIOD nu au capabilitate; orice răspuns are `relay_period_id` la cel mult o săptămână de săptămâna ceasului dispozitivului și un `relay_minute` în interiorul acelei săptămâni. Altfel `malformed_response`. `relay_period_id` și `relay_minute` servesc numai deciziilor față de relay, niciodată `base_week` sau programării apelurilor către issuer (§19.4). Kotlin nu parsează capabilitatea.

**Termenul per apel.** `deadlineMs` limitează tot apelul (rendezvous, cerere, răspuns). Termenul efectiv este `min(deadlineMs, 60 s)` (`RELAY_RPC_DEADLINE`); 0 sau o valoare negativă dă `invalid_argument`. Kotlin acceptă 1..60 000 ms (`require`); metodele fără termen folosesc 60 000. Depășirea termenului dă `timeout`. Un singur transport servește apeluri concurente din mai multe fire JVM (runtime multi-thread; test cu două apeluri simultane pe același handle).

## Entitlement (Faza 8, design §11.7)

**Entitlement Schedule.** `protocol/entitlement/schedule.ghes` este compilat în bibliotecă cu `include_bytes!` (acoperit de build-ul reproductibil, T12; nicio cale de rețea nu îl poate înlocui) și verificat o singură dată, la prima folosire, sub cheia de schedule fixată pentru rețeaua lui (`Schedule::verify`, singura intrare de producție; un schedule regtest este refuzat). Dacă verificarea eșuează, fiecare apel de entitlement eșuează cu `internal`. Kotlin nu vede niciodată octeții ES-ului: primește rezumatul verificat și îl compară cu propria memorie (regula 5).

**Izolarea fluxurilor de issuer.** `IsolationScope::IssuerFlow([u8; 16])` înlocuiește scopul unic `Issuer`: fiecare instanță de flux (un pas de cumpărare, un trial, o revendicare, un refresh, o revocare) are 16 octeți aleatori și propriul token de izolare, deci două fluxuri nu împart niciodată un circuit, între ele sau cu un namespace. `nativeEndFlow` renunță la tokenul fluxului; harta fluxurilor aparține transportului (dispare la închiderea lui; un token nu este refolosit niciodată) și e mărginită la 64 de fluxuri (al 65-lea scoate cel mai vechi flux, care primește doar circuite noi). Testul unitar stabil `issuer_flows_get_distinct_tokens_dropped_at_the_end_and_never_reused` (`net/src/isolation.rs`) este ținta mutantului M4 (`SharedIssuerScope`, prins în același modul) și are un echivalent la granița JNI (`jni_bridge.rs`).

**Apelurile către issuer (JNI `TorIssuerTransport`).** Folosesc handle-ul unui `TorRelayTransport` (un singur client Tor per proces). Destinația este onion-ul issuer-ului din ES; niciun apelant nu o alege. HTTP/2 fără `user-agent`, origine constantă (`issuer.invalid`), termen `min(deadlineMs, 60 s)`, respectiv 120 s pentru `BlindSign` și `RedeemInvite`; răspunsurile peste 1 MiB sunt refuzate. **Înainte de orice I/O** (`invalid_argument`, nimic trimis): layout-ul este recalculat din (produs, săptămâna de bază sau epoca creditului) și comparat cu digest-ul stocat la cumpărare; cererea este recalculată din seed (identică la fiecare reîncercare); creditele, invitația și creditul primit sunt verificate sub ES (tip, provocare, `ring`, nerevocate), creditele sunt distincte, iar creditele unui pachet sunt cel mai mic set care acoperă prețul; adresa de plată este a rețelei ES. **După răspuns** (altfel `malformed_response`): rezultatul sau starea este o valoare cunoscută și fiecare câmp i se potrivește; suma facturii este prețul din ES (0 la plata cu credite) iar subadresa este a rețelei ES; semnăturile oarbe vin în numărul layout-ului, fiecare cu `s'^e ≡ B`, și se finalizează în tokenuri verificate de `ring`; suma unei plăți în coadă este valoarea creditelor ei; o mască de credite folosite numește doar credite ale cererii. Rezultatele protocolului (`WRONG_PERIOD`, `CREDITS_SPENT`, `CLAIM_CONFLICT`, `OTHER_REQUEST_ISSUED`, `REPLAYED`, `ADDRESS_REJECTED`) sunt în bandă, nu excepții. Seed-ul, r, blinded messages și semnăturile oarbe nu ajung în Kotlin.

- **nativeRequestInvoice**: flux (16), `claimHash` (32), credite (0, sau 354 bytes fiecare, concatenate), `baseWeek` (ceasul dispozitivului), `deadlineMs` → `result(1) ‖ invoice_id(16) ‖ amount(8) ‖ subaddress(0 sau 95) ‖ spent_mask(4)`; `result` 1 OK, 2 WRONG_PERIOD, 3 CREDITS_SPENT, 4 CLAIM_CONFLICT.
- **nativeBlindSign**: flux, `invoiceId` (16), `claimKey` (32), `seed` (32), produs (1 pachet XMR, 2 pachet cu credite), `baseWeek`, `layoutDigest` (32), `deadlineMs` → `state(1) ‖ credited(8) ‖ seen(8)`, urmat la SIGNED de `N × (nullifier(32) ‖ token(354))` în ordinea layout-ului; `state` 1 SIGNED, 2 AWAITING_PAYMENT, 3 AWAITING_CONFIRMATIONS, 4 UNDERPAID, 5 EXPIRED, 6 OTHER_REQUEST_ISSUED.
- **nativeInvoiceStatus**: flux, `invoiceId`, `claimKey`, `deadlineMs` → `state(1) ‖ credited(8) ‖ seen(8)`.
- **nativeRedeemInvite**: flux, token de invitație (354), `seed`, `baseWeek`, `layoutDigest`, `deadlineMs` → `result(1)`, urmat la OK de `N_t × (nullifier ‖ token)`; `result` 1 OK, 2 REPLAYED, 3 WRONG_PERIOD.
- **nativeClaimPayout**: flux, `claimId` (16), credite (`min_claim_credits .. max_claim_credits`), adresa de plată, `deadlineMs` → `result(1) ‖ queued(8) ‖ spent_mask(8)`; `result` 1 QUEUED, 2 CREDITS_SPENT, 3 CLAIM_CONFLICT, 4 ADDRESS_REJECTED. Masca are 8 bytes (`uint64` în `issuer.proto`, §19.21).
- **nativeRefreshCredit**: flux, creditul primit (354), `seed`, `layoutDigest` al `refresh(epoca creditului)`, `deadlineMs` → `result(1)`, urmat la OK de `nullifier(32) ‖ token(354)`; `result` 1 OK, 2 REPLAYED.
- **nativeEndFlow**: flux → renunță la tokenul de izolare al fluxului (un handle oprit: nimic).

**Funcții fără stare (JNI `EntitlementCrypto`, peste ES-ul inclus).**

- **nativeScheduleSummary** → `digest(32) ‖ seq(8) ‖ network(1) ‖ first_week(8) ‖ last_week(8) ‖ constante(20) ‖ slot_count(1) ‖ slot_count × (slot(1) ‖ valid_from(8) ‖ valid_until(8) ‖ onion_len(1) ‖ onion ASCII) ‖ price_count(2) ‖ … × (price_epoch(8) ‖ price(8)) ‖ key_count(2) ‖ … × (kind(1) ‖ epoch(8) ‖ key_id(32)) ‖ revoked_count(2) ‖ … × (kind(1) ‖ epoch(8))` (constantele în ordinea ES; sursa: `net/src/entitlement.rs`).
- **nativeLayoutDigest**: produs (1 pachet XMR, 2 pachet cu credite, 3 trial, 4 refresh), index (săptămâna de bază; epoca creditului la refresh) → `digest(32) ‖ N(4)`; un layout pe care ES-ul nu îl acoperă dă `invalid_argument`.
- **nativeVerifyToken**: token, tip (1 access, orice slot; 2 invite; 3 credit) → `kind(1) ‖ epoch(8) ‖ slot(1, 0xFF fără slot) ‖ nullifier(32)`; un token refuzat dă categoria `rejected` (Kotlin întoarce `null`).
- **nativeValidateAddress**: adresă, scop (1 factură, 2 plată) → `(rețea << 8) | tip` (tip 1 standard, 2 subadresă); refuzată: `rejected`.
- **nativePaymentUri**: subadresă, sumă > 0 → `monero:<subadresă>?tx_amount=<12 zecimale>`, construit local.

**Verificarea opțională `CLOCK_UNTRUSTED` (§19.4 punctul 4) nu este implementată:** Arti 0.46 nu expune durata de viață a consensului fără feature-ul `experimental-api` (câmpurile `dir_status` și `skew` din `arti_client::status::BootstrapStatus` sunt private, `DirStatus::declared_lifetime` este privată în `tor-dirmgr`, iar `TorClient::dirmgr()` cere `experimental-api`, interzis de `rust-feature-policy.sh`). Regulile 1–2 din §19.4 închid canalul fără ea.

## Build

```bash
cd ghost
cargo test -p ghost-client-net                                     # teste unitare + round-trip pe un relay local (fără Tor) + testele de entitlement (ES de test, issuer model, relay real în proces)
cargo test -p ghost-client-net --test live_tor -- --ignored        # bootstrap Tor real, stream onion, izolare pe circuite reale (rețea)
# biblioteci native pentru Android (necesită NDK și cargo-ndk 4.1.2):
bash scripts/build-native.sh android/network/src/main/jniLibs
```

Testele care folosesc ES-ul de test și cheile lui (`issuer/crates/entitlement/tests/fixtures`) stau în `net/tests/`: nicio sursă de producție (`src/`, inclusiv modulele `#[cfg(test)]`) nu numește material de test (`entitlement-schedule.sh`). Ele exercită logica prin interfețele `IssuerRpc` și `RedeemRpc`, pe care transportul Tor le implementează.

`jniLibs/` nu se comite. În CI, jobul `android-native` construiește biblioteca de două ori în aceeași cale, pornind de fiecare dată de la un director `target` gol, cu căile de build remapate, și eșuează dacă hash-urile diferă sau dacă binarul conține căi ale mașinii de build (HOME, CARGO_HOME, RUSTUP_HOME, NDK, workspace); APK-ul din joburile `android` și `reproducible` este construit cu exact aceste biblioteci. Asta dovedește determinismul la aceeași cale, nu identitatea între medii diferite: pe Windows separatorii rămân `\`, iar cargo include flag-urile de remapare (care numesc căile mașinii) în numele directoarelor de build-script. Un builder cu căi fixe (container) vine în Faza 14, împreună cu generatorul de manifest care va consuma `native-libs.sha256` (azi un artefact CI al aceleiași rulări, nu o referință revizuită separat). Un build local de release împachetează ce `.so` găsește în `jniLibs/`; doar gate-ul T12 verifică bibliotecile.

## Regula de graniță JNI

Prin JNI trec doar `String`, `ByteArray`, `Int`, `Long`. Rezultatele sunt șiruri de bytes cu layout fix (întregi big-endian), citite strict de decodoarele Kotlin (lungimi, numărări și valori exacte; altfel `malformed_response`). Starea nativă stă într-un registru indexat de un id opac; `close()` nu poate elibera memorie sub un apel în curs, iar apelurile în curs primesc `closed`. O panică Rust prinsă la graniță devine excepția `internal`, fără mesaj pe stderr (hook de panică silențios); o panică apărută în timpul altei panici sau lipsa memoriei opresc procesul. Erorile ajung în Kotlin ca `NetworkException` cu o categorie constantă, niciodată cu adrese, hash-uri, conținut sau textul unui răspuns de relay ori issuer (testul T3 `net/tests/jni_error_canaries.rs`). Stările issuer-ului se mapează pe categoriile existente (`categories::for_issuer`, design §5.7): nicio categorie nouă. Lista completă (sursa: `net/src/categories.rs`, verificată de un test):

| Categorie | Când |
|---|---|
| `invalid_argument` | argument invalid verificat în Rust (TTL 0 sau peste 90 zile, cursor, limită de lot, hash repetat în `check`, termen 0 sau negativ); capabilitate care nu se poate parsa, care numește alt namespace decât apelul sau al cărei tip nu se potrivește operației (T21), refuzată înainte de orice I/O; token de entitlement legat de alt relay sau refuzat de ES, layout sau credite care nu se potrivesc, refuzate înainte de orice I/O; verificările Kotlin (`require`) aruncă `IllegalArgumentException` înainte de apelul nativ |
| `not_onion` | destinația nu este o adresă onion v3 validă (inclusiv checksum) |
| `closed` | transportul a fost închis înainte sau în timpul apelului |
| `runtime` | runtime-ul nativ nu a putut porni |
| `bridge_config` | linie de bridge invalidă sau nesuportată (inclusiv transporturi încă neactivate) |
| `tor_setup` | clientul Tor nu a putut fi creat local: director de stare/cache inutilizabil, cache sau keystore care nu se deschide. Un director de stare folosit deja de alt transport viu NU produce eroare (Arti trece pe stare read-only): două transporturi nu trebuie să împartă directorul |
| `tor_bootstrap` | bootstrap Tor eșuat, sau o reîncercare pe un transport al cărui bootstrap a eșuat deja: după orice eșec de bootstrap transportul trebuie închis și creat altul |
| `tor_bootstrap_timeout` | bootstrap Tor peste termenul limită (180 s): transportul trebuie închis și creat altul |
| `not_bootstrapped` | apel către relay sau issuer înainte de un bootstrap reușit (conexiunile nu pornesc niciodată un bootstrap implicit) |
| `transport` | relay-ul sau issuer-ul onion nu poate fi atins (descriptor, rendezvous, circuit) |
| `timeout` | RPC-ul către relay sau issuer a depășit termenul apelului (`deadlineMs`, cel mult 60 s, respectiv 120 s pentru `BlindSign` și `RedeemInvite`) |
| `unauthorized` | capabilitate sau token respinse de relay; cheie de revendicare, factură, invitație sau credite respinse de issuer (`PERMISSION_DENIED`) |
| `quota` | cota capabilității depășită; limita de rată a issuer-ului (`RESOURCE_EXHAUSTED`) |
| `not_found` | blob inexistent în namespace-ul capabilității |
| `rejected` | cerere respinsă de relay sau issuer ca invalidă; în `EntitlementCrypto`: token sau adresă refuzate de verificarea offline |
| `relay_unavailable` | eroare tranzitorie a serviciului onion la distanță (relay sau issuer) sau a conexiunii; la issuer: `UNAVAILABLE` și orice alt cod gRPC |
| `not_bucket_sized` | blob-ul trimis nu are exact o dimensiune de bucket |
| `not_stored` | relay-ul a confirmat un blob cu o expirare mai scurtă decât TTL-ul cerut (toleranță de ceas 3 zile), deci blob-ul ar dispărea mai devreme |
| `malformed_response` | răspunsul relay-ului sau al issuer-ului încalcă protocolul sau ES-ul (hash, dimensiune, cursor, lot, `check` cu hash-uri necerute sau repetate, expirare peste acum + 90 zile + toleranța de ceas; sumă sau subadresă diferite de ES, număr de semnături, `s'^e ≢ B`, `ring`, capabilitate v2 greșită) |
| `internal` | eroare internă (inclusiv panică prinsă la graniță; ES-ul inclus nu se verifică) |
| `native_missing` | doar în Kotlin: biblioteca nativă lipsește sau nu se poate încărca (`UnsatisfiedLinkError`) |
