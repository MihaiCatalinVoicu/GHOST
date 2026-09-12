# client-core/ — nucleul de client în Rust (ADR-19)

Logica de rețea și, în fazele următoare, de protocol a clientului Android trăiește în Rust și este expusă modulelor Kotlin prin JNI. Kotlin-ul validează tipuri și afișează; nu implementează protocol (spec §6.1).

| Crate | Rol | Modul Android |
|---|---|---|
| `net` | Tor embedded (Arti) cu onion-service client, vanguards-lite și bridges simple (`IP:PORT FINGERPRINT`; transporturile obfs4/webtunnel/snowflake vin în Faza 12); `OnionAddress` strict cu checksum v3; izolare de circuite per namespace/scop; client gRPC relay prin Tor legat de un namespace (`NamespaceClient`: HTTP/2 fără `user-agent`, deadline pe fiecare RPC, validarea răspunsurilor, capabilitate verificată față de namespace înainte de orice I/O); JNI `org.ghost.network.TorRelayTransport` | `android/network` |

## Contractul de date către relay

Clientul relay transportă doar blob-uri **deja criptate și de dimensiune exactă de bucket** (1/4/16/64 KiB). Padding-ul se aplică *în interiorul* plaintext-ului AEAD de stratul care criptează (`ghost_relay_transport::pad_plaintext`), niciodată pe ciphertext: un prefix de lungime în clar i-ar da relay-ului dimensiunea exactă. TTL-ul este rotunjit la bucket-urile permise (1/7/30/90 zile).

## Apelurile relay (JNI `TorRelayTransport`)

Fiecare apel construiește un `NamespaceClient` pentru namespace-ul apelului: circuitele folosesc izolarea `IsolationScope::Namespace(ns)`, iar înainte de orice I/O antetul capabilității (`ghost_relay_api::capability_header`: formatul v1 `version‖kind‖namespace‖quota‖expiry‖mac`, 82 bytes, emis din CLI-ul relay-ului, sau v2 cu un serial de 16 bytes înaintea MAC-ului, 98 bytes, emis de `RedeemToken`) trebuie să numească același namespace și un tip potrivit: write pentru `store`; read sau write pentru `get`, `list`, `check` (la relay, write include read). Altfel apelul eșuează cu `invalid_argument` fără să deschidă o conexiune (invariant T21); un token într-un format pe care build-ul nu îl cunoaște e refuzat la fel. `RelayClient` nu are constructor public.

Argumentele și rezultatul (bytes) fiecărui apel:

- **store** (`nativeStore`): relay, namespace (32), capabilitate, ciphertext (un bucket), TTL, `deadlineMs` → `blob_hash(32) ‖ expiry(8, BE)`.
- **get** (`nativeGet`): relay, namespace, capabilitate, `blob_hash` (32), `deadlineMs` → `expiry(8, BE) ‖ ciphertext`: expirarea declarată de relay (cel mult acum + 90 zile + 3 zile toleranță de ceas; una mai mare e `malformed_response`), apoi ciphertext-ul verificat (hash, bucket).
- **list** (`nativeList`): relay, namespace, capabilitate, cursor (0 sau 8 bytes), limită (1..256), `deadlineMs` → `cursor_len(1) ‖ cursor ‖ hash-uri (32 fiecare)`.
- **check** (`nativeCheck`): relay, namespace, capabilitate, hash-uri distincte concatenate (32 fiecare, cel mult 256; un hash repetat dă `invalid_argument`), `deadlineMs` → hash-urile deținute de relay, concatenate: un subset al cererii, fiecare cel mult o dată (verificat nativ și în Kotlin).

**Termenul per apel.** `deadlineMs` limitează tot apelul (rendezvous, cerere, răspuns). Termenul efectiv este `min(deadlineMs, 60 s)` (`RELAY_RPC_DEADLINE`); 0 sau o valoare negativă dă `invalid_argument`. Kotlin acceptă 1..60 000 ms (`require`); metodele fără termen folosesc 60 000. Depășirea termenului dă `timeout`. Un singur transport servește apeluri concurente din mai multe fire JVM (runtime multi-thread; test cu două apeluri simultane pe același handle).

## Build

```bash
cd ghost
cargo test -p ghost-client-net                                     # teste unitare + round-trip pe un relay local (fără Tor)
cargo test -p ghost-client-net --test live_tor -- --ignored        # bootstrap Tor real, stream onion, izolare pe circuite reale (rețea)
# biblioteci native pentru Android (necesită NDK și cargo-ndk 4.1.2):
bash scripts/build-native.sh android/network/src/main/jniLibs
```

`jniLibs/` nu se comite. În CI, jobul `android-native` construiește biblioteca de două ori în aceeași cale, pornind de fiecare dată de la un director `target` gol, cu căile de build remapate, și eșuează dacă hash-urile diferă sau dacă binarul conține căi ale mașinii de build (HOME, CARGO_HOME, RUSTUP_HOME, NDK, workspace); APK-ul din joburile `android` și `reproducible` este construit cu exact aceste biblioteci. Asta dovedește determinismul la aceeași cale, nu identitatea între medii diferite: pe Windows separatorii rămân `\`, iar cargo include flag-urile de remapare (care numesc căile mașinii) în numele directoarelor de build-script. Un builder cu căi fixe (container) vine în Faza 14, împreună cu generatorul de manifest care va consuma `native-libs.sha256` (azi un artefact CI al aceleiași rulări, nu o referință revizuită separat). Un build local de release împachetează ce `.so` găsește în `jniLibs/`; doar gate-ul T12 verifică bibliotecile.

## Regula de graniță JNI

Prin JNI trec doar `String`, `ByteArray`, `Int`, `Long`. Starea nativă stă într-un registru indexat de un id opac; `close()` nu poate elibera memorie sub un apel în curs, iar apelurile în curs primesc `closed`. O panică Rust prinsă la graniță devine excepția `internal`, fără mesaj pe stderr (hook de panică silențios); o panică apărută în timpul altei panici sau lipsa memoriei opresc procesul. Erorile ajung în Kotlin ca `NetworkException` cu o categorie constantă, niciodată cu adrese, hash-uri sau conținut. Lista completă (sursa: `net/src/categories.rs`, verificată de un test):

| Categorie | Când |
|---|---|
| `invalid_argument` | argument invalid verificat în Rust (TTL 0 sau peste 90 zile, cursor, limită de lot, hash repetat în `check`, termen 0 sau negativ); capabilitate care nu se poate parsa, care numește alt namespace decât apelul sau al cărei tip nu se potrivește operației (T21), refuzată înainte de orice I/O; verificările Kotlin (`require`) aruncă `IllegalArgumentException` înainte de apelul nativ |
| `not_onion` | destinația nu este o adresă onion v3 validă (inclusiv checksum) |
| `closed` | transportul a fost închis înainte sau în timpul apelului |
| `runtime` | runtime-ul nativ nu a putut porni |
| `bridge_config` | linie de bridge invalidă sau nesuportată (inclusiv transporturi încă neactivate) |
| `tor_setup` | clientul Tor nu a putut fi creat local: director de stare/cache inutilizabil, cache sau keystore care nu se deschide. Un director de stare folosit deja de alt transport viu NU produce eroare (Arti trece pe stare read-only): două transporturi nu trebuie să împartă directorul |
| `tor_bootstrap` | bootstrap Tor eșuat, sau o reîncercare pe un transport al cărui bootstrap a eșuat deja: după orice eșec de bootstrap transportul trebuie închis și creat altul |
| `tor_bootstrap_timeout` | bootstrap Tor peste termenul limită (180 s): transportul trebuie închis și creat altul |
| `not_bootstrapped` | apel către relay înainte de un bootstrap reușit (conexiunile nu pornesc niciodată un bootstrap implicit) |
| `transport` | relay-ul onion nu poate fi atins (descriptor, rendezvous, circuit) |
| `timeout` | RPC-ul către relay a depășit termenul apelului (`deadlineMs`, cel mult 60 s) |
| `unauthorized` | capabilitate respinsă de relay |
| `quota` | cota capabilității depășită |
| `not_found` | blob inexistent în namespace-ul capabilității |
| `rejected` | cerere respinsă de relay ca invalidă |
| `relay_unavailable` | eroare tranzitorie a relay-ului sau a conexiunii |
| `not_bucket_sized` | blob-ul trimis nu are exact o dimensiune de bucket |
| `not_stored` | relay-ul a confirmat un blob cu o expirare mai scurtă decât TTL-ul cerut (toleranță de ceas 3 zile), deci blob-ul ar dispărea mai devreme |
| `malformed_response` | răspunsul relay-ului încalcă protocolul (hash, dimensiune, cursor, lot, `check` cu hash-uri necerute sau repetate, expirare peste acum + 90 zile + toleranța de ceas) |
| `internal` | eroare internă (inclusiv panică prinsă la graniță) |
| `native_missing` | doar în Kotlin: biblioteca nativă lipsește sau nu se poate încărca (`UnsatisfiedLinkError`) |
