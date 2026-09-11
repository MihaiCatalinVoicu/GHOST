# client-core/ — nucleul de client în Rust (ADR-19)

Logica de rețea și, în fazele următoare, de protocol a clientului Android trăiește în Rust și este expusă modulelor Kotlin prin JNI. Kotlin-ul validează tipuri și afișează; nu implementează protocol (spec §6.1).

| Crate | Rol | Modul Android |
|---|---|---|
| `net` | Tor embedded (Arti) cu onion-service client, vanguards-lite și bridges simple (`IP:PORT FINGERPRINT`; transporturile obfs4/webtunnel/snowflake vin în Faza 12); `OnionAddress` strict cu checksum v3; izolare de circuite per namespace/scop; client gRPC relay prin Tor (HTTP/2 fără `user-agent`, deadline pe fiecare RPC, validarea răspunsurilor); JNI `org.ghost.network.TorRelayTransport` | `android/network` |

## Contractul de date către relay

Clientul relay transportă doar blob-uri **deja criptate și de dimensiune exactă de bucket** (1/4/16/64 KiB). Padding-ul se aplică *în interiorul* plaintext-ului AEAD de stratul care criptează (`ghost_relay_transport::pad_plaintext`), niciodată pe ciphertext: un prefix de lungime în clar i-ar da relay-ului dimensiunea exactă. TTL-ul este rotunjit la bucket-urile permise (1/7/30/90 zile).

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
| `invalid_argument` | argument invalid verificat în Rust (TTL 0 sau peste 90 zile, cursor, limită de lot); verificările Kotlin (`require`) aruncă `IllegalArgumentException` înainte de apelul nativ |
| `not_onion` | destinația nu este o adresă onion v3 validă (inclusiv checksum) |
| `closed` | transportul a fost închis înainte sau în timpul apelului |
| `runtime` | runtime-ul nativ nu a putut porni |
| `bridge_config` | linie de bridge invalidă sau nesuportată (inclusiv transporturi încă neactivate) |
| `tor_setup` | clientul Tor nu a putut fi creat local: director de stare/cache inutilizabil, cache sau keystore care nu se deschide. Un director de stare folosit deja de alt transport viu NU produce eroare (Arti trece pe stare read-only): două transporturi nu trebuie să împartă directorul |
| `tor_bootstrap` | bootstrap Tor eșuat, sau o reîncercare pe un transport al cărui bootstrap a eșuat deja: după orice eșec de bootstrap transportul trebuie închis și creat altul |
| `tor_bootstrap_timeout` | bootstrap Tor peste termenul limită (180 s): transportul trebuie închis și creat altul |
| `not_bootstrapped` | apel către relay înainte de un bootstrap reușit (conexiunile nu pornesc niciodată un bootstrap implicit) |
| `transport` | relay-ul onion nu poate fi atins (descriptor, rendezvous, circuit) |
| `timeout` | RPC-ul către relay a depășit termenul limită (60 s) |
| `unauthorized` | capabilitate respinsă de relay |
| `quota` | cota capabilității depășită |
| `not_found` | blob inexistent în namespace-ul capabilității |
| `rejected` | cerere respinsă de relay ca invalidă |
| `relay_unavailable` | eroare tranzitorie a relay-ului sau a conexiunii |
| `not_bucket_sized` | blob-ul trimis nu are exact o dimensiune de bucket |
| `not_stored` | relay-ul a confirmat un blob cu o expirare mai scurtă decât TTL-ul cerut (toleranță de ceas 3 zile), deci blob-ul ar dispărea mai devreme |
| `malformed_response` | răspunsul relay-ului încalcă protocolul (hash, dimensiune, cursor, lot) |
| `internal` | eroare internă (inclusiv panică prinsă la graniță) |
| `native_missing` | doar în Kotlin: biblioteca nativă lipsește sau nu se poate încărca (`UnsatisfiedLinkError`) |
