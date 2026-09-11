# Review de securitate — Faza 6 (client Tor, JNI, modul Android `network`)

| Câmp | Valoare |
|---|---|
| Data | 2026-09-11 |
| Obiect | commit-urile `1ae4f73..25b2b88` (client-core/net, android/network, CI, deny.toml) și remedierile lor |
| Metodă | Runda 1: 6 revieweri independenți pe dimensiuni (siguranță FFI/JNI, confidențialitate și fail-closed, protocol față de un relay rău-intenționat, configurație Tor/Arti, supply chain și CI, afirmații vs dovezi) + critic de completitudine; fiecare constatare verificată de 3 sceptici cu lentile diferite, păstrată doar la ≥ 2 voturi. Runda 2: fiecare remediere verificată adversarial (e completă? a introdus regresii?), apoi regresiile confirmate de sceptici. Runda 3: 5 revieweri pe zonele atinse în runda 2 (stocare relay, client Rust, Kotlin, CI și scripturi, afirmații în documente), fiecare constatare păstrată doar dacă ambii sceptici o confirmă |
| Rezultat | Runda 1: 55 constatări brute → 47 confirmate → **27 după deduplicare**; 8 respinse. Runda 2: 16 remedieri complete, 11 parțiale; **11 regresii confirmate** (1 high, 2 medium, 8 low), 5 respinse; toate rezolvate în runda 2. Runda 3: 18 constatări, **15 confirmate** (7 medium, 8 low), 3 respinse; toate rezolvate (tabelele de mai jos) |
| Dovezi CI | Commit cd145fc: toate joburile verzi, inclusiv două build-uri native identice la aceeași cale și T12; jobul live `live-tor` verde (https://github.com/MihaiCatalinVoicu/GHOST/actions/runs/34585120238) |
| Limită | Reviewerii sunt agenți AI; nu înlocuiesc auditul extern din Faza 15 și nici review-ul independent cerut de gate-ul Fazei 2 |

## Constatări și rezolvare

| # | Sev. | Constatare | Rezolvare |
|---|---|---|---|
| 1 | high | Ciclul de viață al handle-ului JNI nesincronizat: `close()` concurent cu un apel → use-after-free; două `close()` → double-free; timer tokio pe runtime oprit → abort | **Rezolvat.** Registru de handle-uri cu id opac, `Arc` ținut pe durata apelului, `stop` idempotent cu anulare (`closed`), runtime oprit la ultima referință; `AtomicLong` în Kotlin; `reachabilityFence` pe fiecare apel nativ (runda 2); testele apelează direct funcțiile `register`/`stop` folosite de JNI |
| 2 | medium | Padding aplicat pe ciphertext: prefixul de lungime în clar dezvăluia relay-ului dimensiunea exactă | **Rezolvat.** Clientul trimite doar blob-uri deja criptate de dimensiune bucket (`not_bucket_sized` altfel); `pad_plaintext`/`unpad_plaintext` pentru plaintext-ul AEAD, care refuză acum un overhead sub 16 octeți (fără AEAD, runda 2) |
| 3 | medium | Vanguards dezactivat (feature lipsă) → descoperirea gărzii de către operatorul relay-ului | **Rezolvat.** Feature `vanguards`, mod `Lite` fixat explicit; test de configurație; gate `rust-feature-policy.sh` cu self-test (runda 2); ADR-01 actualizat |
| 4 | medium | RPC-uri fără deadline: un relay care nu răspunde blochează firul pentru totdeauna | **Rezolvat.** 60 s pe fiecare RPC (inclusiv conectarea), anulare la `close()`; test cu un peer care nu răspunde. Bugetul pe relay pentru buclele de sync rămâne în Faza 7 |
| 5 | medium | Bootstrap fără termen și neanulabil; client Tor „orfan” după abandon | **Rezolvat.** Creare separată de bootstrap; bootstrap 180 s, anulabil din alt fir; `start()` închide la eșec; `finalize()` ca plasă de siguranță. Runda 2: după un bootstrap abandonat, reîncercarea pe același transport eșuează (nu mai raportează fals „gata”), cu test |
| 6 | medium | Biblioteca nativă nu ajungea în APK-ul din CI și nici în gate-ul de reproductibilitate | **Rezolvat (runda 2).** Jobul `android-native` construiește de două ori în aceeași cale, din `target` gol, cu `pipefail` pe toți pașii, și compară; `android` și `reproducible` folosesc artefactul; `apk-native-libs.sh` cere bibliotecile pe ambele ABI cu hash-urile înregistrate de build (nu o referință revizuită separat), cu self-test pe arhive fabricate. **Rămâne:** un build local de release împachetează ce `.so` găsește în `jniLibs/`; doar T12 îl verifică |
| 7 | medium | Căi absolute ale mașinii de build în `.so` → build nereproductibil între medii | **Parțial.** Căi remapate (prin `CARGO_ENCODED_RUSTFLAGS`, deci și cu spații), argumente absolute, verificare de scurgeri extinsă la HOME, RUSTUP_HOME și NDK. Determinismul e dovedit doar la aceeași cale: cargo include flag-urile de remapare în numele directoarelor de build-script, iar pe Windows separatorii rămân `\`. Builder cu căi fixe în Faza 14 |
| 8 | medium | Biblioteca Rust a clientului nu avea allowlist de pachete (gate-ul T7 acoperea doar Gradle) | **Rezolvat (runda 2).** Allowlist pe ambele ABI (a apărut `curve25519-dalek-derive`, doar pe x86_64), diagnostic la eșecul `cargo tree`, self-test care cere mesajul exact, inclus în `rust-gates.sh`; denylist de clienți HTTP și telemetrie în `deny.toml`. Potrivirea rămâne după nume de pachet |
| 9 | medium | `TorTransport::client()` public permitea conexiuni prin exit-uri Tor, ocolind `OnionAddress` | **Rezolvat (rundele 2 și 3).** `client()` e `pub(crate)`, fixat de un doctest `compile_fail`; tonic e legat doar cu `codegen` (fără `Channel` și fără `connect()` generat; au ieșit din bibliotecă și `axum`, `hyper-timeout`, `matchit`, `mime`); clippy interzice 23 de API-uri clearnet/DNS numite și orice conectare Arti în afara `connect_isolated`, fiecare dovedită de un fixture negativ. Formularea T6 spune explicit ce nu acoperă (API-uri nelistate, alt cod care folosește pachete permise) |
| 10 | medium | Liniile obfs4/webtunnel/snowflake erau documentate, dar nesuportate; eroarea apărea ca `tor_bootstrap` | **Parțial, restul în Faza 12.** Documentație corectată, categorie `bridge_config` rezervată liniilor de bridge (erorile locale de creare au acum `tor_setup`, runda 2), test care fixează refuzul; AD-4 din modelul de amenințări notează că bridges simple nu ascund Tor până în Faza 12 |
| 11 | low | Header `user-agent: tonic/<versiune>` pe fiecare cerere → partiționarea clienților pe versiune | **Rezolvat.** HTTP/2 printr-un client hyper fără `user-agent`; testul pe relay real verifică absența header-ului |
| 12 | low | TTL exact trimis relay-ului | **Rezolvat.** TTL rotunjit la bucket-urile 1/7/30/90 zile; peste 90 zile refuzat (și în Kotlin, runda 2) |
| 13 | low | `NetworkException` putea fi redenumită de R8 | **Rezolvat.** Regulă `-keep` în `consumer-rules.pro`; fallback pe `IllegalStateException` |
| 14 | low | Panică Rust la granița JNI = abort de proces | **Rezolvat.** `catch_unwind` pe fiecare intrare → categoria `internal`; hook de panică silențios (runda 2). O panică în timpul altei panici sau lipsa memoriei opresc totuși procesul |
| 15 | low | Cursor de listare trunchiat prin `as u8`; pagini peste limită | **Rezolvat.** Cursor 0 sau 8 octeți, pagină ≤ limită, altfel `malformed_response`; decodorul Kotlin verifică acum și limita (runda 2), cu cazuri care treceau de vechea verificare |
| 16 | low | APK instalabil pe ABI fără nucleul Tor | **Rezolvat.** `abiFilters` arm64-v8a/x86_64; T12 respinge directoare ABI neașteptate; o bibliotecă lipsă devine `native_missing`, nu `UnsatisfiedLinkError` (runda 2) |
| 17 | low | Store confirmat pentru un blob care nu ar fi servit (apartenență expirată, alt namespace sau TTL scurtat) | **Rezolvat (runda 2).** Relay: apartenență (namespace, hash) cu refcount, reînnoire la expirare, extindere la max(existent, acum+TTL), schema v2 cu versiune (ADR-18, anexă). Client: expirarea din chitanță e comparată cu TTL-ul rotunjit, cu toleranță de ceas 3 zile (`not_stored`) |
| 18 | low | Relay-ul cere PoW pe onion service, clienții nu îl rezolvă | **Decizie documentată** (torrc, ADR-01) și urmărită ca risc rezidual în `LIMITE_REZIDUALE_SI_MITIGARI.md` L5 |
| 19 | low | Gate-urile de logging și placeholder nu scanau `client-core/` | **Rezolvat.** Scanare extinsă + fixture negativ dedicat; self-test-ul a descoperit și un bug în gate (listări sărite sub `set -e`), reparat |
| 20 | low | cargo-ndk nefixat, fără `--locked`, acțiuni CI pe tag-uri mobile | **Rezolvat.** cargo-ndk 4.1.2, `--locked` pe toate comenzile cargo din CI și gate-uri, acțiuni fixate pe SHA, `protoc` 36.1 fixat pe hash (runda 2) |
| 21 | low | Justificarea pentru RUSTSEC-2023-0071 era greșită („unreachable”) | **Rezolvat (rundele 2 și 3).** Justificarea spune invariantul real: keystore-ul Arti e compilat și deschis, dar nimic activat nu pune o cheie acolo (test unitar după creare, cu verificarea că directorul există; test live după bootstrap, în jobul `live-tor`). Gate-ul verifică `relay` pe cele trei crate-uri care îl au (tor-proto, tor-chanmgr, tor-llcrypto; `tor-cell/relay` e activat necondiționat de tor-proto și adaugă doar un helper de codare, revizuit), absența `tor-hsservice`/`arti-relay`, `keymgr` pe `tor-hsclient` și că `rsa` e atins doar prin crate-uri Arti în tot workspace-ul, pe toate target-urile. O interogare cargo eșuată oprește acum gate-ul (runda 3), cu self-test pentru fiecare verificare |
| 22 | low | Licențe pre-aprobate nefolosite (BSL-1.0, OpenSSL) | **Rezolvat.** Eliminate; `unused-allowed-license = "deny"` |
| 23 | low | Testul de izolare era tautologic | **Rezolvat (runda 2); verificat live** în jobul `live-tor`, rularea CI 34585120238 (commit cd145fc: bootstrap Arti, două scope-uri pe circuite reale diferite, keystore gol după conexiuni onion). Conectorul relay-ului folosește aceeași funcție de conectare (`connect_isolated`) ca testul live, care compară circuitele reale a două scope-uri; testul unitar verifică alegerea token-ului |
| 24 | low | `RelayClient` și JNI fără teste | **Parțial.** Round-trip pe un relay real, relay ostil servit prin gRPC care încearcă fiecare metodă a clientului, relay de neatins → `transport`, deadline, maparea categoriilor, `stop`/`register` testate direct. **Rămâne:** încărcarea `.so` pe JVM/emulator (Faza 13) |
| 25 | low | README listea doar o parte din categoriile de eroare | **Rezolvat (runda 2).** Lista completă, verificată de un test; categoria `transport` e din nou produsă (cauza e recuperată din lanțul de erori tonic/hyper); `tor_setup` nouă; rândul `invalid_argument` corespunde verificărilor Kotlin |
| 26 | low | Parserul onion nu verifica versiunea și checksum-ul v3 | **Rezolvat.** Validare completă în Rust (`HsId`) și Kotlin (SHA3-256); categorie `not_onion`; vectorul etichetat greșit a fost corectat (versiune 0x23), iar testul de checksum folosește un vector cu cheie schimbată |
| 27 | low | Parserul Kotlin accepta caractere Unicode pe care Rust le refuza | **Rezolvat (runda 2).** Ambele parsere taie doar spațiu și tab ASCII și refuză orice caracter de control; vectori noi cu escape-uri `\uXXXX` (U+001C, U+001F, U+0085, newline, NUL, DEL); fișierul de vectori e intrare declarată a testelor Gradle |

## Runda 2: regresii găsite la verificarea remedierilor

| Sev. | Regresie | Rezolvare |
|---|---|---|
| high | Cota era taxată după ce `put()` confirma scrierea: un store peste cotă rămânea servibil, iar reîncercarea lui trecea gratuit (umplerea discului cu o cotă de 1 octet) | Cota se taxează în aceeași tranzacție de scriere, înainte de a persista ceva; rambursare dacă tranzacția nu se confirmă; test cu două noduri: store peste cotă → nu e servit, nu e listat, reîncercarea e respinsă, și când conținutul există deja în alt namespace |
| medium | `build-native.sh … \| tee` fără `pipefail`: orice eșec al build-ului era ascuns, iar jobul `android-native` trecea fără verificare | `shell: bash` (cu `-eo pipefail`) pe tot workflow-ul; scriptul scrie hash-urile într-un fișier, iar ieșirea cargo-ndk merge pe stderr |
| medium | Justificarea `keymgr` din `deny.toml` era falsă: keystore-ul Arti e activ prin `tor-chanmgr` | Vezi #21 |
| low | Cursorul „opac” era secvența globală a relay-ului: un cititor număra scrierile din alte namespace-uri | Secvență per namespace (`namespace_seq`) |
| low | ADR-18 descria încă schema veche | Anexă cu schema v2 și regulile ei |
| low | Allowlist-ul Rust verifica doar aarch64 | Vezi #8 |
| low | Self-test-ul allowlist-ului accepta orice eșec, inclusiv un `cargo tree` căzut | Self-test-ul cere mesajul exact al încălcării; în CI, lipsa cargo e eșec |
| low | Relay-ul de neatins apărea ca `relay_unavailable`, nu `transport` | Vezi #25 |
| low | Erorile locale de creare a clientului Tor apăreau ca `bridge_config` | Categoria `tor_setup` (#10) |
| low | Argumente relative în `build-native.sh` scriau bibliotecile în alt loc | Căile sunt făcute absolute la intrare |
| low | Flag-urile de remapare unite cu spații se rupeau pe căi cu spații | `CARGO_ENCODED_RUSTFLAGS` |

Alte lacune închise în runda 2 (fără să fi fost regresii): schema de stocare veche (Faza 5) e refuzată explicit, nu reinterpretată, iar prune-ul nu mai poate intra în panică pe chei malformate; listarea întoarce doar apartenențe vii și examinează cel mult 1 024 de intrări pe apel; `privacy-capture.sh` rulează cu `--locked`; duplicat în `.gitignore`.

## Runda 3: verificarea rundei 2

| Sev. | Constatare | Rezolvare |
|---|---|---|
| medium | Tabela nouă `namespace_seq` nu se ștergea niciodată: relay-ul păstra pentru totdeauna fiecare namespace folosit și numărul lui de scrieri, după ce blob-urile expirau | Rândul se șterge odată cu ultima intrare de index a namespace-ului; un namespace care revine pornește de la o sămânță orară, peste orice secvență anterioară (un cursor vechi nu sare intrări noi); test |
| medium | Clientul Arti pornea implicit un bootstrap la primul apel către relay (mod `OnDemand`), în afara gardei de abandon: un apel întrerupt de termenul RPC lăsa Arti în starea „bootstrap fals reușit” | Mod `Manual`: un apel înainte de bootstrap eșuează imediat cu categoria nouă `not_bootstrapped`; test |
| medium | Interdicțiile clippy prindeau doar API-urile numite; mai multe căi clearnet (constructorul `connect()` generat de tonic, `build_http`, `TcpSocket`, TCP brut al runtime-ului) treceau | tonic doar cu `codegen` și fără `connect()` generat; lista extinsă la 23 de API-uri; fixture negativ care cere ca fiecare interdicție să se declanșeze; documentele spun „API-uri numite”, nu „orice clearnet” |
| medium | Gate-ul de feature-uri trecea (exit 0) când o interogare `cargo tree` secundară eșua (substituție în argument) | Fiecare rezultat e pus întâi într-o variabilă; self-test cu o interogare forțată să eșueze |
| medium | Aceeași lacună, văzută din documente; în plus `relay` pe tor-circmgr/arti-client era o verificare goală | Lista de crate-uri corectată; formularea din `deny.toml` și rândul 21 spun exact ce se impune |
| medium | Clippy-ul anti-clearnet era prezentat în T6, ADR-01/19, STATUS ca acoperire generală | Formulare corectată peste tot |
| medium | Aserțiunile live noi (izolare pe circuite reale, keystore gol) nu rulaseră niciodată, dar documentele le dădeau drept verificate | Documentele trimit la jobul `live-tor`, rulat pe commit-ul acestor remedieri |
| low | Un store repetat cu același TTL la o secundă distanță era taxat din nou (expirare la secundă) | Expirări rotunjite la oră; un store acoperit în limita unei ore e no-op idempotent |
| low | Expirarea la secundă dezvăluia secunda încărcării (`expirare − TTL`) | Aceeași rotunjire la oră |
| low | Două bootstrap-uri concurente: al doilea putea raporta succes după abandonul primului | Încercările sunt serializate, iar garda marchează eșecul înainte de eliberarea blocării; test |
| low | Un bootstrap eșuat cu eroare permitea reîncercarea pe același client (Arti putea răspunde fals „gata”) | Orice eșec face transportul inutilizabil pentru bootstrap (`tor_bootstrap`, trebuie recreat) |
| low | Documentația spunea că o stare blocată de alt client produce `tor_setup`; Arti trece de fapt pe stare read-only | Documentație corectată: două transporturi nu trebuie să împartă directorul de stare |
| low | Verificarea `rsa` pe workspace nu folosea `--target all` | Adăugat |
| low | T12 accepta orice altă bibliotecă nativă într-un director ABI permis | Allowlist de nume `.so` în `apk-native-libs.sh`, cu self-test |
| low | `store()` Kotlin înainte de bootstrap pornea un bootstrap neurmărit | Rezolvat prin modul `Manual` (vezi mai sus) |

Respinse în runda 3: testul de keystore gol ar trece vacuu dacă directorul lipsește (Arti îl creează la pornire; testul verifică acum și existența lui); instalarea `protoc` pe o linie cu `&&` nu oprea pasul (impact fără efect, dar liniile au fost separate); T12 „exact bibliotecile înregistrate” (rezolvat oricum prin allowlist-ul de nume).

## Respinse (nu au supraviețuit verificării)

- Runda 1: lipsa legării unui `RelayClient` de un singur namespace (clientul e creat per apel; legare prin tip în Faza 7); loturi de fetch de dimensiune variabilă (ADR-15, Faza 7); `rotate_all()` fără efect asupra unui client viu (creat per apel); limite de dimensiune ale răspunsurilor (deadline + hash); remaparea `Internal`/`OutOfRange` (tranzitorii pe Tor); testul de bridge (Arti refuză `enabled=true` fără bridges); două duplicate parțiale.
- Runda 2: `finalize()` concurent cu un apel (reclasificat: rezolvat oricum prin `reachabilityFence`); schema fără versiune (inclusă în regresia de stocare, rezolvată); legătura pe disc între namespace-uri care au același ciphertext (apare doar dacă cineva copiază ciphertext-ul, iar relay-ul vede oricum acel store); gossip pe existența conținutului (gossip-ul rămâne oprit până la autentificarea peer-ilor, notat în `relay/README.md`); listarea apartenențelor expirate (rezolvată oricum).

## Note pentru fazele următoare

- Faza 7: `RelayClient` legat de namespace prin tip; loturi de dimensiune fixă; buget de timp per relay; clienții de lungă durată verifică o epocă de rotație a circuitelor; un cursor nevid cu pagină goală nu trebuie să poată ține clientul în buclă.
- Faza 12: transporturi pluggable (lyrebird, snowflake) și bridges implicite în manifest.
- Faza 13: testul T6 dinamic pe emulator și încărcarea `.so` în teste instrumentate.
- Faza 14: builder cu căi fixe pentru identitatea build-ului nativ între medii; generatorul de manifest consumă `native-libs.sha256`.
