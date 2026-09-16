# relay/ — GHOST blind relay (Rust)

Un relay păstrează și servește blob-uri opace, adresate prin conținut, fără să afle cine le-a scris sau citit (CP-06, FR-5.x). Tot ce poate observa este enumerat normativ în `test-harness/privacy/allowed-observables.json` și verificat pe fiecare PR (T1).

| Crate | Rol |
|---|---|
| `crates/api` | Tipuri de wire generate din `protocol/relay/v1/relay.proto` + constante (bucket-uri, treptele TTL în secunde, limite) + formatele publice ale capabilității (`capability_header`, `capability_format`): v1 (82 bytes, emisă din CLI) și v2 (98 bytes, cu serial, emisă de `RedeemToken`), și al treilea format, credențialul purtător v3 (`bearer_credential`, 67 bytes: versiune, tip, slot, namespace, secret; Faza 9), definite o singură dată și folosite de relay și de client |
| `crates/storage` | Blob store pe redb (ADR-18, schema v2): conținut stocat o dată per hash (refcount), apartenență (namespace, hash) cu expirare proprie, cursor per namespace (șters odată cu ultimul blob al namespace-ului), index pe expirare, expirări rotunjite la oră; cota se taxează în tranzacția de scriere; o bază cu altă versiune de schemă e refuzată. Separat, `nullifiers.redb` (schema 1, ADR-25): nullifier-e per săptămână cu etichetă de legare, memoria ES (chei, revocări, seq), pragul perioadelor închise, pragul de refuz după reset și minutul maxim al sweep-ului. Separat, `keys.redb` (schema 1, Faza 9, ADR-30): înregistrările de chei (`bearer_keys`, `serial_use`) și minutul maxim al sweep-ului |
| `crates/capability` | Capabilități HMAC locale relay-ului (read/write pe namespace, cotă, expirare; v1 și v2 cu serial), eticheta de legare și serialul determinist ale unei răscumpărări, ledger de cotă (în memorie); verificatorul credențialului v3 și ledger-ul depunerilor per înregistrare (în memorie) |
| `crates/transport` | Framing de padding pentru plaintext-ul AEAD (`pad_plaintext`): după criptare blob-ul are exact o dimensiune de bucket (1/4/16/64 KiB) și niciun prefix de lungime în clar |
| `crates/gossip` | Reconciliere de inventar între relay-uri (doar hash-uri) |
| `crates/prune` | Sweep determinist: blob-uri expirate, ledgere expirate, nullifier-ele săptămânilor închise, înregistrările de chei expirate și intrările lor din ledger-ul depunerilor |
| `crates/node` | Serviciul gRPC `RelayService` (corpul fiecărui handler e `Relay::{store,get,check,list,redeem,register_key}_at(cerere, now)`, apelat cu ceasul serviciului și cu un ceas virtual de vectorii de conformitate), mod captură (T1), binarul `ghost-relay` (`serve`, `mint`) |

## Ce impune relay-ul

- Blob-ul are exact o dimensiune de bucket; hash-ul e recalculat și comparat; TTL-ul e exact una dintre treptele 3600, 86400, 604800, 2592000, 7776000 s (1 h, 1, 7, 30, 90 de zile; ADR-27, ADR-32), altfel `rejected_ttl`; `request_id` de 16 bytes; versiune de protocol 1 — orice abatere e respinsă cu un mesaj constant, fără ecou al intrării.
- Scriere doar cu capabilitate write pe namespace-ul respectiv, cu cotă, sau cu un credențial de depunere v3 înregistrat; citire cu capabilitate read sau write ori cu un credențial de citire sau de preluare v3 înregistrat; un blob din alt namespace este indistinct de unul inexistent.
- Loturile (`CheckBlobs`, `ListNamespace`, gossip) sunt limitate la 256.
- Gossip-ul e oprit implicit (`--gossip` îl pornește) până la autentificarea peer-ilor (Noise) din Faza 10. Inventarul de gossip răspunde după existența conținutului în orice namespace: un peer află dacă relay-ul deține un hash, nu și în ce namespace; de aceea gossip-ul rămâne oprit până peer-ii sunt autentificați.
- O bază de date scrisă de relay-ul din Faza 5 (schema v1) nu este migrată: relay-ul refuză să pornească, iar directorul de date trebuie golit (blob-urile sunt efemere și re-sincronizate de clienți).

## Răscumpărarea token-urilor (Faza 8, design §10, ADR-25)

- `serve` cu `--schedule <fișier> --slot <n> --onion-hostname-file <HiddenServiceDir/hostname>` (toate trei sau niciunul) pornește `RedeemToken`; fără ele RPC-ul răspunde `UNIMPLEMENTED`. Programul de Entitlement (ES) e verificat cu cheia fixată în build; onion-ul relay-ului, citit din fișierul `hostname` al Tor, trebuie să fie listat pentru slotul lui în săptămâna curentă; ES-ul trebuie să păstreze tot ce relay-ul a acceptat înainte (chei, revocări, `seq`). Altfel relay-ul refuză să pornească (cod 2).
- Un token e valid doar la relay-ul slotului lui, în săptămâna lui, în fereastra `[început − 24 h, sfârșit + 1 h)`. Ordinea verificărilor e cea din design §10.2; token-urile invalide sunt respinse înainte de orice scriere pe disc, iar cele falsificate, de alt tip sau de alt slot primesc același răspuns (`PERMISSION_DENIED`).
- Nullifier-ul e scris (fsync) în `nullifiers.redb` înainte de emiterea capabilității; o cerere identică repetată primește aceeași capabilitate v2, și după repornire; aceeași cerere pentru alt namespace primește `REPLAYED`.
- Sweep-ul (la 60 s) închise definitiv săptămânile a căror fereastră s-a terminat și le șterge nullifier-ele; o săptămână închisă rămâne refuzată și dacă ceasul e dat înapoi.
- Runbook O1: `nullifiers.redb` nu se restaurează niciodată dintr-un backup vechi. După pierderea lui, relay-ul pornește doar cu `--nullifiers-reset` și refuză singur (`UNAVAILABLE`) săptămânile deschise în momentul resetului. Un director de date din Fazele 5–7 (are `relay.key`, nu are `nullifiers.redb`) pornește cu răscumpărarea o singură dată cu `--nullifiers-init`. Fișierul `redemption.marker`, scris lângă primul store și niciodată șters, face ca `--nullifiers-init` să fie refuzat în orice director care a avut un store și ca un store pierdut să nu fie recreat gol.
- `relay.key` nu se înlocuiește niciodată în tăcere: se creează abia după ce toate verificările care nu citesc directorul de date au trecut (flag-uri, ES, onion listat), deci o primă pornire refuzată lasă directorul neatins; un fișier de altă lungime e refuzat; store-ul ține o valoare de control a cheii, iar o cheie nouă lângă un store păstrat e refuzată până la `--nullifiers-reset`.
- Rezidual declarat (decizia proprietarului): dacă se pierde tot directorul de date (inclusiv `relay.key` și `redemption.marker`), dar cheile onion ale Tor rămân, relay-ul nu îl poate deosebi de unul nou. Operatorul pornește atunci cu `--nullifiers-reset`; altfel token-urile răscumpărate deja în săptămânile deschise pot fi răscumpărate a doua oară la acest relay.
- Ledger-ul de cotă rămâne în memorie (o scriere peste cotă cel mult o dată per repornire, ADR-25). O excursie a ceasului înainte și înapoi nu îl resetează: o capabilitate expirată la cel mai mare moment al unui sweep nu mai e taxată. Găleata globală de răscumpărări (50/s, rafală 500) își reia rata imediat după un pas înapoi al ceasului.

## Înregistrarea cheilor (Faza 9, design §4, ADR-30)

- `RegisterKey(namespace, săptămână, tip ∈ {READ, DEPOSIT, FETCH}, verificator, capabilitate de scriere, request_id)` înregistrează `SHA-256(etichetă ‖ slot ‖ namespace ‖ secret)`; secretul nu ajunge la relay la înregistrare. Săptămâna trebuie să fie săptămâna capabilității sau următoarea (o capabilitate v2 e a săptămânii `week(expiry − 3601)`, una v1 a săptămânii curente), judecată după capabilitate, niciodată după ceasul relay-ului; altfel `WRONG_PERIOD` și nimic înregistrat. Capabilitățile falsificate, expirate, de alt namespace, de citire sau aflate în conflict primesc același răspuns (`PERMISSION_DENIED`).
- Înregistrările se acumulează și nu se înlocuiesc: o a doua capabilitate care înregistrează același verificator îi adaugă cota (cel mult patru capabilități per înregistrare); o capabilitate înregistrează cel mult un verificator per (namespace, săptămână, tip). O înregistrare trăiește până la `start(săptămână + 2) + 1 h`.
- Credențialul purtător v3 (67 bytes) e acceptat doar la relay-ul slotului lui (un relay fără `--slot` le refuză pe toate), doar pentru namespace-ul lui și doar cu o înregistrare vie a verificatorului pentru o săptămână din `[săptămâna curentă − 3, + 1]`. READ: `list`, `get`, `check`; DEPOSIT: `store`, `check`; FETCH: `list`, `get`. La `get`, READ și FETCH primesc `uploaded_at` rotunjit la începutul săptămânii ISO, iar FETCH și expirarea rotunjită în sus la granița săptămânii.
- Depunerile se taxează în ledger-ul depunerilor, pe înregistrarea vie cu cel mai devreme `valid_until` care mai are cotă; ledger-ul e în memorie (o înregistrare poate fi depășită cel mult o dată per repornire).
- `keys.redb` e stare refăcută de proprietari: lipsa lui nu refuză pornirea (se creează gol), `--nullifiers-reset` nu îl atinge, iar după pierderea lui depunerile sunt refuzate până când proprietarii înregistrează din nou (în prima lor sesiune). Un fișier cu altă schemă e refuzat la pornire; fiind stare refăcută, operatorul îl poate șterge. Sweep-ul (la 60 s) șterge înregistrările expirate și nu rulează sub minutul maxim persistat.

## Rulare locală

```bash
cd ghost
cargo run -p ghost-relay-node -- serve --data-dir /tmp/relay-a --listen 127.0.0.1:7443 --capture /tmp/relay-a.ndjson
cargo run -p ghost-relay-node -- mint --data-dir /tmp/relay-a --namespace <hex 32 bytes> --write --quota 1048576 --expiry <unix>
cargo test -p ghost-relay-node   # suita cu două noduri: abuz, failover, captură validată T1
cargo test -p ghost-relay-node --test semantics_vectors   # protocol/test-vectors/relay_semantics.txt (reluat și de ModelRelay din android/sync)
cargo test -p ghost-relay-node --test redeem_vectors      # protocol/test-vectors/redeem.txt (reluat și de ModelRedeemRelay, slice S9)
cargo test -p ghost-relay-node --test redeem              # negative, reporniri, concurență, mutanții MM13, MM14, MM18
cargo test -p ghost-relay-node --test register_vectors    # protocol/test-vectors/register.txt (Faza 9; ModelRelay îl reia în slice-ul S2)
cargo test -p ghost-relay-node --test register            # keys.redb creat la pornire, neatins de reset, schemă străină refuzată, concurență
cargo test -p ghost-relay-node --test cli                 # refuzurile de pornire ale flag-urilor de răscumpărare
```

Deploy ca onion service: `infra/relay/` (Dockerfile, torrc, compose cu trei relay-uri pentru staging).
