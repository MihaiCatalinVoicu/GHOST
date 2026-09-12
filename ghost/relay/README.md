# relay/ — GHOST blind relay (Rust)

Un relay păstrează și servește blob-uri opace, adresate prin conținut, fără să afle cine le-a scris sau citit (CP-06, FR-5.x). Tot ce poate observa este enumerat normativ în `test-harness/privacy/allowed-observables.json` și verificat pe fiecare PR (T1).

| Crate | Rol |
|---|---|
| `crates/api` | Tipuri de wire generate din `protocol/relay/v1/relay.proto` + constante (bucket-uri, TTL, limite) + formatele publice ale capabilității (`capability_header`, `capability_format`): v1 (82 bytes, emisă din CLI) și v2 (98 bytes, cu serial, emisă de `RedeemToken`), definite o singură dată și folosite de relay și de client |
| `crates/storage` | Blob store pe redb (ADR-18, schema v2): conținut stocat o dată per hash (refcount), apartenență (namespace, hash) cu expirare proprie, cursor per namespace (șters odată cu ultimul blob al namespace-ului), index pe expirare, expirări rotunjite la oră; cota se taxează în tranzacția de scriere; o bază cu altă versiune de schemă e refuzată. Separat, `nullifiers.redb` (schema 1, ADR-25): nullifier-e per săptămână cu etichetă de legare, memoria ES (chei, revocări, seq), pragul perioadelor închise, pragul de refuz după reset și minutul maxim al sweep-ului |
| `crates/capability` | Capabilități HMAC locale relay-ului (read/write pe namespace, cotă, expirare; v1 și v2 cu serial), eticheta de legare și serialul determinist ale unei răscumpărări, ledger de cotă (în memorie) |
| `crates/transport` | Framing de padding pentru plaintext-ul AEAD (`pad_plaintext`): după criptare blob-ul are exact o dimensiune de bucket (1/4/16/64 KiB) și niciun prefix de lungime în clar |
| `crates/gossip` | Reconciliere de inventar între relay-uri (doar hash-uri) |
| `crates/prune` | Sweep determinist: blob-uri expirate, ledgere expirate, nullifier-ele săptămânilor închise |
| `crates/node` | Serviciul gRPC `RelayService` (corpul fiecărui handler e `Relay::{store,get,check,list,redeem}_at(cerere, now)`, apelat cu ceasul serviciului și cu un ceas virtual de vectorii de conformitate), mod captură (T1), binarul `ghost-relay` (`serve`, `mint`) |

## Ce impune relay-ul

- Blob-ul are exact o dimensiune de bucket; hash-ul e recalculat și comparat; TTL în 1 s … 90 zile; `request_id` de 16 bytes; versiune de protocol 1 — orice abatere e respinsă cu un mesaj constant, fără ecou al intrării.
- Scriere doar cu capabilitate write pe namespace-ul respectiv, cu cotă; citire cu capabilitate read; un blob din alt namespace este indistinct de unul inexistent.
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

## Rulare locală

```bash
cd ghost
cargo run -p ghost-relay-node -- serve --data-dir /tmp/relay-a --listen 127.0.0.1:7443 --capture /tmp/relay-a.ndjson
cargo run -p ghost-relay-node -- mint --data-dir /tmp/relay-a --namespace <hex 32 bytes> --write --quota 1048576 --expiry <unix>
cargo test -p ghost-relay-node   # suita cu două noduri: abuz, failover, captură validată T1
cargo test -p ghost-relay-node --test semantics_vectors   # protocol/test-vectors/relay_semantics.txt; modelul Kotlin (pasul S3) îl va relua și el
cargo test -p ghost-relay-node --test redeem_vectors      # protocol/test-vectors/redeem.txt (reluat și de ModelRedeemRelay, slice S9)
cargo test -p ghost-relay-node --test redeem              # negative, reporniri, concurență, mutanții MM13, MM14, MM18
cargo test -p ghost-relay-node --test cli                 # refuzurile de pornire ale flag-urilor de răscumpărare
```

Deploy ca onion service: `infra/relay/` (Dockerfile, torrc, compose cu trei relay-uri pentru staging).
