# relay/ — GHOST blind relay (Rust)

Un relay păstrează și servește blob-uri opace, adresate prin conținut, fără să afle cine le-a scris sau citit (CP-06, FR-5.x). Tot ce poate observa este enumerat normativ în `test-harness/privacy/allowed-observables.json` și verificat pe fiecare PR (T1).

| Crate | Rol |
|---|---|
| `crates/api` | Tipuri de wire generate din `protocol/relay/v1/relay.proto` + constante (bucket-uri, TTL, limite) |
| `crates/storage` | Blob store pe redb (ADR-18): hash → date, index pe namespace cu cursor opac, index pe expirare |
| `crates/capability` | Capabilități HMAC locale relay-ului (read/write pe namespace, cotă, expirare), ledger de cotă, nullifier-e pe perioadă |
| `crates/transport` | Framing cu padding pe bucket-uri (1/4/16/64 KiB) |
| `crates/gossip` | Reconciliere de inventar între relay-uri (doar hash-uri) |
| `crates/prune` | Sweep determinist: blob-uri expirate, ledgere expirate, perioade vechi de nullifier-e |
| `crates/node` | Serviciul gRPC `RelayService`, mod captură (T1), binarul `ghost-relay` (`serve`, `mint`) |

## Ce impune relay-ul

- Blob-ul are exact o dimensiune de bucket; hash-ul e recalculat și comparat; TTL în 1 s … 90 zile; `request_id` de 16 bytes; versiune de protocol 1 — orice abatere e respinsă cu un mesaj constant, fără ecou al intrării.
- Scriere doar cu capabilitate write pe namespace-ul respectiv, cu cotă; citire cu capabilitate read; un blob din alt namespace este indistinct de unul inexistent.
- Loturile (`CheckBlobs`, `ListNamespace`, gossip) sunt limitate la 256.
- Gossip-ul e oprit implicit (`--gossip` îl pornește) până la autentificarea peer-ilor (Noise) din Faza 10.

## Rulare locală

```bash
cd ghost
cargo run -p ghost-relay-node -- serve --data-dir /tmp/relay-a --listen 127.0.0.1:7443 --capture /tmp/relay-a.ndjson
cargo run -p ghost-relay-node -- mint --data-dir /tmp/relay-a --namespace <hex 32 bytes> --write --quota 1048576 --expiry <unix>
cargo test -p ghost-relay-node   # suita cu două noduri: abuz, failover, captură validată T1
```

Deploy ca onion service: `infra/relay/` (Dockerfile, torrc, compose cu trei relay-uri pentru staging).
