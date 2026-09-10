# client-core/ — nucleul de client în Rust (ADR-19)

Logica de rețea și, în fazele următoare, de protocol a clientului Android trăiește în Rust și este expusă modulelor Kotlin prin JNI. Kotlin-ul validează tipuri și afișează; nu implementează protocol (spec §6.1).

| Crate | Rol | Modul Android |
|---|---|---|
| `net` | Tor embedded (Arti) cu onion-service client și bridges; `OnionAddress` strict; izolare de circuite per namespace/scop; client gRPC relay prin Tor cu padding și verificare de hash; JNI `org.ghost.network.TorRelayTransport` | `android/network` |

## Build

```bash
cd ghost
cargo test -p ghost-client-net                                     # teste unitare (fără rețea)
cargo test -p ghost-client-net --test live_tor -- --ignored        # bootstrap Tor real + stream onion (rețea)
# biblioteci native pentru Android (necesită NDK și cargo-ndk):
cargo ndk -t arm64-v8a -t x86_64 -o android/network/src/main/jniLibs build --release -p ghost-client-net
```

`jniLibs/` nu se comite: bibliotecile se construiesc în CI (job `android-native`), iar hash-urile lor intră în manifestul de release (ADR-07).

## Regula de graniță JNI

Prin JNI trec doar `String`, `ByteArray`, `Int`, `Long`. Erorile ajung în Kotlin ca `NetworkException` cu o categorie constantă (`not_onion`, `unauthorized`, `quota`, `not_found`, `rejected`, `relay_unavailable`, `tor_bootstrap`, `payload_too_large`, `malformed_response`), niciodată cu adrese, hash-uri sau conținut.
