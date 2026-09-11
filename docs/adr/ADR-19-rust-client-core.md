# ADR-19 — Nucleu de client în Rust (rețea, protocol) expus Android-ului prin JNI

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-11 (proprietar proiect); aplicat în Faza 6, revizuit 2026-09-11 |
| Sursă | Faza 6 (client Tor + network) |
| Modifică | Spec v2.0 §6.1 (modulul `network` devine un wrapper Kotlin peste `client-core/net`) |

## Context
Tor pe Android înseamnă Arti (Rust) sau un daemon C separat. Padding-ul, izolarea circuitelor, clientul gRPC peste Tor și, mai târziu, bridge-ul OpenMLS sunt toate Rust. Duplicarea logicii de protocol în Kotlin ar dubla suprafața de audit și ar introduce divergențe între client și relay.

## Decizie
Un crate `ghost-client-net` (și, în fazele următoare, `ghost-client-mls`) conține logica de rețea/protocol și se compilează ca `cdylib` pentru `arm64-v8a` și `x86_64` cu `cargo-ndk`. Kotlin-ul din `android/network` este un wrapper subțire: validează tipurile (de ex. `OnionAddress` este verificat și în Kotlin, și în Rust), apelează JNI cu bytes/string/int, primește excepții cu categorii constante. Nicio logică de protocol în Kotlin, conform §6.1 („no protocol logic in UI”). Bibliotecile native se construiesc cu `scripts/build-native.sh` (cargo-ndk fixat la 4.1.2, `--locked`, căi de build remapate, verificare că binarul nu conține căi ale mașinii de build). CI le construiește de două ori în aceeași cale, de fiecare dată dintr-un director `target` gol, și eșuează dacă hash-urile diferă; APK-ul verificat de gate-ul T12 conține exact aceste biblioteci. Asta dovedește determinismul la aceeași cale, nu identitatea între medii: cargo include flag-urile de remapare (care numesc căile mașinii) în numele directoarelor de build-script, iar pe Windows separatorii rămân `\`. Un builder cu căi fixe (container) și generatorul de manifest care consumă `native-libs.sha256` vin în Faza 14.

## Consecințe
(+) un singur cod de protocol, auditat o dată, partajat cu relay-ul; Arti cu suport onion-service client și bridges; (−) toolchain suplimentar (NDK, cargo-ndk), APK mai mare (Arti ≈ 8–12 MB per ABI înainte de strip), depanare JNI mai grea. Regula de granță: prin JNI trec doar tipuri primitive și byte arrays; nicio excepție nu poartă adrese, hash-uri sau conținut.

## Completări după review-ul de securitate al Fazei 6 (2026-09-11)
- **Ciclul de viață al stării native:** registru de handle-uri indexat de un id opac (niciodată un pointer); fiecare apel ține o referință pe durata sa; `nativeStop` e idempotent și anulează apelurile în curs (`closed`); runtime-ul se oprește la ultima referință. Kotlin ține id-ul într-un `AtomicLong`.
- **Panici:** fiecare funcție JNI rulează sub `catch_unwind`; o panică devine excepția `internal`, nu abort de proces, iar un hook silențios ține mesajul departe de stderr. O panică în timpul altei panici sau lipsa memoriei opresc totuși procesul.
- **Deadline-uri:** 60 s pe fiecare RPC către relay, 180 s pentru bootstrap; bootstrap-ul poate fi anulat din alt fir.
- **Categorii de eroare:** listă unică în `net/src/categories.rs`, documentată în `client-core/README.md` și verificată de un test; `NetworkException` e păstrată de R8 prin `consumer-rules.pro`, cu fallback pe `IllegalStateException`.
- **ABI:** aplicația filtrează `arm64-v8a` și `x86_64`; alte dispozitive sunt refuzate la instalare, nu la prima utilizare.
- **Supply chain:** allowlist de pachete Rust pentru biblioteca clientului, pe ambele ABI (`client-core/rust-dependency-allowlist.txt`), și politică de feature-uri Arti (vanguards obligatoriu; relay, onion-service-service, keymgr experimental, pt-client, hs-pow-full interzise; `rsa` doar prin crate-uri Arti), ambele gate-uri CI cu self-test; `protoc` fixat pe versiune și hash.
- **Graniță clearnet în crate:** tonic e legat doar cu `codegen` (fără `Channel`/`Endpoint` și fără `connect()` generat), iar clippy `disallowed-methods`/`disallowed-types` (`client-core/net/clippy.toml`) interzice o listă de API-uri clearnet și DNS și orice conectare Arti în afara `connect_isolated`; fiecare interdicție e dovedită de un fixture negativ. Interdicția e pe API-uri numite, nu pe „orice clearnet”: acoperirea completă rămâne testul dinamic T6 (Faza 13). Clientul Arti rămâne privat (doctest `compile_fail`), iar conexiunile nu pornesc niciodată un bootstrap implicit (mod manual).
- **Erori:** crearea clientului Tor are categoria proprie `tor_setup` (director de stare, blocare, cache), separată de `bridge_config`; o conexiune eșuată către relay ajunge ca `transport`; după un bootstrap abandonat (termen depășit sau anulare) transportul refuză reîncercarea și trebuie recreat.
