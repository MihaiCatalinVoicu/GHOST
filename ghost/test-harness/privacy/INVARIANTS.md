# Invarianți de confidențialitate (T1–T18)

Fiecare invariant are: ce afirmă, cum se verifică, când devine executabil, și unde trăiește codul. Un invariant fără test executabil nu poate susține o afirmație în UI (CP-10).

| ID | Invariant | Verificare | Executabil din | Cod |
|---|---|---|---|---|
| T1 | Un relay observă doar câmpurile din `allowed-observables.json`; niciodată IP, identitate, plaintext, dimensiune nepadată, timp sub minut | relay-ul în mod captură scrie NDJSON; `capture-check` validează fiecare linie | **Faza 2** (validator + fixture-uri); **Faza 5** (captură reală din suita cu două noduri, `relay/crates/node/tests`) | `capture-check/` |
| T2 | Jurnalul issuer-ului și nullifier-ele relay-urilor nu au nicio cheie de join | test de integrare: se rulează N plăți sintetice, se exportă ambele jurnale, se caută orice valoare comună sau corelare peste prag statistic | Faza 8 | `issuer/` tests |
| T3 | Secretele-canar nu apar în log/telemetrie/crash | se injectează șiruri unice (seed, chei, capabilități, ID-uri) și se grep-uiește tot ce iese din proces | Faza 3 | `android/` instrumentation |
| T4 | Backup/device-transfer nu conțin seed, cheie DB, stare protocol, cache decriptat | `bmgr`/`adb backup` pe emulator, inspecție arhivă | Faza 4 | `android/` instrumentation |
| T5 | Media criptată nu mai conține EXIF/XMP/GPS/atomi de locație | fișiere cu metadate cunoscute → decriptare → parser de metadate returnează gol | Faza 11 | `android/media` tests |
| T6 | Fără Tor: zero conexiuni clearnet și zero interogări DNS | în `client-core/net` din Faza 6: singura destinație publică e `OnionAddress` (checksum v3; vectori partajați Rust + Kotlin), clientul Arti nu e expus (doctest `compile_fail`), tonic e legat doar cu `codegen` (fără `Channel`/`Endpoint`, verificat de `rust-feature-policy.sh`), iar în crate clippy interzice o listă de API-uri clearnet și DNS (socket-uri std/tokio, rezolvatoare, conectorul HTTP hyper-util, TCP/UDP brut al runtime-ului) și orice apel de conectare Arti în afara `connect_isolated`; un fixture negativ dovedește că fiecare interdicție se declanșează. **Nu acoperă** un API care nu e pe listă, alt crate sau cod Kotlin care ar deschide socket-uri cu pachete deja permise (allowlist-ul și `deny.toml` țin afară doar pachete nerevizuite); acoperirea completă vine de la testul dinamic: emulator cu Tor blocat + captură `tcpdump`, 0 pachete non-Tor | **Faza 6** (API + gate-uri); Faza 13 (emulator) | `client-core/net`, `android/network` tests, `scripts/gates/rust-client-allowlist.sh` |
| T7 | Orice dependență în afara allowlist-ului oprește build-ul | Gradle: `dependency-allowlist.sh` + fixture negativ (Faza 1); Rust (biblioteca nativă, ambele ABI): `rust-client-allowlist.sh` + self-test (Faza 6); potrivire după nume de pachet | **Faza 1**, extins în Faza 6 | `scripts/gates/` |
| T8 | Niciun placeholder pe calea de producție | `anti-placeholder.sh` + fixture negativ | **Faza 1** | `scripts/gates/` |
| T9 | Pe fir și în stocare apar doar dimensiuni din {1,4,16,64} KiB, cu octeți indistinctibili de aleator | relay-ul refuză orice altă dimensiune (T1, `size_bucket`); clientul refuză să trimită blob-uri care nu sunt bucket (`not_bucket_sized`); padding-ul se aplică în plaintext-ul AEAD (`pad_plaintext`), deci fără prefix de lungime în clar; captură rețea | Faza 5/6 (dimensiuni); Faza 9/10 (criptare + padding în AEAD) | `capture-check/`, `relay/crates/transport`, `client-core/net` tests |
| T10 | Ecranele sensibile au FLAG_SECURE; nimic în recents | test UI: screenshot returnează negru | Faza 13 | `android/app` UI tests |
| T11 | Notificările cu dispozitiv blocat nu conțin text/expeditor | test UI pe notificare | Faza 13 | `android/app` UI tests |
| T12 | Două build-uri release au hash identic | `reproducible-build.sh` (APK) + `apk-native-libs.sh` (APK-ul conține exact bibliotecile native înregistrate, pe ambele ABI; self-test pe arhive fabricate); bibliotecile native: două build-uri în aceeași cale, identice (CI). Identitatea între medii diferite (alt host, Windows) nu e încă dovedită: builder cu căi fixe în Faza 14 | **Faza 1**, extins în Faza 6 | `scripts/gates/` |
| T13 | Timestamps de autor au secunde = 0 | test unitar pe envelope | Faza 10 | `android/messaging` tests |
| T14 | Pseudonimele aceluiași utilizator în două canale nu sunt egale și nu sunt derivabile fără seed | vectori de derivare | Faza 3 | `android/identity` tests |
| T15 | Manifestele rămân întărite (allowBackup=false etc.) | `manifest-lint.sh` + fixture negativ | **Faza 1** | `scripts/gates/` |
| T16 | Invitația nu conține host web, cheie de identitate în clar, și nu e rejucabilă | teste parser + redeem | Faza 3/8 | `android/identity`, `issuer/` |
| T17 | Traficul în idle e statistic indistinct de traficul activ (polling constant) | captură rețea pe două sesiuni; test KS pe distribuția intervalelor și dimensiunilor | Faza 7/12 | harness rețea |
| T18 | Cu bridges active, captura nu conține fingerprint Tor cunoscut | captură + set de semnături | Faza 12 | harness rețea |

## Formatul capturii de relay (T1)

O linie JSON per eveniment observabil. Câmpuri permise și forme: `allowed-observables.json`. Exemple: `fixtures/capture-ok.ndjson` (trece), `fixtures/capture-bad.ndjson` (fiecare linie încalcă altă regulă). Rulare:

```bash
cd ghost
cargo run -p ghost-capture-check -- --schema test-harness/privacy/allowed-observables.json --capture test-harness/privacy/fixtures/capture-ok.ndjson
```

Regula de evoluție: adăugarea unui câmp în schema permisă este o **decizie de confidențialitate** și cere un ADR sau o modificare a threat model-ului §6, nu doar un PR.
