# ADR-19 — Nucleu de client în Rust (rețea, protocol) expus Android-ului prin JNI

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-10 — aplicat sub rezerva aprobării în Faza 6 |
| Sursă | Faza 6 (client Tor + network) |
| Modifică | Spec v2.0 §6.1 (modulul `network` devine un wrapper Kotlin peste `client-core/net`) |

## Context
Tor pe Android înseamnă Arti (Rust) sau un daemon C separat. Padding-ul, izolarea circuitelor, clientul gRPC peste Tor și, mai târziu, bridge-ul OpenMLS sunt toate Rust. Duplicarea logicii de protocol în Kotlin ar dubla suprafața de audit și ar introduce divergențe între client și relay.

## Decizie
Un crate `ghost-client-net` (și, în fazele următoare, `ghost-client-mls`) conține logica de rețea/protocol și se compilează ca `cdylib` pentru `arm64-v8a` și `x86_64` cu `cargo-ndk`. Kotlin-ul din `android/network` este un wrapper subțire: validează tipurile (de ex. `OnionAddress` este verificat și în Kotlin, și în Rust), apelează JNI cu bytes/string/int, primește excepții cu categorii constante. Nicio logică de protocol în Kotlin, conform §6.1 („no protocol logic in UI”). Bibliotecile native se construiesc reproductibil în CI și hash-urile lor intră în manifestul de release.

## Consecințe
(+) un singur cod de protocol, auditat o dată, partajat cu relay-ul; Arti cu suport onion-service client și bridges; (−) toolchain suplimentar (NDK, cargo-ndk), APK mai mare (Arti ≈ 8–12 MB per ABI înainte de strip), depanare JNI mai grea. Regula de granță: prin JNI trec doar tipuri primitive și byte arrays; nicio excepție nu poartă adrese, hash-uri sau conținut.
