# ADR-17 — Ed25519 și primitive de identitate prin BouncyCastle (bcprov-jdk18on)

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | Faza 3 (identitate) |
| Modifică | Allowlist dependențe (ADR-06): adaugă `org.bouncycastle` |

## Context
Identitatea GHOST este Ed25519 (RFC 8032) derivată determinist din seed (spec §7.1, FR-1.3). Platforma Android nu garantează Ed25519 în `java.security` pe minSdk 29 și nu oferă construcție deterministă din seed prin API public. libsignal expune XEdDSA pe Curve25519, nu Ed25519 standard.

## Decizie
Modulul `identity` folosește API-ul lightweight BouncyCastle (`org.bouncycastle.crypto.*`, nu provider-ul JCA) pentru: Ed25519 din seed de 32 bytes, semnare, verificare. HKDF-SHA256 și SHA-256 rămân pe `javax.crypto`/`java.security` (platformă), cu vectori RFC 5869 în teste. Versiune pinuită în catalog; checksum în `verification-metadata.xml`.

## Alternative respinse
- Ed25519 din JCA al platformei: indisponibil garantat sub API 33.
- libsignal XEdDSA ca identitate: schimbă specificația (RFC 8032) și formatul `ghost1…`.
- Tink: dependență Google mai mare, fără avantaj aici.

## Consecințe
(+) determinism și interoperabilitate RFC 8032; (−) +~6 MB în APK înainte de minificare (R8 păstrează doar clasele folosite); dependența intră în audit (Faza 15).
