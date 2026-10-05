# ADR-50 — Build reproductibil din două medii: rețeta cu căi fixe, setul de artefacte, simboluri și SBOM

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-10-05 de proprietar (propus 2026-10-03; designul aprobat cu valorile implicite) |
| Sursă | Plan §6.2 rândul 14 („hash identic din două medii”); FR-8.1; FR-8.9; ADR-07; ADR-19 (builder-ul cu căi fixe e lucrul Fazei 14); ADR-37 punctele 3, 8; ADR-38 punctele 5, 9; INVARIANTS T12; LIMITE L5 |
| Modifică | T12 (identitatea între medii devine executabilă); `ghost/Cargo.toml` (un profil nou `client-release` pentru bibliotecile clientului: informații de linie, separare și eliminare după legare, build-id; `[profile.release]` neschimbat; X-D15); `app/build.gradle.kts` (`vcsInfo` oprit, contorul de versiune comis; X-D14); `ci.yml` (JDK fixat la patch); G-L5 (numele de predare `ghost-release-diag`) |

## Context
T12 dovedește azi doar determinismul la aceeași cale: pe Windows căile păstrează `\`, iar cargo include flag-urile de remapare în numele directoarelor de build-script. `trim-paths` nu e stabil pe Rust 1.98.1. FR-8.9 cere două medii independente, unul al unui auditor; până la audit, poarta fazei folosește două medii ale furnizorului.

## Decizie
1. **O singură rețetă** (`ghost/infra/builder/Dockerfile` și `pins.txt`): imaginea de bază prin digest, pachetele apt dintr-un instantaneu `snapshot.debian.org`, Temurin 17 cu patch fixat, arhivele SDK-ului și NDK-ului Android și ale toolchain-ului Rust 1.98.1 descărcate direct și verificate prin SHA-256 (fără `sdkmanager` și `rustup`), cargo-ndk 4.1.2, protoc 36.1, Gradle 9.7.1, dependențele prin `Cargo.lock` și `verification-metadata.xml` (inclusiv aapt2, azi fără sumă); poarta G-D2 cere ca restul depozitului să fie de acord cu `pins.txt` și interzice `target-cpu=native`.
2. **Build-ul** rulează în container, dintr-un checkout git al unui tag semnat, cu sursele într-un tmpfs și directoarele de build pe disc, la căi fixe, cu numărul de procesoare văzut de unelte fixat la 2 (`-XX:ActiveProcessorCount`, `CARGO_BUILD_JOBS`, lucrătorii Gradle; nu `docker run --cpus`, pe care Docker îl refuză peste numărul real de procesoare), `TZ=UTC`, `LANG=C.UTF-8`, `umask 022`; fiecare binar se construiește într-o invocare `cargo` separată.
3. **Ieșirile** (`SHA256SUMS`): APK-ul nesemnat aliniat, bibliotecile native fără simboluri (cu build-id SHA-1) și fișierele lor de simboluri cu informații de linie, `ghost-relay`, `ghost-issuer`, `ghost-issuer-ops`, `ghost-release-ops`, `ghost-verify` pentru Linux și Windows cu sursa publică exportată, notificările, SBOM-urile CycloneDX 1.7 deterministe, rețeta; nicio ieșire nu conține date personale (G-D9).
4. **Două medii la fiecare versiune:** stația proprietarului (A) și un runner GitHub găzduit `ubuntu-24.04` (B), în bugetul de minute scris; sumele trebuie să fie egale înainte de semnare, iar suma lui B se confirmă pe un dispozitiv independent; jobul rulează și la schimbările rețetei și lunar. Mediul auditorului (C) e condiție de lansare.
5. **Semnarea păstrează nucleul:** `apksigner` din build-tools 37.0.0 cu `--alignment-preserved true`, v2 și v3, fără v1 și v4 (după o rotație: cheia originală și cea nouă în aceeași rulare); `apksigner` pune zerouri înaintea blocului de semnătură, ca acesta să înceapă la o limită de 4 096 de octeți (măsurat), iar regula nucleului le scoate exact; `ghost-release-ops apk-core` refuză orice versiune la care nucleul APK-ului semnat diferă de APK-ul nesemnat reprodus.
6. **Matricea de variații** (cale, procesoare, ordinea fișierelor, dată, utilizator; A față de B pentru procesor și kernel) rulează în S0a și apoi la schimbările rețetei; diferențele se clasifică cu diffoscope, doar în CI, pe ieșirile lui B păstrate în cache-ul rulării.

## Consecințe
(+) „Hash identic din două medii” devine o poartă reală; auditorul primește o rețetă exactă; simbolurile și SBOM-urile sunt reproductibile și legate de versiune; binarele operatorilor rămân fără simboluri. (−) Un build în container durează mai mult; runner-ul găzduit privat are 2 procesoare, 8 GB și 14 GB și 2 000 de minute pe lună; intrările fixate identice în ambele medii (SDK-ul Google, JDK-ul, toolchain-ul) nu sunt verificate de reproductibilitate (L10-D7); o diferență R8 neașteptată poate întârzia poarta (R-D1).

## Alternative respinse
Build nativ pe Windows; `trim-paths` (nestabil pe 1.98.1); Nix (cost de învățare, tot binare Google); Guix (fără SDK Android); doar o imagine precompilată (nereproductibilă ea însăși); runner-ul self-hosted ca al doilea mediu (același laptop și aceeași mașină virtuală WSL2); `apksigcopier` (arhivat, GPLv3+); SPDX 2.3 (cere marcă de timp); `docker run --cpus 4` (refuzat pe un runner cu 2 procesoare); schimbarea profilului `release` comun (ar livra operatorilor binare cu simboluri); un singur `cargo build` pentru toate binarele (unifică feature-urile).

## Teste
`release-build.yml` (A = B) pe tag-ul de închidere; matricea de variații; G-D2, G-D3, G-D8, G-D9; `reproducible` (aceeași cale) păstrat; V-D1 … V-D5, V-D9, V-D10, V-D15 … V-D18, V-D25.
