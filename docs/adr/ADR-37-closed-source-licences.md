# ADR-37 — Distribuție cu sursă închisă și conformitatea licențelor terților; revizuiește ADR-07

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-16, aplicat în Faza 9 (distribuția cu sursă închisă e decizia proprietarului din 2026-09-16; textul ADR e în așteptarea deciziei proprietarului, Q4) |
| Sursă | R-license §0–§7, §10; design Faza 9 (`docs/design/faza9-dm.md`) §2.10, §22 |
| Înlocuiește | ADR-29 (retras); din ADR-07, clauza „Client, relay și issuer sunt open-source” și ținta „repo F-Droid” în sensul depozitului principal F-Droid |
| Modifică | FR-8.9, prima jumătate (plan:276); FR-8.10 (plan:277); plan:202; G12 (plan:125); G16 (plan:129); Anexa D (plan:460); `ghost/Cargo.toml:22` (licența crate-urilor); `ghost/deny.toml` (comentariul de la `:37-38`, interdicții nominale); `libs.versions.toml:18,39`; `dependency-allowlist.txt:12`; `dependency-denylist.txt`; CI (încărcări de artefacte) |

## Context
Proprietarul a decis ca clientul, relay-ul și issuer-ul să fie distribuite cu sursă închisă. Auditul licențelor arată că niciun binar livrat nu leagă cod GPL, LGPL sau AGPL; există două pachete MPL-2.0 aduse de Arti (`option-ext`, `priority-queue`) și sute de componente MIT, BSD, ISC, Unicode-3.0 și Apache-2.0 care cer notificări. APK-ul nu conține azi aceste notificări, iar CI a publicat binare fără ele. Politica depozitului principal F-Droid acceptă doar software liber; Accrescent acceptă aplicații proprietare.

## Decizie
1. Tot codul GHOST are licență proprietară: fișier `LICENSE` la rădăcină, `license-file` în Cargo, `[licenses.private] ignore = true` în `deny.toml`.
2. În niciun binar livrat nu intră componente GPL, AGPL sau LGPL legate, nici licențe „doar pentru evaluare”. MPL-2.0 e permis doar nemodificat, cu sursa exactă publicată pe canalele de distribuție și o notă în ecranul de licențe; nu se fac fork-uri ale crate-urilor MPL. Stiva DM (vodozemac, libcrux) nu adaugă MPL.
3. Notificările terților (Rust și Gradle, textul Apache-2.0, fișierele suplimentare, orice `NOTICE`, atribuirea SQLCipher) se generează automat pentru fiecare artefact livrat; ecranul „Licențe” (Faza 13) e obligatoriu înaintea primei distribuiri.
4. Porți noi, fiecare cu fixture negativ în `self-test.sh`: G-L1 (notificări regenerate identic), G-L2 (licențe Gradle pe coordonată), G-L3 (notificările în APK), G-L4 (sursele MPL), G-L5 (niciun binar încărcat public cât depozitul e public), G-R5 (scanarea antetelor de licență din sursele vendorizate: SPDX în afara listei, texte GPL/AGPL, copyright „Signal Messenger”).
5. Interdicții nominale în `deny.toml`, cu nume exacte (cargo-deny nu acceptă tipare): `libsignal-protocol`, `libsignal-core`, `libsignal-net`, `libsignal-service`, `libsignal-jni`, `libsignal-ffi`, `signal-crypto`, `zkgroup`, `spqr`, `spqr-syft`, `pq-ratchet`, `libsignal-dezire`, `wacore-libsignal`, `wa-rs-libsignal`; un test propriu așteaptă „bans FAILED”. `org.signal` trece din allowlist în denylist; pinul libsignal dispare din `libs.versions.toml`.
6. Imaginile de operator (issuer cu Monero, relay pe Debian) nu se distribuie; operatorii independenți (ADR-11) primesc doar binarul `ghost-relay` cu notificările lui. Dacă o imagine se distribuie totuși, se includ ofertele de sursă pentru pachetele GPL/LGPL.
7. Distribuție: mirror onion cu manifest semnat (canalul principal), Accrescent, opțional un depozit propriu în format F-Droid; actualizările prin magazine și prima instalare nu trec prin verificarea jurnalului de transparență a actualizatorului, reziduu declarat (Q71, §22.8.8). Depozitul principal F-Droid nu mai e o țintă. Build-ul reproductibil (T12), manifestul semnat și anti-rollback rămân din ADR-07; verificabilitatea fără sursă publică e ADR-38.
8. SBOM-ul fiecărei versiuni se publică împreună cu hash-ul notificărilor (FR-8.2).
9. Regula de proveniență: nicio componentă nu se implementează după surse AGPL; se folosesc doar specificații publice și articole.
10. Înaintea primei distribuiri comerciale: confirmarea juridică a efectului declarației `MIT OR Apache-2.0` publicate înainte de trecerea depozitului pe privat (cel puțin `b2df181` și artefactele CI de atunci; SHA-ul final și inventarul se consemnează la trecere) și a regulii despre imaginile de operator. Licența proprietară, `license-file` și `[licenses.private] ignore = true` se adoptă înaintea oricărei felii de cod a Fazei 9 (§22.8.9).

## Consecințe
(+) Distribuția închisă respectă licențele terților; capcanele de licență și derivele la actualizări sunt prinse automat. (−) Codul Rust publicat sub `MIT OR Apache-2.0` trebuie considerat reutilizabil de terți; utilizatorii pierd posibilitatea de a citi sursa (compensare în ADR-38, reziduu L7-D23); șase porți noi de întreținut; F-Droid principal exclus.

## Alternative respinse
Client AGPL (ADR-29, fără obiect după excluderea libsignal); sursă deschisă doar pentru nucleul de securitate (contrar deciziei; rămâne o opțiune de reevaluat după primul audit, Q61); ignorarea notificărilor pentru binarele „interne” (artefactele CI dintr-un depozit public sunt distribuire).

## Teste
G-L1 … G-L5 și G-R5 cu fixture-uri negative; testul `cargo deny check licenses` cu interdicțiile nominale; punctul 13 al listei de închidere a Fazei 9.

## Aplicare în S0′ (2026-09-16)
Consemnare completă: `docs/design/faza9-s0-hygiene.md`.
1. **Punctul 1:** `LICENSE` proprietar la rădăcină, `license = "LicenseRef-GHOST-Proprietary"` în `ghost/Cargo.toml` și `[licenses.private] ignore = true` în `ghost/deny.toml` există deja (acțiunea proprietarului din 2026-09-16). Designul numea `license-file`; identificatorul SPDX `LicenseRef-…` trimite la același fișier `LICENSE`.
2. **Punctul 3 (notificări):** `ghost/licenses/THIRD_PARTY_NOTICES-client-net.txt`, `-relay.txt`, `-issuer.txt` și `-android.txt`, generate de `ghost/scripts/gates/license-notices.sh`. APK-ul poartă `assets/THIRD_PARTY_NOTICES.txt` (preambulul cu mențiunea SQLCipher, partea Gradle, partea bibliotecii native cu oferta de sursă MPL-2.0 pentru `option-ext` 0.2.0 și `priority-queue` 2.7.0), construit de `app/build.gradle.kts`. Textele lipsă vin din SPDX License List 3.28.0 (copia din crate-ul `spdx` 0.13.4), fișierele NOTICE din amonte dintr-un instantaneu revizuit (`ghost/licenses/upstream/`). Ecranul „Licențe” rămâne în Faza 13.
3. **Punctul 4 (porți):** G-L1 `license-notices.sh`, G-L2 `gradle-license-allowlist.txt` (verificat de `license-notices.sh android`), G-L3 `apk-notices.sh`, G-L4 `mpl-sources.sh`, G-L5 `no-public-binaries.sh`, G-R5 `rust-license-headers.sh`, fiecare cu fixture-uri negative în `self-test.sh`.
4. **Punctul 5:** cele 14 interdicții nominale sunt în `ghost/deny.toml`, cu testul care așteaptă „bans FAILED” pentru fiecare nume; `org.signal` a ieșit din `libs.versions.toml` și din allowlist și a intrat în denylist.
5. **Rămân:** confirmarea juridică (punctul 10), SBOM-ul per versiune (punctul 8) și ecranul de licențe (punctul 3) înaintea primei distribuiri.
