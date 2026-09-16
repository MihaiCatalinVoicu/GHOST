# ADR-39 — Depozitul devine privat; artefactele CI; istoricul deja public

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-16, aplicat în Faza 9 (în așteptarea deciziei proprietarului, Q4; acțiuni ale proprietarului) |
| Sursă | R-license §7.4; design Faza 9 (`docs/design/faza9-dm.md`) §2.10.5, §22 |
| Modifică | `.github/workflows/ci.yml` (încărcările APK și `.so`), setările depozitului, identitatea commit-urilor viitoare |

## Context
Depozitul e public din 2026-09-10: istoricul până la `f273dcd`, codul fazelor 0–8, toate design-urile (inclusiv cel cu libsignal), modelul de amenințări, runbook-urile, adresele onion ale releelor de staging, metadatele commit-urilor și artefactele CI (299 la 2026-09-16, printre care APK-uri și biblioteci native fără notificări de licență, inclusiv pentru `b2df181`).

## Decizie
1. Tot ce a fost publicat înainte de trecerea pe privat (cel puțin `b2df181`; SHA-ul final și inventarul artefactelor se consemnează la trecere) se consideră public pentru totdeauna; securitatea nu depinde de secretul lui (CP-09). Istoricul nu se rescrie.
2. Proprietarul șterge imediat artefactele binare publice și oprește încărcările de APK, AAR și `.so` (G-L5 le blochează cât depozitul e public), apoi trece depozitul pe privat și adoptă licența proprietară, înainte de orice felie de cod a Fazei 9, inclusiv S1–S3 (§22.8.9).
3. CI se adaptează depozitelor private (runnere standard Linux de 2 CPU și 8 GB; GitHub Free: 2 000 de minute și 500 MB de artefacte, blocate la epuizare fără metodă de plată): porțile de ieșire, lumea de confidențialitate și emulatorul rulează nocturn pe `main` și la cerere; pragurile sensibile la timp și numărul de shard-uri se recalculează în S0′; fiecare încărcare are `retention-days`; un runner self-hosted e permis doar pentru depozitul privat.
4. Commit-urile viitoare folosesc adresa no-reply și, pentru orice material public, o identitate de proiect separată de contul personal.
5. Cheile onion ale releelor de staging se rotesc dacă releele sunt folosite dincolo de staging.
6. Materialul public (ADR-38 punctul 7) se publică dintr-un depozit nou.

## Consecințe
(+) Nicio expunere nouă; binarele nu mai circulă fără notificări. (−) Ce s-a publicat nu poate fi retras; costul CI se recalculează în S0′ (estimarea de aproximativ 200 USD pe lună folosea runnere publice de 4 CPU); runnere private mai lente.

## Consemnare la trecerea pe privat (2026-09-16)
Detalii: `docs/design/faza9-s0-hygiene.md`.
1. **Ultimul SHA public:** `3edf9dd0b2b20d7e4061b5028801d455f0268648` („Phase 9 design revised: no libsignal, closed source”), ultimul push cât depozitul era public; istoricul public cuprinde cele 118 commit-uri accesibile din el, inclusiv `b2df181` și tot ce e mai vechi. API-ul GitHub arată depozitul `private` la 2026-09-16T18:13Z.
2. **Inventarul artefactelor** (2026-09-16T18:13Z): 348 de artefacte, niciunul expirat, create între 2026-09-10T08:58:23Z și 2026-09-16T17:57:56Z. Din rulările commit-urilor publice: 331 (2026-09-10T08:58:23Z … 2026-09-16T15:12:39Z), printre ele 37 `app-release-unsigned` (APK-uri) și 33 `ghost-client-net-jniLibs` (biblioteci native), păstrate până la 2026-12-15. **Ștergerea lor e acțiunea proprietarului (punctul 2) și nu s-a făcut încă.**
3. **Încărcările CI:** APK-ul nu se mai încarcă; singurul artefact binar este predarea internă `ghost-client-net-jniLibs`, cu `retention-days: 1`; dovezile porților (rapoarte text) rămân 3 zile. Poarta G-L5 (`no-public-binaries.sh`) le impune și compară vizibilitatea declarată (`ghost/scripts/gates/repository-visibility.txt`) cu evenimentul GitHub.
4. **Runnere:** CI rulează pe runnere self-hosted (`docs/ci-self-hosted.md`), permise doar cât depozitul e privat (punctul 3).
