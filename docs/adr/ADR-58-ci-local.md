# ADR-58 — CI-ul rulează local, nu prin GitHub Actions

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-10-04 de proprietar („orice CI să ruleze local, nu prin GitHub Actions”; regulă oficială și permanentă până o schimbă proprietarul) |
| Sursă | decizia proprietarului din 2026-10-04; experiența Fazelor 9–11 (verificarea locală a fost semnalul real de îmbinare; CI-ul consultativ a fost în fiecare zi saturat sau blocat de cota de artefacte și de laptopul proprietarului) |
| Modifică | `docs/ci-self-hosted.md` (devine istoric), `.github/workflows/*.yml` (legacy, de migrat și de șters), jobul `workflow-yaml` din `run-all.sh` (de retras la ștergerea fișierelor), toate referințele din designurile Fazelor 9–14 la „workflow”, „job CI”, „runner” (se citesc ca „script local cu același conținut”) |

## Context
Din 2026-09-16 CI-ul rula pe patru runnere GitHub Actions self-hosted într-o distribuție WSL2 de pe laptopul proprietarului (`docs/ci-self-hosted.md`). În practică: runnerele erau saturate în zilele de lucru (V10-14), cota de artefacte a blocat jobul `android` din 2026-09-20, nightly-urile porneau abia dimineața, iar CI-ul era declarat consultativ (planul GitHub Free nu are protecția ramurilor pentru un depozit privat). Semnalul de îmbinare a fost, de fapt, verificarea locală completă pe commit-ul exact, iar GitHub Actions a adăugat costuri (încărcarea laptopului, cozi, artefacte) fără un semnal în plus.

## Decizie
1. **Tot CI-ul rulează local**, pe mașina proprietarului. Nimic nu rulează prin GitHub Actions: nici hosted, nici self-hosted. Un push pe GitHub e doar copie de siguranță și partajare, nu o verificare, și nimic nu depinde de o rulare de la distanță.
2. **Un gate, o verificare, un nightly, o poartă de ieșire, un job de fuzzing sau de modele = un script local** (`ghost/scripts/gates/*.sh` pentru porțile statice, `ghost/scripts/ci/*.sh` pentru joburile lungi), cu fixturi negative și cazuri în `self-test.sh`. Nu se mai creează fișiere `.yml`.
3. **Semnalul de îmbinare este rețeta de verificare locală**, rulată pe commit-ul exact și consemnată cu hash-ul și cifrele ei (STATUS sau notele slice-ului): `cargo fmt/clippy/test` (și `cargo deny` când se schimbă dependențe), build Gradle curat cu biblioteca gazdă (`-Dghost.dm.native`) cu sume JUnit `skipped=0`, `dm-report-check.sh` pe rapoartele `pr` și `privacy-pr`, `run-all.sh`, tot `self-test.sh` în WSL pe un `git archive`. Detaliile și comenzile: `docs/CI_LOCAL.md` și `CLAUDE.md`.
4. **Joburile lungi** (lumile de confidențialitate la scara porții, fuzzing, modelele de stări, suitele de emulator, porțile de ieșire) rulează la cerere sau după o programare aprobată de proprietar, tot ca scripturi locale; rapoartele lor se verifică cu scripturile `*-report-check.sh` corespunzătoare.
5. **Workflow-urile existente și runnerele sunt legacy**: nu se extind, nu se bazează nimeni pe ele; conținutul lor se migrează în scripturi locale (felia CI-L, `docs/CI_LOCAL.md` §4), apoi fișierele se șterg (rămân în istoricul git). Dezactivarea Actions la nivelul depozitului, oprirea serviciilor runner și scoaterea task-ului programat `GHOST ghost-runner keepalive` sunt acțiuni ale proprietarului sau cer acordul lui explicit.

## Consecințe
(+) Un singur loc de adevăr (scripturile din depozit), rulate exact pe commit; fără cozi, fără cotă de artefacte, fără laptop saturat de joburi de fundal; evidența fiecărei rulări e consemnată cu commit-ul. (−) Fără semnal automat la fiecare push: disciplina verificării locale cade pe lead și pe proprietar; joburile nocturne nu mai pornesc singure până nu se aprobă o programare locală (Task Scheduler) — până atunci se rulează la cerere; porțile de ieșire cer ore de mașină locală (T32 la scara porții ~2 h per pereche) și nu pot rula în paralel cu build-uri grele fără încetinire.

**Reziduu:** o rulare locală nu e reproductibilă de un terț; pentru auditul extern (Faza 15) se păstrează scripturile, versiunile uneltelor și rapoartele rulărilor, iar construcția reproductibilă din trei medii (Faza 14) rămâne un script local rulat pe trei mașini sau medii.
