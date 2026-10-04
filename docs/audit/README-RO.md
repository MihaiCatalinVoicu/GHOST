# Pachetul pentru auditul extern (Faza 15): notă pentru proprietar

**Data:** 2026-10-03, revizuit 2026-10-04 după două review-uri adversariale · **Commit de bază:** `a0f3f58` (`main`, încă nepus pe `origin/main`) · **Autor:** agent AI, pentru proprietar · Documentele din `docs/audit/` sunt în engleză (pentru auditori); aceasta e singura notă în română și **nu se trimite nimănui**.

## Pe scurt

1. Pachetul îți dă ce îți trebuie ca să **bugetezi și să programezi** auditul: ce conține GHOST (mărime măsurată), ce se auditează, ce dovezi există, ce e deschis și cum ceri oferte. **Nu spune că sistemul e gata de audit.**
2. Auditul final cere Fazele 9–14 închise sau explicit abandonate; azi **nu sunt**. Ordin de mărime: **58–78 / 31–67 / 62–131 persoană-săptămâni** (S0 / S1 / S2), adică **cel puțin** 0,2–0,8 milioane USD (limită inferioară, probabil mai mult).
3. Firmelor le trimiți **doar** `AUDITOR_RFQ.md` (după ce ștergi blocul „Owner” de la început); restul pachetului, **numai după NDA**. `README-RO.md` și `OWNER_ONLY_MARKET_AND_BUDGET.md` nu se atașează niciodată.

## Ce este pachetul

| Fișier | Pentru ce | Se trimite? |
|---|---|---|
| `README.md` | Indexul pachetului în engleză (ordinea de citire pentru prima zi) | doar după NDA |
| `AUDITOR_RFQ.md` | Cererea de ofertă, autonomă (poate pleca înainte de NDA; nu conține sursă, slăbiciuni nerezolvate sau buget) | da, cu invitația |
| `AUDIT_SCOPE.md` | Componentele (cale, limbaj, mărime măsurată), active și secrete, puncte de intrare, fluxuri de date, ce intră și ce nu în audit, **lista de priorități după risc**, inventarul criptografic cu versiuni exacte, ipoteze, registrul afirmațiilor (CP, T1–T35, garanțiile fazelor), ce **nu** afirmă proiectul | doar după NDA |
| `EVIDENCE_INDEX.md` | Ce s-a verificat deja și cum se reproduce; porți, mutanți, modele ProVerif, fuzzing, revizuiri; lista **a ce nu a rulat** | doar după NDA |
| `KNOWN_ISSUES.md` | Constatări deschise, decizii ale proprietarului, reziduuri declarate, ipoteze neverificate | doar după NDA |
| `BUILD_AND_REVIEW_GUIDE.md` | Cum primește auditorul sursa (privată), cum construiește, comenzile de test, ordinea de citire, indexul componentă → specificație | doar după NDA |
| `ci-runs.tsv`, `ci-log-facts.tsv` | Copii statice ale rezultatelor CI citate (jurnalele GitHub expiră în 90 de zile, iar auditorul n-are cont) | doar după NDA |
| `tools/measure.sh`, `tools/check-package.sh` | Măsurătoarea mărimilor (anexa A din `AUDIT_SCOPE.md`) și verificarea că numerele din pachet mai corespund arborelui | doar după NDA |
| `OWNER_ONLY_MARKET_AND_BUDGET.md` | **Doar pentru tine:** tabelul de firme cu rapoarte publice, metoda de buget, deciziile tale | **niciodată** |

## Starea reală (nu e „gata de audit”)

Auditul final cere Fazele 9–14 închise. La commit-ul de bază:

* **Faza 9:** din cele 16 puncte ale porții (design §17.2) sunt deschise 5, 6, 7, 8, 9, 10, 11, 12, 14 și 16 (punctul 15 trebuie reverificat): suitele KC, RO, CB, RE, OS, RK nu sunt construite, mutanți rulați 26/57 (corectitudine) și 15/40 (confidențialitate), T2 roșu pe perechile 2, 3, 9, nicio rulare pe emulator în CI, nicio verificare pe dispozitive, 8 decizii ale review-ului la tine.
* **Faza 10** (OpenMLS) nu e în `main`, doar pe ramuri nemerguite; **Fazele 11, 13, 14** sunt doar design propus, **Faza 12** neînceput; **nu există UI**.
* **CI** (citit 2026-10-03 și 2026-10-04): `ci` are totul verde în afară de un caz din `self-test`, care pică doar pe checkout-ul superficial al jobului `static gates`; l-a reparat `a0f3f58`, care **nu e pe `origin/main` și n-a rulat niciodată în CI** (reparația a fost verificată separat, pe un clone complet și unul superficial).
* **`dm-fuzz` pică în fiecare noapte** pe ținta `bundle`. Diagnosticul e **reprodus din arbore**: proprietate veche în ținta de fuzzing după repararea CRY-P9-01, nu defect al criptografiei; corecția e o linie în țintă (neaplicată, pachetul descrie `a0f3f58`).
* **T32 la scară de poartă pică** din 28.09 pe toate cele 10 perechi: JD5 pe 10, JD6 pe 7, JD7 pe 1 (suita cu twin-uri, T34 și mutanți e verde); a trecut o singură dată, pe 27.09. **T2** pică pe perechile 2, 3 și 9. Emulatorul n-a rulat niciodată pe runner (fără KVM).
* Nocturnele din 03.10 ale `messaging-exit-gate`, `entitlement-exit-gate` și `dm-privacy-gate` au fost **anulate** (cauza nu e înregistrată).

## Ce ai de făcut, în ordine

1. **Alege tier-urile** (A criptografie și protocoale, B client Android, C relay și issuer, D lanț de aprovizionare; opțiuni: MLS, UI, distribuție) și **scenariul** (S0 baseline, S1 focalizat, S2 tot planul).
2. **Trimite `AUDITOR_RFQ.md`** la 3–5 firme din tabelul din `OWNER_ONLY_MARKET_AND_BUDGET.md`. **NDA înainte de ofertare** (B0 din cerere): după ce o firmă semnează, îi dai pachetul (cele patru documente, cele două `.tsv`, `tools/`). Recomandare **(dedusă)**: o firmă de criptografie pentru A, o firmă de securitate de aplicații pentru B–D, sau două oferte paralele.
3. **Fixează data de înghețare** a codului (tag `audit-rc1`) și data de start: contractul trebuie semnat cu **cel puțin 4 săptămâni înainte** de start.
4. **NDA și licență de utilizare limitată** (fișierul `LICENSE` nu dă niciun drept). **Nu adăuga auditori ca „collaborators” pe GitHub:** pe un depozit personal primesc drept de scriere, iar CI-ul rulează pe laptopul tău; sursa se dă printr-un `git bundle` cu hash comunicat separat (ghidul, §1.2; secvența pentru auditor a fost corectată și testată).

## Ce mai datorează proiectul înainte de audit

* **a)** Închiderea sau **renunțarea explicită** la porțile Fazelor 9–14 și merge-ul Fazei 10.
* **b)** Deciziile din `KNOWN_ISSUES.md` §2 și §4 (MD-1, MD-4–7, CRY-P9-03, A-2, GATES-5, G-DM3, TIMER_SET, T2 perechile 2/3/9, ADR-22…26) și corectarea proprietății țintei `bundle` din `dm-fuzz`.
* **c)** Rulări la scară de poartă care trec: T2 (3 perechi), T32 (JD5, JD6, JD7), `dm-fuzz`, `dm-emulator` cu KVM.
* **d)** Lista de verificare pe **două telefoane fizice**.
* **e)** Staging real: 3 relee și issuer-ul pe stagenet, cu un Program de Entitlement care acoperă perioada auditului (cel curent: săptămânile 2957–2989, release până la săptămâna 2964 = 2026-10-26).
* **f)** **Versiuni în engleză** ale `THREAT_MODEL`, `INVARIANTS` și `LIMITE` (192 KB în română) sau un glosar.
* **g)** Semnarea commit-urilor (FR-8.1) și revizia juridică a istoricului public (ADR-37 p.10, ADR-39). **Identitățile din istoric:** adresa ta de e-mail personală e în 371 din 391 de commit-uri (ADR-39 p.4 cere o identitate no-reply pentru cele viitoare); un bundle cu istoric le dă auditorului, o arhivă fără istoric nu. Alege.
* **h)** Arhivarea dovezilor CI la înghețare: artefactele se păstrează 3 zile, **jurnalele 90 de zile** (cele din 28.09 expiră în jur de 27.12). Poți ridica retenția (maximum 400 de zile) și exporta jurnalele; pachetul are copii statice ale faptelor citate. Artefactele publice vechi par deja șterse (API GitHub, 2026-10-04: 98 de artefacte, 258 MiB, toate din 1–3 octombrie).
* **i)** Măsurarea **NFR-3** (cel puțin 1.000 blob-uri/s pe nod, pe redb): ADR-18 o pune în Faza 15 și prevede RocksDB dacă nu se atinge, iar o schimbare de motor după audit ar anula revizuirea releului. Fă-o **înainte** de înghețare.
* **j)** Un contact tehnic care răspunde într-o zi lucrătoare.

## Decizii doar ale tale

Tier-uri și scenariu · buget și dacă retestul e inclus · **politica de publicare** (ADR-38 cere raport complet publicat; „doar rezumat public” contrazice ADR-38) · termenii de acces la sursă și ce istoric dai · data de înghețare · cine face auditul de criptografie (Q57) · cumpărarea sau nu de ore de traducere · **regula pentru problemele cunoscute** în anexa de severitate (B11; implicit: contează la poartă dacă auditorul le evaluează Critical/High) · dacă cererea de ofertă afișează durata și echipa recomandate (le-am scos, ca să nu ancoreze ofertele) · **NDA înainte de ofertare** (am adăugat pasul în B0) · corectarea țintei `bundle` din `dm-fuzz`.

## Cât costă (metodă, nu preț)

Mărime măsurată: ~73.000 de linii de producție (33.500 Rust, 39.700 Kotlin; codul doar-de-test e scos), ~1,8 ori atât cod de test (prima versiune a pachetului numărase ~2.900 de linii de test ca producție). Persoană-săptămâni **(deduse, incertitudine ±50 %)**: S0 **58–78**, S1 **31–67**, S2 **62–131**, plus MLS **+14–27**. Cele **6–8 săptămâni** din plan cer, la S2, 8–16 auditori în paralel (S0: 7–10; S1: 4–8); precedentele publice au 2–6 (SRLabs/OpenMLS: 4 oameni, 12 săptămâni; Cure53/Nym: 6 oameni, 56 zile). **Planifică 10–14 săptămâni cu 6–8 auditori sau separă tier-urile.** Singurul agregat public (OSTIF, ~150 USD/oră, **estimare slabă**) dă doar o **limită inferioară**: cel puțin ~0,4–0,8 milioane USD la S2 și ~0,2–0,4 la S1, înainte de marje, probabil mai mult. Nicio pagină citită nu afișează prețuri — cere oferte. Aritmetica și sursele: `OWNER_ONLY_MARKET_AND_BUDGET.md` A2.

## Ce nu afirmă pachetul

Nicio afirmație de confidențialitate sau de rezistență cuantică (CP-10); nu spune că sistemul e sigur, ci ce s-a verificat, cum, și ce nu. Faptele externe (rapoarte publice, linkuri, date de acces) trebuie reverificate de tine înainte de trimitere.
