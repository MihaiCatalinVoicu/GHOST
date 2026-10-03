# Pachetul pentru auditul extern (Faza 15): notă pentru proprietar

**Data:** 2026-10-03 (completat 2026-10-04) · **Commit de bază:** `a0f3f58` (`main`) · **Autor:** agent AI, pentru proprietar · Documentele din `docs/audit/` sunt în engleză (pentru auditori); aceasta e singura notă în română.

## Ce este pachetul

| Fișier | Pentru ce |
|---|---|
| `AUDIT_SCOPE.md` | Componentele (cale, limbaj, mărime măsurată), ce intră și ce nu în audit, **lista de priorități după risc**, inventarul criptografic cu versiuni exacte, ipoteze, registrul afirmațiilor (CP, T1–T35, garanțiile fazelor) și ce **nu** afirmă proiectul |
| `EVIDENCE_INDEX.md` | Ce s-a verificat deja și cum se reproduce; contoare de teste, porți, mutanți, modele ProVerif, fuzzing, revizuiri; și lista **a ce nu a rulat** |
| `KNOWN_ISSUES.md` | Constatări deschise, decizii ale proprietarului, reziduuri declarate, ipoteze neverificate (ca auditorul să nu piardă timp pe ce se știe) |
| `BUILD_AND_REVIEW_GUIDE.md` | Cum primește auditorul sursa (privată), cum construiește, comenzile de test, ordinea de citire, indexul componentă → specificație |
| `AUDITOR_RFQ.md` | **Partea A (doar pentru tine):** tabel de firme cu rapoarte publice și metoda de buget. **Partea B:** cererea de ofertă gata de trimis |

## Starea reală (nu e „gata de audit”)

Auditul final cere Fazele 9–14 închise. La commit-ul de bază: **Faza 9** are poarta deschisă (mutanți 26/57 corectitudine și 15/40 confidențialitate rulați, 8 decizii ale review-ului la tine, nicio rulare pe dispozitive); **Faza 10** (OpenMLS) nu e în `main`, doar pe ramuri nemerguite; **Fazele 11, 13, 14** sunt doar design propus, **Faza 12** neînceput; **nu există UI**. Din CI (citit 2026-10-03): `ci` are totul verde în afară de un caz din `self-test` (reparat în `a0f3f58`, încă nepus pe `origin/main`); **`dm-fuzz` pică în fiecare noapte** pe ținta `bundle` (probabil o proprietate veche în harness după repararea CRY-P9-01, neconfirmat); **T32 la scară de poartă pică** din 28.09 pe toate cele 10 perechi (JD5; a trecut o dată, pe 27.09); **T2** pică pe perechile 2, 3 și 9; emulatorul nu a rulat niciodată pe runner (fără KVM). Pachetul spune asta în `AUDIT_SCOPE.md` §0 și în `KNOWN_ISSUES.md`.

## Ce ai de făcut, în ordine

1. **Alege tier-urile** (A criptografie și protocoale, B client Android, C relay și issuer, D lanț de aprovizionare; opțiuni: MLS, UI, distribuție) și **scenariul** (S0 baseline, S1 focalizat, S2 tot planul).
2. **Trimite Partea B** din `AUDITOR_RFQ.md` la 3–5 firme din tabel (după NDA, atașezi cele patru documente). Recomandare **(dedusă)**: o firmă de criptografie pentru A, o firmă de securitate de aplicații pentru B–D, sau două oferte paralele.
3. **Fixează data de înghețare** a codului (tag `audit-rc1`) și data de start: contractul trebuie semnat cu **cel puțin 4 săptămâni înainte** de start.
4. **NDA și licență de utilizare limitată** (fișierul `LICENSE` nu dă niciun drept). **Nu adăuga auditori ca „collaborators” pe GitHub:** pe un depozit personal primesc drept de scriere, iar CI-ul rulează pe laptopul tău; sursa se dă printr-un `git bundle` cu hash comunicat separat (ghidul, §1.2).

## Ce mai datorează proiectul înainte de audit (pași de pregătire)

a) Închiderea sau **renunțarea explicită** la porțile Fazelor 9–14 și merge-ul Fazei 10; b) deciziile din `KNOWN_ISSUES.md` §2 și §4 (MD-1, MD-4–7, CRY-P9-03, A-2, GATES-5, G-DM3, TIMER_SET, T2 perechile 2/3/9, ADR-22…26); c) rulări la scară de poartă care trec: T2 (3 perechi), T32 (JD5), `dm-fuzz` (repararea țintei `bundle`), `dm-emulator` cu KVM; d) lista de verificare pe **două telefoane fizice**; e) staging real: 3 relee și issuer-ul pe stagenet, cu un Program de Entitlement care acoperă perioada auditului (cel curent: săptămânile 2957–2989, release până la săptămâna 2964 = 2026-10-26); f) **versiuni în engleză** ale `THREAT_MODEL`, `INVARIANTS` și `LIMITE` (192 KB în română) sau un glosar; g) semnarea commit-urilor (FR-8.1), revizia juridică a istoricului public (ADR-37 p.10, ADR-39) și arhivarea rapoartelor porților la înghețare (artefactele CI se păstrează doar 3 zile); artefactele publice vechi par deja șterse (API GitHub, 2026-10-04: 98 de artefacte, toate din 1–3 octombrie); h) un contact tehnic care răspunde într-o zi lucrătoare.

## Decizii doar ale tale

Tier-uri și scenariu · buget și dacă retestul e inclus · **politica de publicare** (ADR-38 cere raport complet publicat; „doar rezumat public” contrazice ADR-38) · termenii de acces la sursă · data de înghețare · cine face auditul de criptografie (Q57) · cumpărarea sau nu de ore de traducere.

## Cât costă (metodă, nu preț)

Mărime măsurată: ~76.000 de linii de producție (36.400 Rust, 39.750 Kotlin), ~1,8 ori atât cod de test. Persoană-săptămâni **(deduse, incertitudine ±50 %)**: S0 **50–90**, S1 **36–76**, S2 **66–139**, plus MLS **+13–26**. Cele **6–8 săptămâni** din plan cer 6–17 auditori în paralel; precedentele publice au 2–6 (SRLabs/OpenMLS: 4 oameni, 12 săptămâni; Cure53/Nym: 6 oameni, 56 zile). **Planifică 10–14 săptămâni cu 6–8 auditori sau separă tier-urile.** Nicio firmă nu publică prețuri; singurul agregat public (OSTIF, ~150 USD/oră, **estimare slabă**) dă un ordin de mărime de ordinul a 0,2–0,8 milioane USD înainte de marje — cere oferte. Detalii și surse: `AUDITOR_RFQ.md` Partea A.

## Ce nu afirmă pachetul

Nicio afirmație de confidențialitate sau de rezistență cuantică (CP-10); nu spune că sistemul e sigur, ci ce s-a verificat, cum, și ce nu. Faptele externe (rapoarte publice, linkuri, date de acces) trebuie reverificate de tine înainte de trimitere.
