# ADR-56 — Afirmații și disclosure-uri în interfață (CP-10)

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-10-05 de proprietar (propus 2026-10-03; designul aprobat cu valorile implicite) |
| Completează | CP-10, FR-8.7, C-10, ADR-36 punctul 6, ADR-38 punctul 11, designul Fazei 14 §2.6 |
| Modifică | designul Fazei 10 §4.5 (fraza pentru canale apare fără comparația cu mesajele directe până la dovezile ADR-36) |

**Context.** `docs/STATUS.md` spune „Afirmații permise în marketing/UI: niciuna”. O interfață are totuși nevoie să spună ce nu protejează GHOST, cum se comportă o setare și care sunt obiectivele de design, fără să afirme ce nu e dovedit. Revizia 1 lăsa autorul să-și aleagă tipul frazei, așa că o afirmație putea ieși ca „funcționalitate”, fără dovezi.

**Decizie.**
1. Registrul `ghost/android/ui/claims/claims.tsv` conține fiecare frază de confidențialitate sau securitate, cu tipul ei (`LIMIT` — o limită; `FEATURE` — cum funcționează o setare; `GOAL` — un obiectiv de design; `CLAIM` — o afirmație despre ce poate sau nu poate face un adversar), dovezile, reziduul care o însoțește și sursa. **O frază care spune ce poate sau nu poate face un adversar, alt dispozitiv, un releu, rețeaua sau platforma e un `CLAIM`, oricum ar numi-o autorul**: o listă revizuită de declanșatori, în română și engleză, o prinde. Fiecare text al ecranelor de securitate, plată, media, canale și încredere are un rând.
2. Un `CLAIM` intră într-un release doar dacă toate dovezile lui sunt în lista verde `ghost/test-harness/privacy/claims-evidence.txt` (azi goală); fiecare linie a listei numește rularea CI, commit-ul, verificarea raportului și suma SHA-256 a raportului arhivat; identificatorii dovezilor sunt unici în tot proiectul. Un `GOAL` se afișează mereu cu starea lui („obiectiv de design — neverificat încă”).
3. Formulările interzise, în română și engleză, sunt cele din design §8.4. Nicio **afirmație** post-cuantică până când modelul ADR-36 a rulat și revizia externă e publicată; apoi doar fraza ADR-36, pentru mesajele directe. Limitările apar de acum, în paralel: pentru canale, criptografia clasică, fără comparație; pentru mesajele directe, ratchet-ul și autentificarea clasice și metadatele de rețea neprotejate post-cuantic; stratul X-Wing al plicurilor DM apare doar ca obiectiv, cu starea lui.
4. Trei straturi de disclosure: onboarding (trei carduri scurte), la momentul acțiunii riscante, pagini de referință („Cine vede ce” după tabelul din plan §4, cu oglinzile de actualizare, Google pe telefoanele cu servicii Google și aplicațiile cu acces la utilizare; „Limite”; „Cine poate citi ecranul”).
5. Disclosure-urile DC-1 … DC-33 ale designului (DC-26 retras) sunt obligatorii; un redactor nativ și un jurist revizuiesc textele de plată, de confidențialitate și ghidul Tor; lista de afirmații semnată (FR-8.7) e condiție de release.

**Consecințe.** (+) CP-10 devine o regulă verificată la build, iar o afirmație nu mai poate trece drept descriere. (−) Azi interfața nu spune nici măcar „criptat end-to-end” și nici „captura de ecran e blocată” până la dovezile lor (porțile Fazelor 9, 10 și 13, auditul Fazei 15); (−) lista de declanșatori cere revizie la fiecare text nou.

**Alternative respinse.** Textele revizuite „din ochi”, fără registru; tipul ales doar de autor.

**Teste.** T56, G-U8, mutanții PM-U24 și PM-U37.
