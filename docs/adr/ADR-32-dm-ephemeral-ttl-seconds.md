# ADR-32 — Mesaje efemere în DM: trepte TTL în secunde, acceptare exactă, termene, numărătoare, ștergere (precizează ADR-27)

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-16, aplicat în Faza 9 (în așteptarea deciziei proprietarului, Q4); **ADR-27 punctul 11 rămâne neschimbat** |
| Sursă | Design Faza 9 (`docs/design/faza9-dm.md`: §10), R-envelope §8, R-privacy §3.9 |
| Modifică | `allowed-observables.json` (`ttl_bucket_seconds` în locul `ttl_bucket_days`); relay-ul (acceptă doar treptele exacte); `client-core` (refuză în loc să rotunjească; limită superioară a expirării la confirmare); `relay_semantics.txt`; INVARIANTS T20 (o alarmă inexactă permisă) și formularea T25; plan §6.2 rândul 9 („TTL pe relee ≤ timer” se citește ca ADR-27 punctul 11, erată); regulile ferestrei Fazei 7 pentru TTL sub 2σ (re-derivate) |

## Context
Nicio componentă nu poate exprima 1 oră (câmpul observat e în zile). Releul acceptă orice TTL. Fereastra de stocare de 7 zile a Fazei 7 permite copii după ce textul expeditorului a expirat. T25 spune că timer-ul nu apare în nimic din ce observă releul, dar treapta derivă din el. ADR-27 numește un câmp `ttl_bucket` care nu există.

## Decizie
1. Treptele sunt {3600, 86400, 604800, 2592000, 7776000} de secunde; releul acceptă exact aceste valori (`rejected_ttl` altfel); câmpul observat devine `ttl_bucket_seconds`.
2. **Tabelul DM, exact ca ADR-27 punctul 11:** 5 minute și 1 oră → 1 oră; 1 zi → 1 zi; 7 zile → 7 zile; 30 de zile → 30 de zile; dezactivat → 30 de zile. Toate blob-urile unei conversații folosesc treapta conversației; TIMER_SET folosește treapta mai mare dintre cea veche și cea nouă. Comprimarea la 7 zile rămâne doar întrebarea Q15.
3. Fiecare operație DM are termenul `autor + min(treaptă, 7 zile)`; după termen nu se mai stochează nicio copie; mesajele de 5 minute au termenul celor de o oră, iar expirarea mesajului nu anulează operația (§21.10). Plafonul de 7 zile face ca fereastra de prospețime de 45 de zile să fie corectă.
4. Numărătoarea pornește la expeditor la commit-ul trimiterii, la destinatar la prima afișare; un mesaj necitit se șterge la `min(expirarea pe releu, consum + treaptă + 1 h)`, cu expirarea venită prin `InboundBlob.relayExpiryHour`; termenele pot doar să scadă; ceasul de expirare nu merge înapoi.
5. Timer-ul și versiunea lui stau în L0; versiunea mai mare câștigă; la versiuni egale câștigă timer-ul mai scurt.
6. Se șterg: rândul, reacțiile, maparea operațiilor și blob-ul reținut, trimiterile în așteptare, mesajele reținute peste limită, cererile expirate, etichetele de deduplicare și cheile de pereche expirate, prekey-urile vechi. Citările sunt doar referințe; nu există FTS; notificarea are text constant; urmează `wal_checkpoint(TRUNCATE)` cu `busy = 0` verificat, plus un checkpoint la fiecare deschidere a bazei.
7. Ștergerile rulează la deschiderea bazei, la fiecare sesiune în prim-plan, în coada de consum a joburilor de fundal și a rulărilor liniștite, printr-un timer în proces și printr-o alarmă inexactă (receiver neexportat, fără extras, fără permisiune nouă); fiecare interogare filtrează rândurile expirate.
8. Pentru treptele de 1 oră și 1 zi, regulile ferestrei Fazei 7 au fost re-derivate: siguranța rămâne; un rezultat ambiguu se încheie `indeterminate`; limita inferioară a confirmării e vidă și e declarată.

## Consecințe
(+) T25 e verificabil pe fiecare cale; releele oneste nu păstrează o copie după ora-termen stocată de Faza 7 + treaptă + 1 h; ADR-27 rămâne neschimbat. (−) Releele văd patru clase TTL, care împart inbox-ul pe clase de conversație și leagă cele două inbox-uri ale unei conversații cu timer diferit de cel implicit în ~2–3 schimburi (L7-D4, Q39); un mesaj efemer nelivrat la timp eșuează; ștergerea fizică poate întârzia sub Doze (L7-D14).

## Alternative respinse
Câmp în ore sau zile fracționare; rotunjire pe client; 7 zile pentru „30 de zile” și „dezactivat” (abatere de la ADR-27, lăsată la decizia proprietarului); operații fără termen (copii târzii); termenul necitit calculat din conținut (un ceas al expeditorului înainte îl prelungește); numărătoarea destinatarului pornită la primire; FTS; notificări cu text; nicio alarmă.

## Teste
T25 (logic și fizic), T30, T33; JD5; NI-DM4; vectorii relay și client; fixture-urile `capture-check`; scenariile S-F ale Fazei 7 cu 1 h și 1 zi; SCN-F; mutanții PM-5, PM-9, PM-10 și ME-7 … ME-21.

## Corecturi după revizie (§21; au prioritate)
1. Mesajele de 5 minute au termenul de stocare de o oră, ca cele de o oră, iar nicio operație DM nu se anulează la expirarea mesajului: altfel, în modul high-privacy, aproximativ jumătate din mesajele de 5 minute nu ar fi fost stocate niciodată, iar releele ar fi deosebit cele două timere (§21.10, Q41).
2. Prospețimea și durata etichetelor de deduplicare depind de treaptă: 6 zile și 4 ore pentru 1 h, 8 zile și 2 ore pentru 1 zi, 20 de zile și 2 ore pentru 7 zile, 45 de zile pentru 30 de zile și dezactivat. Declarat: cine confiscă dispozitivul și cunoaște un `message_id` poate confirma din etichetă primirea mesajului și săptămâna ei.
3. Mesajele reținute la schimbarea cheii păstrează expirarea pe releu și minutul consumului, deci termenul lor de necitit nu se prelungește; afișarea ignoră mesajele deja expirate; triggerul „doar descreștere” numește explicit coloanele.
4. Alarma primește un moment absolut (`SystemClock.elapsedRealtime()` plus întârzierea). Nu există receiver de boot: după o repornire fără rețea, ștergerea fizică așteaptă jobul periodic sau deschiderea aplicației (declarat, L7-D14).
5. Faza 9 nu postează notificări; regulile ADR-27 pentru notificări se dovedesc în Faza 9 doar prin contractul portului, iar verificările pe emulator și pe dispozitive trec în Faza 13.
