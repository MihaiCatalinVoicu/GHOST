# ADR-52 — Canalele de distribuție și identitatea aplicației

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-10-05 de proprietar (propus 2026-10-03; designul aprobat cu valorile implicite) |
| Sursă | FR-8.10; ADR-37 punctul 7; Q71 (valoarea implicită aplicată); ADR-07; documentația Accrescent, politica F-Droid, documentația Google despre semnarea Play, verificarea dezvoltatorilor Android și Play Protect (accesate 2026-10-03) |
| Modifică | Plan rândul 14 („repo F-Droid/Accrescent”: decise, neconstruite în Faza 14, X-D6); ADR-37 punctul 7 (Accrescent amânat de condiții externe); spec §12.2 pasul 4 (APK doar din mirror-uri onion, X-D2); THREAT_MODEL S10 și LIMITE L4 („F-Droid repo” eliminat); identificatorul aplicației (X-D14) |

## Context
Accrescent acceptă aplicații cu sursă închisă, dar interzice actualizatoarele proprii, acceptă doar seturi de APK-uri, verifică domeniul identificatorului aplicației și primește dezvoltatori doar dintr-o listă. Depozitul principal F-Droid acceptă doar software liber. Google Play ține cheia de semnare. Din 2027, pe dispozitivele certificate, aplicațiile dezvoltatorilor neînregistrați se instalează doar prin „fluxul avansat” sau ADB.

## Decizie
1. **Mirror-ul onion e canalul principal și singurul construit în Faza 14**; fiecare mirror are două puncte de ascultare pe același onion (HTTP/2 pentru aplicație, HTTP/1.1 pentru browsere, fiindcă Tor Browser nu vorbește HTTP/2 fără TLS); prima instalare vine din mirror (Tor Browser) sau din orice canal, verificată cu `ghost-verify`; fără mirror pe clearnet; mirror-urile nu stau niciodată pe conexiunea de acasă a proprietarului, pe stația de semnare sau pe un host CI, nu țin jurnale (poarta G-D10) și publicarea trece doar prin Tor.> 2. **Accrescent** se amână până când: contul e pe lista de acces, identificatorul aplicației e sub un domeniu al proiectului, există o variantă fără modulul `:update` și fără `REQUEST_INSTALL_PACKAGES`, iar pachetul aplicației și setul de APK-uri sunt reproductibile și semnate cu `K-APK`.
3. **Fără depozit în format F-Droid** (Q71); **fără Google Play**.
4. **Identificatorul aplicației** se stabilește definitiv înaintea primei distribuiri, sub un domeniu controlat de proiect (Q3, Q4); stagenet adaugă `.stagenet`.
5. **Verificarea dezvoltatorilor Android și Play Protect** sunt fapte ale platformei: nicio înregistrare în Faza 14; decizia proprietarului, cu avocatul, înainte ca Faza 16 să primească testeri; contul cu distribuție limitată nu e propus (ar înregistra la Google telefoanele testerilor); backup-ul `K-APK` păstrează posibilitatea înregistrării.
6. **Identitatea materialului public:** tot ce se publică (depozitul public nou, notificările, SBOM-urile, registrul versiunii, domeniul) poartă o identitate de proiect, niciodată numele, contul sau adresele personale ale proprietarului (ADR-39 punctele 4 și 6; poarta G-D9); titularul juridic se decide cu avocatul înainte ca Faza 16 să primească testeri (Q45).

## Consecințe
(+) Un singur lanț de distribuție, verificat de actualizator; nicio dependență de clearnet pentru aplicație. (−) Utilizatorii GrapheneOS nu au o cale prin magazin; prima instalare depinde de Tor Browser sau de verificatorul extern; pe dispozitivele cu Google, platforma poate trimite către Google detalii despre aplicație la instalare (L10-D9), iar verificatorul platformei poate căuta la Google instalările și actualizările (L10-D24); din 2027 o aplicație neînregistrată cere fluxul avansat (L10-D10); sub un flood de introduceri, clienții GHOST nu rezolvă PoW (L10-D18).

## Alternative respinse
Google Play (Google ține cheia; identitatea dezvoltatorului); depozitul principal F-Droid (doar software liber); un depozit propriu F-Droid (a treia familie de chei; actualizări fără verificarea jurnalului); un mirror HTTPS pe clearnet (IP-ul utilizatorilor, domeniu public al aplicației); IPFS (gateway-ul vede IP-ul și versiunea); varianta Accrescent construită acum (fără admitere).

## Teste
T51 (cereri doar către onion-uri din rădăcină, din manifest sau din lista inițială); verificatorul pe o versiune reală de stagenet; Tor Browser pentru Android descarcă și instalează din mirror-ul de staging (V-D22); G-D4 (rădăcini și chei de rețele separate); G-D9 (identitatea); G-D10 (fără jurnale).
