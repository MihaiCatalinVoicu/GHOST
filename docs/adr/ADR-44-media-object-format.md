# ADR-44 — Formatul obiectului media: STREAM pe chunk-uri de 256 KiB aliniate la fragmente de 64 KiB, manifest cu angajament de cheie, clase de dimensiune, cheia de fișier ținută nativ

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-10-04 de proprietar (propus 2026-09-25; designul Fazei 11 aprobat cu întrebarea Q1; revizuit 2026-10-04 după dovezile S0) |
| Sursă | Spec §7.4 (pașii 1–7), FR-2.3, FR-2.4; plan §6.2 rândul 11; ADR-09, ADR-19; designul Fazei 9 (§2.5, §6.6, §7.1) |
| Modifică | Plan rândul 11 („AEAD per chunk 256 KiB” = 256 KiB de ciphertext) și structura modulelor (plan:360: AEAD-ul trece în Rust); spec §7.4 pasul 3 (nonce-ul); designul Fazei 9 (corpul tipului 0x05 MEDIA, funcțiile JNI 2, 3, 4, 8, 13, 14, 18); T35 (extins la cheile media) |

## Context
Spec §7.4 cere cheie de fișier aleatoare, AEAD per chunk de 256 KiB, fragmentare în blob-uri ≤ 64 KiB, hash pe blob exact și cheia învelită în contextul DM/MLS, dar nu definește încadrarea. Un chunk de 256 KiB plus tag nu umple un număr întreg de blob-uri de 64 KiB, iar T9 interzice lungimi în clar și cozi de altă dimensiune. Nonce-ul „file nonce plus index” nu încape în 12 octeți. ChaCha20-Poly1305 nu angajează cheia („invisible salamanders”).

## Decizie
1. Cheie de fișier `K_f` de 256 de biți și `object_id` de 128 de biți, aleatoare, per obiect **și per destinație**; niciodată derivate din conținut.
2. `K_p`, `K_m` și un angajament de 32 de octeți se derivă cu HKDF-SHA256 din `K_f`, cu `object_id` ca sare (construcția age/Tink; sarea leagă `object_id` și separă domeniile, fără câștig multi-utilizator, fiindcă `K_f` e deja aleatoare per obiect). Angajamentul leagă cheia de conținut, nu de expeditor: fără „franking”, un raport de abuz nu dovedește cine a trimis.
3. Conținutul, urmat de zerouri, se împarte în chunk-uri de 262 128 de octeți; fiecare se criptează cu ChaCha20-Poly1305 sub `K_p`, cu nonce-ul `0^7 ‖ u32_be(i) ‖ ultimul` (STREAM, Hoang–Reyhanitabar–Rogaway–Vizár 2015) și AD care leagă `object_id` și tipul; indicatorul „ultimul” apare doar pe ultimul chunk; rezultă exact 4 fragmente de 65 536 de octeți, fără antet.
4. Numărul de fragmente F ia doar valorile {16, 24, 36, 56, 84, 128, 192, 288, 432, 648, 804}, funcție doar de lungimea conținutului; orice imagine are clasa 0 (16 fragmente, 1 MiB), regulă verificată în descriptor, în manifest și în schemă.
5. Un manifest de exact 64 KiB: angajamentul în clar (octeți pseudo-aleatori), apoi AEAD sub `K_m` cu tipul, clasa, lungimea, dimensiunile (geometria canonică a ADR-46) și durata (derivate de verificatorul Rust din fluxul parcurs, nu primite din Kotlin), o previzualizare de cel mult 32 KiB cu latura lungă de 320 px (niciuna la „vezi o singură dată”; restul zerouri verificate) și hash-urile fragmentelor, în ordine.
6. Mesajul DM de tip 0x05 poartă un descriptor fix de 86 de octeți plus o descriere de cel mult 1 024 de octeți, deci orice mesaj media e în treapta de 4 KiB.
7. `K_f` nu ajunge niciodată în Kotlin: se stochează doar învelită sub `session_state_key` (`key_env`), legată de rol, destinatar/expeditor, `object_id` și `manifest_hash`; în L0 stă într-un „slot” de 32 de octeți pe care doar `encrypt` îl completează (după verificarea legăturii) și doar cele două funcții care întorc un L0 decriptat, `decrypt` (13) și `sessionInbound` (14, primul mesaj și reluarea mesajelor reținute), îl golesc.
8. Criptografia media stă în crate-ul Rust `ghost-client-media`, exportat prin clasa JNI închisă `MediaNative` din `ghost-client-dm`; nu intră niciun crate extern nou în bibliotecile livrate.
9. O cheie nu se salvează înainte ca toate chunk-urile obiectului să fie sigilate; o pregătire întreruptă începe un obiect nou, cu cheie nouă (fără reutilizare de nonce).
10. Excepție CP-09 înregistrată: compunerea (manifest, angajament, aliniere, clase) intră în revizia criptografică externă, cu vectori, oracol diferențial (`aead-stream` 0.6.0, doar în teste) și teste de proprietăți.
11. Prefixele datelor asociate sunt `ghost/v1/media/ad/chunk` și `ghost/v1/media/ad/manifest`; niciun șir al formatului (cele trei etichete HKDF, cele două prefixe AD, eticheta `op_id` și cea de învelire) nu e prefixul altuia (S0-6: eticheta HKDF a lui `K_m` și prefixul AD al manifestului erau identice).

## Consecințe
(+) Fragmente uniforme de 64 KiB; acces aleator pentru derulare; resume la nivel de fragment; trunchierea, reordonarea și substituția sunt respinse; un manifest se deschide sub cel mult o cheie. (−) Umplutură de până la ~59 % în cel mai rău caz; releele văd una din 11 clase; o imagine mică costă 17 blob-uri de 64 KiB.

## Alternative respinse
Unitate AEAD de 64 KiB (se abate de la plan fără câștig; rezervă); chunk-uri nealiniate (coadă care nu e bucket); flux secvențial înlănțuit (fără derulare); nonce aleator per chunk (fără legare de ordine); manifest în mesajul DM (dimensiunea obiectului ar apărea în treapta DM); Padmé (pe lungimi în octeți, definiția lui: ~110 clase peste clasa 0 după alinierea la chunk-uri; pe numărul de fragmente: ~55); puteri ale lui 2 (umplutură până la 100 %); cheia în Kotlin.

## Teste
Vectorii `media_object.txt` (Rust, oracolul `aead-stream`, implementare JDK independentă; verificați în S0: 145 de valori egale, 12 refuzuri AEAD, cazurile negative trec în fișier ca date); matricea de corupere; registrul de nonce-uri în toate lumile și scenariile de crash; testele slotului de cheie prin funcțiile 13 și 14 și prin reluarea mesajelor reținute; T42; mutanții PM-M1 … PM-M4, PM-M13, PM-M17, PM-M22, MC-M1 … MC-M5, MC-M11, MC-M21.
