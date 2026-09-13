# ADR-27 — Protecția ecranului și a textului; mesaje efemere

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-13 (proprietar proiect, la cererea lui, după discuția despre limitele reziduale); de implementat în Fazele 9, 10, 11 și 13 |
| Sursă | Cererea proprietarului din 2026-09-13; LIMITE L1 („mesaje efemere implicit”) și §3.2; ADR-08 |
| Completează | ADR-08 (FLAG_SECURE și ștergerea clipboard-ului devin reguli detaliate); spec FR-7.8 (ecrane sensibile și clipboard) și FR-4.4 (mesaje efemere, implicit active); plan §6.2 rândurile Fazelor 9, 10, 11 și 13; invariantul T10 (extins) și invarianții noi T24 și T25 |
| Modifică | Setul de trepte TTL observabile de relee (`ttl_bucket` în `allowed-observables.json`): se adaugă treapta de 1 oră. Schimbarea se face în Faza 9, odată cu codul din relay și client |

## Context
Două limite reziduale nu pot fi eliminate de nicio aplicație: un membru rău-intenționat poate păstra ce vede, iar un dispozitiv compromis sau confiscat arată tot ce conține. Se pot însă reduce mult scurgerile accidentale și ocazionale (screenshot-uri, aplicații care citesc ecranul sau clipboard-ul) și cantitatea de istoric expusă. ADR-08 prevedea deja FLAG_SECURE și ștergerea clipboard-ului, iar LIMITE L1 prevedea mesaje efemere implicit, dar fără reguli precise și fără teste. Acest ADR le face normative.

## Decizie

### A. Protecția ecranului (Faza 13)
1. **FLAG_SECURE pe fiecare fereastră a aplicației** (activități, dialoguri, bottom sheets, orice fereastră proprie), **activ întotdeauna, fără opțiune de dezactivare**. Efect: screenshot-ul și înregistrarea ecranului dau imagine neagră, aplicația nu apare cu conținut în lista de aplicații recente, conținutul nu se proiectează pe ecrane nesigure. Pe API 33+ se apelează și `setRecentsScreenshotEnabled(false)`.
2. Nicio notificare nu arată conținut cât dispozitivul e blocat (T11, deja în plan).

### B. Protecția textului (Faza 13)
3. **Mesajele nu se pot selecta, copia sau partaja**: fără text selectabil, fără acțiunile „Copiază”, „Partajează” sau „Trimite către” pentru conținutul mesajelor și pentru media, fără drag & drop în afara aplicației. Câmpul de compunere rămâne normal (utilizatorul poate lipi în el propriul text).
4. **Câmpurile sensibile** (mesaje, pseudonime, safety numbers, cuvintele seed-ului) sunt marcate `accessibilityDataSensitive` (API 34+): doar serviciile declarate ca instrumente de accesibilitate (cititoarele de ecran) le mai pot citi, nu orice aplicație cu permisiune de accesibilitate. Pe API < 34, aplicația afișează în setări un avertisment dacă un serviciu de accesibilitate terț e activ.
5. **Clipboard**: aplicația copiază doar date pe care utilizatorul le cere explicit și care nu sunt conținut de mesaj (link de invitație, adresă de payout). Seed-ul nu se copiază niciodată. Fiecare copiere e marcată `ClipDescription.EXTRA_IS_SENSITIVE` (API 33+, fără previzualizare în sistem) și e ștearsă automat după 30 s sau la blocarea aplicației, doar dacă clipboard-ul mai conține datele puse de GHOST.
6. Tastatura: `IME_FLAG_NO_PERSONALIZED_LEARNING` pe toate câmpurile și avertismentul unic despre tastaturi terțe (ADR-08, neschimbat).

### C. Mesaje efemere (Fazele 9, 10, 11)
7. **Timer per conversație (DM) și per canal** (în politica de canal MLS, ADR-13), cu valorile: dezactivat, 5 minute, 1 oră, 1 zi, 7 zile, 30 de zile. **Implicit: 7 zile în DM** (LIMITE L1, FR-4.4 activ implicit); în canale, valoarea din politica fixată de creatorul canalului, implicit 7 zile.
8. Timer-ul face parte din **conținutul criptat** al fiecărui mesaj, nu din metadatele văzute de releu. Schimbarea timer-ului este ea însăși un mesaj, afișat tuturor participanților.
9. **Numărătoarea**: pentru expeditor pornește la trimitere, pentru destinatar la prima afișare. Un mesaj necitit se șterge cel târziu la expirarea blob-ului lui pe relee.
10. **La expirare, fiecare dispozitiv șterge**: rândul mesajului și conținutul decriptat, media și miniaturile (cache-ul criptat din Faza 11), notificarea, citările și reacțiile care îl reproduc. `secure_delete` (activ din Faza 7) suprascrie paginile șterse; după fiecare lot de ștergeri se face un checkpoint WAL.
11. **TTL pe relee**: blob-ul unui mesaj efemer primește cea mai mică treaptă TTL ≥ timer. Treptele devin {1 oră, 1 zi, 7 zile, 30 de zile, 90 de zile} (se adaugă treapta de 1 oră); un timer de 5 minute folosește treapta de 1 oră. Astfel conținutul criptat nu rămâne pe releele oneste mai mult decât pe telefoane.
12. **Media „vezi o singură dată”** (Faza 11, P1): media se decriptează doar în memorie la afișare, nu se poate redeschide, iar cheia ei se șterge după prima afișare.

## Teste (fiecare cerință are un invariant executabil)
- **T10 (extins)**: fiecare fereastră a aplicației are FLAG_SECURE și nu există nicio cale de cod care îl scoate (gate static); test UI: screenshot și înregistrare negre; pe API 33+ `setRecentsScreenshotEnabled(false)`.
- **T24 (nou)**: în UI-ul de mesaje nu există text selectabil, acțiuni de copiere sau partajare, drag în afara aplicației; câmpurile sensibile sunt `accessibilityDataSensitive`; orice scriere în clipboard are `EXTRA_IS_SENSITIVE` și e ștearsă după 30 s. Gate static (interzice `SelectionContainer`, `textIsSelectable` și `setPrimaryClip` în afara unui singur modul aprobat) plus teste UI.
- **T25 (nou)**: după expirarea timer-ului, pe fiecare dispozitiv onest nu mai există mesajul, media, notificarea sau conținutul decriptat (harness JVM cu ceas virtual; inspecția bazei și a fișierelor după ștergere și checkpoint caută un canar de plaintext); TTL-ul trimis releului este cea mai mică treaptă ≥ timer; timer-ul nu apare în nimic din ce observă releul (T1).

## Consecințe
(+) Screenshot-urile accidentale, înregistrările de ecran și aplicațiile spion obișnuite (ecran, clipboard, accesibilitate) nu mai văd conținut. Un dispozitiv pierdut sau confiscat conține cel mult ultima fereastră de timp a fiecărei conversații. Releele oneste nu păstrează istoric mai vechi decât timer-ul.

(−) Utilizatorul nu poate face screenshot nici în scop legitim; raportarea abuzului se face prin flag-urile din ADR-13. Cititoarele de ecran continuă să funcționeze. Un mesaj efemer necitit la timp se pierde. Treapta TTL de 1 oră îi arată releului că un blob e un mesaj scurt-viu (o metadată nouă, declarată; majoritatea mesajelor folosesc treapta implicită de 7 zile).

## Reziduuri declarate (nu pot fi eliminate)
- Fotografia ecranului cu alt dispozitiv; un client modificat care ignoră FLAG_SECURE sau timer-ul; un telefon cu root, pe care module speciale pot anula FLAG_SECURE; pe API < 34, serviciile de accesibilitate pot citi textul.
- Un releu rău-intenționat poate păstra ciphertext-ul după TTL. Fără cheile de mesaj, șterse după decriptare (forward secrecy în Signal și MLS), acesta e inutil, cu excepția unui dispozitiv compromis înainte de ștergere.
- Hash-urile blob-urilor rămân pe telefon ca tombstone-uri de deduplicare, fără conținut, până la retenția lor (ADR-20, LIMITE L1.1).
- Pe memoria flash, pagini vechi pot supraviețui fizic (wear leveling), dar sunt criptate de SQLCipher cu cheia bazei.
