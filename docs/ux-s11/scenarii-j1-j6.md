# S11 — scenariile călătoriilor J1–J6 (materiale comune rundei formativă și celei summative anonime)

Versiunea 1, 2026-10-20. Pragurile (decizia proprietarului, Q42): **0 erori critice per călătorie**;
la J1 și la restore, o eroare critică = identitate sau fonduri pierdute — nu există „acceptabil".
Înțelegere: **≥ 7/8 răspunsuri corecte** la întrebările de după călătorie. Fiecare călătorie se rulează
pe build-ul de candidat la release, pe telefonul participantului, fără ajutor din partea facilitatorului
(ajutorul se acordă doar ca să deblochezi un impas procedural — și se notează ca eroare de completare,
nu critică).

## J1 — invitația, cuvintele, copia (onboarding)
**Scop:** participantul ajunge de la aplicația proaspăt instalată la ecranul principal, cu cuvintele
de recuperare notate și verificate.
**Pași:** deschide aplicația → citește ecranele de bun venit → introduce invitația primită → setează
PIN-ul → alege modul de confidențialitate (standard/ridicat) → primește cele 24 de cuvinte și le
notează pe hârtie → trece verificarea de copie (provocarea cu pozițiile) → alege notificările.
**Măsurat:** timp total; erori critice (identitate pierdută / cuvinte ratate netratate); întrebările J1.
**Criteriu de trecere:** completare fără eroare critică; cuvintele pe hârtie sunt suficiente pentru
restaurare (verificat la J-restore, separat).

## J1-restore — restaurarea pe al doilea telefon (NFR-10)
**Scop:** aceeași identitate, pe alt telefon, din cele 24 de cuvinte.
**Pași:** pe telefonul gol → restaurare → cele 24 de cuvinte tastate pe WordKeyboard → provocarea de
copie → așteptarea activării.
**Măsurat:** timp de tastare (median < 3 min, p95 < 5 min); erori critice (fonduri/identitate pierdute).
**Criteriu:** 0 erori critice; timpul în prag.

## J2 — cumpărarea accesului
**Scop:** de la „nu ai acces" la „plata trimisă", participantul înțelege ce se întâmplă mai departe.
**Pași:** ecranul de acces → alegerea pachetului → instrucțiunile de plată (adresă, sumă, termen) →
plata din propriul portofel (din afara aplicației) → ecranul „plata trimisă" → explicația așteptării.
**Măsurat:** erori critice (plată greșită neobservată); întrebările J2.
**Criteriu:** participantul poate explica de ce tokenii întârzie ore și ce vede/cine vede momentul plății.

## J3 — contactul, mesajul, siguranța
**Scop:** adăugarea unui contact din QR (inclusiv cazul codului fotografiat), primul mesaj, timerul,
numărul de siguranță, schimbarea de cheie.
**Pași:** scanare QR în persoană → întrebarea de proveniență → primul mesaj → setarea timerului →
compararea numărului de siguranță → scenariul de schimbare de cheie și bannerul din aplicație.
**Măsurat:** erori critice; întrebările J3 (proveniență, „ce înseamnă Trimis", ce vede celălalt).
**Criteriu:** 0 erori critice; participantul înțelege diferența dintre scanat în persoană și primit ca
fotografie.

## J4 — canalul cu parolă
**Scop:** intrarea într-un canal protejat cu o frază-parolă dată pe hârtie, compararea amprentei, postarea.
**Pași:** primirea linkului + a frazei pe hârtie → previzualizarea locală a invitației → tastarea celor
5 cuvinte → cererea de intrare → compararea amprentei (cod + epocă) cu invitatorul, pe alt canal →
primul post.
**Măsurat:** erori critice; întrebările J4 (pseudonimul, ce vede moderatorul, ce înseamnă epoca).
**Criteriu:** 0 erori critice; amprenta comparată la aceeași epocă înainte de a posta.

## J5 — media
**Scop:** trimiterea unei fotografii și deschiderea unui element „vezi o dată".
**Pași:** atașare din galerie → mesajul despre re-codare → trimiterea → deschiderea elementului
view-once → citirea limitelor înainte de deschidere.
**Măsurat:** erori critice; întrebările J5.
**Criteriu:** 0 erori critice; participantul poate spune ce garantează „o singură dată" și ce nu.

## J6 — versiunea și actualizarea
**Scop:** găsirea versiunii, înțelegerea stării de actualizare.
**Pași:** Setări → Despre → versiunea instalată → „Cine vede ce" (rândul oglinzilor de actualizare) →
în cadrul acestei faze: afișarea stării fără instalare (update-ul efectiv vine cu Faza 14).
**Măsurat:** erori critice; întrebările J6.
**Criteriu:** participantul găsește versiunea neghidat și înțelege cine vede verificările de versiune.

## Notă de domeniu pentru ambele runde
Călătoriile J1–J6 sunt și scriptul de test automată (rulează pe JVM și emulator); scenariile de față
sunt pentru măsurarea umană — completarea mecanică este o dovadă separată (dry-run, raport propriu).
