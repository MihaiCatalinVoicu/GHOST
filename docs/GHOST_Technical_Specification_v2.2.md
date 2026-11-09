# GHOST - Specificație tehnică v2.2

Mesh opțional, voce locală E2EE și rezistența APK-ului la analiză și modificare

Data: 31 octombrie 2026. Status: FINAL DOCUMENTAR - cerințe pentru implementare; funcționalitățile noi sunt planificate, neimplementate și nevalidate prin această revizie.

## 1. Autoritate, versiune și limitele reviziei

Această revizie actualizează cerințele GHOST pentru mesh între contacte verificate, mesaje vocale, apeluri locale unu-la-unu și protecția APK-ului. Se citește împreună cu Master Plan v2.1, ADR-urile acceptate și designurile de fază din repository. Nu este o certificare de securitate și nu închide nicio poartă de implementare sau audit.

Ordinea de autoritate pentru domeniul acestei revizii: cererea proprietarului din 31 octombrie 2026; cerințele v2.2 de mai jos; deciziile existente aplicabile; PDF-ul v2.0 numai acolo unde nu a fost înlocuit. Nu se reactivează arhitectura veche din PDF. Starea execuției rămâne în `docs/STATUS.md`; estimările și pașii noi sunt în `docs/GHOST_Roadmap_v2.2.md`.

Amendamente documentare explicite: ADR-01 primește excepția locală din §4.1; punctul 9 din ADR-38 este înlocuit de regulile H-01/H-09. Formulările anterioare din designurile de fază descriu baseline-ul istoric; implementarea v2.2 trebuie să le reconcilieze prin H0/M0, fără a pretinde că porțile T6/T12b au fost deja modificate sau trecute.

| Element | Baza păstrată și efectul v2.2 |
|---|---|
| Internet | Tor/Arti și onion services, fără fallback clearnet. Excepția locală este strict delimitată în §4. |
| Mesaje directe | Motorul existent vodozemac/Olm și plicul GHOST, ADR-35/36. Validarea lor externă rămâne necesară; nu se reintroduce libsignal. |
| Forum | OpenMLS și pseudonime per canal, ADR-40-43. Transportul mesh inițial deservește DM, fără sincronizare de canale sau liste de membri. |
| Plăți | Entitlement blind și rail-ul existent, fără schimbare de prețuri, plăți, token-uri sau autorizare financiară. |
| Media | Formatul existent din ADR-44-47: chunk de ciphertext 256 KiB și fragmente 64 KiB. Notele vocale reutilizează criptografia media. |
| Dependențe | Fără GMS, Nearby SDK, FCM, Firebase sau analytics. Bibliotecile audio/RTC intră numai după verificarea licenței și a grafului de dependențe. |
| Distribuție | Sursă închisă conform ADR-37; build reproductibil și dovezi independente conform ADR-38. Obfuscarea nu anulează accesul auditorilor. |
| Verificare | Rețete locale și dovezi pe commit/artefact exact, ADR-58. Nicio cerință nouă de GitHub Actions. |

MUST/MUST NOT sunt obligatorii; SHOULD permite abatere motivată și revizuită; MAY este opțional. Toate cerințele M, V și C sunt obligatorii pentru activarea respectivului modul. H este obligatoriu pentru orice viitoare versiune de producție. Opțional înseamnă alegerea utilizatorului de a activa mesh-ul, nu posibilitatea de a omite securitatea lui.

Ținta de produs include toate cele trei funcții solicitate. O livrare intermediară fără mesh este permisă de planul de bază, dar nu reprezintă finalizarea v2.2. Criteriile și calendarele vechi nu sunt dovezi că noul domeniu este gata.

## 2. Scop funcțional și non-obiective

- Mesaje text și note vocale între destinatari verificați, direct sau prin retransmitere temporară prin vecini verificați.
- Mesh dezactivat implicit; activarea comunicației locale, a retransmiterii pentru alții și a gateway-ului sunt controale separate.
- Apeluri audio live locale, unu-la-unu, numai pe legătură Wi-Fi directă validată. Fără numere telefonice sau acces la rețeaua telefonică publică.
- Mesaje vocale asincrone; nu se confundă cu push-to-talk live. O înregistrare poate ajunge mai târziu dacă destinatarul nu este conectat.
- Protecție prin obfuscare, eliminarea informațiilor inutile, integritatea distribuției și validare independentă de client.

Nu sunt incluse: retransmitere prin necunoscuți, rutare globală anonimă nouă, apeluri live multi-hop, apeluri de grup, video live, clonarea automată a contactelor pe alte dispozitive, transcriere cloud sau promisiuni că APK-ul nu poate fi decompilat. Un apel live are nevoie de o cale disponibilă simultan la ambele capete.

## 3. Model de adversar și garanții

Adversarul poate controla un vecin autorizat, mai multe identități, pachete și temporizarea lor, un gateway, o copie modificată a APK-ului sau un dispozitiv destinatar. Poate copia ciphertext, elimina/întârzia/rejuca mesaje, minți despre rută și provoca multe cereri. Distincția dintre identitate verificată și comportament onest este obligatorie în design.

| Observator | Date observabile / limită | Protecție solicitată |
|---|---|---|
| Radio local | Prezență, proximitate, activitate și identificatori radio expuși de OS | Fără identitate GHOST în discovery; identificatori aplicație temporari; nicio promisiune de invizibilitate radio |
| Vecin de transport | Identitatea verificată a vecinului său, moment, volum, obiecte și roluri pe care trebuie să le proceseze | Canal autentificat, E2EE interior, inventar limitat, permisiuni separate; nu vede contactele sau canalele fără legătură |
| Intermediar | Poate corela transferuri identice și deduce ruta din context; poate refuza livrarea | Autorizație limitată, cozi criptate, expirare și alternative; nu i se dau chei de conținut |
| Destinatar | Conținut, voce și informațiile oferite explicit de expeditor | Verificarea interlocutorului; nu se poate împiedica înregistrarea sau redistribuirea de către el |
| Adversar cu multe noduri | Poate controla aparent mai mulți vecini și observa mai multe capete | Admitere explicită și buget global; nu se pretinde eliminarea Sybil sau independența nodurilor |
| Dispozitiv compromis | Poate observa plaintext și chei active în proces | Keystore și hardening reduc expunerea; nu garantează securitatea unui endpoint controlat |
| Analist APK | Poate extrage, decompila, instrumenta și modifica binarul | Cost de analiză crescut; niciun secret global sau control critic nu depinde de ascunderea codului |

Criptarea nu garantează anonimat, disponibilitate, unicitatea persoanei din spatele unei identități sau dispariția copiilor de la un peer ostil. Bruiajul radio și izolarea de toate rutele nu sunt rezolvabile prin retransmitere software. Pentru voce live, padding-ul și ritmul constant pot reduce indicii, fără garanție împotriva corelării temporale [R7].

## 4. Arhitectură și excepția locală de transport

Fluxul asincron: conținut -> motor DM/media existent -> outbox criptat -> transport Tor sau transport local autorizat -> inbox tranzacțional -> confirmare autenticată. Intermediarii operează pe ciphertext; nu decriptează și nu recodifică vocea.

Fluxul apelului: acord reciproc -> semnalizare autentificată între identitățile verificate -> negociere media efemeră -> audio E2EE direct pe rețeaua locală selectată -> închidere și eliminarea stării efemere. Coada store-and-forward nu este utilizată ca transport pentru cadrele unui apel live.

| Modul propus | Responsabilitate |
|---|---|
| `transport-local` | Discovery, legături Android Wi-Fi Aware/Direct, legare la interfață, politici de destinație și lifecycle |
| `mesh-policy` | Contacte/dispozitive verificate, autorizări, limite, revocare și alegerea următorului vecin |
| `mesh-store` | Cozi criptate, deduplicare, expirare, stare custody/delivery și integrare tranzacțională cu sync |
| `voice-notes` | Captură, codec, metadate minime și reutilizarea formatului media existent |
| `local-calls` | Stare apel, semnalizare, identitate, audio, control jitter și terminarea sesiunii |
| `release-hardening` | Configurație release, inspecție APK, simboluri, reproducibilitate și probe de modificare |

Aceste nume sunt limite de responsabilitate, nu dovada că modulele există. Migrațiile se proiectează înainte de cod și păstrează datele utilizatorului.

### 4.1 Regula de rețea obligatorie

Tor rămâne obligatoriu pentru orice destinație externă. Excepția locală se aplică doar unui socket legat de o rețea Android selectată explicit și de un peer autentificat, aflat pe acea legătură. O adresă privată RFC1918 sau link-local nu dovedește singură că peer-ul este autorizat.

În modul local-only, nicio componentă GHOST nu contactează Internetul: relay, issuer, update, STUN, TURN, DNS public sau telemetrie. Modul hibrid este separat și permite numai traficul extern existent prin Tor. Gateway-ul este opt-in separat; poate depune ciphertext la relay-uri exclusiv prin Tor, cu autorizație limitată la obiecte. Nu se transmit vecinului parole, seed, token-uri generale de cont sau drepturi nelimitate de relay.

IP-ul local poate fi cunoscut de vecinul direct și de interlocutorul unui apel; UI declară această diferență față de un DM prin Tor. Secretele, descriptorii și listele de candidați locale nu se trimit către alte contacte sau servicii.

Adapterul pornește cu Wi-Fi Aware unde există suport; Wi-Fi Direct este fallback doar după teste de compatibilitate. BLE poate fi folosit pentru discovery limitat. API-urile nu furnizează automat un mesh rutat [R1]. Alegerea finală și limitările de conexiuni simultane se probează pe dispozitive înainte de înghețarea protocolului. Fără hardware compatibil, funcția se declară indisponibilă, fără reducerea securității.

Rendezvous prin QR sau schimb BLE autentificat, numai într-o sesiune de descoperire pornită explicit și vizibilă; fără discovery în fundal. Nu se admit DNS, mDNS, SSDP, scanare de subnet, endpoint public, rută implicită sau fallback Internet pentru acest transport. Descriptorul semnat leagă peer-ul, interfața, adresele/porturile și expirarea. Pierderea ori schimbarea căii autentificate închide socket-urile; reconectarea mesajelor cere un nou handshake și reverificarea grant-ului. Un apel se termină și necesită acceptarea unui apel nou.

Permisiunile Nearby/Bluetooth/Wi-Fi și microfon se cer contextual și intră în allowlist prin excepții punctuale de la gate-ul manifest existent. WorkManager deservește reluări asincrone; nu este bucla unui apel. Scanarea, serviciile foreground, notificarea persistentă și accesul la microfon respectă versiunea Android și oprirea explicită a utilizatorului [R2].

## 5. Cerințe mesh între contacte verificate

| ID | Cerință obligatorie | Dovadă minimă de acceptare |
|---|---|---|
| M-01 | Implicit OFF; mod local-only, hibrid, forwarding și gateway controlate separat. Oprirea închide sockets și advertising și suspendă coada locală. | MESH-01: zero activitate locală când este OFF; stop și restart nu reactivează fără starea salvată autorizată. |
| M-02 | Verificare reciprocă a identității și dispozitivului prin QR/amprentă pe canal independent. Invitația în aplicație sau un nume afișat nu reprezintă verificare. | MESH-02: substituție de cheie/dispozitiv refuzată; reverificare explicită. |
| M-03 | Autorizații distincte pentru comunicare, forwarding și gateway, limitate la dispozitiv, scop, volum și expirare. Verificarea A-B și B-C nu îl face automat verificat pe C pentru A. | MESH-02: trust tranzitiv și escaladarea scopului eșuează; destinatarul final A-D este verificat independent. |
| M-04 | Discovery nu publică identitatea GHOST, amprenta permanentă, canalele sau lista de contacte. Identificatorii aplicației sunt efemeri. | MESH-03: capturi repetate și negative pentru identitate/canale; limitele MAC/OS sunt documentate. |
| M-05 | Handshake autentificat prin biblioteci revizuite; legare de dispozitive, rol, versiune și context. E2EE existent rămâne interior, fără recriptare de conținut la hop. | MESH-04: MITM, replay, downgrade și schimbare de rol respinse; intermediarul nu obține plaintext. |
| M-06 | Inventarul este pereche/scop limitat și schimbat numai după autorizare. Fără broadcast de hash-uri stabile, Bloom filter global sau enumerare de obiecte neautorizate. | MESH-03: peer fără grant nu poate confirma existența unui obiect; corelarea între vecinii autorizați este reziduu explicit. |
| M-07 | Envelope cu versiune, ID interior autenticat, termen de expirare și limite de forwarding. Hash-ul de integritate nu este autentificare a expeditorului. | MESH-04: substituție, tamper, duplicați și schimbare expiry respinse; fără reînviere prin schimbare outer ID. |
| M-08 | Admitere și expediere sub cote per autorizare și per dispozitiv; parsare cu limite înainte de alocări mari. | MESH-05: flood, identități rotite, numere extreme și fișiere corupte rămân sub plafonul global. |
| M-09 | Storage criptat și persistent; transferuri reluabile și operații idempotente în motorul existent. Retenția minimă dintre timer-ul mesajului, grant și plafonul mesh. | MESH-06: crash, disc plin, întreruperi și reluare fără mesaj final duplicat sau prelungirea retenției. |
| M-10 | Custody ACK diferit de delivery ACK. Doar destinatarul autenticat poate confirma recepția durabilă; nu confirmă citirea. Chitanțele opționale nu sunt expuse vecinilor. | MESH-06: ACK fals al intermediarului nu afișează livrat; după commit în inbox și crash nu se pierde mesajul confirmat. |
| M-11 | Rutare limitată, fără flooding global sau reputație globală. Alternative numai între vecini autorizați; pierderea tuturor căilor înseamnă queued/expired, nu succes. | MESH-07: blackhole, buclă, rută mincinoasă și despărțirea rețelei; retry finit. |
| M-12 | Blocarea/revocarea aplicată imediat local; la aflarea schimbării de cheie se suspendă trimiterea și se cere reverificare. | MESH-08: cozi existente nu se livrează automat cheii noi; grant revocat nu mai este acceptat local. |
| M-13 | Revocările offline sunt eventuale, cu grant-uri finite. Clock rollback sau timp nesigur nu prelungește grant-uri ori mesaje; noile forwarding-uri se opresc conservator până la restabilirea timpului verificabil. | MESH-08: reboot, rollback de ceas și revocare întârziată; nicio afirmație de revocare instantanee globală. |
| M-14 | Local-only și gateway respectă §4.1. Lipsa Internetului/issuer-ului nu declanșează clearnet și nu schimbă politica de plată. | MESH-09: captură DNS/TCP/UDP inclusiv IPv6; gateway fără grant și token expirat refuzate. |
| M-15 | Fără jurnale cu peer IDs, rute, hash-uri stabile, conținut sau audio; diagnostice locale criptate și export manual minim. | MESH-03: inspecție log/cache/backup și export; fără SDK de telemetry. |
| M-16 | Capabilitatea experimentală se activează numai după MESH-01-09 și auditul domeniului; nu extinde implicit sincronizarea forumului. | Gate documentat pe build exact; teste regresie pentru Tor și pseudonime per canal. |

### 5.1 Limite inițiale de protocol și resurse

Valorile sunt baseline de validat la M0, nu rezultate măsurate. Mărirea lor necesită justificare și rerularea testelor de abuz/performance.

| Parametru | Limită inițială |
|---|---|
| Vecini autentificați simultan | Maximum 4, sau mai puțini dacă platforma impune |
| Lungime rută mesaje | Maximum 3 legături, cel mult 2 intermediari; fiecare legătură verificată separat |
| Copii active | Maximum 2 următori vecini autorizați per obiect și per dispozitiv onest |
| Coada forwarding | Maximum 64 MiB total și 16 MiB per grant; refuz controlat când este plină |
| Grant mesh | Maximum 24 ore fără reînnoire autentificată; fără reînnoire implicită de către intermediar |
| Retenție forwarding | Maximum 24 ore și niciodată peste termenul original al mesajului sau grant-ului |
| Frame de date | Maximum 68 KiB serializat: fragment ciphertext de cel mult 64 KiB plus maximum 4 KiB overhead; cotele de trafic numără întregul frame |
| Handshake neautentificat | Maximum 2 în curs, 10 inițieri/minut/dispozitiv; backoff până la 5 minute, fără blocarea resurselor pentru contactele deja autentificate |
| Transfer de background | Plafon implicit 1 MiB/minut/dispozitiv și pauză forwarding sub 20% baterie când nu se încarcă |

Hop limit-ul și limitele de copii sunt obligatorii pe clienții onești; un peer modificat poate copia sau păstra propriul ciphertext. Validarea grant-ului, a obiectului și a expirării limitează acceptarea de către restul rețelei; nu poate forța ștergerea pe dispozitivul atacatorului. Rutele alternative nu dovedesc operatori independenți.

Autorizarea offline a mesh-ului este un grant local între contacte, separat de token-urile de unică folosință ale issuer-ului. Un token destinat unui relay nu se reutilizează ca permis mesh. Plățile/activările noi păstrează fluxul existent; disponibilitatea locală nu declară un abonament reînnoit.

### 5.2 Contractul de autorizare și confirmare

Grant-ul este semnat, direcțional, netransferabil și nedelegabil. Leagă ID/epoch, cheile celor două dispozitive, operația permisă, obiectele/scopul, expirarea, limita de octeți și obiecte, rata și limita de hop-uri. Autentificarea vecinului autorizează numai custodia/transportul; destinatarul autentifică separat expeditorul original prin plicul DM. Nu există o cheie mesh comună tuturor contactelor.

Inventarul folosește identificatori derivați prin PRF per grant și epoch, numai după autorizare; derivarea exactă și separarea de domenii intră în review la M1. Protecția replay/buclă și cotele globale persistă peste restart și rotația identificatorilor. Se verifică mărimea, numărul obiectelor, conexiunile în curs și bugetul înainte de alocări mari/decriptare. M0 fixează și plafoanele CPU/memorie, număr obiecte și mesaje de control pe baza măsurătorilor; protocolul nu se îngheață cu aceste limite nedefinite.

Custody ACK este autentificat de hop. Delivery ACK este autentificat de dispozitivul destinatar numai după commit durabil, legat de ID-ul mesajului, dispozitiv și încercarea de transfer. Doar al doilea poate marca livrarea sau permite ștergerea automată a copiei din outbox pe motiv de livrare. Expirarea și ștergerea explicită de către utilizator rămân căi separate. Dacă receipt-urile sunt dezactivate, aplicația nu inventează starea livrat; receipt-ul de destinație, când există, circulă opac pentru intermediari.

Revocarea folosește epoch-uri semnate monoton crescătoare și expirări scurte. O revocare cunoscută se aplică imediat local, iar rollback-ul stării sau timpul nevalid blochează noi forwarding-uri. Revocarea nu poate șterge ciphertext deja copiat de un peer ostil.

## 6. Mesaje vocale criptate

| ID | Cerință obligatorie | Dovadă minimă |
|---|---|---|
| V-01 | Captură explicită cu permisiune și indicator; maximum 120 s și 1 MiB de audio codificat, oricare limită este atinsă prima. | VOICE-01: stop/cancel, refuz permisiune, întrerupere OS și limite; fără captură automată. |
| V-02 | Profil Opus fixat și validat; criptare incrementală cu formatul media aprobat, cheie per obiect învelită numai pentru destinatar. Fără cheie statică nouă. | VOICE-02: vectori media și tamper; intermediarul nu poate reda sunetul. |
| V-03 | Plaintext audio numai în buffere volatile limitate; fără fișier temporar, waveform persistent, transcript sau cloud transcription. | VOICE-03: inspecție filesystem/cache/backup/log după captură, crash și redare. OS compromis rămâne în afara garanției. |
| V-04 | Metadate strict necesare în interiorul plicului E2EE; fără model dispozitiv, locație sau timestamp precis de captură. | VOICE-03: corpus cu metadate-canary; durată și bitrate doar unde sunt necesare destinatarului. |
| V-05 | Aceeași notă poate folosi Tor sau mesh autorizat; stările queued/custody/delivered/expired sunt distincte. | VOICE-04: A-B-C cu B offline între întâlniri; reconectare Tor fără duplicare și fără resetarea ratchet-ului. |
| V-06 | Timer-ul DM și ștergerea locală existente se aplică și descriptorilor/cache-ului vocal. Replay-ul nu reîncepe retenția. | VOICE-04: expirare în toate stările; nu se promite ștergere fizică garantată sau ștergere la destinatar ostil. |

Mesajul vocal poate fi trimis cu întârziere și în loturi. Acest lucru oferă opțiuni de reducere a corelării, fără a demonstra anonimat. Push-to-talk live nu primește implicit aceleași proprietăți.

Captura parcurge encode -> criptare chunk -> persistență; niciun chunk audio plaintext nu este scris înainte de criptare. Cheia media aleatoare proaspătă se livrează în DM autentificat. Manifestul/contextul autentificat leagă conversația, dispozitivele expeditor/destinatar, object ID, codec și durata; adaptarea la AAD/descriptorul formatului existent este revizuită înainte de cod. La redare se limitează și numărul de sample-uri decodate, nu doar mărimea fișierului comprimat. Sunt excluse și media index, dump-urile, backup-urile și artefactele de crash cu audio. Plaintext există inevitabil tranzitoriu în proces și în pipeline-ul audio al OS; nu se garantează ștergerea fizică a memoriei flash.

## 7. Apeluri audio locale E2EE

Baseline de integrare: Opus și o bibliotecă WebRTC nativă întreținută, cu DTLS-SRTP și handshake efemer autentificat prin identitatea GHOST verificată [R3, R4]. Pachetul exact, licența și funcționalitățile activate se fixează la C0; dacă biblioteca nu poate impune izolarea locală, gate-ul rămâne deschis. Nu se creează un protocol criptografic propriu și nu se derivă cheile audio direct din seed sau dintr-o cheie DM reutilizată.

Build-ul WebRTC este fixat și intră în revizia independentă; profilul permite numai Opus. Transcriptul DM autentificat leagă call ID, roluri, ambele dispozitive, nonce-uri, expirare, hash-urile offer/answer, ambele fingerprint-uri DTLS și setul complet de candidați. Mașina de stări tratează explicit invitații simultane, replay și refuz; microfonul nu pornește înainte de acceptare.

Lista ICE servers este goală; numai host candidates pe calea autorizată. Nu se folosesc nume DNS/mDNS, loopback, multicast, broadcast, adrese rezervate, publice, de rută implicită ori alte gazde din LAN. Adresele/porturile sunt legate de descriptorul peer-ului verificat și de interfață; o adresă RFC1918 nu este o autorizație. ICE restart și migrarea de adresă/interfață sunt dezactivate; pierderea căii încheie apelul. Aceste reguli se testează contra candidate injection/LAN SSRF, inclusiv IPv6.

| ID | Cerință obligatorie | Dovadă minimă |
|---|---|---|
| C-01 | Un apel unu-la-unu se acceptă explicit doar cu dispozitiv verificat și legătură Wi-Fi locală directă disponibilă. | CALL-01: fără Internet, două telefoane fizice; apel neautorizat sau către alt dispozitiv refuzat. |
| C-02 | Semnalizarea autenticată leagă call ID, roluri, nonce-uri proaspete, identități/dispozitive, fingerprint-uri media și parametrii de securitate acceptați. | CALL-02: MITM, replay, fingerprint substituit, schimbare rol/identitate și downgrade eșuează. |
| C-03 | Numai candidați ICE/socket-uri pentru peer-ul și rețeaua locală autorizate; fără STUN/TURN public, discovery Internet, upload de SDP sau migrare automată pe celular. | CALL-03: captură la inițiere, handover și căderea Wi-Fi; zero egress extern în local-only. |
| C-04 | Media rămâne E2EE între cele două telefoane; nu trece prin coada de mesaje, relay, gateway ori transcodare intermediară. | CALL-02: capturi fără audio plaintext; nicio cheie media pe nod intermediar. |
| C-05 | Chei efemere și replay protection gestionate de protocol; stare separată per apel și cleanup la hangup/crash. | CALL-02: reinițiere, cheie schimbată și pachete vechi nu refolosesc sesiunea audio. |
| C-06 | Jitter buffer limitat, control pierderi/congestie și bitrate adaptiv; degradare vizibilă și terminare dacă ruta dispare. | CALL-04: pierderi 1%/5%/10%, jitter injectat și dispariția peer-ului; fără coadă nelimitată. |
| C-07 | Accept/mute/hangup și permisiunea microfon sunt explicite; fără auto-answer, înregistrare de apel sau upload implicit. | CALL-05: lockscreen, headset, apel celular concurent și retragerea permisiunii. |
| C-08 | Rotația identității sau revocarea locală închide sesiunea și cere reverificare; lipsa unei informații de revocare de la distanță este limită offline. | CALL-05: revocare în timpul apelului; zero reconectare automată la cheia nouă. |
| C-09 | UI declară apropierea, IP-ul local observabil și limitările în fundal; nu afirmă anonimat sau protecție PQ a vocii din simpla utilizare a plicului PQ DM. | CALL-06: review de copy și captură; fără indicator de securitate moștenit nejustificat. |

Apelurile multihop, de grup sau prin Internet sunt o extindere distinctă. Nici scăderea calității, nici blocarea radio nu justifică fallback la audio necriptat ori Internet direct. Plicul de semnalizare poate avea proprietăți diferite de handshake-ul media; acestea sunt evaluate separat.

## 8. Protecția APK-ului împotriva analizei și modificării

Obiectivul este să crească efortul pentru citirea logicii proprietare, extragerea informațiilor și redistribuirea unei copii modificate. Un APK executat pe un dispozitiv controlat de atacator poate fi analizat și modificat. Nicio garanție de confidențialitate sau autorizare nu depinde de imposibilitatea decompilării [R5].

| ID | Cerință obligatorie pentru producție | Dovadă minimă |
|---|---|---|
| H-01 | R8 shrinking, optimization și obfuscation pe release; fără reguli globale care dezactivează protecția. Excepțiile keep sunt minimale și motivate. | APK-01: configurație efectivă și inspecția DEX cu JADX; numele eligibile sunt transformate. Decompilarea reușită nu este automat eșec. |
| H-02 | Release nedebuggable; fără test runner, debug seams, fixtures, loguri sensibile sau chei de test; păstrarea exclusivă a simbolurilor native necesare ABI/JNI. | APK-01: manifest, strings, DEX și simboluri .so inspectate; apelurile JNI/recovery funcționează. |
| H-03 | Fără seed, cheie privată de semnare, credential global, cheie de decriptare universală sau bypass financiar în APK. Cheile publice/trust roots sunt publice prin design. | APK-02: scan secret-canary și inspecție manuală; patch-ul unei condiții UI nu acordă acces suplimentar pe server/peer. |
| H-04 | Semnătura Android, lanțul de release, hash-urile și anti-rollback urmează designul Fazei 14; actualizările neverificate se resping. | APK-03: tamper, resemnare, rollback și rotație legitimă, pe platformele suportate. |
| H-05 | Verificările de integritate proprii și semnalele de debugger/hooking sunt defense-in-depth, pot fi ocolite și nu atestă onestitatea unui peer. | APK-04: instrumentare și bypass controlat; autorizarea la relay, issuer și mesh rămâne obligatorie după bypass. |
| H-06 | Semnalele incerte de root/debugger nu produc ștergere, blocare ireversibilă sau exfiltrare de identificatori. Răspunsul este documentat, local și proporțional. | APK-04: ROM legitim, dispozitiv fără GMS, false positive și mediu auditor; nu se modifică politica separată de migrare ADR-60. |
| H-07 | Funcțiile locale și distribuția proprie nu depind de Play Integrity, cont Google, Google Play Services sau verificare online obligatorie. | APK-05: instalare autorizată și operare offline fără GMS; fără trafic către Google din aceste controale. |
| H-08 | Bibliotecile/obfuscatoarele respectă licențele; nu se introduce packer, loader de cod la runtime sau SDK RASP opac fără evaluare separată. | APK-06: SBOM, notificări și licențe; audit și reproducibilitate nu sunt împiedicate. |
| H-09 | Mapping R8 și simboluri păstrate separat, controlat, legate de hash/versionCode; acces pentru audit și diagnostic autorizat. | APK-06: retrace al unui crash-canary; mapările lipsesc din APK, backup și pachetul public. |
| H-10 | Build-ul release obfuscat este cel testat. JNI, reflection, serializare, Room/SQLCipher, DM/MLS, media, apel și updater trec pe acel artefact. | APK-07: matrice E2E și regresie pe release, fără a substitui un build debug. |
| H-11 | Reproducibilitate pe două medii independente, cu toolchain/dependențe/config R8 fixate; comparație după regulile Fazei 14. | APK-06: rapoarte A/B pentru aceeași sursă, plus hash-ul APK semnat livrat; diferențele justificate nu sunt ignorate. |
| H-12 | Audit independent de reziliență și retest pe candidat; ocolirea unui control local nu trebuie să dezvăluie un secret global sau să anuleze autorizarea. | APK-08: raport cu bypass-uri și limite reale, fără High/Critical deschise în domeniul livrat. |

R8 micșorează și transformă codul; nu îl criptează într-o formă inaccesibilă și nu face din Rust/JNI o zonă de încredere [R6]. Criteriul de succes este aplicarea și verificarea controalelor, nu promisiunea că un anumit decompiler nu produce rezultat. Nu se fixează un prag arbitrar de ore ca dovadă de securitate.

Autenticitatea unei actualizări peste o instalare legitimă și verificarea primei instalări sunt probleme diferite. Pentru prima instalare, utilizatorul/auditorul trebuie să poată verifica amprenta și manifestul prin canalele de distribuție autentificate existente; o copie falsă instalată de la zero nu este făcută sigură de propria ei verificare internă.

## 9. NFR și profiluri de măsurare

Ținte inițiale, neverificate. Fiecare raport fixează modelul telefonului, versiunea OS, ABI, radio, distanța/interferența, starea ecranului/bateriei, build hash, numărul de probe și percentilele. Minimum patru modele fizice de la cel puțin doi producători, două dispozitive fără GMS și variantele de radio suportate; selecția include cea mai veche versiune Android suportată pentru funcție. Emulatoarele nu înlocuiesc probele radio/microfon.

| ID | Țintă | Metodă / condiție |
|---|---|---|
| N-M1 | Stabilire legătură p95 <= 15 s după activarea pe ambele dispozitive | 100 încercări per pereche/radio în foreground; după verificarea contactului și acordarea permisiunilor |
| N-M2 | Text 4 KiB direct p95 <= 3 s | 500 mesaje, legătură deja stabilită, fără congestie; latența DTN multi-hop se raportează separat, fără termen garantat |
| N-M3 | OFF: zero scan/advertising și zero sockets locale GHOST | Captură 30 min incluzând reboot și process death; serviciile OS din afara aplicației sunt separate |
| N-M4 | Buget resurse din §5.1 respectat | Flood 60 min, identități rotite, coadă plină; măsurare CPU/memorie și refuz bounded |
| N-M5 | Consum incremental <= 2 puncte procentuale baterie/oră | 6 ore față de același build cu mesh OFF, aceeași stare ecran și un mesaj 4 KiB/minut; radio și capacitate înregistrate |
| N-V1 | Nota 120 s/1 MiB nu lasă audio plaintext persistent | Captură, întrerupere, proces omorât și redare; inspectare cache, backup, log și temp |
| N-C1 | Stabilire audio p95 <= 5 s de la acceptare | 100 apeluri pe legătură locală deja stabilită; timp discovery exclus și raportat separat |
| N-C2 | Latență audio într-un sens p95 <= 200 ms | Buclă acustică măsurată, câte 30 min pe pereche, traseu direct și pierdere injectată 0%/1%; profilurile 5%/10% testează degradarea |
| N-C3 | Oprire captură <= 1 s după hangup/stop local | Probe microfon și stare serviciu; timeout remote de maximum 5 s fără media/keepalive valid |
| N-H1 | Zero secrete globale, debug seams și mapări în APK | Inspecție statică release plus scan cu fixture negative |
| N-H2 | Regresie hardening <= 10% startup p95 și <= 10% RSS median | Aceeași sursă și device; 50 porniri, 30 min activitate; baseline fără controalele noi măsurat în laborator |
| N-H3 | Reproducibilitate și proveniență verificate | Cele două medii independente și metoda de comparație din Faza 14; semnătura/hash-ul artefactului livrat legate de raport |

Mărimea APK se măsoară din nou cu motorul RTC; NFR-ul de bază nu este relaxat automat. Dacă țintele nu sunt realizabile pe o clasă de dispozitive, compatibilitatea sau designul se revizuiesc înaintea lansării, cu dovadă și disclosure.

## 10. Date, lifecycle și integrare

Schema locală adaugă logic: `verified_device`, `mesh_grant`, `mesh_queue`, `mesh_transfer`, `mesh_receipt`, `mesh_policy` și `voice_descriptor`. Numele și migrațiile SQL exacte apar în designul de implementare. Se păstrează criptarea SQLCipher, FK/unique, tranzacțiile și regulile de backup existente.

Înregistrarea dispozitivului verificat conține fingerprint și starea de verificare/revocare; grant-ul este scop/buget/expirare; coada conține ciphertext și starea transportului, nu chei media în clar. ID-ul de deduplicare rămâne interior și autenticat; handle-urile de transport sunt separate și limitate la peer/scop. Persistența stării ratchet și acceptarea mesajului sunt atomice inclusiv când sosesc simultan prin Tor și mesh.

Apelurile nu persistă audio, chei media sau SDP în istoricul diagnostic. Istoricul minimal de apel este dezactivat implicit și, dacă se introduce, necesită politica explicită de retenție locală. Oprirea mesh-ului nu distruge mesajele proprii; copia din forwarding expiră după regula aplicabilă.

Restore-ul identității nu reactivează automat dispozitive/grant-uri mesh vechi. Reverificarea și emiterea unor grant-uri noi sunt necesare. Nici copierea bazei de date, nici rollback-ul unui backup nu trebuie să reseteze replay protection sau să prelungească autorizații.

## 11. Testare adversarială și condiții de lansare

| Familie | Scenarii obligatorii | Rezultat de urmărit |
|---|---|---|
| MESH-01-03 | OFF, permisiuni, contacte false, identități rotite, inventar neautorizat | Fără activare implicită, trust tranzitiv sau expunere de contacte/canale |
| MESH-04-05 | MITM, tamper/replay, downgrade, framing corupt, flood, bucle | Respingere autenticată/bounded; resursele globale nu cresc fără limită |
| MESH-06-09 | ACK fals, disc plin, kill/reboot, revocare întârziată, ceas dat înapoi, gateway ostil | Stări corecte, fără pierderi confirmate, expirare conservatoare, zero egress interzis |
| VOICE-01-04 | Captură întreruptă, codec input corupt, store/carry/forward, expirare | Fără plaintext pe disc sau deduplicare greșită; aceleași politici media |
| CALL-01-06 | Amprentă media falsă, candidate public/IPv6, handover celular, root de test, loss/jitter | Nicio identitate substituită sau migrare de transport; hangup și resurse bounded |
| APK-01-08 | Decompilare, repack/resign, bypass de verificare locală, JNI minificat, upgrade legitim | Hardening prezent și compatibil; securitatea nu se bazează pe client ascuns |

Fiecare familie are fixture negativ și un contraexemplu care demonstrează că verificarea detectează încălcarea. Raportul local leagă cerința, commit-ul, configurația, hash-ul APK, scenariul și rezultatul. Nu se revendică un PASS dintr-un build diferit.

Suitele includ fuzzing pentru parserele mesh/audio/SDP/RTP, oprirea procesului la fiecare frontieră de persistență/captură/redare, scanarea backup/media index și transferuri cu al treilea dispozitiv ostil. Testele release acoperă fiecare ABI livrată și matricea API Android suportată; excepțiile de laborator nu admit produsul. Auditul extern include explicit grant-urile mesh, izolarea locală, capture/playback, integrarea WebRTC și hardening-ul APK.

Gate de lansare pentru H: APK-01-08, N-H1-3 și regresiile bazei închise. Gate pentru M/V/C: toate cerințele și NFR-urile relevante, matricea fizică, audit independent și retest; zero High/Critical deschise. G-M/V/C se adaugă, nu înlocuiește poarta DM, media, Tor, update sau auditul general.

Protocolul wire al mesh-ului (transcript handshake, encoding, derivare handles și semantica autorizărilor) și binding-ul apelului trebuie înghețate în design și revizuite criptografic înainte de cod. Prezentul document fixează cerințele de produs și testele, nu inventează un protocol criptografic complet.

## 12. Roadmap și condiții de tranziție

Roadmapul detaliat este `docs/GHOST_Roadmap_v2.2.md`, aceeași revizie și dată. H0-H2 extind Fazele 1, 13-15 și sunt obligatorii înainte de producție. M0-M7 și C0 sunt o pistă opțională pentru utilizator, cu acceptare separată; M0 poate cerceta hardware acum, însă integrarea M2/M3/M4 cere porțile DM și media îndeplinite sau dovadă explicită că rulează numai în laborator.

Ordinea pentru domeniul nou: M0 -> M1 -> M2 -> M3 -> M4 -> C0 -> M5 -> M6 -> M7. H0 -> H1 -> H2 rulează cu dependențele de release. Calendarul este reestimat pe munca rămasă; estimările istorice de 8-10 sau 10-12 luni nu se reutilizează ca termen curent.

## 13. Referințe și proveniență

Surse locale consultate: `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` (§2.1, §3, §6), `docs/STATUS.md` (stare declarată, fără reverificare a testelor), `docs/THREAT_MODEL_v2.1.md`, `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`, `docs/adr/README.md`, `CLAUDE.md`. Checkout observat: `main`, commit `d33dbd9df42a15a0ab41c3f000a8bf43ea6b0375`. Existau schimbări locale de produs în două fișiere de release/verify; nu sunt incluse în această revizie documentară.

| Ref | Sursă primară |
|---|---|
| R1 | Android Wi-Fi Aware: https://developer.android.com/develop/connectivity/wifi/wifi-aware |
| R2 | Android BLE în fundal: https://developer.android.com/develop/connectivity/bluetooth/ble/background |
| R3 | WebRTC Security Architecture: https://www.rfc-editor.org/rfc/rfc8827.html |
| R4 | Opus: https://www.rfc-editor.org/rfc/rfc6716.html și https://www.rfc-editor.org/rfc/rfc8251.html |
| R5 | OWASP MASVS-RESILIENCE: https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/ |
| R6 | Android R8: https://developer.android.com/topic/performance/app-optimization/enable-app-optimization |
| R7 | Tor - limite de corelare: https://support.torproject.org/about-tor/security/attacks-on-onion-routing/ |
| R8 | Android app signing: https://developer.android.com/studio/publish/app-signing |
| R9 | Sybil: https://www.microsoft.com/en-us/research/wp-content/uploads/2002/01/IPTPS2002.pdf |
| R10 | MLS, transport și DoS: https://www.rfc-editor.org/rfc/rfc9420.html#section-16.9 |

Referințele susțin mecanismele și limitele; limitele numerice din §5.1 și §9 sunt decizii de proiect propuse pentru măsurare, nu garanții ale Android sau ale bibliotecilor.

## 14. Istoric

| Revizie | Data | Efect |
|---|---|---|
| v2.0 | 20 august 2026 | PDF istoric; modificat ulterior prin Master Plan și ADR-uri. |
| Master Plan v2.1 | septembrie-octombrie 2026 | Tor, schimbări DM/licență/plăți și evidență de execuție; rămâne sursă pentru domeniile neatinse. |
| v2.2 | 31 octombrie 2026 | Domeniul M/V/C/H, limitele de privacy, matricea de teste și roadmapul aferent; fără implementare sau validare de produs în această revizie. |
