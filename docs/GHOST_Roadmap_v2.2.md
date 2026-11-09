# GHOST - Roadmap de finalizare v2.2

Pași secvențiali până la producție: baza existentă, mesh opțional, mesaje vocale, apeluri locale E2EE și hardening APK

Data: 31 octombrie 2026. Status: FINAL DOCUMENTAR. Pașii noi sunt planificați; niciun rezultat de implementare, test sau audit nu este certificat prin acest document.

## 1. Obiectiv, autoritate și punct de plecare

Ținta este o versiune de producție GHOST care păstrează baza Tor/DM/MLS/media și oferă, prin activare voluntară, comunicație locală între contacte verificate, mesaje vocale și apeluri locale E2EE unu-la-unu. Hardening-ul APK este obligatoriu pentru orice versiune de producție. APK-ul rămâne analizabil; protecția crește costul de analiză și modificare.

Acest roadmap extinde, fără renumerotare, Fazele 0-18 din `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`. Cerințele noi sunt în `docs/GHOST_Technical_Specification_v2.2.md`; starea efectivă rămâne în `docs/STATUS.md`. ADR-01 și ADR-38 conțin amendamentele documentare v2.2. Baseline observat: `main`, `d33dbd9df42a15a0ab41c3f000a8bf43ea6b0375`; există modificări locale de produs în release/verify, neincluse aici.

Statusul preluat din documentație este Developer preview / no privacy claim. Fazele DM, media, metadata, Android UI și release au dovezi locale și/sau porți deschise; acestea nu sunt reverificate în această revizie. Se folosesc rezultatele istorice numai după confirmarea sursei, artefactului și precondițiilor. Nu se reîncep fazele terminate și nu se declară terminate cele cu teste locale, dar fără acceptare completă.

## 2. Ordine de execuție și dependențe

Traseul recomandat: B0 -> H0 -> M0 -> B1 -> M1 -> M2 -> M3 -> M4 -> C0 -> M5 -> B2 -> H1 -> B3 -> M6 -> H2 -> B4 -> B5 -> B6 -> M7 -> B7.

Ordinea este una de coordonare, nu obligația de a aștepta fără lucru. Inventarul de release H0 și probele hardware M0 pot avansa în paralel cu închiderea bazei B1. O singură persoană integrează; un singur writer per worktree. Niciun pachet dependent nu este acceptat înaintea porții sale.

| Traseu | Rol | Blocaj obligatoriu |
|---|---|---|
| B0-B7 | Închide munca rămasă din Fazele 0-18 și operaționalizarea | Nicio fază istorică nu primește PASS prin existența acestui plan |
| H0-H2 | Protecția APK și distribuția verificabilă | Obligatoriu înaintea admiterii în producție, inclusiv dacă mesh rămâne OFF |
| M0-M7 | Mesh și note vocale, validare și activare | Funcția rămâne OFF până la propriile teste, audit și acceptare |
| C0, M5 | Fezabilitate și implementare apel local | Fără fallback Internet, multi-hop live sau criptografie improvizată |

Un core release fără M/V/C este posibil numai ca livrare intermediară, după porțile bazei și H. Nu finalizează cererea v2.2. Pentru varianta completă se închid toate pachetele de mai jos; opționalitatea este a utilizatorului, nu a echipei față de cerințele de securitate.

Traseul secvențial descris aici vizează varianta completă. Pentru un release intermediar, B0 îngheață explicit domeniul redus: modulele M/V/C sunt absente sau inaccesibile și OFF; B2/H1/B3 se aplică suprafeței efectiv livrate, iar dependențele M6/M7 și scope-ul B4 aferente acelor module se aplică înaintea includerii/activării lor ulterioare. Baza, H, auditul extern, alpha/beta și admiterea release nu se omit.

## 3. B0 - Reconcilierea stării și înghețarea domeniului

Responsabil: coordonator tehnic; review de securitate pentru orice schimbare de invariant. Intrare: checkout și documentele actuale. Efort: se estimează după inventar; nu este inclus în estimarea funcțiilor noi.

- Înregistrează checkout, branch, SHA, bază/upstream, diff și procese active; păstrează schimbările utilizatorului și separă artefactele vechi.
- Citește STATUS și checklist-urile Fazelor 2-14; construiește lista unică de porți rămase, cu owner, dovadă existentă, hash și precondiții.
- Confirmă ce ADR-uri sunt aprobate, propuse ori aplicate provizoriu. Cererea actuală aprobă domeniul documentar; nu ține loc de review al viitorului protocol wire.
- Leagă fiecare cerință nouă M/V/C/H de pachetul și testul din §23. Înregistrează NFR-urile ca ținte, fără rezultate inventate.
- Stabilește modelele fizice, OS/ABI suportate, bugetul de audit și accesul auditorilor la sursă/mapping; verifică disponibilitatea dispozitivelor fără GMS.
- Îngheață non-obiectivele: fără unknown peers, apeluri de grup, video, multi-hop live, telefonie publică sau colectare automată de diagnostice.

Livrabil: ledger de execuție și matrice de porți actualizate în STATUS. Ieșire: nicio poartă fără owner, criteriu măsurabil și dependențe; fără anularea dovezilor valide sau resetarea codului existent.

## 4. H0 - Designul protecției APK și al dovezilor

Responsabil: Android/build; acceptare de către reviewer de securitate. Depinde de B0. Estimare: 3-5 zile-om.

- Inventariază build types, R8/ProGuard, reguli keep, debug flags, JNI/UniFFI, reflection, serializare și native exports, fără a modifica inițial build-ul.
- Reconciliază ADR-38 punctul 9 și designul Fazei 9: obfuscare permisă, simboluri și mapări private pentru auditori, hash-uri și atestări publicabile.
- Proiectează păstrarea mapărilor: proprietar, control de acces, retenție per release, backup criptat, acces auditor și retrace verificabil.
- Definește scanarea de secrete, endpoint-uri de test, debuggable/profileable și fișiere de diagnostic incluse accidental.
- Separă verificarea update/semnăturii de self-check-urile ocolibile; niciun secret sau drept de protocol nu se bazează pe ascunderea codului.
- Definește reacția la root/debugger: semnal local proporțional, fără wipe, identificatori trimiși sau blocare generală a ROM-urilor legitime. ADR-60 rămâne separat.
- Planifică reproducibilitatea artefactului minificat și strip-uit pe două medii; fixează toolchain/dependențe și comparația înainte/după semnare conform Fazei 14.

Livrabile: design H, plan APK-01-08 și lista exactă de fișiere de modificat. Ieșire: review acceptat, keep rules justificate, traseu de audit compatibil cu distribuția fără GMS.

## 5. M0 - Fezabilitate radio și închiderea limitelor

Responsabil: Android/radio; securitate revizuiește excepția de transport. Depinde de B0. Estimare: 4-6 zile-om.

- Selectează minimum patru modele, doi producători, două dispozitive fără GMS și cea mai veche versiune Android suportată; documentează suportul real Wi-Fi Aware/Direct/BLE.
- Măsoară descoperirea pornită de utilizator, conexiuni simultane, distanța, interferența și comportamentul fără Internet; nu presupune că API-ul oferă rutare mesh.
- Probează rendezvous QR/BLE fără identificator permanent, DNS/mDNS/SSDP, scanare de subnet sau discovery în fundal.
- Demonstrează legarea socket-urilor la rețeaua selectată și închiderea la schimbarea interfeței; probează inclusiv IPv6 și coexistarea cu Tor.
- Validează plafoanele inițiale: 4 vecini, 3 legături, 2 copii per dispozitiv onest, coadă 64 MiB/16 MiB per grant, grant și retenție maximum 24 ore.
- Fixează înainte de M1 și limitele de obiecte, mesaje de control, CPU, memorie, alocări și trafic; alege valori măsurate și cazuri negative pentru fiecare.
- Verifică efortul de baterie și restricțiile OS pentru sesiune vizibilă/foreground, transferuri deja autorizate și oprirea completă. Fără worker de fundal folosit ca buclă de apel.

Livrabil: raport de fezabilitate și matrice de compatibilitate, inclusiv clase nesuportate. Ieșire: cel puțin un transport local aplicabil, controlabil și fără egress interzis. Dacă nu există, se revizuiește transportul sau compatibilitatea; nu se relaxează izolarea.

## 6. B1 - Închiderea bazei DM, storage, sync, media și metadate

Responsabil: owner-ii Fazelor 2-12; reviewer de securitate pentru DM/chei/stare durabilă. Depinde de B0. Durata se reestimează din porțile reale.

- Închide review-ul independent al threat model-ului și porțile de dispozitiv/Keystore/backup încă deschise.
- Reconciliază Faza 9: sesiuni, envelope, schimbare de cheie, timer, replay, atomicitatea ratchet/inbox și dovezi pe două dispozitive; păstrează ADR-35/36 și validarea criptografică externă.
- Verifică Faza 7 pentru concurență de transport și process death; aceeași primire prin Tor și local trebuie să producă un singur mesaj, fără reset de sesiune.
- Închide condițiile efective din Faza 11, inclusiv întrebările/porțile încă deschise: chunk ciphertext 256 KiB, fragmente 64 KiB, descriptor, resume, metadate și zero cache plaintext.
- Păstrează autonomia forumului: OpenMLS, pseudonime per canal și reveal opt-in; mesh nu exportă membri sau identitatea cross-channel.
- Închide separat munca rămasă din Faza 12: tuning jitter/batch, review independent al capturilor și probele live/pe dispozitive pentru transporturile pluggable conform porților existente. Mesh nu substituie aceste probe și nu le primește automat garanțiile.
- Confirmă autorizarea/entitlement existentă și limitele offline; grant-ul local nu dublează un token de unică folosință și nu reînnoiește plata.

Ieșire: contracte de integrare stabile și porți de bază acceptate la nivelul necesar integrării. Experimentele care preced închiderea auditului extern sunt marcate strict laborator, fără activare publică sau afirmație de privacy.

## 7. M1 - Protocol, grant-uri și design de date

Responsabil: securitate/protocol, cu Android și storage. Depinde de M0 și contractele B1. Estimare: 6-10 zile-om.

- Scrie protocolul wire versionat: encoding canonic, framing, handshake, transcript, downgrade, derivări cu separare de domenii și vectori de test.
- Definește grant-ul semnat: ID/epoch, dispozitive, direcție, scop/obiecte, expirare, cote, TTL și hop limit; fără delegare sau trust tranzitiv.
- Definește identitatea verificată separat de identitatea efemeră de discovery și de dreptul de forwarding; revocare monotonă, schimbare de cheie și restore cu reverificare.
- Definește inventarul PRF per grant/epoch și minimizarea metadata; evită hash-uri globale, Bloom filters publice și anunțuri ale întregii cozi.
- Formalizează state machine pentru custody/delivery/expiry, ACK-uri autentificate și ștergere; testează contraexemplul intermediarului care pretinde livrarea.
- Definește deduplicarea și replay/cycle state persistente peste rotații/restart; limite înainte de alocare/decriptare; clock rollback fail-closed.
- Proiectează schema criptată și migrațiile fără pierderi, inclusiv disc plin, crash și rollback de backup; nu persista chei media în clar.
- Actualizează contractul T6: Tor rămâne obligatoriu extern, localul este excepție separată auditată. Harness-ul trebuie să distingă traficul GHOST de cel OS.

Livrabile: design protocol, vectori, schemă propusă, matrice adversarială și review criptografic. Ieșire: protocol înghețat, fără incertitudini critice; review independent înainte de implementare.

## 8. M2 - Legătura locală directă între două dispozitive

Responsabil: Android/transport; reviewer independent de securitate. Depinde de M1 și B1. Estimare: 10-15 zile-om.

- Implementează controalele OFF/local-only/hibrid; permisiuni contextuale, sesiune vizibilă de discovery și oprire completă.
- Implementează rendezvous și handshake autentificat; respinge peer-ul neverificat, alt dispozitiv, grant expirat sau rol schimbat.
- Leagă rețeaua și endpoint-ul de descriptorul verificat; nu introduce client HTTP, rezolvare DNS sau fallback celular în adaptor.
- Integrează envelope-ul DM existent și outbox/inbox; suportă reluare, duplicate și sosire simultană Tor/local.
- Explică în UI expunerea IP-ului local/proximității și diferența dintre contact verificat și contact de încredere ca disponibilitate.
- Rulează MESH-01-04 și MESH-09, inclusiv Tor oprit, Wi-Fi schimbat, IPv6, permisiune retrasă și process death. Măsoară N-M1-3.

Livrabil: text E2EE direct în laborator, pe build identificat. Ieșire: zero egress interzis, substituție de identitate refuzată, nicio activare implicită; funcția publică rămâne închisă.

## 9. M3 - Store/carry/forward controlat

Responsabil: sync/storage/transport; review de securitate și concurență. Depinde de M2. Estimare: 12-20 zile-om.

- Adaugă autorizarea separată de forwarding, coada ciphertext criptată local, inventarul pereche și transferuri reluabile sub cote.
- Implementează limite globale și per grant, expirare, bucle/replay și protecție contra rotației identităților. Un peer verificat nu primește resurse nelimitate.
- Distinge ACK de custodie de ACK de destinație durabilă; numai ultimul marchează livrat. Receipt-urile dezactivate nu produc succes presupus.
- Testează A-B-C cu B care transportă mesajul după o întâlnire ulterioară cu C; A-C trebuie verificați independent, iar A-B și B-C autorizați separat.
- Testează blackhole, rută falsă, ACK forjat, grafic de contacte fals, disc plin, crash, reboot, ceas înapoi și revocare întârziată.
- Integrează gateway-ul numai opt-in, separat, către relay prin Tor, cu drepturi limitate la obiect. Include absența issuer-ului și lipsa entitlement-ului valid fără bypass.
- Rulează MESH-05-09 și N-M4-5; raportează limitele radio reale și latența multi-hop separat de mesageria directă.

Ieșire: transfer finit, bounded și idempotent; niciun hop nu vede plaintext sau cheia media; retenția nu se prelungește prin replay. Custodia ostilă și bruiajul rămân riscuri declarate.

## 10. M4 - Mesaje vocale asincrone

Responsabil: Android audio/media; review de crypto integration. Depinde de M3 și gate-ul media B1. Estimare: 8-12 zile-om.

- Definește UX record/stop/cancel/preview/send, indicator de microfon și limite 120 s/1 MiB; fără pornire automată sau transcript cloud.
- Folosește profil Opus fixat și pipeline encode -> encrypt -> persist, cu cheie nouă per obiect livrată în DM autentificat.
- Leagă manifestul de conversație, dispozitive, object ID, codec și durată, păstrând formatul media și chunking-ul existent.
- Redă prin buffere volatile limitate; limitează sample-urile decodate, input corupt, durată falsă și alocări. Nu produce waveform/cache/index audio persistent.
- Integrează stările queued/custody/delivered/expired și timer-ul DM; comutarea Tor/mesh nu duplică obiectul și nu reîncepe retenția.
- Rulează VOICE-01-04 și N-V1 cu crash la fiecare frontieră, backup/media-index/log scan și fuzzing codec/container; verifică două dispozitive plus intermediar ostil.

Ieșire: note vocale E2EE funcționale în laborator și fără plaintext persistent în domeniul controlat de aplicație. Se declară explicit bufferele OS și imposibilitatea de a împiedica înregistrarea de către destinatar.

## 11. C0 - Alegerea și verificarea motorului de apel

Responsabil: Android/RTC; securitate și licențiere. Depinde de M2; în traseul recomandat urmează M4. Estimare: 5-8 zile-om.

- Selectează o versiune fixată și întreținută de WebRTC nativ/DTLS-SRTP cu Opus; inspectează licențele, SBOM, dependențele și procedura de update de securitate.
- Demonstrează că toate ICE servers sunt eliminate, rămân numai host candidates autorizate și pot fi dezactivate mDNS, ICE restart și migrarea de interfață.
- Construiește un experiment fără utilizatori/date reale care refuză candidates către Internet, localhost, alte gazde LAN, multicast și interfață greșită.
- Definește transcriptul DM: call ID, dispozitive, roluri, nonces, expiry, offer/answer hashes, fingerprint-uri DTLS și întreg setul de candidați.
- Definește accept/refuse, glare, timeout, terminare și chei efemere; fără cheie derivată din seed și fără claim PQ pentru audio.
- Măsoară creșterea APK, CPU/baterie, latența și compatibilitatea JNI/R8. NFR-ul existent de mărime nu este relaxat automat.

Ieșire: motor demonstrat controlabil și design acceptat. Dacă izolarea locală nu poate fi impusă, C0 rămâne blocat; nu se înlocuiește cu apel Internet sau protocol crypto propriu.

## 12. M5 - Apeluri locale E2EE unu-la-unu

Responsabil: Android audio/RTC; review de securitate. Depinde de C0 și M2; integrare după M4. Estimare: 15-25 zile-om.

- Implementează invitație/accept/refuse/mute/hangup și indicator de microfon; apel numai cu dispozitiv verificat pe calea locală directă.
- Autentifică transcriptul complet și fingerprint-urile; respinge replay, rol schimbat, offer/answer modificat și candidate injection/LAN SSRF.
- Activează DTLS-SRTP cu material efemer per apel și replay protection; audio nu intră în mesh queue/gateway/relay.
- Impune host candidates și interfața autorizată; schimbarea sau pierderea rețelei termină apelul. Un apel nou cere acceptare nouă.
- Limitează jitter buffer și resursele; implementează degradare controlată la pierderi/congestie și oprirea microfonului în maximum 1 s local.
- Tratează revocarea, schimbarea cheii, permisiune retrasă, ecran blocat, proces omorât și apeluri simultane; nu înregistra audio/SDP/chei în logs.
- Rulează CALL-01-06 și N-C1-3: 100 inițieri, probe de latență, 0%/1%/5%/10% loss, timeout remote, parser fuzz și scenarii ostile.

Ieșire: apel local verificat funcțional și adversarial în laborator; fără apel live multi-hop, înregistrare implicită sau fallback Internet.

## 13. B2 - Integrarea Android și privacy UX

Responsabil: Faza 13/Android; review de securitate și UX. Depinde de UX-ul bazei și de contractele M4/M5 pentru modulele incluse în release. Durata: reestimată din munca rămasă a Fazei 13.

- Integrează onboarding, contacte/dispozitive verificate, grant/revoke, stări de livrare și funcții audio în aplicația finală; fără ecrane de laborator în release.
- Prezintă explicit limitele locale: proximitate/IP, retransmitere prin contacte, întârziere posibilă, înregistrare de către destinatar și imposibilitatea ștergerii la peer ostil.
- Păstrează FLAG_SECURE/politicile existente, accesibilitatea prevăzută de proiect și permisiunile contextuale; nu cere microfon pentru mesaje text.
- Verifică OFF după instalare și restore, schimbare de dispozitiv, offline, revoke, low battery și hardware indisponibil.
- Actualizează manifest/permission allowlist doar cu justificarea funcției; nu accepta GMS/analytics pentru comoditate.
- Extinde T6 și capture schema cu excepția locală exactă; vechile teste Tor și pseudonime trebuie să rămână eficiente pe contraexemple.

Ieșire: trasee end-to-end complete și matrice UI/device actualizată, fără afirmații de audit sau privacy neacoperite.

## 14. H1 - Implementarea hardening-ului release

Responsabil: Android/build/native; review de securitate. Depinde de H0, B2 și suprafața release înghețată; integrarea RTC este precondiție când aceasta este inclusă. Estimare: 8-12 zile-om.

- Activează minify/optimization/resource shrinking în release; elimină keepnames global și restrânge keep rules la API-uri/JNI/reflection efectiv necesare.
- Strip simbolurile native inutile și limitează exporturile; păstrează mappings/simboluri separat cu hash-uri legate de artefact și ACL.
- Elimină debug/profileable, test endpoints, fixtures, verbose logs, backup leaks și instrumente de laborator; scanează APK-ul final pentru secrete și chei private.
- Integrează verificarea identității distribuitorului/update/anti-rollback conform Fazei 14; self-check-urile locale rămân suplimentare, ocolibile și fără putere de autorizare.
- Testează repack/resign și ocolirea verificărilor locale; nu revendica protecție a unui telefon compromis sau imposibilitatea decompilării.
- Verifică ROM fără GMS, sideload legitim și mediul auditorului; nu introduce Play Integrity obligatoriu, telemetrie sau wipe la detectarea root.
- Rulează APK-01-07, JNI/reflection/serialization/DB/media/call/update E2E pe release minificat și N-H1-2; măsoară startup, RSS și dimensiunea APK.

Ieșire: hardening prezent, compatibil și verificat pe artefactul de release; niciun secret global nu devine accesibil prin bypass. APK-08 și reproducibilitatea finală rămân porți ulterioare.

## 15. B3 - Candidatul distribuibil și dovezile Fazei 14

Responsabil: release owner; reviewer de securitate. Depinde de B2/H1 pentru domeniul selectat la B0 și îngheață exact acel domeniu. Durata: conform backlog-ului real al Fazei 14.

- Îngheață sursa candidatului, toolchain-ul, SBOM/licențele și configurațiile; leagă toate dovezile de exact aceeași sursă/artefact.
- Finalizează semnarea, anti-rollback, update onion, manifest, jurnal de transparență și martori potrivit ADR-37/38 și designului existent.
- Construiește independent în două medii și compară după contractul de reproducibilitate al proiectului; publică hash-urile și explică orice diferență permisă.
- Verifică prima instalare separat de actualizare, sideload și canalele autorizate; o verificare internă a unei clone nu stabilește autenticitatea inițială.
- Exersează păstrarea și retrace-ul mappings/simbolurilor fără includerea lor în APK/public downloads.
- Îngheață candidat de laborator pentru M6/H2; un test care necesită instrumentare separată trebuie să arate legătura cu codul release și să nu substituie proba pe binarul livrat.

Ieșire: candidat identificabil și reproductibil, pregătit pentru validare; aceasta nu reprezintă încă admitere în producție.

## 16. M6 - Validare integrată și teste adversariale pe dispozitive

Responsabil: QA/security independent de implementare. Depinde de M3-M5, B2, H1 și B3. Estimare: 10-18 zile-om.

- Rulează MESH-01-09, VOICE-01-04 și CALL-01-06 pe matricea fizică stabilită; fixează APK hash/OS/ABI/radio în raport.
- Capturează local-only, hibrid, gateway, OFF, reboot și cădere rețea; demonstrează zero egress interzis, DNS/mDNS/SSDP/STUN/TURN și fallback.
- Introdu al treilea dispozitiv ostil: grants false/revocate/expirate, ID rotation, replay, cicluri, false ACK, blackhole și flood 60 min.
- Testează crash/restart/disc plin și ceas/backup rollback la fiecare frontieră durabilă; nu pierde mesaje confirmate și nu prelungi expirarea.
- Scanează cache, backup, media index, logs și crash artifacts pentru canary audio/plaintext; fuzz framing/audio/SDP/RTP și candidates către alte dispozitive LAN.
- Măsoară N-M1-5, N-V1, N-C1-3; probe de 6 ore baterie și 24 ore soak mixt cu pauze/reconectări, fără audio live continuu în afara scenariilor definite.
- Rulează regresiile DM/MLS/Tor/entitlement/storage/update cerute de integrare; repară constatările și repetă numai testele afectate, apoi gate-ul final pe candidat înghețat.

Ieșire: raport independent complet, toate cerințele relevante trecute, fără defecte de securitate critice/înalte deschise. Orice incompatibilitate de dispozitiv este declarată și nu activează automat un transport mai slab.

## 17. H2 - Acceptarea protecției APK pe candidat

Responsabil: reviewer independent security/release. Depinde de H1, B3 și M6 pentru varianta completă. Estimare: 6-10 zile-om, fără timpul extern de audit.

- Reexecută verificările necesare APK-01-07 și N-H1-3 și pregătește precondițiile/pachetul de intrare pentru APK-08, pe artefactul candidat, fiecare ABI livrată și matricea API suportată; păstrează testele minificate.
- Inspectează rezultatul JADX/apktool/native analysis: faptul că se decompilează nu este defect în sine; se verifică secretele, debug seams, exports și controalele efective.
- Testează actualizare legitimă, APK modificat, downgrade, prima instalare și absența rețelei/GMS; verifică fail-closed fără distrugerea datelor.
- Verifică independent cele două rebuild-uri, mapping/symbol custody și retrace; o mapare pierdută nu este acceptabilă pentru un release auditat.
- Înregistrează bypass-urile de self-check/root/debugger ca limite; confirmă că autorizarea și cheile nu depind de imposibilitatea bypass-ului.
- Pregătește pachetul pentru auditul extern: sursă, vectori, artefact, threat model, rezultate, limite și instrucțiuni de reproducere.

Ieșire internă: controale H validate și pachet de audit complet. Acceptarea H-12/APK-08 rămâne condiționată de raportul extern și retestul B4; H2 singur nu autorizează lansarea.

## 18. B4 - Audit extern și remediere, Faza 15

Responsabil: auditori independenți; owner tehnic remediază; release owner acceptă dovezile. Depinde de B3/M6/H2.

- Confirmă în contractul auditului DM/PQ/MLS, client/server/build existente plus grants, local egress, capture/playback, binding WebRTC și hardening APK.
- Oferă acces la sursă și mapări/simboluri conform ADR-38; asigură teste negative reproductibile și acces la dispozitivele suportate.
- Cere raport complet, severități motivate, scenarii de exploatare și retest; review-ul documentar intern sau al unui agent nu substituie auditul.
- Remediază constatările și reface dovezile pe noul SHA/hash. Zero Critical/High deschise în domeniul livrat; restul riscurilor au tratament și acceptare explicită potrivit politicii proiectului.
- Publică dovezile și limitele necesare ADR-38; eticheta „auditat” numește raportul și versiunea exactă.

Ieșire: audit și retest închise, H-12/APK-08 acceptate, threat model actualizat. Durata depinde de contractare și constatări; nu este inclusă în suma zilelor-om pentru extensie.

## 19. B5 - Private alpha, operare și recuperare, Faza 16

Responsabil: operare/release/security. Depinde de designurile bazei; acceptarea după B4.

- Închide runbook-urile relay/issuer/distribuție, rotația cheilor, operatorii independenți și răspunsul la incidente conform planului existent.
- Execută private alpha cu 20-50 testeri, relay-uri staging și plăți Monero testnet/stagenet; păstrează gate-ul existent de două săptămâni stabile și recovery verificat.
- Exersează restaurarea din backup, compromiterea cheii de distribuție și rollback-ul permis fără anularea anti-rollback-ului de securitate.
- Adaugă runbook pentru dezactivarea mesh/voce/apel la defect: update semnat ori mecanismul existent auditat, control local și expirări; fără remote wipe sau canal nou de comandă.
- Declară limita offline: un dispozitiv fără conexiune nu primește imediat revocări/update-uri. Nu promite kill switch instantaneu global.
- Verifică suportul și exportul manual minim de diagnostice; fără SDK analytics/crash reporting sau liste de contacte în tichete.

Ieșire: exerciții reușite cu probe, responsabili și timpi observați; backup existent fără test de restore nu închide faza.

## 20. B6 - Beta controlată, Faza 17

Responsabil: owner produs/QA/security. Depinde de B4/B5; orice distribuire publică respectă auditul prealabil ADR-38.

- Selectează voluntari și dispozitive din matrice; explică explicit limitele de proximitate, IP local, disponibilitate și endpoint compromis.
- Rulează onboarding, verify/revoke, text/voice pe Tor și mesh, apel direct, upgrade, restore și funcția indisponibilă pe hardware nesuportat.
- Păstrează gate-ul existent: 200-500 utilizatori, trezorerie limitată, SLO-uri, minimum 30 zile stabile și reconciliere XMR. Volumul insuficient nu produce PASS prin simpla trecere a timpului.
- Colectează doar feedback și diagnostice exportate voluntar; măsurătorile cantitative provin din probe controlate, fără colectare automată de grafuri sau audio.
- Menține registrul defectelor și probele de remediere; orice regresie de identitate/E2EE/egress/backup blochează promovarea.

Ieșire: scenariile de acceptare ale utilizatorilor trecute, zero incidente/defecte blocante nerezolvate și decizie documentată pe candidatul exact.

## 21. M7 - Admiterea modulelor opționale

Responsabil: owner produs și reviewer security/release. Depinde de M6, H2, B4 și B6. Estimare: 5-8 zile-om, incluzând documentarea și revalidarea finală.

- Verifică acoperirea integrală M-01-16, V-01-06, C-01-09 și NFR; confirmă auditul/retestul și probele pe versiunea livrată.
- Publică matricea hardware/OS și ghidul de privacy în limbaj simplu, inclusiv ce vede vecinul și ce nu poate fi revocat de la distanță.
- Livrează separat controalele local-only/hibrid, forwarding și gateway; toate sunt opt-in și nu se activează prin restore/update fără consimțământul deja salvat aplicabil.
- Verifică oprirea rapidă fără ștergerea mesajelor proprii, închiderea sockets/microfon și lipsa fallback-ului pe Internet.
- Consemnează decizia de activare în rollout-ul existent; o cohortă primește capabilitatea, dar utilizatorul alege dacă o pornește.

Ieșire: admitere explicită a fiecărui modul, cu dovezi și limite. Dacă un modul eșuează, rămâne OFF; un release intermediar nu este declarat finalizarea v2.2.

## 22. B7 - Pregătit de producție și lansare, Faza 18

Responsabil: release owner; acceptare independentă security și owner produs. Depinde de toate porțile aplicabile, inclusiv H și M7 pentru ținta completă.

- Îngheață versiunea finală și verifică identitatea exactă a artefactului auditat, testat, semnat, reprodus și înregistrat în jurnal.
- Verifică integral checklist-ul de mai jos și planul de rollback/retragere; nu considera exit code 0 sau build verde dovadă suficientă.
- Pregătește canalele de distribuție aprobate, notele de release, rapoartele publice și suportul; nicio promisiune „imposibil de decompilat” sau „anonimat garantat prin mesh”.
- Păstrează rollout-ul 5/25/50/100 din Faza 18, cu verificare și decizie de continuare la fiecare treaptă; disponibilitatea funcției nu echivalează cu activarea ei de către utilizator.
- Marchează PREPARED FOR PRODUCTION numai după admiterea documentată; publicarea/deploy-ul se execută în cadrul unei autorizări de release, nu prin această actualizare de documente.
- După lansare, urmărește doar dovezile operaționale și feedback-ul autorizate, verifică rollout-ul și actualizează STATUS cu rezultatul real.

Checklist final obligatoriu:

- [ ] Porțile bazei din STATUS și Fazele 0-18 sunt închise cu dovezi actuale, nu doar inventariate.
- [ ] H-01-12 și APK-01-08 sunt acceptate; artefact release minificat, fără secrete/debug, reproductibil și verificabil.
- [ ] M/V/C și NFR sunt acceptate pe dispozitive fizice; modulele rămân opt-in.
- [ ] Zero Critical/High deschise; audit extern și retest publicabile, legate de versiune.
- [ ] Upgrade/anti-rollback/restore/revocare/expirare și răspunsul la incident sunt exersate.
- [ ] Matrice compatibilitate, limite de privacy și suport sunt publicate; nicio afirmație mai largă decât dovada.
- [ ] Beta/UAT, acceptarea produsului și admiterea release sunt semnate; hash-ul livrat este cel admis.

## 23. Trasabilitate și contractul fiecărui pachet

| Cerințe spec v2.2 | Implementare / design | Probe și poartă finală |
|---|---|---|
| M-01, M-02, M-04, M-05 | M0-M2, B2 | MESH-01-04; N-M1-3; M6/M7 |
| M-03, M-06, M-07 | M1-M3 | MESH-02-04; M6/M7 |
| M-08, M-09, M-10, M-11 | M1/M3 | MESH-05-07; N-M4-5; M6/M7 |
| M-12, M-13 | M1/M3, B2 | MESH-08; restore/revoke; M6/M7 |
| M-14, M-15, M-16 | M2/M3, B2/B4 | MESH-03/09, T6 regresie; M6/M7 |
| V-01, V-02, V-03 | M4 | VOICE-01-03, N-V1; M6/M7 |
| V-04, V-05, V-06 | M3/M4 | VOICE-03-04; M6/M7 |
| C-01, C-02, C-03, C-04, C-05 | C0/M5 | CALL-01-03; N-C1; M6/M7 |
| C-06, C-07, C-08, C-09 | M5, B2 | CALL-04-06; N-C2-3; M6/M7 |
| H-01, H-02, H-03, H-04, H-05 | H0/H1, B3 | APK-01-04/07; N-H1-2; H2/B4 |
| H-06, H-07, H-08, H-09 | H0/H1 | APK-04-06; H2/B4 |
| H-10, H-11, H-12 | H1/H2, B3/B4 | APK-06-07 la H2; APK-08 la B4; N-H3; B7 |

Fiecare pachet produce: obiectiv, checkout/SHA, fișiere modificate, decizii, comenzi, exit codes, număr/scop teste, rezultate negative, hash-uri, limite și următorul gate. Reviewer-ul verifică material dovezile; un PASS al unui worker nu este admitere. Măsurătorile și log-urile rămân concise, fără secrete sau date personale.

Toate verificările sunt locale potrivit ADR-58. Suita largă se rulează proporțional pe candidatul înghețat; editarea documentelor nu cere rerularea întregului produs. Niciun push, deploy, migrare de date sau schimbare a serviciilor nu este implicită în acest roadmap.

## 24. Estimare, resurse și puncte de replanificare

Estimări inițiale de efort pentru extensie, nu termene contractuale. O zi-om înseamnă o zi de lucru efectiv a unui specialist; două persoane nu înjumătățesc automat traseul dependent. Valorile se reconfirmă la B0, după M0 și C0.

| Pachet | Zile-om | Ce include |
|---|---|---|
| H0 | 3-5 | Design hardening și evidență |
| H1 | 8-12 | Implementare release și regresii focalizate |
| H2 | 6-10 | Review intern, probe și pregătire audit |
| M0 | 4-6 | Fezabilitate și matrice radio |
| M1 | 6-10 | Protocol, date, review și vectori |
| M2 | 10-15 | Transport direct și integrare DM |
| M3 | 12-20 | Forwarding, cote, gateway și erori |
| M4 | 8-12 | Note vocale și lifecycle |
| C0 | 5-8 | Motor RTC și verificarea izolării |
| M5 | 15-25 | Apel local și scenarii adverse |
| M6 | 10-18 | Matrice fizică, performanță și integrare |
| M7 | 5-8 | Admitere module și documentare |
| Total extensie | 92-149 | Fără restul bazei, audit extern și timpi de așteptare |

Nu sunt incluse: backlog-ul B0-B7/Fazele 0-18, achiziția dispozitivelor, contractarea și durata auditului extern, refaceri majore cerute de audit, fereastra calendaristică de beta și operarea după lansare. Integrarea specifică noilor funcții este inclusă în M/H; lucrul rămas deja necesar bazei se estimează separat, pentru a evita dublarea.

Echipa minimă funcțională acoperă Android/radio/audio, Rust/crypto integration/storage, QA pe dispozitive și review independent de securitate; rolurile pot fi part-time, dar autorul nu își acordă singur acceptarea de securitate. Se limitează la două fluxuri de implementare independente și un flux de verificare; fără scrieri concurente în același worktree.

Replanificare obligatorie la: hardware incompatibil (M0), review protocol neacceptat (M1), NFR radio/baterie depășite (M3/M6), WebRTC imposibil de izolat ori APK prea mare (C0), reproductibilitate pierdută (B3/H2), constatări High/Critical (B4) sau regresie de confidențialitate în beta. Se modifică designul ori compatibilitatea și se repetă probele afectate; pragurile de securitate nu se relaxează prin schimbarea etichetei de release.

## 25. Istoric și limitele acestui livrabil

v2.2 adaugă M0-M7, C0 și H0-H2 și ordonează închiderea bazei prin B0-B7. Păstrează istoria Fazelor 0-18 și deciziile actuale privind Tor, vodozemac, OpenMLS, media, plăți, sursă închisă și CI local. Nu certifică starea codului, nu modifică aplicația și nu autorizează lansarea.

Surse: specificația v2.2; Master Plan v2.1 §6; STATUS; THREAT_MODEL; LIMITE_REZIDUALE; ADR-01, 35-38, 44-47, 58, 60-62 și designurile de fază aferente. Validarea independentă a acestei revizii privește coerența documentară, nu eficacitatea unei implementări inexistente.
