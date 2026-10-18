# GHOST — Threat Model v2.1

| Câmp | Valoare |
|---|---|
| Status | Livrabil Faza 2 — **așteaptă review independent** (gate-ul de ieșire al fazei) |
| Data | 2026-09-10 |
| Bază | Spec v2.0 §2, §6.4, §11, §15; ADR-01…ADR-16; `LIMITE_REZIDUALE_SI_MITIGARI.md` |
| Metodă | Active → adversari (capabilități explicite) → suprafețe și granițe de încredere → scenarii → mitigări legate de FR/ADR → risc rezidual → test (T-ID) |
| Completări | 2026-09-13, Faza 8 (ADR-22 … ADR-26, propuse 2026-09-12 și aplicate; design `docs/design/faza8-issuer.md` Anexa B): AS-6, AS-9, AD-1, AD-3, TB-4; §5 (token-uri și cheia ES); §6 (șase rânduri: cumpărare, redeem, invitație, revendicare, livrare prin drop, reîmprospătare); S2, S11; R-14 (corectat după design §18 F2); §9 (T1–T23). După review-ul documentelor: §5 (păstrarea cheii CREDIT), S2 (orice cheie INVITE sau CREDIT ținută, design §19.1 regula 4), S11 (retenția nullifier-elor de invitație). 2026-09-24, Faza 9 (ADR-30′ … ADR-34′, ADR-35 … ADR-39, propuse și aplicate; design `docs/design/faza9-dm.md` Anexa B.3, reconciliată cu notele §22 în §22.29): A1, AS-3, AD-1 și adversarul nou AD-V, AD-7, AD-9, TB-6, rândul DM din §5, tabelul DM din §6, S12 (FR-4.6), §9 (T1–T35); în aceeași zi, după JD8 (design §22.26) și review-ul adversarial al documentelor (design §22.29 punctul 7): A1 (abaterea pickle-ului: citire și scriere), nota DM din §6 (abaterile 5–8, trimiterea la LIMITE L5, LD definit), S6 (atestarea amânată). **Faza 9 nu e închisă**: rândurile DM descriu designul implementat și ce se verifică azi, nu o garanție validată. **2026-10-11, Faza 10 (ADR-40 … ADR-43, propuse; design `docs/design/faza10-forum.md` Anexa B.2):** AS-7 și AD-2 (co-apariția reconstruiește graful client ↔ namespace de canal), §5 (pseudonimul stabil pe viața canalului, retenția epocilor), §6 (scopurile DEPOSIT/READ unice ale generației; rândul „Flag / Remove” corectat; rândurile noi „Invitație în canal”, „Rotație de generație”, „Dezvăluire” și „Parola de canal”), S3 (corectura RFC 9750 §5.2), S4 (oracolul membrului scos T38), S5 (simularea pragului GV), AD-1/AD-2 (rolurile recunoscute, L8-C19) și AD-6 (captura invitatului, L8-C25). Reziduurile canalelor: LIMITE §L8; argumentul porții: design §12.12 și §19.53. **2026-10-15, Faza 11 (ADR-44 … ADR-47, aprobate 2026-10-04; aplicate în S10, design `docs/design/faza11-media.md` Anexa B):** AS-4 (media ca ciphertext E2E în fișiere, decriptat doar în memorie), §5 (rândul „Cheie fișier media”: per fișier și per destinație, `key_env`, ștergerea cu checkpoint), §6 (tabelul nou „Media”), §9 (T42–T47). Reziduurile media: LIMITE §L9; argumentul porții: design §17.3 cu starea fiecărui punct (poarta nu e îndeplinită: Q32, Q31, staging) |

## 1. Scop și presupuneri

**În scop:** clientul Android, relay-urile blind, entitlement issuer-ul, transportul Tor, schemele de protocol, stocarea locală, distribuția/actualizarea, lanțul de aprovizionare, plata pe Monero, guvernanța în canal.

**Presupuneri de securitate (dacă una cade, garanțiile de mai jos cad cu ea):**

| ID | Presupunere | Dacă e falsă |
|---|---|---|
| A1 | vodozemac (Olm) și OpenMLS implementează corect protocoalele la versiunile fixate; noi nu le modificăm (GHOST folosește API-ul public al vodozemac, cu o abatere declarată de la ADR-35: `chainPosition` și `sessionPrune` citesc **și scriu** formatul serde al pickle-ului, nedocumentat și neversionat, iar `sessionPrune` rescrie starea stocată a sesiunii, design §2.1). Dovezile de maturitate sunt în ADR-35 (un audit vodozemac din 2022, cod ulterior neauditat; LIMITE L7-D22). Compunerea post-cuantică și regulile de sesiune ale GHOST **trebuie** acoperite de modelul formal și de revizia externă (ADR-36): modelele ProVerif pentru M-1, M-2, M-3, pasul (3) al M-6 și structura M-7 au rulat local o dată (2026-09-24: 48 de interogări conform așteptărilor, design §22.31; jobul CI încă nu), M-4 și M-5 nu au model, revizia externă nu a avut loc; până atunci compunerea e o presupunere a acestui document, nu o proprietate verificată (PQ-R6) | confidențialitatea conținutului cade (R-03) |
| A2 | Android Keystore hardware-backed nu exportă chei | impersonare după extragere (L1) |
| A3 | Tor oferă rezistență la observatori locali, nu la GPA | corelare IP ↔ relay (L2) |
| A4 | RSA blind signatures / Privacy Pass sunt corecte (RFC 9474/9578) | linkabilitate plată ↔ token |
| A5 | Monero ascunde expeditorul, suma și destinatarul pe lanț | linkabilitate plată ↔ persoană |
| A6 | Cel puțin unul din cele ≥3 relay-uri e onest și disponibil | disponibilitate; nu confidențialitate |
| A7 | Cheia de semnare a release-ului rămâne offline și necompromisă | update malițios (R-11) |
| A8 | Utilizatorul păstrează mnemonicul și nu îl introduce în alte aplicații | pierdere/preluare identitate (R-01) |

## 2. Active

| ID | Activ | Unde trăiește | Impactul compromiterii |
|---|---|---|---|
| AS-1 | Entropia rădăcină / mnemonic | Keystore (învelit), memoria utilizatorului | Critic: toate cheile, identitatea, referral-ul |
| AS-2 | Cheia de identitate Ed25519 și pseudonimele per canal | Keystore / DB criptat | Impersonare; legarea pseudonimelor între canale |
| AS-3 | Stare Olm (sesiuni, generații de chei), criptată cu cheia de stare, și stare OpenMLS (epoch, tree) | SQLCipher (starea Olm: plic sub cheia de stare, învelită în Keystore) | Citirea mesajelor viitoare până la vindecare PCS |
| AS-4 | Conținut: mesaje, postări, media în clar | doar pe endpoint; textul și postările în DB criptat; media ca ciphertext E2E identic cu cel de pe relee, în fișiere din `noBackupFilesDir/m/` (și, temporar, în tabelele de sincronizare ale DB-ului criptat); decriptat doar în memorie | Confidențialitate |
| AS-5 | Cheia DB (SQLCipher) | Keystore | Acces la AS-3/AS-4 offline |
| AS-6 | Token-uri de acces, de invitație și de credit (valoare la purtător; secretul de referral e retras, ADR-24) | DB criptat | Abuz de cotă; furtul creditelor; ziua finalizării unui lot (LIMITE L1.1, E19) |
| AS-7 | Graful social: cine e în ce canal, cine invită pe cine | în capetele MLS; sub AD-1, co-apariția sesiunilor reconstruiește graful client ↔ namespace de canal (LIMITE L7-D2, L8-C2); sponsor vizibil în canal | Deanonimizare relațională |
| AS-8 | Metadate de trafic: momente, dimensiuni, namespace-uri | observabile la relay/rețea | Corelare activitate |
| AS-9 | Datele issuer-ului: facturi, sume, subadrese, nullifier-e de invitație și de credit, revendicări și adrese de plată în așteptare, `issued.journal`, instantanee, contoare săptămânale, istoricul portofelului de vizualizare (fără commitment-uri de referral, ADR-24) | issuer (redb, jurnal, portofel); stația de plăți a operatorului | Linkabilitate financiară (nu identitate); retenția: ADR-26 punctul 5 |
| AS-10 | Cheia de semnare release + manifest | HSM/offline | Distribuție malițioasă |
| AS-11 | Cheile relay-urilor (onion service, Noise) | relay | Impersonare relay; DoS; nu conținut |
| AS-12 | Codul sursă și dependențele | GitHub, registre | Supply chain |

## 3. Adversari și capabilități

| ID | Adversar | Capabilități presupuse | Ce NU poate |
|---|---|---|---|
| AD-1 | **Operatorul GHOST** (insider, sau operator constrâns legal) | Controlează issuer-ul, manifestul de release, unul sau mai multe relay-uri, jurnalele lor, infrastructura; poate publica versiuni noi (cu sursă închisă, pentru versiunile noi AD-1 și AD-V sunt în practică aceeași parte: vezi AD-V; garanțiile de mai jos față de AD-1 sunt valabile doar pentru un build publicat în jurnalul de transparență și reprodus de auditori, iar azi nu există nici jurnalul, nici auditorii) | Nu deține chei de conținut (CP-01); nu poate semna release fără cheia offline (A7); nu poate lega token-uri de plăți (A4) dincolo de scurgerea declarată L1–L7 a Fazei 8 (momente și prezență, LIMITE L6; testul T2) |
| AD-2 | **Relay compromis / malițios** | Vede tot traficul propriu: namespace-uri, hash-uri, bucket-uri, momente, nullifier-e; poate refuza, întârzia, șterge, servi date vechi; poate colabora cu alte relay-uri | Nu vede IP (onion), identități, conținut, apartenență, în afara celei deduse din co-apariție (L8-C2); nu poate forja blob-uri acceptate (hash + AEAD); recunoaște rolurile într-un canal: finanțatorii (implicit proprietarul) după răscumpărările săptămânale, comitentul care rotește după răscumpărările pentru un namespace nou și Welcome-urile stocate, membrul scos (singurul care nu trece pe namespace-ul nou); co-apariția le leagă de clusterul DM al clientului (LIMITE L8-C19) |
| AD-3 | **Issuer compromis** | Vede facturi, sume, înălțimi, subadrese, istoricul portofelului de vizualizare, mesaje blind, nullifier-e de invitație și de credit, adrese de plată, momentul fiecărui apel (în rulări liniștite, cel mult 6 apeluri legate per cumpărare); poate emite token-uri fraudulos (cel mult 6 săptămâni de acces înainte; invitații și credite până la revocarea I1); poate refuza sau întârzia serviciul (n−1, LIMITE L6 E8) | Nu vede identități GHOST, IP; nu poate lega token deblindat ↔ factură (dovada de permutare, ADR-22); nu poate alege cheia, prețul sau perioada unui singur client (ES fixat, ADR-22); nu poate decripta nimic |
| AD-4 | **Observator de rețea local** (ISP, Wi-Fi ostil, angajator) | Vede IP-ul utilizatorului și că vorbește cu Tor/bridge; volum și timing. Cu bridges simple: vede și fingerprint-ul Tor. Cu transport pluggable (Faza 12, după poartă): **nu vede nici Tor** pe hop-ul client↔bridge (obfs4: octeți aleatorii; WebTunnel: HTTPS); vede în continuare IP-ul bridge-ului, volumul și timingul (LIMITE L12) | Destinație, conținut, GHOST ca aplicație |
| AD-5 | **Adversar global pasiv** | Vede toate legăturile; corelare statistică intrare/ieșire Tor | Conținut; cu polling constant, tiparul nu reflectă activitatea |
| AD-6 | **Membru de grup rău-intenționat** | Citește tot ce se postează cât e membru; copiază; spam; flag abuziv; încearcă „reveal”; dacă e comitent numit într-o invitație (chiar scos între timp), poate captura invitatul într-o ramificare a grupului real și îl poate ține acolo cât o întreține; se vede doar comparând amprenta în afara aplicației (LIMITE L8-C25) | Nu decriptează după `Remove`; nu deanonimizează fără reveal; nu vede IP |
| AD-7 | **Corespondent DM rău-intenționat** | Cunoaște identitatea de bază; păstrează istoricul; screenshot. Din Faza 9 are și cardul meu de contact, definitiv: îmi poate depune, prelua bundle-ul, lista inbox-ul cu propriul token, recunoaște plicurile intro și, colaborând cu releele, lega namespace-urile mele de `ghost1` (§6, tabelul DM; LIMITE L7-D3, L7-D16, L7-D25) | Nu vede alte canale; nu vede IP; nu citește conținutul altor conversații |
| AD-V | **Furnizorul livrează un build rău-intenționat sau țintit** (furnizorul, un insider sau un furnizor constrâns; ADR-38) | Cu sursă închisă, publică o versiune nouă care face orice; pentru versiunile noi e aceeași parte cu AD-1 | Nimic, azi: atenuările ADR-38 sunt **planificate** (Fazele 14–15) și niciuna nu există încă — jurnal de transparență cu martori și verificarea includerii în actualizator, un verificator independent pentru prima instalare, versiunile relay și issuer în jurnal și în atestări verificate de operatori, fișierele de simboluri native publicate, atestările auditorului, escrow. Rezidual chiar după ele: un defect din sursa auditată care scapă auditului, o versiune încă nerevizuită, prima instalare fără verificatorul independent, actualizările livrate de magazine și binarele operatorilor neverificate; independența operatorilor nu protejează împotriva AD-V (LIMITE L-SRC = L7-D23) |
| AD-8 | **Atacator cu dispozitivul deblocat / malware cu root** | Tot ce vede utilizatorul; DB deschis | Nu exportă chei hardware; nu vede istoricul expirat (excepție: hash-urile de deduplicare ale blob-urilor expirate recent, fără conținut, LIMITE L1.1; tot acolo, statisticile OS de trafic și baterie per aplicație, din care se vede când s-a trimis sau primit mult); pierde accesul la revocare |
| AD-9 | **Atacator de lanț de aprovizionare** | Compromite o dependență, un registru, CI, un mainteiner | Nu trece de allowlist/checksums/cargo-deny; nu produce APK cu hash reproductibil identic fără a fi în sursă. Cu sursă închisă (ADR-37), reproducerea o pot face doar mediile furnizorului și ale auditorului: build-ul reproductibil verificat și de mediul auditorului (T12b), jurnalul de transparență și ieșirea din depozitul principal F-Droid sunt ținte ale ADR-38 (Faza 14); azi T12 dovedește doar determinismul la aceeași cale, în mediile proprii |
| AD-10 | **Atacator de rețea activ** (MITM între client și relay) | Modifică pachete, joacă rolul relay-ului | Onion service = autentificat E2E; capabilități semnate; blob-uri hash-verificate |
| AD-11 | **Sybil / brigading** | Cumpără N abonamente, obține invitații, coordonează flag-uri | Costă N×$10/lună + invitații; ponderare vechime + diversitate sponsori (ADR-13) |
| AD-12 | **Autoritate legală** care cere date | Poate cere operatorului, relay-urilor, issuer-ului tot ce au | Primește doar ce există: nimic despre conținut/identități; jurisdicții și operatori separați (ADR-11) |

## 4. Granițe de încredere (revizuite)

| ID | Graniță | Ce traversează | Ce NU traversează niciodată |
|---|---|---|---|
| TB-1 | Proces Android ↔ Keystore | operații de semnare/derivare/deschidere prin API | material de cheie brut |
| TB-2 | Client ↔ relay (prin Tor) | pachete padate, capabilități, token-uri de unică folosință, hash-uri | IP, identitate, plaintext, cheia de fișier |
| TB-3 | Relay ↔ relay | inventar autentificat, blob-uri | identități de endpoint, capabilități ale clienților |
| TB-4 | Client ↔ issuer (prin Tor) | cereri de factură (în rulări liniștite), `BlindSign` cu structură fixă (servește și ca interogare a plății; „verifică acum” doar la cererea utilizatorului), mesaje blind, token-uri de invitație (trial) și de credit (discount, reîmprospătare, revendicare de plată) deblindate, adrese de plată; câte un scop de izolare Tor per flux (`IssuerFlow`, ADR-22, ADR-23) | identitate GHOST, pseudonime, IP, token-uri de **acces** deblindate, chei, prețuri sau configurație (nicio cale de rețea pentru ES, ADR-22) |
| TB-5 | Issuer ↔ rețeaua Monero | view key: observarea plăților la subadrese | spend key (offline/multisig) |
| TB-6 | Build ↔ release | artefact reproductibil, manifest semnat offline; planificat (ADR-38, Faza 14): build reprodus și de mediul auditorului (T12b), intrare în jurnalul de transparență; distribuție fără depozitul principal F-Droid (ADR-37) | cheia de semnare (niciodată în CI) |
| TB-7 | Membru ↔ grup MLS | mesaje de aplicație, commit-uri, politici semnate, flag-uri | identitatea de bază (fără reveal explicit) |

## 5. Ciclul de viață al cheilor

| Cheie | Generare | Stocare | Rotire | Revocare/Distrugere |
|---|---|---|---|---|
| Entropie rădăcină | CSPRNG 256 bit la prima pornire | Keystore-wrapped; mnemonic la utilizator | niciodată (identitate) | doar prin abandonarea identității |
| Identitate Ed25519 | HKDF(`ghost/v1/identity`) | Keystore | la compromitere → identitate nouă | certificat de revocare (ADR-14); pentru DM, certificatul v2 trimis contactelor ca mesaj E2E în inbox-urile lor, la cererea utilizatorului (ADR-33′; nu mai e un blob în namespace-ul identității) |
| Pseudonim per canal | HKDF(`ghost/v1/channel-pseudonym` ∥ channel_id) | derivat la nevoie | stabil pe viața canalului (ADR-43); un pseudonim nou = un canal nou | inerent la `Remove` |
| DM: vodozemac (Olm) și stratul GHOST (ADR-35, ADR-36; înlocuiește rândul libsignal, revizia din 2026-09-16) | identitatea Olm derivată din ramura messaging (`ghost/v1/dm/olm-identity`); generații săptămânale (cheie de rezervă Olm, cheie X-Wing) aleatoare | starea sesiunilor criptată cu cheia de stare în SQLCipher; cheile de stare și de conținut învelite în Keystore | generații săptămânale, șterse la 91 de zile după înlocuire; ratchet per mesaj; cel mult două sesiuni per contact; rădăcini de pereche înlocuite rar, cu X-Wing când există o cheie proaspătă a contactului (PQ-C) | ștergere sesiune; PCS clasic; vindecarea față de un adversar cuantic, doar la nivelul sigiliului și doar după un ciclu PQ-C, e proiectată și implementată, **nevalidată** (modelul M-6 nerulat, revizia externă neefectuată; PQ-R2) |
| OpenMLS (epoch secrets) | biblioteca | SQLCipher | fiecare commit avansează epoch-ul | secretele epocilor trecute păstrate cel mult 2 zile (1 zi în canalele cu timer ≤ 1 zi), cel mult 16 (design Faza 10 §8.3) |
| Cheie fișier media | random 256 bit **per fișier și per destinație** | învelită nativ sub cheia de stare (`key_env`, legată de rol, contact, obiect și manifest); transportată doar în L0 DM (slot completat și golit doar în Rust) sau, din Faza 10, în mesajul MLS | per fișier | se șterge odată cu mesajul, urmată de checkpoint WAL; la «vezi o singură dată», înaintea primei afișări (ADR-44, ADR-47) |
| Cheie DB | Keystore | Keystore | la cerere (re-cifrare) | wipe / duress |
| Token-uri de acces/invitație/credit (chei de semnare blind ale issuer-ului) | ceremonie offline (K1), o cheie RSA-2048 per (tip, epocă), cu dovadă de permutare; token-urile: blind, cu blinding derivat dintr-o sămânță per flux | token-uri: DB criptat; chei private: fișiere sigilate per (tip, epocă) pe discul criptat al issuer-ului, în memorie doar o fereastră (ADR-26 punctul 4) | săptămânal (acces), 4 săptămâni (invitații), 13 săptămâni (credite) | listă de revocări în ES; nullifier la relay și issuer; cheia privată distrusă după ultima factură care o folosește (cel târziu sfârșitul epocii + 42 de zile; cheia CREDIT a epocii c până la `end(c + 1)` + 8 zile, pentru `RefreshCredit`) |
| Cheia Programului de Entitlement (ES) | Ed25519, offline, disciplina de custodie a cheii de release (A7); alpha: cheie doar de stagenet, generată în afara repository-ului (Q20) | offline; cheia publică fixată per rețea în biblioteca nativă | la fiecare versiune nouă a ES-ului (doar se completează) | ceremonia K1 cu cheia offline reală înaintea primului ES de mainnet (Faza 16/17) |
| Chei relay (onion, Noise) | operator | HSM/disc criptat | politică FR-5.7 | manifest actualizat |
| Cheie release | offline/HSM | offline | drill anual | rotație de urgență (runbook) |

## 6. Matricea de expunere a metadatelor

Ce poate observa fiecare actor, per eveniment. „—” = nimic. Fiecare rând e un invariant testat (T-ID).

| Eveniment | Relay | Issuer | Rețea locală | Membri canal | Test |
|---|---|---|---|---|---|
| Postare în canal | namespace, hash, bucket, moment ±granularitate; scopul DEPOSIT unic al generației; treaptă după lungime și clasă; TTL-ul canalului | — | trafic Tor, volum bucket | pseudonim, conținut, minut | T1, T9, T13 |
| Citire canal | namespace, cursor, moment; toate cererile unui client pentru un namespace sunt legabile între ele prin `capability_scope` și prin valorile de cursor pe care le emite relay-ul (un relay rău-intenționat poate folosi cursoare unice drept cookie între circuite și sesiuni); ritm de listare fix, același pentru toți clienții; scopul READ unic al generației (D11 aplicat, per generație) | — | trafic Tor | — | T1, T19, T21 |
| Mesaje directe (Faza 9) | vezi tabelul DM de mai jos (înlocuiește rândurile „DM trimis” și „Publicare prekeys”) | — | — | — | T1, T26–T31 |
| Cumpărare abonament | — (prima folosire a token-urilor noi, la un slot de activare: scurgerea declarată L1, LIMITE L6) | subadresă, sumă, înălțimi, istoricul portofelului de vizualizare, momentul fiecărui apel (în rulări liniștite), numărul fix de token-uri, tipul plății | trafic Tor | — | T2, T22, T23 |
| Redeem token la relay | nullifier, perioadă (săptămână), namespace, moment, hash-ul capabilității emise; token-ul e legat de slotul relay-ului; nullifier-ele persistate cu etichetă de legare cel mult două săptămâni | — | trafic Tor | — | T1, T2 |
| Invitație acceptată | — | nullifier-ul invitației, momentul, un trial; nicio legătură cu factura celui care invită | trafic Tor | sponsor (la Add) | T16, T2 |
| Revendicare credit (plată de referral) | — | numărul de credite, adresa de plată, momentul | trafic Tor | — | T2 |
| Livrare credit (drop) | un blob de 1 KiB într-un namespace nou, listat de alt client (credit sau blob fals, la un moment tras la activare) | — | trafic Tor | — | T1, T2 |
| Reîmprospătare credit primit | — | creditul primit (cunoscut de invitatul care l-a trimis), momentul unei rulări liniștite a celui care invită, un credit nou blind al aceleiași epoci | trafic Tor | — | T2 (LIMITE L6, E17) |
| Flag / Remove | namespace, hash — **Scoatere (Faza 10):** un commit al unui comitent la o trecere programată, arătând ca o postare; o rotație (namespace nou) vizibilă sub AD-1 | — | — | flagger, țintă, decizie | T1 |
| Invitație în canal (Faza 10) | o cerere de intrare de treapta minimă, un Welcome mai mare la trecerea comitentului, un ascultător nou | — | trafic Tor | sponsorul (la Add) | T1, JN, NI-CH5 |
| Rotație de generație (Faza 10) | răscumpărări și înregistrări ale comitentului, namespace nou, cel vechi golit în 14 zile; trecerea pe namespace-ul nou la ora fixată de commit (nu la minutul descărcării); rotații și după invitații expirate nefolosite și la 28 de zile (cu Q45 (a), și la punerea sau schimbarea parolei de canal) | — | trafic Tor | — | JC-4, NI-CH4 |
| Dezvăluire (Faza 10) | nimic la relee; membrii văd autorul, nu destinatarul; destinatarul poate dovedi legătura oricui, L8-C8 | — | trafic Tor | destinatarul primește cardul | RV, T14 |
| Parola de canal (Faza 10) | la relee nimic nou (invitația circulă în afara canalului; NI-CH5); cine are un link vede dacă cere parolă și poate ghici parola offline, cu costul unui Argon2id pe încercare; un membru care poate invita o ocolește (de aceea, cu Q46 (b), într-un canal cu parolă invită doar comitenții); orice membru, și orice membru scos, o cunoaște (LIMITE L8-C26) | — | trafic Tor | — | JN, NI-CH5, MM-PW1 … MM-PW5 |
| Sync periodic (idle) | per pereche (relay, namespace): în prim-plan, listări cu `limit` 128 la 30 s × U[0,5; 1,5], cu fază independentă per pereche; în fundal, un eveniment per pereche per job, la momente alese de OS; get-uri câte produc scrierile altora; verificări ale propriilor copii (`check`) | — | începutul și sfârșitul sesiunilor Tor (aplicație deschisă, joburi OS, câte un bootstrap Tor per job: LIMITE L4); rată agregată proporțională cu numărul de perechi; momentele listărilor nu depind de activitate, volumul da (până la cover traffic, P2) | — | T19 (Faza 7, JVM); T17 (Faza 12, doar high-privacy mode cu cover traffic P2) (ADR-15, ADR-20) |

Notă (Faza 7, ADR-20, design §6.3): trimiterile (hash, bucket, bucket de TTL, minut) urmează scrierile proprii, imediat în modul standard și cu întârziere U[0, 10 min] în high-privacy mode. Namespace-urile unui client nu împart un ceas de listare în prim-plan (faze independente, izolare de circuit per namespace, T21), dar toate perechile pornesc în primele 30 s după deschiderea aplicației și în primele 90 s ale fiecărui job de fundal. Reziduurile sunt în `LIMITE_REZIDUALE_SI_MITIGARI.md` L2.1.

Notă (Faza 8, ADR-22 … ADR-26, design `docs/design/faza8-issuer.md` §1.2): sub AD-1 (issuer-ul și toate relay-urile la același operator), singura informație care poate trece de la issuer la relay-uri e scurgerea declarată L1–L7: ziua slotului de activare a primei folosiri a unui lot; săptămâna de sfârșit a acoperirii; „online” la un apel imediat cerut de utilizator și începutul trialului; tipul cumpărării; „în rulare liniștită” la fiecare apel de fundal (≤ 3 biți per apel, cel mult 6 apeluri legate per cumpărare); momentul primei apariții a plății în portofel; începutul unei cumpărări după `ENTITLEMENT_NEEDED`. Orice altceva e o încălcare T2 (INVARIANTS T2, T22, T23). Reziduurile, cu cifrele lor, sunt în `LIMITE_REZIDUALE_SI_MITIGARI.md` L6 (E1–E32).

### Mesaje directe (Faza 9; ADR-30′ … ADR-36; design `docs/design/faza9-dm.md` §1, §11.2)

Coloana „Contact” e ce vede corespondentul (sau un deținător al cardului meu), nu un membru de canal. Coloana „Test” numește invariantul care acoperă rândul; **cât din el e executabil azi e scris în INVARIANTS** (T26–T35 sunt verificați parțial, la scara PR și local; poarta Fazei 9 nu e îndeplinită; `docs/STATUS.md`). Scurgerea declarată DM (numită LD în design `docs/design/faza9-dm.md` §1.2: singura informație pe care T32 o lasă să treacă) și reziduurile din interiorul ei: LIMITE L7.

| Eveniment | Relay | Issuer | Rețea locală | Contact | Test |
|---|---|---|---|---|---|
| DM trimis (depunere) | namespace-ul inbox al destinatarului (derivat din secretul cardului, nelegabil de ghost1); hash; treaptă 4/16/64 KiB independentă de tipul mesajului; treapta TTL (1 h, 1 zi, 7 zile sau 30 de zile); minutul; scopul static al cheii de depunere a inbox-ului la acel releu, **același pentru toți expeditorii** (design §21.2); circuitul expeditorului | — | upload 3 × treaptă (imediat în modul standard, U[0, 10 min] în high-privacy) | — | T1, T9, T26, T27, T29, T30 |
| DM primit | listări la programul T19 cu scopul de citire static per releu, derivat din seed; câte un get per blob nou; prezența | — | download la listări | cu releul: momentul aducerii propriului blob | T19, T28 |
| Reînnoirea săptămânală proprie | răscumpărări pentru inbox și bundle la momentul PRF de reînnoire; apoi `register` (depunere, citire, preluare) cu `key_kind` | — | — | cunoaște namespace-urile | T1, T27, T31 |
| Publicare bundle | namespace-ul P derivat din card; bundle sigilat de 4 KiB, TTL 30 de zile; la un decalaj fix al săptămânii, independent de activitate | — | trafic Tor | vede rotațiile, săptămâna publicării și, prin rang, dacă în acea săptămână a existat o publicare în afara programului (activare sau restaurare); citirile de preluare întorc doar momente rotunjite la săptămână; singur, citind periodic namespace-ul, minutul apariției fiecărui bundle, deci prima sesiune după `t_pub`, absențele și momentele activării și restaurării (L7-D10) | T26, T31 |
| Preluare bundle | o listare a lui P cu secretul de citire al acelui releu, comun tuturor deținătorilor cardului, doar la stabilirea contactului, la resetare sau la reconectare, în cel mult trei încercări | — | 4 KiB | — | T31 |
| Schimbare de cheie, verificare, blocare, cereri | **nimic** | — | — | — | T28, T31 |
| Expirare / schimbare timer | nimic la expirare; primul blob pe o treaptă nouă marchează schimbarea | — | — | vede schimbarea | T25, T30 |
| Restaurare | înregistrări și bundle nou pe aceleași namespace-uri, din circuite noi, după ce dispozitivul restaurat are un token | — | — | mesajele trimise înainte de reconectare se pierd și nu îi arată dispozitivului restaurat cine a scris; o resetare din partea lui eșuează până la publicarea bundle-ului nou, care îl depășește pe cel vechi prin rang | T26, T31 |
| Reconectare / revocare | k trimiteri inițiate de utilizator, eșalonate pe 48 h / 24 h | — | — | primește mesajul | T28, T31 |
| Un deținător de card cumpără acces la inbox | o răscumpărare, listări și citiri cu un scop de scriere străin | — | — | volumul și momentele inbox-ului, minutul și generația fiecărui plic intro, conversațiile fără răspuns (L7-D16) | — |
| Trimit un prim mesaj unui card | o depunere, ca orice mesaj | — | — | destinatarul păstrează definitiv cardul meu complet (L7-D25) | — |

Notă (Faza 9, starea implementării; design §22.29). Rândurile descriu designul implementat. Abateri cunoscute ale codului de azi, vizibile releelor, declarate și nerezolvate (lista completă a defectelor și întrebărilor deschise e LIMITE L5): (1) un TIMER_SET pus în așteptare înaintea unei sesiuni e stocat cu treapta timer-ului nou, nu cu cea mai mare dintre cele două (R-T3), deci releul poate distinge tipul unui prim zbor după TTL, contrar rândului „DM trimis” (design §22.21 punctul 2; LIMITE L5); (2) „Restaurare”: rangul unei publicări în afara programului e mereu 1, deci bundle-ul restaurat poate pierde la paritate în fața celui al dispozitivului pierdut timp de până la o săptămână (design §22.13 punctul 18; LIMITE L5); (3) „Preluare bundle”: o revocare care sosește în timpul unei restabiliri nu oprește ferestrele de preluare rămase (design §22.19 punctul 14(h)); (4) o depunere refuzată pentru că înregistrările destinatarului au expirat se reîncearcă cam o dată per releu per sesiune a expeditorului, până la termenul mesajului (design §22.25 punctele 4 și 5); (5) o operație cu o copie posibilă (un timeout după aplicare) rămâne deschisă după termen și își face verificările (CHECK) până când copia se poate rezolva, față de un destinatar care nu mai revine până la circa `copy_hour + 30 de zile` (design §22.25 punctul 14(a)); (6) „Publicare bundle”: o publicare FAILED sau INDETERMINATE nu se re-sigilează, deci în acea săptămână nu există bundle și orice stabilire către proprietar eșuează până la `t_pub` următor (design §22.12 punctul 19); (7) „Reconectare / revocare”: un control FAILED nu se reprogramează (design §22.13 punctul 9); (8) „Reînnoirea săptămânală proprie”: reținerea de răscumpărare e armată și de nevoile de scriere LOCAL ale DM, deci lungimea unei sesiuni de fundal poate depinde de starea DM (design §22.26 punctul 14; citit din cod, nerulat). Nimic din acest tabel nu a fost verificat pe dispozitiv sau pe relee de staging.

### Media (Faza 11; ADR-44 … ADR-47)

Coloana „Contact” e ce vede corespondentul. Scurgerea declarată media (LM în LIMITE L9.0) și reziduurile: LIMITE L9; argumentul porții: design `docs/design/faza11-media.md` §17.3 (starea fiecărui punct), lumea media JM1–JM7 și gemenii NI-M1–NI-M7 la scara PR (design §22.12). **Poarta de ieșire a Fazei 11 nu e îndeplinită** (punctele 2–5 așteaptă Q32/Q31 și relay-uri de staging), deci rândurile descriu designul implementat și ce se verifică local azi, nu o garanție validată.

| Eveniment | Relay | Issuer | Rețea locală | Contact | Test |
|---|---|---|---|---|---|
| Trimit media | în namespace-ul media al destinatarului (derivat din card): F + 1 blob-uri de 64 KiB în câteva minute, clasa F (una din 11; orice imagine în prima), treapta TTL a conversației de la commit (aceeași și pentru descriptor), scopul de depunere comun tuturor expeditorilor, circuitul meu; apoi o depunere de 4 KiB în inbox, în aceeași sesiune; mai puține blob-uri și niciun descriptor după FAILED, la termen sau dacă șterg mesajul, niciodată din cauza timer-ului; același fișier trimis mai multor contacte leagă destinatarii prin sesiune | — | upload 3 × (F + 1) × 64 KiB | pixelii, sunetul, raportul de aspect, durata; nu dimensiunile exacte, rata de cadre peste 30 sau formatul sunetului sursei | T1, T42, T43, T47 |
| Primesc media | listări `M` la programul T19 (încă o pereche ascultată per releu); câte un `get` per blob, la evenimentele de listare, indiferent de starea locală | — | download (F + 1) × 64 KiB | un necunoscut care trimite media într-o cerere nu află nimic; obiectul lui nu se poate deschide la mine | T19, T45, T47 |
| Deschid, văd, „vezi o singură dată” | **nimic** | — | — | — | T47 |
| Expirare media | nimic | — | — | — | T25, T45 |
| Un deținător de card inundă `M` | depuneri cu scopul comun până la epuizarea cotei fiecărui releu, plus stocări cu capabilități de scriere cumpărate cu propriile token-uri (L7-D16) | — | download forțat | — | L9-M4 |

## 7. Scenarii de atac și răspuns

Format: **Scenariu** → ce obține atacatorul fără mitigări → mitigări (FR/ADR) → rezidual → test.

### S1. Operatorul vrea să afle cine a scris o postare
Fără mitigări: ar corela IP la relay + plată + identitate. Cu: relay-uri onion-only nu văd IP (ADR-01); token-uri nelegabile de plată (ADR-02); pseudonime per canal (ADR-04); relay-uri ale altor operatori (ADR-11). **Rezidual:** dacă operatorul deține și dispozitivul (L1). **Test:** T1, T2, T6.

### S2. Issuer compromis emite token-uri gratis și înregistrează tot
Obține: abonamente gratuite; datele issuer-ului (facturi, sume, înălțimi, nullifier-e de invitație și de credit, adrese de plată în așteptare; fără jurnal de cereri, ADR-26). Nu obține: identități, conținut, legătura token deblindat ↔ factură. Mitigări (Faza 8): o cheie per (tip, epocă) în Programul de Entitlement semnat offline și inclus în versiunea aplicației, fără nicio cale de rețea pentru chei (ADR-22); chei private sigilate, în memorie doar o fereastră de cel mult 6 săptămâni înainte (ADR-26); revocare prin runbook-ul I1; reconciliere „token-uri semnate vs. pachete și trialuri”, cu verificări independente pe care un issuer compromis nu le poate falsifica; spend key offline (TB-5). **Rezidual:** token-uri de acces falsificate pentru cel mult 6 săptămâni înainte; invitații și credite falsificate sub orice cheie INVITE sau CREDIT ținută (cele curente, epoca CREDIT anterioară, cele păstrate pentru facturi deschise) până când runbook-ul I1 revocă acele epoci la issuer (imediat); creditele și invitațiile oneste nefolosite ale epocilor revocate se pierd (LIMITE L6, E12); issuer-ul nu mai are commitment-uri de referral; reconciliere independentă prin portofelul de vizualizare al stației operatorului (plafon cumulat de 10 %) și numărătorile relay-urilor (suma pe sloturi, per săptămână; exportul lor e încă deschis, LIMITE L5). **Test:** T2, T22, reconcilierea (`ghost-issuer-ops reconcile-check`), scenariile de crash I-A…I-M ale issuer-ului (Faza 8).

### S3. Relay malițios servește istoric trunchiat sau blob-uri vechi
Obține: cenzură selectivă pe namespace; nu poate forja. Mitigări: clientul scrie pe ≥2 relay-uri și compară inventarul (ADR-11); hash + AEAD detectează modificarea; golurile se detectează în canal când traficul ramurilor se întâlnește (CO-11, CO-12); o partiție prin relee care ține ramurile separate se semnalează după 9 zile fără commit al unui comitent, iar un membru rupt în tăcere după 9 zile fără commit și fără mesaje (`stale_suspected`), și prin amprenta `epoch_authenticator` comparată în afara aplicației (L8-C17). **Rezidual:** întârziere; disponibilitate. **Test:** FORK, WITHHOLD_COMMIT (și permanent, pe un subset), LATE_COMMIT, GRIND, EM-3, T41 (Faza 10).

### S4. Membru rău-intenționat scurge conținutul
Obține: tot ce a văzut. Mitigări: istoric „none” pentru noi (FR-3.8), probațiune, efemere per canal, fără screenshot și fără copierea mesajelor (ADR-27), pseudonime, flag → carantină → `Remove` (ADR-13), strike pe sponsor, filigran per destinatar pentru media sensibilă (P2). **Rezidual:** ce a copiat rămâne copiat (fotografia ecranului cu alt dispozitiv, client modificat). **Test:** T38 cu variantele de reținere a postărilor și de restaurare (dispozitivul înlocuit), oracolul membrului scos (Faza 10); T14; T24; T25.

### S5. Brigading cu conturi Sybil pentru a scoate un membru
Obține: fără mitigări, 3 conturi ajung. Mitigări: ponderare vechime, diversitate sponsori, carantină cu drept la răspuns, moderatori (ADR-13). **Rezidual:** o majoritate reală poate scoate o minoritate: decizie de produs, transparentă în politica canalului. **Test:** simularea pragului (GV, Faza 10); mecanica flag-urilor în Faza 13.

### S6. Dispozitiv cu root
Vezi L1. Mitigări: Keystore hardware, auto-lock, efemere, revocare, PCS, atestare (ADR-14; amânată în Faza 9 și niciodată în bundle, ADR-30′ punctul 8). **Rezidual:** tot ce e pe ecran cât durează accesul. **Test:** T4, T10, revocare (Faza 3/9).

### S7. Corelare GPA
Vezi L2. Mitigări: padding P0, polling constant, trimitere întârziată, izolare circuite (ADR-09, ADR-15). **Rezidual:** „acest IP folosește Tor, probabil GHOST”. **Test:** T9, T17.

### S8. ISP blochează Tor / marchează utilizatorii Tor
Mitigări: bridges în manifest, WebTunnel, mod auto, fail-closed (ADR-16, ADR-01). **Rezidual:** trafic către un bridge/VPN e vizibil. **Test:** T6, T18 (captură fără fingerprint Tor).

### S9. Dependență compromisă (supply chain)
Mitigări: allowlist + denylist (T7), Gradle dependency verification cu checksums, cargo-deny, cargo-audit, build reproductibil din două medii (T12), cheie release offline, SBOM (FR-8.1). **Rezidual:** compromitere upstream a unei versiuni pinuite înainte de detectare publică. **Test:** T7, T12, CI.

### S10. Update malițios livrat utilizatorilor
Mitigări: manifest semnat cu cheie pinuită, hash APK, anti-rollback, două locații de manifest, F-Droid repo cu build reproductibil (ADR-07, FR-7.5). **Rezidual:** compromiterea cheii offline (runbook de rotație). **Test:** tamper/downgrade drill (Faza 14).

### S11. Autoritate cere date de la operator/issuer/relay
Ce există: agregate; la issuer facturi (sume, înălțimi, subadrese) cel mult ~30 de zile, nullifier-e de invitație până la 22 de zile după ce epoca lor nu mai e acceptată (începutul epocii + 2, plus 22 de zile), nullifier-e de credit cât sunt acceptate, adrese de plată cât revendicarea așteaptă, jurnalul de emitere ≈ 7–14 zile, instantanee cel mult 7 zile, contoare săptămânale și istoricul portofelului de vizualizare, fără nicio coloană de timp mai fină decât săptămâna și fără jurnal de cereri (ADR-26); la relay hash-uri/namespace-uri cu TTL și nullifier-e cu etichetă de legare cel mult două săptămâni (ADR-25). Nu există: identități, IP-uri, conținut, graf social. Mitigări: minimizare structurală, TTL, operatori și jurisdicții separate (ADR-11), warrant canary (opțional, non-tehnic). **Test:** T1, T3, politica de logging §11.1.

### S12. Cheia de identitate a unui contact se schimbă (MITM la bundle sau dispozitiv nou)
Mitigări: avertisment blocant (**FR-4.6**; erată: nu FR-4.5): schimbarea cheii se recunoaște doar printr-o semnătură validă sub identitatea Ed25519 fixată; trimiterea se blochează, iar mesajele sub cheia nouă sunt reținute până la confirmare; safety number verificabil offline; atestarea hardware amânată (ADR-30′, ADR-33′). **Rezidual:** utilizatorul confirmă fără verificare; mesajele reținute peste limită se pierd (L7-D17); un hoț de mnemonic pe clientul oficial nu produce avertisment (L7-D18). **Test (Faza 9, starea azi):** SCN-D în enumerarea de crash-uri, cu varianta falsificată, și `KeyChangeTest`/`TrustFlowTest` pe JVM, rulate local, iar SCN-D și în `messaging-exit-gate.yml`; suita KC1–KC13 ca atare nu e construită (KC13, impersonarea la primul contact, lipsește; design §22.13 punctul 14, §22.15 punctul 7); pasul 5 pe dispozitive neexecutat.

### S13. Plata de la un exchange cu KYC direct la subadresa GHOST
Obține (exchange-ul): „clientul X a plătit o subadresă asociată GHOST” doar dacă poate recunoaște subadresa (nu poate: subadresă unică per factură, nelegată public de GHOST). **Rezidual:** dacă utilizatorul declară scopul plății. Mitigare: avertisment înainte de plată (FR-6.8). **Test:** review UX.

## 8. Registrul de risc rezidual (delta față de §15 din spec)

| ID | Risc | Prob | Impact | Stare după v2.1 |
|---|---|---|---|---|
| R-02 | Endpoint compromis | Med | Critic | limitat la fereastra de acces + 7 zile istoric |
| R-04 | Corelare relay/GPA | Med | Mare | redus prin Tor + padding + polling constant; rezidual statistic |
| R-07 | Linkabilitate plată | **Scăzut** (era Med) | Mare | blind tokens + Monero; rezidual: exchange KYC |
| R-10 | Abuz/spam/brigading | Mare | Mare | ADR-13; rezidual: majorități reale |
| R-14 (nou) | Issuer compromis | Scăzut | Med | pierdere financiară per perioadă; confidențialitate: atacuri active de tip n−1 și de prezență (LIMITE L6); niciun key tagging datorită ES fixat (corectat în Faza 8, design §18 F2: formularea „fără impact pe confidențialitate” era prea tare) |
| R-15 (nou) | Dependență de Tor (blocare) | Med | Med | bridges; fără clearnet |
| R-16 (nou) | Reglementare Monero | Med | Med | Lightning P1 cu aceeași emitere |

## 9. Legătura cu harness-ul de invarianți

Fiecare invariant T1–T35, T36–T41 din Faza 10, T42–T47 din Faza 11 (media: obiecte uniforme, EXIF-zero, fără plaintext în repaus, custodia și ștergerea cheii, decodoare izolate, traficul media) și T58–T60 din Faza 12 (transporturi pluggable: nicio linie de bridge în afara bazei, doar binarul verificat se execută, hop-ul PT doar client→bridge) are o definiție în `ghost/test-harness/privacy/INVARIANTS.md` (T22 și T23 din Faza 8, T24 și T25 din ADR-27, T26–T35 din Faza 9); rândul fiecăruia spune din ce fază e executabil și, pentru T26–T35, ce parte e construită și rulată azi (parțial, poarta Fazei 9 nefiind îndeplinită). Faza 2 livrează: schema observabilelor permise pentru relay (`allowed-observables.json`), validatorul `capture-check` (Rust) care respinge orice captură ce conține câmpuri sau valori neadmise, și fixture-uri pozitive/negative. Din Faza 5 relay-ul emite capturi în acest format în modul test, iar validatorul rulează pe fiecare PR. Rândul AD-4 de mai sus se actualizează cu Faza 12 (Anexa B.2 a designului `docs/design/faza12-transports.md`, aplicată în felia S4): observatorul local nu mai vede Tor pe hop-ul client↔bridge după poartă; scurgerea care rămâne (IP-ul bridge-ului, volum, timing) e declarată în LIMITE L12.0.

## 10. Gate de ieșire

Faza 2 se închide prin **review independent** al acestui document și al harness-ului (persoană din afara echipei de implementare). Până atunci statusul rămâne „așteaptă review”, iar nicio afirmație din matricea de garanții nu se consideră validată.

## 11. Addendum 2026-10-04 (ADR-59, ADR-60) — decizii ale proprietarului

| Intrare | Ce se schimbă față de modelul de mai sus | Starea |
|---|---|---|
| ADR-59 (Wallet Sync), **varianta aprobată, fără issuer** | **Nu schimbă încrederea în issuer sau în relay:** issuer-ul rămâne view-only (TB-5, ADR-02), T2 și ADR-23 rămân intacte; restore-ul e derivare locală din cele 24 de cuvinte, blob-ul e criptat pe partea clientului și depus orb în namespace-ul propriu. **Adaugă un activ pe endpoint doar pentru cei care optează:** seed-ul wallet-ului stă în Keystore și în blob, sub o cheie derivată din seed-ul GHOST, deci compromiterea seed-ului GHOST sau a dispozitivului (S6) expune și fondurile; se declară la opt-in (CP-10) | aprobat; fără cod |
| ADR-59, **alternativa cu issuer (respinsă)** | Clasă nouă de risc, nu incrementală: custodie de chei de cheltuit la issuer (un issuer compromis sau constrâns poate fura fonduri) și legătură identitate–wallet la issuer, ceea ce rupe T2/ADR-23. Consemnată pentru cazul în care ar fi reluată | respinsă |
| ADR-60 (migrare între versiuni, `kill_flag`) | Operatorul de distribuție (AD-1) poate comanda, printr-un bit în manifestul semnat, ștergerea automată a datelor locale ale tuturor utilizatorilor, fără confirmare și fără export. Nu e o clasă nouă de încredere (poate deja publica un update oarecare), dar scade costul abuzului. Condițiile de semnare (prag, jurnal de transparență, anti-rollback) sunt cele ale designului Fazei 14 (CS-D1, CS-D3, ADR-38 punctul 6, ADR-49). Reziduu: pierderea conversațiilor locale la o ștergere necerută, acceptat de proprietar; consimțământ la onboarding (CP-10) | aprobat; fără cod |
