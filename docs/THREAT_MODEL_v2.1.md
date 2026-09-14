# GHOST — Threat Model v2.1

| Câmp | Valoare |
|---|---|
| Status | Livrabil Faza 2 — **așteaptă review independent** (gate-ul de ieșire al fazei) |
| Data | 2026-09-10 |
| Bază | Spec v2.0 §2, §6.4, §11, §15; ADR-01…ADR-16; `LIMITE_REZIDUALE_SI_MITIGARI.md` |
| Metodă | Active → adversari (capabilități explicite) → suprafețe și granițe de încredere → scenarii → mitigări legate de FR/ADR → risc rezidual → test (T-ID) |
| Completări | 2026-09-13, Faza 8 (ADR-22 … ADR-26, propuse 2026-09-12 și aplicate; design `docs/design/faza8-issuer.md` Anexa B): AS-6, AS-9, AD-1, AD-3, TB-4; §5 (token-uri și cheia ES); §6 (șase rânduri: cumpărare, redeem, invitație, revendicare, livrare prin drop, reîmprospătare); S2, S11; R-14 (corectat după design §18 F2); §9 (T1–T23). După review-ul documentelor: §5 (păstrarea cheii CREDIT), S2 (orice cheie INVITE sau CREDIT ținută, design §19.1 regula 4), S11 (retenția nullifier-elor de invitație) |

## 1. Scop și presupuneri

**În scop:** clientul Android, relay-urile blind, entitlement issuer-ul, transportul Tor, schemele de protocol, stocarea locală, distribuția/actualizarea, lanțul de aprovizionare, plata pe Monero, guvernanța în canal.

**Presupuneri de securitate (dacă una cade, garanțiile de mai jos cad cu ea):**

| ID | Presupunere | Dacă e falsă |
|---|---|---|
| A1 | libsignal și OpenMLS implementează corect protocoalele; noi nu le modificăm | confidențialitatea conținutului cade (R-03) |
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
| AS-3 | Stare libsignal (sesiuni, prekeys) și stare OpenMLS (epoch, tree) | SQLCipher | Citirea mesajelor viitoare până la vindecare PCS |
| AS-4 | Conținut: mesaje, postări, media în clar | doar pe endpoint, în DB criptat, decriptat în memorie | Confidențialitate |
| AS-5 | Cheia DB (SQLCipher) | Keystore | Acces la AS-3/AS-4 offline |
| AS-6 | Token-uri de acces, de invitație și de credit (valoare la purtător; secretul de referral e retras, ADR-24) | DB criptat | Abuz de cotă; furtul creditelor; ziua finalizării unui lot (LIMITE L1.1, E19) |
| AS-7 | Graful social: cine e în ce canal, cine invită pe cine | distribuit: doar în capetele MLS; sponsor vizibil în canal | Deanonimizare relațională |
| AS-8 | Metadate de trafic: momente, dimensiuni, namespace-uri | observabile la relay/rețea | Corelare activitate |
| AS-9 | Datele issuer-ului: facturi, sume, subadrese, nullifier-e de invitație și de credit, revendicări și adrese de plată în așteptare, `issued.journal`, instantanee, contoare săptămânale, istoricul portofelului de vizualizare (fără commitment-uri de referral, ADR-24) | issuer (redb, jurnal, portofel); stația de plăți a operatorului | Linkabilitate financiară (nu identitate); retenția: ADR-26 punctul 5 |
| AS-10 | Cheia de semnare release + manifest | HSM/offline | Distribuție malițioasă |
| AS-11 | Cheile relay-urilor (onion service, Noise) | relay | Impersonare relay; DoS; nu conținut |
| AS-12 | Codul sursă și dependențele | GitHub, registre | Supply chain |

## 3. Adversari și capabilități

| ID | Adversar | Capabilități presupuse | Ce NU poate |
|---|---|---|---|
| AD-1 | **Operatorul GHOST** (insider, sau operator constrâns legal) | Controlează issuer-ul, manifestul de release, unul sau mai multe relay-uri, jurnalele lor, infrastructura; poate publica versiuni noi | Nu deține chei de conținut (CP-01); nu poate semna release fără cheia offline (A7); nu poate lega token-uri de plăți (A4) dincolo de scurgerea declarată L1–L7 a Fazei 8 (momente și prezență, LIMITE L6; testul T2) |
| AD-2 | **Relay compromis / malițios** | Vede tot traficul propriu: namespace-uri, hash-uri, bucket-uri, momente, nullifier-e; poate refuza, întârzia, șterge, servi date vechi; poate colabora cu alte relay-uri | Nu vede IP (onion), identități, conținut, apartenență; nu poate forja blob-uri acceptate (hash + AEAD) |
| AD-3 | **Issuer compromis** | Vede facturi, sume, înălțimi, subadrese, istoricul portofelului de vizualizare, mesaje blind, nullifier-e de invitație și de credit, adrese de plată, momentul fiecărui apel (în rulări liniștite, cel mult 6 apeluri legate per cumpărare); poate emite token-uri fraudulos (cel mult 6 săptămâni de acces înainte; invitații și credite până la revocarea I1); poate refuza sau întârzia serviciul (n−1, LIMITE L6 E8) | Nu vede identități GHOST, IP; nu poate lega token deblindat ↔ factură (dovada de permutare, ADR-22); nu poate alege cheia, prețul sau perioada unui singur client (ES fixat, ADR-22); nu poate decripta nimic |
| AD-4 | **Observator de rețea local** (ISP, Wi-Fi ostil, angajator) | Vede IP-ul utilizatorului și că vorbește cu Tor/bridge; volum și timing | Destinație, conținut, GHOST ca aplicație (cu bridges cu transport pluggable: nici Tor; până în Faza 12 clientul acceptă doar bridges simple, recognoscibile ca Tor) |
| AD-5 | **Adversar global pasiv** | Vede toate legăturile; corelare statistică intrare/ieșire Tor | Conținut; cu polling constant, tiparul nu reflectă activitatea |
| AD-6 | **Membru de grup rău-intenționat** | Citește tot ce se postează cât e membru; copiază; spam; flag abuziv; încearcă „reveal” | Nu decriptează după `Remove`; nu deanonimizează fără reveal; nu vede IP |
| AD-7 | **Corespondent DM rău-intenționat** | Cunoaște identitatea de bază; păstrează istoricul; screenshot | Nu vede alte canale; nu vede IP |
| AD-8 | **Atacator cu dispozitivul deblocat / malware cu root** | Tot ce vede utilizatorul; DB deschis | Nu exportă chei hardware; nu vede istoricul expirat (excepție: hash-urile de deduplicare ale blob-urilor expirate recent, fără conținut, LIMITE L1.1; tot acolo, statisticile OS de trafic și baterie per aplicație, din care se vede când s-a trimis sau primit mult); pierde accesul la revocare |
| AD-9 | **Atacator de lanț de aprovizionare** | Compromite o dependență, un registru, CI, un mainteiner | Nu trece de allowlist/checksums/cargo-deny; nu produce APK cu hash reproductibil identic fără a fi în sursă |
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
| TB-6 | Build ↔ release | artefact reproductibil, manifest semnat offline | cheia de semnare (niciodată în CI) |
| TB-7 | Membru ↔ grup MLS | mesaje de aplicație, commit-uri, politici semnate, flag-uri | identitatea de bază (fără reveal explicit) |

## 5. Ciclul de viață al cheilor

| Cheie | Generare | Stocare | Rotire | Revocare/Distrugere |
|---|---|---|---|---|
| Entropie rădăcină | CSPRNG 256 bit la prima pornire | Keystore-wrapped; mnemonic la utilizator | niciodată (identitate) | doar prin abandonarea identității |
| Identitate Ed25519 | HKDF(`ghost/v1/identity`) | Keystore | la compromitere → identitate nouă | certificat de revocare ca blob (ADR-14) |
| Pseudonim per canal | HKDF(`ghost/v1/channel-pseudonym` ∥ channel_id) | derivat la nevoie | odată cu părăsirea canalului | inerent la `Remove` |
| libsignal (identity, prekeys, sesiuni) | biblioteca, seed din ramura messaging | SQLCipher | prekeys periodic; ratchet per mesaj | ștergere sesiune; PCS |
| OpenMLS (epoch secrets) | biblioteca | SQLCipher | fiecare commit avansează epoch-ul | secretele vechi șterse conform politicii de istoric |
| Cheie fișier media | random 256 bit per fișier | învelită în contextul DM/MLS | per fișier | expiră cu mesajul |
| Cheie DB | Keystore | Keystore | la cerere (re-cifrare) | wipe / duress |
| Token-uri de acces/invitație/credit (chei de semnare blind ale issuer-ului) | ceremonie offline (K1), o cheie RSA-2048 per (tip, epocă), cu dovadă de permutare; token-urile: blind, cu blinding derivat dintr-o sămânță per flux | token-uri: DB criptat; chei private: fișiere sigilate per (tip, epocă) pe discul criptat al issuer-ului, în memorie doar o fereastră (ADR-26 punctul 4) | săptămânal (acces), 4 săptămâni (invitații), 13 săptămâni (credite) | listă de revocări în ES; nullifier la relay și issuer; cheia privată distrusă după ultima factură care o folosește (cel târziu sfârșitul epocii + 42 de zile; cheia CREDIT a epocii c până la `end(c + 1)` + 8 zile, pentru `RefreshCredit`) |
| Cheia Programului de Entitlement (ES) | Ed25519, offline, disciplina de custodie a cheii de release (A7); alpha: cheie doar de stagenet, generată în afara repository-ului (Q20) | offline; cheia publică fixată per rețea în biblioteca nativă | la fiecare versiune nouă a ES-ului (doar se completează) | ceremonia K1 cu cheia offline reală înaintea primului ES de mainnet (Faza 16/17) |
| Chei relay (onion, Noise) | operator | HSM/disc criptat | politică FR-5.7 | manifest actualizat |
| Cheie release | offline/HSM | offline | drill anual | rotație de urgență (runbook) |

## 6. Matricea de expunere a metadatelor

Ce poate observa fiecare actor, per eveniment. „—” = nimic. Fiecare rând e un invariant testat (T-ID).

| Eveniment | Relay | Issuer | Rețea locală | Membri canal | Test |
|---|---|---|---|---|---|
| Postare în canal | namespace, hash, bucket, moment ±granularitate | — | trafic Tor, volum bucket | pseudonim, conținut, minut | T1, T9, T13 |
| Citire canal | namespace, cursor, moment; toate cererile unui client pentru un namespace sunt legabile între ele prin `capability_scope` și prin valorile de cursor pe care le emite relay-ul (un relay rău-intenționat poate folosi cursoare unice drept cookie între circuite și sesiuni); ritm de listare fix, același pentru toți clienții | — | trafic Tor | — | T1, T19, T21 |
| DM trimis | namespace inbox destinatar, hash, bucket | — | trafic Tor | — | T1 |
| Publicare prekeys | namespace identitate, hash | — | trafic Tor | — | T1 |
| Cumpărare abonament | — (prima folosire a token-urilor noi, la un slot de activare: scurgerea declarată L1, LIMITE L6) | subadresă, sumă, înălțimi, istoricul portofelului de vizualizare, momentul fiecărui apel (în rulări liniștite), numărul fix de token-uri, tipul plății | trafic Tor | — | T2, T22, T23 |
| Redeem token la relay | nullifier, perioadă (săptămână), namespace, moment, hash-ul capabilității emise; token-ul e legat de slotul relay-ului; nullifier-ele persistate cu etichetă de legare cel mult două săptămâni | — | trafic Tor | — | T1, T2 |
| Invitație acceptată | — | nullifier-ul invitației, momentul, un trial; nicio legătură cu factura celui care invită | trafic Tor | sponsor (la Add) | T16, T2 |
| Revendicare credit (plată de referral) | — | numărul de credite, adresa de plată, momentul | trafic Tor | — | T2 |
| Livrare credit (drop) | un blob de 1 KiB într-un namespace nou, listat de alt client (credit sau blob fals, la un moment tras la activare) | — | trafic Tor | — | T1, T2 |
| Reîmprospătare credit primit | — | creditul primit (cunoscut de invitatul care l-a trimis), momentul unei rulări liniștite a celui care invită, un credit nou blind al aceleiași epoci | trafic Tor | — | T2 (LIMITE L6, E17) |
| Flag / Remove | namespace, hash | — | — | flagger, țintă, decizie | T1 |
| Sync periodic (idle) | per pereche (relay, namespace): în prim-plan, listări cu `limit` 128 la 30 s × U[0,5; 1,5], cu fază independentă per pereche; în fundal, un eveniment per pereche per job, la momente alese de OS; get-uri câte produc scrierile altora; verificări ale propriilor copii (`check`) | — | începutul și sfârșitul sesiunilor Tor (aplicație deschisă, joburi OS, câte un bootstrap Tor per job: LIMITE L4); rată agregată proporțională cu numărul de perechi; momentele listărilor nu depind de activitate, volumul da (până la cover traffic, P2) | — | T19 (Faza 7, JVM); T17 (Faza 12, doar high-privacy mode cu cover traffic P2) (ADR-15, ADR-20) |

Notă (Faza 7, ADR-20, design §6.3): trimiterile (hash, bucket, bucket de TTL, minut) urmează scrierile proprii, imediat în modul standard și cu întârziere U[0, 10 min] în high-privacy mode. Namespace-urile unui client nu împart un ceas de listare în prim-plan (faze independente, izolare de circuit per namespace, T21), dar toate perechile pornesc în primele 30 s după deschiderea aplicației și în primele 90 s ale fiecărui job de fundal. Reziduurile sunt în `LIMITE_REZIDUALE_SI_MITIGARI.md` L2.1.

Notă (Faza 8, ADR-22 … ADR-26, design `docs/design/faza8-issuer.md` §1.2): sub AD-1 (issuer-ul și toate relay-urile la același operator), singura informație care poate trece de la issuer la relay-uri e scurgerea declarată L1–L7: ziua slotului de activare a primei folosiri a unui lot; săptămâna de sfârșit a acoperirii; „online” la un apel imediat cerut de utilizator și începutul trialului; tipul cumpărării; „în rulare liniștită” la fiecare apel de fundal (≤ 3 biți per apel, cel mult 6 apeluri legate per cumpărare); momentul primei apariții a plății în portofel; începutul unei cumpărări după `ENTITLEMENT_NEEDED`. Orice altceva e o încălcare T2 (INVARIANTS T2, T22, T23). Reziduurile, cu cifrele lor, sunt în `LIMITE_REZIDUALE_SI_MITIGARI.md` L6 (E1–E32).

## 7. Scenarii de atac și răspuns

Format: **Scenariu** → ce obține atacatorul fără mitigări → mitigări (FR/ADR) → rezidual → test.

### S1. Operatorul vrea să afle cine a scris o postare
Fără mitigări: ar corela IP la relay + plată + identitate. Cu: relay-uri onion-only nu văd IP (ADR-01); token-uri nelegabile de plată (ADR-02); pseudonime per canal (ADR-04); relay-uri ale altor operatori (ADR-11). **Rezidual:** dacă operatorul deține și dispozitivul (L1). **Test:** T1, T2, T6.

### S2. Issuer compromis emite token-uri gratis și înregistrează tot
Obține: abonamente gratuite; datele issuer-ului (facturi, sume, înălțimi, nullifier-e de invitație și de credit, adrese de plată în așteptare; fără jurnal de cereri, ADR-26). Nu obține: identități, conținut, legătura token deblindat ↔ factură. Mitigări (Faza 8): o cheie per (tip, epocă) în Programul de Entitlement semnat offline și inclus în versiunea aplicației, fără nicio cale de rețea pentru chei (ADR-22); chei private sigilate, în memorie doar o fereastră de cel mult 6 săptămâni înainte (ADR-26); revocare prin runbook-ul I1; reconciliere „token-uri semnate vs. pachete și trialuri”, cu verificări independente pe care un issuer compromis nu le poate falsifica; spend key offline (TB-5). **Rezidual:** token-uri de acces falsificate pentru cel mult 6 săptămâni înainte; invitații și credite falsificate sub orice cheie INVITE sau CREDIT ținută (cele curente, epoca CREDIT anterioară, cele păstrate pentru facturi deschise) până când runbook-ul I1 revocă acele epoci la issuer (imediat); creditele și invitațiile oneste nefolosite ale epocilor revocate se pierd (LIMITE L6, E12); issuer-ul nu mai are commitment-uri de referral; reconciliere independentă prin portofelul de vizualizare al stației operatorului (plafon cumulat de 10 %) și numărătorile relay-urilor (suma pe sloturi, per săptămână; exportul lor e încă deschis, LIMITE L5). **Test:** T2, T22, reconcilierea (`ghost-issuer-ops reconcile-check`), scenariile de crash I-A…I-M ale issuer-ului (Faza 8).

### S3. Relay malițios servește istoric trunchiat sau blob-uri vechi
Obține: cenzură selectivă pe namespace; nu poate forja. Mitigări: clientul scrie pe ≥2 relay-uri și compară inventarul (ADR-11); hash + AEAD detectează modificarea; cursor semnat la nivel de aplicație (MLS transcript) detectează lipsuri. **Rezidual:** întârziere; disponibilitate. **Test:** failover (Faza 5), T1.

### S4. Membru rău-intenționat scurge conținutul
Obține: tot ce a văzut. Mitigări: istoric „none” pentru noi (FR-3.8), probațiune, efemere per canal, fără screenshot și fără copierea mesajelor (ADR-27), pseudonime, flag → carantină → `Remove` (ADR-13), strike pe sponsor, filigran per destinatar pentru media sensibilă (P2). **Rezidual:** ce a copiat rămâne copiat (fotografia ecranului cu alt dispozitiv, client modificat). **Test:** Remove → nu decriptează epoch nou (Faza 10); T14; T24; T25.

### S5. Brigading cu conturi Sybil pentru a scoate un membru
Obține: fără mitigări, 3 conturi ajung. Mitigări: ponderare vechime, diversitate sponsori, carantină cu drept la răspuns, moderatori (ADR-13). **Rezidual:** o majoritate reală poate scoate o minoritate: decizie de produs, transparentă în politica canalului. **Test:** simulare guvernanță (Faza 10).

### S6. Dispozitiv cu root
Vezi L1. Mitigări: Keystore hardware, auto-lock, efemere, revocare, PCS, atestare (ADR-14). **Rezidual:** tot ce e pe ecran cât durează accesul. **Test:** T4, T10, revocare (Faza 3/9).

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

### S12. Cheia de identitate a unui contact se schimbă (MITM la prekeys sau dispozitiv nou)
Mitigări: avertisment blocant, safety number verificabil offline, atestare hardware afișată (FR-4.5, ADR-14). **Rezidual:** utilizatorul ignoră avertismentul. **Test:** teste schimbare cheie (Faza 9).

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

Fiecare invariant T1–T25 are o definiție executabilă în `ghost/test-harness/privacy/` (T22 și T23 din Faza 8, T24 și T25 din ADR-27). Faza 2 livrează: schema observabilelor permise pentru relay (`allowed-observables.json`), validatorul `capture-check` (Rust) care respinge orice captură ce conține câmpuri sau valori neadmise, și fixture-uri pozitive/negative. Din Faza 5 relay-ul emite capturi în acest format în modul test, iar validatorul rulează pe fiecare PR.

## 10. Gate de ieșire

Faza 2 se închide prin **review independent** al acestui document și al harness-ului (persoană din afara echipei de implementare). Până atunci statusul rămâne „așteaptă review”, iar nicio afirmație din matricea de garanții nu se consideră validată.
