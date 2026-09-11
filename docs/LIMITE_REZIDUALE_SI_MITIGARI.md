# Limitele reziduale și mitigările lor

| Câmp | Valoare |
|---|---|
| Status | Analiză + ADR-13…ADR-16 **propuse** (neaprobate) |
| Completează | `GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §7 |
| Data | 2026-09-10 |

## 0. Principiul

Cele patru limite din §7 nu pot fi **eliminate**: sunt proprietăți ale lumii fizice (dispozitivul e al utilizatorului), ale rețelei (cineva poate vedea tot) sau ale încrederii (un membru care a primit cheia a primit și conținutul). Ce se poate face pentru fiecare, pe patru straturi:

1. **Prevenire** — scade probabilitatea evenimentului.
2. **Limitarea pagubei** — când se întâmplă, expune cât mai puțin (blast radius).
3. **Detectare** — utilizatorul și grupul află devreme.
4. **Recuperare** — există o cale înapoi la o stare sigură, fără a pierde identitatea.

Plus un strat **non-tehnic**: norme, stimulente economice, disclosure onest. Regula CP-10 rămâne: nimic din ce urmează nu se afirmă în UI până nu are test sau review.

---

## L1. Dispozitiv compromis

**Ce poate face atacatorul:** citește tot ce vede utilizatorul (ecran, tastatură, notificări), extrage baza de date locală dacă are root, extrage cheile dacă nu sunt în hardware, se dă drept utilizator.

**De ce e ireductibil:** aplicația rulează pe sistemul atacatorului. Orice verificare „anti-root” rulează și ea pe acel sistem și poate fi mințită.

| Strat | Mitigare | Prio | Evidență |
|---|---|---|---|
| Prevenire | Cheile de identitate și cheia DB în **Android Keystore hardware-backed (StrongBox când există)**, neexportabile, cu autentificare biometrică/PIN per deblocare. Un atacator cu root citește DB-ul deschis, dar **nu poate exporta cheile** ca să impersoneze utilizatorul de pe alt dispozitiv | P0 (FR-1.7) | test: cheia are `isInsideSecureHardware`; export eșuează |
| Prevenire | **Auto-lock** agresiv (implicit 1 min fundal) + PIN de aplicație; FLAG_SECURE; IME incognito; avertisment tastatură terță; fără link previews | P0 (ADR-08) | T10, UI tests |
| Prevenire | Recomandare în onboarding: GrapheneOS / dispozitiv dedicat pentru profiluri de risc ridicat; explicat de ce | P0, non-tehnic | review UX |
| Limitare | **Mesaje efemere implicit** (7 zile în DM, configurabil per canal): un dispozitiv compromis azi expune doar ultimele 7 zile, nu istoricul | P0 (FR-4.4 devine default-on) | test expirare |
| Limitare | **Pseudonime per canal** (ADR-04): compromiterea nu leagă automat toate canalele de o persoană, dacă nu a făcut „reveal” | P0 | T14 |
| Limitare | **Post-compromise security** din libsignal și MLS: după ce atacatorul pierde accesul, ratchet-ul se vindecă singur; documentăm că PCS nu ajută cât timp accesul persistă | P0 (biblioteci) | vectori bibliotecă |
| Detectare | **Atestare hardware a cheii de identitate** (Android Key Attestation): lanțul de atestare se publică în prekey bundle; contactul vede în safety view „cheie în hardware: da/nu”. Nu detectează malware, dar exclude clasa „cheie copiată pe alt telefon” | P1 | ADR-14 |
| Detectare | **Lista de dispozitive și sesiuni** vizibilă utilizatorului; orice dispozitiv nou al unui contact = avertisment blocant (FR-4.5); safety number verificabil offline | P0 | teste schimbare cheie |
| Recuperare | **Certificat de revocare** semnat cu cheia de identitate (sau derivat din mnemonic pe alt dispozitiv), publicat ca blob în namespace-ul identității: contactele și grupurile îl preiau la sync și scot dispozitivul/identitatea; utilizatorul re-derivă identitatea din mnemonic pe un dispozitiv curat și trece prin **re-verificare** a safety number cu contactele | P0 (FR-1.9) | test: dispozitiv revocat nu decriptează epoch-uri noi |
| Recuperare | **Duress PIN**: un PIN secundar care șterge cheile locale și afișează un profil gol; explicat onest că ștergerea pe flash e best-effort (§8.1) | P2 | test wipe |
| Non-tehnic | Disclosure în UI, în limbaj simplu: „Dacă telefonul tău e compromis, GHOST nu te poate proteja. Iată ce reduce paguba: …” | P0 (CP-10) | review legal/UX |

---

## L2. Adversar global pasiv (GPA)

**Ce poate face:** vede toate legăturile din rețea; corelează momentul și volumul intrării tale în Tor cu momentul și volumul ieșirii către un relay `.onion`. Tor nu apără împotriva acestui adversar prin design.

**De ce e ireductibil:** orice sistem cu latență mică și trafic dependent de activitatea utilizatorului scurge un semnal statistic. Singura apărare completă e traficul constant, independent de activitate, cu costuri de baterie/rețea.

| Strat | Mitigare | Prio | Evidență |
|---|---|---|---|
| Prevenire | **Padding pe bucket-uri** 1/4/16/64 KiB (ADR-09) | P0 | T9 |
| Prevenire | **Polling la ritm constant, independent de activitate**: clientul cere loturi de dimensiune fixă la intervale fixe + jitter, indiferent dacă utilizatorul a scris sau nu. Un observator vede același tipar de la un utilizator inactiv și de la unul activ. Costul: baterie (măsurat, NFR-5) | P1 | ADR-15; test: distribuția traficului în idle vs activ e statistic indistinctă |
| Prevenire | **Trimitere întârziată („mixing” local)**: forumul nu e real-time; postările pot pleca cu întârziere aleatoare 0–N minute (setare per canal, implicit pornită în high-privacy mode), ceea ce rupe corelarea „a apăsat send la 12:03:41 → blob apărut la relay la 12:03:43” | P1 | ADR-15; test latență distribuție |
| Prevenire | **Circuite izolate** per canal/scop și **guard diversity** (Arti) | P0 (ADR-01) | test izolare |
| Prevenire | **Bucketizare la citire**: mai multe canale împart același bucket de fetch, clientul filtrează local (PIR-lite) — observatorul relay-ului vede bucket-ul, nu canalul | P2 | ADR-15 |
| Prevenire | **Cover traffic** cu politică conștientă de baterie (FR-2.6) | P2 | măsurare NFR-5 |
| Limitare | Chiar dacă GPA leagă „acest IP folosește GHOST”, nu află **cu cine** vorbește sau **ce**: conținut E2E, relay-uri blind, entitlement nelegabil. Paguba maximă = „este utilizator GHOST” + tipar de activitate | — | matricea de garanții |
| Non-tehnic | Disclosure: „rezistență, nu imunitate” (CP-07). Pentru utilizatorii cu adversar statal se recomandă explicit: rețea publică, nu cea de acasă; bridges; dispozitiv dedicat | P0 | review UX |

---

## L3. Membru de grup rău-intenționat

**Ce poate face:** a primit cheia canalului, deci **a primit conținutul**: îl poate copia, fotografia ecranul, redistribui; poate face spam/phishing; poate colecta pseudonimele; poate încerca să scoată membri la „reveal”; poate corela momentele de activitate.

**De ce e ireductibil:** nu există criptografie care să dea cuiva acces la conținut și să-l împiedice să-l rețină. „Invalidarea APK-ului” nu e posibilă: nu putem opri software pe telefonul altcuiva, iar un atacator folosește oricum un client modificat.

### 3.1 Ideea propusă: flag-uri de la utilizatori cu prag configurabil

Ideea e bună și **implementabilă** în forma corectă: pragul nu „invalidează APK-ul”, ci declanșează **o operațiune criptografică pe care grupul o poate face**: `Remove` în MLS (epoch nou → membrul nu mai decriptează nimic de acum înainte) plus efecte economice asupra celui care l-a adus. Analiza:

**Ce funcționează**
- Fiecare flag e un **mesaj MLS de aplicație semnat** de pseudonimul flagger-ului: `Flag{target_pseudonym, reason_code, epoch}`. Toate clienții din canal îl văd și îl numără identic (aceeași sursă de adevăr, fără server).
- **Pragul** e în **politica canalului** (obiect MLS semnat de creator/delegați): număr absolut sau fracțiune din membri activi, cu minim absolut (ex. `max(3, 20%)`).
- Când pragul e atins, **orice client cu rol de moderator (sau, în canalele fără moderatori, primul client care observă pragul) emite `Remove`**. Rezultatul: membrul iese, epoch avansează, cheile vechi nu-i mai folosesc pentru mesaje noi. Este exact FR-3.8.
- Cel scos își păstrează entitlement-ul (token-urile sunt nelegabile — nu putem și nu vrem să-l identificăm la issuer). Dar e **afară din acel canal** și, prin propagarea deciziei, poate fi ținut afară din canalele care aleg să accepte lista.

**Ce nu funcționează sau e periculos**
- **Brigading / Sybil**: un atacator cu 3 conturi scoate pe oricine. Într-un sistem plătit și invite-only, fiecare cont costă un abonament și o invitație, ceea ce ridică prețul, dar nu îl face imposibil.
- **Cenzura prin flag**: majoritatea poate scoate o minoritate incomodă. E o decizie de produs: forumul e privat, creatorul canalului răspunde de politica lui; noi dăm instrumentul și îl facem transparent.
- **Flag-urile scurg metadate în grup**: cine pe cine a raportat. Se vede doar în canal (pseudonime), niciodată la relay. Opțional: flag-uri **ascunse** până la prag (commitment publicat imediat, dezvăluire la prag) — mai complex, P2.

**Cum se face rezistent la abuz (propunere ADR-13)**
1. **Sponsor și „strike”**: în MLS, cine adaugă un membru e vizibil (`Add` semnat). Sponsorul răspunde pentru cine aduce: la fiecare membru sponsorizat scos prin prag, sponsorul primește un strike; la K strike-uri pierde dreptul de a adăuga în acel canal; politica poate escalada până la scoaterea sponsorului. Stimulent puternic pentru invitații atente, coerent cu modelul de referral.
2. **Ponderare după vechime**: flag-urile membrilor cu < X zile în canal contează 0 sau 0,5. Un atacator trebuie să aștepte, ceea ce costă abonamente.
3. **Diversitate a flagger-ilor**: pragul cere flag-uri din cel puțin k **subarbori de sponsorizare distincți** (membrii adăugați de același sponsor numără ca unul). Blochează atacul „îmi aduc trei conturi”.
4. **Cool-down și drept la răspuns**: după N flag-uri (sub prag) membrul intră în **carantină**: read-only, mesajele sale ascunse local pentru cine vrea; are un interval să răspundă înainte de `Remove`. Reduce eroarea și cenzura la cald.
5. **Probațiune la intrare**: membru nou = read-only și limită de rată în primele X ore/zile, fără istoric (history policy „none”). Un atacator care intră doar ca să extragă istoricul nu primește nimic.
6. **Listă de excludere semnată, portabilă, opt-in** (§11.2 din spec): canalul publică lista pseudonimelor scoase; alte canale ale aceluiași „creator/comunitate” pot importa lista. Deoarece pseudonimele sunt per canal (ADR-04), portabilitatea reală cere o **verificare de identitate la intrare**: canalele „cu verificare” cer la `Add` un commitment la identitatea de bază (hash + dovadă), astfel încât o excludere se aplică persoanei, nu pseudonimului. Este un compromis explicit între unlinkability și reputație, **ales per canal și afișat membrilor** înainte de a intra.

### 3.2 Mitigări independente de flag-uri

| Strat | Mitigare | Prio |
|---|---|---|
| Prevenire | Canale mici, invite-only; **politica de istoric „fără istoric pentru membri noi”** implicită | P0 (FR-3.8) |
| Prevenire | **Probațiune** (read-only + rate limit) pentru membri noi | P1 |
| Prevenire | „Reveal” (legarea pseudonimului de identitatea de bază) e **opt-in, per persoană, cu avertisment**: un membru rău nu poate forța pe nimeni la deanonimizare | P0 (ADR-04) |
| Limitare | **Mesaje efemere per canal** + fără media descărcabilă implicit (view-once pentru media sensibilă, cu avertismentul onest că screenshot-ul rămâne posibil) | P1 |
| Limitare | Pseudonime per canal: leak-ul dintr-un canal nu deanonimizează participarea în altele | P0 |
| Detectare | **Traitor tracing pentru media** (P2, cercetare): pentru fișiere marcate „sensibile”, expeditorul criptează **o variantă cu filigran invizibil per destinatar** (cost N× pentru grupuri mici); un leak identifică pseudonimul sursă. Pentru text nu există echivalent robust la screenshot; se documentează ca limită | P2 |
| Detectare | Flag-uri + carantină (3.1) | P1 |
| Recuperare | `Remove` MLS, strike pe sponsor, listă de excludere; **rotire** a cheii canalului la fiecare scoatere (inerent MLS) | P0/P1 |
| Non-tehnic | Reguli de canal afișate la intrare; rolul moderatorilor; termeni: GHOST nu poate șterge ce a fost deja copiat | P0 |

---

## L4. ISP-ul vede că folosești Tor

**Ce vede:** conexiuni către relay-uri Tor cunoscute (listă publică) sau tipare de trafic Tor. Nu vede destinația, conținutul sau GHOST ca aplicație.

**De ce e ireductibil:** cineva trebuie să transporte pachetele. Se poate ascunde *ce* protocol e, nu *că* există trafic.

| Strat | Mitigare | Prio | Evidență |
|---|---|---|---|
| Prevenire | **Bridges + pluggable transports**: WebTunnel (trafic care arată ca HTTPS către un site obișnuit), obfs4, Snowflake (WebRTC). Arti le suportă; livrăm un set de bridges implicite în manifestul semnat și rotim | P1 (ADR-16) | test: captură nu conține fingerprint Tor |
| Prevenire | **Mod „auto”**: clientul încearcă Tor direct; dacă e blocat sau utilizatorul alege „ascunde utilizarea Tor”, trece pe bridges; niciodată pe clearnet | P1 | test fail-closed |
| Prevenire | Opțiunea **Tor peste VPN** (VPN-ul utilizatorului): ISP-ul vede VPN, furnizorul VPN vede Tor; explicat ca mutare a încrederii, nu eliminare | P1, non-tehnic | disclosure |
| Prevenire | **Polling la ritm constant** (L2): utilizarea GHOST nu se distinge de orice altă utilizare Tor prin tipar temporal | P1 | ADR-15 |
| Limitare | Chiar dacă ISP-ul știe „Tor”, nu știe „GHOST”: aplicația nu are domenii, IP-uri sau certificate proprii pe clearnet; distribuția prin F-Droid repo/onion mirror | P0 (ADR-07) | T6 |
| Non-tehnic | Ghid regional în app: unde utilizarea Tor e riscantă legal, recomandăm bridges implicit și disclosure clar; nu promitem invizibilitate | P0 | review legal |

---

## L5. Riscuri reziduale ale implementării (adăugat după review-ul Fazei 6, 2026-09-11)

| Risc | Stare | Plan |
|---|---|---|
| **PoW pe onion service nerezolvat de clienți.** Relay-ul poate cere proof-of-work la introducere (Prop 327); clientul Arti nu compilează `hs-pow-full` (experimental). Sub un flood de introduceri, clienții GHOST nu primesc prioritate și pot fi refuzați ca oricine altcineva (DoS, AS-11) | acceptat temporar (ADR-01, torrc) | reevaluare când `hs-pow-full` devine stabil în Arti; gate-ul de feature-uri împiedică activarea accidentală |
| **Bridges doar simple până în Faza 12.** O linie `IP:PORT FINGERPRINT` ascunde relay-ul de gardă, nu faptul că traficul e Tor (AD-4) | cunoscut | transporturi pluggable (lyrebird/obfs4, snowflake, webtunnel) în Faza 12, ADR-16 |
| **Keystore Arti compilat și deschis** (gol) | test unitar (după creare) și test live (după bootstrap și conexiuni onion, jobul CI `live-tor`) | vezi `deny.toml` (RUSTSEC-2023-0071) |
| **Build nativ reproductibil doar la aceeași cale** | parțial | builder cu căi fixe în Faza 14 (ADR-07) |

## 5. Sinteză: ce rămâne cu adevărat imposibil după toate acestea

| Limită | După mitigări rămâne |
|---|---|
| Dispozitiv compromis | Atacatorul vede tot ce vede utilizatorul, cât timp are acces. Nu poate extrage chei hardware; nu vede istoricul expirat; pierde accesul după revocare + PCS |
| GPA | Poate afla „acest IP folosește Tor, posibil GHOST” și un tipar temporal; cu polling constant, tiparul nu reflectă activitatea. Nu poate afla cu cine sau ce |
| Membru rău-intenționat | A văzut ce s-a postat cât a fost membru. Nu vede nimic după `Remove`; nu poate deanonimiza pe nimeni fără „reveal”; îl costă (strike-uri pe sponsor, abonament pierdut din canal) |
| ISP | Vede trafic către o destinație (bridge/VPN/Tor); cu WebTunnel arată ca HTTPS. Nu vede GHOST |

Formularea permisă în UI: „Reducem paguba și o facem vizibilă. Nu o putem face zero.”

---

## 6. ADR-uri propuse (de aprobat)

- **ADR-13 — Guvernanță în canal: flag-uri, prag, carantină, strike pe sponsor, liste de excludere opt-in.** Implementare: politica canalului ca obiect MLS semnat; `Flag`, `Quarantine`, `Remove`, `Strike` ca mesaje/commit-uri MLS; ponderare după vechime și diversitatea sponsorilor; canale „cu verificare” pentru portabilitatea excluderii. Fază: 10 (MLS) pentru primitive, 13 (UX) pentru interfață. P1.
- **ADR-14 — Atestare hardware a cheilor și recuperare după compromitere.** Key Attestation în prekey bundle; certificat de revocare ca blob; re-verificare safety number; duress PIN (P2). Fază: 3 și 9. P1 (revocarea este P0 deja).
- **ADR-15 — Traffic shaping: polling constant, trimitere întârziată, bucketizare la citire.** Fază: 7 (sync) și 12 (hardening). P1, bucketizare P2.
- **ADR-16 — Rezistență la cenzură: bridges implicite în manifest, mod auto, WebTunnel/obfs4/Snowflake.** Fază: 6 (network) și 12. P1.

Fiecare ADR primește teste de acceptare în `test-harness/` înainte de a fi marcat „done”, conform DoD.
