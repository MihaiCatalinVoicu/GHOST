# B0 — Ledger de execuție și matrice de porți v2.2

Reconcilierea stării cerută de `docs/GHOST_Roadmap_v2.2.md` §3. Surse: STATUS.md (rândurile fazelor,
verificate 2026-11-09 prin self-test integral 1 194 ok / 0 FAIL și run-all 46/46 pe arborele real),
roadmap §23, specificația v2.2. Nicio poartă de mai jos nu primește PASS prin existența acestui
ledger; dovezile rămân cele din STATUS, la commit-urile menționate acolo.

## 1. Punct de control

- Branch `main`, HEAD la întocmire: `117819eb` (după `bfd22420` — închiderea verificărilor Fazei 14 —
  plus acest pachet documentar v2.2 comis ca baseline).
- Arbore curat la cod (toate fixurile F14 din 2026-11-09 comise); `docs/tools/build_ghost_v2_2.py` +
  `verify_ghost_v2_2.py` + PDF-urile `output/pdf/*v2.2*` rămân artefacte de documentație ale
  proprietarului (necomise, neincluse în dovezile de produs).
- CI local conform ADR-58; rulările de mai jos se fac în WSL (`ghost-runner`), codul sursă de
  adevăr fiind acest worktree.
- ADR-uri: aprobate 01-62 inclusiv amendamentele v2.2 documentare (ADR-01 excepție locală, ADR-38
  punct 9 înlocuit); nimic propus-nerezolvat în afara celor din §4.

## 2. Clasele de blocaj folosite în matrice

| Clasă | Sens | Cine o ridică |
|---|---|---|
| EXEC | Implementabil acum: cod, design, teste locale (WSL/emulator), documente | agentul, fără input extern |
| DEVICE | Cere dispozitive fizice (telefoane, radio, al doilea mediu de build) | proprietarul pune la dispoziție |
| 3P | Cere terți (auditori, counsel/editor, testeri umani, includere Sigsum live, GMS-free hardware cumpărat) | contractare/recrutare |
| OWNER | Decizie sau achiziție a proprietarului (token-uri hardware, domeniu, buget audit, autorizare lansare, Q3/Q18) | decizie scrisă |

Regula obiectivului curent al proprietarului: se lucrează tot ce este EXEC, în ordinea
roadmap-ului, astfel încât la final să rămână exclusiv DEVICE/3P/OWNER. Ledger-ul se actualizează
la fiecare pachet închis.

## 3. Matricea pachetelor

| Pachet | Rol | Stare | Blocaj |
|---|---|---|---|
| B0 | Reconciliere + matrice porți | **ÎNCHIS** (acest fișier) | — |
| H0 | Design protecție APK | **DESIGN REV1 COMIS** (`8c666fe8`, `docs/design/h0-apk-hardening.md`) — 4 întrebări de review rămân (Q-H0-1..4) | EXEC (review OWNER înainte de H2) |
| M0 | Fezabilitate radio | PARȚIAL: spike-uri de laborator EXEC; matricea fizică de măsurat | DEVICE (4 modele / 2 producători / 2 fără GMS / cel mai vechi API) |
| B1 | Închidere bază DM/storage/sync/media/metadate | PARȚIAL EXECUTAT 2026-11-09: AUDIT_SCOPE §0 revizit (`1f229663`), clasa head-1/SIGPIPE eliminată (`73c37285`, self-test final 1 209 ok / 0 FAIL / 0 skip), cargo-deny 0.20.2 instalat cu cele 14 cazuri de bans active; rămân rulările la scara porții F11 (T2/T32 — programate), tuning jitter/batch, Q31/Q32 | EXEC parțial + DEVICE (runner KVM, telefoane) + 3P (review captură F-T1) |
| M1 | Protocol mesh, grant-uri, design date | **DESIGN REV1 COMIS** (`ddc3140f`, `docs/design/m1-mesh-protocol.md`) — framing GHM1, Noise XX, grant semnat, PRF inventory, ACK-uri, state machine, schemă, matrice adversarială; **așteaptă review criptografic** — codul M2/M3 începe abia după el | EXEC (review OWNER/3P — porță declarată a roadmap-ului) |
| M2 | Legătură locală directă | BLOCAT DE M1/B1 | EXEC cod + DEVICE teste |
| M3 | Store/carry/forward + gateway | BLOCAT DE M2 | EXEC cod + DEVICE teste |
| M4 | Note vocale | BLOCAT DE M3 + poarta media B1 | EXEC |
| C0 | Motor apel: selecție + verificare izolare | **ANALIZA COMISĂ** (`4407ba7e`, `docs/design/c0-rtc-engine.md`): libwebrtc audio-only din sursă în builder, izolare ICE proiectată, binding DTLS prin transcript DM, impact NFR; experimentul pe două telefoane rămâne | DEVICE (experiment) + OWNER (Q-C0-1..3) |
| M5 | Apel local E2EE | BLOCAT DE C0+M2 | EXEC cod + DEVICE teste |
| B2 | Integrare Android + privacy UX | BLOCAT DE contractele M4/M5 | EXEC |
| H1 | Implementare hardening release | **JUMĂTATEA 1 COMISĂ** (`e6e11bfb`): H-01 obfuscare reală (validat pe mapping real: 747 clase, 15 nume justificate) + G-DM5 rescris pe whitelist; H-02 verificat (recipe A strip-uiește .so). **H-10 stare 2026-11-11:** jumătatea DM deja rulează app-smoke pe APK-ul release R8-minificat (`dm-emulator-run.sh`, `app-release.apk`); mecanismul update comis (`e05c7baf`: `update-emulator.sh --build-release` — fixtures/smoke contra APK-ului release minificat, semnat smokeRelease cu cheia debug de mașină, exact signer-ul din fixture root). **Rămân la H-10:** rulările de validare pe emulator (EXEC, după matricea T32/T2 — cer emulator liber) + jumătățile media/UI — ambele module de bibliotecă nu pot fi „minificate" singure (R8 trece la nivel de aplicație); patternul corect e cel app-smoke (test APK contra `app-release.apk`), de decizionat la review sau felia următoare. **H-11 lansat 2026-11-11:** repo WSL resincronizat la HEAD (`640de07`, surse+.git, `target/` păstrat); job cron `/home/runner/run-h11.sh` — așteaptă `all.done` al matricei T2, apoi rulează `selfcheck-android.sh` (două build-uri `builder-selfcheck` din imaginea `ghost-builder:24.04-5`, comparație byte APK/lib/symbols) — log `/tmp/h11.log`, marker `/tmp/h11.done`. Pornește singur după T2, fără contendere de resurse | EXEC (H-10 parțial DEVICE — emulator) |
| B3 | Candidat distribuibil + dovezi F14 | PARȚIAL FĂCUT (F14: build reproductibil în imagine, gates, recipe unificat); rămân mediul B, tag-ul semnat, workflows | DEVICE (mediul B) + OWNER (cheie tag, token-uri) + EXEC (CI-L workflows) |
| M6 | Validare integrată pe dispozitive | BLOCAT DE M3-M5/H1/B3 | DEVICE-heavy + QA independent |
| H2 | Acceptare protecție APK pe candidat | BLOCAT DE H1/B3 (+M6 varianta completă) | EXEC + 3P (audit la B4) |
| B4 | Audit extern + remediere | DESCHIS | 3P (contractare auditori, buget OWNER) |
| B5 | Private alpha (20-50 testeri) | DESCHIS | 3P (oameni) + OWNER (timp) |
| B6 | Beta controlată (200-500) | DESCHIS | 3P (oameni) + OWNER |
| M7 | Admitere module opționale | BLOCAT DE M6/H2/B4/B6 | EXEC (documentare) + OWNER (decizie) |
| B7 | Pregătit de producție + lansare | BLOCAT DE toate porțile | OWNER (autorizare semnată) |

## 4. Porțile rămase din fazele 0-18 (listă unică, cu clasă)

| # | Poartă / item | Fază | Dovadă existentă | Clasă rămasă |
|---|---|---|---|---|
| 1 | Rulări la scara porții F11 — **ÎN DESFĂȘURARE** (2026-11-09): pasul `world` (JM1-JM7 + NI-M1-7, N=300, 28 zile, 5 seeds) lansat detașat pe mașina de lucru (java pid urmărit; log `ghost/android/messaging/build/reports/media/logs/world-agent.log`, raport `.../media/exit.txt`; ≤240 min); după el: `media-exit-gate.sh mutants` (43) și `check` (G-M9). T2/T32 (DM, N=600) rămân de lansat la fel pe rând. Dovadă locală, nu gate evidence până la Q32 (D23). **Constatare reală #1**: prima rulare (14:15, heap 4g — bugetul design §15.1) a murit cu `OutOfMemoryError` la `MediaPrivacyWorldTest.kt:45` după 21 min; lumea N=300 cere >4g pe mașina locală (97 GB RAM) — rerun la 14:45 cu heap 6g (deviere documentată; relevant pentru dimensionarea runner-ului Q32). **Constatare reală #2 (în investigație)**: cu 6g lumea a rulat cap-coadă (1h45m); 8/9 teste verzi (JM1-JM7 + NI-M la violații 0, ephemeral, T25-media), dar linia de confiscare a eșuat: `no stored key_env opens an archived blob expected:<0> but was:<6>` (`MediaPrivacyWorldTest.kt:66`) — la scara PR (N=60) era 0; scala gate (N=300×28z×5 seeds) scoate 6 deschideri: **VERDICT: artefact de oracol** (`3dd7895e`) — cele 3 obiecte (×2 sloturi de manifest = 6 deschideri) au timer 7z și expiră cu ~43 min înaintea orizontului; retenția legală a cheii este deadline+24h (delete_at), oracolul măsura deadline-ul nominal; fix: expired() folosește bound-ul de retenție. Validat 120×14; **rerunul gate-scale cu fixul: VERDE în 1h34m** — JM1-JM7 PASS 0 la N=300 (2 489 obiecte, 125k stores, 65k list/get), `seizure: 0 opened (1 133 key_env × 84 606 blob-uri), control 1 454` (oracol viu); muțanții JVM 9/9 + Rust 52/52; check-ul G-M9 refuză corect raportul parțial — rămân: shards 1-8 (SCN-MA…MF + 1 000 seeded worlds), linia «5 seed pairs» (mecanismul nu există în cod — worldul rulează 1 seed pinned; drift check-vs-implementare de documentat) și linia agregată «43 mutanți» (implementarea măsoară onest 9+52 cu lista pending — drift similar). **Shard 1 rulat** (8 min): a rulat suitele media la scara PR — deoarece proprietățile `ghost.media.shard/shards` din media-exit-gate.sh NU au cititor în cod (a doua drift: scriptul documentează un mecanism de sharduire care nu există). **Constatare majoră**: liniile «SCN-MA…MF: N crash points … invariants hold» și «seeded worlds: 1000» pe care le cere G-M9 în forma gate NU au scriitor în cod — harnessul de enumerare a crashurilor media (echivalentul lui DmCrashEnumerationTest) nu a fost implementat în S7-S10; scenariile media acoperă crashuri scriptate punctual (3 teste/clasă). **Corecție după inventarul profund (pas 1 al harnessului comis `06069083`)**: enumerarea la nivel de store EXISTĂ în `:media` (`MediaStoreScenarioTest` — fiecare operație de fișier și fiecare statement, pentru jumătățile de storage ale SCN-MA/MC/ME/MF), iar migrația SCN-MF are enumerare proprie (`Migration8Test` în `:storage`). Ce lipsește pentru liniile gate: (1) **SCN-MB** — nicio enumerare de crash în `MediaUploadScenarioTest` (lipsea reală; spec §15.3 cere per-ordinal/per-object + class-10 eșantionat); (2) linii de raport cross-module din `:media`/`:storage` în raportul media (SCN-ME storage half, SCN-MF Migration8Test + testul object-set v5→M F9 G-9); (3) **seeded worlds media** (§15.4 — 1000 lumi funcționale; există doar varianta DM); (4) rerun curat al raportului + check gate. **Pașii 2-3 comiși (`222a21ec`, `16c81a24`)**: enumerarea SCN-MB a fost construită (51 de puncte, verde din prima — crash la fiecare fișier al rulării de upload, oracolele MB după fiecare reboot); liniile cross-module SCN-ME (38, din `:media`) și SCN-MF (74, din Migration8Test) cu forwardingul proprietății în test JVM pe ambele module. Toate cele șase linii SCN au acum scriitori reali. **§15.4 comis (`01ee84dc`)**: MediaSeededWorldsTest — viață completă per seed cu crash aleator pe fază, reboot+invariante+reluare, oracole finale (uploaded, verified, zero rânduri/fișiere/octeți de cheie după sweep); 20/20 verzi la validare; shard 7 = 1 000 lumi la gate. **Gate-ul media complet curat lansat** (`media-exit-gate.sh all`, raport proaspăt, heap 6g): shards 1-8 → world gate 5 seeduri (~8h) → mutanți → check G-M9; log `/tmp/gate-all.log` + `messaging/build/reports/media/logs/`. **VERDICT FINAL: `[media-report-check] OK (gate)`** — gate-ul media complet este VERDE în forma gate: 6 linii SCN, seeded worlds 1000/1000, **lumea N=300×28 zile la toate cele 5 seed pairs** (JM1-J7 la zero violații per seed; seizure 0 opened per seed cu controle vii 1 376-1 502), muțanți 9/9 JVM + 52/52 Rust. Două fixuri pe parcurs (`1136ba92`): media-mutants.sh își scrie close-out-ul în raport, iar jumătatea Rust rulează prin WSL (pe Windows bare: «cargo exited 127» la toți cei 52). **Observație de scheduling**: cele 5 seeduri au durat 2-4,8h fiecare (13,5h total) — lumea media gate complete nu încape în 240 min pe o mașină singură; matricea de seeduri cere runner-ul KVM (Q32), conform Q22 din design. **Comis acum**: helper `MediaScenarios` (shard gating verificat: shard 4 rulează doar SCN-MD) + liniile oneste SCN-MA (51 puncte), SCN-MC (5), SCN-MD (17) din enumerările existente + pasul shard filtrează doar clasele-scenariu. Ce e MĂSURAT și verde: lumea gate-scale, muțanții 9+52, gemenele, T25, MA/MC/MD. | 11 | scripturile există; mașina de lucru rulează pasul world | EXEC (rulare; mașina de lucru e resursa) |
| 2 | ~~Clasa `… \| head -1` SIGPIPE~~ **ÎNCHISĂ** (`73c37285`): 19 gate-uri convertite la `sed -n 1p`; self-test final 1 209 ok / 0 FAIL / 0 skip | gates | — | — |
| 3 | `cargo-deny` 0.20.2 instalat în runner; cele 14 cazuri de bans rulează (self-test 2026-11-09) | CI local | — | — |
| 4 | Rândurile G-D1/G-D2/G-D4 care scanează workflows CI | 14 | documentate ca manuale în gate-uri | EXEC (CI-L: migrarea workflows în scripturi locale, decizie ADR-58) |
| 5 | Refresh `docs/audit/AUDIT_SCOPE.md` §0 — **făcut** (`1f229663`, revizie 2026-11-09) | 15 | — | — |
| 6 | Tuning jitter/batch transporturi (rândul 12 rămas) + review independent captură metadate (F-T1, cere design propriu sau repointare L9) | 12 | loopback verde, porți G-T1-T8 | EXEC (tuning) + 3P (review independent) |
| 7 | F11 R3: expeditorul nu-și vede propriul obiect „vezi o dată" (mai strict decât design) | 11 | înregistrat cu probes | OWNER (decizie produs) |
| 8 | Hang load-dependent `ChannelM20CrashTest.aCrashAtEveryEventOfTheFourthWave…` | 11 | nu se reproduce izolat; reprodus 2× sub load | DEVICE/EXEC (rulare la scara gate pe runner KVM — Q32) |
| 19c | T32 la scara porții (DM): **perechile 0-8 VERZI (1h38m-2h4m fiecare)** — perechea 8 lansată; mai rămâne 9 + suita | — N=600×42 zile, 82 438 senduri, JD1-JD9 toate PASS 0; perechile 1-9 + suita scale-independent lansate secvențial (estimat ~16-20h) | (`DmPrivacyWorldTest.t32JoinsAndSdm3HoldOverThePrivacyWorld -Dghost.dm.privacy=gate -Dghost.dm.privacy.seed=0 -Dghost.dm.heap=6g`, raport `build/reports/dm/privacy-t32-pair0.txt`), rulează paralel cu T2 pe mașina Windows; primele 9 perechi rămân pentru Q32/nopți |
| 19c0 | T32 la scara porții (DM): per pereche de seeduri (0-9, matricea nightly-ului CI) — `--tests org.ghost.messaging.dmworld.DmPrivacyWorldTest.t32JoinsAndSdm3HoldOverThePrivacyWorld -Dghost.dm.privacy=gate -Dghost.dm.privacy.seed=<N> -Dghost.dm.heap=6g`; o dată: suita scale-independentă (niDm1-3, jd7 withhold, t34×2); plus mutanții de privacy. Cost onest: N=600×42 zile per pereche ≈ ore pe mașina locală — matricea completă de 10 cere runner KVM (Q32) sau nopți consecutive; dovada locală = perechea 0, ca la media | 9 | comenzile extrase din workflowul legacy | EXEC (după gate-ul media) |
| 19b | T2 la scara porții (DM): **perechea 0 oprită intenționat la ~7h** — contendența cu lumea gate media (care trecea de la 1h34/seed la ~5h+/seed) îl încetinea pe amândoi; build-ul release rămâne în cache, relansarea e ieftină — se face după verdictul G-M9. **Relansat 2026-11-10: perechea 0 PASS la scara gate** (`T2 RESULT: PASS`), perechea 1 în curs;  matricea continuă autonom cu markeri. **PRIMA CONSTATARE ROȘIE: perechea 2 a eșuat — `NI-1d: FAIL drop writes differ at write 0 (9 and 9 writes)`** (scrierile drop ale issuerului diferă între gemeni la indexul 0, deși numărul e identic); corelează cu nightly-ul istoric (PC-4: perechile 2, 3, 9 eșuau și pe 2026-10-03) — fie defect real persistent legat de seed, fie artefact de harness al acelorași perechi; perechea 3 rulează acum (așteptat roșie dacă e persistentă); investigația (gate::ni1_drop_writes + world) e item de lucru prioritar, primul candidat real din rulările la scară ale sesiunii. **Ipoteza caracterizată (citire world.rs/gate.rs)**: drop_out.due e tras la trial (aleator între săptămâna base+3 și base+8, din seeds.sched — NU depinde de primul pachet); shift-ul NI-1d mută doar first_pack_at. MECANISMUL probabil al eșecului: momentul WRITE-ului drop = max(due, prima sesiune după due) — sesiunea suplimentară a cumpărării mutate (+2z5h) poate prinde drop-ul înaintea sesiunii de background care l-ar fi scris la due (interacțiune cu hold-urile E30), decplând scrierea de due. Perechile 0/1 au trecut (interacțiunea nu s-a produs); perechea 2 a avut draw-ul care o produce. VERDICT — **GAP DESIGN-IMPLEMENTARE (nu artefact)**: designul LNK-04 (faza8-issuer.md) declară „scrie exact un blob ATUNCI" (la t_drop tras), iar implementarea (lume + comportament de producție prin `drop_tick` în sesiuni) scrie la PRIMA SESIUNE după due — cuplajul write-time-activitate-client este real și exact forma pe care mutantul M18 o exemplifica. Gate-ul T2 (corect strict: „orice diferență de due time eșuează geamănul") prinde forma M18 în lumea onestă pentru draw-urile unde interacțiunea apare (perechile 2/3/9 istoric). FIXUL e decizie de threat-model a proprietarului: (a) implementare cu scriere la t_drop (bandă de fundal dedicată) sau (b) amendament de design care declară cuplajul (modelul E17: declarat, apoi eliminat prin Q31). **Prima constatare de audit a sesiunii. Confirmare 2026-11-10: perechile 2 ȘI 3 ambele eșuat la NI-1d** (perechile 0-1 PASS; perechile 4-5 PASS la rând) — pattern parțial (doar unele draw-uri de seed), nu global; se așteaptă perechea 9 (a treia din istoric); T2 în perechea 6 |
| 19b0 | T2 la scara porții (DM): `GHOST_T2_SCALE=gate GHOST_T2_SEEDS=<pair> cargo test --release --locked -p ghost-issuer --test t2_unlinkability t2_exit_gate -- --ignored --exact` (10 perechi) + `t2_mutants` — build release lansat în WSL (joburi capped ca să coexiste cu gate-ul media), perechea 0 ca smoke | 9 | rulează | EXEC (WSL) |

| 9 | Q32 runner KVM + cotă artefacte; Q31 telefoane de referință; jumătatea Android a porților la scara PR | 10/11/13 | porțile de cod verzi | DEVICE (hardware/procurement) |
| 10 | OA-1 live pe bridge-uri publice + WebTunnel live; OA-2 pasul arm64 pe două telefoane; confirmare scrisă prune OA-3 | 12 | mecanism deblocat, `tests/live_pt.rs` | DEVICE + OWNER (confirmare scrisă) |
| 11 | F13: TalkBack walkthrough formal; T4 calea device-transfer (D2D); geamănul T6 cu identitate configurată | 13 | dovezi emulator parțiale | DEVICE (emulator pe runner KVM / telefoane) + 3P (evaluator uman TalkBack) |
| 12 | OA-5: editor nativ RO + counsel texte plată/privacy/Tor | 13 | — | 3P (contractare) |
| 13 | Runda formativă 2-3 oameni + summativ anonim S11 (materiale `docs/ux-s11/` gata) | 13 | staging real J1-J6 măsurat | 3P (oameni) |
| 14 | F14: mediul B (al doilea mediu independent) | 14 | runbook + recipe unificat validat | DEVICE (mașina fizică) |
| 15 | F14: cheie de tag + token-uri hardware + domeniu; proba vie V-D11b (includere Sigsum live) | 14 | chei software stagenet pentru drill | OWNER (achiziție) + 3P (Sigsum) |
| 16 | F14: drill live S9 pe telefon real; ceremonii RK0-RK6 | 14 | APK drill + staging gata | DEVICE + OWNER (token-uri) |
| 17 | Q3: domeniul `org.ghost.app` neînregistrat; Q18: verificarea dezvoltatorilor Google (2027) | 14/13 | înregistrat | OWNER (decizie/domeniu) |
| 18 | B4 audit extern: contractare, buget, acces auditori la sursă/mapping | 15 | RFQ + pachet există | 3P + OWNER (buget) |

## 5. Trasabilitatea cerințelor v2.2

Tabelul cerință→pachet→probă din roadmap §23 se adoptă ca atare (M-01…M-16, V-01…V-06,
C-01…C-09, H-01…H-12 → MESH-01…09, VOICE-01…04, CALL-01…06, APK-01…08). Ledger-ul de mai sus
adaugă peste el doar clasa de blocaj. Protocoalele wire (mesh) și binding-ul apelului rămân de
înghețat în design (M1/C0) și revizuite criptografic ÎNAINTE de cod — specificația v2.2 nu
inventează protocol, doar fixează cerințele.

## 6. NFR înregistrate ca ținte (fără rezultate inventate)

N-M1 (legătură p95 ≤ 15 s), N-M2 (text 4 KiB p95 ≤ 3 s), N-M3 (OFF = zero activitate locală),
N-M4 (buget resurse §5.1), N-M5 (≤ 2 pp baterie/oră), N-V1 (zero audio plaintext persistent),
N-C1 (audio p95 ≤ 5 s), N-C2 (latență p95 ≤ 200 ms), N-C3 (oprire captură ≤ 1 s), N-H1 (zero
secrete/debug/mapping în APK), N-H2 (≤ 10% startup/RSS), N-H3 (reproducibilitate verificată).
Mărimea APK se remsoară cu motorul RTC ales (C0); NFR-ul de bază nu se relaxează automat.

## 7. Model fizic, OS/ABI, buget audit, acces auditori — puncte deschise (B0)

- **Matricea fizică minimă** (propunere de validat la M0, proprietarul confirmă/procură):
  4 modele / ≥2 producători, 2 fără GMS, cel mai vechi API suportat de funcție; fiecare raport
  fixează model/OS/ABI/radio/distanță/build hash.
- **Bugetul auditului și accesul la sursă/mapping** (ADR-38 punct 9 amendat: mapping privat cu
  acces controlat) — decizie OWNER, blocată la B4.
- **Escrow de sursă** (ADR-38 punct 10) — decizie OWNER.

## 8. Non-obiective înghețate (B0)

Fără: unknown peers, apeluri de grup, video, multi-hop live, telefonie publică, colectare
automată de diagnostice, fallback Internet pentru local, STUN/TURN, discovery în fundal,
scanare de subnet, DNS/mDNS/SSDP, trust tranzitiv, delegare de grant, reputație globală,
packere/loadere opace fără evaluare separată. Push-to-talk live nu primește proprietățile
notelor vocale. Orice extindere trece prin revizie de design, nu prin roadmap tacit.

## 9. Reguli de execuție (din roadmap §2/§23, adoptate)

Un singur integrator (agentul), un singur writer per worktree, un singur flux de implementare +
unul de verificare; fiecare pachet produce: obiectiv, checkout/SHA, fișiere modificate, decizii,
comenzi, exit codes, număr/scop teste, rezultate negative, hash-uri, limite, următorul gate.
Nicio fază istorică nu primește PASS retroactiv. Verificări locale conform ADR-58.
