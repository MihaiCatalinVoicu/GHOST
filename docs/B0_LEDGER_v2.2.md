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
| H1 | Implementare hardening release | **JUMĂTATEA 1 COMISĂ** (`e6e11bfb`): H-01 obfuscare reală (validat pe mapping real: 747 clase, 15 nume justificate) + G-DM5 rescris pe whitelist; H-02 verificat (recipe A strip-uiește .so). Rămân: H-10 (suite E2E pe release minificat), H-11 (selfcheck reproductibilitate în imagine, la rebuild) | EXEC (H-10 parțial DEVICE — emulator) |
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
| 1 | Rulări la scara porții F11 — **ÎN DESFĂȘURARE** (2026-11-09): pasul `world` (JM1-JM7 + NI-M1-7, N=300, 28 zile, 5 seeds) lansat detașat pe mașina de lucru (java pid urmărit; log `ghost/android/messaging/build/reports/media/logs/world-agent.log`, raport `.../media/exit.txt`; ≤240 min); după el: `media-exit-gate.sh mutants` (43) și `check` (G-M9). T2/T32 (DM, N=600) rămân de lansat la fel pe rând. Dovadă locală, nu gate evidence până la Q32 (D23). **Constatare reală #1**: prima rulare (14:15, heap 4g — bugetul design §15.1) a murit cu `OutOfMemoryError` la `MediaPrivacyWorldTest.kt:45` după 21 min; lumea N=300 cere >4g pe mașina locală (97 GB RAM) — rerun la 14:45 cu heap 6g (deviere documentată; relevant pentru dimensionarea runner-ului Q32). **Constatare reală #2 (în investigație)**: cu 6g lumea a rulat cap-coadă (1h45m); 8/9 teste verzi (JM1-JM7 + NI-M la violații 0, ephemeral, T25-media), dar linia de confiscare a eșuat: `no stored key_env opens an archived blob expected:<0> but was:<6>` (`MediaPrivacyWorldTest.kt:66`) — la scara PR (N=60) era 0; scala gate (N=300×28z×5 seeds) scoate 6 deschideri: **VERDICT: artefact de oracol** (`3dd7895e`) — cele 3 obiecte (×2 sloturi de manifest = 6 deschideri) au timer 7z și expiră cu ~43 min înaintea orizontului; retenția legală a cheii este deadline+24h (delete_at), oracolul măsura deadline-ul nominal; fix: expired() folosește bound-ul de retenție. Validat 120×14; **rerunul gate-scale cu fixul: VERDE în 1h34m** — JM1-JM7 PASS 0 la N=300 (2 489 obiecte, 125k stores, 65k list/get), `seizure: 0 opened (1 133 key_env × 84 606 blob-uri), control 1 454` (oracol viu); muțanții JVM 9/9 + Rust 52/52; check-ul G-M9 refuză corect raportul parțial — rămân: shards 1-8 (SCN-MA…MF + 1 000 seeded worlds), linia «5 seed pairs» (mecanismul nu există în cod — worldul rulează 1 seed pinned; drift check-vs-implementare de documentat) și linia agregată «43 mutanți» (implementarea măsoară onest 9+52 cu lista pending — drift similar). **Shard 1 rulat** (8 min): a rulat suitele media la scara PR — deoarece proprietățile `ghost.media.shard/shards` din media-exit-gate.sh NU au cititor în cod (a doua drift: scriptul documentează un mecanism de sharduire care nu există). **Constatare majoră**: liniile «SCN-MA…MF: N crash points … invariants hold» și «seeded worlds: 1000» pe care le cere G-M9 în forma gate NU au scriitor în cod — harnessul de enumerare a crashurilor media (echivalentul lui DmCrashEnumerationTest) nu a fost implementat în S7-S10; scenariile media acoperă crashuri scriptate punctual (3 teste/clasă). **Corecție după inventarul profund (pas 1 al harnessului comis `06069083`)**: enumerarea la nivel de store EXISTĂ în `:media` (`MediaStoreScenarioTest` — fiecare operație de fișier și fiecare statement, pentru jumătățile de storage ale SCN-MA/MC/ME/MF), iar migrația SCN-MF are enumerare proprie (`Migration8Test` în `:storage`). Ce lipsește pentru liniile gate: (1) **SCN-MB** — nicio enumerare de crash în `MediaUploadScenarioTest` (lipsea reală; spec §15.3 cere per-ordinal/per-object + class-10 eșantionat); (2) linii de raport cross-module din `:media`/`:storage` în raportul media (SCN-ME storage half, SCN-MF Migration8Test + testul object-set v5→M F9 G-9); (3) **seeded worlds media** (§15.4 — 1000 lumi funcționale; există doar varianta DM); (4) rerun curat al raportului + check gate. **Pașii 2-3 comiși (`222a21ec`, `16c81a24`)**: enumerarea SCN-MB a fost construită (51 de puncte, verde din prima — crash la fiecare fișier al rulării de upload, oracolele MB după fiecare reboot); liniile cross-module SCN-ME (38, din `:media`) și SCN-MF (74, din Migration8Test) cu forwardingul proprietății în test JVM pe ambele module. Toate cele șase linii SCN au acum scriitori reali. **§15.4 comis (`01ee84dc`)**: MediaSeededWorldsTest — viață completă per seed cu crash aleator pe fază, reboot+invariante+reluare, oracole finale (uploaded, verified, zero rânduri/fișiere/octeți de cheie după sweep); 20/20 verzi la validare; shard 7 = 1 000 lumi la gate. **Gate-ul media complet curat lansat** (`media-exit-gate.sh all`, raport proaspăt, heap 6g): shards 1-8 → world gate 5 seeduri (~8h) → mutanți → check G-M9; log `/tmp/gate-all.log` + `messaging/build/reports/media/logs/`. **Primul rezultat din gate**: shards 1-8 verzi cu toate cele 6 linii SCN, iar **seeded worlds 1000/1000 fără eșec** la prima rulare la scară. Lumea gate (5 seeduri) rulează. **Comis acum**: helper `MediaScenarios` (shard gating verificat: shard 4 rulează doar SCN-MD) + liniile oneste SCN-MA (51 puncte), SCN-MC (5), SCN-MD (17) din enumerările existente + pasul shard filtrează doar clasele-scenariu. Ce e MĂSURAT și verde: lumea gate-scale, muțanții 9+52, gemenele, T25, MA/MC/MD. | 11 | scripturile există; mașina de lucru rulează pasul world | EXEC (rulare; mașina de lucru e resursa) |
| 2 | ~~Clasa `… \| head -1` SIGPIPE~~ **ÎNCHISĂ** (`73c37285`): 19 gate-uri convertite la `sed -n 1p`; self-test final 1 209 ok / 0 FAIL / 0 skip | gates | — | — |
| 3 | `cargo-deny` 0.20.2 instalat în runner; cele 14 cazuri de bans rulează (self-test 2026-11-09) | CI local | — | — |
| 4 | Rândurile G-D1/G-D2/G-D4 care scanează workflows CI | 14 | documentate ca manuale în gate-uri | EXEC (CI-L: migrarea workflows în scripturi locale, decizie ADR-58) |
| 5 | Refresh `docs/audit/AUDIT_SCOPE.md` §0 — **făcut** (`1f229663`, revizie 2026-11-09) | 15 | — | — |
| 6 | Tuning jitter/batch transporturi (rândul 12 rămas) + review independent captură metadate (F-T1, cere design propriu sau repointare L9) | 12 | loopback verde, porți G-T1-T8 | EXEC (tuning) + 3P (review independent) |
| 7 | F11 R3: expeditorul nu-și vede propriul obiect „vezi o dată" (mai strict decât design) | 11 | înregistrat cu probes | OWNER (decizie produs) |
| 8 | Hang load-dependent `ChannelM20CrashTest.aCrashAtEveryEventOfTheFourthWave…` | 11 | nu se reproduce izolat; reprodus 2× sub load | DEVICE/EXEC (rulare la scara gate pe runner KVM — Q32) |
| 19c | T32 la scara porții (DM): per pereche de seeduri (0-9, matricea nightly-ului CI) — `--tests org.ghost.messaging.dmworld.DmPrivacyWorldTest.t32JoinsAndSdm3HoldOverThePrivacyWorld -Dghost.dm.privacy=gate -Dghost.dm.privacy.seed=<N> -Dghost.dm.heap=6g`; o dată: suita scale-independentă (niDm1-3, jd7 withhold, t34×2); plus mutanții de privacy. Cost onest: N=600×42 zile per pereche ≈ ore pe mașina locală — matricea completă de 10 cere runner KVM (Q32) sau nopți consecutive; dovada locală = perechea 0, ca la media | 9 | comenzile extrase din workflowul legacy | EXEC (după gate-ul media) |
| 19b | T2 la scara porții (DM): **perechea 0 oprită intenționat la ~7h** — contendența cu lumea gate media (care trecea de la 1h34/seed la ~5h+/seed) îl încetinea pe amândoi; build-ul release rămâne în cache, relansarea e ieftină — se face după verdictul G-M9 |
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
