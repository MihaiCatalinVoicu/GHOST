# H0 — Designul protecției APK și al dovezilor (roadmap v2.2 §4)

Revizia 1, 2026-11-09. Autor: agent (singurul integrator). Review: proprietar/reviewer de
securitate înainte de H1. Sursa normativă a cerințelor: `docs/GHOST_Technical_Specification_v2.2.md`
§8 (H-01…H-12) și roadmap §4/§14. ADR-38 punct 9 **amendat v2.2** înlocuiește explicit cerința
istorică de nume `org.ghost.**` neofuscate — acest design o operationalizează.

## 1. Inventarul stării actuale (fără modificări de build)

| Suprafață | Stare la `0a108685` |
|---|---|
| `release` build type | `isMinifyEnabled = true`, `isShrinkResources = true`, fără signingConfig (semnare offline, ADR-07); `vcsInfo.include = false` (F14 §6.3) |
| Reguli R8 aplicație | `proguard-android-optimize.txt` + `app/proguard-rules.pro`: doar `-dontwarn org.ghost.**` și `-keepnames class org.ghost.** { *; }` (**global keepnames — de eliminat la H1**, vezi §2) |
| Reguli R8 module | JNI per suprafață închisă (`DmNative`, `MlsNative` în `:crypto-bridge`; `TorRelayTransport`, `TorIssuerTransport`, `EntitlementCrypto`, `NetworkException` în `:network`), BouncyCastle în `:identity` — înguste, justificate, se păstrează |
| `gate` build type | debug + `src/gate`, semnat debug, niciodată distribuit (G-L5) — nu atinge release-ul |
| Debug seams | `UpdateLoopback` (src/gate), `DmBranch` (src/gate) — în afara release-ului prin construcție; G-DM5 le verifică în mapping |
| Native | `libghost_client_net.so`: cargo strip + `keepDebugSymbols` pentru build-id (reproductibilitate F14); recipe-ul A (F14) face split simboluri cu `llvm-objcopy` (`symbols/<abi>/*.so.debug`) — **artefactul livrat poate fi strip-uit complet** (vezi §5) |
| Reflection/serializare | Compose (cod generat), Room? nu — storage propriu pe SQLCipher; kotlinx-serialization nu e în uz; JNI tables în `:crypto-bridge`/`:network` — de re-verificat la H1 cu o scanare efectivă |
| Secrets în arbore | G-D1 verde (2026-11-09); cheile din repo sunt doar stagenet/test (`test-harness/update/keys/` carve-out) |
| `debuggable` | implicit false pe release; `profileable` nu e setat — de confirmat în manifestul merged la H1 |
| Reproductibilitate | recipe A unificat validat în imagine (F14): două rulări byte-identice pe același mediu; egalitatea A/B pe două medii independente rămâne a mediului B |

## 2. Reconcilierea ADR-38 §9 amendat cu realitatea

Trei lucruri afirmau/presupuneau nume neofuscate și trebuie realiniate o dată cu H1:

1. **`app/proguard-rules.pro`**: `-keepnames class org.ghost.** { *; }` se elimină. Rămân doar
   excepțiile înguste: JNI (native `<methods>` per clasă exportată — deja în consumer rules),
   reflection/serializare efectivă (scanare la H1, adăugate una câte una cu justificare).
2. **G-DM5 (`apk-no-debug-hooks.sh`)**: jumătatea de mapping asumă identitatea numelor
   („mapping.txt maps every `org.ghost.` class to itself"). Cu obfuscare activă, mapping-ul
   devine obfuscat→original; gate-ul se rescrie (H1): refuză ca orice clasă `org.ghost.*`
   **să supraviețuiască în release** cu numele ei original (mapping + DEX), cu excepția
   whitelist-ului JNI; verificarea anti-debug-hook rămâne (hooks, harness, seams).
3. **Comentariile din consumer rules** care spun „GHOST classes are not obfuscated" se
   actualizează la trimiterea la acest design.

## 3. Planul per cerință (H-01…H-12 → pași H1)

| Cerință | Pas concret H1 | Probă |
|---|---|---|
| H-01 | elimin keepnames global; keep rules doar justificate (§2.1); shrinking+optimization rămân | APK-01: JADX pe DEX — nume transformate; build verde |
| H-02 | release nedebuggable (confirmat merged manifest); fără src/gate în release (deja); strip complet al .so livrat (§5) | APK-01: manifest/strings/DEX/simboluri .so |
| H-03 | scan secret-canary pe APK (chei test existente doar în harness); nimic nou — verificat, nu adăugat | APK-02 + canary |
| H-04 | existent (F14: semnare, lanț, anti-rollback, update onion) — fără schimbare; verificat pe noul artefact | APK-03 (drill F14 S5) |
| H-05 | self-check-urile locale rămân suplimentare; niciuna nu acordă drepturi (deja invariant F14) | APK-04 bypass controlat — documentat, nu implementat acum (fără RASP nou, H-08) |
| H-06 | politica de reacție root/debugger: **semnal local proporțional** (banner în UI + log local criptat), fără wipe, fără blocare ROM, fără identificatori trimiși; ADR-60 rămâne separat | APK-04: tabel de comportament (design §6) |
| H-07 | nicio dependență GMS/Play Integrity (deja: Tor-only, distribuție proprie) | APK-05: captură zero trafic Google |
| H-08 | fără packer/loader/RASP nou; obfuscare = R8 stock + ProGuard rules text (licență Apache/GPL classpath — regula e a noastră, fără runtime nou) | APK-06: SBOM neschimbat la runtime |
| H-09 | custodia mapping/simboluri (§4) | APK-06: retrace canary |
| H-10 | **release-ul minificat e cel testat**: suitele E2E (DM/media/update/UI smoke) rulează pe varianta release minificată, nu pe debug | APK-07: matrice — mecanizare H1 + emulator |
| H-11 | reproductibilitate cu R8: R8 e parte din AGP pinuit (F14 builder image); determinismul R8 verificat prin rebuild dublu în imagine (selfcheck existent, re-executat după H1) | APK-06: rapoarte A/B |
| H-12 | audit extern/retest | B4 — nu e H1 |

## 4. Custodia mapping-urilor și a simbolurilor (H-09)

- Mapping-ul R8 (`mapping.txt` per ABI-invariant) și simbolurile native (`*.so.debug` din
  recipe A) se păstrează **în afara APK-ului și a repo-ului public**, în arhiva de release
  a proprietarului: `release-private/<versionCode>/` cu manifest propriu.
- Legare de artefact: SHA-256 al mapping-ului și al simbolurilor intră în `SHA256SUMS`-ul
  intern (nu în cel public al recipe-ului, care rămâne deschis verificatorilor) și în
  înregistrarea de lansare RK (jurnal).
- ACL: proprietarul + auditorii numiți (ADR-38); retenție: pe viața versiunii + un ciclu de
  lansare; backup criptat la proprietar.
- Retrace verificabil: la fiecare release, un crash-canary (stack cunoscut) e retrasat cu
  mapping-ul păstrat și rezultatul e arhivat ca dovadă (APK-06).
- Pierderea mapping-ului nu blochează utilizatorul; blochează diagnosticul autorizat —
  de aceea retenția e obligatorie, nu opțională (H2 refuză un release fără custodie).

## 5. Simbolurile native (H-02)

Recipe-ul A produce deja `lib/<abi>/libghost_client_net.so` + `symbols/<abi>/*.so.debug`.
Decizie H0: artefactul din APK livrat este **strip-uit complet** (`.dynsym` păstrat pentru
JNI/G-R6; build-id păstrat pentru G-D3 simbol==bibliotecă); simbolurile complete stau în
custodia §4. Schimbare concretă în `build.gradle.kts`: `keepDebugSymbols` rămâne în build
(deci reproductibilitatea pe bytes nu se schimbă prin strip-ul AGP), iar strip-ul final se
face în recipe A cu `llvm-objcopy --strip-all` pe copia din APK (simbolurile deja sunt
split-uite în `symbols/`). Verificare: G-D3 (build-id) rămâne verde; G-R6 (JNI surface) nu
depinde de simboluri.

## 6. Reacția la root/debugger (H-05/H-06) — politica propusă

- Detectare: doar semnale locale, fără SDK RASP (H-08). Lista semnalelor: debugger conectat
  (`Debug.isDebuggerConnected`), `FLAG_SECURE` existent rămâne, semne de tampering a
  propriului APK (semnătura verificată deja la update, F14).
- Reacție: banner informativ local („mediul acesta dispozitiv poate fi monitorizat"),
  dezactivarea previzualizărilor media (FLAG_SECURE deja), log local criptat. **Fără** wipe,
  fără blocarea aplicației, fără identificatori trimiși oriunde.
- Ce nu devine niciodată bază de securitate: disponibilitatea funcției, autorizarea la
  relay/issuer/mesh, cheile (H-05).
- ADR-60 (kill_flag la migrare majoră) rămâne mecanismul separat de răspuns la compromitere.

## 7. Scanarea de secrete și endpoint-uri (H-03)

- Există: G-D1 pe arbore; APK-02 se adaugă la H1 ca gate nou? **Nu** — se extinde G-D1 cu
  un pas opțional pe APK (strings scan + canary), pentru că APK-ul e produsul, nu arborele.
  Simplu și fără gate nou: `release-no-secrets.sh` primește mod `--apk <fișier>` reutilizând
  aceiași detectori (header PEM/magics) peste `unzip -p`. Decizie de review.
- Endpoint-uri de test: niciunul (Tor-only; verificat de porțile existente).

## 8. Reproductibilitatea artefactului minificat (H-11)

R8 face parte din AGP-ul pinuit în imaginea builder (F14). Pericolul de nedeterminism:
regulile ProGuard text sunt parte din sursă (la fel), shrinkResources depinde de resurse
(determinist), iar `mapping.txt` poate varia doar dacă graful de clase variază — sursa e
fixată de tag. Selfcheck-ul F14 (două rulări consecutive byte-identice) se re-execută după
H1 pe noul profil; egalitatea A/B rămâne porția mediului B.

## 9. Fișierele exacte de modificat la H1 (lista de review)

1. `ghost/android/app/proguard-rules.pro` — scoate keepnames global; păstrează dontwarn +
   eventuale keep-uri noi justificate.
2. `ghost/android/*/consumer-rules.pro` — actualizează comentariile (trimitere la acest
   design); adaugă keep-uri noi doar cu motiv.
3. `ghost/scripts/gates/apk-no-debug-hooks.sh` — rescrie jumătatea de mapping pentru
   mapping obfuscat→original + supraviețuire whitelist JNI (G-DM5 rămâne la fel în rest).
4. `ghost/scripts/gates/self-test.sh` — cazurile G-DM5 aferente se actualizează.
5. `ghost/scripts/release/build-release.sh` — strip final cu llvm-objcopy pe copia din APK
   (simbolurile rămân în `symbols/`).
6. `ghost/scripts/gates/run-all.sh` — nicio schimbare (G-DM5 e deja în listă).
7. Teste E2E pe release minificat (H-10): `update-emulator.sh` primește un flag de build
   release-minificat pentru jumătatea sa de smoke.

## 10. Întrebări deschise pentru review (înainte de H1)

- Q-H0-1: banner-ul de root/debugger (§6) — acceptați forma propusă sau preferați doar
  dezactivarea previzualizărilor fără mesaj?
- Q-H0-2: custodia §4 — unde fizic ține proprietarul arhiva privată (opțiune: același
  loc cu cheile de semnare, air-gapped)?
- Q-H0-3: `--apk` pe G-D1 (§7) — extindem gate-ul existent sau gate nou dedicat?
- Q-H0-4: scanarea efectivă reflection/serializare — se face la H1 cu o trecere JADX +
  test runtime pe release; dacă apar keep-uri noi, se adaugă una câte una. OK?
