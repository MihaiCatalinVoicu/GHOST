# android/sync — motorul de sincronizare (Faza 7)

Modulul mută blob-uri deja criptate E2E și de dimensiune bucket între baza SQLCipher locală și relay-urile blind: outbox idempotent (fiecare operație e scrisă pe toate relay-urile active ale setului namespace-ului și e „trimisă” când cel puțin 2 operatori distincți o arată în inventar), inbox cu deduplicare pe (namespace, hash), cursoare opace per (relay, namespace), reîncercări cu backoff, un program de trafic per pereche (relay, namespace) independent de activitate (ADR-15), un job JobScheduler în fundal și o sesiune în proces în prim-plan (ADR-20). Nu criptează, nu emite capabilități (Faza 8) și nu implementează protocolul relay-ului (ADR-19: framing, gRPC și validarea răspunsurilor sunt în Rust). Design: `docs/design/faza7-sync-engine.md`; secțiunea §11 are prioritate.

| Pachet | Rol |
|---|---|
| `api` | API-ul public pentru Fazele 9–11: `SyncDatabase`/`SyncTransaction`, `Outbox`, `Inbox`, `Namespaces`, `Capabilities`, `RelayDirectory`, `SyncController`, tipuri cu `toString()` redactat |
| `store` | tranzițiile SQL păzite pe schema v2 (`android/storage`, `Schema.kt`, 12 triggere), deciziile de rezultat, mentenanța, retenția și GC-ul (`RetentionPolicy`, `StoreLimits`) |
| `engine` | motorul pur JVM (fără `android.*`, `java.net`, `javax.net`): banda de citire (listări) și banda de lucru (aduceri, trimiteri, verificări, GC), programul per pereche (`PairSchedule`, PRF cu cheie), `ErrorPolicy` (fiecare categorie din `client-core/README.md`, verificat de test), backoff, breakere, bugete, sesiuni; toți parametrii în `TrafficPolicy` |
| `port` | interfețele spre relay, transport, ceas, aleator și planificator |
| `android` | singurul pachet cu `android.*`: `TorRelayPort`, `TorTransportHolder` (un singur transport nativ viu per proces), `SyncRuntime`, `SyncJobService`, `JobSchedulerWake`, `ForegroundDriver`, `AndroidSyncController` |

Legarea în aplicație: `android/app` (`GhostApp`, `SyncWiring`, `AppDatabase`).

## API pentru Fazele 9–11 (design §9)

`AndroidSyncController.stores` (`SyncStores`; null cât baza de date nu e deschisă) expune `database`, `outbox`, `inbox`, `namespaces`, `capabilities` și `relayDirectory`. Exemplul de mai jos folosește nume ilustrative pentru codul Fazei 9 (`session`, `messages`, `dm`).

```kotlin
val stores = syncController.stores ?: return
stores.database.transaction { tx ->
    val ct = session.encrypt(tx.sql, paddedPlaintext)             // starea ratchet-ului, în aceeași tranzacție
    messages.insertQueued(tx.sql, opId, conversation, ct)
    stores.outbox.enqueue(tx, OutboundBlob(opId, recipientInbox, ct, TtlBucket.DAYS_7))
}
syncController.requestExpedite()                                    // doar în modul standard
// la SyncChange.OUTCOMES
for (o in stores.outbox.outcomes(Consumer.DM, 64)) stores.database.transaction { tx ->
    if (stores.outbox.release(tx, o.operationId)) messages.setOutcome(tx.sql, o.operationId, o.outcome)
}
// la SyncChange.INBOX
for (b in stores.inbox.claim(Consumer.DM, 32)) stores.database.transaction { tx ->
    if (stores.inbox.markConsumed(tx, b.namespace, b.hash)) dm.decryptAndStore(tx.sql, b.ciphertext) // sau respingerea
}
```

Contracte:
- Ciphertext-ul se produce **o singură dată** per mesaj, iar `enqueue` rulează în aceeași tranzacție cu starea protocolului: un crash nu poate pierde un mesaj al cărui ratchet a avansat și nici produce un al doilea ciphertext. `enqueue` aruncă la intrare invalidă, conflict, fereastră de retrimitere închisă sau sub 2 operatori distincți în set (`InsufficientReplicasException`), iar tranzacția apelantului se anulează. Nu trezește nimic.
- `release()` și `markConsumed()` întorc true **exact o dată**: efectul consumatorului se face condiționat de ele, în aceeași tranzacție. `markConsumed` se cheamă pentru orice blob, inclusiv cele respinse sau nedecriptabile.
- `claim()` rulează în propria tranzacție scurtă (nu în `transaction`) și incrementează un contor de oferte înainte de predare: un blob oferit de 2 ori fără consum e returnat singur, iar de la a 3-a ofertă e amânat 1 h, 2 h, 4 h … 24 h. Nu e aruncat niciodată (`StatusFlag.CONSUMER_POISONED`). `defer()` re-oferă un blob după 1 s … 7 zile (de exemplu un mesaj MLS pentru un epoch viitor).
- Rezultate: `SENT`; `DEGRADED` (cel puțin un relay are o copie verificată: nu retrimite); `FAILED` (nicio copie n-a existat: re-criptarea și retrimiterea sunt sigure); `INDETERMINATE` (o copie poate exista: retrimite doar **aceiași bytes**, ca operație nouă, după `release`, până la `resendNotAfterEpochSeconds`).
- Consumatorii scriu doar prin `tx.sql` și nu fac I/O de rețea în tranzacție. `SyncDatabase.transaction` serializează toate firele printr-un singur lock și nu e reentrant pe același fir.
- Hint-urile `SyncChange` (INBOX, OUTCOMES, CAPABILITIES, TOPOLOGY) sosesc după commit, prin `Inbox.setListener`, fără payload.
- Faza 8 instalează capabilități prin `Capabilities.put` și urmărește `Capabilities.needed()`; Faza 14 umple `RelayDirectory` din manifestul semnat (azi sursa e `CONFIG`). Media (Faza 11) va adăuga `Inbox.want`.

## Adăugiri pentru mesajele directe (Faza 9, design `docs/design/faza9-dm.md` §13.3, ADR-34′)

Toate sunt în `api`, în afara checkpoint-ului (ultimul punct: `Gc` e în `store`, iar `Checkpoint` și `StorageFullException` în `:storage`), și au teste în `:sync`; enumerarea exhaustivă a Fazei 7 include `peek` și `claimOne` (V-11). Faza 9 nu e închisă (`docs/STATUS.md`).

- **`TtlBucket.HOUR_1`** (3 600 s), cu regulile de fereastră ale §10.4 (schema v4). Releul primește exact treapta; clientul nu rotunjește nimic (`client-core/README.md`).
- **`CapabilitySource`** pe `Namespaces.register` (`REDEEM` implicit; `LOCAL`: consumatorul își instalează singur credențialele purtătoare v3 prin `Capabilities.put`, iar planificatorul de entitlement nu răscumpără niciodată pentru el, deci inbox-ul unui contact nu costă niciun token). O livrare fără credențial utilizabil se parchează în `wait_capability` la fel ca una `REDEEM`; o generație nouă de credențial o rearmează. `CapabilityNeed.source` o raportează. `Namespaces.setSendDelay` și `register` refuză `SendDelay.OFF` pentru `Consumer.DM` (și un trigger v4).
- **`Registrations`** (`KeyKind`: `READ` 1, `DEPOSIT` 3, `FETCH` 4): `request` (idempotent, întoarce true doar când a inserat), `keep` (înlocuiește un rând al cărui verificator e al altui slot, §5.2), `rearm` (regula de vindecare, §4.8), `pending`, `forget`, `pendingCount`. Rândurile rulează pe banda de lucru, niciodată pe cea de citire (T19), cu o capabilitate de scriere utilizabilă a săptămânii c pentru perioadele `{c, c + 1}`; `OK` → `done` cu valabilitatea releului, `WRONG_PERIOD` și `unauthorized` → în așteptare până la următoarea generație de capabilitate. Regula nevoilor: o pereche cu un rând în așteptare și fără capabilitate de scriere raportează WRITE MISSING (Q31 din designul Fazei 9), ceea ce armează reținerea Q29 a Fazei 8 (LIMITE L5, Q34 reevaluat). *(Deschis, design Faza 9 §22.26 punctul 14: reținerea numără orice nevoie de scriere, inclusiv una LOCAL — credențialul de depunere refuzat sau epuizat al unui contact —, deci și aceasta armează sesiunile de fundal.)*
- **`Capabilities.installed`** (`InstalledCapability`: starea și ora expirării, fără token), ca proprietarul să-și citească înapoi credențialul de citire instalat. **Selecția credențialului:** pentru `list` și `get` se preferă un credențial READ utilizabil, cu capabilitatea de scriere ca rezervă; `store` folosește credențialul de tip write (o capabilitate sau, pentru un namespace `LOCAL`, credențialul de depunere, stocat ca `kind = 'write'`).
- **`Namespaces.listening(tx, ns)`**: dacă namespace-ul e înregistrat și ascultat, în tranzacția apelantului (fereastra de preluare a unui bundle, §21.7).
- **`Inbox.peek`** (citire într-o tranzacție care nu schimbă nimic, pentru ordonare, §7.7), **`Inbox.claimOne`** (revendică rândul numit dacă e încă adus, cu regulile de oferire ale lui `claim`) și **`Inbox.forgetConsumed`** (doar pentru namespace-urile `Consumer.PREKEYS`: un bundle consumat se poate prelua din nou după o resetare, §21.7 punctul 2). `InboundBlob` poartă `relayExpiryHour` și `offers`.
- **`ConsumerTail`** și `SyncController.setConsumerTail`: rulat pe firul jobului după benzile unei sesiuni de fundal, reținerea de răscumpărare și închiderea transportului, și după apelul către issuer al unei rulări liniștite; niciodată în prim-plan; lucru local până la termen, fără acces la transport. *(Constatat în Faza 9, nerezolvat: `:messaging` rulează în coadă o trecere declanșată de timp, nu cererea de golire pe care o descrie §13.3 punctul 6; design §22.25 punctul 4, LIMITE L5.)*
- **Checkpoint:** `Gc.checkpoint` folosește `Checkpoint.truncate()` (verifică `busy`), iar un disc plin ajunge ca `StorageFullException` tipizată (`:storage`).

**Idiomul de trimitere DM** (`android/messaging`, `SendStep`): **două faze, un singur scriitor**. (1) Pregătirea: o tranzacție scurtă de planificare (setul de relee, indexul minutului, eventuala rădăcină oferită), apoi, **în afara oricărei tranzacții**, conținutul L0 e codificat în Rust, care alege și treapta din lungimea corpului (R-B1; Kotlin nu calculează nicio treaptă), iar credențialele de depunere se derivă pentru releele care au nevoie de unul. (2) Scrierea, într-o singură tranzacție `SyncDatabase.transaction`, care recitește fiecare condiție de care depinde: sesiunea Olm criptează (o stare nouă, ca valoare); plicul e sigilat în Rust la exact 4, 16 sau 64 KiB (padding-ul e în AEAD); se scriu starea sesiunii și rândurile operației, namespace-ul inbox-ului destinatarului se înregistrează `listen = false, CapabilitySource.LOCAL`, credențialele de depunere pregătite se pun cu `Capabilities.put`, iar `outbox.enqueue(OutboundBlob(op, inbox, blob, ttl, deadline))` cu termenul `autor + min(treaptă, 7 zile)`. Separarea e sigură doar pentru că actorul DM e singurul scriitor al stării DM (design Faza 9 §13.7). Pasul de ratchet nu se commit-ează niciodată fără operație (CS-1).

## Adăugiri pentru canale (Faza 10, felia S1a, design `docs/design/faza10-forum.md` §7.5, §7.6, §9 „Migration 6”, §19.33)

Schema v6. Nimic de aici nu schimbă o observabilă a releului (T1, T19, T40): niciun tip nou de cerere, niciun câmp nou, nicio sincronizare nouă; testele `ChannelSyncNoTrafficTest` și `T19BasicTest` (varianta cu namespace finanțat) o dovedesc. Faza 10 nu e închisă (`docs/STATUS.md`).

- **`Funding`** (`set`, `isFunded`; tabela `sync_namespace_fund`, un rând = „clientul finanțează acest namespace”): finanțatorii unui canal (proprietarul și cel mult doi membri numiți de politică) își răscumpără singuri tokenii pentru capabilitățile de înregistrare; ceilalți membri depun cu credențialul DEPOSIT și citesc cu cel READ, instalate prin `Capabilities.put` ca pentru orice namespace `LOCAL`, și nu cheltuiesc niciun token. Steagul **nu e un act**: nu răscumpără, nu înregistrează și nu stochează nimic. Îl schimbă doar pașii care au voie să provoace comportament vizibil releelor (gate G-DM2 listează `Funding.set`; designul §7.5 punctul 7 interzice apelul din `CH-SETTLE` și `CH-RECV`). `set(false)` păstrează capabilitățile de înregistrare (inerte, colectate la expirare); `Namespaces.remove` le șterge odată cu steagul.
- **`CapabilityKind.REGISTER`** și tabela `relay_register_capability`: capabilitatea pe care un finanțator o răscumpără pentru `RegisterKey` și pentru nimic altceva. `Capabilities.put/installed` o scriu și o citesc ca pe celelalte (UPDATE apoi INSERT, nu upsert: tabela are un gard REPLACE); `store`, `list`, `get` și `check` **nu o citesc niciodată** (`forReading`, `forChecking` și leasing-ul de stocare selectează doar din `relay_capability`). `Capabilities.needed()` o raportează (MISSING, REJECTED, EXHAUSTED, EXPIRING) doar pentru un namespace finanțat, **mereu cu sursa `REDEEM`** chiar dacă a canalului e `LOCAL`: planificatorul o răscumpără ca pe o nevoie WRITE a unui namespace REDEEM (Q29 o armează, §7.6). O înregistrare în așteptare a unui namespace finanțat nu mai e muncă de scriere (nu raportează WRITE MISSING).
- **Pasul de înregistrare:** un rând al unui namespace finanțat e servit de capabilitatea lui de înregistrare și de nicio alta (credențialul DEPOSIT din slotul `write` e un credențial purtător, pe care `RegisterKey` îl refuză); orice alt namespace, ca în Faza 9, de capabilitatea de scriere — doar dacă sursa lui e `redeem` (un namespace `LOCAL` nefinanțat cu rânduri în așteptare nu prezintă niciodată credențialul de depunere la `RegisterKey`). O capabilitate nouă rearmează rândurile doar dacă e cea care le servește. Un refuz (`unauthorized`) marchează capabilitatea prezentată, nu cealaltă.
- **`SendDelay.OFF`** refuzat și pentru `Consumer.CHANNEL` (`Namespaces.setSendDelay`, `register` și triggerele `sync_namespace_channel_delay_{insert,update}`; acesta din urmă urmărește și `consumer`).
- **`Inbox.reofferDeferred(tx, namespace)`**: face scadente imediat rândurile amânate (`defer`) ale namespace-ului, în ordinea sosirii, ca blobul epocii e + 1 amânat șase ore să nu aștepte după ce epoca e s-a stabilit. Scrie doar `offer_after_minute = 0`; un rând pe backoff-ul de otravă (oferit de trei ori fără consum) nu e amânat și îl păstrează; trimite hint-ul `INBOX` doar dacă a mutat ceva; **nu provoacă trafic**. Rândurile amânate nu numără la `FETCHED_CAP` cât așteaptă.

## Participantul sesiunii (Faza 8, design Faza 8 §11.6, §12.2, §19.11, §19.14; ADR-23 modifică ADR-20 punctul 1)

`SyncController` are un singur slot de participant (`setParticipant`, pus o dată la cablare; în Faza 8 motorul de entitlement). Participantul folosește singurul transport Tor al procesului prin lease-uri (`LeasePort`/`TransportLease`, implementate de `TorTransportHolder`), nu un al doilea client Arti.

- **Sesiuni cu relay-uri** (prim-plan sau job obișnuit): după READY, `onRelaySession` rulează pe propriul fir, cu `relayRedeem` (răscumpărare) și fără `issuer`. Lease-ul se închide când sesiunea se oprește; sfârșitul sesiunii nu îl așteaptă.
- **Rulări liniștite:** fiecare job trage `QuietRunScheduler.quiet(n)` pentru indexul său în proces (PRF cu cheia procesului, `RandomSources.quietRun`; probabilitate exact 1/8), indiferent ce devine jobul; nicio stare de entitlement nu e intrare. Un job liniștit, cât un participant e instalat, face transportul READY, cheamă `onQuietRun` (cu `issuer`, fără `relayRedeem`), apoi închide lease-ul și transportul și termină jobul, la întoarcerea participantului sau la termen (8 min), oricare vine întâi. Nu atinge niciun relay. Sesiunile de prim-plan nu sunt niciodată liniștite; o aplicație devenită vizibilă încheie imediat rularea liniștită.
- **Apelurile către issuer:** cel mult unul per sesiune (primul apel consumă accesul; următoarele eșuează `closed`), fiecare pe un `IssuerFlow` nou, încheiat după apel; termenul apelului e tăiat la timpul rămas; un apel din interiorul unei tranzacții sync e refuzat (`IllegalStateException`).
- **`runUserIssuerCall`** (onboarding și butoanele opționale din modul standard; doar acțiuni ale utilizatorului, cu aplicația vizibilă): blocul rulează exact o dată, pe propriul fir, cu o sesiune `USER_ISSUER_CALL`, pe transportul sesiunii de prim-plan sau, când nicio sesiune cu relay-uri nu poate rula (reținerea ecranului de plată), pe un transport făcut READY pentru el (închis după). Un apel făcut cât o sesiune se oprește așteaptă sfârșitul ei. Cu aplicația ascunsă, după `onWipe` sau cu sync oprit, sesiunea e deja închisă: niciun apel către issuer nu are loc în timpul unei sesiuni de fundal sau al unei rulări liniștite (P-7, T23). Nimic vizibil relay-urilor nu așteaptă un apel al utilizatorului (R1): ascunderea aplicației închide apelurile care și-au făcut singure transportul READY, la fel și pornirea sesiunii de prim-plan la sfârșitul reținerii; apelul eșuează `closed` (reîncercabil).
- **Ecranul de plată** (`onPaymentScreenShown`/`onPaymentScreenHidden`; ascunderea aplicației îl ascunde): închide imediat sesiunea cu relay-uri și nu pornește alta cât e afișat și încă U[20, 60] min după. Rulările liniștite și apelurile utilizatorului nu sunt sesiuni cu relay-uri. Reținerea stă în memorie; un proces nou o primește prin `restorePaymentHold(lastShownEpochSeconds)`: motorul de entitlement persistă momentul în care ecranul a fost vizibil ultima dată (rotunjit în sus la minut) și îl dă la cablare, înainte ca un job sau prim-planul să poată porni o sesiune; reținerea se trage din nou, U[20, 60] min de la acel moment, niciodată peste 60 min de acum.
- Nimic din ce face participantul nu atinge breakerele, bugetele, pauzele sau erorile de transport ale sesiunii (T19), prin construcție: un apel eșuat pe lease nu schimbă starea transportului (`TransportLeaseTest`). `SessionParticipantTest` verifică programul de citire (inclusiv sfârșitul jobului) în lumea deterministă și numărul de apeluri ale unui job pe runtime-ul real.

## Garanții (design §0.2, §11)

| ID | Garanție |
|---|---|
| OUT-1 (fără pierderi) | Fiecare enqueue confirmat se termină cu exact un rezultat. O operație fără copie posibilă nu e închisă de timp offline, reconectări, moartea procesului, timeout-uri sau erori tranzitorii; se închide doar la termenul dat de apelant, la refuzuri permanente per relay, la scoaterea sau retragerea relay-urilor, ori la expirarea ferestrei de stocare (7 zile) după ce o copie există. |
| OUT-2 (fără duplicat local) | Rezultatul se decide o singură dată (trigger); `release()` e true o singură dată. |
| OUT-3 (fără duplicat în rețea) | O operație nu produce niciodată un al doilea ciphertext: fiecare store trimite aceiași (namespace, bytes), iar un relay ține cel mult o apartenență per (namespace, hash). |
| OUT-4 (adevărul rezultatului) | `SENT`: cel puțin 2 operatori distincți au arătat hash-ul în inventar (listare sau `check`) după confirmare. `FAILED`: nicio încercare nu putea lăsa o copie pe vreun relay. `DEGRADED`: cel puțin o copie verificată. `INDETERMINATE`: o copie poate exista sau a putut exista. |
| IN-1 (fără pierderi) | Fiecare (namespace, hash) pe care un relay onest și accesibil din setul unui namespace ascultat îl listează și îl servește e adus și oferit consumatorului. |
| IN-2 (fără duplicat) | Fiecare (namespace, hash) e marcat consumat cel mult o dată, iar consumatorul nu își vede propriile blob-uri. Retenția tombstone-urilor e derivată astfel încât, după ștergerea lor, niciun relay onest să nu mai poată lista hash-ul. |
| IN-3 (siguranța cursorului) | Un cursor stocat nu trece niciodată de un hash neînregistrat durabil local. |

**Granița.** IN-2 ține față de relay-uri oneste și pentru apartenențele create în fereastra de stocare a unei operații. Stratul de protocol (contoarele sesiunii Olm, epoch și generație MLS) rămâne responsabil, iar Fazele 9 și 10 trebuie să păstreze protecția anti-replay, pentru: un relay care minte despre expirare sau re-servește blob-uri expirate; un consumator care retrimite aceiași bytes ca operație nouă mult după prima; un namespace scos și adăugat din nou; un relay scos din directorul local, adăugat din nou mai târziu și care încă ține blob-uri vechi.

**Presupuneri și precondiții.** Commit-ul atomic SQLite (sqlite-jdbc pe JVM, SQLCipher pe dispozitiv); relay-urile nu pot falsifica blob-uri (Rust verifică hash-ul și bucket-ul); cât transportul e READY, ceasurile dispozitivului și ale relay-urilor oneste sunt la cel mult 3 zile de timpul real; pentru progres, cel puțin 2 operatori onești, accesibili, cu capabilități utilizabile; consumatorii golesc coada și dispozitivul e online cel puțin o dată per TTL (limitele de capacitate sunt în ADR-20, punctul 9). Modelul de crash e moartea procesului; durabilitatea la pierderea alimentării se sprijină pe `synchronous = FULL` (declarat, nu simulat).

## Harness-ul exit-gate

Dovada gate-ului („offline/reconnect/process-death fără pierderi sau duplicate”) e pe JVM, în `src/test/kotlin/org/ghost/sync/harness`: `FaultySqlExecutor` (fiecare instrucțiune și fiecare commit e un punct de crash), `HarnessRelayPort` peste `ModelRelay` (verificat față de `protocol/test-vectors/relay_semantics.txt`, reluat și de relay-ul Rust), driver determinist, enumerarea exhaustivă a crash-urilor simple și duble pentru scenariile S-A…S-H și S-L (plus S-P, consumatorul cu `peek`/`claimOne`, din Faza 9, și, din Faza 10 felia S1a, S-P/reoffer-deferred, un actor de canal care amână și readuce blobul cu `reofferDeferred`, și S-R/funded-channel, un canal finanțat ale cărui înregistrări sunt servite de capabilitatea de înregistrare, nu de credențialul bearer din slotul de scriere), lumi cu seed (relay-uri ostile, offline de ore până la 60 de zile, salturi de ceas, schimbări de set), mutanții M1–M13, T19 exact, canare T3. Codul de producție nu are comutatoare de test: mutanții substituie `Steps` sau instrucțiuni SQL doar în sursele de test. Harness-ul micșorează `listLimit`, `fetchedCap` și `backlogCap` prin `TrafficPolicy` ca scenariile să rămână enumerabile; valorile de producție nu se schimbă.

```bash
cd ghost/android
./gradlew --no-daemon :sync:testDebugUnitTest            # implicit: 1 000 de seed-uri, crash-uri duble în WAL (~10 min local)
./gradlew --no-daemon :sync:testDebugUnitTest -Dghost.sync.seeds=20000 -Dghost.sync.exhaustive=full   # ca jobul CI sync-exit-gate
./gradlew --no-daemon :sync:testDebugUnitTest --tests '*SeededWorldsTest' -Dghost.sync.seed=<seed>   # reia un seed din mesajul de eșec
```

Setări (prin `-D` sau `-P`): `ghost.sync.seeds`, `ghost.sync.seed`, `ghost.sync.exhaustive=full` (crash-uri duble și variantele S-F de 3 zile în ambele moduri de jurnal), `ghost.sync.threads`, `ghost.sync.harness.dir` (pe Linux, bazele merg implicit în `/dev/shm` când există). Raportul rulării (seed-uri, numărul de evenimente, mutanți, timpi) e în `sync/build/harness/report.txt`; jobul CI `sync-exit-gate` îl pune în sumarul rulării.

## Gate-uri

- `scripts/gates/sync-no-catch-all.sh`: în `android/sync/src/main` și `android/entitlement/src/main` (participantul, Faza 8; directorul trebuie să existe), niciun catch de `Throwable`, `Exception`, `RuntimeException` sau `*Error`, niciun `runCatching`, `Result.getOrElse`/`recoverCatching` și nicio setare de handler pentru excepții neprinse, ca un crash să nu poată fi înghițit (fixture: `test-harness/gates/negative-sync/`). Singurele excepții prinse de motor sunt `NetworkException` și `IllegalArgumentException`, în jurul apelului către relay (`ErrorPolicy.relayCall`).
- `kotlin-clearnet.sh` (T6, partea Kotlin), `manifest-lint.sh` și `merged-manifest-lint.sh` (T15/T15m), `no-logging.sh` (fără `Log.*`/`println`), `anti-placeholder.sh` (T8), `dependency-allowlist.sh` (T7).
- `scripts/gates/run-all.sh` rulează gate-urile statice; `merged-manifest-lint.sh` are nevoie de `:app:assembleRelease` și rulează în jobul CI android.

Starea gate-ului Fazei 7 și ce mai rămâne: `docs/STATUS.md`.
