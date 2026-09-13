# Runbook-uri: issuer-ul GHOST pe stagenet

Proceduri de operare pentru issuer-ul de entitlement (design Faza 8 §3.3, §6.7, §6.8, §7.5, §9.5,
§10.5, §19.1, §19.10, §19.21, §19.22; ADR-26) și pentru operatorii de relay (O1). Fiecare runbook
este o listă de verificare; după fiecare comandă este dat rezultatul așteptat. Un rezultat diferit
oprește procedura: nu se continuă „ca să vedem”.

Fișierele din acest director:

| Fișier | Rol |
|---|---|
| `Dockerfile` | imaginea issuer-ului (ghost-issuer, Tor, monerod, monero-wallet-rpc, monero-wallet-cli din arhiva fixată în `monero-release.pin`, verificată cu `sha256sum -c` înainte de extragere) și ținta separată `ops` (ghost-issuer-ops pentru host) |
| `docker-compose.stagenet.yml` | containerele `tor`, `monerod`, `wallet-rpc`, `issuer` (plus `ops`, pornit doar la cerere) |
| `entrypoint.sh` | pornirea fiecărui rol: secretele trec din Docker secrets într-un tmpfs, procesul rulează neprivilegiat |
| `torrc` | serviciul onion al issuer-ului (`HiddenServicePort 443 127.0.0.1:7444`) și portul SOCKS al lui monerod |
| `config.stagenet.toml` | șablonul configurației issuer-ului, fără secrete și fără valori ale operatorului |
| `monero-release.pin` | singurul loc cu versiunea, URL-ul și SHA-256 al arhivei Monero (runbook M1/M2) |
| `snapshot.sh` | snapshot-ul orar al lui `issuer.redb` (B1, cron) |
| `journal-prune.sh` | tăierea orară a lui `issued.journal` după cel mai nou snapshot verificat (B1, cron) |

## 0. Convenții

- Comenzile de pe host rulează din rădăcina checkout-ului repository-ului (de exemplu
  `/srv/ghost-src`), ca root, cu:

  ```sh
  export H=/srv/ghost-issuer                 # directorul de pe host (secțiunea 1)
  export GHOST_ISSUER_HOST_DIR="$H"
  C="docker compose -f ghost/infra/issuer/docker-compose.stagenet.yml"
  ```

- Săptămâna curentă (indexul săptămânilor ISO al grilei, `ghost_entitlement::grid::week`; săptămâna
  2957 începe luni 2026-09-07 00:00 UTC):

  ```sh
  w=$(( ($(date -u +%s) - 345600) / 604800 )); echo "$w"
  date -u -d @$(( 345600 + 604800 * w ))     # începutul săptămânii w
  ```

  Epoca de invitație a săptămânii w este `w / 4`, epoca de credit și de preț este `w / 13`
  (împărțire întreagă).
- Mașina offline (ceremonia K1, încărcarea K3) are un checkout al aceluiași commit și
  `ghost-issuer-ops` construit din el: `cargo build --release -p ghost-issuer-ops --locked`
  (în exemple, `ghost-issuer-ops` este acel binar). `M` este directorul mediului amovibil montat.
- Uneltele de operator pe host-ul issuer-ului rulează în containerul `ops`, fără rețea:
  `$C --profile ops build ops`, apoi `$C run --rm ops <comandă> …`.
- **Fereastra de mentenanță.** O procedură care oprește, pornește sau recreează un container al
  issuer-ului (K2, K3, restaurarea B1, M2, R5, I1) începe cu

  ```sh
  touch "$H/maintenance" && flock "$H/snapshot.lock" true
  ```
  Așteptat: comanda se întoarce fără ieșire, cel mult după durata unui snapshot sau a unei tăieri a
  jurnalului în curs (câteva secunde). De acum snapshot-ul orar și tăierea jurnalului B1 (secțiunea
  6) nu mai ating containerele și jurnalul. Procedura se
  încheie, după ultimul ei rezultat așteptat, cu `rm "$H/maintenance"`. Așteptat: fără ieșire; la
  ora următoare apare un snapshot nou (`ls -t "$H/snapshots" | head -1`). Cât timp fișierul există
  nu se face niciun snapshot: o procedură întreruptă se duce la capăt sau se închide explicit.
- Issuer-ul nu scrie niciun log (ADR-26). Starea se citește din `$H/data/status.json`; un refuz la
  pornire este codul de ieșire al containerului (secțiunea 3). monerod și monero-wallet-rpc scriu
  la `--log-level 0` într-un tmpfs, pierdut la oprire (§6.5).

### Ce nu intră niciodată în repository

Cheia de schedule, secretul de custodie, fișierele de chei sigilate, fișierele de încărcare K3,
cheile secrete ale serviciilor onion, login-urile RPC, parola și fișierele wallet-ului, cheia ops,
copia de pe host a configurației, snapshot-urile, fișierele de lot și de confirmare ale plăților.
`scripts/gates/entitlement-schedule.sh` refuză cheile sigilate, fișierele de încărcare și cheile
secrete onion (după nume și după antet); `.gitignore` acoperă numele lor implicite. Restul este
păstrat afară doar prin această procedură: pe stagenet materialul generat în S2b stă pe mașina
proprietarului (`%USERPROFILE%\.ghost-stagenet-keys\`) și pe host-ul issuer-ului (secțiunea 1).

## 1. Directorul de pe host

Un singur director, pe un disc criptat (LUKS), proprietar root, mod 0700; fișierele secrete mod
0600. Numele lui este variabila `GHOST_ISSUER_HOST_DIR`; exemplele folosesc `/srv/ghost-issuer`.

| Cale în `$H` | Montat în container | Conținut |
|---|---|---|
| `config/issuer.toml` | `issuer`: `/etc/ghost-issuer/issuer.toml` (ro) | `config.stagenet.toml` plus `treasury_address` și `restore_height` |
| `secrets/wallet-rpc.login` | secret `wallet_rpc_login` | `utilizator:parolă` pentru monero-wallet-rpc (digest) |
| `secrets/daemon-rpc.login` | secret `daemon_rpc_login` | `utilizator:parolă` pentru RPC-ul lui monerod (digest) |
| `secrets/wallet.password` | secret `wallet_password` | parola fișierului wallet-ului view-only |
| `secrets/ops.key` | secret `ops_key` | sămânța de 32 de octeți a cheii ops (loturile de plată, P1) |
| `secrets/key-load.ghkl` | secret `key_load` | fișierul de încărcare K3 (valorile `k_seal`) |
| `sealed-keys/` | `issuer`: `/var/lib/ghost-issuer/sealed-keys` (ro) | fișierele sigilate `<kind>-<epoch>.ghks` |
| `tor/ghost-issuer/` | `tor`: `HiddenServiceDir` | setul de chei al onion-ului issuer-ului (`ghost-issuer-ops onion-keygen`) |
| `tor/state/` | `tor`: `DataDirectory` | starea lui Tor (gărzile de intrare) |
| `wallet/` | `wallet-rpc` | `issuer-view`, `issuer-view.keys` (view-only) |
| `monerod/` | `monerod` | blockchain-ul stagenet (pruned) |
| `data/` | `issuer`; `data/journal/` și în `ops` la `/journal`, doar pentru rularea din `journal-prune.sh` | `issuer.redb`, `journal/`, `status.json` |
| `export/` | `issuer` | `batch-<id>.ghpb` (ieșire), `ack-<id>.ghpa` (intrare) |
| `snapshots/` | `ops` (ro) | snapshot-urile B1 |
| `transfer/` | `ops` | numărătorile relay-urilor (intrare), fișierul de contoare (ieșire), R2 |
| `maintenance` | — | există doar într-o fereastră de mentenanță (secțiunea 0) |
| `snapshot.lock` | — | lacătul (`flock`) snapshot-ului B1 |

Entrypoint-ul copiază secretele și fișierele montate read-only în tmpfs-ul `/run/ghost` al
containerului, citibile doar de utilizatorul procesului; nimic secret nu ajunge pe disc în
container. Parolele RPC ajung la monerod și monero-wallet-rpc prin variabila `RPC_LOGIN`, nu pe
linia de comandă; singura excepție este `--daemon-login` al lui monero-wallet-rpc, vizibil doar în
containerul lui.

## 2. Instalare (prima pornire pe stagenet)

- [ ] Discul criptat este montat:

  ```sh
  findmnt -no SOURCE,FSTYPE /srv/ghost-issuer
  ```
  Așteptat: un dispozitiv `/dev/mapper/…` (LUKS), nu o partiție în clar.
- [ ] Directoarele:

  ```sh
  install -d -m 0700 "$H" "$H"/{config,secrets,sealed-keys,tor,tor/ghost-issuer,tor/state,wallet,monerod,data,export,snapshots,transfer}
  ```
- [ ] Login-urile și parola wallet-ului (câte o linie `utilizator:parolă`, fără alt conținut):

  ```sh
  umask 077
  printf 'ghost-wallet:%s' "$(head -c 24 /dev/urandom | base64 | tr -d '/+=')" > "$H/secrets/wallet-rpc.login"
  printf 'ghost-daemon:%s' "$(head -c 24 /dev/urandom | base64 | tr -d '/+=')" > "$H/secrets/daemon-rpc.login"
  head -c 32 /dev/urandom | base64 | tr -d '/+=' > "$H/secrets/wallet.password"
  ```
  Un login de altă formă este refuzat la pornire: `entrypoint: secret … is not one user:password line`.
- [ ] Cheia ops, pe mașina offline:

  ```sh
  ghost-issuer-ops keygen --new-ops-key "$M/ops.key"
  ```
  Așteptat: `OPS_KEY_CREATED public=<64 hex>`. Cheia publică se notează pentru stația de plăți
  (`--ops-public-key`, P1). `ops.key` se copiază în `$H/secrets/ops.key` (0600) și se șterge de pe
  mediu.
- [ ] Setul de chei al onion-ului issuer-ului generat în S2b (cele trei fișiere
  `hs_ed25519_secret_key`, `hs_ed25519_public_key`, `hostname`) se copiază în
  `$H/tor/ghost-issuer/`. Fără cheia secretă containerul `tor` refuză să pornească (altfel Tor ar
  crea un onion nou). `hostname`-ul copiat nu contează: rolul `tor` îl șterge la fiecare pornire și
  Tor îl rescrie din cheia secretă pe care o încarcă, deci onion-ul se verifică față de ES abia după
  pornirea lui Tor (mai jos).

  ```sh
  ls "$H/tor/ghost-issuer"
  ```
  Așteptat: `hostname  hs_ed25519_public_key  hs_ed25519_secret_key`.
- [ ] Fișierele sigilate ale orizontului ES (generate în S2b) se copiază în `$H/sealed-keys/`, apoi
  se face o încărcare K3 (secțiunea 5.3) care produce `$H/secrets/key-load.ghkl`.
- [ ] Wallet-ul view-only din adresa primară a trezoreriei și cheia secretă de vizualizare (fără
  cheia de cheltuire), cu înălțimea de restaurare a trezoreriei:

  ```sh
  export TREASURY=5…                 # adresa primară stagenet a trezoreriei
  export RESTORE_HEIGHT=…            # înălțimea de restaurare a wallet-ului trezoreriei
  $C build
  docker run --rm -it --network none --entrypoint monero-wallet-cli \
    -v "$H/wallet:/w" -v "$H/secrets/wallet.password:/p/wallet.password:ro" \
    ghost-issuer-stagenet:local --stagenet --offline \
    --generate-from-view-key /w/issuer-view --restore-height "$RESTORE_HEIGHT" \
    --password-file /p/wallet.password
  ```
  La întrebări: adresa standard (`$TREASURY`) și cheia secretă de vizualizare; dacă se cere parola,
  este conținutul lui `wallet.password`. Așteptat: adresa afișată de wallet este exact
  `$TREASURY`, apoi promptul wallet-ului; se iese cu `exit`. În `$H/wallet/` există `issuer-view` și
  `issuer-view.keys`.
- [ ] Configurația:

  ```sh
  install -m 0600 ghost/infra/issuer/config.stagenet.toml "$H/config/issuer.toml"
  printf 'treasury_address = "%s"\nrestore_height = %s\n' "$TREASURY" "$RESTORE_HEIGHT" >> "$H/config/issuer.toml"
  ```
- [ ] Tor și monerod:

  ```sh
  $C up -d tor monerod
  ```
  Așteptat: ambele containere `running` în `$C ps`.
- [ ] Onion-ul issuer-ului, pe fișierul `hostname` scris de Tor din cheia secretă (după câteva
  secunde; dacă lipsește, `$C logs tor`), comparat cu `issuer_onion` din ES (port 443), pe care
  `ghost-issuer-ops schedule-onions` îl afișează în vocabularul rapoartelor:

  ```sh
  $C --profile ops build ops
  $C run --rm ops schedule-onions --schedule /etc/ghost/schedule.ghes \
    | grep -c -x -F "ISSUER_ONION onion=$(cat "$H/tor/ghost-issuer/hostname") port=443"
  ```
  Așteptat: `1`. Cu `0` se oprește instalarea (`$C down`): Tor servește alt onion decât
  `issuer_onion` din ES, iar clienții nu l-ar găsi; se verifică setul de chei. Onion-ul unui relay
  nu trece verificarea (el apare doar în liniile `SLOT_ONION`). Fără filtru, comanda dă o singură
  linie, `ISSUER_ONION onion=<56>.onion port=443`; cu `--now "$(date +%s)"` adaugă câte o linie
  `SLOT_ONION week=<w> slot=<s> onion=<56>.onion port=<p>` pentru fiecare slot al săptămânii curente
  și al celei următoare. `ES_REFUSED …` (cod 1): ES-ul nu se verifică sub cheia fixată.
- [ ] Sincronizarea lui monerod (prin Tor durează ore):

  ```sh
  $C exec monerod sh -c 'monerod --stagenet --rpc-bind-port 38081 --rpc-login "$(cat /run/secrets/daemon_rpc_login)" status'
  ```
  Așteptat, la final: `Height: N/N (100.0%) on stagenet, not mining, net hash …, v16, K(out)+0(in)
  connections, uptime …`, cu K > 0 și `0(in)` (monerod nu acceptă conexiuni de intrare). Fără
  `--rpc-login` răspunsul este `Error: Problem fetching info` (autentificarea digest este activă).
- [ ] Wallet-ul și issuer-ul:

  ```sh
  $C up -d wallet-rpc issuer
  $C ps
  cat "$H/data/status.json"
  ```
  Așteptat: cele patru containere `running` (niciunul `restarting`) și un status ca în secțiunea 3,
  cu `"SCANNER":"SCANNER_OK"`, `"POOL_SIZE":"POOL_OK"` (după câteva minute de reumplere),
  `"KEYS_MISSING":0`, `"HALTED":false`.

## 3. Starea issuer-ului

`$H/data/status.json`, rescris la fiecare 60 s, o linie, doar coduri fixe și numere agregate:

```json
{"SCANNER":"SCANNER_OK","KEYS_READY_UNTIL_WEEK":2963,"ES_HORIZON_WEEKS":33,"POOL_SIZE":"POOL_OK","OPEN_INVOICES":0,"RECONCILIATION":"RECONCILIATION_OK","REORG_AFTER_ISSUE":0,"CONFIRMED_UNISSUED":0,"POOL_RECONCILED":0,"SIGN_FAULT":0,"KEYS_MISSING":0,"PAYOUT_BATCH_READY":false,"PAYOUT_BATCHES_OPEN":0,"PAYOUT_OLDEST_BATCH_WEEKS":0,"PAYOUT_ACKS_REFUSED":0,"HALTED":false}
```

| Câmp | Normal | Acțiune altfel |
|---|---|---|
| `SCANNER` | `SCANNER_OK` | `WALLET_UNREACHABLE`: containerul `wallet-rpc`; `WALLET_INCOMPLETE`: R5; `SCANNER_STALLED` sau `REORG_DEPTH`: resincronizare monerod, niciodată expirare forțată (R4) |
| `KEYS_READY_UNTIL_WEEK` | ≥ săptămâna curentă + 4 | K3 |
| `ES_HORIZON_WEEKS` | ≥ 8 | K1/K2 (alarmă de orizont) |
| `POOL_SIZE` | `POOL_OK` | `POOL_LOW`/`POOL_EMPTY`: wallet-ul sau monerod |
| `RECONCILIATION` | `RECONCILIATION_OK` | R2 imediat |
| `SIGN_FAULT`, `REORG_AFTER_ISSUE` | 0 | investigare; I1 dacă nu are explicație |
| `PAYOUT_BATCHES_OPEN`, `PAYOUT_OLDEST_BATCH_WEEKS` | 0 după P1 | P1 |
| `PAYOUT_ACKS_REFUSED` | 0 | fișierul de confirmare nu corespunde unui lot exportat |
| `HALTED` | `false` | `true`: jurnalul sau baza au eșuat; `$C restart issuer` reia jurnalul |

Codul de ieșire al unui issuer oprit:

```sh
docker inspect -f '{{.State.ExitCode}}' ghost-issuer-stagenet-issuer-1
```

| Cod | Refuz |
|---|---|
| 1 | listener-ul sau serverul gRPC |
| 2 | utilizare sau fișierul de configurație |
| 3 | ES: semnătura, rețeaua, regula 5 față de memoria bazei |
| 4 | cheile: fișierul de încărcare, un fișier sigilat, o cheie care nu este intrarea ei din ES, cheia ops |
| 5 | wallet-ul: login, inaccesibil, nu este view-only, adresa primară nu este trezoreria, daemon pe altă rețea; `--restore-wallet`: reluarea sau rescanarea |
| 6 | starea: baza, jurnalul, reluarea, altă înălțime de restaurare decât cea înregistrată |
| 64 | entrypoint-ul: un secret sau o montare lipsește (mesajul `entrypoint: …` în `$C logs issuer`) |

## 4. Regula de lansare a ES (§19.21 punctul 1)

ES seq 1 acoperă săptămânile de acces 2957…2989 (2026-W37 … 2027-W16). O versiune de aplicație
livrează cel puțin 26 de săptămâni de chei (§3.1).

- [ ] O versiune care încorporează seq 1 se lansează **cel târziu în săptămâna 2964 (luni
  2026-10-26)**: săptămânile 2964…2989 sunt exact 26.
- [ ] Orice versiune ulterioară încorporează un ES a cărui ultimă săptămână este cel puțin
  săptămâna lansării + 25, deci seq 2 se semnează (K1) înainte de prima lansare de după săptămâna
  2964, nu doar până la termenul K2.
- [ ] **seq 2 ajunge în versiuni ale aplicației și la toți operatorii de relay cel târziu în
  săptămâna 2982 (luni 2027-03-01)**: 8 săptămâni înainte de săptămâna 2990, prima neacoperită de
  seq 1 (K2).
- [ ] Nicio poartă nu verifică regula (`entitlement-schedule.sh` numără orizontul de la prima
  săptămână a ES-ului, ca nimic să nu depindă de data build-ului, T12); o aplică procesul de
  lansare. Alarma de pe issuer: `ES_HORIZON_WEEKS` < 8.
- [ ] ES-ul comis se verifică sub cheia fixată (ce rulează poarta):

  ```sh
  bash ghost/scripts/gates/entitlement-schedule.sh
  ```
  Așteptat pentru seq 1: `ES_OK seq=1 network=stagenet first_week=2957 last_week=2989 weeks=33
  keys=45 slots=3 sha256=6d70be75c120b75884e97c35cf495be5e2c73686173ca9983be26d8f12d8e0de
  schedule_key=pinned`, `DIRECTORY_OK weeks=2`, `[entitlement-schedule] OK`. Același `sha256` îl
  dă `sha256sum ghost/protocol/entitlement/schedule.ghes` pe orice host care îl folosește.

## 5. Cheile (K1–K4, §3.3, §19.1)

### 5.1 K1: ceremonia (trimestrial)

Pe o mașină offline de clasa wallet-ului rece Monero, cu două persoane. Pe stagenet cheia de
schedule este cheia doar-stagenet din S2b (Q20 revizuit); primul ES mainnet cere cheia offline
reală și ceremonia K1 cu ea (Faza 16/17). Exemplul este seq 2: săptămânile de acces 2990…3015,
epocile de invitație 748…753, epocile de credit și de preț 230…231.

- [ ] Mașina nu are rețea; checkout-ul este commit-ul lansării; `ghost-issuer-ops` construit din el.
- [ ] Pe mediul `M`: secretul de custodie și cheia de schedule (păstrate în custodie, niciodată pe
  host-ul issuer-ului).
- [ ] Cheile noi, câte una pentru fiecare (tip, epocă):

  ```sh
  ghost-issuer-ops keygen --kind access --from-epoch 2990 --count 26 \
    --custody-secret "$M/custody.secret" --public-dir "$M/public" --sealed-dir "$M/sealed"
  ghost-issuer-ops keygen --kind invite --from-epoch 748 --count 6 \
    --custody-secret "$M/custody.secret" --public-dir "$M/public" --sealed-dir "$M/sealed"
  ghost-issuer-ops keygen --kind credit --from-epoch 230 --count 2 \
    --custody-secret "$M/custody.secret" --public-dir "$M/public" --sealed-dir "$M/sealed"
  ```
  Așteptat: câte o linie `KEY_CREATED kind=<tip> epoch=<e> key_id=<64 hex>` pentru fiecare cheie;
  `KEY_REFUSED` oprește ceremonia (verificările prime au eșuat) și fișierul nu este scris.
- [ ] Sursa seq 2 = sursa seq 1 cu `seq 2`, intervalele `keys` extinse (`keys access 2957 3015`,
  `keys invite 739 753`, `keys credit 227 231`) și `price 230 …`, `price 231 …` noi. Tot ce a
  acceptat seq 1 rămâne neschimbat (regula 5): cheile, sloturile săptămânilor acoperite, prețurile,
  revocările. Un slot nou sau un relay nou intră doar de la o graniță de săptămână neacoperită.
- [ ] Semnarea:

  ```sh
  ghost-issuer-ops schedule-sign --source "$M/es-seq2.source" --schedule-key "$M/schedule.key" \
    --public-dir "$M/public" --previous ghost/protocol/entitlement/schedule.ghes --out "$M/es-seq2"
  ```
  Așteptat: `ES_SIGNED seq=2 network=stagenet first_week=2957 last_week=3015 weeks=59 keys=79
  slots=<n> sha256=<64 hex>`. `ES_REFUSED` sau `KEY_CONFLICT` înseamnă că sursa schimbă ceva
  acceptat: nu se semnează altceva „ca să treacă”.
- [ ] Verificarea față de tot istoricul: noul fișier se pune peste
  `ghost/protocol/entitlement/schedule.ghes` în checkout (necomis) și se rulează poarta:

  ```sh
  bash ghost/scripts/gates/entitlement-schedule.sh
  ```
  Așteptat: `ES_OK seq=2 network=stagenet first_week=2957 last_week=3015 weeks=59 keys=79 …
  schedule_key=pinned`, `ES_APPEND_ONLY previous_seq=1 history=1`, `DIRECTORY_OK weeks=2`,
  `[entitlement-schedule] OK`.
- [ ] Fișierele sigilate noi (`$M/sealed/`) merg pe host-ul issuer-ului în `$H/sealed-keys/`
  (sunt criptate; transport pe mediu amovibil). Cheia de schedule și secretul de custodie se întorc
  în custodie; mașina offline se șterge.
- [ ] ES-ul semnat intră printr-un pull request care înlocuiește
  `ghost/protocol/entitlement/schedule.ghes` (și rândurile README-ului de lângă el); CI:
  `entitlement-schedule.sh` (regula 5 pe istoricul first-parent) și `monero-regtest` verzi.

### 5.2 K2: publicarea

- [ ] ES-ul nou ajunge într-o versiune a aplicației și la fiecare operator de relay cu cel puțin 8
  săptămâni înainte de prima săptămână de care e nevoie (secțiunea 4; relay-urile: O1).
- [ ] Pe host-ul issuer-ului, după merge, fereastra de mentenanță (secțiunea 0):

  ```sh
  touch "$H/maintenance" && flock "$H/snapshot.lock" true
  ```
  Așteptat: fără ieșire.
- [ ] Noul ES:

  ```sh
  git pull --ff-only && $C up -d --force-recreate issuer
  sha256sum ghost/protocol/entitlement/schedule.ghes
  ```
  Așteptat: `issuer` `running`, `ES_HORIZON_WEEKS` crescut; hash-ul este `sha256` din `ES_SIGNED`.
  Cod de ieșire 3: ES-ul încalcă regula 5 față de memoria bazei; se revine la ES-ul anterior (în
  aceeași fereastră).
- [ ] Închiderea ferestrei: `rm "$H/maintenance"` (așteptat ca în secțiunea 0).

### 5.3 K3: încărcarea cheilor (la 2 săptămâni)

- [ ] Pe mașina offline, în săptămâna w (`from-week = w − 6` pentru cheile încă referite de facturi
  deschise, `through-week = w + 6`, §19.1):

  ```sh
  ghost-issuer-ops keys-seal --schedule ghost/protocol/entitlement/schedule.ghes \
    --custody-secret "$M/custody.secret" --sealed-dir "$M/sealed" \
    --from-week $((w - 6)) --through-week $((w + 6)) --out "$M/key-load.ghkl"
  ```
  Așteptat: câte o linie `SEAL_KEY_READY kind=<tip> epoch=<e> key_id=<64 hex>` (fiecare fișier
  sigilat deschis în cheia intrării lui din ES), apoi `SEAL_LOAD_WRITTEN entries=<n>`. `KEY_MISSING`
  sau `SEAL_REFUSED`: un fișier sigilat lipsește sau nu corespunde ES-ului.
- [ ] Pe host, într-o fereastră de mentenanță (secțiunea 0; fișierul nou are alt inode: containerul
  se recreează ca secretul să fie remontat):

  ```sh
  touch "$H/maintenance" && flock "$H/snapshot.lock" true
  install -m 0600 /media/transfer/key-load.ghkl "$H/secrets/key-load.ghkl"
  shred -u /media/transfer/key-load.ghkl
  $C up -d --force-recreate issuer
  ```
  Așteptat: prima comandă fără ieșire; `running`; în `status.json` `KEYS_READY_UNTIL_WEEK` = w + 6
  și `KEYS_MISSING` 0. Cod 4: fișierul de încărcare sau un fișier sigilat (fereastra rămâne deschisă
  până la o pornire reușită).
- [ ] Închiderea ferestrei: `rm "$H/maintenance"` (așteptat ca în secțiunea 0).

### 5.4 K4: distrugerea

- [ ] Automat, fără acțiune: cheia privată a unei (tip, epoci) părăsește memoria când
  `now ≥ end(epocă) + 8 z` și nicio factură deschisă nu o referă, cel târziu la `end(epocă) + 42 z`;
  cheia CREDIT a epocii c rămâne până la `end(c + 1) + 8 z` (RefreshCredit).
- [ ] Trimestrial, în săptămâna w: se șterg fișierele sigilate pe care K3 nu le mai cere, pe host
  și pe mediile offline: `access-<p>.ghks` cu p < w − 6, `invite-<e>.ghks` cu
  e < (w − 6) / 4, `credit-<c>.ghks` cu c < (w − 6) / 13 − 1.

  ```sh
  ls "$H/sealed-keys"
  shred -u "$H/sealed-keys/access-2950.ghks"      # câte unul, după regula de mai sus
  ```
  Așteptat: `ls` nu mai arată nicio epocă sub prag. Cu fișierul sigilat șters, cheia nu mai poate
  fi reconstruită (secretul de custodie dă doar `k_seal`).

## 6. B1: snapshot-uri și restaurare

Snapshot-ul este o copie a lui `issuer.redb` cu issuer-ul oprit câteva secunde (o copie în timpul
unei scrieri poate fi ruptă), făcută de `ghost/infra/issuer/snapshot.sh`. Tor rămâne pornit, deci
wallet-ul și monerod nu sunt atinse; clienții primesc `UNAVAILABLE` și reîncearcă la termenul lor.
Issuer-ul se termină la SIGTERM (compose: `init: true`) fără să-și închidă baza, ca la o cădere.
`reconcile-check` și `counters-export` nu deschid snapshot-ul însuși: îl copiază într-un fișier
privat din tmpfs-ul `/tmp` al containerului `ops` și îl deschid acolo cu reparația pe care o face
și issuer-ul când repornește după o cădere; copia se șterge după verificare, iar snapshot-ul
rămâne neschimbat.

Scriptul repornește doar un issuer pe care l-a oprit el. Într-o fereastră de mentenanță
(`$H/maintenance`, secțiunea 0) nu atinge nimic și nu scrie nimic. Un issuer care nu rulează (oprit
de operator sau în repornire după un refuz de pornire) rămâne oprit, cu mesajul `snapshot: skipped,
the issuer is not running …` în mail-ul cron-ului. Dacă copia eșuează, issuer-ul este repornit și
mesajul este `snapshot: failed, …`.

- [ ] Cron pe host, în `/etc/cron.d/ghost-issuer` (root; `snapshot.sh` și `journal-prune.sh` sunt
  executabile în checkout):

  ```cron
  7 * * * * root GHOST_ISSUER_HOST_DIR=/srv/ghost-issuer /srv/ghost-src/ghost/infra/issuer/snapshot.sh
  17 * * * * root find /srv/ghost-issuer/snapshots -name 'issuer-*.redb' ! -name 'issuer-*00.redb' -mmin +2819 -delete
  27 * * * * root find /srv/ghost-issuer/snapshots -name 'issuer-*00.redb' -mmin +10019 -delete
  37 * * * * root GHOST_ISSUER_HOST_DIR=/srv/ghost-issuer /srv/ghost-src/ghost/infra/issuer/journal-prune.sh
  ```
  Retenția (§19.15) este un maxim: `find -mmin +n` potrivește fișierele de cel puțin n + 1 minute și
  ștergerea rulează orar, deci un snapshot orar trăiește cel mult 47 h + 1 h = 48 h, iar cel zilnic
  (ora 00 UTC) cel mult 167 h + 1 h = 7 zile. Ștergerea rulează și într-o fereastră de mentenanță.
  Snapshot-urile stau pe discul criptat; o copie în afara host-ului se criptează înainte
  (`gpg --symmetric`) și respectă aceeași retenție. Așteptat, după ora următoare:
  `ls -t "$H/snapshots" | head -1` dă `issuer-<AAAALLZZHH>.redb` al orei curente (UTC).
- [ ] Zilnic, verificarea ultimului snapshot:

  ```sh
  $C run --rm ops reconcile-check --database /snapshots/issuer-<AAAALLZZHH>.redb \
    --schedule /etc/ghost/schedule.ghes --now "$(date +%s)"
  ```
  Așteptat: `RECONCILIATION_OK weeks=<n> relays=0` (copia se deschide cu schema 1 și invarianții
  țin). Altfel snapshot-ul nu este „verificat” și nu se folosește la restaurare.
- [ ] Tăierea jurnalului (§6.3, §6.4; automată, linia de la minutul 37 din cron): `journal-prune.sh`
  ia cel mai nou snapshot din `$H/snapshots/`, îl verifică la fel ca pasul de mai sus (se deschide cu
  schema 1, invarianții reconcilierii țin) și abia apoi șterge, cel mai vechi întâi, segmentele
  `issued.journal.<săptămână>` ale căror intrări sunt toate mai vechi de 7 zile și aplicate în
  snapshot (marcajul lui `journal_applied`, citit prin copia privată); segmentul cel mai nou, în care
  scrie issuer-ul, rămâne. Un snapshot neverificat sau care nu se potrivește jurnalului (a aplicat
  intrări pe care jurnalul nu le are, sau jurnalul nu mai are intrarea de după el) nu șterge nimic.
  Rulează în containerul `ops`, cu `data/journal/` montat la `/journal` și capabilitatea
  `DAC_OVERRIDE` doar pentru această rulare (fișierele jurnalului sunt ale utilizatorului
  issuer-ului); issuer-ul poate rula între timp (nu se deschide niciun segment pentru scriere). Ține
  `$H/snapshot.lock` cât rulează și nu face nimic într-o fereastră de mentenanță. Retenția: segmentul
  săptămânii w pleacă la prima rulare după `start(w + 2)`, deci o intrare trăiește cel mult 14 zile
  și o oră (§6.4: 7–14 zile), iar orice snapshot păstrat (cel mult 7 zile) rămâne restaurabil cu
  jurnalul rămas. Așteptat: nicio ieșire; un refuz (`PRUNE_REFUSED reason=<…>`, cu
  `RECONCILIATION_MISMATCH …` înainte pentru `snapshot-unverified`, sau `INPUT_REFUSED …`,
  `ES_REFUSED …`) ajunge în mail-ul cron-ului și se investighează înainte de orice restaurare.
  Verificare manuală:

  ```sh
  GHOST_ISSUER_HOST_DIR="$H" ghost/infra/issuer/journal-prune.sh && ls "$H/data/journal"
  ```
  Așteptat: niciun mesaj de la script, apoi doar segmente `issued.journal.<w>` cu w cel puțin
  săptămâna curentă − 1 (și săptămâna curentă − 2 în prima oră a unei săptămâni).
- [ ] Restaurare, când `issuer.redb` este corupt sau pierdut și `data/journal/` este intact, într-o
  fereastră de mentenanță (secțiunea 0; altfel snapshot-ul orar ar putea porni issuer-ul între `mv`
  și `install`, pe un director fără bază):

  ```sh
  touch "$H/maintenance" && flock "$H/snapshot.lock" true
  $C stop issuer
  mv "$H/data/issuer.redb" "$H/data/issuer.redb.broken"
  install -m 0600 "$H/snapshots/issuer-<cel mai nou verificat>.redb" "$H/data/issuer.redb"
  GHOST_ISSUER_FLAGS=--restore $C up -d --force-recreate issuer
  ```
  Issuer-ul reia jurnalul de după snapshot, golește pool-ul de subadrese și îl reumple peste
  numărul de subadrese al wallet-ului (niciun minor nu se dă de două ori, §19.5). Jurnalul tăiat
  păstrează intrările de după orice snapshot care nu a fost încă șters (cel mult 7 zile). Așteptat:
  `running`; `status.json` cu `"HALTED":false`, `"RECONCILIATION":"RECONCILIATION_OK"` și, după
  reumplere, `"POOL_SIZE":"POOL_OK"`. Cod 6: jurnalul are o gaură sau snapshot-ul nu este al
  acestui issuer.
- [ ] Imediat după: `$C up -d --force-recreate issuer` fără variabilă (pornirile următoare sunt
  normale). Așteptat: `running`, `"HALTED":false`. Apoi închiderea ferestrei și un snapshot nou,
  verificat ca mai sus:

  ```sh
  rm "$H/maintenance"
  GHOST_ISSUER_HOST_DIR="$H" ghost/infra/issuer/snapshot.sh && ls -t "$H/snapshots" | head -1
  ```
  Așteptat: niciun mesaj de la script, apoi numele snapshot-ului nou. `issuer.redb.broken` se șterge
  (`shred -u`).
- [ ] Pierderea bazei **și** a jurnalului pierde facturile plătite dar neemise de după snapshot
  (R13, declarat); se restaurează la fel, cu jurnalul care există.

## 7. M2: înaintea unui hard fork Monero

- [ ] Versiunea Monero a fork-ului: pull request care schimbă doar `monero-release.pin` (versiune,
  URL, arhive, SHA-256). Valorile vin din `hashes.txt` semnat de binaryFate (amprenta
  `81AC 591F E9C4 B65C 5806 AFC3 F0AF 4D46 2A0B DF92`), verificat cu gpg într-un keyring de
  unică folosință, și din SHA-256 al arhivelor descărcate de la adresa din linia `url` a pinului
  (antetul pinului descrie pașii). `scripts/gates/monero-pin.sh` refuză o a doua copie a unui hash.
- [ ] Jobul `monero-regtest` trece pe noua versiune: dovada view-only, semnarea la rece, plata,
  restaurarea. Dacă eșuează, nu se face upgrade (vezi mentenanța, mai jos).
- [ ] Înainte de înălțimea fork-ului: loturile de plată în curs se termină (P1, până la
  `"PAYOUT_BATCHES_OPEN":0`).
- [ ] Fereastra de mentenanță (secțiunea 0), deschisă până la ultimul pas: în mentenanță (mai jos)
  issuer-ul nu poate reporni fără wallet (cod 5), deci nici snapshot-ul orar nu trebuie să-l
  oprească.

  ```sh
  touch "$H/maintenance" && flock "$H/snapshot.lock" true
  ```
  Așteptat: fără ieșire.
- [ ] Upgrade:

  ```sh
  git pull --ff-only && $C build && $C up -d --force-recreate monerod wallet-rpc issuer
  $C exec monerod sh -c 'monerod --stagenet --rpc-bind-port 38081 --rpc-login "$(cat /run/secrets/daemon_rpc_login)" status'
  ```
  Așteptat: `Height: N/N (100.0%) on stagenet, …` după resincronizare, apoi
  `"SCANNER":"SCANNER_OK"`.
- [ ] Mentenanță, dacă wallet-ul view-only sau semnarea la rece nu funcționează pe noua versiune:
  `$C stop wallet-rpc`. Facturile XMR noi primesc `UNAVAILABLE` (niciun tick sincronizat),
  `BlindSign` pentru facturile deja confirmate, pachetele plătite cu credite și invitațiile continuă;
  tokenurile și relay-urile nu sunt afectate. Starea așteptată: `"SCANNER":"WALLET_UNREACHABLE"`.
  Issuer-ul nu se repornește în mentenanță (la pornire cere wallet-ul: cod 5). Mentenanța se
  încheie cu upgrade-ul de mai sus, pe o versiune pe care `monero-regtest` trece.
- [ ] Închiderea ferestrei, după `"SCANNER":"SCANNER_OK"`: `rm "$H/maintenance"` (așteptat ca în
  secțiunea 0).

## 8. O1: operatorii de relay (la fiecare ES)

Staging: o singură parte rulează cele trei relay-uri din `ghost/infra/relay/docker-compose.staging.yml`
(sloturile 0, 1, 2 = `relay-a`, `relay-b`, `relay-c`); independența ADR-11 nu este revendicată
pentru staging. `GHOST_STAGING_KEYS` numește directorul cu seturile de chei onion generate cu ES-ul
(`relay-a/`, `relay-b/`, `relay-c/`), în afara repository-ului.

- [ ] ES-ul nou instalat cu cel puțin 8 săptămâni înainte: aceiași octeți ca în versiunea aplicației
  (`sha256sum ghost/protocol/entitlement/schedule.ghes` = `sha256` din `ES_SIGNED`).
- [ ] Relay-ul pornește cu `--schedule /etc/ghost/schedule.ghes --slot <n> --onion-hostname-file
  /run/ghost-relay/onion-hostname --redemption-counts /var/lib/ghost/redemption-counts.txt`
  (compose-ul de staging le dă). Entrypoint-ul șterge `hostname`-ul
  venit cu setul de chei, îl lasă pe Tor să-l scrie din cheia secretă pe care o încarcă și abia apoi
  îl copiază acolo, pentru relay-ul neprivilegiat: relay-ul compară cu ES-ul onion-ul pe care Tor îl
  servește. O actualizare a ES-ului este o repornire; nulifierii persistați rămân:

  ```sh
  export GHOST_STAGING_KEYS=/srv/ghost-staging-keys
  R="docker compose -f ghost/infra/relay/docker-compose.staging.yml"
  git pull --ff-only && $R up -d --force-recreate relay-a relay-b relay-c
  $R logs relay-a relay-b relay-c | grep -e 'onion address:' -e 'ghost-relay listening on'
  ```
  Așteptat, după cel mult un minut: pentru fiecare relay câte o linie `onion address: <56>.onion`,
  același onion ca rândul slotului lui în `ghost/protocol/entitlement/relay-directory.txt`, și câte
  o linie `ghost-relay listening on 127.0.0.1:7443 (protocol v1)`; cele trei containere `running`.
  Relay-ul refuză să pornească (mesaj constant, apoi repornire) dacă: ES-ul nu se verifică; încalcă
  regula 5 față de `nullifiers.redb`; onion-ul lui nu este listat pentru slot în săptămâna curentă;
  lipsește `nullifiers.redb` lângă un `relay.key` existent. Entrypoint-ul refuză fără setul de chei
  onion (`error: --schedule needs the onion service key set …`) și când Tor nu scrie `hostname` în
  60 s (`error: tor wrote no onion hostname …`).
- [ ] `nullifiers.redb` stă pe discul criptat și **nu se restaurează niciodată dintr-un backup
  vechi**: un set vechi redeschide reutilizarea tokenurilor.
- [ ] Upgrade-ul Faza 8 al unui relay care nu a răscumpărat niciodată (`relay.key` există,
  `nullifiers.redb` nu), o singură pornire cu `--nullifiers-init`:

  ```sh
  GHOST_RELAY_A_NULLIFIERS=--nullifiers-init $R up -d --force-recreate relay-a
  $R logs relay-a | grep -c 'ghost-relay listening on'
  $R exec relay-a ls /var/lib/ghost
  ```
  Așteptat, după cel mult un minut (Tor scrie `hostname`, apoi relay-ul creează store-ul și
  pornește; ultimele două comenzi se repetă până atunci): `1`, apoi o listă cu `nullifiers.redb`,
  `redemption.marker` și `relay.key`. Abia apoi pornirea normală:

  ```sh
  $R up -d --force-recreate relay-a
  $R logs relay-a | grep -c 'ghost-relay listening on'
  ```
  Așteptat: `1` și containerul `running`. O pornire normală venită înainte de store este refuzată
  (`nullifier store is missing …`, apoi repornire în buclă): se reia pasul cu `--nullifiers-init`,
  permis cât timp `redemption.marker` lipsește. `--nullifiers-init` este refuzat într-un director
  care a avut un store (`redemption.marker`).
- [ ] După pierderea lui `nullifiers.redb`, sau a întregului director de date cu cheile onion
  păstrate (Q25: relay-ul nu se poate deosebi de unul nou; reziduu declarat în ADR-25), o singură
  pornire cu `--nullifiers-reset`:

  ```sh
  GHOST_RELAY_A_NULLIFIERS=--nullifiers-reset $R up -d --force-recreate relay-a
  $R logs relay-a | grep -c 'ghost-relay listening on'
  $R exec relay-a ls /var/lib/ghost
  ```
  Așteptat, ca la `--nullifiers-init`: `1`, apoi `nullifiers.redb`, `redemption.marker` și
  `relay.key`. Abia apoi pornirea normală:

  ```sh
  $R up -d --force-recreate relay-a
  $R logs relay-a | grep -c 'ghost-relay listening on'
  ```
  Așteptat: `1` și containerul `running`. Relay-ul refuză singur răscumpărările (`UNAVAILABLE`)
  pentru fiecare perioadă a cărei fereastră era deschisă la reset: până la
  `start(week(now) + 2) + 1 h` dacă resetul cade în ultimele 24 h ale unei săptămâni, altfel până
  la `start(week(now) + 1) + 1 h` (§19.10).
- [ ] Săptămânal, pentru R2 (§6.9 verificarea 2): fișierul de numărători al fiecărui relay. Relay-ul
  pornit cu `--redemption-counts` îl rescrie la pornire și după fiecare sweep care închide o
  săptămână, din `nullifiers.redb` (store-ul este ținut deschis de relay, deci nu se citește direct):

  ```sh
  for r in a b c; do $R exec -T relay-$r cat /var/lib/ghost/redemption-counts.txt > relay-$r.txt; done
  cat relay-a.txt
  ```
  Așteptat: prima linie `# ghost-relay redemption counts, closed weeks only (runbook R2)`, apoi câte
  o linie `week <w> slot <s> redemptions <n>` pentru fiecare săptămână închisă (fereastra ei s-a
  încheiat la `start(w + 1) + 1 h`) cu cel puțin o răscumpărare, cel mult ultimele 13, cu slotul
  relay-ului (0, 1, 2 pentru `relay-a`, `relay-b`, `relay-c`). Numărul unei săptămâni închise nu se
  mai schimbă; săptămânile deschise nu apar. Fișierul are doar agregate: nicio valoare de token,
  nulifier, tag sau namespace și niciun moment mai fin decât săptămâna. Cele trei fișiere ajung pe
  mediu amovibil în `$H/transfer/` (`relay-a.txt`, `relay-b.txt`, `relay-c.txt`) și la stația de
  plăți (R2). După un `--nullifiers-reset`, numărătorile săptămânilor de dinaintea resetului s-au
  pierdut cu store-ul.

## 9. P1: plățile (săptămânal)

- [ ] Issuer-ul exportă singur, o dată pe săptămână la o oră aleatoare: `$H/export/batch-<id>.ghpb`
  (semnat cu cheia ops). `"PAYOUT_BATCH_READY":true` înseamnă cereri care așteaptă lotul următor.
- [ ] Fișierul de lot trece pe mediu amovibil la stația de plăți (host separat, cu propriul
  monero-wallet-rpc view-only, `store-tx-info` oprit, și propriul monerod de încredere prin Tor).
- [ ] Pe stație: vederea proprie = răspunsul salvat al apelului JSON-RPC
  `get_transfers {"in":true,"account_index":0}` al wallet-ului stației (autentificare digest), în
  `view-dump.json`. Apoi:

  ```sh
  ghost-issuer-ops payout-check --batch batch-<id>.ghpb --ops-public-key <cheia publică ops> \
    --network stagenet --view-dump view-dump.json --restore-height "$RESTORE_HEIGHT" --ledger payouts.ledger
  ```
  Așteptat: `PAYOUT_ACCEPTED … entries=<n> refused=<k>`. `PAYOUT_REFUSED reason=<…>` (semnătura,
  rețeaua, un lot sau o cerere văzută deja, plafonul cumulativ de 10 % din venitul văzut de stație)
  oprește lotul. O intrare refuzată (adresă invalidă sau refolosită) închide cererea neplătită și
  creditele ei rămân cheltuite (Q26).
- [ ] Pentru fiecare intrare k, strict pe rând (k + 1 abia după ce k a fost trimisă, §19.7):
  1. `transfer` pe wallet-ul watch-only al stației → `unsigned_txset`;
     `ghost-issuer-ops payout-entry --ledger payouts.ledger --batch-id <id> --entry k --to built`.
  2. Pe wallet-ul rece (air-gapped): `describe_transfer` (destinatarul și suma egale cu intrarea
     din lot, restul la trezorerie), apoi `sign_transfer`; `--to signed --raw-tx <fișierul hex din
     tx_raw_list> --txid <txid>`. Așteptat: `ENTRY_STATE batch=<id> entry=k state=signed
     txid=<64 hex> images=<n>`.
  3. `submit_transfer` prin `--tx-proxy tor`, la un moment aleator în cel mult 72 h de la trimiterea
     precedentă; `--to submitted`.
  4. După 10 confirmări: răspunsul `get_transfer_by_txid` salvat; `--to confirmed --transfer
     <json>`.
  O intrare semnată dar netrimisă se reconstruiește doar după ce `is_key_image_spent` arată toate
  imaginile de cheie necheltuite (`--to abandoned --spent-status <json>`) și tranzacția semnată veche
  a fost distrusă.
- [ ] Confirmarea, când fiecare intrare este confirmată sau refuzată:

  ```sh
  ghost-issuer-ops payout-ack --ledger payouts.ledger --batch batch-<id>.ghpb \
    --ops-public-key <cheia publică ops> --out ack-<id>.ghpa
  ```
  Așteptat: `ACK_WRITTEN batch=<id> entries=<n>`. `ack-<id>.ghpa` (numele exact) se copiază în
  `$H/export/`; la rularea orară următoare `PAYOUT_BATCHES_OPEN` scade și `PAYOUT_ACKS_REFUSED`
  rămâne 0.
- [ ] Reîmprospătarea imaginilor de cheie pe stație (RM §6.1 pașii 1–4 și 9). Fișierele de lot se
  șterg la 7 zile după confirmare (§19.15).

## 10. R2: reconcilierea (săptămânal)

- [ ] Pe host, pe ultimul snapshot verificat (B1), cu numărătorile relay-urilor în `$H/transfer/`
  (fișierele de numărători din O1; o săptămână intră în verificare după ce s-a închis la toate
  relay-urile):

  ```sh
  $C run --rm ops reconcile-check --database /snapshots/issuer-<AAAALLZZHH>.redb \
    --schedule /etc/ghost/schedule.ghes --now "$(date +%s)" \
    --relay-counts /transfer/relay-a.txt --relay-counts /transfer/relay-b.txt --relay-counts /transfer/relay-c.txt
  ```
  Așteptat: `RECONCILIATION_OK weeks=<n> relays=3`. Orice `RECONCILIATION_MISMATCH …` (cod 1):
  investigare; credite răscumpărate peste cele semnate sau răscumpărări de acces peste
  `16·|sloturi(w)|·pachete + 8·|sloturi(w)|·trialuri` într-o săptămână indică falsuri: I1.
- [ ] Contoarele pentru stația de plăți (snapshot-ul nu părăsește host-ul):

  ```sh
  $C run --rm ops counters-export --database /snapshots/issuer-<AAAALLZZHH>.redb --out /transfer/counters-$w
  ```
  Așteptat: `COUNTERS_WRITTEN counters=<n>`.
- [ ] Pe stație, cu vederea ei proprie (verificarea pe care un issuer compromis nu o poate falsifica):

  ```sh
  ghost-issuer-ops reconcile-check --counters counters-<w> \
    --schedule ghost/protocol/entitlement/schedule.ghes --now "$(date +%s)" \
    --relay-counts relay-a.txt --relay-counts relay-b.txt --relay-counts relay-c.txt \
    --view-dump view-dump.json --restore-height "$RESTORE_HEIGHT" --ledger payouts.ledger
  shred -u counters-<w> "$H/transfer/counters-$w"
  ```
  Așteptat: `RECONCILIATION_OK weeks=<n> relays=3`; fișierul de contoare se șterge după verificare
  (pe stație și pe host).

## 11. R5: pierderea wallet-ului (doar prin `ghost-issuer --restore-wallet`)

Pașii 2–3 din §7.5 (subadresele până la `highest_minor`, apoi `rescan_blockchain`) îi face doar
issuer-ul, cu numărul luat din baza lui; nimeni nu creează subadrese și nu rescanează de mână.

- [ ] Oprire, într-o fereastră de mentenanță (secțiunea 0: rescanarea durează ore și snapshot-ul
  orar nu trebuie să o întrerupă):

  ```sh
  touch "$H/maintenance" && flock "$H/snapshot.lock" true
  $C stop issuer wallet-rpc
  ```
  Așteptat: prima comandă fără ieșire; `$C ps` nu mai arată `issuer` și `wallet-rpc`.
- [ ] Fișierele wallet-ului deteriorat se mută deoparte (`$H/wallet/issuer-view*`) și se șterg după
  restaurare.
- [ ] Pasul 1: wallet-ul view-only regenerat din adresa trezoreriei și cheia de vizualizare cu
  înălțimea de restaurare **originală** (`restore_height` din `$H/config/issuer.toml`; alta este
  refuzată la pornire, cod 6), cu aceeași comandă `monero-wallet-cli --generate-from-view-key` ca la
  instalare (secțiunea 2). Wallet-ul de producție rulează cu `--wallet-file` și fără
  `--wallet-dir` (§7.1), deci nu poate crea un wallet prin RPC-ul `generate_from_keys`;
  `--generate-from-view-key` produce același wallet (adresă și cheie de vizualizare, fără cheie de
  cheltuire).
- [ ] Pașii 2–3:

  ```sh
  $C up -d wallet-rpc
  GHOST_ISSUER_FLAGS=--restore-wallet $C up -d --force-recreate issuer
  ```
  Issuer-ul recreează subadresele (în bucăți) și rescanează (până la 6 h) **înainte** de a servi:
  în acest timp `status.json` nu se rescrie și onion-ul nu răspunde. Așteptat, la final:
  `status.json` rescris (ora fișierului se schimbă) cu `"SCANNER":"SCANNER_OK"` (nu
  `WALLET_INCOMPLETE`) și `"POOL_SIZE":"POOL_OK"`. Cod 5: reluarea sau rescanarea a eșuat.
- [ ] Imediat după: `$C up -d --force-recreate issuer` fără variabilă. Așteptat: `running`,
  `"SCANNER":"SCANNER_OK"`. Apoi închiderea ferestrei: `rm "$H/maintenance"` (așteptat ca în
  secțiunea 0).

## 12. I1: compromiterea issuer-ului (suspectată)

- [ ] Oprire imediată, cu snapshot-ul orar oprit (fereastra de mentenanță, secțiunea 0, rămâne
  deschisă până la repornirea cu noul ES):

  ```sh
  touch "$H/maintenance" && flock "$H/snapshot.lock" true
  $C stop issuer
  ```
  Așteptat: prima comandă fără ieșire (cel mult câteva secunde); `$C ps` nu mai arată `issuer`.
  Relay-urile continuă (verificare offline); tokenurile existente rămân valabile.
- [ ] Probele (snapshot, jurnal, `status.json`) se copiază pe discul criptat; nimic în clar în afara
  host-ului.
- [ ] Fereastra de expunere: cheile din memorie = săptămânile de acces până la curenta + 6 (ultima
  încărcare K3), epocile de invitație și de credit curente, epoca de credit anterioară și orice
  cheie trecută reținută pentru facturi deschise.
- [ ] Ceremonie K1 extraordinară: următorul `seq` listează în `revoked` (linii `revoke access <w>`,
  `revoke invite <e>`, `revoke credit <c>` în sursă) săptămânile de acces viitoare expuse și
  **fiecare** epocă INVITE și CREDIT a cărei cheie privată era în memorie, inclusiv cele curente.
  Cheile acceptate nu se schimbă niciodată (regula 5); chei noi doar pentru săptămânile de după
  fereastră. Așteptat: `ES_SIGNED seq=<n> …`, apoi poarta cu `ES_APPEND_ONLY previous_seq=<n − 1>`.
- [ ] Dacă host-ul însuși este compromis, și cheia onion a issuer-ului este: host nou, set de chei
  onion nou (`ghost-issuer-ops onion-keygen --hs-dir …`) și `issuer_onion` nou în același ES
  (decizia proprietarului; clienții vechi sună onion-ul vechi până la actualizare).
- [ ] Publicare urgentă: versiune a aplicației și toți operatorii de relay (O1); relay-urile aplică
  revocările de acces din configurația lor.
- [ ] Repornirea issuer-ului cu noul ES, după merge:

  ```sh
  git pull --ff-only && $C up -d --force-recreate issuer
  ```
  Așteptat: `running`, `status.json` cu `"HALTED":false`. Issuer-ul refuză imediat invitațiile și
  creditele epocilor revocate (este singurul lor verificator); până la epoca următoare semnează în
  continuare pozițiile acelor epoci cu cheia expusă, deci layout-urile și clienții rămân
  neschimbați, iar acele invitații și credite nu valorează nimic. Apoi închiderea ferestrei:
  `rm "$H/maintenance"` (așteptat ca în secțiunea 0).
- [ ] R2 pe fereastra de expunere (credite răscumpărate > credite semnate = falsuri).
- [ ] Anunț: tokenurile, invitațiile și creditele necheltuite ale epocilor revocate se pierd (E12).

## 13. Limite cunoscute

- Cât timp o fereastră de mentenanță este deschisă (M2 lung, R5, I1) nu se fac snapshot-uri B1 și
  jurnalul nu se taie; o restaurare folosește ultimul snapshot și jurnalul de după el.
- Jurnalul se taie doar după un snapshot verificat: cât timp snapshot-urile lipsesc (issuer oprit,
  mentenanță lungă) sau cel mai nou nu se verifică, segmentele rămân și retenția de 7–14 zile a
  jurnalului se depășește (siguranța restaurării are prioritate); refuzul apare în mail-ul
  cron-ului la fiecare oră.
- Numărătorile relay-urilor sunt doar ale săptămânilor închise, cele ale ultimelor 13, păstrate în
  `nullifiers.redb` (tabela `redemption_counts`, un număr pe săptămână); un store pierdut
  (`--nullifiers-reset`) le pierde, iar o săptămână fără răscumpărări nu apare (valoarea ei este 0).
- Rularea manuală `live-tor` (CI, `workflow_dispatch`) dovedește circuitele distincte ale fluxurilor
  `IssuerFlow`; un apel real la onion-ul issuer-ului de staging și o răscumpărare prin Tor rămân de
  înregistrat după prima pornire a acestei instalări.
