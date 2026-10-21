# staging-harness — client real contra staging-ului GHOST (artefact de test)

Un CLI JVM care rulează motoarele reale (`:entitlement`, `:sync`, `:messaging`) contra
staging-ului live (issuer + 3 relay-uri pe onion-uri reale, pornite din `infra/issuer` +
`infra/relay` pe ghost-runner). Este driverul pentru:

1. **trial activation reală** prin onion-ul issuer-ului (prima: 2026-10-2x);
2. **sesiuni DM cap-coadă** între două identități harness peste relay-urile de staging
   (mesaje, timere, key change — coloana J3 a călătoriilor);
3. **geamănul T6 „Tor inaccesibil"** (Appendix B.2): aceleași sesiuni cu Tor disponibil vs.
   blocat, cu captură pcap + atribuire pe UID — așteptat: zero pachete non-Tor, zero DNS.

Nu este livrat: modul de test, nicio dependență de producție inversă, porțile CI nu-l ating.

## Rulare (ghost-runner, WSL)

```sh
# nativul Linux (dm + net) se construiește o dată:
./scripts/build-native.sh --host   # sau: cargo build --release -p ghost-dm-host … (vezi RUNBOOK-uri)

./gradlew :tools:staging-harness:stagingRun --args='activate --issuer yc5kgo3q….onion:443 --state /srv/harness/alice'
./gradlew :tools:staging-harness:stagingRun --args='dm --with /srv/harness/bob --state /srv/harness/alice'
./gradlew :tools:staging-harness:stagingRun --args='t6-twin --state /srv/harness/alice --out /srv/harness/t6'
```

Starea fiecărei identități (seed, DB, credențiale) trăiește în `--state`; două directoare = două
identități. Comenzile sunt idempotente cât permite protocolul (re-activate = ACTIVATE idempotent
per identitate, §21.12).

## Configurația de staging (fixată aici, nu în cod)

| Rol | Onion | Sursa adevărului |
|---|---|---|
| issuer | `yc5kgo3q6eyexdscqt7lhwlhxqni4a6b3p2yzcfalmmaxbgbggvya3ad.onion:443` | `ghost-issuer-ops schedule-onions` vs `$H/tor/ghost-issuer/hostname` |
| relay-a (slot 0) | `dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443` | `protocol/entitlement/relay-directory.txt` |
| relay-b (slot 1) | `zlaedoy2kjoq6kybq4lidy2mvsvnnfbgfn4cgzowwqtpmg624xpni3ad.onion:443` | idem |
| relay-c (slot 2) | `dlwabzl7bh6x3xotfnujdi7poevpkvu7u5yz22bkhm32a6gs4mufolyd.onion:443` | idem |

ES: `protocol/entitlement/schedule.ghes` (același pe care îl servesc relay-urile).
Staging = „local/test infrastructure, no privacy claim" (spec §3.1): cheile onion sunt cele S2b,
releele au gossip pornit, nu e infrastructură de producție.

## Ce reutilizează (harta reutilizării)

- **Lumi**: fabricile de lumi din testele `:messaging` (`OwnerWorld` și lumile DM/canale) se
  construiesc peste o bază reală migrată; harness-ul le apelează cu `RelayEntry(Source.CONFIG)`
  pe cele trei onion-uri reale în locul onion-urilor de fixture.
- **Transport**: la fel ca aplicația — `:sync` peste JNI `ghost-client-net` (Tor integrat,
  circuite izolate per namespace); pe host se încarcă `.so`-ul Linux, nu dll-ul Windows.
- **Activare**: fluxul de trial al `:entitlement` (cerere la issuer prin onion, confirmare,
  finalizare K20) — aceeași cale ca onboarding-ul aplicației, fără UI.
- **T6**: captura și atribuirea pe UID urmează scriptul `scripts/device/t6-dynamic-run.sh`
  (pcap pe dispozitiv + coloana uid din `/proc/net/*` ca root); geamănul rulează sesiunile o dată
  cu Tor lăsat să iasă și o dată cu egress-ul Tor blocat pe emulator (firewall pe UID / rețea
  oprită pentru procesul de transport), aceeași identitate.

## Ieșire și jurnal

O linie fixă per pas (`activate: REQUESTED|FINALIZING|ACTIVE`, `dm: sent <hash8> delivered`,
`t6: tor-up <n> tor-blocked <n>`), nicio cheie, nicio adresă, niciun plaintext (T3). Exit 0 numai
când pasul și-a încheiat criteriul.

## Stare

- [x] schelet modul + CLI (3 comenzi, config staging ca date, nu cod)
- [ ] `activate` verde contra issuer-ului live
- [ ] `dm` cap-coadă între două identități
- [ ] `t6-twin` cu pcap + atribuire pe UID
