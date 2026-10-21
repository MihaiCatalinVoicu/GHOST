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

### Mediul (o dată pe distro)

```sh
# Rust 1.98.1 (pinuit de rust-toolchain.toml), profil minimal:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.98.1 --profile minimal
. "$HOME/.cargo/env"

# Android SDK (AGP 9.4.0, compileSdk 37): cmdline-tools + platform + build-tools:
mkdir -p "$HOME/Android/Sdk/cmdline-tools" && cd "$HOME/Android/Sdk/cmdline-tools"
curl -fsSL -o tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip -q tools.zip && rm tools.zip && mv cmdline-tools latest
export ANDROID_HOME="$HOME/Android/Sdk"
yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" "platform-tools" "platforms;android-37" "build-tools;37.0.0"
```

### Biblioteca nativă de host

`ghost/scripts/build-native.sh` construiește **doar Android** (cargo-ndk, ABI-urile
`aarch64/x86_64-linux-android`) — nu există mod `--host`. Pentru `.so`-urile Linux de care
rulează harness-ul pe JVM, comanda directă (fără NDK):

```sh
sudo apt-get install -y protobuf-compiler   # build.rs-ul net cere protoc
cargo build --release -p ghost-dm-host --locked      # → target/release/libghost_dm_host.so
```

Biblioteca se încarcă pe JVM prin proprietatea existentă
(`DmNative.HOST_LIBRARY_PROPERTY`, `-Dghost.dm.native=<cale>/libghost_dm_host.so`); ea poartă
suprafețele DM, entitlement și Tor ale `ghost-client-net` pentru host.

### Comenzile

```sh
./gradlew :tools:staging-harness:stagingRun --args='activate --state /srv/harness/alice'
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
- **T6**: mecanismul se schimbă față de emulator, cerința nu. Scriptul existent
  `ghost/scripts/device/t6-dynamic-run.sh` rulează pe dispozitiv (pcap pe emulator + coloana uid
  din `/proc/net/*`). Geamănul harness-ului rulează pe host-ul Linux: procesul pornește sub un
  **UID dedicat** (utilizator nou în distro), captura e `tcpdump` pe interfața de rețea, iar
  atribuirea pe UID se face din `/proc/net/tcp{,6}` și `/proc/net/udp{,6}` (coloana uid) plus
  filtrul pe UID în `nftables`/`iptables` (regulă de egress per-uid sau cgroup). Cele două brațe:
  sesiuni cu Tor lăsat să iasă vs. egress blocat pentru UID-ul harnessului — aceeași identitate,
  așteptat zero pachete non-Tor și zero interogări DNS în brațul blocat.

## Ieșire și jurnal

O linie fixă per pas (`activate: REQUESTED|FINALIZING|ACTIVE`, `dm: sent <hash8> delivered`,
`t6: tor-up <n> tor-blocked <n>`), nicio cheie, nicio adresă, niciun plaintext (T3). Exit 0 numai
când pasul și-a încheiat criteriul.

## Stare

- [x] schelet modul + CLI (3 comenzi, config staging ca date, nu cod)
- [ ] `activate` verde contra issuer-ului live
- [ ] `dm` cap-coadă între două identități
- [ ] `t6-twin` cu pcap + atribuire pe UID
