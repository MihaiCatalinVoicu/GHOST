# CI pe runnere self-hosted (ghost-runner)

**Decizia proprietarului (2026-09-16):** depozitul GHOST e privat, iar planul GitHub Free dă 2 000 de minute hosted pe lună; CI-ul GHOST cere ore pe fiecare push. Toate joburile din `.github/workflows/` rulează de aceea pe patru runnere self-hosted, pe laptopul proprietarului, într-o distribuție WSL2 dedicată. Acest document spune ce s-a instalat și unde, cum se operează runnerele și cum se anulează totul.

> **CI-ul e consultativ, nu blochează nimic** (review-ul Fazei 9, GATES-4): planul GitHub Free nu oferă protecția ramurilor sau rulesets pentru un depozit privat (API-ul răspunde 403), nu se deschid pull request-uri și push-urile merg direct pe `main`. Un job roșu nu oprește un merge; merge-ul se judecă după rulările commit-ului împins (`gh run list`, citite după push) și după verificarea locală completă (`run-all.sh`, `self-test.sh`, testele Gradle la scara CI). Joburile doar pe `pull_request` (varianta redusă din `dm-emulator.yml`) nu rulează deci niciodată.

> **Regulă de securitate:** runnere self-hosted **numai** pentru acest depozit și **numai cât timp e privat**. Dacă depozitul redevine public, runnerele se dezînregistrează înainte de schimbarea vizibilității (secțiunea 9).

## 1. Pe scurt

| Ce | Unde |
|---|---|
| Distribuția WSL2 `ghost-runner` (Ubuntu 24.04 LTS, systemd) | disc virtual `D:\WSL\ghost-runner\ext4.vhdx` |
| Arhiva rootfs verificată și `SHA256SUMS` + semnătura | `D:\WSL\downloads\` |
| Scripturile de instalare | `D:\WSL\setup\` (copie în distribuție: `/usr/local/share/ghost-runner/setup/`) |
| 4 runnere `ghost-runner-1` … `ghost-runner-4`, etichete `self-hosted, Linux, X64, ghost` | `/home/runner/actions-runner-N` (în distribuție) |
| Cache-uri per runner (rustup, Cargo, Gradle, Android user home) | `/home/runner/ci-cache/runner-N/{rustup-tools,rustup,cargo,gradle,android}` |
| SDK Android + NDK 30.0.16248370 | `/usr/local/lib/android/sdk` (aceeași cale ca imaginea GitHub) |
| Serviciile systemd | `actions.runner.MihaiCatalinVoicu-GHOST.ghost-runner-N.service` |
| Pornirea la logare | Task Scheduler: `GHOST ghost-runner keepalive` |
| `%USERPROFILE%\.wslconfig` | **neschimbat** (nu există; secțiunea 7) |

Totul ce ocupă spațiu (distribuția, cache-urile, SDK-ul, imaginile Docker, spațiile de lucru ale joburilor) stă în `ext4.vhdx` pe D:. Pe C: rămân doar task-ul programat și, ca pentru orice distribuție WSL2, fișierul de swap al VM-ului comun (secțiunea 8).

## 2. Ce s-a instalat

### 2.1 Distribuția

- Rootfs: `ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz` de pe `https://cloud-images.ubuntu.com/wsl/releases/24.04/current/`. Înainte de import: `sha256sum -c` contra `SHA256SUMS`, iar `SHA256SUMS.gpg` verificat cu cheia „UEC Image Automatic Signing Key” (amprenta `D2EB 4462 6FDD C30B 513D 5BB7 1A5D 6C4C 7DB8 7C81`). Import: `wsl --import ghost-runner D:\WSL\ghost-runner <rootfs> --version 2`.
- `/etc/wsl.conf`: `systemd=true`; utilizator implicit `runner`; `appendWindowsPath=false` (PATH-ul Windows nu intră în joburi); `useWindowsTimezone=false` și `/etc/localtime` = UTC (ca imaginea hosted); hostname `ghost-runner`; **interop oprit** (un job nu poate porni direct programe Windows) și **automount oprit** (fără `/mnt/c`, `/mnt/d`: joburile nu văd discurile Windows). Ambele sunt un obstacol, nu o graniță: `runner` are `sudo` fără parolă, iar ca root discul se poate monta manual (`mount -t drvfs C: …`, verificat). Efect secundar al automount oprit: `\\wsl.localhost\ghost-runner` nu mai e accesibil din Windows; fișierele se citesc și se scriu prin `wsl.exe` (secțiunea 4). Pentru o sesiune de mentenanță: `enabled=true` în secțiunea `[automount]` din `/etc/wsl.conf`, `wsl --terminate ghost-runner`, apoi înapoi.
- Utilizatorul `runner` (neprivilegiat, `sudo` fără parolă prin `/etc/sudoers.d/90-runner`, membru al grupului `docker`).
- Pachete (apt): `git git-lfs curl wget unzip zip jq xz-utils bzip2 zstd build-essential pkg-config clang libclang-dev llvm cmake libssl-dev python3 python3-pip python3-venv ca-certificates gnupg file perl sqlite3 rsync openssh-client` și utilitare (`procps psmisc iproute2 dnsutils time acl less`), plus dependențele aplicației runner (`bin/installdependencies.sh`).
- JDK 17: `openjdk-17-jdk-headless` (`JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64`); jobul `android-native` rulează `sdkmanager` fără `actions/setup-java`, deci cere un Java preinstalat, ca imaginea hosted. Celelalte joburi își instalează Temurin 17 cu `actions/setup-java` în tool cache-ul runnerului.
- Docker Engine (`docker-ce`, depozitul apt Docker, cheie verificată după amprentă): `EmbarkStudios/cargo-deny-action` e o acțiune container. **Nu activați** integrarea WSL a Docker Desktop pentru `ghost-runner` (ar pune alt `docker` în PATH și ar da joburilor acces la motorul Docker Desktop).
- GitHub CLI `gh` (depozitul apt GitHub, cheie verificată după amprentă): pasul de eșec din `signer-timing.yml` deschide un issue cu `gh`.
- Limite: `DefaultLimitNOFILE=65536:524288` (`/etc/systemd/system.conf.d/ghost-ci.conf`), ca `ulimit -n` al imaginii hosted.
- Curățenie: `/etc/tmpfiles.d/ghost-ci.conf` șterge din `/dev/shm` ce nu a mai fost atins de 12 ore (bazele lumilor T2 și ale harness-urilor sync/entitlement rămase de la un job oprit forțat; cel mai lung timeout de job e 480 de minute, la `messaging-exit-gate`, iar trei rulări ale lui au atins limita pe 2026-09-24 — review-ul Fazei 9, GATES-6 — deci 12 ore rămân peste orice job) și din `/tmp` după 3 zile; timer-ul `systemd-tmpfiles-clean` rulează la 15 minute după pornirea distribuției și apoi orar (`/etc/systemd/system/systemd-tmpfiles-clean.timer.d/hourly.conf`).

### 2.2 SDK Android

`/usr/local/lib/android/sdk`, proprietar `runner`: `cmdline-tools/latest` (arhiva `commandlinetools-linux-15859902_latest.zip`, SHA-256 verificat contra paginii developer.android.com/studio), `cmdline-tools/16.0` (versiunea pe care o caută `android-actions/setup-android@v3`, deci acțiunea nu mai descarcă nimic), `platform-tools`, `platforms;android-37.0`, `platforms;android-37.2`, `build-tools;37.0.0`, `build-tools;36.0.0`, `ndk;30.0.16248370`. Licențele sunt acceptate. `sdkmanager` verifică fiecare pachet cu suma din manifestul Google.

### 2.3 Runnere

- Aplicația: `actions/runner` v2.337.0, `actions-runner-linux-x64-2.337.0.tar.gz`, SHA-256 `70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613` (din notele de release, egal cu digest-ul asset-ului). Se actualizează singură (secțiunea 5).
- Patru copii: `/home/runner/actions-runner-{1,2,3,4}`, nume `ghost-runner-{1,2,3,4}`, grup `Default`, spațiu de lucru `_work`.
- `.env` al fiecărui runner: `LANG=C.UTF-8`, `JAVA_HOME`, `JAVA_HOME_17_X64`, `ANDROID_HOME`, `ANDROID_SDK_ROOT` și, **per runner**, `CARGO_HOME`, `RUSTUP_HOME`, `GRADLE_USER_HOME`, `ANDROID_USER_HOME` sub `/home/runner/ci-cache/runner-N`. Motiv: patru joburi rulează simultan, iar `Swatinem/rust-cache` curăță registrul Cargo, `gradle/actions/setup-gradle` restaurează și curăță Gradle User Home; un director comun ar fi modificat sub un alt job.
- `.path`: `/home/runner/ci-cache/runner-N/rustup-tools/bin` (rustup și proxy-urile `cargo`, `rustc`, …) și `/home/runner/ci-cache/runner-N/cargo/bin` (uneltele instalate de joburi: `cargo-ndk`, `cargo-audit`) înaintea PATH-ului de sistem. Toolchain-ul fixat `1.98.1` (profil minimal, `rustfmt`, `clippy`, țintele `aarch64-linux-android` și `x86_64-linux-android`) e preinstalat în `RUSTUP_HOME`, cu `rustup-init` verificat SHA-256; `dtolnay/rust-toolchain` găsește rustup și nu mai descarcă nimic. rustup stă **în afara** `CARGO_HOME`: `Swatinem/rust-cache` șterge la finalul fiecărui job fișierele care erau în `$CARGO_HOME/bin` la începutul lui (corect pe o VM hosted efemeră; pe un runner persistent ștergea rustup și lăsa proxy-urile fără țintă, prima rulare a eșuat așa).
- Token-urile de înregistrare nu au fost afișate și nu au ajuns în fișiere sau loguri: fiecare vine din `gh api -X POST .../registration-token` direct pe stdin-ul scriptului de înregistrare, care îl dă lui `config.sh` prin mediu (`ACTIONS_RUNNER_INPUT_TOKEN`).

## 3. Pornire și oprire

**Automat.** WSL oprește o distribuție la câteva secunde după ce ultimul proces `wsl.exe` atașat se termină, chiar dacă systemd are servicii active. Task-ul programat `GHOST ghost-runner keepalive` (utilizatorul `mihai`, doar când e logat, fără drepturi de administrator) rulează `conhost.exe --headless wsl.exe -d ghost-runner -u root --exec /usr/local/sbin/ghost-runner-keepalive`: scriptul pornește toate serviciile `actions.runner.*` și rămâne în prim-plan (`sleep infinity`), ceea ce ține distribuția pornită. Declanșatoare: la logare și la fiecare 5 minute; `MultipleInstances=IgnoreNew`, deci o instanță care rulează nu e dublată, iar una oprită (de un `wsl --shutdown` sau o repornire Docker Desktop) repornește în cel mult 5 minute. Fără limită de durată; rulează și pe baterie.

**Manual (PowerShell):**

```powershell
# pornire (echivalent cu task-ul)
Start-ScheduledTask -TaskName 'GHOST ghost-runner keepalive'
# starea
wsl -l -v
wsl -d ghost-runner -- systemctl --no-pager status 'actions.runner.*'
gh api repos/MihaiCatalinVoicu/GHOST/actions/runners --jq '.runners[] | [.name, .status, .busy] | @tsv'
# oprirea unui runner (joburile noi merg la celelalte)
wsl -d ghost-runner -u root -- systemctl stop actions.runner.MihaiCatalinVoicu-GHOST.ghost-runner-4.service
# oprirea tuturor: întâi task-ul (altfel le repornește în 5 minute), apoi distribuția
Disable-ScheduledTask -TaskName 'GHOST ghost-runner keepalive'
wsl --terminate ghost-runner
# repornire după oprirea tuturor
Enable-ScheduledTask -TaskName 'GHOST ghost-runner keepalive'; Start-ScheduledTask -TaskName 'GHOST ghost-runner keepalive'
```

Oprirea unui serviciu, `wsl --terminate ghost-runner` sau `wsl --shutdown` întrerup jobul în curs, care eșuează. Pentru o oprire fără pierderi, așteptați ca runnerul să fie liber (`busy` = `false` în comanda de stare de mai sus); un `wsl --shutdown` oprește și Docker Desktop.

**Laptopul:** runnerele lucrează doar cât utilizatorul e logat și sistemul e treaz. Sleep-ul sau hibernarea în timpul unui job îl pierd; pentru rulări lungi (T2 gate, cele 12 shard-uri entitlement), setați „Sleep: Never” când e în priză. Închiderea capacului, delogarea sau repornirea Windows opresc runnerele până la următoarea logare.

## 4. Adăugarea și eliminarea unui runner

Scripturile sunt idempotente; în distribuție, copia lor e în `/usr/local/share/ghost-runner/setup/` (automount e oprit, deci `D:\WSL\setup` nu se vede din Linux). După o modificare în `D:\WSL\setup`, copia se actualizează prin stdin:

```powershell
Get-Content -Raw D:\WSL\setup\03-runners.sh | wsl.exe -d ghost-runner -u root --exec sh -c 'cat > /usr/local/share/ghost-runner/setup/03-runners.sh'
```

**Adăugare (exemplu: al cincilea):**

```powershell
# aplicația și cache-urile pentru runnerele 1..5 (cele existente rămân neatinse)
wsl -d ghost-runner -u runner -- env COUNT=5 bash /usr/local/share/ghost-runner/setup/03-runners.sh
# înregistrarea și serviciul; token-ul trece doar prin pipe
gh api -X POST repos/MihaiCatalinVoicu/GHOST/actions/runners/registration-token --jq .token | wsl.exe -d ghost-runner -u runner --exec bash /usr/local/share/ghost-runner/setup/04-register.sh 5
```

Fiecare runner în plus mai ia CPU și RAM din aceeași mașină (secțiunea 8); patru e un compromis pentru 24 de nuclee și VM-ul WSL de ~47 GB.

**Eliminare (exemplu: al patrulea):**

```powershell
# oprește și șterge serviciul, dezînregistrează runnerul; DELETE_FILES=1 șterge și directorul și cache-urile
gh api -X POST repos/MihaiCatalinVoicu/GHOST/actions/runners/remove-token --jq .token | wsl.exe -d ghost-runner -u runner --exec env DELETE_FILES=1 bash /usr/local/share/ghost-runner/setup/98-unregister.sh 4
```

Dacă distribuția nu mai există, runnerul rămas „offline” se șterge din GitHub: `gh api -X DELETE repos/MihaiCatalinVoicu/GHOST/actions/runners/<id>` (id-ul din `gh api repos/MihaiCatalinVoicu/GHOST/actions/runners`). GitHub șterge oricum singur runnerele self-hosted offline de peste 14 zile.

## 5. Actualizarea aplicației runner

Runnerele se actualizează singure când GitHub publică o versiune nouă (descarcă, se opresc între joburi, repornesc; serviciul systemd rămâne același). GitHub nu mai trimite joburi unui runner mai vechi de 30 de zile față de ultima versiune, deci nu dezactivați actualizarea automată.

Actualizare manuală (de exemplu dacă cea automată eșuează): luați versiunea și suma din notele de release (`gh api repos/actions/runner/releases/latest`, linia `<!-- BEGIN SHA linux-x64 -->`), apoi pentru fiecare N: opriți serviciul, dezarhivați noua arhivă peste `/home/runner/actions-runner-N` (fișierele `.runner`, `.credentials*`, `.env`, `.path` și `_work` rămân), porniți serviciul:

```powershell
wsl -d ghost-runner -u runner -- env RUNNER_VERSION=<versiune> RUNNER_SHA=<sha256> bash -c 'set -e; f=actions-runner-linux-x64-$RUNNER_VERSION.tar.gz; cd ~/downloads; curl -fsSLO https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/$f; echo "$RUNNER_SHA  $f" | sha256sum -c -; for n in 1 2 3 4; do u=actions.runner.MihaiCatalinVoicu-GHOST.ghost-runner-$n.service; sudo systemctl stop $u; tar -xzf $f -C ~/actions-runner-$n; sudo systemctl start $u; done'
```

Restul sistemului: `sudo apt-get update && sudo apt-get upgrade` în distribuție (actualizările de securitate se instalează oricum zilnic prin `unattended-upgrades`). Imaginile Docker construite de `cargo-deny-action` (~1,2 GB fiecare, una per runner) se adună în timp: `wsl -d ghost-runner -- docker image prune -af` din când în când, cu runnerele libere (se reconstruiesc la următorul job `rust`). Toolchain-ul Rust, pachetele SDK și NDK sunt fixate de workflow-uri; o schimbare a lor în workflow se preinstalează cu `03-runners.sh` (Rust; editați `RUST_TOOLCHAIN`) sau `02-android.sh` (SDK; editați `PACKAGES`), altfel acțiunile de setup le instalează la primul job (mai lent, dar funcționează).

### 5.1 O instalare „înțepenită” în `CARGO_HOME`

`CARGO_HOME` e per runner și persistent (`/home/runner/ci-cache/runner-N/cargo`, secțiunea 2.3), spre deosebire de un runner hosted efemer. Un `cargo install <unealtă> --locked` obișnuit copiază fiecare binar în `$CARGO_HOME/bin` doar dacă nu găsește deja un fișier cu acel nume acolo; dacă o rulare e anulată chiar în timpul copierii, binarele rămân în `bin/` fără ca propria evidență a lui cargo (`.crates.toml`/`.crates2.json`) să fi fost actualizată. Rularea următoare programată pe același runner vede fișierele, nu evidența, și refuză:

```
error: binary `cargo-ndk` already exists in destination
binary `cargo-ndk-env` already exists in destination
Add --force to overwrite
```

(observat pe `ghost-runner-4`, rularea CI 35492470508, după ce rularea 35492418192 a fost anulată în timpul acestui pas pe același runner).

Singurul loc din workflow-uri care face un `cargo install` brut într-un `CARGO_HOME` persistent e pasul „install pinned protoc and cargo-ndk” al jobului `android-native`; de la reparația din 2026-09-20 sare peste instalare când unealta răspunde deja cu versiunea fixată, altfel instalează cu `--force` (curăță atât un binar „înțepenit”, cât și o versiune veche). **Corecție 2026-09-21:** prima variantă a acestei reparații verifica doar evidența (`cargo install --list`), nu dacă binarul chiar rulează — pe `ghost-runner-2` evidența spunea „instalat” cât timp `cargo ndk --version` (verificarea reală, din `scripts/build-native.sh`) nu găsea nimic, deci pasul sărea la nesfârșit peste o reinstalare de care era nevoie, iar `build-native.sh` eșua imediat după. Pasul rulează acum exact verificarea din `build-native.sh` (`cargo ndk --version`), ca să nu mai poată diverge de ea. Pasul echivalent din jobul `rust` (`taiki-e/install-action` pentru `cargo-audit`/`cargo-deny`) nu are aceeași problemă: descarcă binarul precompilat și îl mută (`mv`) peste orice există deja la destinație, fără verificare de coliziune — nu trece prin evidența `cargo install`. (Bazat pe sursa acțiunii, nu pe o garanție documentată a ei; dacă vreodată apare aceeași eroare la un pas `install-action`, aplicați aceeași reparație acolo.)

Deblocare manuală a unui runner deja înțepenit (fără să așteptați reparația din workflow, sau pentru orice altă unealtă instalată la fel): ștergeți binarele din `$CARGO_HOME/bin` pe runnerul afectat și lăsați job-ul următor să reinstaleze, sau reinstalați direct cu `--force`:

```powershell
wsl -d ghost-runner -u runner -- bash -c 'rm -f /home/runner/ci-cache/runner-4/cargo/bin/cargo-ndk*'
# sau, cu toolchain-ul Rust deja pe PATH-ul acelui runner:
wsl -d ghost-runner -u runner -- env CARGO_HOME=/home/runner/ci-cache/runner-4/cargo bash -c 'cargo install cargo-ndk --version 4.1.2 --locked --force'
```

## 6. Ce s-a schimbat în workflow-uri

- Toate joburile din `ci.yml`, `entitlement-exit-gate.yml`, `t2-exit-gate.yml`, `monero-regtest.yml`, `signer-timing.yml`: `runs-on: [self-hosted, linux, x64, ghost]`; pașii au rămas aceiași.
- Încărcări: eliminată `app-release-unsigned` (APK-ul release nesemnat din jobul `android`; niciun job nu îl consumă). Dovezile porților (`entitlement-exit-gate-N`, `t2-exit-gate-N`, `t2-mutants`, `t2-views-N` la cerere, `sync-exit-gate-reports` la eșec, rapoartele DM) rămân încărcări cu `retention-days: 3`, **toate cu `continue-on-error: true` din 2026-09-26** (designul Fazei 9 §22.33 punctul 2): cota de stocare a artefactelor, atinsă din 2026-09-20, făcea roșu orice job după ce testele lui treceau; un raport e dovadă, nu poartă, iar copia lui e în rezumatul jobului, unde un test JVM picat își scrie și mesajul și începutul stack trace-ului (`ghost/scripts/ci/junit-failures.sh`). **Predarea bibliotecilor native** (`android-native` → `android`, `reproducible`) nu mai e un artefact (era `ghost-client-net-jniLibs`, cu `retention-days: 1` din 2026-09-16, §22.8.9 punctul 3): trece prin cache-ul Actions al rulării (`actions/cache/save` și `actions/cache/restore`, la commit-ul pe care îl fixa deja `monero-regtest.yml`; cheia `ghost-client-net-jniLibs-<run_id>-<attempt>`), care nu intră în cota artefactelor. `android-native` publică sumele SHA-256 ca output al jobului, iar fiecare consumator restaurează intrarea (`fail-on-cache-miss`) și verifică fișierele față de acele sume înainte să le folosească. Poarta G-L5 (`ghost/scripts/gates/no-public-binaries.sh`) impune regulile: fiecare încărcare are `retention-days` între 1 și 7; singurul artefact binar permis rămâne predarea internă cu o zi (niciun workflow nu o mai folosește); un cache cu binare e permis doar cât depozitul e declarat privat (`ghost/scripts/gates/repository-visibility.txt`, comparat în CI cu evenimentul GitHub), doar sub o cheie de predare care poartă `github.run_id` și doar dacă un job al aceluiași workflow o restaurează; niciun workflow nu publică nimic. **Reluarea unui consumator singur** („Re-run failed jobs”): restaurarea găsește intrarea rulării prin prefixul `restore-keys` cât timp cache-ul o păstrează (GitHub șterge intrările neaccesate timp de 7 zile și, peste plafonul de 10 GB al depozitului, pe cele mai vechi); dacă a dispărut, jobul pică la restaurare și se folosește „Re-run all jobs”, care o reconstruiește.
- `live-tor`: `TMPDIR` = directorul temporar al jobului, ca starea Arti să nu rămână între rulări în `/tmp/ghost-live-tor-test`.
- `monero-regtest`: `MONERO_RANDOMX_FULL_MEM=1` pe pasul scenariului. monerod calculează RandomX pentru fiecare bloc generat; în modul light (implicit) runnerul WSL2 face ~10 blocuri/s (măsurat: 300 de blocuri în 28,8 s; un runner hosted ~3× mai repede, probabil prin paginarea memoriei VM-ului), scenariul minează peste 22 000 de blocuri și jobul a depășit timeout-ul de 45 de minute. Cu dataset-ul de 2 GB: ~85 blocuri/s. Schimbă doar viteza proof-of-work, nimic din ce observă rail-ul issuer-ului.
- `entitlement-exit-gate.yml`: cu patru runnere, cele 12 shard-uri rulează câte patru, restul așteaptă în coadă (timpul din coadă nu intră în `timeout-minutes`); comentariul de buget descrie clasa de runner.

Validare pe ramura `ci/self-hosted` (commit `a072e35`, workflow-uri identice cu cele din acest commit), toate joburile verzi, fiecare pe un runner `ghost-runner-N`: `ci` 35113371144 (cu `live-tor`), `monero-regtest` 35113375077, `t2-exit-gate` 35113378927, `entitlement-exit-gate` 35113382897, `signer-timing` 35126444765.

Presupunerea „mașină curată”: `actions/checkout` curăță spațiul de lucru (`git clean -ffdx`, deci și `target/`, `build/`, `.gradle/`), runnerul golește `$RUNNER_TEMP` la fiecare job și termină procesele rămase, bazele din `/dev/shm` au nume unice per lume și cele rămase se șterg după 12 ore, iar cache-urile care persistă (Cargo, Gradle, toolchain-uri) sunt per runner.

## 7. `.wslconfig` (neschimbat)

Nu s-a creat `%USERPROFILE%\.wslconfig`. Toate distribuțiile WSL2, inclusiv `docker-desktop`, rulează în **aceeași** mașină virtuală, iar orice cheie din secțiunea `[wsl2]` (`memory`, `processors`, `swap`, `vmIdleTimeout`) se aplică acelei VM, deci și Docker Desktop, și intră în vigoare abia după `wsl --shutdown` (care oprește și Docker Desktop). `vmIdleTimeout` ar conta doar când nu mai rulează nicio distribuție; procesul keepalive ține `ghost-runner` pornită, deci nu e nevoie de el. Limita implicită de memorie a VM-ului e 50 % din RAM (~47 GB), comună cu Docker Desktop. Dacă joburile rămân fără memorie când Docker Desktop are containere mari, se poate ridica plafonul:

```ini
[wsl2]
memory=64GB
```

urmat de `wsl --shutdown`. Efect asupra Docker Desktop: are și el plafonul mai mare (e o limită, nu o rezervare). Anulare: ștergeți linia (sau fișierul) și `wsl --shutdown`.

## 8. Impactul asupra host-ului

- **CPU:** cele 4 joburi simultane împart cele 24 de nuclee (8 P + 16 E) ale Core Ultra 9 275HX; fiecare job vede toate 24 și își dimensionează paralelismul după ele (cargo, harness-urile JVM, lumile T2). Load average-ul VM-ului a urcat la ~73 în prima rulare completă. La încărcare completă ventilatoarele merg la maxim și laptopul e lent pentru alt lucru.
- **RAM:** VM-ul WSL2 crește până la plafonul de ~47 GB, comun cu Docker Desktop; `/dev/shm` (bazele lumilor) e tmpfs de 24 GB din aceeași memorie. Măsurat în prima rulare completă: vârf ~31 GB folosiți, minim ~16 GB disponibili, `/dev/shm` sub 2,2 GB. Memoria eliberată revine încet la Windows.
- **Disc:** `D:\WSL\ghost-runner\ext4.vhdx` crește dinamic: 0,9 GB la import, 40,6 GB după instalare și prima rulare completă (25 GB ocupați în distribuție: runnere cu spațiile de lucru 1,2–2 GB fiecare, cache-urile per runner 9,8 GB în total, SDK+NDK 3,2 GB, imaginile Docker 1,2 GB). Un VHDX nu se micșorează singur: `wsl --manage ghost-runner --set-sparse true` sau `Optimize-VHD` cu distribuția oprită. Swap-ul VM-ului (implicit 25 % din memoria VM) e fișierul `swap.vhdx` din `%TEMP%` pe C:, ca pentru orice distribuție WSL2.
- **Durate** (prima rulare completă, 2026-09-16, commit `a072e35`, toate cele cinci workflow-uri pornite deodată pe 4 runnere): `ci` 1 h 55 min de la pornire la final (`rust` 52 min, `android` 56 min cu cache-ul Gradle gol, `sync-exit-gate` 17 min, `android-native` 10 min, `reproducible` 6 min, `live-tor` 4 min, `static-gates` 2 min); `entitlement-exit-gate` 1 h 52 min (shard-uri de 10–23 min); `t2-exit-gate` 2 h 49 min (gate 123 min, mutanți 52 min); `monero-regtest` 26 min (scenariul 19,5 min); `signer-timing` 9 min. Toate sub `timeout-minutes` (cel mai strâns: `monero-regtest`, 26 din 45 de minute sub încărcare maximă).
- **Rețea:** descărcări de toolchain, dependențe Cargo/Gradle, cache-uri GitHub Actions și imagini Docker; conexiuni doar de ieșire (runnerul face long-poll la GitHub; nu se deschide niciun port).

## 9. Anulare completă

În PowerShell, ca utilizatorul `mihai` (fără drepturi de administrator):

```powershell
# 1. Dezînregistrarea celor patru runnere din GitHub și ștergerea serviciilor
foreach ($n in 1..4) {
  gh api -X POST repos/MihaiCatalinVoicu/GHOST/actions/runners/remove-token --jq .token | wsl.exe -d ghost-runner -u runner --exec bash /usr/local/share/ghost-runner/setup/98-unregister.sh $n
}
gh api repos/MihaiCatalinVoicu/GHOST/actions/runners --jq '.total_count'   # 0
# 2. Task-ul programat
Unregister-ScheduledTask -TaskName 'GHOST ghost-runner keepalive' -Confirm:$false
# 3. Distribuția (șterge ext4.vhdx cu tot ce e în ea)
wsl --unregister ghost-runner
Remove-Item -Recurse -Force D:\WSL\ghost-runner, D:\WSL\downloads, D:\WSL\setup
# 4. .wslconfig: nu a fost creat; dacă l-ați adăugat ulterior (secțiunea 7), ștergeți cheia și rulați wsl --shutdown
```

Apoi, în depozit, `runs-on` înapoi la `ubuntu-24.04` în toate workflow-urile (commit-ul „CI: self-hosted runners …” se poate reverti). Fără pasul 1, runnerele apar „offline” în GitHub și se șterg cu `gh api -X DELETE repos/MihaiCatalinVoicu/GHOST/actions/runners/<id>`.

## 10. Securitate

- Un runner self-hosted execută codul oricărui workflow care ajunge la el, cu acces la mașina proprietarului. **Pe un depozit public, orice pull request dintr-un fork ar putea rula cod pe laptop.** De aceea: runnere doar la nivelul acestui depozit (nu la nivel de cont sau organizație), doar cât timp e privat; înainte de a-l face public, rulați secțiunea 9 (cel puțin pasul 1) și readuceți `runs-on` la runnere hosted.
- Izolare: joburile rulează ca `runner` într-o distribuție separată, fără interop Windows și fără discurile Windows montate; `runner` are totuși `sudo` fără parolă și acces la Docker, deci un job are control total **în** distribuție și acces la rețea. Nu puneți în distribuție secrete care nu țin de CI (chei SSH, token-uri personale).
- Joburile nu primesc material de semnare (TB-6); semnarea release-urilor rămâne offline (FR-8.2). Acțiunile rămân fixate pe SHA complet (FR-8.1).
- Token-ul `GITHUB_TOKEN` al unui job expiră la finalul jobului; credențialele runnerului (`.credentials`, `.credentials_rsaparams` din `actions-runner-N`) permit doar preluarea de joburi pentru acest depozit și se revocă prin dezînregistrare.
- Oricine poate împinge o ramură sau deschide un pull request în depozit poate rula cod pe runnere (`ci.yml` rulează la `pull_request`, iar un workflow se poate modifica pe ramura proprie). Dacă adăugați colaboratori sau permiteți fork-uri private cu workflow-uri, tratați-i ca având acces la laptop.
