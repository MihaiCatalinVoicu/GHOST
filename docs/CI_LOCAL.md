# CI local (regulă oficială, ADR-58, 2026-10-04)

**Regula.** Tot CI-ul GHOST rulează local, pe mașina proprietarului. Nimic nu rulează prin GitHub Actions (nici hosted, nici self-hosted). Un push e copie de siguranță, nu verificare. Textul normativ: ADR-58; instrucțiunile pentru sesiuni și subagenți: `CLAUDE.md` din rădăcină.

## 1. Semnalul de îmbinare (rețeta de verificare locală, pe commit-ul exact)

| Ce | Comandă | Se consemnează |
|---|---|---|
| Rust | `cd ghost && cargo fmt --all -- --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked` (cel puțin crate-urile atinse); `cargo deny check` dacă s-au schimbat dependențe. `CARGO_TARGET_DIR=C:\Users\mihai\AppData\Local\Temp\ghost-target-<nume>`, `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`; la final se șterg `*.pdb` și directorul | numărul de teste, 0 picate |
| Biblioteca gazdă | `cd ghost && cargo build -p ghost-dm-host --release --locked --features provenance` | calea DLL-ului |
| Kotlin | `cd ghost/android && ./gradlew --no-daemon clean && ./gradlew --no-daemon --continue --no-build-cache build -Dghost.dm.native=<ghost_dm_host.dll>` | sume JUnit pe modul, **skipped=0** (testele DM/MLS sar în tăcere fără bibliotecă) |
| Rapoarte | `bash ghost/scripts/gates/dm-report-check.sh ghost/android/messaging/build/reports/dm/report.txt pr` și `…/privacy.txt privacy-pr` | OK (pr), OK (privacy-pr) |
| Porți statice | `GHOST_YAML_VIA_WSL=ghost-runner bash ghost/scripts/gates/run-all.sh` | ieșire 0, numărul de porți OK (în WSL lipsește `protoc`: `proto-check` se rulează pe Windows) |
| Self-test al porților | `.claude/scratch/selftest-wsl.sh <worktree> <log> ghost-runner` (tot `self-test.sh` în WSL, pe `git archive HEAD`, ~3 min; în Git Bash durează ore) | `ok=N fail=0` |

## 2. Unde se consemnează
Fiecare îmbinare în `main` poartă în mesaj sau în notele slice-ului (`docs/design/…` §N) comanda, hash-ul commit-ului și cifrele de mai sus. Joburile lungi își păstrează raportul într-un fișier datat (`docs/ci-local/runs/<data>-<job>-<commit>.txt`: comanda, versiunile uneltelor, sumarul, ieșirea scriptului `*-report-check.sh`); `docs/STATUS.md` cită ultimul raport.

## 3. Joburi lungi: cine le pornește
La cerere (proprietarul sau sesiunea-lead), sau după o programare locală aprobată de proprietar (Windows Task Scheduler pornind scriptul din `ghost/scripts/ci/`). Până la aprobare nu se creează nicio programare.

## 4. Migrarea fostelor workflow-uri (felia CI-L; legacy până atunci)
Echivalentul local al unui job: un script `ghost/scripts/ci/<nume>.sh` cu pașii din `run:` ai jobului (aceleași comenzi, același `*-report-check.sh`), cu fixturi și cazuri în `self-test.sh`; după migrare se șterge `.github/workflows/<nume>.yml` și referințele din porți. Până atunci workflow-urile de mai jos sunt legacy: nu se extind și nu se bazează nimeni pe ele.

| Fost workflow | Declanșatori (fost) | Program (cron, fost) | Joburi | Timp maxim | Echivalent local |
|---|---|---|---|---|---|
| `channel-state-models.yml` | push, schedule, workflow_dispatch | `29 5 * * 1` | `channel-state-models` | 90 min | `ghost/scripts/ci/channel-state-models.sh` (scris 2026-11-11; EM-3 full, overflow checks în release, ulimit 24G doar pe Linux, check `full`) |
| `ci.yml` | push, pull_request, workflow_dispatch | — | `static-gates`, `rust`, `android-native`, `android`, `sync-exit-gate`, `reproducible`, `live-tor` | 150 min | `ghost/scripts/ci/…` (de scris) |
| `dm-emulator.yml` | pull_request, schedule, workflow_dispatch | `17 2 * * *` | `emulator` | 150 min | `ghost/scripts/ci/…` (de scris) |
| `dm-fuzz.yml` | schedule, workflow_dispatch | `43 2 * * *` | `fuzz` | 150 min | `ghost/scripts/ci/dm-fuzz.sh` (exista; prima rulare locală la buget lansată 2026-11-11, lanțuită după H-11) |
| `dm-privacy-gate.yml` | schedule, workflow_dispatch | `11 4 * * *` | `worlds`, `suite` | 300 min | `ghost/scripts/ci/dm-privacy-gate.sh` (scris 2026-11-11: ambele joburi — lumea T32 per pereche de seeduri cu host provenance + judecată `privacy-gate` per raport, apoi suita cu `privacy-suite`; relansabil cu markeri) |
| `dm-state-models.yml` | push, pull_request, schedule, workflow_dispatch | `53 2 * * *` | `dm-state-models` | 60 min | `ghost/scripts/ci/dm-state-models.sh` (scris 2026-11-11; EM-1×EM-2 la limitele ridicate, `--sends/--wire/--budget` pentru variante) |
| `entitlement-exit-gate.yml` | push, schedule, workflow_dispatch | `41 3 * * *` | `entitlement-exit-gate` | 120 min | `ghost/scripts/ci/entitlement-exit-gate.sh` (scris 2026-11-11; un shard sau `--all` secvențial, cu verificarea inline a raportului din workflow) |
| `messaging-exit-gate.yml` | push, pull_request, schedule, workflow_dispatch | `43 3 * * *` | `gate` | 480 min | `ghost/scripts/ci/messaging-exit-gate.sh` (scris 2026-11-11; host fără provenance, harness crash=full seeds=64, check `gate`) |
| `mls-vendor-tests.yml` | schedule, workflow_dispatch, push | `23 4 * * 0` | `openmls`, `advisories` | 90 min | `ghost/scripts/ci/…` (de scris) |
| `monero-regtest.yml` | push, pull_request, schedule, workflow_dispatch | `23 2 * * *` | `monero-regtest` | 45 min | `ghost/scripts/ci/monero-regtest.sh` (scris 2026-11-11; linux-only — rulează în distro-ul ghost-runner WSL; digest verificat contra pin-ului la fiecare rulare) |
| `pq-bump.yml` | push, pull_request, workflow_dispatch | — | `pq-mutants` | 45 min | `ghost/scripts/ci/pq-bump.sh` (scris 2026-11-11; wrapper peste poarta existentă `pq-mutants.sh`, raport păstrat) |
| `pq-model.yml` | push, pull_request, workflow_dispatch | — | `pq-model` | 100 min | `ghost/scripts/ci/…` (de scris) |
| `signer-timing.yml` | schedule, workflow_dispatch | `41 3 * * *` | `signer-timing` | 60 min | `ghost/scripts/ci/signer-timing.sh` (scris 2026-11-11; raport păstrat local, fără deschidere de issue — rolul ei îl joacă exit code + raportul) |
| `t2-exit-gate.yml` | push, pull_request, schedule, workflow_dispatch | `17 2 * * *` | `gate`, `mutants` | 240 min | `ghost/scripts/ci/t2-exit-gate.sh` (scris 2026-11-11: ambele joburi, raport + `t2-report-check.sh` per pereche/mutanți, relansabil cu markeri) |
| `vendor-tests.yml` | schedule, push, pull_request, workflow_dispatch | `37 1 * * *` | `vodozemac`, `libcrux` | 90 min | `ghost/scripts/ci/vendor-tests.sh` + `mls-advisories.sh` (ambele există; media are `media-emulator.sh`/`media-exit-gate.sh`/`media-mutants.sh`, update-ul are `update-gate.sh`) |

## 5. Aplicare tehnică (acordul proprietarului 2026-10-05; **aplicată**)
1. Dezactivarea GitHub Actions pe depozit (`gh api -X PUT repos/MihaiCatalinVoicu/GHOST/actions/permissions -F enabled=false`); reversibilă cu `-F enabled=true`.
2. Oprirea celor 4 servicii runner din distribuția `ghost-runner` (`actions.runner.MihaiCatalinVoicu-GHOST.ghost-runner-N.service`) și scoaterea task-ului programat `GHOST ghost-runner keepalive`; distribuția WSL `ghost-runner` rămâne ca mediu Linux local pentru `self-test.sh` și `run-all.sh`.
3. Eventuala dezînregistrare a runnerelor din depozit (`docs/ci-self-hosted.md`, secțiunea de dezînregistrare).

**Aplicat 2026-10-05:** Actions dezactivat pe depozit (`enabled=false`); cele 4 servicii `actions.runner.MihaiCatalinVoicu-GHOST.ghost-runner-N.service` dezactivate și oprite în `ghost-runner`; task-ul `GHOST ghost-runner keepalive` oprit și dezactivat (nu șters); distribuția `ghost-runner` rămâne ca mediu local. Reversibil: `gh api -X PUT repos/MihaiCatalinVoicu/GHOST/actions/permissions -F enabled=true`, `systemctl enable --now <unitate>`, `Enable-ScheduledTask`.
