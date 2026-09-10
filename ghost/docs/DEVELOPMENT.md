# Dezvoltare locală

## Toolchain pinuit (spec v2.0 Appendix A)

| Componentă | Versiune | Unde este pinuită |
|---|---|---|
| Gradle | 9.7.1 (SHA-256 verificat) | `android/gradle/wrapper/gradle-wrapper.properties` |
| JDK pentru build | 17 (toolchain) | `jvmToolchain(17)` în fiecare modul |
| Android Gradle Plugin | 9.4.0 (`android.builtInKotlin=false` până la migrarea GHOST-1) | `android/gradle/libs.versions.toml` |
| Kotlin | 2.4.20 | idem |
| compileSdk / targetSdk / minSdk | 37 / 37 / 29 | idem |
| Rust | 1.98.1 | `rust-toolchain.toml` |
| protoc | 36.x | CI: pachetul distro; local: winget `Google.Protobuf` |

Orice schimbare de versiune trece prin gate-ul de allowlist și, pentru Android, prin verificarea Gradle a checksum-urilor de dependențe (`android/gradle/verification-metadata.xml`).

## Comenzi

```bash
# Android
cd ghost/android && ./gradlew build
# Rust
cd ghost && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo deny check
# Gate-uri statice + dovada că resping fixture-urile negative
bash ghost/scripts/gates/run-all.sh && bash ghost/scripts/gates/self-test.sh
# Build reproductibil (două build-uri release, hash identic)
bash ghost/scripts/gates/reproducible-build.sh /tmp/repro
```

## Probleme cunoscute pe Windows

- **Application Control (Smart App Control / WDAC)** poate bloca executabilele de test Rust generate pe alt volum decât `C:` („os error 4551”). Soluție locală: `CARGO_TARGET_DIR=%LOCALAPPDATA%\Temp\ghost-target cargo test --workspace`. CI (Linux) nu este afectat.
- Git Bash: heredoc-urile cu backslash pot fi alterate; editează fișierele Gradle cu un editor, nu prin `sed` cu escape-uri.
- `ANDROID_HOME` trebuie să indice SDK-ul (`%LOCALAPPDATA%\Android\Sdk`); alternativ, un `local.properties` (ignorat de git) cu `sdk.dir=`.

## Reguli de contribuție (DoD, spec v2.0 §14.2)

- Niciun placeholder, succes simulat sau `TODO` fără ticket (`TODO(GHOST-123)`) pe calea de producție — gate-ul `anti-placeholder.sh` refuză.
- Nicio dependență în afara `scripts/gates/dependency-allowlist.txt`; orice adăugare citează un ADR în mesajul de commit.
- Fără `Log.*`, `println`, `printStackTrace` în `src/main`; telemetria trece prin modulul dedicat, sub politica §11.1.
- Manifestele rămân cu `allowBackup=false`, `dataExtractionRules`, `networkSecurityConfig`, permisiuni doar din setul admis.
- Commit-uri semnate (FR-8.1): configurează `git config commit.gpgsign true` cu cheia proprietarului sau a mainteinerului.
