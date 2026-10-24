# Faza 14 — evidența S0a

Rezultatele verificărilor din slice-ul S0a (`faza14-distribution.md` §13, Appendix C): fiecare
linie numește verificarea, metoda, rezultatul brut și efectul asupra planului (replanare înainte
de S1 la orice eșec, §13 rândul S0a). Verificările care au nevoie de acțiuni ale proprietarului
(OA-5 minutes, token-uri YubiKey, domeniu) rămân deschise până la acele acțiuni; aici se consemnează
doar cele rulate.

## V-D11a — politica Sigsum `sigsum-generic-2025-1`, bytes exacte (NU necesită domeniu)

- **Sursă:** fișierul built-in al tooling-ului de referință, `sigsum-go` `pkg/policy/builtin/sigsum-generic-2025-1.builtin-policy`, `https://git.glasklar.is/sigsum/core/sigsum-go/-/raw/main/pkg/policy/builtin/sigsum-generic-2025-1.builtin-policy` (descărcat 2026-10-24; calea veche sigsum.org/transparency-policy/… întoarce 404 — mențiunea din design la sigsum.org e învechită, fără efect asupra deciziei D9).
- **Rezultat:** transcris byte-cu-byte în `ghost/protocol/test-vectors/sigsum-generic-2025-1.policy` (22 de linii).
- **SHA-256** (al fișierului transcris, LF): `666d9d0b9ab2e4019769c42eaccd7d6d502a9abac45979bb9b08b7213e4f53e3`.
- **Conținut:** 2 loguri — `seasalp.glasklar.is` (`0ec7e16843119b120377a73913ac6acbc2d03d82432e2c36b841b09a95841f25`), `ginkgo.tlog.mullvad.net` (`f00c159663d09bbda6131ee1816863b6adcacfe80b0b288000b11aba8fe38314`); 3 witnesses — `witness.glasklar.is` (`b2106d…8536`), `witness.mullvad.net` (`15d6d0…61ad`), `tillitis.se/tillitis-witness-1` (`076be8…770c`); quorum `2 of 3` peste cei trei witnesses (`group quorum-rule 2 …`, `quorum quorum-rule`).
- **Efect asupra planului:** `GHRT.logs` / `GHRT.witnesses` / `quorum` din D9 se codifică din aceste bytes exacte; quorum-ul flat k-of-m din root trebuie să fie **cel puțin la fel de strict** — politica fiind deja 2-of-3 peste 3 witnesses, rootul GHOST ia exact această regulă (k=2, m=3) cu aceleași chei. Observația din design despre părintele comun al celor doi operatori de witness (glasklarteknik.se) rămâne valabilă și e înregistrată în LIMITE.

## §6.5 core/padding — proba apksigner cu cheie software (extensie a Appendix C.3, 2026-10-24)

Mediu: `apksigner.jar` din build-tools **37.0.0**, JVM JetBrains 17.0.20.1, cheie throwaway RSA-2048 generată pe loc, intrare = APK minimal real (manifest compilat cu `aapt2 link` pe platforma android-37.2, 683 B). Măsurători:

- **Determinismul apksigner:** aceeași intrare semnată de două ori → ieșiri **byte-identice** (SHA-256 `dbbccce1…e183` ambele). Semnătura v2/v3 nu include timestamp implicit.
- **Verify:** `apksigner verify --print-certs` verde pe ambele variante; afișează DN și digests SHA-256/SHA-1/MD5 ale certificatului.
- **Structura blocului de semnătură** (parse manual, magic `APK Sig Block 42`): la ambele variantele blocul ocupă `[4080, 8192)` — **capătul blocului fixat pe graniță 4096** indiferent de padding-ul din intrare; perechi: `0x00000ff8` (stripping protection, gol) + `0x00000566` (APK Signature Scheme v3); **perechea de padding explicită (`0x42726577`) absentă** — padding-ul este implicit, prin dimensionarea blocului.
- **Relația de core:** apksigner **rescrie arhiva** la semnare (re-aliniază intrările — regiunea pre-bloc a semnatului nu e byte-egală cu intrarea nesemnată; nici cd+EOCD). Regiunea pre-bloc crește de la 683 B (nesemnat) la 4080 B (semnat) tocmai pentru a fixa blocul pe aliniere; un padding de +64 B în intrare (`+60 B` pe cd) **nu mută blocul** — capătul rămâne la 8192. Regula „apksigner paddează înaintea blocului de semnătură" se confirmă la nivel de aliniere: poziția blocului e o funcție de aliniere, nu de conținutul nucleului.
- **Efect asupra planului:** relația exactă core(p) pentru două build-uri reale (A/B) se verifică în matricea recipe-ului (V-D1…V-D5) — proba sintetică confirmă determinismul, alinierea fixă a blocului și absența perechii explicite de padding; nu înlocuiește matricea A/B.
- **V-D23 (pin-uri, constatări):** aapt2 = **2.20-15087165** (build-tools 37.0.0) — versiunea exactă de notat în pin-ul unificat; AGP = **9.4.0** (`gradle/libs.versions.toml`); aapt2 jars sunt deja în `verification-metadata.xml` (de verificat că pin-ul acoperă și versiunea 2.20-15087165 efectiv descărcată).

## V-D12 + V-D22 — ambii listeneri ai oglinzii (2026-10-24)

- **Ce s-a făcut:** imaginea `ghost/infra/mirror/` a crescut al doilea listener: nginx `http2 on;` pe `127.0.0.1:8081` (h2c prior-knowledge), expus de Tor ca portul **443** al aceluiași onion; portul 80 rămâne HTTP/1.1 pentru browsere și `ghost-verify` (D14). Cheile onion persistă — hostnames neschimbate.
- **Rezultat măsurat peste Tor** (curl prin SOCKS5, ambele oglinzi): `:80` → HTTP/1.1 200 cu manifestul JSON; `:443` cu `--http2-prior-knowledge` → **HTTP/2 200, 409 B** pe mirror-a și mirror-b. Amândoi listeneri funcționali pe același onion, decizia D14 de a păstra nginx e confirmată de V-D22 (un `ghost-mirror` propriu nu mai e justificat de această verificare; rămâne opțiunea din D14 dacă S0 mai găsește altceva).
- **Efect asupra planului:** nimic de replanat; listenerul h2c din rândul V-D12 e bifat. Poarta G-D10 (configuration gate + container test) rămâne de construit în S1+.

## V-D15 — parse v2 / v3 / v3.1 per SDK cu apksigner (2026-10-24)

- **Matrice rulată** (build-tools 37.0.0, cheie throwaway, aceeași intrare, trei variante de schemă: v2-only, v3-only, v2+v3): `apksigner verify --print-certs --min-sdk-version {24,28,29,33,35}` parsează și verifică **toate cele trei variante pe toate cele cinci valori min-sdk** — parse-ul apksigner e pe schemă, nu e grozavat pe SDK.
- **Nuanță consemnată:** *acceptarea* pe SDK e comportament de platformă (v2 = API 24+, v3 = API 28+, v3.1 = API 33+ pentru rotația cheii), pe care apksigner nu-l emulează — verificarea de instalare rămâne la V-D13 (emulator/dispozitiv, în drill).
- **Consecință pentru decizii:** `minSdk = 29` al aplicației (`gradle/libs.versions.toml`) înseamnă că **v3 e disponibil pe fiecare dispozitiv suportat**; v3.1 (rotire la instalare) nu e necesar decât dacă designul cere citirea semnatarului pe SDK (§7.4 pasul 9) — consemnat, nu blocant.

## V-D19 — binarele relay/issuer, câte o invocație cargo (2026-10-24)

- **Rulat pe ghost-runner** (WSL, target cald): `cargo build --release -p ghost-relay-node` (27,6 s), `-p ghost-issuer` (22,6 s), `-p ghost-issuer-ops` (1,6 s) — fiecare **independent, o singură invocație per binar**, toate trei reușite; artefactele `target/release/{ghost-relay, ghost-issuer, ghost-issuer-ops}` (4,3 / 5,4 / 2,9 MB). Cerința D12 („each built in its own `cargo` invocation") e confirmată ca practică de build.

## V-D18 — pin-urile R8 și JDK (2026-10-24, parțial)

- **AGP** = 9.4.0, pin-uit în `gradle/libs.versions.toml` ✓. **aapt2** = 2.20-15087165 (V-D23). **JDK** pe mașina de build: JetBrains Runtime 17.0.20.1 (de înlocuit în pin-ul unificat cu JDK-ul recipe-ului A/B, care fixează patch level-ul — D23).
- **R8:** `isMinifyEnabled = true` pe release, deci R8 rulează — dar artefactul `com.android.tools:r8` **nu apare ca modul în cache-ul Gradle** nici pe Windows, nici în WSL, iar POM-ul AGP 9.4.0 nu expune o dependență `com.android.tools:r8` directă (AGP 9 o livrează prin mecanism propriu de classpath). **Consecință pentru D23:** pin-ul unificat trebuie să fixeze „R8 = build-ul livrat cu AGP 9.4.0", identitatea exactă fiind verificată prin ieșirile byte-identice ale build-urilor reproductibile A/B (nu prin rezolvare de dependență); extragerea versiunii directe se face în matricea recipe-ului (V-D1…V-D5), nu aici.

## V-D14 + coroborare V-D11a — validarea politicii cu toolingul de referință (2026-10-24)

- **Mediu:** Go 1.22.2 (apt), `sigsum-verify` **v0.13.1** (`go install sigsum.org/sigsum-go/cmd/sigsum-verify@v0.13.1`).
- **Rezultat:** politica transcrisă (`ghost/protocol/test-vectors/sigsum-generic-2025-1.policy`), instalată ca fișier de politică numit (`SIGSUM_POLICY_DIR`, sufix `.sigsum-policy`), verifică **offline o dovadă reală publicată** — `guile-gnutls-5.0.2.tar.gz` + `.proof` de la ftp.gnu.org, cheia ed25519 publicată în anunț: `sigsum-verify -k gnutls-sigsum-key.pub -P s0a-transcribed …` → **exit 0** (semnătura checksum-ului, includerea în log, cvorumul de cosignature 2-of-3 — toate offline). Transcrierea din V-D11a e confirmată ca funcțională de toolingul de referință, nu doar ca bytes.
- **Notă de utilizare:** `-P` la v0.13.1 acceptă doar *nume* (built-in sau din directorul de politici), nu căi — de reținut pentru `ghost-verify` (D21) și documentație.

## V-D20 — valabilitatea certificatului de semnare (2026-10-24)

- **Măsurat:** `keytool -genkeypair` implicit → certificat **valabil 90 de zile** (24 oct 2026 → 22 ian 2027, fix 90). Certificatul semnat intră în blocul v2/v3 al fiecărui APK.
- **Constatare pentru recipe:** platforma verifică valabilitatea certificatului **la instalare și la fiecare update** — un certificat de 90 de zile ar refuza update-urile după expirare. Recipe-ul de release (RK1) trebuie să impună explicit o valabilitate lungă (`-validity`, ex. 30+ ani, practica cheilor de publicare) sau să documenteze deliberat alegerea; valoarea implicită a toolului e o capcană.
- **Efect asupra planului:** de adăugat ca punct explicit în recipe-ul A/B (V-D1…V-D5) și în checklist-ul RK1 din §3.

## V-D23 (completare) — cele două artefacte aapt2 (2026-10-24)

- **aapt2 din Gradle** (cel care compilează resursele APK-ului): `com.android.tools.build:aapt2:9.4.0-15978811` — **deja pin-uit cu checksum-uri în `verification-metadata.xml`** (jar-ul windows, pom-ul, proto). ✓
- **aapt2 din build-tools** (2.20-15087165, cel rulat direct din SDK în probe): vine cu instalarea SDK-ului, în afara verificării Gradle — D23 îl pin-ește prin SHA-256 al arhivei build-tools în recipe. Cele două versiuni sunt artefacte distincte (gradle-resolved vs SDK), de consemnat separat în pin-ul unificat.

## V-D17 — CycloneDX / SBOM (2026-10-24, constatare)

- **Măsurat:** niciun plugin CycloneDX sau task SBOM nu există astăzi în `build.gradle.kts`/`settings.gradle.kts`/`libs.versions.toml` — cerința D12 (SBOM-uri CycloneDX 1.7 deterministe per release) **nu e încă cablată** în build.
- **Efect asupra planului:** alegerea plugin-ului (`org.cyclonedx.bom`, versiune pin-uită) și proba de determinism (două generări consecutive byte-identice) intră în recipe-ul A/B (V-D1…V-D5); nu are sens proba de determinism înainte de cablare. Consemnat, nu blocant pentru S1 (SBOM-ul e produs de release tooling, nu de client).

## Restul verificărilor S0a — de rulat

| Verificare | Ce probează | Stare |
|---|---|---|
| V-D1…V-D5, V-D9, V-D10 | builder recipe A/B, N=2 pin, arhive SHA-256, matricea de variație, AGP/`vcsInfo`, CPU pin | de rulat (necesită runner-ul self-hosted; dependență de CI-L pentru buget) |
| §6.5 core/padding | regula de core și padding apksigner pe cheie software (p=0, p>0, două semnături) | **RULAT 2026-10-24** (determinism ✓, bloc capăt-4096-fix, fără pereche de padding explicită; matricea A/B rămâne la V-D1…V-D5) |
| V-D6, V-D7 | căile PKCS#11, CKM_ED25519 pe token-urile cumpărate | de rulat (necesită token-urile YubiKey — acțiune proprietar) |
| V-D12, V-D22 | ambii listeneri ai oglinzii (h2c prior-knowledge + HTTP/1.1); nginx confirmă sau `ghost-mirror` | **RULAT 2026-10-24**: ambele oglinzi servesc HTTP/2 pe :443 (h2c, 200) și HTTP/1.1 pe :80 peste Tor; nginx confirmat (V-D22) |
| V-D11b | depunerea reală la logul public | așteaptă domeniul (OA-4); stagenet poate folosi logurile publice (staging, §5 note) |
| V-D21 | pre-auth token / verificarea dezvoltatorilor Google | de rulat (emulator API 35+) |
| V-D13…V-D20, V-D23…V-D25 | installer, CycloneDX, R8/JDK pins, binare relay/issuer per invocație, certificate, v2/v3/v3.1 per SDK, vectori sigsum-go, SETTINGS HTTP/2, update runs, ghost-verify | parțial: **V-D19 ✓, V-D15 ✓, V-D20 ✓** (90-zile keytool = capcană), **V-D23 ✓** (aapt2 gradle pin-uit 9.4.0-15978811; build-tools prin recipe), **V-D17 constatare** (fără plugin SBOM — intră în recipe A/B), **V-D18 parțial** (R8 prin AGP) |

**Următorul pas S0a:** matricea core/padding apksigner (extensie a Appendix C.3) și pin-urile
aapt2/JDK/R8 (V-D23), ambele locale; apoi listenerul h2c al oglinzii de staging (V-D12).
