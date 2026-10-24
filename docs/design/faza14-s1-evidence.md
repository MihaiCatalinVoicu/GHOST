# Faza 14 — evidența S1 (canalul de distribuție, cod)

Data: 2026-10-24. S1 = „codul canalului de distribuție": formatele §4, instrumentul de operare
`ghost-release-ops` și primul test de canal cap-coadă pe oglinzile de staging.
Design: `docs/design/faza14-distribution.md` (aprobat 2026-10-05). Evidența S0 (decizii de plan):
`docs/design/faza14-s0-evidence.md`.

## Ce s-a construit (toate pe `main`)

1. **`ghost-client-release`** — crate Rust pur (fără I/O, ceas, aleatoriu) cu toate formatele §4:
   onion canonic (parser total, checksum v3 SHA3-256), statement + sigblock (regula TUF
   ignore-don't-error), `GHRT` (root versionat, keyset-uri cu prag, log-uri Sigsum cu origin,
   witnesses cu quórum plat, anchor mirrors), `GHRC` (lanț contiguu, ≤ 64), `GHRM` (manifest cu
   expirare ≤ 91 zile, secvență monotonă, floor, rollout permille + salt, artifacts kind 1–24 cu
   16 obligatoriu, bloc de atestare per release), `GHRA` (statement-ul de atestare), `GHRP`
   (dovezile Sigsum v1: frunză 128 B, incluziune RFC 6962, checkpoint C2SP, cosignature-uri cu
   plafonul de timp σ+1 zi), `GHRB` (bundle cu limitele fixe §4.8: 1 MiB / 16 KiB / 64 KiB /
   16 KiB). 21 de teste.
2. **`ghost-release-ops` — `apk-core`** — regula nucleului §6.5 (`core(signed) = unsigned` byte
   cu byte, padding-ul pereche, blocurile de semnătură v2/v3), validată pe output real
   apksigner 37.0.0: `CORE_EQUAL padding=3560/3461 blocks=0x42726577,0x7109871a,0xf05368c0`
   (atentie: ZIP/blocurile de semnătură sunt little-endian, formatele GHOST sunt BE).
3. **`ghost-release-ops` — builder-e** (`keygen`, `root-build`, `chain-build`, `proof-build`,
   `manifest-build`, `bundle`) — pipeline-ul stagenet cu chei software: fiecare builder
   re-parse-uite exact bytes-ele scrise și auto-verifică pragurile/incluziunea înainte de a
   scrie. Reguli de refuz implementate (structurale, locale documentelor): secvența manifestului
   monotonă față de precedentul logat, `issued_day` nedescrescător, salt stabil pentru un
   `apk_sha256` logat, escrow kind 16 obligatoriu, release wire-changing la permille strict între
   0 și 1000 refuzat, floor peste cel mai mic release atestat refuzat, `anchor_root` în afara
   lanțului refuzat, oglinzi/relay-uri non-canonice refuzate, reutilarea unei chei între keyset-uri
   refuzată. Regulile RK1 care cer date de la issuer (acoperire sloturi ES, retrageri de relay,
   indexul arhivei, transcript-ul wire) NU sunt încă implementate — se notează la fiecare builder;
   vin cu tooling-ul complet de ceremonie.
4. **`ghost-release-ops` — `inspect`** — scheletul acceptanței client §7.4: lanțul (fiecare root
   verificat sub keyset-ul predecessorului), manifestul sub cheile release ale rootului cel mai
   nou, atestările, incluziunea fiecărui proof + numărul de cosignature-uri față de quórum,
   potrivirea rețelei, expirarea manifestului față de `--today` (zile epoch).
5. **Testul de canal end-to-end** (`ghost/scripts/staging/channel-test-{build,fetch}.sh`) —
   rulat în WSL pe `ghost-runner` 2026-10-24.

## Măsurători (2026-10-24, WSL)

- Teste: `ghost-client-release` 21/21 verzi; `ghost-release-ops` 9/9 verzi (6 apk-core sintetice
  + 3 de integrare: pipeline complet cu două root-uri, două manifeste, refuzurile de secvență și
  `issued_day`, bundle re-parse-uit).
- Canal real: chei stagenet generate (root 2/2, release 1/1, attest 1/1, 1 log, 2 witnesses,
  quórum 1), root cu cele două oglinzi reale de staging ca ancore
  (`ls2jkm3…lfoqd.onion:443`, `tfhsac26…no4id.onion:443`), manifest seq 1 (emis azi, expirare
  +30 zile), bundle **1 628 bytes** (`sha256=52c4087d…c16359` la rularea de referință).
- Publicare pe ambele oglinzi la calea fixă `ghost/v1/stagenet/current.ghrb` (copie `.staged` +
  rename atomic). Fetch prin Tor (SOCKS gazdă 127.0.0.1:9050): **4/4 combinații verzi**
  (mirror-a :80, mirror-a :443, mirror-b :80, mirror-b :443) — HTTP 200, hash SHA-256 identic
  cu originalul, `BUNDLE_OK` pe fiecare copie descărcată.

## Decizii de implementare luate pe parcurs (nu le redeschidem)

- Oglinzile rămân nginx (V-D22 a confirmat ambele listener-e); `ghost-mirror` propriu nu e
  justificat.
- Proof-urile de test sunt sintetice (arbore cu o frunză, chei generate local): submission-ul
  real `sigsum-submit` + `proof-assemble` e RK1/V-D11b (necesită domeniu, OA-4).
- Builder-e pe `main`, pe `main` se lucrează direct (repo privat, CI local ADR-58).
- Sincronizarea sursei de adevăr: commit-uri pe Windows (`D:\Forum`), build/test în WSL
  (`/srv/ghost-src`).

## Rămâne (S1 neînchis complet / faze ulterioare)

- Regulile RK1 complete de refuz la `manifest-build` (date de issuer) și `proof-assemble` /
  `leaf-request` (submission reală la logul Sigsum, V-D11b — necesită OA-4 domeniu).
- `ghost-client-update` (crate-ul pur client, §7.4–§7.8), transportul `TorMirrorTransport` și JNI
  (§9), modulele Kotlin `:update` — S2+.
- `ghost-verify` (verificatorul public, §9.1) — poate porni din `inspect` + fetch.
- Live-drill-ul pe telefon real cu drill root (D26, §11.4) — după S2.
- SBOM CycloneDX în recipe A/B, R8 pin prin AGP, RK0–RK6 (ceremonii cu token-uri hardware).
