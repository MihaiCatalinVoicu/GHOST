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

## Restul verificărilor S0a — de rulat

| Verificare | Ce probează | Stare |
|---|---|---|
| V-D1…V-D5, V-D9, V-D10 | builder recipe A/B, N=2 pin, arhive SHA-256, matricea de variație, AGP/`vcsInfo`, CPU pin | de rulat (necesită runner-ul self-hosted; dependență de CI-L pentru buget) |
| §6.5 core/padding | regula de core și padding apksigner pe cheie software (p=0, p>0, două semnături) | de rulat (extinde Appendix C.3 la matrice) |
| V-D6, V-D7 | căile PKCS#11, CKM_ED25519 pe token-urile cumpărate | de rulat (necesită token-urile YubiKey — acțiune proprietar) |
| V-D12, V-D22 | ambii listeneri ai oglinzii (h2c prior-knowledge pentru aplicație + HTTP/1.1 pentru browsere/ghost-verify); nginx confirmă sau `ghost-mirror` | PARȚIAL: staging-ul Fazei 13 are doar HTTP/1.1 (`ghost/infra/mirror/`); listenerul h2c e de adăugat la imagine înainte de S1 (D14) |
| V-D11b | depunerea reală la logul public | așteaptă domeniul (OA-4); stagenet poate folosi logurile publice (staging, §5 note) |
| V-D21 | pre-auth token / verificarea dezvoltatorilor Google | de rulat (emulator API 35+) |
| V-D13…V-D20, V-D23…V-D25 | installer, CycloneDX, R8/JDK pins, binare relay/issuer per invocație, certificate, v2/v3/v3.1 per SDK, vectori sigsum-go, SETTINGS HTTP/2, update runs, ghost-verify | de rulat |

**Următorul pas S0a:** matricea core/padding apksigner (extensie a Appendix C.3) și pin-urile
aapt2/JDK/R8 (V-D23), ambele locale; apoi listenerul h2c al oglinzii de staging (V-D12).
