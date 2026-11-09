# Runbook RK1 + mediul B — ceremoniile de închidere ale Fazei 14

Ghid operațional pentru ce rămâne după încheierea lucrului de dezvoltare: construirea
**mediului B** (al doilea mediu independent, pentru egalitatea A/B a recipe-ului), **RK1**
(prima lansare semnată cu token-ul hardware) și verificările care le însoțesc. Fiecare pas
numește instrumentul comis care îl execută; designul rămâne sursa normativă
(`docs/design/faza14-distribution.md`, citat §).

## 0. Ce e gata (verificat 2026-11-09, `08045ecf`)

- Mediul A: imaginea `ghost-builder:24.04-5` (pins în `ghost/infra/builder/pins.txt`,
  selfcheck PASS înregistrat acolo), recipe unificat `scripts/release/build-release.sh`
  validat în imagine: selfcheck 2× byte-identic (files=20), cross complet (files=24).
- Exportul public `ghost-release-ops export-public` + build standalone `--locked` din
  arborele exportat (verificat end-to-end).
- Gate-urile ceremoniei: `release-sums.sh` (G-D3), `release-records.sh` (G-D4),
  `release-no-secrets.sh` (G-D1), `mirror-config.sh` (G-D10) — toate verzi pe arbore;
  G-D4 așteaptă `allowed_signers` (pasul 4 de mai jos) și `GHOST_D4_CHECKER` pentru
  clauzele (a)–(c).
- `ghost-verify` complet (apk/libs/fetch/operator/monitor, regulile (a)–(i)).

## 1. Mediul B (mașina independentă)

Cerințe: Linux x86_64 cu Docker, ~8 GB RAM, ~30 GB disc, acces la rețea doar pentru
descărcările pinuite din recipe (o rulare completă).

```bash
git clone <repo> ghost-src && cd ghost-src
git checkout <tagul-de-inchidere>          # tag semnat, pasul 4
docker build -t ghost-builder:24.04-5 -f ghost/infra/builder/Dockerfile ghost/infra/builder
ghost/infra/builder/run-in-image.sh <tagul-de-inchidere> --out ./build-B
```

`run-in-image.sh` montează repo-ul read-only, construiește din imagine, scrie `build-B/`.
Egalitatea cu mediul A:

```bash
# pe oricare dintre mașini, cu build-A de la mediul owner-ului lângă build-B:
bash ghost/scripts/gates/release-sums.sh ./build-A ./build-B
# așteptat: [release-sums] OK — SHA256SUMS egale și complete, lib-urile APK-ului egale,
# build-id simbol==bibliotecă. Orice diferență oprește ceremonia (R-D1: raport, nu relaxare).
```

## 2. Înainte de tag (pe ambele medii, identic)

- `bash ghost/scripts/gates/run-all.sh` verde.
- `GHOST_RELEASE_CROSS=1 ghost/infra/builder/run-in-image.sh <tag> --out ./build-cross`
  produce toate cele 24 de artefacte (inclusiv `ghost-verify` pe 3 ținte).
- `bash ghost/scripts/gates/release-no-secrets.sh` — nimic de semnat în arbore.
- `bash ghost/scripts/gates/public-identity-scrub.sh <output>` pe ambele output-uri.

## 3. Tag-ul de închidere

Tag semnat cu cheia de tag (prima cheie a proprietarului — de aceea G-D4(e) așteaptă):

```bash
git tag -s <tag> -m "<tag>"
# allowed_signers pentru rețeaua de lansare (stagenet mai întâi, RK0):
git verify-tag <tag>   # cu allowed_signers populat în protocol/release/<network>/
```

## 4. RK0 pe stagenet (înainte de orice lansare reală)

Pe hostul de semnare (§13.3 checklist 6; laptopul dedicat din §5.4 al designului):

1. Cheile stagenet generate pe token-uri (procedura din design §5, RK0) — până atunci
   stagenet folosește cheile software din `test-harness/update/keys/` doar pentru drill-uri.
2. Root-ul stagenet cu amorsele sale + certificatul comise în `protocol/release/stagenet/`.
3. `bash ghost/scripts/gates/release-records.sh` verde (cu `GHOST_D4_CHECKER` dacă
   clauzele (a)–(c) rulează înainte de binarul de records-check).
4. Drill de rotație cu token-urile reale: RK2, RK3, RK4, RK5 — înregistrări semnate.

## 5. RK1 (prima lansare)

1. A și B la același tag, `release-sums.sh` OK (pasul 1).
2. Semnarea nucleului: pe hostul de semnare, `apksigner sign` cu `K-APK` de pe token
   (carve-out-ul G-D1 permite doar `test-harness/update/keys/`; semnarea reală e pe
   hostul air-gapped, nu în arbore) — vezi design §5.4 și spike-urile V-D6/V-D7.
3. Submission Sigsum din containerul Tor-only (procedura R-P din design §7.4) — necesită
   token-ul de rate-limit pe domeniul proiectului (OA-4); proba vie V-D11b cu captură.
4. `proof-assemble` pe proof-uri; manifestul + bundle-ul publicate pe oglinzile de staging;
   `ghost-verify monitor` peste arhiva de lansare — zero constatări.
5. Înregistrarea lansării: `archive-index.txt`, checklist-ul RK1 (redactat), STATUS.

## 6. După lansare

- Monitorul independent (auditorul OA-9) rulează `ghost-verify monitor` săptămnal;
  `ghost-verify served-once` zilnic la oră aleatorie, scris în recordul servit.
- Următoarele lansări: doar pașii 1–2 + submission (rotațiile RK2–RK5 după caz).

## Resturi cunoscute (nu blochează pașii de mai sus)

- Rândurile G-D1/G-D2/G-D4 care scanează workflow-urile CI se mecanizează când
  `.github/workflows` intră în arbore (acum documentate în gate-uri ca manuale).
- `release-records.sh` clauzele (a)–(c) devin live cu primul binar de records-check
  (`ghost-release-ops records-check` sau `ghost-verify` — de construit la prima ceremonie,
  cu `GHOST_D4_CHECKER` până atunci).
- Proba vie V-D11b și identitatea de proiect (Q45) rămân puncte ale proprietarului.
