# ADR-59 — Wallet Sync: wallet-ul existent, restaurat pe alt dispozitiv din cele 24 de cuvinte (fără issuer)

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-10-04 de proprietar, în cuvintele lui, în chat („ADR-59 — aprobat în varianta fără issuer”). Propus mai întâi cu varianta cu issuer; aceea e **respinsă** (vezi „Alternative”). Fără cod acum |
| Sursă | decizia proprietarului din 2026-10-04; obiecțiile lead-ului (secțiunea „Obiecții și rezoluții”) |
| Bază de autoritate | ADR-03: „Ramura `wallet` din ierarhia de chei rămâne rezervată (etichetă de domeniu definită, nefolosită), pentru a evita migrarea seed-ului dacă apare un rail on-chain opțional.” Wallet Sync activează această rezervare; nu suprascrie ADR-02, ADR-03 sau ADR-23. *Nota lead-ului:* ADR-03 mai spune că în P0 nu există portofel în aplicație și că endpoint-ul nu are chei financiare; pentru utilizatorii care optează, aplicația ține material financiar pe dispozitiv (vezi „Consecințe” și `docs/THREAT_MODEL_v2.1.md` §11). Proprietarul a decis că aceasta intră în limitele rezervării |
| Numerotare | cerut ca „ADR-58”; ADR-58 este „CI local”, deci acesta este ADR-59 |
| Cod | niciunul. Crate-ul `ghost-monero-rpc` (profilul `spendable`) **nu** se extrage până apare un apelant real pe server; tabelul `wallet_link` rămâne rezervat pentru prima utilizare reală, în prima migrare care are sens |

## Context
Utilizatorii GHOST plătesc cu XMR din wallet-uri externe (ADR-02/03). Pentru a putea restaura pe un alt dispozitiv fără seed fizic, utilizatorul poate conecta wallet-ul existent.

## Decizie
1. Opțional, cu consimțământ explicit în UI („Sincronizează wallet-ul pentru restore pe alt dispozitiv”), seed-ul wallet-ului utilizatorului se păstrează **local** în Keystore și, în plus, ca **blob criptat pe partea clientului**, cu o cheie derivată din seed-ul BIP-39 de 24 de cuvinte al identității GHOST (ramura rezervată `wallet`, ADR-03), depus **orb** în namespace-ul propriu al utilizatorului, pe relay-uri.
2. **Restore:** cu aceleași 24 de cuvinte, derivare pur locală (seed → cheie → namespace), citirea blob-ului și decriptarea locală. Issuer-ul nu autentifică și nu primește nimic.
3. **Issuer-ul rămâne view-only.** T2, ADR-02 și ADR-23 nu se schimbă. Nimic nu ajunge la issuer.
4. Rămân amânate: profilul `spendable` al adaptorului Monero și extragerea crate-ului `ghost-monero-rpc`, până apare un apelant real pe server; tabelul `wallet_link`.

## Consecințe
- **+** Restore cross-device fără seed fizic, fără încredere suplimentară în operator; infrastructura existentă (relay-uri, Tor, namespace-uri orbe).
- **−** Pentru utilizatorii care optează, seed-ul sincronizat stă local (Keystore) și ca blob criptat pe relay. **Un activ nou pe endpoint:** compromiterea seed-ului GHOST de 24 de cuvinte sau a dispozitivului expune acum și fondurile wallet-ului sincronizat (miză financiară pentru S6, dispozitiv cu root, și pentru protecția seed-ului). Se declară în dezvăluirile de la opt-in (CP-10).
- **Deschis pentru design (la implementare):** TTL-urile relay-urilor sunt limitate, deci blob-ul trebuie reînnoit periodic (ca pachetele DM de chei) sau restore-ul după o pauză lungă eșuează; clasa de mărime a blob-ului și forma lui orbă; ce se întâmplă la schimbarea wallet-ului.

## Alternative
- **Varianta cu issuer (custodie sau stocare de blob la issuer) — respinsă.** Ar fi o clasă nouă de risc, nu incrementală: custodie de chei de cheltuit la issuer (un issuer compromis sau constrâns poate fura fondurile) și o legătură identitate–wallet la issuer (identificator stabil per identitate), ceea ce rupe T2/ADR-23. Rămâne consemnată în `docs/THREAT_MODEL_v2.1.md` §11 ca alternativă respinsă.
- Vault custodial (fonduri depuse în app) — respins: migrare vizibilă a fondurilor, UX mai complex.
- Seed phrase local doar — respins: nu permite restore fără acces fizic la telefon.

## Obiecții și rezoluții (2026-10-04)
| # | Obiecția lead-ului | Rezoluția proprietarului |
|---|---|---|
| 1 | „E2E” și „issuer custode” se contrazic | custodie **client-side**: issuer-ul nu deține nimic, deci nici profil `spendable`, nici extragerea crate-ului; din consecințe a dispărut „issuer devine custode” |
| 2 | identificator stabil la issuer pentru restore | irelevantă în varianta fără issuer: restore-ul e derivare locală, issuer-ul nu autentifică nimic |
| 3 | alternativa fără issuer | **aleasă** |
| 4 | intrarea în modelul de amenințări | varianta fără issuer nu schimbă încrederea în issuer/relay; adaugă un activ pe endpoint pentru cei care optează (`THREAT_MODEL_v2.1.md` §11); linia cu issuer rămâne ca alternativă respinsă |
| 5 | procedura (suprascriere ADR-02/03/23) | nu se suprascrie nimic; baza e rezervarea din ADR-03; niciun cod până la primul apelant real |
