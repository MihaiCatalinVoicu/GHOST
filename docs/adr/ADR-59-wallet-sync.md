# ADR-59 — Wallet Sync: conectarea wallet-ului existent pentru restore pe alt dispozitiv

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-04 — decizia a fost transmisă ca text lipit în chat („A1 — aprobat cu addendum”), nu scrisă direct de proprietar; **nu e aprobat** până proprietarul confirmă în chat, cu cuvintele lui, suprascrierea ADR-02, ADR-03 și ADR-23 descrisă în „Obiecții”. Nicio implementare. |
| Sursă | decizia transmisă 2026-10-04 (structura și formularea din text păstrate; consecințele corectate față de ADR-02/03/23 și T2, vezi „Obiecții”) |
| Ar suprascrie | ADR-02 („Issuer-ul deține doar view key; spend key offline/multisig”; „issuer = componentă fără chei de conținut și fără identități”), ADR-03 (fără wallet integrat), părți din ADR-23 (issuer și relay nelegabile), TB-5 din modelul de amenințări |
| Numerotare | cerut ca „ADR-58”; ADR-58 este deja „CI local” (aprobat 2026-10-04), deci acesta este ADR-59 |
| Cod | niciunul. Tabelul `wallet_link` e rezervat pentru prima utilizare reală (prima migrare care are sens), nu se creează ca tabel mort; crate-ul `ghost-monero-rpc` nu se extrage până la aprobare |

## Context
Utilizatorii GHOST plătesc cu XMR, dar cheile financiare stau în afara app-ului (ADR-02/03). Pentru a permite restaurarea pe un alt dispozitiv fără seed phrase fizic, se propune opțiunea de a conecta wallet-ul existent al utilizatorului.

## Decizie (propusă)
Se extinde adaptorul `ghost-monero-rpc` cu profilul `spendable` (aceleași metode JSON-RPC, fără flag-ul `watch-only`). Utilizatorul optează explicit în UI: „Sincronizează wallet-ul pentru restore pe alt dispozitiv”. Cheile se trimit la issuer criptate E2E (cheia de sesiune derivată din identitatea GHOST) și se stochează în baza de date a issuer-ului.

## Consecințe (cele din text, plus ce rezultă din ele)
- **+** Restore cross-device fără seed fizic; folosește infrastructura existentă (issuer + Tor).
- **−** Issuer-ul devine custode temporar al cheilor de cheltuit (doar pentru wallet-urile sincronizate). **Aceasta este o clasă nouă de risc, nu una incrementală:** T2 și ADR-02 apără *confidențialitatea* (issuer-ul vede plăți către subadresele lui, nu fonduri ale utilizatorilor); aici un issuer compromis sau constrâns legal poate **fura fondurile** tuturor utilizatorilor care au optat.
- **−** Necesită încredere în operatorul issuer-ului (extinde T2 de la view key la chei de cheltuit).

## Alternative considerate (din text)
- Vault custodial (utilizatorul depune fonduri în app) — respins: migrare vizibilă a fondurilor, UX mai complex.
- Seed phrase local doar — respins: nu permite restore fără acces fizic la telefon.

## Obiecții consemnate de lead (de rezolvat înainte de aprobare)
1. **Contradicție internă.** Textul spune și „criptat E2E cu cheia derivată din identitatea GHOST”, și „issuer-ul devine custode al cheilor de cheltuit”. Dacă blob-ul e criptat cu o cheie pe care issuer-ul nu o are, issuer-ul **nu** e custode și **nu** are nevoie de profilul `spendable` (nu cheltuiește nimic; doar păstrează un blob). Dacă îl poate folosi, este custodie de fonduri, cu riscurile de mai sus (și juridice/reglementare). Decizia trebuie să aleagă una.
2. **Legătura identitate–wallet la issuer.** Pentru a returna blob-ul la restore, issuer-ul trebuie să recunoască utilizatorul printr-un identificator stabil. ADR-02 și ADR-23 stau pe faptul că issuer-ul nu are identități și nu poate lega plăți de tokenuri; un identificator stabil per identitate rupe această proprietate (T2) pentru cei care optează. Orice variantă trebuie să spună cum se autentifică restore-ul fără identificator stabil la issuer.
3. **Alternativă care nu atinge issuer-ul (recomandată):** blob criptat pe partea clientului (cheie derivată din seed-ul BIP-39 de 24 de cuvinte, ramură HKDF separată), depus în namespace-ul propriu, orb, pe relay-uri, ca restul datelor; restore cu aceleași 24 de cuvinte. Fără issuer, fără profil `spendable`, fără extinderea T2, fără încredere suplimentară în operator. Pentru un wallet existent: importul lui local, nu trimiterea la un server.
4. **Intrare în modelul de amenințări** (propusă, vezi `docs/THREAT_MODEL_v2.1.md` §11): marcată ca **clasă nouă** (custodie de chei de cheltuit) dacă se păstrează varianta cu issuer; nu „incrementală”.
5. **Procedură:** schimbarea ADR-02/03/23 cere o decizie explicită de suprascriere, un design aprobat și teste de invarianți (T2) înainte de cod.
