# ADR-60 — Migrare între versiuni: ștergere locală și dezinstalare comandate de manifest (`kill_flag`)

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-10-04 de proprietar, în cuvintele lui, în chat („ADR-60 — aprobat cu ștergere automată, fără ecran de confirmare”). Fără cod acum |
| Sursă | decizia proprietarului din 2026-10-04; critica lead-ului la propunerea de cohortă acceptată (fără listă de chei de cohortă în manifest: apartenența s-ar divulga) |
| Numerotare | cerut ca „ADR-59”; ADR-59 este „Wallet Sync”, deci acesta este ADR-60 |
| Atinge | designul Fazei 14 (manifestul de distribuție, propus, neaprobat), designul Fazei 13 (modulul `:ui`, propus, neaprobat), `IdentityManager` (wipe-ul existent, Faza 3), gate-ul G-M4 (Faza 11, „nicio permisiune nouă”; excepție explicită aici) |
| Cod | niciunul acum. Stub-ul `UninstallFacade.requestInstall()` (`NOT_IMPLEMENTED`) se creează în Faza 13, în `:ui`: acum nu există modul potrivit, iar gate-ul anti-placeholder respinge un stub cu `NOT_IMPLEMENTED` în codul de producție |

## Context
La o migrare majoră a platformei (schimbare de protocol, rebranding) toți utilizatorii trebuie să poată trece la noua versiune fără urme locale din cea veche: ștergerea bazei locale, a Keystore-ului și, opțional, dezinstalarea curată prin `PackageInstaller`.

## Decizie
- Permisiunea `REQUEST_PACKAGE_INSTALL` se adaugă în manifestul modulului `:ui` (Faza 13), ca permisiune **opțională** (nu e cerută la onboarding). Excepție explicită de la G-M4.
- Stub `UninstallFacade.requestInstall()` care returnează `NOT_IMPLEMENTED`, în Faza 13.
- Se extinde wipe-ul existent din `IdentityManager` (fără trait nou) cu: zero-fill al bazei SQLCipher, ștergerea Keystore, oprirea JobScheduler și a sesiunii Tor.
- Manifestul de distribuție semnat (Faza 14) primește un câmp `kill_flag: bool`. Dacă e `true`, aplicația execută **automat, la pornire**, wipe-ul complet și, opțional, dezinstalarea prin `PackageInstaller`. **Fără ecran de confirmare și fără fereastră de export** (decizia proprietarului: tocmai acesta e punctul). Toți utilizatorii primesc același flag: fără ținte pe identitate, fără liste de cohortă în manifest.
- **Consimțământul** se colectează la onboarding, cu formularea din CP-10: „manifestul semnat poate comanda ștergerea locală a datelor”.
- Variantă opțională, **neactivată**: staged rollout (`rollout_pct: u8`, eventual cohortă), implementat doar la cerere explicită. O cohortă din identități listate în manifest divulgă apartenența; varianta acceptabilă ar fi tragerea locală a clientului împotriva lui `rollout_pct`, fără liste.

## Consecințe
- **+** Migrare curată între versiuni, fără urme locale; toți primesc același update (blind).
- **−** **Reziduu acceptat de proprietar:** ștergere silențioasă, fără confirmare și fără export; utilizatorul pierde conversațiile locale (identitatea se recuperează din cele 24 de cuvinte). De adăugat în `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`, în secțiunea Fazei 14, la aplicare.
- **−** Operatorul de distribuție (cine setează `kill_flag` și deține cheile de semnare) poate șterge datele locale ale tuturor utilizatorilor deodată. Nu e o clasă nouă de încredere față de AD-1 (operatorul poate deja publica un update oarecare), dar scade costul abuzului la un singur bit; se declară în STATUS, în inventarul pentru auditul extern și în dezvăluirile din aplicație.
- **−** Permisiune nouă în manifest (excepție de la G-M4).

## Obiecții și rezoluții (2026-10-04)
| # | Obiecția lead-ului | Rezoluția proprietarului |
|---|---|---|
| 1 | consimțământ: ștergerea la pornire distruge mesaje necerute | ștergerea silențioasă e cerută explicit și acceptată ca reziduu; consimțământ la onboarding cu formularea CP-10; nu există fereastră de export |
| 2 | blast radius: cheie compromisă sau operator constrâns | condițiile (versiune mai mare decât cea instalată, jurnal de transparență Sigsum, semnătură de prag, anti-rollback) sunt **satisfăcute de cerințele din designul Fazei 14** (propus, neaprobat): CS-D1 (manifest semnat de pragul de release al rădăcinii de încredere), CS-D3 (fără rollback în epoca de încredere), jurnalul de transparență (ADR-38 punctul 6, ADR-49). Se onorează ca orice alt câmp al manifestului, doar după aceste verificări; nu sunt cerințe noi |
| 3 | transparență | acceptat: STATUS, inventarul pentru auditul extern (`docs/audit/`) și dezvăluirea CP-10 |
| 4 | permisiune și politici de magazin | distribuția Fazei 14 e prin oglinzi onion (D1, X-D2), fără Google Play: `REQUEST_PACKAGE_INSTALL` nu trece printr-o politică de magazin. Rămân: setarea Android „instalează aplicații necunoscute” și posibile avertismente Play Protect pe dispozitive cu Google Play Services; de verificat în Faza 14, nu blochează |
