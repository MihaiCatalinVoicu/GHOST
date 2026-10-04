# ADR-60 — Migrare între versiuni: ștergere locală și dezinstalare comandate de manifest (`kill_flag`)

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-04 — decizia a fost transmisă ca text lipit în chat („A3 — aprobat cu ADR”, „A4 — corectat”), nu scrisă direct de proprietar; **nu e aprobat** până proprietarul confirmă în chat, cu cuvintele lui, cele trei condiții din „Obiecții”. Nicio implementare. |
| Sursă | decizia transmisă 2026-10-04; critica lead-ului la A4 acceptată (fără listă de chei de cohortă în manifest, apartenența s-ar divulga) |
| Numerotare | cerut ca „ADR-59”; ADR-59 este acum „Wallet Sync”, deci acesta este ADR-60 |
| Atinge | designul Fazei 14 (manifestul de distribuție, propus, neaprobat), designul Fazei 13 (modulul `:ui`, propus, neaprobat), `IdentityManager` (wipe-ul existent, Faza 3), gate-ul G-M4 (Faza 11, „nicio permisiune nouă”) |
| Cod | niciunul acum. Stub-ul `UninstallFacade.requestInstall()` (răspuns `NOT_IMPLEMENTED`) se creează în Faza 13, în `:ui`; acum nu există modul potrivit și gate-ul anti-placeholder respinge un stub cu `NOT_IMPLEMENTED` în codul de producție |

## Context
La o migrare majoră a platformei (schimbare de protocol, rebranding) se vrea ca toți utilizatorii să poată trece la noua versiune fără urme locale din cea veche: ștergerea bazei locale, a Keystore-ului și, opțional, dezinstalarea curată prin `PackageInstaller`.

## Decizie (propusă)
- Permisiunea `REQUEST_PACKAGE_INSTALL` se adaugă în manifestul modulului `:ui` (Faza 13), ca permisiune **opțională** (nu e cerută la onboarding). Contrazice G-M4 („nicio permisiune nouă”): excepție explicită, cu justificarea de aici.
- Stub `UninstallFacade.requestInstall()` care returnează `NOT_IMPLEMENTED` până la Faza 13.
- Se extinde wipe-ul existent din `IdentityManager` (nu apare un trait nou) cu: zero-fill al bazei SQLCipher, ștergerea Keystore, oprirea JobScheduler și a sesiunii Tor.
- Manifestul de distribuție semnat (Faza 14) primește un câmp `kill_flag: bool`. Dacă e `true`, aplicația execută la pornire wipe-ul complet și, opțional, dezinstalarea prin `PackageInstaller`. Toți utilizatorii primesc același flag: **fără ținte pe identitate**, fără liste de cohortă în manifest (apartenența s-ar divulga).
- Variantă opțională, **neactivată**: staged rollout (`rollout_pct: u8`, eventual cohortă), implementat doar la cerere explicită. Orice cohortă bazată pe identități listate în manifest divulgă apartenența; varianta acceptabilă este tragerea locală a clientului împotriva lui `rollout_pct`, fără liste.

## Consecințe
- **+** Migrare curată între versiuni, fără urme locale; toți primesc același update (blind).
- **−** Permisiune nouă în manifest (excepție de la G-M4); permisiune sensibilă pentru politicile magazinelor de aplicații.
- **−** Operatorul de distribuție (cine setează `kill_flag` și deține cheile de semnare) poate **șterge datele locale ale tuturor utilizatorilor deodată**. Nu e o clasă nouă de încredere față de AD-1 (operatorul poate deja publica un update oarecare), dar scade costul abuzului la un singur bit și trebuie declarat în auditul extern și în dezvăluirile din aplicație.

## Obiecții consemnate de lead (de rezolvat înainte de aprobare)
1. **Consimțământ.** O ștergere automată la pornire distruge mesajele locale ale unui utilizator care nu a ales-o (identitatea se recuperează din cele 24 de cuvinte, conversațiile nu). Recomandat: ecran de confirmare cu termen (utilizatorul poate exporta/migra), `kill_flag` neaplicat automat pe un telefon cu date neexportate decât după confirmare; ștergerea silențioasă doar dacă proprietarul o cere explicit și o acceptă ca reziduu.
2. **Blast radius.** O cheie de semnare compromisă sau un operator constrâns poate declanșa ștergerea în masă. Condiții propuse (Faza 14): flag-ul se onorează doar într-un manifest cu versiune mai mare decât cea instalată, publicat în jurnalul de transparență (Sigsum), cu semnătură de prag; fără reluare (anti-rollback).
3. **Transparență.** Capacitatea trebuie să apară în STATUS, în inventarul pentru auditul extern (Faza 15, `docs/audit/`) și în dezvăluirile din aplicație (CP-10): „manifestul semnat poate comanda ștergerea locală a datelor”. Nu se ascunde în formulări neutre.
4. **Permisiune:** `REQUEST_PACKAGE_INSTALL` e verificată de Google Play Protect și de politicile magazinelor; de verificat compatibilitatea cu canalele din Faza 14 înainte de Faza 13.
