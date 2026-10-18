# ADR-62 — Liniile de bridge: doar de la utilizator, stocare învelită, fără listă încorporată, mod auto redus

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-17 (design Faza 12, `docs/design/faza12-transports.md`), **aplicat** în Faza 12 (feliele S0–S4 de pe `p12-s4`: validatorul total și refuzurile, tabela `transport_bridge` la schema v9, modul auto redus, suprafața PT-1 … PT-5, porțile G-T7/G-T8), în așteptarea deciziei proprietarului (Q11). Amendamentul S3-T8 (clauza de disc a lui T58): arti 0.46 persistă identitatea bridge-ului configurat în magazinele proprii de stare (`guards.json`, `dir.sqlite3`) — comportament proiectat de upstream, fără comutator; clauza se citește prin rândul T58 din INVARIANTS |
| Sursă | design Faza 12 §6, §7, §8.5; ADR-16 (modul auto); `docs/design/faza13-ux.md` (interfața de introducere e a Fazei 13) |
| Faze | 12; P1 |
| Modifică | ADR-16 (modul auto complet cu listă livrată și rotită devine, până la Faza 14, un mod auto redus peste liniile utilizatorului — X-T2); schema bazei (o tabelă nouă, la prima versiune de migrație liberă de la îmbinare); suprafața JNI închisă (funcțiile PT-1 … PT-5); INVARIANTS (T58 … T60); THREAT_MODEL (rândul AD-4 se actualizează) |

## Context

Faza 6 acceptă doar linii simple (`IP:PORT FINGERPRINT`) și refuză explicit liniile `obfs4`/`webtunnel`/`snowflake`; ADR-16 cere activarea lor ca schimbare deliberată și un mod auto (Tor direct → bridges, niciodată clearnet). Interfața de introducere a liniilor (paste/QR) aparține Fazei 13 (care deține textul sigur și scanarea), iar distribuția liniilor — cine operează bridge-uri, cum se rotesc, ce costă o listă confiscată — e spațiul de design al Fazei 14. Modul auto al ADR-16 presupune o listă livrată în manifestul semnat, pe care P0 nu o are.

## Decizie

1. În P0 liniile de bridge sunt **doar de la utilizator**: Faza 12 livrează parsarea, validarea, stocarea și o intrare de test pe partea gazdă; lipirea și QR-ul rămân în Faza 13, prin aceeași apelare a suprafeței (PT-3/PT-4).
2. **Nicio listă încorporată**, niciun fetch, nicio rotație automată: distribuția e întrebarea Fazei 14 (Q5 din design). APK-ul conține zero linii de bridge (fixture de poartă care scanează APK-ul). Aceasta e abaterea declarată față de „bridges implicite" din decizia ADR-16 (X-T2).
3. Validarea e o singură funcție totală, cu un tabel de gramatici fix: linie simplă, `obfs4` (cu `cert=` și `iat-mode` 0/1/2), `webtunnel` (cu `url=` https și `ver=`), fiecare cu verificări structurale; parametrii opaci semantic pentru GHOST nu se interpretează niciodată de GHOST (Arti și ptmgr dețin protocolul). `snowflake` și orice alt nume de transport se refuză cu erori distincte; limită de 1 024 de caractere și de 8 linii per dispozitiv; deduplicare exactă. Test de proprietate cu 10⁶ de intrări însămânțate per rulare CI (regula parserelor din proiect).
4. Stocarea: o tabelă nouă (`transport_bridge`: linia ca cheie primară, ziua adăugării; fără coloană de timp, `WITHOUT ROWID`) în baza SQLCipher existentă — criptată cu cheia bazei, fără cheie de custodie nouă, cu aceeași politică no-backup ca restul configurației. Ordinea liniilor e ordinea adăugării (deterministă, fără timp). **Nicio linie de bridge în loguri, în crash dump-uri sau în vreun fișier în afara bazei** (invariantul T58, cu amendamentul S3-T8 pentru magazinele proprii de stare ale arti; scanarea-canar PT-P1 injectează o linie sintetică și verifică toate celelalte locuri, iar textul integral al linii nu apare nicăieri).
5. **Modul auto redus** (X-T2): dacă nu sunt linii configurate, un singur bootstrap direct (comportamentul actual, neschimbat); dacă sunt linii, mai întâi direct, iar la eșec sau timeout — un client nou pe bridge-uri, în ordinea liniilor, fiecare cu termenul propriu de 180 s, fiecare sub regula clientului consumat din Faza 6; niciodată clearnet, niciodată un fallback non-Tor. Modul auto complet cu listă livrată și rotită se decide odată cu distribuția (Faza 14).
6. Suprafața JNI e închisă (PT-1 … PT-5): instalare/disponibilitate PT, setare/listare linii, câmpurile de configurare ale transportului. Erorile poartă indexul linii, nu linia; liniile nu intră niciodată în mesaje de eroare formate pentru log.

## Consecințe

(+) fără o a doua poveste de custodie pentru linii (aceeași cu a întregii baze); fără o jumătate de suprafață de distribuție proiectată înaintea Fazei 14; refuzurile rămân deliberate, distincte și testate (activarea PT a fost o schimbare deliberată, ca la Faza 6); modul auto există în forma lui onestă, limitată la ce știe clientul. (−) majoritatea utilizatorilor nu are bridge-uri până la distribuție — o problemă de disponibilitate, nu de confidențialitate (L12-C6); a doua încercare de bootstrap dublează latența pe rețele blocate (termen per încercare, consemnat); o linie de bridge e un identificator durabil al intenției de rețea la sechestru cu baza deblocată (aceeași custodie ca tot restul bazei, deci fără clasă de risc nouă).

## Alternative respinse

Listă de bridge-uri încorporată în P0 (distribuția nerezolvată: cine operează bridge-urile, rotația, costul unei liste confiscate — ar fi reproiectată de Faza 14 oricum); fetch de linii la prima rulare (aceeași problemă, plus un contact de rețea nou observabil); fișier învelit separat per linie (a doua poveste de custodie, fără câștig); lăsarea Arti să persiste liniile în directorul de stare (T58 interzice explicit, cu canar); mod auto care pornește direct pe bridge-uri (linia ar deveni semnalul permanent al utilizatorului față de observatorul local; ordinea direct-întâi e cea mai puțin zgomotoasă când Tor merge).

## Teste

PT-U1 (tabelul de gramatici și refuzurile), PT-U2 (formele de configurare), PT-U4 (secvența modului auto ca politică pură peste transporturi imitate), PT-U5 (proprietatea validatorului), PT-U7 (round-trip-ul setare/listare prin biblioteca gazdă, fără logare); PT-P1 (canarul T58); porțile G-T7 (nicio linie în loguri) și G-T8 (gramaticile fixate; snowflake refuzat; APK fără linii reale).
