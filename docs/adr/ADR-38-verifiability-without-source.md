# ADR-38 — Verificabilitate fără sursă publică

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-27 de proprietar (propus 2026-09-16, aplicat în Faza 9; decizia proprietarului pe Q4; condiții de lansare) |
| Sursă | R-license §8; design Faza 9 (`docs/design/faza9-dm.md`) §2.9, §2.10.4, §9.5, §22 |
| Înlocuiește | din ADR-07, fraza din plan „Fără open-source, CP-10 nu poate fi îndeplinit pentru utilizator” (plan:202); FR-8.9, a doua jumătate (precizată) |
| Completează | CP-08, CP-09, CP-10, FR-8.2, FR-8.8, spec §12.2, ADR-11, ADR-22, THREAT_MODEL (AD-9, TB-6, adversar nou AD-V), LIMITE (L-SRC = L7-D23), INVARIANTS T12 (T12b) |

## Context
Fără sursă publică, utilizatorul nu mai poate verifica singur afirmațiile. CP-10 cere în continuare ca orice afirmație să fie trasabilă la teste, măsurători sau audit; dovezile trebuie deci să fie publice, iar un build rău-intenționat sau țintit nu trebuie să ajungă nevăzut la utilizatori. Construcțiile proprii ale Fazei 9 (sigiliul DM, legătura v3, modul provizoriu, compunerea PQ, selecția sesiunilor, encoderul de pickle, numărul de siguranță) nu au altă evaluare independentă decât revizia externă.

## Decizie
1. **Audituri externe cu rapoarte complete publicate**, înaintea primei distribuiri publice și la fiecare versiune majoră: protocol și criptografie (inclusiv versiunea fixată vodozemac și folosirea ei, integrarea libcrux, `ghost-client-dm`), client Android, relay și issuer, pipeline-ul de build. Retestările se publică.
2. **Analiză formală publicată:** modelul ProVerif al DM (ADR-36), modelele de stare EM-1 și EM-2 și modelele pentru adresarea oarbă și cheile de depunere.
3. **Revizia criptografică externă a compunerii DM** (ADR-36 punctul 5) e condiție de lansare, cu raport publicat.
4. **Acces la sursă** pentru auditori și cercetători verificați, sub licență de utilizare limitată; program de recompense din beta controlată.
5. **Build reproductibil verificat de auditor:** auditorul reconstruiește commit-ul etichetat în imaginea cu căi fixe (Faza 14) și semnează hash-urile APK-ului, ale bibliotecilor native și ale binarelor relay și issuer (T12b).
6. **Jurnal de transparență binară** cu martori; actualizatorul refuză un APK fără dovadă de includere și checkpoint cosemnat (invariant nou în Faza 14). Verificarea actualizatorului nu acoperă prima instalare, actualizările livrate de un magazin și binarele relay și issuer rulate de operatori (§22.8.8): se publică un verificator independent pentru prima instalare; versiunile relay și issuer intră în jurnal și în atestările T12b, iar operatorii le verifică înainte de rulare; independența operatorilor (ADR-11) nu protejează împotriva AD-V.
7. **Depozit public separat**, cu istoric curat și licență permisivă: specificația protocolului DM, vectorii de test, `allowed-observables.json`, modelul, verificatorul pentru prima instalare, kitul de verificare black-box (trafic doar onion; treptele văzute prin propriul card exportat și un client de releu publicat; manifest și biblioteci native). Kitul nu poate verifica P-1 … P-8 și nici T1 la relee.
8. **Dovezi publicate per versiune:** modelul de amenințări, matricea de garanții, limitele reziduale, SBOM, rezultatele porților (T1–T35, mutanți, statistici T2/T32).
9. **Închis, auditat și întărit la analiză - amendament documentar v2.2, 2026-10-31:** release-ul folosește R8 shrinking/optimization/obfuscation, fără `-keepnames` global pe `org.ghost.**`; numai excepții înguste justificate pentru JNI/reflection/serializare. Simbolurile native inutile sunt eliminate din artefact. Mapping R8 și simbolurile complete se păstrează separat, privat, cu acces controlat pentru auditori și diagnostic autorizat; hash-urile lor sunt legate de hash/versionCode și de dovezile release-ului. Auditorul reproduce artefactul minificat/strip-uit; publicarea atestărilor, SBOM, rapoartelor, vectorilor și jurnalului rămâne obligatorie. Acest punct înlocuiește explicit cerința anterioară de nume `org.ghost.**` neobfuscate și simboluri publicate; formulările istorice din designul Fazei 9 trebuie reconciliate la H0. Nicio măsură nu garantează imposibilitatea decompilării și nici nu înlocuiește verificarea independentă; implementare și validare încă necesare. Vezi [spec v2.2 §8](../GHOST_Technical_Specification_v2.2.md).
10. **Escrow de sursă** per versiune, cu hash-ul în jurnal și condiții publice de eliberare.
11. **Afirmații în UI:** interzise „open source”, „sursă deschisă”, „verificabil de oricine”, „auditat” fără raport numit; permise doar afirmațiile legate de o dovadă publicată, alături de reziduul „Nu puteți verifica singuri codul sursă; vă bazați pe auditorii numiți și pe jurnalul public.”
12. **Model de amenințări:** adversar nou AD-V (furnizorul, un insider sau un furnizor constrâns livrează un build rău-intenționat sau țintit); reziduu L-SRC. Cu sursă închisă, operatorul din AD-1 („poate publica versiuni noi”) și furnizorul din AD-V sunt în practică aceeași parte: garanțiile P-1 … P-8 și orice formulare „Operatorul nu poate …” sunt valabile doar pentru build-ul din jurnal, reprodus de auditori (§1.3, §22.8.8).

## Consecințe
(+) Un build țintit nu poate ajunge prin actualizatorul verificat fără să fie public în jurnal (prima instalare, magazinele și binarele operatorilor au doar atenuările din punctul 6); afirmațiile rămân trasabile; specificația, vectorii și modelele pot fi verificate de oricine, iar comportamentul binarului livrat e atestat doar de auditorii numiți și de jurnal. (−) Încrederea în sursă trece la auditori și martori; un defect sau backdoor din sursa auditată care scapă auditului nu e exclus; costuri externe recurente; închiderea diferenței de reproductibilitate între medii devine condiție pentru prima distribuire.

## Alternative respinse
Doar un rezumat al auditului (insuficient; analiza Threema de la USENIX Security 2023 arată că auditurile singure nu ajung); deschiderea sursei doar pentru nucleul de securitate acum (contrar deciziei proprietarului; reevaluată după primul audit, Q61); fără jurnal de transparență (un build țintit ar rămâne nevăzut).
