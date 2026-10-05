# ADR-57 — Componente și permisiuni noi: notificări, camera pentru QR, zxing, legături `ghost://`

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-10-05 de proprietar (propus 2026-10-03; designul aprobat cu valorile implicite) |
| Completează | ADR-06, ADR-05, ADR-10 (setul de permisiuni T15), T15m, T16 |
| Modifică | designul Fazei 11 Q15 („CameraX în Faza 13”) și fraza despre selectorul de fotografii; designul Fazei 9 §8.4 (un card scanat e „în persoană” doar când utilizatorul spune asta); nota din `MessagingPorts.kt` despre ADR-ul permisiunii de notificare |

**Context.** Interfața are nevoie de notificări, de scanarea codurilor QR (invitații, carduri, numere de siguranță, canale) și de legături `ghost://`, fără SDK-uri terțe, fără biblioteci native noi și fără componente exportate noi. Camera nu poate deosebi telefonul unei persoane de o fotografie a codului primită prin altă aplicație.

**Decizie.**
1. `POST_NOTIFICATIONS` (deja în lista T15) se declară și se cere la sfârșitul onboarding-ului (API 33+), după ce utilizatorul vede exact textul notificării.
2. `CAMERA` (în lista T15) se declară, cu `android.hardware.camera` neobligatoriu, doar pentru scanarea codurilor QR în fereastra securizată, prin Camera2 al platformei; fără CameraX, fără aplicația de cameră a sistemului, fără ML Kit. **După scanarea unui card, aplicația întreabă unde a fost arătat codul**; doar „pe telefonul persoanei, în fața mea” îl înregistrează ca scanat în persoană (verificat); implicit e „nu știu”, adică un link neverificat.
3. `com.google.zxing:core` 3.5.4 (Apache-2.0, fără dependențe la rulare) intră în allowlist (grupul `com.google.zxing`), cu notificare și sume în `verification-metadata.xml`. Suma de control afișată pentru un link (8 caractere) arată doar că linkul nu e deteriorat, nu cine l-a trimis.
4. Activitatea de lansare primește filtre `VIEW` pentru schema `ghost` cu gazdele `invite`, `contact` și `channel`; fără `http` sau `https`, fără `autoVerify`; cu `launchMode="singleTask"` și `persistableMode="persistNever"`, ca sistemul să nu păstreze linkul în înregistrările task-urilor; după citire, activitatea se relansează într-un task curat; legăturile sunt intrări neîncrezute.
5. `USE_BIOMETRIC` (în lista T15) pentru deblocare, prin `BiometricPrompt` al platformei; fără `androidx.biometric`.
6. Selectorul de fotografii e al platformei, unde există; altfel `ACTION_OPEN_DOCUMENT`, direct, niciodată varianta de rezervă pe care o implementează serviciile Google Play.
7. Dependențe doar pentru teste: Robolectric 4.17 (MIT), AndroidX Test (doar în modulul de test `:app-uitest`), Accessibility Test Framework 4.1.1; absente din graful release (G-U7).

**Consecințe.** (+) Nicio bibliotecă nativă nouă și nicio componentă exportată nouă; (+) un cod QR primit ca fotografie nu mai devine „verificat”. (−) Cod propriu pentru previzualizarea camerei; (−) o întrebare în plus după scanarea unui card; (−) o altă aplicație poate revendica schema `ghost://` și intercepta un link deschis din afara GHOST (reziduu L11-U13; QR-ul în persoană rămâne calea recomandată).

**Alternative respinse.** CameraX (bibliotecă nativă nouă), ML Kit (Google Play services), zxing-cpp (nativ), intentul camerei sistemului (o aplicație terță vede imaginea); foaia de partajare; `androidx.biometric` (cere `FragmentActivity`); contractul `PickVisualMedia` de la AndroidX așa cum e (poate ajunge la serviciile Google Play); orice scanare înregistrată automat ca „în persoană”.

**Teste.** G-U2, G-U7, G-U10, G-U11, T15m, T16; testul de proveniență; verificările V-U8, V-U31, V-U34.
