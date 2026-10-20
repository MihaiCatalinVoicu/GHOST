# Dry-run mecanic J1–J6 — raport (2026-10-20)

**Ce este:** completarea mecanică a călătoriilor P0, pe JVM, peste motoarele reale și gateway-uri
înregistratoare, plus porțile statice. Componenta umană (comprehension, erori născute din
neînțelegere, timp de tastare de către om) NU este acoperită aici — ea rămâne rundei formativă și
celel summative anonime (amendamentul de poartă, 2026-10-20). Pragurile Q42 se aplică doar măsurătorilor
umane.

**Rezultat:** `:app:testDebugUnitTest` — 132 de teste, 0 eșecuri, 0 erori (26 de fișiere de suită),
pe `main` la `55b925b7`. Compile `:ui` și `:messaging` (inclusiv sursele de test) verzi.
Porțile run-all au stat 41/41 verzi la ultimul merge; suitele de emulator (smoke, accessibility,
ATF, inventory) verzi la API 29 și 35.

## Maparea călătoriilor pe dovezi

| Călătorie | Acoperire mecanică (suitele :app) |
|---|---|
| J1 onboarding + cuvinte | `OnboardingModelTest` (mașina de stări D36), `RestoreModelTest` (ceasul NFR-10 al copiei), `IdentityGatewayAdapterTest`, `SettingsSecurityModelsTest` (blocarea PIN), `LockControllerTest` |
| J1 restore | `RestoreModelTest`, `WipeCrashTest` + enumerarea CS-U1; timpul de tastare mecanic nu înlocuiește timpul uman (NFR-10 rămâne al summativului) |
| J2 acces/plată | `PaymentModelTest` (READY/UNDERPAID, bracketul shown/hidden), `AccessGatewayAdapterTest`, `WhoSeesWhatModelTest` (rândul issuer) |
| J3 contact/mesaj | `ContactAddModelTest` (proveniența D34), `DmGatewayAdapterTest`, `MessagingWiringTest`, `GhostNotifierTest`, `DesignTokensTest` |
| J4 canal cu parolă | `ChannelModelsTest` (cele 5 modele J4), `ChannelGatewayAdapterTest` (expansiunea parolei, cap-ul de 7 zile), `ChannelRejoinTest` pe lumea reală (:messaging, 17 teste) |
| J5 media | `MediaModelsTest`, `MediaGatewayAdapterTest` (sniff 64 B, video vs. imagine) |
| J6 versiunea | `WhoSeesWhatModelTest` (rândul oglinzilor), `AboutScreen` compus cu versiunea primită din `:app`; install-ul efectiv așteaptă Faza 14 (declarat în scenariu) |

## Limitele acestui raport (declarate, nu ascunse)
- Nu măsoară înțelegerea, SUS-ul sau erorile născute din neînțelegere.
- J3–J5 nu au rulat cap-coadă cu relee reale: staging-ul (OA-3) nu e deployat; lumea reală a
  canalelor a rulat pe harness-ul JVM de fază. Runda cu staging rămâne de făcut după OA-3.
- Suitele de emulator acoperă platforma, nu călătoria completă cu date reale.
