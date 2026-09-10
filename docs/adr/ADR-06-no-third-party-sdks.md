# ADR-06 — Zero SDK-uri terțe; fără GMS/FCM/Firebase; allowlist de dependențe în CI

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 NFR-11 (crash telemetry), §11.1 |

## Decizie
Interzise în client: Google Play Services, Firebase, orice SDK de analytics, crash, atribuire, A/B. Sync prin WorkManager (+ foreground service opțional) prin Tor. Notificări locale fără conținut cât dispozitivul e blocat. Crash logs: local, criptat, trimis numai manual după scrubbing, prin Tor, fără SDK. Gradle dependency verification + allowlist explicită (`scripts/gates/dependency-allowlist.txt`); build-ul eșuează la orice dependență din afara listei (gate T7).
