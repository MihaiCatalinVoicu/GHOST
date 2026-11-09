# C0 — Selecția și verificarea motorului de apel (roadmap v2.2 §11)

Revizia 1, 2026-11-09. Autor: agent. Stare: **analiză + design de izolare propus**; experimentul
de verificare pe dispozitive rămâne DEVICE (două telefoane fizice). Cerințe: spec v2.2 §7
(C-01…C-09), probe CALL-01…06, NFR N-C1…3; non-obiective B0.

## 1. Selecția motorului

**Decizie propusă: libwebrtc construit din sursă, audio-only, în imaginea builder** — nu AAR
comunitar. Motivarea:

- Google nu mai publică un AAR Android oficial prebuilt; cea mai răspândită sursă de azi este
  furculița comunitară `getstream/webrtc-android` [Fora Soft, 2026-10-26]. Un binar third-party
  nepinned intră direct în conflict cu modelul nostru de supply-chain (ADR-37/38, deny.toml,
  build reproductibil, SBOM): nu acceptăm un `.so` pe care nu-l putem reproduce.
- Sursa upstream: `webrtc.googlesource.com/src`, licență BSD-3-Clause, branch-heads stabilite
  (ex. m137/m140+); construire cu `tools_webrtc/android/build_aar.py`, doar Linux, ~2-4 h,
  ~100 GB [optisol 2023; CSDN m137 2025-06; Khomenko 2025-08].
- **Audio-only**: GHOST nu are video (non-obiectiv B0). Configurare GN care exclude VP8/H264/AV1,
  captură video și rendering → suprafață de atac mult mai mică, licențe mai puține (fără libvpx),
  dimensiune cu ~40-60% mai mică decât build-ul complet.

Alternativa (respinsă acum, reevaluabilă dacă build-ul din sursă devine nesustenabil): forkul
Stream, pinned pe digest AAR, cu verificare de reproducer parțială — supply-chain mai slab.

## 2. Licențe și SBOM (C-08/H-08)

libwebrtc BSD-3-Clause. Dependențele relevante ale build-ului audio-only (toate permisive,
compatibile cu distribuția closed-source): abseil-cpp (Apache-2.0), opus (BSD), boringssl
(ISC + OpenSSL dual), libsrtp (BSD), webrtc-audio-processing (BSD), rnnoise (BSD), pffft (zlib).
Fără SDK RASP, fără packer, fără loader la runtime. Consecință directă: **notices-urile Android
(G-L1) cresc** — pipeline-ul `license-notices.sh android` primește componenta `libwebrtc` la M5.
Audit trail: versiunea exactă branch-heads + hash commit intră în SBOM și în jurnalul release-ului.

## 3. Procedura de update de securitate

Pinned pe branch-heads/mXXX; urmărirea advisory Chromium/WebRTC (mailing list + release notes);
rebuild în imaginea builder (aceeași disciplină ca Rust/JDK: versiunea intră în `pins.txt`);
upgrade-ul intră în jurnal ca orice schimbare de dependență nativă. Cost onest: build 2-4 h,
100 GB — de aceea se face la nevoie, nu noaptea; riscul de întârziere la un advisory e un reziduu
declarat aici.

## 4. Izolarea locală (C-03) — design, de verificat experimental

1. **Lista ICE servers goală** (`RTCConfiguration.iceServers = []`) → zero STUN/TURN.
2. **mDNS dezactivat** (candidații mDNS nu se generează; configurabil prin RTCConfiguration).
3. **ICE restart și migarea de interfață dezactivate** — pierderea căii termină apelul (spec §7);
   nu există renegociere automată.
4. **Filtrarea candidaților**: prin `onIceCandidate` + transformare SDP, supraviețuiesc numai
   candidații host ale căror adresă/port aparțin descriptorului peer-ului verificat (endpoint-ul
   din handshake-ul mesh + interfața selectată). Respingem explicit: orice adresă publică, alte
   gazde LAN, multicast, IPv6 în afara scope-ului autorizat, loopback.
5. **Legare de rețea**: socket-urile folosesc rețeaua selectată de M2; schimbarea interfeței = apel
   terminat, nu migrare.
6. **Egress**: modul local-only nu inițiază conexiuni GHOST la Internet; verificat prin captură
   (CALL-03) — experiment DEVICE.

Semnal de risc: libwebrtc are propriul allocator de rețea (nu e trivial de constrâns la un singur
endpoint), de aceea filtrarea candidaților e dublată de captură în M6 — nu declarăm izolarea
dovedită din design.

## 5. Autentificarea apelului (C-02, C-04, C-05)

- Semnalizarea trece prin plicul DM existent (canal criptic autenticat); transcriptul DM semnat
  leagă: call ID, roluri, ambele dispozitive, nonce-uri proaspete, expiry, hash offer/answer,
  **ambele fingerprint-uri DTLS** și setul complet de candidați acceptați (spec §7).
- Chei efemere per apel: generăm certificatul DTLS al PeerConnection-ului nostru (nu reutilizăm,
  nu derivăm din seed). Verificarea fingerprint-ului remote: hook de verificare SSL injectat
  (API nativ `SSLCertificateVerifier`), care acceptă **doar** fingerprint-ul din transcript.
  Replay/rol-schimbat/offer modificat → verificare eșuează → apel refuzat.
- Audio nu trece niciodată prin mesh queue/gateway/relay (C-04): calea media e directă, peer-to-peer.
- Fără claim PQ pentru audio (C-09): DTLS-SRTP clasic + efemer; plicul PQ DM protejează doar
  semnalizarea.

## 6. Impact NFR

- **Dimensiune APK**: build audio-only estimat +6-12 MiB/ABI comprimat (arm64-v8a + x86_64) →
  NFR-4 (<80 MiB) rămâne fezabil, dar se măsoară real la M5 (spec §9 nu relaxează automat).
- **N-C1** (stabilire ≤ 5 s p95), **N-C2** (latență ≤ 200 ms), **N-C3** (oprire captură ≤ 1 s):
  profilele se măsoară pe dispozitive (M6); jitter buffer limitat și degradare controlată la
  pierderi (C-06) se configurează din AudioProcessing.
- Foreground service cu tip `microphone` obligatoriu de la API 34+ pentru captură din fundal
  [Fora Soft 2026]; GHOST cere sesiune vizibilă oricum (M-01 mesh), deci nu e o relaxare.

## 7. Experimentul C0 (DEVICE — pașii, de executat când există două telefoane)

1. Build audio-only pinned într-un container reproducibil; digest în `pins.txt`.
2. Aplicație-spike (fără utilizatori/date): PeerConnection cu configurația §4; două telefoane pe
   același Wi-Fi; apel 1:1.
3. Verificări: `iceServers=[]`, zero candidați non-host, respingere candidat public/IPv6/multicast
   injectat prin semnalizarea falsificată (negativele CALL-02/03), captură 0 egress extern,
   latență măsurată buclă acustică (date inițiale pentru N-C2).
4. Dacă izolarea nu poate fi impusă → C0 rămâne blocat; nu se înlocuiește cu apel Internet și nu
   se improvizează protocol criptografic propriu (roadmap §11 ieșire).

## 8. Întrebări pentru decizie/review

- Q-C0-1: confirmarea build-ului din sursă (cost operațional ~2-4 h/upgrade, 100 GB în imaginea
  builder) vs. forkul Stream pinned — recomandarea noastră: sursă.
- Q-C0-2: ABI-urile livrate devin arm64-v8a (+x86_64 doar pentru emulator/teste) pentru NFR-4?
- Q-C0-3: hook-ul de verificare a fingerprint-ului DTLS (punctul 5) — acceptabil ca punct de
  audit pentru binding-ul C-02, sau se cere verificare suplimentară a SDP-ului?
