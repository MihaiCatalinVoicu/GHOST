# M1 — Protocolul mesh: wire format, grant-uri, state machine, schemă, vectori

Revizia 1, 2026-11-09. Autor: agent. **Stare: propus spre review criptografic** — protocolul se
îngheață abia după review (roadmap §7 ieșire; spec v2.2 §11: „protocolul wire … trebuie înghețat
în design și revizuite criptografic ÎNAINTE de cod"). Nimic din acest document este implementat.

Cerințele sunt în `docs/GHOST_Technical_Specification_v2.2.md` §4-5 (M-01…M-16, limitele §5.1,
contractul grant §5.2); probele MESH-01…09 din §11. Non-obiectivele B0 (§8 din B0_LEDGER_v2.2.md)
se respectă aici fără reiterare.

## 1. Modelul de adversar pentru domeniul local

Pe lângă adversarii existenți (THREAT_MODEL v2.1), domeniul mesh adaugă:

- **N1 vecin neverificat** poate vedea traficul radio local și poate încerca handshake, discovery,
  inventar, flood.
- **N2 contact verificat dar ostil** (dispozitiv compromis intenționat): poate păstra ciphertext,
  refuza livrarea, minți despre custodie, injecta cicluri, reactiva grant-uri vechi din backup.
- **N3 intermediar** (B transportă pentru A→C): vede metadatele outer envelope (mărime, timing,
  handle), nu vede plaintext, nu poate confirma existența obiectelor fără grant; poate minți despre
  custodie — de aceea custody ACK ≠ delivery ACK (M-10).
- **N4 observator LAN pasiv** vede MAC-uri, timpi, mărimi; nu primește identități GHOST, canale
  sau contacte (M-04). Limitele MAC/OS se documentează la M0 (reziduu explicit).

## 2. Identități și separarea lor (M-02, M-03, M-04)

| Identitate | Cheie | Durată | Expune |
|---|---|---|---|
| **Identitate verificată** | Ed25519 din seed-ul identității (ADR-17), per identitate + per dispozitiv (`verified_device`) | permanentă, revocabilă prin epoch | numai după verificare reciprocă (QR/amprentă pe canal independent) |
| **Cheie de rol mesh** | Ed25519 derivată prin HKDF din seed, domeniu `ghost.mesh.device-sign.v1` | rotită la schimbarea cheii identității | semnează grant-uri și ACK-uri; fără legătură cu pseudonimele de canal |
| **Identitate de discovery** | X25519 efemeră per sesiune de rendezvous | minute | QR/BLE rendezvous în sesiune explicită; niciun identificator permanent, niciun byte GHOST înainte de handshake autentificat |
| **Handle de transport** | PRF per grant+epoch (§5) | epoch | inventarul pereche/scop; nu e hash global |

Reguli: invitația în aplicație sau numele afișat nu verifică nimic (M-02). A-B și B-C verificate
nu îl verifică pe C pentru A — fiecare legătură se autentifică separat, iar destinatarul final
autentifică expeditorul original prin plicul DM interior (M-03, M-05).

## 3. Wire protocol (M-05, M-07, M-08)

### 3.1 Framing și limite

- Transport: stream TCP sau datagrame QUIC/DTLS peste calea locală — alegerea finală la M2 după
  M0; protocolul e identic deasupra.
- Frame: `header(8B: magic 'GHM1' | type u8 | reserved u8 | length u32be) || payload`,
  `length ≤ 69632` (68 KiB §5.1: fragment ciphertext ≤ 64 KiB + ≤ 4 KiB overhead). Parsare cu
  limite ÎNAINTE de alocare (M-08): length validat contra cotă per grant și plafonul global înainte
  de orice `alloc`.
- Cotele de trafic numără întregul frame. Mesajele de control nu depășesc 1 KiB.

### 3.2 Tipuri de mesaj

`HELLO` (versionare), `HANDSHAKE` (§4), `GRANT` (§5, doar după handshake autentificat),
`GRANT_REVOKE` (epoch semnat monoton), `INVENTORY` (handles PRF, numai după autorizare),
`OBJECT` (outer envelope, §6), `CUSTODY_ACK` (§7), `DELIVERY_ACK` (§7), `PING/GOODBYE`.

### 3.3 Versionare și downgrade

- `HELLO.versions = [1]` astăzi; ambele capete aleg max comun; lipsa comună → închidere.
- Downgrade sub versiunea minimă acceptată de fiecare capăt → refuz explicit (MESH-04). Transcript-ul
  (toate frame-urile handshake + GRANT) intră în hash-ul de sesiune, deci un rollback al
  conversației e detectabil ca transcript diferit.

### 3.4 Encoding canonic

Câmpurile semnate folosesc același stil ca GHRT (F14 §4): text canonic cu prefix de lungime,
un câmp per linie, fără ambiguități de whitespace. Payload-urile binare (object frames) sunt
exterior encoding-ului canonic; hash-ul lor intră în câmpuri semnate ca hex.

## 4. Handshake (M-05)

Recomandare: **Noise XX** prin `snow` (pure-Rust, `no_std`, revizuită larg; propunere de
dependență nouă — intră prin allowlist + rust-feature-policy + audit, alternativa este un handshake
SIGMA construit peste curve25519-dalek/Ed25519 deja din graf, dar un protocol home-grown e mai
puțin revizuit și spec v2.2 cere „biblioteci revizuite”).

- Pattern **XX 25519+ChaChaPoly+BLAKE2s**: anonimat față de observator până la finalul handshake.
- La finalul Noise, fiecare parte atașează **semnătura Ed25519 a cheii de rol mesh** peste
  transcript hash — autentificare de identitate verificată + legare de dispozitiv, rol și versiune.
- Rezultat: două canale criptice cu forward secrecy; dedesubt circulă envelope DM nemodificate
  (fără recriptare de conținut la hop — M-05).
- Anti-DoS §5.1: maximum 2 handshake neautentificate în curs, 10 inițieri/minut/dispozitiv,
  backoff până la 5 min; handshake-urile între contacte deja autentificate nu sunt blocate.
- Respingere (MESH-02/04): peer neverificat, alt dispozitiv decât cel din grant, grant expirat,
  rol schimbat, fingerprint diferit de cel verificat → `GOODBYE` cu cod, socket închis.

## 5. Grant-ul (M-03, contract §5.2)

Document semnat (encoding canonic §3.4), câmpuri obligatorii:

```
gh-grant/v1
id:            random 16B (hex) — unic per emitent, nu derivat din identitate
epoch:         u64 monoton crescător per (emitent, recipient)
issuer:        cheie publică de rol mesh a emitentului (Ed25519, 32B)
recipient:     cheie publică de rol mesh a destinatarului
devices:       ambele device IDs verificate (hash de cheie, nu nume)
operation:     communicate | forward | gateway   (exact una)
scope:         object selectors (conversation ids PRF-derivate; nu liste de contacte)
expiry:        unix seconds; ≤ 24h de la emitere (§5.1), fără reînnoire implicită de intermediar
limits:        bytes_total, objects_total, bytes_per_sec, hop_limit (≤3 legături, ≤2 intermediari)
nonce:         16B proaspete per grant — anti-replay la re-prezentare
signature:     Ed25519 peste canonical body (toate liniile de mai sus)
```

Reguli: direcțional, netransferabil, nedelegabil; un token de relay nu se reutilizează niciodată
ca grant mesh (§5.1). Verificarea: semnătura, epoch > ultimul epoch acceptat (anti-rollback),
expiry împotriva ceasului local, limite înainte de alocare. **Clock rollback fail-closed**: starea
persistată ține `max_epoch_seen` și `max_time_seen` monotone; un ceas înapoi nu reînvie grant-uri
(acceptarea noilor forwarding-uri se oprește conservator până la timp verificabil — M-13).

**Revocare**: `GRANT_REVOKE` = același corp semnat cu `revoked_epoch: N`; aplicat imediat local;
cozile existente nu se livrează automat cheii noi (M-12) — expiră prin regulile proprii.

## 6. Inventarul și obiectele (M-06, M-07)

- Handle de inventar: `PRF(mesh-inventory-key, grant_id || epoch || object_id)` — cheia de
  inventar derivată per grant prin HKDF (`ghost.mesh.inventory.v1`). Peer fără grant nu poate
  confirma existența unui obiect (răspuns uniform la orice handle). Fără Bloom global, fără
  broadcast de hash-uri stabile (M-06).
- Outer envelope `OBJECT`: `gh-object/v1` — outer_id (16B aleatoriu per copie), grant_id, hop_count,
  inner_expiry, ciphertext = envelope DM existant (interior neschimbat, autenticat de expeditorul
  original). Hash-ul de integritate outer nu e autentificare a expeditorului (M-07): originea e
  dovadă doar din plicul interior. Duplicat, tamper, substituție de expiry sau reînviere prin
  schimbare outer_id = refuz (MESH-04).
- Copii active: ≤ 2 următori vecini autorizați per obiect și per dispozitiv onest (§5.1); un peer
  modificat își poate copia propriul ciphertext — declarat, neprevenibil (M-11).

## 7. ACK-uri (M-10)

- **Custody ACK**: semnat de hop-ul care primește custodia, legat de `outer_id + grant_id + hop`;
  acoperă doar „am preluat”. Un intermediar poate minți — nu marchează livrat.
- **Delivery ACK**: semnat de **dispozitivul destinatar** doar după commit durabil în inbox
  (aceeași tranzacție cu acceptarea mesajului), legat de ID-ul mesajului interior + dispozitiv +
  încercarea de transfer. Numai acesta permite ștergerea automată a copiei din outbox pe motiv de
  livrare. Receipt-urile dezactivate ⇒ aplicația nu inventează starea „livrat”.
- Receipt-ul de destinație, când există, circulă opac pentru intermediari.
- Contraexemplu testat (roadmap §7): B pretinde livrarea la C fără delivery ACK de la C → A păstrează
  copia; expirare normală.

## 8. State machine (custody / delivery / expiry)

```
OFFERED --(dedup ok, grant ok, cote ok)--> RECEIVING --(commit inbox)--> DELIVERED
   | replay/duplicat/expirat            | crash mid-receive
   v                                    v
DUPLICAT_REFUSED (no state)          STALE_PARTIAL (reîncepe; idempotent prin inner ID)
COPIED --(custody ack la următor)--> FORWARDING --(delivery ack destinatar)--> PURGED(outbox copy)
  | grant revocat / expiry            | refuz bounded
  v                                   v
PURGED la expirare                  EXPIRED (retenția = min(timer mesaj, grant, plafon 24h))
```

Dedup/replay persistă peste restart și rotații (MESH-06): `mesh_transfer` ține `outer_id` +
`inner_id` + `max_epoch_seen`; limitele se verifică înainte de alocare/decriptare.

## 9. Schemă SQL (propunere; migrațiile exacte la M2/M3)

Peste SQLCipher existent, stil schema U (triggere write-once, FK, tranzacții):

```sql
verified_device(device_pk BLOB PRIMARY KEY, identity_fk REFERENCES identity NOT NULL,
                label TEXT, verified_at INTEGER, revoked_epoch INTEGER, state BLOB NOT NULL);
mesh_grant(grant_id BLOB PRIMARY KEY, epoch INTEGER NOT NULL,
           our_device_fk REFERENCES verified_device NOT NULL,
           peer_device_fk REFERENCES verified_device NOT NULL,
           operation TEXT NOT NULL CHECK(operation IN ('communicate','forward','gateway')),
           scope BLOB NOT NULL, expiry INTEGER NOT NULL, limits BLOB NOT NULL,
           peer_sig BLOB NOT NULL, UNIQUE(our_device_fk, peer_device_fk, epoch));
mesh_queue(object_inner_id BLOB PRIMARY KEY, conversation_id BLOB NOT NULL,
           envelope BLOB NOT NULL, expires_at INTEGER NOT NULL, retention_floor INTEGER NOT NULL);
mesh_transfer(outer_id BLOB PRIMARY KEY, grant_id REFERENCES mesh_grant, hop_count INTEGER NOT NULL,
              inner_id REFERENCES mesh_queue, custody_state TEXT NOT NULL,
              last_attempt INTEGER, UNIQUE(grant_id, inner_id, copy_index));  -- copy_index ≤ 2
mesh_receipt(message_id BLOB PRIMARY KEY, from_device_fk REFERENCES verified_device,
             attempt BLOB NOT NULL, sig BLOB NOT NULL, received_at INTEGER NOT NULL);
mesh_policy(enabled INTEGER NOT NULL DEFAULT 0, mode TEXT CHECK(mode IN ('off','local-only','hybrid')),
            forwarding INTEGER NOT NULL DEFAULT 0, gateway INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL);
```

Reguli: nicio cheie media în clar (M-09); cozile ciphertext; restore-ul nu reactivează grant-uri
vechi (reverificare obligatorie — spec §10); backup/rollback nu resetează replay protection.

## 10. Vectori de test (structură; setul complet la înghețare)

Fiecare vector: nume, chei fixture (hex), intrare canonică, ieșire așteptată, motiv.
Grupuri: handshake transcript (inclusiv downgrade + rol schimbat), grant semnat/rezumat greșit/
epoch rollback/expirat, envelope outer tamper/duplicat/expiry schimbat, custody vs delivery ACK
(falsificat de intermediar), inventar handle neautorizat, clock rollback. Formatul fișierelor:
`protocol/test-vectors/mesh_*.txt`, golden ca la wire_transcript.txt.

## 11. Matrice adversarială (MESH-01…09 → mecanism)

| Proba | Mecanismul care o satisface |
|---|---|
| MESH-01 (OFF zero activitate) | modul OFF nu deschide sockets/advertising; `mesh_policy` persistat; restart nu reactivează |
| MESH-02 (contact fals, trust tranzitiv) | verificare QR pe canal independent; handshake cu semnătura cheii de rol; grant per legătură |
| MESH-03 (identitate/canale în captură) | discovery efemer fără bytes GHOST; handles PRF; nimic de logat (M-15) |
| MESH-04 (MITM/replay/downgrade/tamper) | Noise XX + transcript hash; versionare; envelope interior autenticat; limite framing |
| MESH-05 (flood, identități rotite, bounded) | cote §5.1; plafon global înainte de alloc; backoff handshake |
| MESH-06 (crash/disc plin/restart) | state machine §8; dedup persistent; commit atomic |
| MESH-07 (blackhole/rută falsă) | custody ≠ delivery; retry finit; queued/expired, nu succes |
| MESH-08 (revocare/reboot/ceas înapoi) | epoch monoton + fail-closed §5 |
| MESH-09 (gateway fără grant; zero egress) | gateway = grant separat `operation=gateway`; Tor pentru extern; T6 extins §12 |

## 12. Contractul T6 extins (ADR-01 amendat)

Harness-ul T6 distinge: trafic GHOST extern = doar Tor (ca azi); excepția locală = socket-uri
legate la endpoint-ul descriptorului peer-ului verificat, pe rețeaua selectată, în sesiune
autorizată — zero DNS/mDNS/SSDP/STUN/TURN/Internet. Fixture negative noi: candidate IP străin,
DNS lookup, fallback celular, discovery în fundal. Rândul istoric T6 rămâne ne-PASS pentru mesh
până la M6.

## 13. Întrebări pentru review-ul criptografic

1. Noise XX + semnături de rol pe transcript — acceptabil vs. pattern IK (publicitatea cheii
   statice la initiator este acceptabilă aici? recomandarea noastră: XX, pentru că discovery-ul
   nu trebuie să publice identitatea).
2. `snow` ca dependență nouă: pin, allowlist, FIPS nu e relevant — confirmare.
3. PRF inventory: HKDF-SHA256 cu domenii separate suficient, sau cerem HMAC construction explicit?
4. Delivery ACK: legarea de „încercarea de transfer” — forma exactă (attempt counter + nonce)
   pentru a opri replay-ul ACK-ului pe altă copie.
5. Ceas: expirările pe unix seconds cu fail-closed la rollback — suficient, sau cerem logica
   „timp verificabil” (epoch-uri semnate) pentru grant-uri?
6. Gateway: autorizare separată `operation=gateway` cu scope pe obiect — confirmare că drepturile
   limitate la obiect nu permit enumerare.
