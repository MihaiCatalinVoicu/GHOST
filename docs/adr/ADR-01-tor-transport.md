# ADR-01 — Transport anonim: Tor (Arti) și relay-uri ca onion services

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 FR-2.7, FR-5.6 (onion routing propriu), Faza 10 |

## Context
Onion routing propriu peste 3–5 relay-uri ale operatorului oferă un set de anonimat minuscul; primul hop vede IP-ul clientului; este un protocol de anonimat custom (contrar spiritului CP-09).

## Decizie
- Clientul Android încorporează Arti (Tor în Rust, prin JNI/UniFFI). Fallback acceptat: tor-android.
- Toate conexiunile (relay-uri, issuer, manifest de update) merg exclusiv prin Tor către adrese .onion v3 din manifestul semnat.
- Fără Tor: eșuare închisă — zero clearnet, zero DNS (test T6).
- Relay-urile acceptă trafic doar ca onion service; nu văd IP-uri structural.
- Gossip relay↔relay pe Noise (sau echivalent revizuit).
- Strat propriu de autentificare a cererilor (capabilități) independent de Tor.
- Padding pe bucket-uri înainte de trimiterea în Tor; circuit izolat per canal/scop.
- Bridges (obfs4/snowflake): P1.

## Consecințe
(+) set de anonimat = rețeaua Tor; fără DNS/IP expuse; fără protocol custom de auditat.
(−) latență (NFR-1 DM p95 < 5 s, NFR-2 post sync p95 < 8 s, măsurate); APK +5–10 MiB (NFR-4 < 80 MiB); dependență de Tor, atenuată prin bridges.

## Amendament documentar v2.2 - excepție locală limitată (2026-10-31)

Prin cererea proprietarului de a documenta mesh opțional, regula de mai sus se extinde exclusiv pentru comunicația locală explicit activată între dispozitive de contacte verificate. Cerințele sunt în [spec v2.2 §4-7](../GHOST_Technical_Specification_v2.2.md). Implementarea și porțile nu sunt validate prin acest amendament.

- Relay, issuer, entitlement, bootstrap și update păstrează transportul Tor existent; nu sunt expuse prin noul adaptor local. Un gateway separat autorizat poate retransmite ciphertext către relay numai prin Tor, cu drepturi limitate.
- Transportul local se leagă de rețeaua Android și endpoint-ul peer-ului autentificat; rendezvous QR/BLE într-o sesiune explicită, fără discovery în fundal, DNS/mDNS/SSDP, scanare de subnet, STUN/TURN, rută implicită sau fallback Internet.
- Modul local-only nu inițiază conexiuni GHOST la Internet; modul hibrid este separat și folosește Tor pentru extern. Pierderea căii locale închide socket-urile; reconectarea mesajelor cere handshake nou, iar apelul se termină.
- Excepția nu oferă anonimatul Tor: vecinul/interlocutorul local poate afla IP-ul local, proximitatea și timing-ul. UI declară diferența; verificarea unui contact nu dovedește onestitatea lui.
- T6 păstrează interdicția externă; extinderea viitoare a harness-ului trebuie să probeze exact excepția și zero egress interzis, cu fixture-uri negative. Rândul istoric T6 nu este marcat PASS pentru mesh.

## Completări după review-ul de securitate al Fazei 6 (2026-09-11)
Completări de implementare; decizia aprobată (Arti embedded, onion-only, izolare per scop) nu se schimbă.
- **Vanguards-lite activ** (feature `vanguards`, mod `Lite` fixat explicit în configurație). Toate circuitele GHOST se termină la onion service-ul unui operator de relay, exact adversarul (AD-1/AD-2) împotriva căruia vanguards-lite protejează garda clientului (Prop 333). Impus de gate-ul `rust-feature-policy.sh` și de un test unitar.
- **PoW pentru onion services:** relay-urile activează `HiddenServicePoWDefensesEnabled`, dar clienții nu rezolvă PoW încă (`hs-pow-full` e experimental în Arti și costă baterie). Consecință acceptată: la un flood de introduceri clienții GHOST stau în coada cu efort 0. Se reevaluează când feature-ul devine stabil; riscul e urmărit în `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` (L5).
- **API onion-only:** clientul Arti nu mai este expus în afara `client-core/net`; singura cale publică de conectare primește un `OnionAddress` validat complet (checksum v3). În crate, tonic e legat fără `Channel`, iar clippy interzice o listă de API-uri clearnet și DNS și orice conectare Arti în afara căii izolate (fiecare interdicție dovedită de un fixture negativ). Clienții HTTP generali sunt interziși în `deny.toml`, iar pachetele bibliotecii clientului sunt pe allowlist; acestea țin afară pachete nerevizuite, dar nu împiedică cod nou să folosească pachete permise pentru clearnet, de aceea T6 are și un test dinamic (Faza 13).
