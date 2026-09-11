# ADR-18 — Stocare relay pe redb (Rust pur) în loc de RocksDB

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | Faza 5 (relay v1) |
| Modifică | Spec v2.0 §6.2 „Storage: RocksDB content-addressed blobs” și Appendix A |

## Context
Relay-ul are nevoie de un depozit embedded, tranzacțional, cu chei ordonate (indexuri pe namespace și pe expirare). RocksDB este C++ cu un graf de dependențe invizibil pentru `cargo-audit`/`cargo-deny`, cere toolchain C++ pe fiecare mașină de build și îngreunează build-ul reproductibil (ADR-07). Volumul relay-ului (blob-uri de max 64 KiB, TTL 90 zile, mii de blob-uri/s/nod ca țintă NFR-3) nu cere caracteristicile specifice RocksDB.

## Decizie
`ghost-relay-storage` folosește **redb** (embedded, ACID, Rust pur, licență MIT/Apache-2.0): tabelă `blobs` (hash → expirare ∥ minut-încărcare ∥ namespace ∥ date), index `namespace_index` (namespace ∥ secvență → hash) pentru cursoare opace, index `expiry_index` pentru prune determinist. Toate scrierile sunt tranzacționale; un blob există fie complet cu ambele indexuri, fie deloc.

## Consecințe
(+) tot graful de dependențe al relay-ului este auditat de `cargo-deny`/`cargo-audit`; build reproductibil fără C++; API simplu de revizuit. (−) redb este mai tânăr decât RocksDB: NFR-3 (≥ 1 000 blob-uri/s/nod) trebuie **măsurat** în Faza 15 și, dacă nu se atinge, se revine la RocksDB printr-o implementare alternativă a aceluiași `BlobStore` (interfața nu expune detalii de motor).

## Anexă 2026-09-11 — schema v2 (apartenență), după review-ul Fazei 6

Decizia de motor rămâne neschimbată; schema tabelelor se schimbă (constatarea 17 din `docs/reviews/2026-09-11-faza6-security-review.md` și regresiile găsite la verificarea ei):

| Tabelă | Cheie → valoare | Rol |
|---|---|---|
| `content` | hash → refcount ∥ date | ciphertext-ul, stocat o singură dată |
| `members` | namespace ∥ hash → expirare ∥ minut-încărcare ∥ secvență | apartenența unui blob la un namespace, cu expirare proprie |
| `namespace_index` | namespace ∥ secvență → hash | listare în ordinea inserării |
| `namespace_seq` | namespace → următoarea secvență | cursorul e per namespace: un cititor nu află nimic despre scrierile altor namespace-uri. Rândul se șterge odată cu ultima intrare de index a namespace-ului (nimic despre un namespace nu supraviețuiește blob-urilor lui); un namespace care revine pornește de la o sămânță orară, peste orice secvență folosită înainte, ca un cursor vechi să nu sară intrări noi |
| `expiry_index_v2` | expirare ∥ namespace ∥ hash → () | prune determinist, per apartenență |
| `meta` | `schema_version` → 2 | o bază scrisă de altă versiune (inclusiv schema v1 din Faza 5, recunoscută după tabelele `blobs`/`expiry_index`) este **refuzată**, nu reinterpretată |

Reguli: un blob e servit, verificat și listat doar printr-o apartenență **vie** în namespace-ul apelantului; un store peste o apartenență expirată o reînnoiește, iar un TTL mai lung extinde una vie. Orice store care creează, reînnoiește sau extinde o apartenență este taxat din cota capabilității **în aceeași tranzacție de scriere**, înainte de a persista ceva: un store peste cotă nu lasă nimic în urmă, iar reîncercarea lui e respinsă din nou (cota e rambursată dacă tranzacția nu se confirmă). Listarea examinează cel mult 1 024 de intrări de index pe apel, ca apartenențele expirate care așteaptă prune să nu transforme o listare într-o scanare nelimitată. Gossip-ul relay-relay folosește existența conținutului (`has_content`), independent de namespace — hash-urile sunt deja publice între relay-uri (TB-3), iar citirea cere în continuare o apartenență vie.

Completare după runda 3 de verificare (2026-09-11): expirarea stocată și returnată este rotunjită în sus la oră, deci nu mai dezvăluie secunda încărcării (TTL-urile sunt pe bucket-uri, iar `expirare − TTL` ar fi dat-o); un store repetat cu același TTL în aceeași oră este un no-op idempotent, fără o a doua taxare a cotei.
