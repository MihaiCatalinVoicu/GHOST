# ADR-18 — Stocare relay pe redb (Rust pur) în loc de RocksDB

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-10 — aplicat sub rezerva aprobării în Faza 5 |
| Sursă | Faza 5 (relay v1) |
| Modifică | Spec v2.0 §6.2 „Storage: RocksDB content-addressed blobs” și Appendix A |

## Context
Relay-ul are nevoie de un depozit embedded, tranzacțional, cu chei ordonate (indexuri pe namespace și pe expirare). RocksDB este C++ cu un graf de dependențe invizibil pentru `cargo-audit`/`cargo-deny`, cere toolchain C++ pe fiecare mașină de build și îngreunează build-ul reproductibil (ADR-07). Volumul relay-ului (blob-uri de max 64 KiB, TTL 90 zile, mii de blob-uri/s/nod ca țintă NFR-3) nu cere caracteristicile specifice RocksDB.

## Decizie
`ghost-relay-storage` folosește **redb** (embedded, ACID, Rust pur, licență MIT/Apache-2.0): tabelă `blobs` (hash → expirare ∥ minut-încărcare ∥ namespace ∥ date), index `namespace_index` (namespace ∥ secvență → hash) pentru cursoare opace, index `expiry_index` pentru prune determinist. Toate scrierile sunt tranzacționale; un blob există fie complet cu ambele indexuri, fie deloc.

## Consecințe
(+) tot graful de dependențe al relay-ului este auditat de `cargo-deny`/`cargo-audit`; build reproductibil fără C++; API simplu de revizuit. (−) redb este mai tânăr decât RocksDB: NFR-3 (≥ 1 000 blob-uri/s/nod) trebuie **măsurat** în Faza 15 și, dacă nu se atinge, se revine la RocksDB printr-o implementare alternativă a aceluiași `BlobStore` (interfața nu expune detalii de motor).
