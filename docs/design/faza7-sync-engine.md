# GHOST Phase 7: Sync Engine — Final Design

| Field | Value |
|---|---|
| Status | **Approved for implementation** ("începe Faza 7", 2026-09-11) with the §11 corrections and defaults; ADR-20 propus |
| Date | 2026-09-11 |
| Phase | 7: "Sync engine: outbox/inbox idempotent, WorkManager, cursors opace, jitter, retry" (Android track) |
| Depends on | Phase 4 (`ghost/android/storage`), Phase 6 (`ghost/android/network`, `ghost/client-core/net`) |
| Exit gate | "offline/reconnect/process-death fără pierderi sau duplicate" |
| Basis | The winning design "correctness". This version fixes every finding the three judges raised against it, fixes three further gaps found while re-verifying it against the repository, and grafts ideas from "privacy" and "platform" where they add no scope beyond Phase 7 (§0.3). |
| ADR impact | **ADR-20 (propus)**, draft in Appendix A. It covers: JobScheduler instead of WorkManager and coroutines; two permissions; per-(relay, namespace) schedules as the reading of ADR-09 and ADR-15; the NFR-1 conflict; the on-device dedup residue compared with THREAT_MODEL AD-8; the outbox store window and its outcomes. There is also an **ADR-19 addendum** (Appendix B), which records completions and changes no decision. |
| Sources verified | Master Plan v2.1 §3, §6.2, §6.6; spec v2.0 PDF (FR-7.x "Background synchronization MUST use WorkManager and coroutines…", §6.1 module table, NFR-1/5); ADR-06/09/11/15/19; THREAT_MODEL_v2.1 §3 (AD-2/4/5/8), §6, S3; LIMITE L1/L2/L5; INVARIANTS.md T1–T18; STATUS.md; Phase 6 review "Note pentru fazele următoare"; `storage/{Schema,SqlExecutor,MigrationRunner,GhostDatabase,Repositories}.kt`, `storage/src/test/{JdbcSqlExecutor,SchemaAndMigrationTest}.kt`; `network/{TorRelayTransport,OnionAddress}.kt`; `client-core/net/src/{relay_client,jni_bridge,categories,isolation,transport}.rs`, `client-core/README.md`; `relay/crates/{storage,node,capability,api}`; `protocol/relay/v1/relay.proto`; `scripts/gates/*`; `libs.versions.toml`, `verification-metadata.xml`, `~/.gradle/caches`; the merged release manifest; the `work-runtime:2.11.2` POM (fetched from dl.google.com). Appendix C separates what was verified from what is assumed. |

---

## 0. Summary

### 0.1 Decisions

| # | Decision | Plan alignment |
|---|---|---|
| D1 | The engine is Kotlin in `android/sync`. Its core is pure JVM, behind ports for relay, transport, clock, randomness and SQL. Rust receives small completions: `NamespaceClient` (namespace bound by type, capability-scope guard), `check()` over JNI, a per-call deadline, and `get` that also returns the relay's expiry. | ADR-19 (Appendix B addendum). §6.6 places `sync/` in Android. |
| D2 | Idempotency comes from content addressing. The ciphertext is frozen at enqueue and the same bytes are sent on every retry. `(namespace, blob_hash)` is unique locally and is one membership on each relay. | FR-5.x |
| D3 | Crash model: a write-ahead lease, then one result transaction. A crash is treated like an ambiguous timeout. One idempotent statement normalizes stale leases when a session starts. | new |
| D4 | Each op is written to every active relay in the namespace's relay set. It is **`sent` once at least 2 distinct operators have *verified* copies**: the hash must appear in the relay's inventory (a listing or `check`) after its receipt. | ADR-11, THREAT_MODEL S3 |
| D5 | **No op is ever reported `failed` while a copy may exist.** The outcomes are `sent`, `degraded` (at least 1 verified copy but under quorum), `failed` (no copy was ever possible) and `indeterminate` (an unverified copy may exist or may have existed). A **store window** of 7 days from the first possible copy bounds how far apart copies of one op can be in time. Offline time and unreachable relays never close an op that has no copy. | new |
| D6 | Inbox: one cursor per (relay, namespace). A page's hashes and its cursor commit in **one transaction**. An empty `next_cursor` keeps the old cursor ("sticky tail"). Each event reads 1 page in HIGH mode and at most 4 in STANDARD. Dedup is on `(namespace, blob_hash)`. **Tombstone retention is tied to the relay's own expiry** (expiry + 24 d) and stored at day granularity. | ADR-09, Phase 6 note |
| D7 | Consumer contract: pull, with a conditional effect in the consumer's own transaction. `release()` and `markConsumed()` return true exactly once. A write-ahead offer counter backs off poison blobs and never drops them. | new (API for Phases 9–11) |
| D8 | SQL triggers in the production schema enforce the state machines. `verifyIntegrity()` refuses a schema with a missing trigger or with `foreign_keys` off. | Schema.kt philosophy |
| D9 | Scheduling uses **one activity-independent periodic JobScheduler job**, plus an in-process driver while the app is visible. **WorkManager and coroutines are not used.** The foreground service ("prompt mode") is deferred to Phase 13. | **Deviates from ADR-06, §6.6 and the spec's FR-7.x line; ADR-20** |
| D10 | Traffic: **each (relay, namespace) pair has its own independent schedule** (30 s fixed interval, uniform jitter ±50 %, keyed PRF, independent phase). A **read lane** issues lists, separate from the **work lane** (fetch, store, check), so the read schedule does not depend on activity. In HIGH mode, sends are delayed by U[0, 10 min] and happen only at pair events. | ADR-09, ADR-15 (reading recorded in ADR-20) |
| D11 | Timestamps are persisted at minute, hour or day granularity only (enforced by CHECK). Schedules, breakers, relay health, latency and request history live in memory only. | ADR-08 spirit, T20 |
| D12 | The exit gate is proved on the JVM. The harness uses a fault-injecting `SqlExecutor` and relay port, a deterministic two-lane driver, exhaustive crash-point enumeration (single and double crashes), seeded random worlds, hostile relays, 13 mutant engines that must be caught, and a model relay checked against conformance vectors that the real Rust relay also replays. | exit gate |

### 0.2 The exactly-once contract

| ID | Guarantee |
|---|---|
| OUT-1 (no loss) | Every committed enqueue ends with exactly one decided outcome. An op with no possible copy is never closed by offline time, reconnects, process death, timeouts or transient relay errors. It stays pending and keeps trying, however long it takes. It closes only for four reasons: its caller-supplied deadline passes, permanent per-relay refusals, relay removal or retirement, or its store window expires after a copy already exists. |
| OUT-2 (no local duplicate) | The outcome is decided once (enforced by a trigger). `release()` returns true exactly once. |
| OUT-3 (no network duplicate) | An op never produces a second ciphertext. Every store sends the same `(namespace, bytes)`. A relay holds at most one membership per `(namespace, hash)`. |
| OUT-4 (outcome truth) | `sent` means at least 2 distinct operators showed the hash in their inventory after a receipt. `failed` means no store attempt could have left a copy on any relay; an absence counts as proof only while a copy made at the earliest possible time would still be live. `degraded` means at least one verified copy. `indeterminate` means a copy may exist or may have existed. |
| IN-1 (no loss) | Every `(namespace, hash)` that an honest, reachable relay in a listening namespace's set lists and serves is fetched and offered to the consumer. |
| IN-2 (no duplicate) | Each `(namespace, hash)` is marked consumed at most once (UNIQUE plus trigger), and the consumer never sees its own blobs. Tombstone retention (§2.3) is derived so that **no honest relay can list the hash again** after the tombstone is deleted. |
| IN-3 (cursor safety) | A stored cursor never passes a hash that is not durably recorded locally. |

**Boundary.** IN-2 holds against honest relays and for memberships created by one op's store window. The protocol layer (libsignal counters, MLS epoch and generation) remains responsible for four cases, and Phases 9 and 10 must keep replay protection:

- replays by a relay that lies about expiry or re-serves expired blobs;
- a consumer resending the same bytes as a new op long after the first (§9);
- a namespace removed and re-added;
- a relay removed from the local directory, re-added later, and still holding old blobs. The IN-2 proof covers directory retirement without deletion.

**Assumptions:**

- SQLite atomic commit holds (sqlite-jdbc on the JVM, SQLCipher on the device).
- Relays cannot forge blobs: Rust checks hash and bucket.
- While the transport is READY, device and honest relay clocks are within σ = 3 d of true time. This is `CLOCK_SKEW_SECONDS` in `relay_client.rs`, the tolerance the Phase 6 code attributes to Arti.
- For liveness, at least 2 honest, reachable operators have usable capabilities.

### 0.3 What changed from the winning design

| # | Finding | Source | Resolution |
|---|---|---|---|
| 1 | Acks never compared with relay inventory (S3). A relay that acks and drops still counted toward quorum. | all judges | A verification step (§3.4). Quorum counts **verified** deliveries. Absence after ack triggers a repair store, with 2 strikes. Limit, stated honestly: a relay that lies consistently to the writer is caught only by readers (MLS transcript, Phase 10). |
| 2 | An op could be `failed` while a relay held a copy ("failed-but-delivered"). | J0, J1 | D5. `copy_hour` records every possibly-applied attempt. `failed` requires no possible copy. Check-before-restore and resolution checks settle ambiguity. There is a supported path to resend identical bytes (§9). |
| 3 | One global foreground tick links namespaces by timing. T19 was proved only with zero latency. | all judges | Independent per-pair schedules. The read lane is separate from the work lane, and breakers are per lane. T19 is proved with a seeded non-zero latency trace (§8.6). |
| 4 | Forensic trail: 94-day hour-granular tombstones, `own` rows for write-only namespaces, AUTOINCREMENT order, own/received distinguishable. | J1 | Retention is relay expiry + 24 d, day granularity. One final state `done` covers own and received. The table is WITHOUT ROWID, so there is no insertion order. Write-only namespaces get no inbox rows. A CHECK makes `done` rows carry nothing but `(ns, hash, retain_until_day)`. The residue is declared in ADR-20 against AD-8. |
| 5 | Found in re-verification: fixed 94-day tombstones do not cover stores made up to `enqueue + TTL`. After an ambiguous first store and a long offline period, a later replica could be listed after the tombstone expired. GC could also run before a backlog drained. | this review | A store window bounds the time spread of copies. Tombstone retention is derived from the relay's expiry plus that window, and never depends on listing progress (§2.3 derivation). |
| 6 | Kotlin test fixtures in AGP are experimental. | J2 | `JdbcSqlExecutor` moves to `storage/src/testShared/kotlin`, added as an extra test source directory in `:storage` and `:sync`. |
| 7 | One page per cycle drains a backlog slowly. | J2 | STANDARD reads up to 4 pages per event while pages are full. HIGH reads exactly 1. |
| 8 | The own-row insert had no conflict path, so identical bytes could not be resent. | J2 | UPSERT on `done` rows. Identical bytes can be re-enqueued as a new op after release. |
| 9 | Poison blobs could crash-loop the process. The privacy design dropped them after 3 attempts. | J0–J2 | A write-ahead offer counter with exponential re-offer delay (1 h to 24 h). Blobs are never dropped. |
| 10 | Grafted from "platform" | | Per-call deadline over JNI. Non-reentrant `transaction()` in both executors (the JDBC nested commit bug is verified). `foreign_keys`/`secure_delete` set in `onConfigure`. Check before re-store after an ambiguous attempt. Transport closed 30 s after the app is backgrounded. `defer` disposition. Platform facts table. Operation ids never leave the device (test). |
| 11 | Grafted from "privacy" | | Independent per-pair schedules and the "no request caused by a local event" rule in HIGH mode. Minute/hour/day timestamps. Nothing about health or schedule persisted. TTL-bound tombstones via `get` expiry. Fail-closed v2 migration guard. Cursor and capability linkability note. Merged-manifest T15. |
| 12 | Scope reductions | | No persisted `relay_health`. No periodic global circuit rotation: a global rotation would create correlated change points, and capabilities link a namespace's requests anyway (§6.3). No filler gets (§6.1, ADR-20). |

### 0.4 Phase 6 review notes

| Note | Where handled |
|---|---|
| `RelayClient` bound to a namespace by type | `NamespaceClient` in Rust plus the capability-scope guard, T21 (§1.5) |
| Fixed-size batches | Constant `limit` = 128. A fixed page count per event in HIGH mode. `check` batches are bounded. How "loturi fixe" is read is recorded in ADR-20 (§6.1). |
| Time budget per relay | Per-call deadline over JNI, per-relay session budget, per-lane breakers (§3.7) |
| Long-lived clients check a circuit-rotation epoch | Not applicable. JNI still builds one client per call. Pooled clients in Phase 12 must add the epoch (ADR-19 addendum). |
| A non-empty cursor with an empty page must not loop the client | A hard page bound per event (§4.1) |

---

## 1. Architecture and module layout

### 1.1 Layers

```
 Phases 9/10/11 consumers ──► org.ghost.sync.api  (SyncDatabase/SyncTransaction, Outbox, Inbox, Namespaces,
                                                   Capabilities, RelayDirectory, SyncController)
                                     │
                                     ▼
                               org.ghost.sync.engine  (pure Kotlin; no android.*, java.net.*, javax.net.*)
                                 ReadLane: ListStep            WorkLane: Maintenance, FetchStep, StoreStep,
                                 PairSchedule (keyed PRF)                 VerifyStep, ResolveStep, Gc
                                 ErrorPolicy, Backoff, LaneBreaker, TrafficPolicy, RetentionPolicy
                                     │ ports
          ┌──────────────┬───────────┼──────────────┬──────────────┐
      RelayPort     TransportPort  SyncClock   RandomSources   SqlExecutor (:storage)
          │              │
 org.ghost.sync.android (only package importing android.*)
   TorRelayPort ──► org.ghost.network.RelayTransport (TorRelayTransport) ──JNI──► client-core/net (Rust)
   TorTransportHolder   SyncRuntime   SyncJobService + JobSchedulerWake   ForegroundDriver   SyncController
```

### 1.2 Why the engine is Kotlin (ADR-19 check)

ADR-19 forbids *protocol logic* in Kotlin: framing, gRPC, padding, and validation of relay responses. The sync engine does none of these. It orchestrates local durable state (queues, retry state, cursors, dedup) in the SQLCipher database, and Kotlin owns that database (Phase 4).

Everything the engine receives from Rust is already validated:

- `get`: hash, bucket size and expiry bound;
- `list`: cursor length and page size;
- `store`: hash and receipt expiry;
- `check`: the result is a subset of the request.

Cursors and capabilities stay opaque bytes in Kotlin.

A Rust engine would need either a second SQLCipher binding (rusqlite with sqlcipher, a new C supply chain, and a second path for the database key) or one JNI callback per SQL statement. Both enlarge the audit surface ADR-19 set out to shrink.

The single protocol rule Kotlin repeats is `blob_hash = SHA-256(ciphertext)` (JDK `MessageDigest`), which it cross-checks against Rust's receipt.

### 1.3 Package layout (`ghost/android/sync/src/main/kotlin/org/ghost/sync/`)

```
api/     SyncDatabase.kt SyncTransaction.kt Outbox.kt Inbox.kt Namespaces.kt Capabilities.kt RelayDirectory.kt
         Types.kt (OperationId, NamespaceId, BlobHash, RelayId, TtlBucket, Consumer, CapabilityKind, PrivacyMode,
         Outcome) SyncStatus.kt SyncController.kt (interface)
engine/  SyncEngine.kt Session.kt ReadLane.kt WorkLane.kt PairSchedule.kt ListStep.kt FetchStep.kt StoreStep.kt
         VerifyStep.kt ResolveStep.kt Maintenance.kt Gc.kt ErrorPolicy.kt Backoff.kt LaneBreaker.kt
         TrafficPolicy.kt RetentionPolicy.kt Steps.kt
store/   OutboxStore.kt InboxStore.kt CursorStore.kt CapabilityStore.kt DirectoryStore.kt Sql.kt (shared fragments)
port/    RelayPort.kt TransportPort.kt SyncClock.kt RandomSources.kt WakeScheduler.kt
android/ TorRelayPort.kt TorTransportHolder.kt SyncRuntime.kt SyncJobService.kt JobSchedulerWake.kt
         ForegroundDriver.kt AndroidSyncController.kt
```

Steps are injected objects (`Steps.DEFAULT` in production). Test sources substitute mutant steps to prove the harness catches classic bugs (§8.8). Production code has no test switches and no step observers, which the T8 anti-placeholder gate also requires.

### 1.4 Concurrency model: sessions and two lanes

- **`SyncRuntime`** is a process-wide singleton. It owns the one `TorTransportHolder` (two transports must not share Arti's state directory, per client-core README), the `SyncEngine`, and **at most one session**: `FOREGROUND` or `BACKGROUND`.
  - If the app comes to the foreground during a background session, the background session stops accepting items, finishes the calls in flight, and the foreground session starts.
  - A job that arrives during a foreground session returns immediately.
- A session runs **two single-threaded lanes** on the same `SqlExecutor`:
  - **Read lane**: only `ListStep`, at pair-event times (§6.1). It issues each request from an **in-memory snapshot** (cursor, read token, generation) refreshed after its own commits and after capability changes. So it never waits on the database before sending.
    - An event that cannot start within `LATE_TOLERANCE = 2 s` of its scheduled time is **skipped, not delayed**. The schedule consumes the index anyway.
    - The read lane has its own breaker, counting only list failures.
  - **Work lane**: maintenance, fetches (queued after a pair's list commit), stores, verification and resolution checks, GC. It has its own breaker.
- **No network call ever runs inside a transaction.** Each step is a short transaction, then a call outside any lock, then a short transaction. Every mutating statement is guarded by its expected current state (`WHERE state = … AND inflight = …`), so any interleaving of the lanes and of consumer transactions is correct. The interleaving tests exercise this (§8.5).
- Rust: both lanes call into one `TorRelayTransport` handle. The handle's runtime is `new_multi_thread` (verified in `jni_bridge.rs`), and `Runtime::block_on` may be called from several non-runtime threads. S2 adds a Rust test with two concurrent calls on one handle.
- Tests replace the two threads with `DeterministicDriver`. It runs both lanes' items in virtual-time order, one at a time, with a seeded latency model, so every run is reproducible.

### 1.5 Changes in other modules

**`storage` (Phase 4 module)**

- `SqlExecutor.execUpdate(sql, args): Int` returns the row count. It is implemented with `compileStatement(...).executeUpdateDelete()` on the device and `executeUpdate()` over JDBC. Guarded transitions need it.
- `SqlExecutor.inTransaction: Boolean`.
- **`transaction()` becomes non-reentrant in both executors**: a nested call throws `IllegalStateException`. Verified: in `JdbcSqlExecutor` a nested call commits the outer work early and resets autocommit, while `SupportSqlExecutor` nests silently, so JVM tests would not model the device. No existing caller nests (`InviteNonceRepository`, `MigrationRunner` checked).
- **`PRAGMA foreign_keys = ON` and `PRAGMA secure_delete = ON` move into `SupportSQLiteOpenHelper.Callback.onConfigure`**, so they apply to every connection. Today `foreign_keys` is executed once at the end of `MigrationRunner.migrate()` (verified). v2 relies on `ON DELETE CASCADE`.
- `Schema` migration v2 (§2). `expectedTables` is updated. A new `expectedTriggers` set is added. `verifyIntegrity()` also checks `PRAGMA foreign_keys = 1`.
- `JdbcSqlExecutor` moves to `storage/src/testShared/kotlin` and is added to the test sources of `:storage` and `:sync` (`android.sourceSets["test"].kotlin.srcDir(...)`). No experimental test-fixtures support is needed.
- `SchemaAndMigrationTest` line 93 inserts into `relay_queue` to test the 64 KiB cap. That test moves to `outbox_op.ciphertext`.

**`network` (Kotlin)**

- Extract `interface RelayTransport` (bootstrap, store, get, list, check, rotateCircuits, close). `TorRelayTransport` implements it, so the adapter is JVM-testable.
- Add `deadlineMillis: Int` (1..60 000) to store, get, list and check. The existing overloads keep 60 000.
- Add `check(relay, ns, cap, hashes, deadline): List<ByteArray>` with a strict decoder: a multiple of 32 bytes, no more than requested, a subset of the request.
- `get` returns `FetchedBlob(ciphertext, expiryUnixSeconds)`. The wire format is `expiry(8, BE) ‖ data`.

**`client-core/net` (Rust, ADR-19)**

- `ghost_relay_api::capability_header(token) -> Option<CapabilityHeader{kind, namespace, quota_bytes, expiry_unix}>` parses the public v1 layout `version(1)‖kind(1)‖namespace(32)‖quota(8)‖expiry(8)‖mac(32)`. The layout is documented in `relay/crates/capability`, which switches to this parser so the layout is defined once.
- `NamespaceClient { inner: RelayClient<C>, namespace: [u8; 32] }` is built only by `NamespaceClient::over_tor(transport, relay, namespace)` with `IsolationScope::Namespace(namespace)`. Its methods take no namespace. Before any I/O, every call checks that the capability header's namespace equals the bound namespace, and that the kind fits: Write for store; Read or Write for list, get and check (on the relay, write also grants read, verified in `capability/src/lib.rs`). A mismatch, or a token that does not parse, **fails closed with `invalid_argument`**. `RelayClient::over_tor` becomes `pub(crate)`.

  This closes a verified hazard: `GetBlobRequest` and `CheckBlobsRequest` carry no namespace, and the relay derives it via `verify_any`. A caller passing namespace A for isolation with a capability for namespace B would otherwise send B's reads over A's circuit.
- JNI: `nativeCheck`; a `deadlineMs` argument on store, get, list and check, where the effective deadline is `min(deadlineMs, RELAY_RPC_DEADLINE)` and 0 gives `invalid_argument`; `nativeGet` returns the relay's expiry. `validate_get` additionally rejects an expiry greater than `now + 90 d + CLOCK_SKEW_SECONDS` as `malformed_response`.
- No new error category. `client-core/README.md` documents `check` and the deadline.

**`relay` (Phase 5 code; refactor only)**

Each gRPC handler body is extracted into `Relay::{store,get,check,list}_at(req, now)`, so conformance vectors can drive the real relay with an injected clock (§8.7). Behaviour does not change.

### 1.6 Ports

```kotlin
package org.ghost.sync.port

/** Blocking relay calls. Failures: NetworkException(category) or IllegalArgumentException (Kotlin require).
 *  The engine catches nothing else and never catches Throwable/Error. */
interface RelayPort {
    fun store(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, ciphertext: ByteArray,
              ttlSeconds: Int, deadlineMillis: Int): StoreReceipt
    fun get(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hash: BlobHash, deadlineMillis: Int): FetchedBlob
    fun list(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, cursor: ByteArray /* 0|8 */,
             limit: Int, deadlineMillis: Int): ListPage
    fun check(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hashes: List<BlobHash>,
              deadlineMillis: Int): Set<BlobHash>
}
class StoreReceipt(val blobHash: BlobHash, val expiryUnixSeconds: Long)
class FetchedBlob(val ciphertext: ByteArray, val expiryUnixSeconds: Long)
class ListPage(val hashes: List<BlobHash>, val nextCursor: ByteArray)

enum class TransportState { READY, UNAVAILABLE, BRIDGE_CONFIG, FAILED }
interface TransportPort {
    /** Creates/bootstraps if needed; never blocks past the deadline (bootstrap is bounded at 180 s natively). */
    fun ensureReady(deadlineMonotonicMillis: Long): TransportState
    val relays: RelayPort
    /** Any thread (onStopJob, background grace): in-flight calls end with `closed`. */
    fun abort()
}
interface SyncClock { fun epochSeconds(): Long; fun monotonicMillis(): Long }

/** Keyed PRF streams. Production: 32-byte key from SecureRandom, fresh per process; HmacSHA256 (platform JCA). */
interface RandomSources {
    /** Uniform in [0,1) for (pair, purpose, index); independent of everything else (T19). */
    fun schedule(pair: PairKey, purpose: SchedulePurpose, index: Long): Double
    /** HIGH-mode send delay, sampled once per op at enqueue. */
    fun sendDelay(): Double
    /** Backoff jitter, candidate choice. Never used by the read lane. */
    fun selection(): Double
}
enum class SchedulePurpose { FOREGROUND_START, FOREGROUND_STEP, BACKGROUND_OFFSET }
class PairKey(val relayId: RelayId, val namespace: NamespaceId)
interface WakeScheduler { fun ensurePeriodic(); fun cancel() }
```

---

## 2. Storage: migration v2

### 2.1 Principles

- v1 is never edited. `Migration(version = 2)` is added and `CURRENT_VERSION = 2`. `MigrationRunner` already runs each migration in one transaction with `user_version`, so an interrupted v2 leaves v1 intact.
- v1 `relay_queue` and `sync_cursor` were designed before multi-relay, and **no code reads or writes them**. Verified: the only references are `Schema.kt` and `SchemaAndMigrationTest.kt`. v2 drops them behind a fail-closed guard: if either table is not empty, the migration aborts and the database stays at v1.
- All sync state lives inside SQLCipher. Payload columns hold E2E ciphertext only and are named `ciphertext` (`noPlaintextContentColumnsExist` rejects `body`, `text`, `content`, …). Identifiers are opaque.
- **Persisted times are minute (`*_minute`, `% 60 = 0`), hour (`*_hour`, `% 3600 = 0`) or day (`*_day`) only**, and only where correctness needs them. No schedule, attempt time, latency, breaker or success timestamp is stored.
- No inbox rows exist for write-only namespaces. `done` rows carry only `(namespace, hash, retain_until_day)`, and `inbox_blob` is WITHOUT ROWID, so there is no insertion order.

### 2.2 Exact SQL: `Migration(version = 2, statements = listOf(...))`

```sql
-- (0) Fail-closed guard: the pre-multi-relay tables never had a writer. A CHECK failure aborts the
--     migration transaction and the database stays at v1.
CREATE TABLE v2_migration_guard (row_count INTEGER NOT NULL CHECK (row_count = 0));
INSERT INTO v2_migration_guard(row_count) SELECT count(*) FROM relay_queue;
INSERT INTO v2_migration_guard(row_count) SELECT count(*) FROM sync_cursor;
DROP TABLE v2_migration_guard;
DROP TABLE relay_queue;                       -- idx_relay_queue_due goes with it
DROP TABLE sync_cursor;

-- (1) Local relay directory. Phase 14 fills it from the signed manifest; until then source = 'config'.
--     A retired onion re-added later reactivates the same row (UNIQUE), keeping its cursors.
CREATE TABLE relay_directory (
    relay_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    onion_address TEXT NOT NULL UNIQUE
                  CHECK (length(onion_address) BETWEEN 64 AND 68
                         AND substr(onion_address, 57, 7) = '.onion:'),  -- OnionAddress.toString() = host:port
    operator_id   BLOB NOT NULL CHECK (length(operator_id) = 16),
    state         TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    source        TEXT NOT NULL CHECK (source IN ('manifest', 'config')),
    retired_day   INTEGER CHECK (retired_day IS NULL OR retired_day >= 0),
    CHECK ((state = 'retired') = (retired_day IS NOT NULL))
);

CREATE TABLE sync_namespace (
    namespace_id BLOB PRIMARY KEY NOT NULL CHECK (length(namespace_id) = 32),
    consumer     TEXT NOT NULL CHECK (consumer IN ('dm', 'prekeys', 'channel', 'media', 'identity')),
    listening    INTEGER NOT NULL CHECK (listening IN (0, 1))               -- 0 = write-only (a contact's DM inbox)
) WITHOUT ROWID;

CREATE TABLE namespace_relay (
    namespace_id BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
    relay_id     INTEGER NOT NULL REFERENCES relay_directory(relay_id),     -- relays are retired, not deleted
    PRIMARY KEY (namespace_id, relay_id)
) WITHOUT ROWID;
CREATE INDEX idx_namespace_relay_relay ON namespace_relay(relay_id);

-- Capabilities are stored and used, never minted (Phase 8 mints; Phase 10 may add MLS-derived read tokens).
CREATE TABLE relay_capability (
    relay_id     INTEGER NOT NULL REFERENCES relay_directory(relay_id) ON DELETE CASCADE,
    namespace_id BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('read', 'write')),
    token        BLOB NOT NULL CHECK (length(token) BETWEEN 1 AND 512),     -- v1 is 82 bytes; not hard-coded
    expires_hour INTEGER CHECK (expires_hour IS NULL OR expires_hour % 3600 = 0),  -- floored; NULL = unknown
    state        TEXT NOT NULL CHECK (state IN ('usable', 'rejected', 'exhausted')),
    generation   INTEGER NOT NULL CHECK (generation >= 1),                  -- +1 on every put (race guard, §3.8)
    PRIMARY KEY (relay_id, namespace_id, kind)
) WITHOUT ROWID;

-- Opaque per-(relay, namespace) cursor. Absent = from the beginning. Only non-empty cursors are stored.
CREATE TABLE relay_cursor (
    relay_id     INTEGER NOT NULL REFERENCES relay_directory(relay_id) ON DELETE CASCADE,
    namespace_id BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
    cursor       BLOB NOT NULL CHECK (length(cursor) = 8),
    PRIMARY KEY (relay_id, namespace_id)
) WITHOUT ROWID;

CREATE TABLE outbox_op (
    operation_id       BLOB PRIMARY KEY NOT NULL CHECK (length(operation_id) = 16),
    namespace_id       BLOB NOT NULL REFERENCES sync_namespace(namespace_id),   -- no cascade: ops pin the namespace
    blob_hash          BLOB NOT NULL CHECK (length(blob_hash) = 32),
    ciphertext         BLOB CHECK (ciphertext IS NULL OR length(ciphertext) IN (1024, 4096, 16384, 65536)),
    ttl_seconds        INTEGER NOT NULL CHECK (ttl_seconds IN (86400, 604800, 2592000, 7776000)),
    not_before_minute  INTEGER NOT NULL CHECK (not_before_minute % 60 = 0),     -- ADR-15 delay, sampled once
    deadline_hour      INTEGER CHECK (deadline_hour IS NULL OR deadline_hour % 3600 = 0),  -- NULL = none (default)
    required_operators INTEGER NOT NULL CHECK (required_operators >= 2),        -- ADR-11
    outcome            TEXT NOT NULL CHECK (outcome IN ('pending', 'sent', 'degraded', 'failed', 'indeterminate')),
    released           INTEGER NOT NULL DEFAULT 0 CHECK (released IN (0, 1)),
    CHECK (deadline_hour IS NULL OR deadline_hour > not_before_minute),
    CHECK (released = 0 OR outcome <> 'pending'),
    UNIQUE (namespace_id, blob_hash)
);
CREATE INDEX idx_outbox_op_open ON outbox_op(outcome, released);

CREATE TABLE outbox_delivery (
    operation_id        BLOB NOT NULL REFERENCES outbox_op(operation_id) ON DELETE CASCADE,
    relay_id            INTEGER NOT NULL REFERENCES relay_directory(relay_id),
    state               TEXT NOT NULL
                        CHECK (state IN ('pending', 'wait_capability', 'acked', 'verified', 'failed', 'closed')),
    attempts            INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_minute INTEGER NOT NULL CHECK (next_attempt_minute % 60 = 0),
    inflight            INTEGER NOT NULL DEFAULT 0 CHECK (inflight IN (0, 1)),   -- write-ahead lease marker
    lease_hour          INTEGER CHECK (lease_hour IS NULL OR lease_hour % 3600 = 0),
    copy_hour           INTEGER CHECK (copy_hour IS NULL OR copy_hour % 3600 = 0), -- earliest attempt that may have stored
    ack_minute          INTEGER CHECK (ack_minute IS NULL OR ack_minute % 60 = 0), -- latest receipt
    strikes             INTEGER NOT NULL DEFAULT 0 CHECK (strikes BETWEEN 0 AND 2),-- absent-after-ack count
    CHECK (inflight = 0 OR lease_hour IS NOT NULL),
    CHECK (state <> 'acked' OR (ack_minute IS NOT NULL AND copy_hour IS NOT NULL)),
    PRIMARY KEY (operation_id, relay_id)
) WITHOUT ROWID;
CREATE INDEX idx_outbox_delivery_due ON outbox_delivery(state, next_attempt_minute);
CREATE INDEX idx_outbox_delivery_relay ON outbox_delivery(relay_id, state);

-- Dedup key and tombstone. WITHOUT ROWID: rows are ordered by (namespace, hash), not by arrival.
-- Large ciphertexts in a WITHOUT ROWID table are correct but slower; FETCHED_CAP bounds how many exist.
CREATE TABLE inbox_blob (
    namespace_id       BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
    blob_hash          BLOB NOT NULL CHECK (length(blob_hash) = 32),
    state              TEXT NOT NULL CHECK (state IN ('listed', 'unavailable', 'fetched', 'done')),
    ciphertext         BLOB CHECK (ciphertext IS NULL OR length(ciphertext) IN (1024, 4096, 16384, 65536)),
    fetch_seq          INTEGER,                                   -- local hand-off order, only while fetched
    fetch_attempts     INTEGER NOT NULL DEFAULT 0 CHECK (fetch_attempts >= 0),
    next_fetch_minute  INTEGER NOT NULL DEFAULT 0 CHECK (next_fetch_minute % 60 = 0),
    offers             INTEGER NOT NULL DEFAULT 0 CHECK (offers >= 0),          -- write-ahead poison guard
    offer_after_minute INTEGER NOT NULL DEFAULT 0 CHECK (offer_after_minute % 60 = 0),
    retain_until_day   INTEGER NOT NULL CHECK (retain_until_day >= 0),
    CHECK ((state = 'fetched') = (ciphertext IS NOT NULL)),
    CHECK ((state = 'fetched') = (fetch_seq IS NOT NULL)),
    CHECK (state <> 'done' OR (fetch_attempts = 0 AND next_fetch_minute = 0
                                AND offers = 0 AND offer_after_minute = 0)),   -- a tombstone carries nothing else
    PRIMARY KEY (namespace_id, blob_hash)
) WITHOUT ROWID;
CREATE UNIQUE INDEX idx_inbox_fetch_seq ON inbox_blob(fetch_seq) WHERE fetch_seq IS NOT NULL;
CREATE INDEX idx_inbox_work ON inbox_blob(namespace_id, state, next_fetch_minute);
CREATE INDEX idx_inbox_retention ON inbox_blob(retain_until_day);

CREATE TABLE inbox_source (                 -- which relays listed a not-yet-fetched hash
    namespace_id BLOB NOT NULL,
    blob_hash    BLOB NOT NULL,
    relay_id     INTEGER NOT NULL REFERENCES relay_directory(relay_id) ON DELETE CASCADE,
    state        TEXT NOT NULL CHECK (state IN ('candidate', 'not_found', 'bad')),
    PRIMARY KEY (namespace_id, blob_hash, relay_id),
    FOREIGN KEY (namespace_id, blob_hash) REFERENCES inbox_blob(namespace_id, blob_hash) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX idx_inbox_source_relay ON inbox_source(relay_id, state);

-- ===== State machines enforced by the schema (D8). Row triggers fire only on rows actually updated. =====
CREATE TRIGGER outbox_op_immutable
BEFORE UPDATE OF operation_id, namespace_id, blob_hash, ttl_seconds, not_before_minute, deadline_hour,
                 required_operators ON outbox_op
BEGIN SELECT RAISE(ABORT, 'outbox_op identity is immutable'); END;

CREATE TRIGGER outbox_op_payload
BEFORE UPDATE OF ciphertext ON outbox_op
WHEN NEW.ciphertext IS NOT NULL
  OR EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = OLD.operation_id
             AND (d.state IN ('pending', 'wait_capability', 'acked') OR d.inflight = 1))
BEGIN SELECT RAISE(ABORT, 'outbox payload is frozen and wiped only after the last possible store'); END;

CREATE TRIGGER outbox_op_outcome
BEFORE UPDATE OF outcome ON outbox_op
WHEN OLD.outcome <> 'pending' OR NEW.outcome = 'pending'
BEGIN SELECT RAISE(ABORT, 'outbox outcome is decided once'); END;

CREATE TRIGGER outbox_op_release
BEFORE UPDATE OF released ON outbox_op
WHEN OLD.released = 1 OR NEW.released <> 1 OR OLD.outcome = 'pending'
BEGIN SELECT RAISE(ABORT, 'release happens once, after the outcome'); END;

CREATE TRIGGER outbox_op_delete
BEFORE DELETE ON outbox_op
WHEN OLD.released = 0 OR OLD.ciphertext IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'only released ops without payload are deleted'); END;

CREATE TRIGGER outbox_delivery_insert
BEFORE INSERT ON outbox_delivery
WHEN NEW.state <> 'pending' OR NEW.inflight <> 0 OR NEW.copy_hour IS NOT NULL
  OR (SELECT ciphertext FROM outbox_op WHERE operation_id = NEW.operation_id) IS NULL
BEGIN SELECT RAISE(ABORT, 'a new delivery starts pending, idle, without copies, and needs the payload'); END;

CREATE TRIGGER outbox_delivery_state
BEFORE UPDATE OF state ON outbox_delivery
WHEN NOT ((OLD.state = 'pending'         AND NEW.state IN ('wait_capability', 'acked', 'verified', 'failed', 'closed'))
       OR (OLD.state = 'wait_capability' AND NEW.state IN ('pending', 'acked', 'verified', 'failed', 'closed'))
       OR (OLD.state = 'acked'           AND NEW.state IN ('pending', 'verified', 'failed', 'closed'))
       OR (OLD.state IN ('failed', 'closed') AND NEW.state = 'verified'))       -- late inventory is truth
  OR (NEW.state IN ('pending', 'wait_capability', 'acked')
      AND (SELECT ciphertext FROM outbox_op WHERE operation_id = OLD.operation_id) IS NULL)
BEGIN SELECT RAISE(ABORT, 'illegal delivery transition'); END;

CREATE TRIGGER outbox_delivery_copy
BEFORE UPDATE OF copy_hour ON outbox_delivery
WHEN (OLD.copy_hour IS NOT NULL AND NEW.copy_hour IS NOT NULL AND NEW.copy_hour <> OLD.copy_hour)
  OR (OLD.copy_hour IS NOT NULL AND NEW.copy_hour IS NULL
      AND (OLD.ack_minute IS NOT NULL OR OLD.state = 'verified'))
BEGIN SELECT RAISE(ABORT, 'a possible copy keeps its earliest hour and is forgotten only when proven absent'); END;

CREATE TRIGGER inbox_blob_insert
BEFORE INSERT ON inbox_blob
WHEN NEW.state NOT IN ('listed', 'done')
BEGIN SELECT RAISE(ABORT, 'inbox rows start listed (or done for own blobs)'); END;

CREATE TRIGGER inbox_blob_identity
BEFORE UPDATE OF namespace_id, blob_hash ON inbox_blob
BEGIN SELECT RAISE(ABORT, 'inbox identity is immutable'); END;

CREATE TRIGGER inbox_blob_state
BEFORE UPDATE OF state ON inbox_blob
WHEN NOT ((OLD.state = 'listed'      AND NEW.state IN ('fetched', 'unavailable'))
       OR (OLD.state = 'unavailable' AND NEW.state = 'listed')
       OR (OLD.state = 'fetched'     AND NEW.state = 'done'))                  -- 'done' is final
BEGIN SELECT RAISE(ABORT, 'illegal inbox transition'); END;

CREATE TRIGGER inbox_blob_sources
AFTER UPDATE OF state ON inbox_blob
WHEN NEW.state IN ('fetched', 'done')
BEGIN DELETE FROM inbox_source WHERE namespace_id = NEW.namespace_id AND blob_hash = NEW.blob_hash; END;
```

Schema constants for v2:

- `Schema.expectedTables`: the v1 set minus `relay_queue` and `sync_cursor`, plus `relay_directory`, `sync_namespace`, `namespace_relay`, `relay_capability`, `relay_cursor`, `outbox_op`, `outbox_delivery`, `inbox_blob`, `inbox_source`. The existing test already filters out `sqlite_sequence`.
- `Schema.expectedTriggers` holds the 12 triggers above.

### 2.3 Retention: what is kept, for how long, and why

**Constants** (`RetentionPolicy`, one file):

| Constant | Value |
|---|---|
| `STORE_WINDOW` H | 7 d |
| `SKEW` σ | 3 d |
| `TAIL` | 24 d |
| `LISTED_RETAIN` | 111 d |
| `OWN_EXTRA` | 8 d |

| Data | Kept until | Removal |
|---|---|---|
| Outbox ciphertext | no delivery is `pending`, `wait_capability` or `acked`, and none is in flight | set to `NULL` (trigger-guarded) |
| Outbox op and deliveries | `released = 1` and the payload is wiped | `DELETE`; deliveries cascade |
| Inbox ciphertext | the consumer calls `markConsumed` | set to `NULL` (CHECK) |
| `fetched` rows | the consumer marks them consumed | **never garbage-collected** (no loss) |
| `done` tombstone of a received blob | `day(E) + TAIL`, where E is the relay expiry returned by `get` | GC ≤ 500 rows per pass |
| `done` tombstone of an own blob (listening namespaces only) | while its op exists; at op deletion it is set to `today + TTL_days + OWN_EXTRA` | GC |
| `listed`/`unavailable` rows | `last listing day + LISTED_RETAIN` | GC |
| Cursors | namespace removed; relay row deleted | cascade |
| Capabilities | replaced; `expires_hour + 1 d` | `DELETE` |
| Relay rows | retired for `LISTED_RETAIN` days and no longer referenced | `DELETE` |
| Scheduler | `/data/system/job/jobs.xml` (system-owned, root-only): one job with no extras | `cancel()` |

**Derivation (IN-2 without duplicates).** Every membership of `(ns, h)` on any relay is created or extended by a store of the one op that produced h. The store window (§3.5) confines those stores to physical times `s ∈ [F, F + H']`, where:

- F is the first possible copy;
- `H' = H + 2σ + 1 h`: two sender clock readings (`copy_hour`, floored to the hour) and the closing check.

The relay rounds expiry up to the hour (verified in `relay/crates/storage`), so a membership created at s expires physically at or before `s + TTL + 1 h + σ_relay`.

**Received blobs.** The recipient fetched from relay A and got expiry E (A's clock), with `E ≥ s_A + TTL − σ` and `s_A ≥ F`. So every membership of h on every relay expires before `E + H + 5σ + 2 h ≈ E + 22.1 d`, measured on the recipient's clock with its own σ included. Rounding to days gives **TAIL = 24 d**. After that, no honest relay can list h, even a relay that joins the namespace's set later or one reading from the beginning. The bound depends on no listing progress and no set membership. That closes the two latent paths found in the "correctness" design (§0.3 row 5).

**Never-fetched rows.** E is unknown. A listing at time t proves h was live at t. Its latest expiry is `t + H + TTL_max + 4σ + 2 h ≈ t + 109.1 d`, so **LISTED_RETAIN = 111 d**. Deleting such a row loses nothing, because no honest relay can serve it any more.

**Own blobs.** The row exists from enqueue and GC skips it while the op exists. At op deletion no further store can happen, so the retention is `today + TTL + 1 h + 2σ` rounded, which is `TTL + 8 d`.

**What a forensic attacker (AD-8) sees:**

- per listening namespace, the hashes of blobs whose relay copy is live, or expired at most 24 days ago (111 days for hashes listed but never fetched);
- each with a day-granular deletion date;
- no content, no order, no own-versus-received distinction;
- nothing for write-only namespaces.

This is a residue against AD-8's "nu vede istoricul expirat", **declared in ADR-20 §6 and to be added to LIMITE L1.** Shortening it means shortening H (Q4).

**Secure delete.** `secure_delete` and `cipher_memory_security` are on. After any GC pass that deleted rows, the engine runs `PRAGMA wal_checkpoint(TRUNCATE)` through `query`, not `exec`, because it returns a row.

### 2.4 Never persisted

Schedules, pair-event indices and PRF keys; breaker and latency state; request history; bytes counters; caught-up or health flags; `CycleReport`s. The sync layer writes **no file, no SharedPreferences entry and no scheduler extra**. Capability tokens, namespace ids, hashes, cursors, onion addresses and operation ids exist only in SQLCipher columns and in JNI arguments.

---

## 3. Outbox

### 3.1 Enqueue (inside the caller's transaction)

`Outbox.enqueue(tx, blob)` runs in the consumer's own transaction. Phase 9 advances the ratchet and enqueues in one commit, so a crash can neither lose a message whose ratchet has moved nor produce a second ciphertext for it. In that transaction it:

1. Validates:
   - the operation id is 16 bytes and the ciphertext is exactly one bucket;
   - the namespace is registered;
   - `SELECT count(DISTINCT rd.operator_id) FROM namespace_relay nr JOIN relay_directory rd ON rd.relay_id = nr.relay_id WHERE nr.namespace_id = :ns AND rd.state = 'active'` is at least 2, otherwise it throws `InsufficientReplicasException` with a constant message.
2. Computes `h = SHA-256(ciphertext)`.
3. Resolves conflicts. The same operation id with the same h returns `AlreadyEnqueued`. The same id with a different h, or `(ns, h)` present under another live op, throws `IllegalStateException` and the caller's transaction rolls back.
4. Samples `not_before_minute` once. STANDARD uses `floor_minute(now)`. HIGH uses `ceil_minute(now + U[0, 10 min])` from the `sendDelay` stream. `deadline_hour = ceil_hour(caller deadline)` or `NULL`.
5. `INSERT outbox_op(..., outcome = 'pending')`, then `INSERT outbox_delivery(op, r, 'pending', 0, not_before_minute)` for every active relay in the set.
6. **Only if the namespace is listening:**

   ```sql
   INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (:ns, :h, 'done', :today + :ttl_days + 8)
   ON CONFLICT(namespace_id, blob_hash) DO UPDATE
      SET retain_until_day = max(inbox_blob.retain_until_day, excluded.retain_until_day)
    WHERE inbox_blob.state = 'done';
   ```

   It then checks that the row is `done`. Any other state would mean someone else's identical bytes, which is cryptographically implausible, so it throws.
7. Never wakes anything. In STANDARD mode the caller may call `SyncController.requestExpedite()` after its commit (§5.4).

### 3.2 State machines

```
delivery (trigger-enforced):
  pending ──store ok──────────────────────────► acked ──inventory shows h──► verified (absorbing)
     │  ▲                                        │  └──check absent: strike<2, window open──► pending (repair)
     │  └──new capability generation── wait_capability ◄──unauthorized / quota+absent / no usable cap
     ├──check shows h (check-before-restore, quota path)──► verified
     ├──rejected / local bug / relay removed or retired───► failed ─┐
     └──window closed or caller deadline──────────────────► closed ─┴─inventory shows h──► verified
  acked ──check absent: strikes = 2 → failed; window closed → closed

copy_hour (per delivery): NULL ──attempt ended ambiguous, succeeded, or crashed──► hour of that lease (earliest, frozen)
                          └──back to NULL only if a check proves absence while a copy would still be live and it was never acked

op outcome (decided once):
  pending ──≥ required distinct operators verified──────────────────────────────► sent
          └──no delivery pending/wait/acked/in flight and no resolvable copy──► degraded | failed | indeterminate
released: 0 ──release() after the outcome──► 1 (once)
```

### 3.3 The store attempt: plan, lease, call, result

**Planning** (a read; the work lane is the only store issuer). A delivery is due when all of these hold:

- `state = 'pending'`, `inflight = 0`, `next_attempt_minute ≤ now`;
- `not_before_minute ≤ now`;
- no caller deadline has passed;
- **the window is open**: `NOT EXISTS (SELECT 1 FROM outbox_delivery x WHERE x.operation_id = :op AND x.copy_hour IS NOT NULL AND x.copy_hour + :H <= :now)`;
- the relay is active, the work-lane breaker is closed, and a usable, unexpired write capability exists;
- in HIGH mode, the attempt belongs to the event of pair (relay, namespace) (§6.1).

Ordering is `not_before_minute`, then `operation_id`. Caps are `STORE_PER_PAIR_EVENT = 8` in HIGH mode and `STORE_PER_PASS = 32` in STANDARD.

**Lease transaction** (write-ahead):

```sql
UPDATE outbox_delivery
   SET attempts = attempts + 1, inflight = 1, lease_hour = :hour, next_attempt_minute = :now_min + :backoff_min
 WHERE operation_id = :op AND relay_id = :r AND state = 'pending' AND inflight = 0
   AND next_attempt_minute <= :now_min;                          -- execUpdate must return 1, else skip
SELECT o.ciphertext, o.namespace_id, o.blob_hash, o.ttl_seconds, d.copy_hour, d.ack_minute
  FROM outbox_op o JOIN outbox_delivery d ON d.operation_id = o.operation_id
 WHERE o.operation_id = :op AND d.relay_id = :r;
SELECT token, generation FROM relay_capability
 WHERE relay_id = :r AND namespace_id = :ns AND kind = 'write' AND state = 'usable';
```

**Call** (outside any transaction):

1. **Check before restore**: if `copy_hour IS NOT NULL`, a previous attempt may have left a copy. The attempt first calls `check([h])` with the write capability. This avoids a 64 KiB upload and a quota extension (a re-store after the relay's one-hour no-op window is charged; verified in `relay/crates/storage::put`).
   - Present: the delivery becomes `verified`.
   - Absent, the delivery was never acked, and `now < copy_hour + ttl − σ`: `copy_hour := NULL`, because a copy made at the earliest possible hour would still be live. Then store.
   - Otherwise: store (repair).
2. `store(relay, ns, token, ciphertext, ttl, deadline)`. Rust re-hashes, sends, checks `stored_hash == h`, and checks that the expiry is at least the bucketed TTL minus σ (`not_stored` otherwise). Kotlin re-checks `receipt.blobHash == h`.

**Result transactions.** One of the following runs, then D1, D2 and W from §3.5.

```sql
-- success (receipt)
UPDATE outbox_delivery SET state = 'acked', inflight = 0, ack_minute = :now_min,
       copy_hour = COALESCE(copy_hour, lease_hour)
 WHERE operation_id = :op AND relay_id = :r AND inflight = 1 AND state IN ('pending', 'wait_capability');
UPDATE outbox_delivery SET inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour)   -- late receipt on a closed/failed row
 WHERE operation_id = :op AND relay_id = :r AND inflight = 1 AND state IN ('failed', 'closed');

-- check-before-restore or quota path found h
UPDATE outbox_delivery SET state = 'verified', inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour)
 WHERE operation_id = :op AND relay_id = :r AND state <> 'verified';

-- ambiguous outcome (timeout, relay_unavailable, internal, closed, malformed_response, not_stored, unknown)
UPDATE outbox_delivery SET inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour)
 WHERE operation_id = :op AND relay_id = :r AND inflight = 1;

-- definite "not applied" (transport, unauthorized, quota+absent, rejected, local bug): §3.6 decides the state
UPDATE outbox_delivery SET inflight = 0 WHERE operation_id = :op AND relay_id = :r AND inflight = 1;
```

**Why this is enough:**

- The relay store is idempotent on `(namespace, hash)`: a repeat within the hour is a no-op, and a later repeat extends the same membership (verified). Resending the frozen bytes is always safe.
- The lease makes "crashed during the call" identical to "timed out".
- M1 (§3.5) is the one normalization statement for leases left in flight by a dead process.
- A native crash inside `store` cannot crash-loop the relay, because attempts and backoff commit before the call.

### 3.4 Verification and repair (S3, "compară inventarul")

A delivery in `acked` becomes `verified` on the first inventory observation after its receipt:

- **Listing, at no extra cost.** The list step marks as verified any own delivery whose hash appears in relay r's page (§4.1): acked, pending with a possible copy, failed or closed, as long as it is not in flight.
- **Check, for write-only pairs** (a contact's DM inbox), for pairs without a usable read capability, and when listing has not verified the delivery within `VERIFY_FALLBACK = 10 min`. At the pair's next event, `check(hashes ≤ 64)` runs with the write capability, which also grants read (verified), for deliveries with `ack_minute + 60 ≤ now`.

```sql
UPDATE outbox_delivery SET state = 'verified' WHERE operation_id = :op AND relay_id = :r AND state = 'acked';      -- present
UPDATE outbox_delivery SET strikes = strikes + 1,                                                                   -- absent
       state = CASE WHEN strikes + 1 >= 2 THEN 'failed' ELSE 'pending' END, next_attempt_minute = :now_min
 WHERE operation_id = :op AND relay_id = :r AND state = 'acked';
```

An absent result also adds 2 to the relay's work-lane breaker, and the relay is flagged `RELAY_SUSPECT` in `SyncStatus`. The repair store is idempotent. If the window has closed, M3 closes the delivery instead.

**Limit, stated honestly.** A relay that answers the writer's checks and listings truthfully but withholds from recipients cannot be detected by the writer, because the capability scope distinguishes the two. It is caught by readers listing every relay in the set (ADR-11) and by MLS transcripts (Phase 10).

### 3.5 Window, resolution, closure and decision (the rules that make D5 hold)

| Rule | Statement |
|---|---|
| Window (W-rule) | A **store** of op o is allowed only while every non-NULL `copy_hour` of o is newer than `now − H`. Before the first possible copy, there is no window. |
| Resolution | A delivery is *resolvable* when all of these hold: `copy_hour IS NOT NULL`; `ack_minute IS NULL`; state in {pending, wait_capability, failed, closed}; relay active; `now < copy_hour + ttl − σ`. Resolvable deliveries receive `check([h])` at their pair's next event (for pending ones, this is the check-before-restore). |
| Closure | Maintenance moves `pending`/`wait_capability` deliveries to `closed` when either the caller deadline has passed, or the window has expired **and** the op has no resolvable delivery. |
| Decision | D1 decides `sent`. D2 decides `degraded`, `failed` or `indeterminate` once nothing can progress. |

```sql
-- D1: quorum of verified copies
UPDATE outbox_op SET outcome = 'sent'
 WHERE operation_id = :op AND outcome = 'pending'
   AND (SELECT COUNT(DISTINCT rd.operator_id) FROM outbox_delivery d JOIN relay_directory rd ON rd.relay_id = d.relay_id
         WHERE d.operation_id = :op AND d.state = 'verified') >= required_operators;

-- D2: nothing left that could still become verified or be resolved
UPDATE outbox_op SET outcome = CASE
      WHEN EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = :op AND d.state = 'verified') THEN 'degraded'
      WHEN EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = :op AND d.copy_hour IS NOT NULL) THEN 'indeterminate'
      ELSE 'failed' END
 WHERE operation_id = :op AND outcome = 'pending'
   AND NOT EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = :op
                    AND (d.state IN ('pending', 'wait_capability', 'acked') OR d.inflight = 1))
   AND NOT EXISTS (SELECT 1 FROM outbox_delivery d JOIN relay_directory rd ON rd.relay_id = d.relay_id
                    WHERE d.operation_id = :op AND d.copy_hour IS NOT NULL AND d.ack_minute IS NULL
                      AND d.state IN ('failed', 'closed') AND rd.state = 'active'
                      AND :now < d.copy_hour + outbox_op.ttl_seconds - :skew);

-- W: payload wipe
UPDATE outbox_op SET ciphertext = NULL
 WHERE operation_id = :op AND ciphertext IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = :op
                    AND (d.state IN ('pending', 'wait_capability', 'acked') OR d.inflight = 1));
```

**Maintenance transaction** (work lane; M1 at session start, M2–M4 on every pass, **M3 and M4 only while the transport is READY**):

```sql
-- M1: leases left in flight by a dead process or an aborted session count as ambiguous (the work lane is idle now)
UPDATE outbox_delivery SET inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour) WHERE inflight = 1;

-- M2: park due deliveries that have no usable, unexpired write capability
UPDATE outbox_delivery SET state = 'wait_capability'
 WHERE state = 'pending' AND inflight = 0
   AND NOT EXISTS (SELECT 1 FROM outbox_op o JOIN relay_capability c
                     ON c.relay_id = outbox_delivery.relay_id AND c.namespace_id = o.namespace_id
                    WHERE o.operation_id = outbox_delivery.operation_id AND c.kind = 'write' AND c.state = 'usable'
                      AND (c.expires_hour IS NULL OR c.expires_hour > :now));

-- M3: closure (deadline, or expired window with nothing resolvable)
UPDATE outbox_delivery SET state = 'closed'
 WHERE state IN ('pending', 'wait_capability') AND inflight = 0
   AND operation_id IN (
     SELECT o.operation_id FROM outbox_op o
      WHERE (o.deadline_hour IS NOT NULL AND o.deadline_hour <= :now)
         OR (EXISTS (SELECT 1 FROM outbox_delivery x WHERE x.operation_id = o.operation_id
                      AND x.copy_hour IS NOT NULL AND x.copy_hour + :H <= :now)
             AND NOT EXISTS (SELECT 1 FROM outbox_delivery y JOIN relay_directory ry ON ry.relay_id = y.relay_id
                      WHERE y.operation_id = o.operation_id AND y.copy_hour IS NOT NULL AND y.ack_minute IS NULL
                        AND y.state IN ('pending', 'wait_capability', 'failed', 'closed') AND ry.state = 'active'
                        AND :now < y.copy_hour + o.ttl_seconds - :skew)));

-- M4: D1, D2, W for every op touched by M1–M3
```

**What this buys:**

- **No `failed` while a copy may exist.** Every attempt that could have stored sets `copy_hour`: in the result transaction, or through M1 after a crash. It returns to NULL only on an absence that proves the copy never existed.
- **No closure by offline time.** M3 runs only while READY, and closure needs a possible copy that is old and unresolvable. A device that comes back after 10 days first resolves: in the next pair events, a check finds absence (while `ttl − σ` has not elapsed), clears `copy_hour`, reopens the window, and stores.
- **The residual `indeterminate` case** needs all of: an ambiguous attempt, then no relay of the set answering for more than `max(H, TTL − σ)`. For example, a 7-day DM blob whose store timed out, followed by more than 7 days without reaching the set.

### 3.6 Mapping of every `NetworkException` category

The source is `client-core/README.md` (`categories.rs` `ALL`, plus `native_missing`). A Kotlin test parses the README table (declared as a Gradle test input, like `onion_addresses.txt`) and fails if any category lacks an explicit mapping. This mirrors the Rust test `categories_are_unique_and_documented`.

"Copy effect" is what a failed **store** attempt means for `copy_hour`. It is derived from the verified code paths: a `transport` error comes from a connector that never opened a stream; the relay verifies the capability and quota before persisting anything, and a quota denial is refunded.

| Category | Class | Copy effect | Store (work lane) | List (read lane) / get / check (work lane) |
|---|---|---|---|---|
| `closed` | ABORT | ambiguous | stop the lane; the result transaction marks the copy | stop the lane |
| `not_bootstrapped` | NEEDS_BOOTSTRAP | none | stop; the holder bootstraps | same |
| `tor_bootstrap`, `tor_bootstrap_timeout` | NEW_TRANSPORT | none | stop; close and recreate the transport; in-memory backoff 1→15 min | same |
| `tor_setup`, `runtime`, `native_missing` | LOCAL_FATAL | none | stop; status `TRANSPORT_FAILED` (`NATIVE_MISSING` disables sync for the process) | same |
| `bridge_config` | CONFIG | none | stop; status `BRIDGE_CONFIG`; no retry until the config changes | same |
| `transport` | RELAY_TRANSIENT | none | lease backoff; breaker +1 | list: skip, cursor unchanged; get: fetch backoff; breaker +1 |
| `timeout`, `relay_unavailable`, `internal` | RELAY_TRANSIENT_AMBIGUOUS | **possible copy** | lease backoff; breaker +1; the next attempt checks first | as above |
| `malformed_response` | RELAY_HOSTILE | **possible copy** | backoff; breaker +2 | list: page dropped, cursor unchanged; get: source `bad`; check: no answer; breaker +2 |
| `not_stored` | RELAY_ANOMALY | **possible copy** (a short membership) | backoff; breaker +2; the retry extends the membership | n/a |
| `unauthorized` | NEEDS_CAPABILITY | none | capability `rejected` (generation guard, §3.8); delivery `wait_capability` | read capability `rejected`; the pair is suspended until a new generation |
| `quota` | NEEDS_CAPABILITY | none (nothing persisted) | `check([h])` with the same token: present → `verified`; otherwise capability `exhausted` and delivery `wait_capability` | cannot occur (charged only on store); treated as RELAY_HOSTILE |
| `not_found` | MISSING | n/a | treated as RELAY_HOSTILE | get: source `not_found`; with no candidate left the row becomes `unavailable` |
| `rejected` | PERMANENT (for item and relay) | none | delivery `failed` (for example the relay's `max_ttl_seconds` is below the bucket; verified in the node) | pair paused 24 h; status `RELAY_REJECTS` |
| `invalid_argument`, `not_bucket_sized`, `not_onion`, Kotlin `IllegalArgumentException` | LOCAL_BUG | none | delivery `failed`; status `BUG` (`not_onion`: relay breaker 24 h) | pair paused 24 h; status `BUG` |
| unknown string | defensive | **possible copy** | as RELAY_TRANSIENT_AMBIGUOUS, plus status `UNKNOWN_CATEGORY` | same |

### 3.7 Backoff, breakers, budgets, clock

- **Delivery and fetch backoff.** `b(n) = min(60 s × 2^(n−1), 1 h) × U[0.5, 1]` from the selection stream, rounded up to the minute and computed at lease time. Offline sessions lease nothing, so they add no attempts.
- **Breakers**, per lane and in memory:
  - they open when `failures ≥ 3`, for `min(60 s × 2^(failures−3), 30 min) × U[0.75, 1.25]`;
  - any success resets them;
  - the read lane counts list outcomes only, so a user's failing stores can never change the list schedule (T19).
- **Budgets:**
  - per-call deadline `min(policy, remaining session budget − 5 s)`; policy is 20 s for lists and 60 s for everything else;
  - background: per-relay work budget of 90 s of call time per session, session budget 8 min (under the ~10 min job limit);
  - foreground: no session budget.
- **Clock:**
  - a backward jump is clamped: any `next_attempt_minute > now + 61 min` is treated as due;
  - M3, D2 and GC run only after the transport reached READY in this process, where Arti has accepted the consensus clock (σ). A forward jump therefore cannot close windows or delete tombstones early.

### 3.8 Capabilities: storage, use, and the rejection race

- Phase 8 calls `Capabilities.put(tx, relay, ns, kind, token, expiresAt)`. This upserts `state = 'usable', generation = generation + 1, expires_hour = floor_hour(expiresAt)`. For write tokens, the same transaction re-arms parked deliveries:

  ```sql
  UPDATE outbox_delivery SET state = 'pending', next_attempt_minute = :now_min
   WHERE relay_id = :r AND state = 'wait_capability'
     AND operation_id IN (SELECT operation_id FROM outbox_op WHERE namespace_id = :ns);
  ```

  A post-commit hook refreshes the read lane's snapshot.
- **The race.** An attempt leases with generation g; Phase 8 installs g+1; the g call then returns `unauthorized`. The result transaction marks the capability rejected only `WHERE generation = :g AND state = 'usable'`. If the stored generation is already greater than g, the delivery stays `pending` with `next_attempt_minute = now`.
- An expired capability returns `unauthorized` from the relay (`CapError::Expired`, verified). Expiry is also filtered locally through `expires_hour`.
- `Capabilities.needed()` returns `CapabilityNeed(relay, ns, kind, reason ∈ {MISSING, REJECTED, EXHAUSTED, EXPIRING})`; EXPIRING means within 24 h. Phase 7 never mints and never contacts the issuer.
- Lists and gets use the read capability, or the write capability when no usable read capability exists (on the relay, write grants read).
- Rust `NamespaceClient` refuses a token whose header names another namespace or the wrong kind (T21). Kotlin never parses tokens.

### 3.9 Relay-set changes, retirement, cancel

- `Namespaces.setRelays(tx, ns, relays)`:
  - adds `pending` deliveries (`INSERT OR IGNORE`) for new relays, for ops that still hold their payload and whose window is open;
  - moves deliveries to removed relays from `pending`, `wait_capability` or `acked` to `failed` (`copy_hour` is kept);
  - runs D1, D2 and W.
- `RelayDirectory.retire(tx, r)`: `state = 'retired', retired_day = today`, then the same delivery handling for every namespace. Cursors and capabilities are kept, so a re-add of the same onion reactivates the row. The row is deleted after `LISTED_RETAIN` days if nothing references it.
- `Outbox.cancel(tx, op)` succeeds only while no delivery of the op has `copy_hour` or `inflight = 1`. It moves all deliveries to `failed`, and D2 then decides `failed`. Otherwise it returns false.

### 3.10 Crash points

| # | Crash point | State after restart | Why it is safe |
|---|---|---|---|
| C1 | inside the enqueue transaction | nothing; the caller's changes are rolled back too | the user action did not happen |
| C2 | after the enqueue commits | op `pending`, deliveries due | durable |
| C3 | inside the lease transaction | unchanged | leased again later |
| C4 | lease committed, request never sent | `inflight = 1` | M1 marks a possible copy; the next attempt checks first; absence clears it; costs one check |
| C5 | relay applied the store, response lost | `inflight = 1`, or an ambiguous result | M1 or the result marks a possible copy; check finds h, so `verified` |
| C6 | response received, crash before the result transaction | as C5 | as C5 |
| C7 | inside a result transaction | rolled back to C5 | as C5 |
| C8 | after the result transaction | `acked`/`verified`, maybe decided | outcome decided once (trigger) |
| C9 | inside a verification or resolution transaction | previous state | the check is repeated; it is read-only at the relay |
| C10 | between the outcome and `release` | decided, `released = 0` | offered again; `release()` is true once, in the consumer's transaction |
| C11 | inside maintenance or GC | rolled back | idempotent |

### 3.11 Proof sketch (outbox)

- **OUT-2/OUT-3.** The ciphertext is immutable (trigger) and is the only payload any store sends. The relay keeps one membership per `(ns, hash)` (conformance vectors, §8.7). `outcome` leaves `pending` once (trigger, guarded updates). `released` goes from 0 to 1 once.
- **OUT-4.** `sent` needs a quorum of verified deliveries, and verification is an inventory observation. `failed` needs every `copy_hour` to be NULL. `copy_hour` is set by every attempt that may have stored (result transactions, and M1 before any other work in a session). It is cleared only by an absence observed while any copy made at or after the earliest possible hour would still be live (`copy_hour + ttl − σ > now`), and never after an ack (trigger). `degraded` and `indeterminate` follow from the D2 CASE.
- **OUT-1.** With no possible copy, M3 can close deliveries only when the caller's deadline passes. A delivery without a copy stays `pending` or `wait_capability`, and is re-attempted at least every `1 h` (backoff cap) plus `30 min` (breaker cap) plus one pair interval. Under the liveness assumption, an honest relay returns a receipt, and the next inventory observation verifies it; with 2 operators the op is `sent`. When a possible copy exists, the resolution rule forces a check before closure while the copy is still resolvable.

---

## 4. Inbox

### 4.1 List step and cursor rules (read lane)

A pair (relay r, namespace ns) is listed when all of these hold: ns is listening; r is active in the set; a usable read (or write) capability exists; the read breaker is closed; the pair is not paused.

At each pair event, the read lane issues `list(cursor = snapshot or empty, limit = 128, deadline = 20 s)`. Then, in one transaction:

```sql
INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day)
VALUES (:ns, :h, 'listed', :today + 111)
ON CONFLICT(namespace_id, blob_hash) DO UPDATE
   SET retain_until_day = max(inbox_blob.retain_until_day, excluded.retain_until_day)
 WHERE inbox_blob.state IN ('listed', 'unavailable');                  -- fetched/done keep their expiry-based bound
INSERT INTO inbox_source(namespace_id, blob_hash, relay_id, state)
SELECT namespace_id, blob_hash, :r, 'candidate' FROM inbox_blob
 WHERE namespace_id = :ns AND blob_hash = :h AND state IN ('listed', 'unavailable')
ON CONFLICT(namespace_id, blob_hash, relay_id) DO NOTHING;             -- existing not_found/bad are kept
UPDATE inbox_blob SET state = 'listed'
 WHERE namespace_id = :ns AND blob_hash = :h AND state = 'unavailable'
   AND EXISTS (SELECT 1 FROM inbox_source s WHERE s.namespace_id = :ns AND s.blob_hash = :h
                AND s.state = 'candidate');
-- own copy seen in this relay's inventory: verification (§3.4); then D1, D2, W for that op
UPDATE outbox_delivery SET state = 'verified'
 WHERE relay_id = :r AND state <> 'verified' AND inflight = 0
   AND operation_id = (SELECT operation_id FROM outbox_op WHERE namespace_id = :ns AND blob_hash = :h);
-- cursor: only when next_cursor is non-empty
INSERT INTO relay_cursor(relay_id, namespace_id, cursor) VALUES (:r, :ns, :next)
ON CONFLICT(relay_id, namespace_id) DO UPDATE SET cursor = excluded.cursor;
```

After the commit, the read lane updates its snapshot cursor and queues `Fetch(pair)` on the work lane.

**Cursor rules.** Kotlin never interprets cursor bytes. Rust enforces a length of 0 or 8.

1. **Hashes and cursor commit in one transaction.** The cursor only moves to a value that arrived with the rows just inserted.
2. **An empty `next_cursor` means "caught up": keep the old cursor (sticky tail).**
   - Verified in `relay/crates/storage::list`: the relay returns an empty cursor when the namespace is exhausted, including when exactly `limit` entries remained.
   - Storing the empty cursor would restart the listing from the beginning.
   - Keeping the old cursor re-lists fewer than `LIST_LIMIT` known hashes per event. Dedup absorbs them and the request count does not change.
3. **Bounded pages per event.**
   - HIGH mode: exactly 1 page.
   - STANDARD mode: up to 4 pages. A further page is requested only if the previous page was full (`|hashes| = limit`) and its non-empty cursor differs from the one sent.
   - A relay that returns a non-empty cursor with an empty page, or cycles through cursors, can therefore cost at most 4 requests per event (Phase 6 note).
   - A non-empty cursor with an empty page is still committed. The real relay produces one when it skips more than `MAX_LIST_SCAN = 1024` expired entries (verified).
4. **Rewinds and jumps.** A rewind only causes re-listing, which dedup absorbs. A forward jump is withholding (§4.4).

**Backpressure never changes the request schedule.**

- Over `BACKLOG_CAP`, the list request is still sent, but its page is discarded and the cursor is left where it was.
- `FETCHED_CAP = 256` fetched-but-unconsumed rows per namespace only throttles fetches, on the work lane.

### 4.2 Fetch step (work lane)

**Planning.** For the pair's namespace, skipped if it is at `FETCHED_CAP`:

- take up to `FETCH_PER_EVENT = 8` rows with `state = 'listed'` and `next_fetch_minute ≤ now`;
- r must be a `candidate` for the row;
- oldest `retain_until_day` first, then the hash.

A hostile relay therefore spends only its own pair's slots.

**Lease.**

```sql
UPDATE inbox_blob SET fetch_attempts = fetch_attempts + 1, next_fetch_minute = :now_min + :backoff_min
 WHERE namespace_id = :ns AND blob_hash = :h AND state = 'listed' AND next_fetch_minute <= :now_min;  -- must be 1
```

**Call.** `get(r, ns, readCap, h, deadline)`. Rust has already checked that SHA-256 matches, that the size is a bucket, and that the expiry is within bounds. Kotlin re-checks the hash.

**Success transaction.**

```sql
UPDATE inbox_blob
   SET state = 'fetched', ciphertext = :c,
       fetch_seq = (SELECT COALESCE(MAX(fetch_seq), 0) + 1 FROM inbox_blob),
       fetch_attempts = 0, next_fetch_minute = 0,
       retain_until_day = :expiry_day + 24                                    -- §2.3, TAIL
 WHERE namespace_id = :ns AND blob_hash = :h AND state = 'listed';            -- trigger drops sources
```

**`not_found`.** The source becomes `not_found`. If no `candidate` source remains, the row becomes `unavailable`. It returns to `listed` if any relay lists the hash again.

**Dedup across relays is structural.** One row exists per `(ns, h)`, and it can have several sources.

### 4.3 Hand-off to consumers (exactly once, no crash loop)

- **`Inbox.claim(consumer, limit)`** runs in its own short transaction:
  - It selects `fetched` rows for the consumer's namespaces with `offer_after_minute ≤ now`, ordered by `fetch_seq`.
  - For each row it sets `offers = offers + 1`. If `offers + 1 ≥ 3`, it also sets `offer_after_minute = now + min(2^(offers+1−3) h, 24 h)`.
  - It returns the blobs.

  A blob that crashes the process natively is therefore offered again after 1 h, 2 h, 4 h … up to 24 h. **It is never dropped**, and `SyncStatus` reports `CONSUMER_POISONED`.
- **`markConsumed(tx, ns, h)`** runs in the consumer's own transaction, together with its own writes:

  ```sql
  UPDATE inbox_blob SET state = 'done', ciphertext = NULL, fetch_seq = NULL, offers = 0, offer_after_minute = 0
   WHERE namespace_id = :ns AND blob_hash = :h AND state = 'fetched';      -- true iff 1 row
  ```

  Consumers must mark every blob consumed, including garbage and undecryptable ones, and record their own verdict.
- **`defer(tx, ns, h, seconds ≤ 7 d)`** (graft from the platform design; for MLS future-epoch messages): `SET offer_after_minute = :m, offers = 0 WHERE state = 'fetched'`.

### 4.4 Hostile relays

| Behaviour | Effect | Defence |
|---|---|---|
| Cursor rewind, or repeated hashes | re-listing | `DISTINCT` per page; UPSERT; page bound |
| Non-empty cursor with an empty page, forever | none | page bound per event |
| Withholding: never lists h, or jumps past it | h missing from this relay | ADR-11: the sender wrote to every relay in the set, and readers list every relay. MLS transcript gaps come in Phase 10 (S3). |
| Lists h but `get` returns `not_found` | h unavailable here | other candidates; `unavailable`; GC after 111 d |
| Serves wrong bytes | Rust returns `malformed_response` | source `bad`; breaker +2; try another candidate |
| Floods garbage hashes | table growth | `BACKLOG_CAP` per (relay, ns): pages are dropped, rows stay bounded |
| Lists a hash from another namespace | undecryptable blob | the consumer marks it consumed and rejected |
| Lies about expiry (short) | early tombstone GC | Rust bounds the high side; a short expiry at worst allows a replay, which is the protocol-layer boundary (§0.2) |
| Acks a store, then drops it | false replication | §3.4 verification and repair |
| Stalls every call for 60 s | cycle time | per-call deadline (20 s for lists), per-relay budget, breakers |

### 4.5 Inbox crash points

| # | Point | State after restart | Why it is safe |
|---|---|---|---|
| L1 | before `list` | unchanged | nothing happened |
| L2 | page received, crash before commit | cursor unchanged | the same page is listed again; inserts are idempotent |
| L3 | inside the list transaction | rolled back to L2 | as L2 |
| L4 | after the commit | hashes durable, cursor advanced | IN-3 |
| F1/F2 | fetch lease committed; crash during or after `get` | `listed`, with backoff | `get` is idempotent |
| F3 | after the fetch commit | `fetched` | durable |
| D0 | after `claim` commits, crash during handling | `fetched`, `offers` incremented | offered again, with backoff from the third offer |
| D1 | inside the consumer transaction | `fetched`; consumer effects rolled back | offered again |
| D2 | after the consumer commits | `done` | never offered again (trigger) |
| G | inside GC | rolled back | idempotent |

### 4.6 Proof sketch (inbox)

- **IN-3.**
  - The cursor for (r, ns) is written only in the transaction that inserted the page returned with it.
  - For an honest relay, page(c) contains every live entry with a sequence in (c, c′], where c′ is the last examined sequence.
  - New entries get larger sequences. An extension keeps its sequence; a renewal gets a new one. A namespace that empties and returns restarts from the hour seed `hours << 32`, above every earlier value. All three verified.
  - So by induction every entry at or below the stored cursor that was live when listed has a row, or its row was garbage-collected after the blob expired everywhere (§2.3).
- **IN-2.**
  - There is at most one row per `(ns, h)`.
  - `fetched → done` happens once (trigger, plus `markConsumed` returns true once).
  - Own blobs are inserted as `done`.
  - A `done` row is deleted only after `retain_until_day`. Past that day no honest relay holds a live membership of h (§2.3 derivation), so h cannot be listed again.
- **IN-1.**
  - A listing creates a candidate. Fetch leases are retried at most every hour plus one pair interval.
  - `listed` rows are garbage-collected only after 111 days without being listed, when no honest relay can serve them.
  - `fetched` rows are never garbage-collected.

---

## 5. Scheduling on Android

### 5.1 Platform facts (API 29–37) that shape the design

| Fact | Consequence | Evidence |
|---|---|---|
| Periodic jobs: minimum period 15 min, minimum flex 5 min; a job runs about 10 min at most | background cadence is set by the OS; the session budget is 8 min | assumed from platform docs; checked in S7 |
| Doze and standby buckets (rare, restricted) defer jobs by hours, up to about a day; Android 16 tightens job quotas | background latency is hours; correctness is unaffected | assumed; S7 |
| `setPersisted(true)` requires `RECEIVE_BOOT_COMPLETED` | permission needed with either scheduler | assumed (documented); S7 |
| targetSdk ≥ 34: network-constrained jobs require `ACCESS_NETWORK_STATE` | permission needed with either scheduler | assumed (Android 14 behaviour change); S7 on API 37 |
| A JobService with `exported="false"` can be bound by `system_server` (the system UID bypasses the exported check) | no exported component added | assumed; S7 on API 29 and 37. Fallback in §5.5 |
| FGS type `dataSync` is capped at 6 h per 24 h for targetSdk ≥ 35 and cannot start from `BOOT_COMPLETED` | prompt mode cannot be always-on `dataSync`; deferred to Phase 13 with its own ADR | assumed |
| The cached-app freezer stops background processes within seconds | the in-process driver runs only while the app is visible; the transport closes 30 s after `onAppBackground` | assumed |
| `AndroidKeystoreWrapper(requireUserAuthentication = true)` makes the DB key unusable outside a 30 s window after unlock | a background job cannot open the DB in that mode, so it returns with **no network I/O** | **verified** (`identity/AndroidKeystoreWrapper.kt`) |
| SQLCipher derives the key with PBKDF2 on every open when given passphrase bytes (`SupportOpenHelperFactory(key)`) | each background job pays one open; measured for NFR-5 | assumed |
| `:app` has no `Application` class; `lifecycle-process` (`ProcessLifecycleInitializer`) is already merged | Phase 7 adds a minimal `GhostApp` | **verified** (app sources, merged manifest) |

### 5.2 Options compared

| Option | Cadence | Survives process death and reboot | Plaintext on disk (AD-8) | Supply chain and manifest | Verdict |
|---|---|---|---|---|---|
| **WorkManager 2.11.2** (ADR-06, §6.6, spec) | runs on JobScheduler at minSdk 29; same limits | yes (own Room DB plus receivers) | **own unencrypted Room DB `androidx.work.workdb`** holding WorkSpec (class, input `Data`, `last_enqueue_time`, run and period counts), tags, names and preferences with force-stop times (assumed from upstream; no local AAR). Work enqueued from a user action records when the user acted. | POM **verified**: room-runtime 2.7.0, lifecycle-service/livedata 2.6.2, concurrent-futures-ktx, tracing-ktx, startup-runtime, kotlinx-coroutines-android 1.9.0, jspecify 1.0.0, listenablefuture 1.0. Manifest (assumed): `WAKE_LOCK`, `ACCESS_NETWORK_STATE`, `RECEIVE_BOOT_COMPLETED`, `FOREGROUND_SERVICE`; exported `SystemJobService` and `DiagnosticsReceiver`; INFO logging by default | works, but adds a second plaintext DB and 4 permissions, 2 of them outside T15 today |
| **JobScheduler (platform)** | same OS limits | yes, with `setPersisted(true)` | only the system `jobs.xml` entry (component, period, constraints, run times); **no extras** | **zero dependencies**; `RECEIVE_BOOT_COMPLETED`, `ACCESS_NETWORK_STATE`; one non-exported `JobService` | **chosen for background** |
| Foreground service | constant | while running | notification only | a type permission; `dataSync` capped | deferred to Phase 13 |
| In-process driver while visible | constant, per pair | no | nothing | none | **chosen for foreground** |
| AlarmManager (exact) | ≥ 9 min apart in Doze | needs a receiver | none | restricted permissions | rejected |

### 5.3 WorkManager evidence

**Verified:**

- `androidx.work:work-runtime-ktx:2.11.2` is declared in `libs.versions.toml`, used by no module, and absent from `~/.gradle/caches`.
- Its POM (fetched 2026-09-11 from dl.google.com) lists the dependencies in the row above.
- `com.google.guava:listenablefuture:1.0`, `org.jspecify:jspecify:1.0.0` and `org.jetbrains:annotations:23.0.0` are already in `verification-metadata.xml` and in the Gradle cache, i.e. already on the shipped classpath through androidx.
- None of these three groups is in `dependency-allowlist.txt`. T7 does not see them because it parses declared coordinates only (F1, §10.6).
- The merged release manifest already contains an exported `ProfileInstallReceiver` (protected by `DUMP`), `InitializationProvider` (not exported), and a signature permission `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`. T15 scans source manifests only.

**Assumed**, to be verified only if ADR-20 is rejected: WorkManager's manifest components, its `workdb` schema, and Room's own transitive set. The conclusion does not depend on the exact columns. Any WorkManager use adds a plaintext database with scheduling times outside SQLCipher.

### 5.4 Decision (goes into ADR-20)

- **Background job:**
  - `JOB_ID = 0x47535931`, `setPeriodic(15 min, 5 min)`, `setPersisted(true)`, `setRequiredNetworkType(NETWORK_TYPE_ANY)`, empty extras, no other constraints.
  - `JobSchedulerWake.ensurePeriodic()` compares `getPendingJob(JOB_ID)` and calls `schedule()` only if it differs, so the period timer is not reset.
  - It is called from `GhostApp.onCreate` only when the DB key envelope exists (`DatabaseKeyProvider.exists()`), and never because of user activity or data arrival.
- **`SyncJobService.onStartJob`** posts a `BACKGROUND` session to the runtime thread and returns true. The session:
  1. opens the DB through the app-supplied `DatabaseOpener`; an auth-bound key means stop with no network;
  2. `ensureReady` (bootstrap within the remaining budget);
  3. M1 and maintenance;
  4. gives each pair one event at offset `W·U(pair, BACKGROUND_OFFSET, job)` within `W = 90 s`;
  5. drains the work lane;
  6. runs GC, closes the transport, and calls `jobFinished(params, false)` **always**, so JobScheduler's backoff never ties timing to failures.

  If a foreground session is active, the job returns immediately.
- **`onStopJob`** calls `transport.abort()` (in-flight calls end with `closed`, which the result transaction treats as ambiguous) and returns false.
- **Foreground:**
  - `SyncController.onAppForeground()` / `onAppBackground()`, wired from `ProcessLifecycleOwner` in `GhostApp`, start and stop a `FOREGROUND` session.
  - Each foreground session creates a fresh transport, which also rotates circuits per session.
  - The transport closes 30 s after `onAppBackground`.
- **Expedite** (STANDARD mode, foreground only): `requestExpedite()` wakes the work lane for due stores. It never creates read-lane events. It is a no-op in HIGH mode.
- **Plan deviation.** ADR-06, Plan §6.2/§6.6 and the spec's FR-7.x line ("WorkManager and coroutines") name WorkManager, so this is recorded as **ADR-20 (propus)**. The engine uses two plain threads rather than coroutines, because the JNI calls block. Nothing in the engine, schema, tests or proofs depends on this choice (§5.7).

### 5.5 Manifest and gate changes

Declared in the **app** manifest. Library manifests stay without `<application>`: `manifest-lint.sh` scans every module's manifest and requires backup attributes on any manifest with `<application>` (verified).

```xml
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />  <!-- ADR-20: persisted job -->
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />    <!-- ADR-20: network constraint -->
<application android:name=".GhostApp" ... existing attributes ...>
    <service android:name="org.ghost.sync.android.SyncJobService"
             android:permission="android.permission.BIND_JOB_SERVICE"
             android:exported="false" />
</application>
```

- `manifest-lint.sh`: add both permissions to `ALLOWED_PERMISSIONS`, citing ADR-20.
- **New merged-manifest mode (T15m)**, run in the `android` CI job after `assembleRelease` against `app/build/intermediates/merged_manifest/release/.../AndroidManifest.xml`. It checks:
  - permissions against the allowlist, plus the app's own signature permission `${applicationId}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`;
  - every exported component is either the LAUNCHER activity or on an ADR-referenced list with a required protecting permission;
  - `SyncJobService` is non-exported and protected by `BIND_JOB_SERVICE`.

  The existing `ProfileInstallReceiver` needs a decision (Q7): remove it with `tools:node="remove"`, or allowlist it with `DUMP`. T15m gets a negative fixture under `test-harness/gates/`.
- **Fallback** if S7 shows that `exported="false"` cannot be bound: `exported="true"` with `BIND_JOB_SERVICE`. This needs a merged-lint exception, covered by ADR-20.
- **New static gate `kotlin-clearnet.sh` (T6, Kotlin side):** no `java.net.(Socket|URL|HttpURLConnection|InetAddress|DatagramSocket)` and no `javax.net` in any `android/*/src/main`. Today there are none (verified). It gets a negative fixture.

### 5.6 Edge cases

| Situation | Behaviour |
|---|---|
| Doze or rare bucket | fewer and later jobs; latency only |
| Reboot | persisted job; runs after first unlock (credential-encrypted storage) |
| Force-stop | job held until the next launch; `ensurePeriodic()` in `GhostApp` |
| App update | persisted job survives; `ensurePeriodic()` anyway |
| Auth-bound DB key (Q6) | background sessions do nothing; foreground only |
| Process killed mid-session | M1 at the next session; §3.10 and §4.5 |
| Foreground starts during a background session | the background session stops new items and drains; then the foreground session starts |

### 5.7 Fallback if ADR-20 is rejected

A `WorkManagerWake : WakeScheduler` adapter:

- one unique `PeriodicWorkRequest` (`KEEP`), no input `Data`, no extra tags, always `Result.success()`;
- no one-time work in HIGH mode; in STANDARD mode, expedite stays in-process;
- on-demand initialization (`WorkManagerInitializer` removed with `tools:node="remove"`), `DiagnosticsReceiver` and `SystemForegroundService` removed, logging level raised through a custom `Configuration`;
- `WAKE_LOCK` added through the ADR;
- T7 first moved to the resolved classpath;
- T20 reworded to "exactly one constant periodic WorkSpec", verified by an instrumented read of `workdb`;
- the `workdb` residue declared in L1.

The engine, schema and proofs do not change.

---

## 6. Traffic shaping (ADR-09, ADR-15)

### 6.1 Model and rules

- **A pair** is (relay r, namespace ns).
  - *Read pairs* are listening namespaces × active relays in their set with a usable read (or write) capability.
  - *Write pairs* are write-only (r, ns) with outstanding deliveries: pending, acked-unverified, or resolvable. They exist only while there is work, because a store *is* the user's activity.
- **Per-pair schedule** (foreground). The first event is at `t₀ = S + T·u(p, START, 0)`; then `t_{k+1} = t_k + T·(0.5 + u(p, STEP, k))`.
  - `u` is HmacSHA256 over (process key, pair, purpose, index), mapped to [0, 1); `T = 30 s`.
  - This is the "interval fix + jitter" of ADR-15, with **an independent phase per pair**. A client's namespaces share no tick, so a relay hosting several of them cannot link them by foreground timing.
  - A pair's times depend only on the key, the pair and the session start S. They do not depend on other pairs, on activity, or on how long events take. Skipped events consume their index.
  - A new pair (subscription or capability change) starts at `now + T·u`.
- **Background.** Each pair gets one event at `S_job + W·u(p, BG_OFFSET, job)`, `W = 90 s`. Session times are chosen by the OS.
- **Event bundle:**
  - read pair: 1 list (1 page in HIGH, ≤ 4 in STANDARD), then up to 8 fetches for that pair on the work lane;
  - verification or resolution checks for the pair (≤ 64 hashes);
  - **HIGH mode**: the pair's stores (≤ 8) run only at its events and only after `not_before`. No request is ever caused directly by a local event.
  - **STANDARD mode**: stores run as soon as they are due (NFR-1). Only the read schedule is independent of activity.
- **"Fixed-size batches" (ADR-09), as read here and recorded in ADR-20:**
  - `limit` is always 128 for every client, so `batch_count` is constant, and HIGH mode reads a fixed number of pages per event.
  - GETs are single-blob requests (the protocol has no batch get) and **are not padded with fillers in Phase 7**. Refetch fillers can be recognised by the relay (same capability scope and hash), cost bandwidth continuously, and protect only against a network observer's volume view. That is cover traffic (FR-2.6 P2, Phase 12).
  - Check batches are not padded, because the relay knows which of the hashes are real.
- **Circuits.** A fresh transport (new isolation tokens) per foreground session and per background job. **No periodic global rotation**, for two reasons:
  - rotating every scope at the same instant would create correlated change points across namespaces;
  - within one namespace, requests are linkable anyway through `capability_scope` (an allowed observable) and through the cursor (§6.3).

  Per-scope rotation is deferred to Phase 12, together with the rotation epoch.

### 6.2 Parameters (`TrafficPolicy`, one file; tuned in Phase 12 against NFR-1 and NFR-5)

| Parameter | STANDARD | HIGH |
|---|---|---|
| Foreground interval per pair | 30 s × U[0.5, 1.5], independent phase | same |
| Background | job 15 min, flex 5 min; one event per pair within W = 90 s | same |
| `LIST_LIMIT` | 128 (identical for all clients) | 128 |
| Pages per event | ≤ 4 (only while full and advancing) | exactly 1 |
| Fetches per pair event | 8 | 8 |
| Stores | when due (≤ 32 per pass) | at pair events, ≤ 8 per event |
| Send delay | 0 | U[0, 10 min], sampled once, minute granularity |
| Check batch | ≤ 64 | ≤ 64 |
| `LATE_TOLERANCE` (read lane) | 2 s | 2 s |
| List deadline / other calls | 20 s / 60 s | same |
| Transport close after backgrounding | 30 s | 30 s |

### 6.3 What each observer can learn after Phase 7

| Observer | Learns | Does not learn / reduced by |
|---|---|---|
| Relay (AD-2), per namespace | All of one client's requests for a namespace are linkable through `capability_scope` and through the cursor values the relay hands out. A malicious relay can use unique cursors as cookies across circuits and sessions. List polls at a fixed rate that is the same for everyone. Gets whose count follows *others'* writes. Stores (hash, bucket, TTL bucket, minute) follow *our* writes: immediately in STANDARD, delayed in HIGH. Own-copy checks. | IP and identity (onion, Tor). Cross-namespace links in the foreground (independent phases, per-namespace isolation, T21). The number of subscriptions (the rate per namespace is fixed). Send time in HIGH mode. |
| Colluding relays | the same hash on each relay of a set (inherent to ADR-11; TB-3) | — |
| Network observer (AD-4/5) | When Tor sessions start and stop (app opened, OS jobs). An aggregate request rate proportional to the number of pairs. Download volume following inbound traffic, upload bursts following sends. | Destinations, namespaces, content, exact sizes |
| Device forensics (AD-8) | The §2.3 residue; pending outbox rows; cursors and capabilities; OS `jobs.xml`, netstats and batterystats, which do not depend on activity in HIGH mode | request history, schedules, failures (none persisted) |

**Honest residuals** (added to LIMITE L2):

1. **Session-start co-occurrence.** All of a client's pairs start within T after the app opens, and within W in each background job. A relay hosting several of the client's namespaces sees them begin together. The fix is ADR-15 read bucketing (P2).
2. **Per-namespace linkability through capability and cursor.** The fix is shared read capabilities (Phase 8 decision) and shared cursor anchors (Phase 12). Recorded in the THREAT_MODEL §6 row "Citire canal".
3. **Volume follows activity** until cover traffic exists (P2).
4. **Presence.** Foreground and background cadences differ.
5. **NFR-1.** With a 30 s interval, DM p95 is about 40 s in the foreground and hours in the background. Recorded in ADR-20; decision Q2.

### 6.4 Deferred to Phase 12 or P2

Tuning T, jitter and caps from measurements; T17 network capture with a KS test; cover stores and filler gets (P2); read bucketing / PIR-lite (P2); per-scope rotation and pooled clients with a rotation epoch; shared cursor anchors; bridges and pluggable transports.

---

## 7. Privacy invariants

### 7.1 Existing invariants this phase touches

| ID | Phase 7 effect |
|---|---|
| T1 | No new relay observable: store, get, list and check already exist; `request_id` stays random per request (verified). A JVM test asserts that **no operation id ever reaches `RelayPort`**. |
| T3 | Every public type's `toString()` is redacted; exceptions carry constant categories only. Canary test in §8.6. |
| T4 | All state is in the SQLCipher DB in the no-backup directory. No new file. |
| T6 | The only network path is `RelayPort` → `TorRelayTransport`. New `kotlin-clearnet.sh` gate. |
| T7 | Phase 7 adds **no production dependency**. Test-only: junit and `org.xerial` (allowlisted). |
| T9 | CHECK limits ciphertext to bucket sizes; Rust enforces the same on the wire. |
| T15 | App manifest changes via ADR-20; new merged-manifest mode T15m. |
| T17 | Phase 7 delivers the JVM precondition (T19). The capture and KS test stay in Phase 12. |

### 7.2 New invariants (added to `INVARIANTS.md`)

| ID | Invariant | Verification | Executable from |
|---|---|---|---|
| T19 | **The read schedule is independent of activity.** Fix the keys, the set of read pairs, capability states and the list-latency trace. Then the start time, pair and `limit` of every event's first list request are identical with and without outbox and inbox activity, including consumer transactions and failures on work-lane calls. In HIGH mode the whole list sequence is identical, and every store and check falls on a pair event at or after `not_before`. Enqueue and consume never create read events. | deterministic JVM test with exact equality and a non-zero latency model (§8.6) | Phase 7 |
| T20 | **Sync leaves nothing outside SQLCipher.** No file, preference or job extra. Every persisted time column in sync tables is `*_minute`, `*_hour` or `*_day` with a matching CHECK. No schedule, breaker, latency or history is persisted. `done` rows hold only `(ns, hash, retain_until_day)`. The scheduler holds one periodic job with empty extras. | schema introspection test (JVM); instrumented sandbox inventory plus `getAllPendingJobs()` (manual until emulator CI) | Phase 7 |
| T21 | **Isolation scope equals capability scope.** Every relay call's isolation namespace equals the namespace in the capability header, and the kind fits the operation. A mismatch fails before any I/O. | Rust unit tests on `NamespaceClient`; a hostile-relay test counts zero requests on mismatch | Phase 7 |

### 7.3 Never logged, never persisted outside SQLCipher

Capability tokens, ciphertexts, blob hashes, namespace ids, operation ids, cursors, onion addresses, timing, and any error detail beyond the constant category. There is no `Log.*` or `println` (gate), no job extras, and no notification content (T11, Phase 13). `SyncStatus` holds counts and enums only.

---

## 8. Test plan that proves the exit gate on the JVM

### 8.1 World and client

- **World** (survives a crash):
  - the SQLite **file** in a temp directory, using sqlite-jdbc; every suite runs in both `journal_mode=DELETE` and `WAL`;
  - the `ModelRelay`s (remote state, which may hold a committed store the client never learned about);
  - `TestClock` (wall and monotonic);
  - "other clients", which write straight into model relays.
- **Client** (discarded at a crash): engine, lanes, snapshots, breakers, transport fake.
- **Crash**: `SimulatedCrash : Error` is thrown at an injected event. The harness catches it at the top, closes the JDBC connection without committing (an uncommitted transaction is discarded, exactly like SQLite recovery), then reboots: a new `JdbcSqlExecutor(samePath)`, `migrate()`, `verifyIntegrity()`, and a new client.
- Torn writes at the file level are SQLite's responsibility and are not modelled (stated).

### 8.2 Fault injection and deterministic driver (no hooks in production code)

- **`FaultySqlExecutor(delegate, plan)`.** Every `exec`, `execUpdate` and `query` is an event, as are transaction **pre-commit** (throw inside the block) and **post-commit** (throw after commit, so the caller never sees success). It fails on any nested `transaction`.
- **`FaultyRelayPort(model, plan)`.** Each call has three events: *before-send*, *after-apply-before-response* (the dangerous window) and *after-response*. At each it can inject `SimulatedCrash` or any `NetworkException(category)`, for example a `timeout` after the store was applied. It can also run a callback mid-call, such as a capability `put`, a `setRelays`, or a consumer transaction.
- **`FakeTransport`.** Offline windows, `closed`, bootstrap failures, and Arti's clock check: `ensureReady` returns `UNAVAILABLE` when the test clock is off by more than σ.
- **`DeterministicDriver`.** Runs read-lane and work-lane items in virtual-time order. Latency comes from a seeded model, with list latency keyed by (pair, index).
- **Oracle consumer.** It writes three tables, each with a primary key, so any duplicate fails at the event that caused it:
  - `oracle_enqueued(op)` in the enqueue transaction;
  - `oracle_outcome(op)` in the transaction where `release()` returns true;
  - `oracle_consumed(ns, hash)` in the transaction where `markConsumed()` returns true.

### 8.3 Exhaustive crash-point enumeration

For each scenario:

1. Run it without faults and record the event count K.
2. For every k in 1..K: crash at k, reboot, check the structural invariants immediately, run to quiescence, check everything (§8.4).
3. Double crashes: every pair (k₁, k₂), where the second crash is during recovery, for S-A, S-D and S-F.
4. Every relay event also runs as the non-crash variant "`timeout` after apply".

The test policy uses `LIST_LIMIT = 4`.

| Scenario | Content |
|---|---|
| S-A outbox | 3 ops, 3 relays over 3 operators, 1 namespace; one relay `rejected` for one op |
| S-B inbox | 2 relays with overlapping sets of 9 hashes (one only on B; one only on A, which then expires); tail of exactly `LIST_LIMIT`, then `LIST_LIMIT + 1`; STANDARD multi-page and HIGH single-page |
| S-C mixed | S-A + S-B, with `claim`, `markConsumed`, `defer` and `release` interleaved at every event |
| S-D capability | `unauthorized` mid-flight while a new generation is `put`; `quota` after a crash window (after-apply crash, +2 h, quota exhausted, so `check` verifies) |
| S-E topology | `setRelays` and `retire` while deliveries are pending or acked; unsubscribe racing a list; a retired relay re-added |
| S-F window | ambiguous first store, then offline for 3 d, 8 d, 40 d, with TTLs of 7 d and 30 d; resolution reopens the window; the outcome is `indeterminate` only in the documented case; a recipient with GC runs throughout |
| S-G verification | an ack-and-drop relay; repair; two strikes then `failed`; outcomes `degraded` and `sent` |

### 8.4 Invariants asserted

**Structural** (after every reboot and at the end):

- `PRAGMA integrity_check` is ok, `PRAGMA foreign_key_check` is empty, and all triggers are present.
- Payload present ⇔ some delivery is `pending`, `wait_capability` or `acked`, or in flight.
- `sent` ⇒ at least `required_operators` distinct operators have `verified` deliveries, each backed by a model-relay membership that existed at verification time.
- `failed` ⇒ no model relay ever held a membership of h.
- `indeterminate` ⇒ some attempt reached *after-apply* or ended ambiguous.
- Every `acked` delivery has a membership (current or expired) on its model relay.
- Every `fetched` row satisfies `SHA-256(ciphertext) = hash`.
- **IN-3**: for every stored cursor c, every membership the model listed with sequence ≤ c that was live at listing time has a row, or its row was garbage-collected after the blob expired everywhere. The test decodes cursors; the engine never does.
- **Retention safety**: whenever GC deletes `(ns, h)`, no honest model relay holds, or can later list, a live membership of h (checked against model state and the scenario's future stores).

**At quiescence** (fault-free tail, clock advanced past every backoff):

- **OUT-1**: `oracle_enqueued = oracle_outcome` as sets. Ops are `sent` unless the script made them infeasible (reason checked).
- **OUT-3**: at most 1 membership per `(ns, hash)` per relay, and one hash per op. Quota charges per (op, relay) ≤ 1 + injected crash windows − check-verified retries.
- **IN-1/IN-2**: `oracle_consumed` equals the union over honest relays of live memberships in listening namespaces, minus own blobs. No duplicate primary key. `claim()` returns nothing.
- **Liveness**: no op `pending` with every delivery terminal and nothing resolvable; no `wait_capability` while a newer usable generation exists.

### 8.5 Randomized worlds, hostile relays, interleavings

- **Seeded worlds**: 1,000 seeds in CI, 20,000 in the `sync-exit-gate` job. Plain JUnit loops with `SplittableRandom`, no new library. A failure message carries its seed.
  - 2–4 relays over 2–3 operators; 1–3 namespaces; both modes; 0–20 ops; 0–50 inbound blobs.
  - Error rates and crash probability per event; offline windows from hours to 60 days.
  - Clock steps: backward within 1 h, forward within 2 d while READY, large jumps while not READY.
  - Capability expiry and renewal; relay-set changes.
- **Hostile relay modes** (one per set): rewind; repeats; non-empty cursor with an empty page forever; withholding; list-but-`not_found`; wrong bytes; floods of 128 garbage hashes per page; 60 s stalls; ack-and-drop; short expiry on `get`.
  - Assertions: the invariants hold against the honest relays.
  - Requests to the hostile relay per event ≤ 4 lists + 8 gets + 1 check.
  - Rows attributable to it ≤ `BACKLOG_CAP + LIST_LIMIT`.
- **Interleavings**: a consumer transaction, `put`, `setRelays` or `retire` injected between any two events on either lane (a single event counter).

### 8.6 Privacy tests

- **T19 (exact)**: two runs with identical keys, pair set, capability states and list-latency trace.
  - Run (a) is idle. Run (b) has 20 enqueues, 50 inbound blobs, consumer transactions, and injected failures on work-lane calls only, with non-zero work-lane latency.
  - HIGH mode: the full list sequences are equal. STANDARD mode: first pages are equal.
  - No request is timestamped outside a lane item.
  - `WakeScheduler` records no call from enqueue or consume.
  - Adding or removing another pair leaves pair p's schedule unchanged.
- **T3 canaries**: canary token, ciphertext, namespace, onion address and op id, with every category injected at every call. No canary bytes, hex or Base64 appear in any exception message, cause chain, or public `toString()`.
- **Op ids never leave the device**: `FaultyRelayPort` asserts that no argument contains an op id.
- **T20**: the schema introspection test.
- **T21**: Rust tests (§1.5).

### 8.7 Model relay conformance (the fake cannot drift from the real relay)

`protocol/test-vectors/relay_semantics.txt` is a line-oriented script with expected results. It covers:

- store with a new membership and sequence;
- a same-hour no-op versus an extension after the hour (charged, same sequence);
- quota denial leaves nothing behind;
- renewal after expiry gets a new sequence;
- get and check outside the capability's namespace look like absence; write grants read;
- empty `next_cursor` at exhaustion and on an exact-`limit` tail;
- 1,100 expired entries give an empty page with a non-empty cursor;
- the hour seed after a namespace empties;
- hour-rounded expiry and `get` expiry;
- `max_ttl` rejection;
- malformed tokens.

It is replayed by `relay/crates/node/tests/semantics_vectors.rs` against the real `Relay` through `*_at(now)`, and by `ModelRelayConformanceTest` in Kotlin. Both declare the file as a test input.

### 8.8 Negative fixtures: mutants the harness must catch

These live in test sources only.

| Mutant | Bug | Expected detection |
|---|---|---|
| M1 CursorFirst | cursor committed before the hashes | IN-3 after a crash between the two |
| M2 QuorumOnAck | `sent` on receipts | "sent ⇒ memberships" in S-G |
| M3 ReencryptOnRetry | fresh bytes on retry | OUT-3 |
| M4 ConsumeOutsideTx | `markConsumed` committed separately | oracle primary key or a missing consume |
| M5 AckOnAnyResponse | ack on `not_stored` or `malformed_response` | "acked ⇒ membership" |
| M6 DedupByHashOnly | namespace missing from the dedup key | cross-namespace scenario |
| M7 EmptyCursorStored | empty cursor stored | re-listing past retention gives a duplicate |
| M8 RetainByFirstSeen | tombstone retention ignores `get` expiry and the window | retention-safety check |
| M9 NoGenerationGuard | an old token's rejection marks the new one | S-D stuck in `wait_capability` |
| M10 FailIgnoringCopies | D2 ignores `copy_hour` | "failed ⇒ never held" |
| M11 NoStoreWindow | stores continue past H | duplicate at the recipient in S-F |
| M12 NoLeaseNormalization | M1 omitted | "indeterminate/failed truth" after a C4/C5 crash |
| M13 SharedTick | one schedule for all pairs | T19 pair-independence test |

### 8.9 Instrumented and manual evidence (supplements the gate)

- SQLCipher on a device or emulator: v1→v2, triggers, UPSERT, `onConfigure` pragmas, and S-A against the real `GhostDatabase`.
- T20 inventory; job `persisted = true` with empty extras.
- Binding of the non-exported JobService on API 29 and 37; `ACCESS_NETWORK_STATE`.
- Manual live run: emulator, Tor, 3 staging relays, `am kill` 20 times mid-session, then the oracle tables.
- A first NFR-5 measurement.

These run manually until emulator CI arrives in Phase 13. **The gate rests on §8.3–§8.8.**

### 8.10 CI and gate closure

- `./gradlew build` runs the `:storage` and `:sync` suites: exhaustive scenarios, 1,000 seeds, mutants, T19, T3, T20, conformance, README coverage.
- A new `sync-exit-gate` job runs 20,000 seeds and records event counts and seeds in the job summary.
- `cargo test --workspace` covers the vectors and T21.
- The gate closes on: green CI on the closing commit, every mutant detected, and the S9 review round.

---

## 9. Public API for Phases 9–11

```kotlin
package org.ghost.sync.api

class OperationId(bytes: ByteArray)   // 16 bytes; content equality; toString() = "OperationId(redacted)"
class NamespaceId(bytes: ByteArray)   // 32 bytes
class BlobHash(bytes: ByteArray)      // 32 bytes
@JvmInline value class RelayId(val value: Long)
enum class TtlBucket(val seconds: Int) { DAY_1(86_400), DAYS_7(604_800), DAYS_30(2_592_000), DAYS_90(7_776_000) }
enum class Consumer(val code: String) { DM("dm"), PREKEYS("prekeys"), CHANNEL("channel"), MEDIA("media"), IDENTITY("identity") }
enum class CapabilityKind { READ, WRITE }
enum class PrivacyMode { STANDARD, HIGH }

/** The only way to get a SyncTransaction. Not reentrant. Post-commit hints (SyncChange) fire after commit. */
class SyncDatabase(sql: SqlExecutor) { fun <T> transaction(block: (SyncTransaction) -> T): T }
class SyncTransaction internal constructor(val sql: SqlExecutor)  // callers do their own writes through `sql`

class OutboundBlob(val operationId: OperationId, val namespace: NamespaceId, val ciphertext: ByteArray, // one bucket, frozen
                   val ttl: TtlBucket, val deadlineEpochSeconds: Long? = null)                          // null = no deadline
sealed interface EnqueueResult { data object Enqueued : EnqueueResult; data object AlreadyEnqueued : EnqueueResult }
enum class Outcome { SENT, DEGRADED, FAILED, INDETERMINATE }
class OutboundOutcome(val operationId: OperationId, val namespace: NamespaceId, val outcome: Outcome)
class OutboxProgress(val acknowledgedOperators: Int, val verifiedOperators: Int, val requiredOperators: Int,
                     val outcome: Outcome?)                                    // for UI ticks; counts only
class InboundBlob(val namespace: NamespaceId, val hash: BlobHash, val ciphertext: ByteArray)

interface Outbox {
    /** In the caller's transaction. Throws on invalid input, a conflict, or < 2 operators (the caller rolls back). */
    fun enqueue(tx: SyncTransaction, blob: OutboundBlob): EnqueueResult
    /** True only while no attempt could have left a copy; the op then ends FAILED. */
    fun cancel(tx: SyncTransaction, operationId: OperationId): Boolean
    fun progress(operationId: OperationId): OutboxProgress?
    fun outcomes(consumer: Consumer, limit: Int): List<OutboundOutcome>     // decided, not yet released
    /** True exactly once per op; make your effect conditional on it, in the same transaction. */
    fun release(tx: SyncTransaction, operationId: OperationId): Boolean
}
interface Inbox {
    /** Commits an offer counter first (poison guard), then returns blobs in local arrival order. */
    fun claim(consumer: Consumer, limit: Int): List<InboundBlob>
    /** True exactly once per (namespace, hash). Call it for every blob, including rejected ones. */
    fun markConsumed(tx: SyncTransaction, namespace: NamespaceId, hash: BlobHash): Boolean
    /** Re-offer later (e.g. an MLS message for a future epoch); at most 7 days. */
    fun defer(tx: SyncTransaction, namespace: NamespaceId, hash: BlobHash, seconds: Int): Boolean
    fun setListener(listener: SyncListener?)
}
fun interface SyncListener { fun onChanged(changes: Set<SyncChange>) }   // hint after commit; no payload
enum class SyncChange { INBOX, OUTCOMES, CAPABILITIES }

interface Namespaces {
    fun register(tx: SyncTransaction, namespace: NamespaceId, consumer: Consumer, relays: Set<RelayId>, listen: Boolean)
    fun setRelays(tx: SyncTransaction, namespace: NamespaceId, relays: Set<RelayId>)   // repairs deliveries (§3.9)
    fun setListening(tx: SyncTransaction, namespace: NamespaceId, listen: Boolean)     // cursors are kept
    /** False while the namespace has ops; otherwise deletes its inbox rows and cursors. */
    fun remove(tx: SyncTransaction, namespace: NamespaceId): Boolean
}
interface Capabilities {                          // Phase 8 writes, Phase 7 uses
    fun put(tx: SyncTransaction, relay: RelayId, namespace: NamespaceId, kind: CapabilityKind,
            token: ByteArray, expiresAtEpochSeconds: Long?)
    fun needed(): List<CapabilityNeed>
}
class CapabilityNeed(val relay: RelayId, val namespace: NamespaceId, val kind: CapabilityKind, val reason: Reason) {
    enum class Reason { MISSING, REJECTED, EXHAUSTED, EXPIRING }
}
interface RelayDirectory {                        // Phase 14 fills it from the signed manifest
    fun upsert(tx: SyncTransaction, entries: List<RelayEntry>): Map<OnionAddress, RelayId>   // reactivates retired rows
    fun retire(tx: SyncTransaction, relay: RelayId)
    fun active(): List<RelayEntry>
}
class RelayEntry(val address: OnionAddress, val operatorId: ByteArray /* 16 */, val source: Source) {
    enum class Source { MANIFEST, CONFIG }
}
interface SyncController {                        // android implementation; wired by GhostApp
    fun onAppForeground(); fun onAppBackground()
    fun requestExpedite()                          // STANDARD only; stores, never reads
    fun setPrivacyMode(mode: PrivacyMode)
    fun status(): SyncStatus                       // counts and enums only
}
```

**Phase 9 usage idiom:**

```kotlin
syncDb.transaction { tx ->
    val ct = session.encrypt(tx.sql, paddedPlaintext)          // ratchet state written in the same transaction
    messages.insertQueued(tx.sql, opId, conversation, ct)
    outbox.enqueue(tx, OutboundBlob(opId, recipientInbox, ct, TtlBucket.DAYS_7))
}
syncController.requestExpedite()                             // STANDARD mode only
// on SyncChange.OUTCOMES
for (o in outbox.outcomes(Consumer.DM, 64)) syncDb.transaction { tx ->
    if (outbox.release(tx, o.operationId)) messages.setOutcome(tx.sql, o.operationId, o.outcome)
}
// on SyncChange.INBOX
for (b in inbox.claim(Consumer.DM, 32)) syncDb.transaction { tx ->
    if (inbox.markConsumed(tx, b.namespace, b.hash)) dm.decryptAndStore(tx.sql, b.ciphertext) // or record rejection
}
```

**Contracts for later phases:**

- Produce the ciphertext once per message.
- `FAILED`: no copy ever existed, so re-encrypting and resending is safe.
- `INDETERMINATE`: resend only **the identical bytes** as a new op, after release. The relay treats it as the same membership, and recipients dedup it while their tombstone lives.
- `DEGRADED`: delivered to at least one relay; do not resend.
- Keep protocol-layer replay protection (§0.2 boundary).
- Consumers write only through `tx.sql` and do no network I/O inside the transaction.
- Media (Phase 11) will add `Inbox.want(tx, ns, hashes)`: `listed` rows with the namespace's relays as candidates, no schema change.

---

## 10. Scope, steps, risks, open questions

### 10.1 Scope

| In Phase 7 | Later |
|---|---|
| Schema v2 with triggers; `execUpdate`, `inTransaction`, non-reentrant transactions, `onConfigure` pragmas; shared test sources | — |
| Rust: `capability_header`, `NamespaceClient` + T21, JNI `check`, deadlines, `get` expiry; relay `*_at(now)`; conformance vectors | Phase 10: new token formats extend the parser. Phase 12: pooled clients with a rotation epoch, per-scope rotation. |
| Engine: two lanes, outbox (verify, window, resolution, outcomes), inbox, cursors, dedup and retention, backoff, breakers, budgets, GC | Phase 12: tuning, parallelism |
| Capability storage and use; `needed()` | Phase 8: minting and redemption |
| Local relay directory (`config` source) | Phase 14: signed manifest and operator ids |
| API with `cancel`, `defer`, `progress` | Phases 9/10/11: consumers, relay sets, `want`, media bulk lane |
| JobScheduler job, foreground driver, controller, minimal `GhostApp`, manifest | Phase 13: UI, prompt-mode FGS (ADR), privacy-mode UI, emulator CI |
| T19, T20, T21, `kotlin-clearnet.sh`, T15m | Phase 12: T17 capture and KS test. P2: cover traffic, read bucketing |

### 10.2 Deliberately not done

No relay protocol change. No WorkManager and no coroutines. No automatic re-encryption. No dead-letter queue. No per-op scheduling. No persisted health. No filler traffic. No new production dependency.

### 10.3 Ordered steps (each ends green in CI)

- **S0.** Owner approves this design and ADR-20, or rejects it and takes §5.7. Answers Q1–Q7.
- **S1. Storage.**
  - `execUpdate`, `inTransaction`, non-reentrant transactions in both executors, `onConfigure` pragmas.
  - Migration v2 and triggers; `expectedTables`, `expectedTriggers`, the `foreign_keys` check.
  - Tests: fresh → v2; v1 with data in other tables → v2; the guard fails on a non-empty `relay_queue`; interruption at every statement; every CHECK and trigger, positive and negative; `noPlaintextContentColumnsExist` stays green.
  - Move `JdbcSqlExecutor` to `testShared`.
- **S2. Rust/JNI.**
  - `capability_header`, reused by the relay; `NamespaceClient` and the guard, with T21 tests.
  - `nativeCheck`, deadlines and `get` expiry, plus Kotlin decoders and tests; a test with two concurrent calls on one handle.
  - Relay `*_at(now)`; vectors with the Rust replay; README update.
  - clippy, fmt, gates.
- **S3. Sync foundations.** API types, ports, `ModelRelay` with the Kotlin conformance replay, `FaultySqlExecutor`, `FaultyRelayPort`, `FakeTransport`, `DeterministicDriver`, `TestClock`, the oracle consumer.
- **S4. Stores.** Outbox, inbox, cursor, capability, directory and GC, with SQL-level tests for each guarded transition, the D1/D2/W rules, M1–M3, the generation race, set repair and retention.
- **S5. Engine.** Pair schedule, both lanes, `ErrorPolicy` (with the README coverage test), backoff, breakers, budgets, sessions.
- **S6. Exit-gate harness.** S-A to S-G (single and double crashes), 1,000 seeds, hostile modes, interleavings, M1–M13, T19, T3, T20; the `sync-exit-gate` CI job.
- **S7. Android** (after ADR-20). `TorRelayPort`, `TorTransportHolder`, `SyncRuntime`, `SyncJobService`, `JobSchedulerWake`, `ForegroundDriver`, `AndroidSyncController`, `GhostApp`; app manifest; `manifest-lint.sh` allowlist plus T15m with a fixture; `kotlin-clearnet.sh` with a fixture; the instrumented checks in §8.9.
- **S8. Docs.**
  - ADR-20 (propus → decided), ADR README row, ADR-19 addendum.
  - INVARIANTS: T19–T21 and the T17 note.
  - THREAT_MODEL §6: the "Sync periodic (idle)" row updated, and the "Citire canal" row gets cursor and capability linkability.
  - LIMITE L1 (dedup residue) and L2 (§6.3 residuals); STATUS.
- **S9. Adversarial review** in the Phase 6 style, then fixes, verification, and the gate recorded as closed in STATUS.

### 10.4 Risks

| Risk | Impact | Mitigation |
|---|---|---|
| R1: the model relay drifts from the real relay | the proof becomes invalid | shared vectors replayed by both (§8.7) |
| R2: SQLCipher behaves differently from sqlite-jdbc (triggers, UPSERT, WITHOUT ROWID, WAL) | device-only bugs | standard SQL only (no `RETURNING`); S-A instrumented on SQLCipher |
| R3: Doze and OEM killers delay background sync by hours | latency | disclosed; prompt mode in Phase 13 |
| R4: **NFR-1 misses by design** (p95 about 40 s in the foreground) | spec target missed | recorded in ADR-20; Q2; measured in Phase 12 |
| R5: Tor load of about 2 lists/s with 60 pairs in the foreground | battery (NFR-5), relay load | measured in S7/Phase 12; ADR-15 bucketing (P2) |
| R6: an auth-bound DB key disables background sync | no background delivery | Q6; documented |
| R7: `indeterminate` outcomes after long outages | UX ambiguity | narrow condition (§3.5); identical-bytes resend |
| R8: forensic dedup residue | AD-8 tension | bounded and declared (ADR-20 §6); H is tunable (Q4) |
| R9: schedule pressure (3–4 weeks) | slip | order S1–S6 first (the gate); S7 can finish in parallel with the S9 review |
| R10: ADR-20 rejected | WorkManager artefacts on disk | §5.7 adapter swap |
| R11: no capabilities exist until Phase 8 | no live end-to-end run | tests mint through the model; manual runs use `ghost-relay mint` |

### 10.5 Open questions for the owner

- **Q1.** Approve ADR-20 (JobScheduler), or keep WorkManager with the §5.7 hardening?
- **Q2.** NFR-1 against ADR-15: accept a 30 s interval now and recalibrate in Phase 12, or a shorter interval for every pair at battery cost?
- **Q3.** Fan-out: every relay in the set (proposed), or exactly 2?
- **Q4.** Store window H = 7 d (tombstones: relay expiry + 24 d; never-fetched rows: 111 d). A longer H means fewer `indeterminate` outcomes and a longer residue.
- **Q5.** HIGH-mode send delay N = 10 min?
- **Q6.** Accept "no background sync" when the DB key requires user authentication?
- **Q7.** `ProfileInstallReceiver`: remove it (`tools:node="remove"`), or allowlist it in T15m?

### 10.6 Findings outside Phase 7 (proposed as separate tasks)

- **F1.** T7 checks declared coordinates only. `com.google.guava:listenablefuture`, `org.jspecify:jspecify` and `org.jetbrains:annotations` already ship and are not on the allowlist. Proposed: a resolved-graph check (for example over the groups in `verification-metadata.xml`) before Phases 8 and 9 add dependencies.

---

## Appendix A: ADR-20 draft (`docs/adr/ADR-20-sync-jobscheduler.md`)

> # ADR-20 — Sincronizare: JobScheduler în loc de WorkManager, program per (relay, namespace), reziduuri declarate
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-11 |
> | Sursă | Design Faza 7 (`docs/design/FAZA7_SYNC_ENGINE.md`) |
> | Modifică | ADR-06 („Sync prin WorkManager”); Master Plan §6.2 (rândul Fazei 7) și §6.6 (`sync/ # WorkManager`); Spec v2.0 FR-7.8 („WorkManager and coroutines”); setul de permisiuni T15. Precizează ADR-09 („loturi de dimensiune fixă”), ADR-11 și ADR-15 („interval fix + jitter”). Declară un conflict cu NFR-1 și un reziduu față de THREAT_MODEL AD-8. |
>
> ## Context
> Corectitudinea exactly-once a sync-ului nu depinde de planificator: toată starea durabilă e în SQLCipher, iar fiecare pas e sigur la crash. Planificatorul doar trezește procesul. Cu minSdk 29, WorkManager rulează oricum peste JobScheduler. În plus, aduce o bază Room necriptată (`androidx.work.workdb`), în care o lucrare programată la o acțiune a utilizatorului înregistrează momentul acelei acțiuni. Mai aduce Room, lifecycle-service/livedata și coroutines în aria de audit (POM 2.11.2 verificat), componente exportate (`SystemJobService`, `DiagnosticsReceiver`), permisiunile WAKE_LOCK, ACCESS_NETWORK_STATE, RECEIVE_BOOT_COMPLETED și FOREGROUND_SERVICE, plus logare implicită. Motorul nu folosește nimic din ce oferă WorkManager peste un singur job periodic.
>
> ## Decizie
> 1. **Planificare.** În fundal, un singur job periodic JobScheduler (15 min, flex 5 min, persistent, rețea oarecare, fără extras), programat idempotent la pornirea procesului și **niciodată** ca urmare a activității utilizatorului sau a sosirii datelor. În prim-plan, o sesiune în proces cu două fire dedicate: citire și lucru. Fără WorkManager și fără coroutines: apelurile JNI sunt blocante. `JobService` e neexportat, protejat de `BIND_JOB_SERVICE` și declarat în manifestul aplicației.
> 2. **Permisiuni** noi în setul T15: `RECEIVE_BOOT_COMPLETED` (job persistent) și `ACCESS_NETWORK_STATE` (constrângere de rețea, targetSdk ≥ 34). Ambele ar fi necesare și cu WorkManager. T15 verifică și manifestul fuzionat de release. Fallback, doar dacă testul pe dispozitiv o cere: serviciu exportat, protejat de `BIND_JOB_SERVICE`, cu excepție explicită în T15.
> 3. **Programul de trafic (lectura ADR-15).** Fiecare pereche (relay, namespace) are propriul program: interval fix 30 s cu jitter uniform ±50 %, fază independentă derivată dintr-un PRF cu cheie. Programul de citire e independent de activitate (invariant T19). În high-privacy mode, trimiterile au o întârziere U[0, 10 min] și pleacă numai la evenimentele perechii. În modul standard pleacă imediat.
> 4. **Loturi fixe (lectura ADR-09).** `limit` constant (128) la listare, identic pentru toți clienții, și număr fix de pagini per eveniment în high-privacy mode. GET-urile sunt per blob și nu se completează cu umplutură în Faza 7: umplutura cu re-citiri e recunoscută de relay și protejează doar volumul față de observatorul de rețea, deci e cover traffic (P2, Faza 12). Verificările (`check`) nu se completează.
> 5. **Conflict NFR-1.** Cu interval de 30 s, latența DM p95 în prim-plan e de ordinul a 40 s (în fundal, ore), deci NFR-1 („DM p95 < 5 s”) **nu e îndeplinit** în Faza 7. Se măsoară și se decide în Faza 12; un interval mai scurt se aplică tuturor perechilor, altfel ritmul ar dezvălui tipul namespace-ului.
> 6. **Reziduu local de deduplicare (față de AD-8).** Pentru namespace-urile ascultate, dispozitivul păstrează (namespace, hash, zi de ștergere) timp de **24 de zile după expirarea blob-ului la relay** (111 zile de la ultima listare pentru blob-urile listate, dar neaduse). Nu păstrează conținut, ordine de sosire sau distincția proprii/primite. Pentru namespace-urile doar de scriere nu păstrează nimic. Un atacator cu baza de date deschisă vede deci hash-urile unui istoric expirat de cel mult 24 de zile. Termenul derivă din fereastra de stocare (punctul 7) și din toleranța de ceas de 3 zile. Se adaugă în LIMITE L1.
> 7. **Fereastra de stocare și rezultatele outbox-ului (precizare ADR-11).** Clientul scrie fiecare blob pe toate relay-urile setului și declară „trimis” numai când cel puțin 2 operatori distincți arată blob-ul în inventar după confirmare. Copiile unui mesaj se scriu cel mult 7 zile după prima copie posibilă. Rezultatele sunt `sent`, `degraded` (cel puțin o copie verificată, sub cvorum), `failed` (nicio copie nu a fost posibilă) și `indeterminate` (o copie poate exista). Nu e o relaxare a ADR-11: clientul încearcă mereu ≥ 2 operatori și raportează onest când rețeaua nu permite.
>
> ## Consecințe
> (+) Zero dependențe noi. Nicio stare de sincronizare în afara SQLCipher. Două permisiuni „normal” în loc de patru și nicio componentă exportată nouă. Programul de citire nu reflectă activitatea. Niciun mesaj nu e raportat „eșuat” cât timp o copie poate exista.
> (−) GHOST întreține ~150 de linii de planificare proprii. Întârzierile în Doze sunt aceleași ca la WorkManager. Constanța completă în fundal cere un serviciu foreground („mod prompt”, Faza 13, cu ADR pentru tipul FGS; `dataSync` e limitat la 6 h/24 h). Reziduul de la punctul 6 e declarat. NFR-1 rămâne deschis.
>
> ## Alternativă dacă e respins
> WorkManager întărit: un singur `PeriodicWorkRequest` unic, fără `Data`; inițializare la cerere; `DiagnosticsReceiver` și `SystemForegroundService` eliminate cu `tools:node="remove"`; logare redusă; `WAKE_LOCK` adăugat în T15; T7 mutat întâi pe classpath-ul rezolvat; reziduul `workdb` declarat în L1. Motorul, schema și testele nu se schimbă.
>
> ## Teste
> T19 (programul de citire e independent de activitate), T20 (nimic în afara SQLCipher; timpi doar la minut/oră/zi; un singur job fără extras), T21 (scopul de izolare = scopul capabilității), `manifest-lint.sh` pe sursă și pe manifestul fuzionat, suita exit-gate a Fazei 7.

## Appendix B: ADR-19 addendum (completions, no decision change)

> ## Completări după Faza 7 (2026-09-11)
> - **`NamespaceClient`.** Clientul relay e legat prin tip de un namespace. Izolarea de circuit și capabilitatea trebuie să numească același namespace, iar tipul capabilității trebuie să corespundă operației; altfel `invalid_argument`, înainte de orice I/O (invariant T21). Formatul antetului de capabilitate v1 e definit o singură dată (`ghost_relay_api::capability_header`) și e folosit și de relay. Un token neparsabil e refuzat până când un format nou (de exemplu token-uri de citire derivate din MLS, Faza 10) e adăugat explicit.
> - **JNI.** `check()` e expus prin JNI. Fiecare apel primește un termen propriu (≤ 60 s), iar `get` întoarce și expirarea declarată de relay, validată în Rust (≤ acum + 90 zile + toleranța de ceas).
> - **Rotația circuitelor.** Clienții rămân creați per apel. Rotația are loc la fiecare transport nou (sesiune în prim-plan, job în fundal). Rotația periodică per scop și verificarea unei epoci de rotație vin în Faza 12, odată cu eventualii clienți de lungă durată.
> - **Motorul de sync.** Motorul din `android/sync` e orchestrare de stare locală (SQLCipher), nu logică de protocol. Kotlin nu parsează cursoare, capabilități sau răspunsuri de relay.

## Appendix C: Evidence — verified vs assumed

**Verified in the repository (2026-09-11):**

- **Relay storage** (`relay/crates/storage`):
  - `list` returns an empty `next_cursor` when the namespace is exhausted, including an exact-`limit` tail;
  - the cursor is the last *examined* sequence; `MAX_LIST_SCAN = 4 × MAX_BATCH = 1024`;
  - the sequence seed is `(now/3600) << 32`, and the sequence row is deleted with the namespace's last membership;
  - `put`: a repeat within the hour is a no-op; an extension keeps the sequence; a renewal after expiry gets a new sequence; the quota `admit` runs inside the write transaction, and a denial persists nothing;
  - expiry is rounded up to the hour.
- **Relay node:**
  - store uses `verify(Write)`; list uses `verify(Read)`, and write grants read; get and check use `verify_any` and take the namespace from the capability;
  - `max_ttl_seconds` returns `invalid_argument`, which the client sees as `rejected`;
  - an expired capability returns `permission_denied`, which the client sees as `unauthorized`;
  - quota maps to `resource_exhausted`, which the client sees as `quota`;
  - the ledger refunds when a store does not commit.
- **Protocol:**
  - the capability is 82 bytes (`version‖kind‖ns‖quota‖expiry‖mac`);
  - `GetBlobRequest` and `CheckBlobsRequest` carry no namespace;
  - `GetBlobResponse` carries `expiry_unix_seconds`;
  - `allowed-observables.json` includes `capability_scope`, `circuit_id` and `batch_count`.
- **Client core:**
  - `RelayClient` is created per JNI call with `IsolationScope::Namespace(ns)`; the runtime is `new_multi_thread`;
  - `CLOCK_SKEW_SECONDS` is 3 d;
  - `categories::ALL` has 20 entries (including `not_onion`); `native_missing` exists only in Kotlin; the README lists all 21.
- **Android:**
  - `OnionAddress.toString()` is `host:port`;
  - `JdbcSqlExecutor.transaction` is not reentrant and commits outer work early; `SupportSqlExecutor` nests;
  - `PRAGMA foreign_keys` runs once, in `migrate()`;
  - `relay_queue` and `sync_cursor` are referenced only in `Schema.kt` and `SchemaAndMigrationTest.kt`;
  - `noPlaintextContentColumnsExist` rejects `body`, `text`, `plaintext`, `content` and `message`;
  - `AndroidKeystoreWrapper` supports `requireUserAuthentication` with 30 s validity;
  - `:app` has no `Application` class;
  - no `java.net` or `javax.net` in `android/*/src/main`.
- **Gates:**
  - `manifest-lint.sh` scans every non-build manifest and requires backup and network attributes on any `<application>`; `ALLOWED_PERMISSIONS` does not include `RECEIVE_BOOT_COMPLETED`, `ACCESS_NETWORK_STATE` or `WAKE_LOCK`;
  - `dependency-allowlist.sh` parses declared coordinates only;
  - the anti-placeholder patterns cover `src/main` and Rust `src/` (inline tests included);
  - `self-test.sh` fixtures live in `test-harness/gates/negative*`.
- **Merged release manifest:** exported `ProfileInstallReceiver` (DUMP), `InitializationProvider` with `ProcessLifecycleInitializer`, the `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` signature permission.
- **Gradle:**
  - `androidx.work` is absent from `~/.gradle/caches`;
  - `listenablefuture:1.0`, `jspecify:1.0.0` and `annotations:23.0.0` are in `verification-metadata.xml`;
  - `work = "2.11.2"` is declared and unused.
- **Docs:**
  - ADR-15: "Polling la interval fix + jitter";
  - ADR-09: "fetch în loturi de dimensiune fixă";
  - ADR-11: "Clientul scrie fiecare blob pe ≥ 2 relay-uri";
  - AD-8: "nu vede istoricul expirat";
  - the spec PDF: "Background synchronization MUST use WorkManager and coroutines with idempotent queues and battery/network constraints".

**Verified externally:** the `androidx.work:work-runtime:2.11.2` POM from dl.google.com, with the dependency list in §5.2.

**Assumed, to be checked in S7 or only if ADR-20 is rejected:**

- The platform numbers and behaviours in §5.1: periodic minimums, Doze and bucket delays, the `ACCESS_NETWORK_STATE` requirement at API 34, binding a non-exported JobService, the FGS 6 h cap, the freezer, SQLCipher PBKDF2 per open.
- WorkManager's manifest components, its `workdb` schema and logging, and Room's transitive set.
- σ = 3 d as Arti's effective clock tolerance: this is the Phase 6 constant, to be re-checked against Arti's `DirTolerance` defaults.
- `Runtime::block_on` concurrency from two JVM threads on one handle: expected from tokio semantics, and pinned by a new Rust test in S2.

---

## 11. Normative corrections after the completeness critique (override earlier sections)

Status of this document: **approved for implementation** by the owner's "începe Faza 7" (2026-09-11), with the defaults below for Q1–Q7. ADR-20 is "propus, aplicat" (same practice as ADR-17/18/19); the owner decides it after delivery. Where this section contradicts §0–§10, this section wins.

### 11.1 Owner-question defaults (Q1–Q7), reported back for decision

| Q | Default applied |
|---|---|
| Q1 | ADR-20: JobScheduler + in-process driver (§5.4). §5.7 stays the fallback adapter. |
| Q2 | T = 30 s now; recalibrate against NFR-1 in Phase 12 (ADR-20 point 5). |
| Q3 | Fan-out to every active relay of the set; quorum = 2 distinct operators. |
| Q4 | H = 7 d. |
| Q5 | N = 10 min. |
| Q6 | Accepted: an auth-bound DB key means no background sync. |
| Q7 | `ProfileInstallReceiver` is removed from the merged manifest (`tools:node="remove"`); no exported component besides the launcher. |
| mode | Default privacy mode is **STANDARD** until the Phase 13 UI; per-namespace send-delay override (11.2 #15). |

### 11.2 Required corrections (numbers = critique items)

1. **FETCHED_CAP** counts only rows with `state='fetched' AND offers < 3 AND offer_after_minute <= now` (deferred and suspect rows are excluded). Phase 7 background sessions run **no consumers** (there are none yet); the exit-gate statement gets the precondition "consumers drain and the device is online at least once per TTL". New scenario **S-H**: consumer paused longer than a TTL, backlog above both caps, honest relays: no loss once consumers resume, as long as blobs were fetched before relay expiry.
2. **BACKLOG_CAP = 4096** rows (`listed` + `unavailable`) per (relay, ns) with that relay as a candidate. Background fetch budget per pair event = **32** (foreground 8 per event, events every ~30 s). Liveness bound: a pair loses nothing while its inbound rate stays below the fetch capacity per TTL, 32 × (jobs per day) × TTL_days in background-only use; about 96 jobs/day × 32 × 7 d ≈ 21 500 blobs per 7-day DM namespace. Recorded as a capacity limit in ADR-20 and LIMITE L2.
3. **`claim()` isolates poison.** Rows with `offers >= 2` are *suspect* and are returned **alone** (a claim that would include a suspect row returns only that row). The offer increment still commits before hand-off. Test: 1 poisoned + 31 innocent blobs; the innocents are consumed; only the poisoned one backs off; status counts 1 poisoned.
4. **Clock clamp on due times.** Reads treat `next_attempt_minute > now + 61 min`, `next_fetch_minute > now + 61 min`, `offer_after_minute > now + 24 h` (claim backoff) and a `defer` beyond `now + 7 d` as due. The seeded-world quiescence check does not advance the clock past backoffs (it advances only by the schedule).
5. **Verification SQL** uses `operation_id IN (SELECT operation_id FROM outbox_op WHERE namespace_id = :ns AND blob_hash = :h AND outcome = 'pending')` and only promotes deliveries in `('pending','wait_capability','acked','failed','closed')` with `inflight = 0` of **undecided** ops. `UNIQUE(namespace_id, blob_hash)` on `outbox_op` stays; a resend of identical bytes is possible only after the old op row is deleted (after release and payload wipe), see #6.
6. **Resend bound and own-tombstone raise.** `OutboundOutcome` carries `resendNotAfterEpochSeconds` for INDETERMINATE (= earliest `copy_hour + ttl − σ`); `enqueue` of bytes whose own `done` row exists is allowed only while `now < retain_until_day − TAIL` of that row, and raises `retain_until_day`. **Every receipt** (ack or extension) raises the own `done` row to `ceil7(day(receipt.expiry) + TAIL)`, so a listened namespace never fetches our own blob back after GC.
7. **Fetched-but-unconsumed rows are never dropped** (correctness). Residue declared in ADR-20 point 6 and LIMITE L1: E2E ciphertext of unconsumed blobs stays in SQLCipher until consumed; `SyncStatus.expiredUnconsumed` counts rows whose `retain_until_day` passed.
8. **T20 wording and coarsening.** `retain_until_day` is rounded **up to a 7-day boundary** (`ceil7`). T20 says: no request history, schedules, breakers or latencies are persisted; *pending-work* retry state (`attempts`, `next_attempt_minute`, `fetch_attempts`, `next_fetch_minute`, `offers`, `offer_after_minute`, `copy_hour`, `lease_hour`, `ack_minute`) exists only while the work is pending and is reset on terminal states where the schema allows. Declared in L1.
9. **Durability.** `PRAGMA synchronous = FULL`, `foreign_keys = ON` and `secure_delete = ON` are set in `onConfigure` on every connection and asserted by `verifyIntegrity()` (the JDBC executor sets the same on open). The crash model of §8 is **process death**; power-loss durability rests on `synchronous = FULL` (stated, not simulated).
10. **Threads.** `SyncDatabase` serializes all transactions through one `ReentrantLock` shared by every lane and consumer; `transaction()` is non-reentrant **per thread** (ThreadLocal flag) and throws on nesting. Test: two threads doing concurrent transactions over one `JdbcSqlExecutor` never interleave.
11. **Crash fidelity.** No `catch (Throwable)`, `catch (Error)`, `runCatching` or a `catch (Exception)` that could wrap an `Error` in `sync/src/main`; new gate `scripts/gates/sync-no-catch-all.sh` with a negative fixture. The harness asserts that every injected `SimulatedCrash` reached the top level.
12. **Read-lane capacity.** The read lane has **k = 4 workers**, serialized per pair, events dispatched by scheduled start time. Maximum read pairs per session: **64**; pairs beyond the cap are listed round-robin at one event per `T × ceil(n / 64)` (defined, deterministic, activity-independent). T19's latency model includes a rendezvous setup cost on the first call per pair per transport.
13. **Breaker scope.** Only list outcomes feed the read breaker; stores, checks, gets and per-relay work budgets never suppress or delay list events (T19 by construction; test with 100 % work-lane failures).
14. **ADR-20 "Modifică"** lists ADR-09, ADR-15, LIMITE L2, T17 and THREAT_MODEL "Sync periodic (idle)". T17 moves explicitly to Phase 12 and is reachable only in HIGH mode plus P2 cover traffic.
15. **Per-namespace send delay.** `Namespaces.register(..., sendDelay)` and `setSendDelay(ns, SendDelay.{DEFAULT, ON, OFF})`; DEFAULT follows the global mode (ON in HIGH, OFF in STANDARD). Default global mode STANDARD (11.1).
16. **L4 conflict** recorded in ADR-20 and LIMITE L4: periodic Tor bootstraps are a timing fingerprint; mitigations for Phase 12 (per-install random period offset, keeping the transport between jobs).
17. **Wipe cancels the job.** `SyncController.onWipe()` cancels `JOB_ID`; `SyncJobService` cancels itself and returns when `DatabaseKeyProvider.exists()` is false; `ensurePeriodic()` also runs right after the key is first created. Instrumented T20 check: after wipe, `getAllPendingJobs()` is empty (manual until emulator CI).
18. **Force-stop** text corrected: jobs may be cancelled by the platform on force-stop (assumed); `ensurePeriodic()` at every process start reschedules when `getPendingJob(JOB_ID)` is null. S7 check.
19. **`Namespaces.remove()`** refuses while the namespace has ops or `fetched` rows; otherwise it sets `listening = 0`, drops its relay set, cursors and capabilities, and **keeps tombstones** until `retain_until_day`; the `sync_namespace` row is deleted by GC after its last row is gone. Re-registering before that reuses the row (no redelivery).
20. **ADR-19 addendum** keeps factual API completions only; the "engine policy in Kotlin" boundary is ADR-20 point 8.
21. **`lifecycle-process`** is declared explicitly in the catalog and in `:app` (androidx, allowlisted), stated in ADR-20.

### 11.3 Optional improvements adopted

Wording of cursor rule 2 ("at most LIST_LIMIT"); relay restored from backup documented in §4.4 (sequence fall-back skips entries on that relay; other relays of the set cover it); §2.3 assumes no relay-side replication creates memberships (gossip exchanges hashes only and is off); `not_found` retried once after at least 60 min before the source becomes `not_found`; K/R event counts and a CI time budget recorded by the harness; T21 hostile helpers live in `tests/`; the transport closes as soon as in-flight calls finish after ON_STOP (no 30 s timer); `ensurePeriodic` compares explicit fields; ADR-20 point 7 says "attest via list or check"; the schedule key is random per process and never persisted; pair order within a background job is a keyed random permutation and the starvation bound is stated; CI re-runs the two-node suite and T1 unchanged after the relay refactor.

### 11.4 Split out of Phase 7

F1 (T7 on the resolved classpath) stays a separate task.
