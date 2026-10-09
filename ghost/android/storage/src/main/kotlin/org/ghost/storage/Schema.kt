package org.ghost.storage

/**
 * The index, trigger and guard texts of `outbox_op` and `outbox_delivery`, shared by the migrations
 * that create them (Phase 9 design §13.6 step 1): migration 2 creates the v2 indexes and triggers,
 * migration 3 the two v3 REPLACE guards, and migration 4 recreates all of them on the rebuilt tables
 * that admit the 1-hour TTL. One text per object, so the rebuilt tables cannot drift from the v2
 * ones (the migration test compares `sqlite_master` rows by (type, name, sql); §21.13 point 9).
 */
private object OutboxObjects {
    const val IDX_OP_OPEN = "CREATE INDEX idx_outbox_op_open ON outbox_op(outcome, released)"
    const val IDX_DELIVERY_DUE = "CREATE INDEX idx_outbox_delivery_due ON outbox_delivery(state, next_attempt_minute)"
    const val IDX_DELIVERY_RELAY = "CREATE INDEX idx_outbox_delivery_relay ON outbox_delivery(relay_id, state)"

    val INDEXES: List<String> = listOf(IDX_OP_OPEN, IDX_DELIVERY_DUE, IDX_DELIVERY_RELAY)

    /** The eight v2 state-machine triggers (design faza7-sync-engine.md §2, D8). */
    val V2_TRIGGERS: List<String> = listOf(
        """CREATE TRIGGER outbox_op_immutable
                BEFORE UPDATE OF operation_id, namespace_id, blob_hash, ttl_seconds, not_before_minute, deadline_hour,
                                 required_operators ON outbox_op
                BEGIN SELECT RAISE(ABORT, 'outbox_op identity is immutable'); END""",
        """CREATE TRIGGER outbox_op_payload
                BEFORE UPDATE OF ciphertext ON outbox_op
                WHEN NEW.ciphertext IS NOT NULL
                  OR EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = OLD.operation_id
                             AND (d.state IN ('pending', 'wait_capability', 'acked') OR d.inflight = 1))
                BEGIN SELECT RAISE(ABORT, 'outbox payload is frozen and wiped only after the last possible store'); END""",
        """CREATE TRIGGER outbox_op_outcome
                BEFORE UPDATE OF outcome ON outbox_op
                WHEN OLD.outcome <> 'pending' OR NEW.outcome = 'pending'
                BEGIN SELECT RAISE(ABORT, 'outbox outcome is decided once'); END""",
        """CREATE TRIGGER outbox_op_release
                BEFORE UPDATE OF released ON outbox_op
                WHEN OLD.released = 1 OR NEW.released <> 1 OR OLD.outcome = 'pending'
                BEGIN SELECT RAISE(ABORT, 'release happens once, after the outcome'); END""",
        """CREATE TRIGGER outbox_op_delete
                BEFORE DELETE ON outbox_op
                WHEN OLD.released = 0 OR OLD.ciphertext IS NOT NULL
                BEGIN SELECT RAISE(ABORT, 'only released ops without payload are deleted'); END""",
        """CREATE TRIGGER outbox_delivery_insert
                BEFORE INSERT ON outbox_delivery
                WHEN NEW.state <> 'pending' OR NEW.inflight <> 0 OR NEW.copy_hour IS NOT NULL
                  OR (SELECT ciphertext FROM outbox_op WHERE operation_id = NEW.operation_id) IS NULL
                BEGIN SELECT RAISE(ABORT, 'a new delivery starts pending, idle, without copies, and needs the payload'); END""",
        // Late inventory is truth: failed/closed may still become verified.
        """CREATE TRIGGER outbox_delivery_state
                BEFORE UPDATE OF state ON outbox_delivery
                WHEN NOT ((OLD.state = 'pending'         AND NEW.state IN ('wait_capability', 'acked', 'verified', 'failed', 'closed'))
                       OR (OLD.state = 'wait_capability' AND NEW.state IN ('pending', 'acked', 'verified', 'failed', 'closed'))
                       OR (OLD.state = 'acked'           AND NEW.state IN ('pending', 'verified', 'failed', 'closed'))
                       OR (OLD.state IN ('failed', 'closed') AND NEW.state = 'verified'))
                  OR (NEW.state IN ('pending', 'wait_capability', 'acked')
                      AND (SELECT ciphertext FROM outbox_op WHERE operation_id = OLD.operation_id) IS NULL)
                BEGIN SELECT RAISE(ABORT, 'illegal delivery transition'); END""",
        """CREATE TRIGGER outbox_delivery_copy
                BEFORE UPDATE OF copy_hour ON outbox_delivery
                WHEN (OLD.copy_hour IS NOT NULL AND NEW.copy_hour IS NOT NULL AND NEW.copy_hour <> OLD.copy_hour)
                  OR (OLD.copy_hour IS NOT NULL AND NEW.copy_hour IS NULL
                      AND (OLD.ack_minute IS NOT NULL OR OLD.state = 'verified'))
                BEGIN SELECT RAISE(ABORT, 'a possible copy keeps its earliest hour and is forgotten only when proven absent'); END""",
    )

    /** The two v3 REPLACE guards of `outbox_op` (§19.21 point 4). */
    val V3_GUARDS: List<String> = listOf(
        """CREATE TRIGGER outbox_op_no_replace BEFORE INSERT ON outbox_op
                WHEN EXISTS (SELECT 1 FROM outbox_op WHERE operation_id = NEW.operation_id
                             OR (namespace_id = NEW.namespace_id AND blob_hash = NEW.blob_hash) OR rowid = NEW.rowid)
                BEGIN SELECT RAISE(ABORT, 'outbox_op rows are never replaced'); END""",
        """CREATE TRIGGER outbox_op_rowid BEFORE UPDATE ON outbox_op
                WHEN NEW.rowid IS NOT OLD.rowid
                BEGIN SELECT RAISE(ABORT, 'outbox_op identity is immutable'); END""",
    )
}

/**
 * Versioned schema (spec v2.0 §8, amended by ADR-04 pseudonyms, ADR-05 invite nonces, ADR-14
 * revocations). Rules enforced here rather than in application code:
 *  - protocol state (Olm, OpenMLS) lives in dedicated tables as opaque serialized records;
 *  - every content column is a ciphertext envelope; no plaintext content column exists;
 *  - author/sent times are stored at minute granularity (`*_minute`, ADR-08);
 *  - foreign keys and uniqueness guard conversation/channel/message integrity (§8.1);
 *  - v2 (Phase 7 sync, docs/design/faza7-sync-engine.md §2 and §11): sync state lives in
 *    SQLCipher only, persisted times are minute/hour/day values checked by CHECK constraints, and
 *    the outbox/inbox state machines are enforced by triggers ([expectedTriggers]);
 *  - v3 (Phase 8 client entitlement, docs/design/faza8-issuer.md §11.3 as corrected by §19.20):
 *    the unused v1 `entitlement`/`referral` tables are dropped behind a fail-closed guard; the
 *    nine `ent_*` tables hold the remembered schedule facts, issuance flows, tokens, invites, the
 *    drop target and payout claims, and their state machines and write-once rules are enforced by
 *    triggers. §19.20 point 1 makes this code, not the §11.3 listing, the reference for the v3 SQL
 *    (NULL-safe trigger comparisons, integer-typed times and grid indices); §19.20 point 2 adds
 *    the remembered revocations of `ent_schedule_fact`;
 *  - REPLACE guards (§19.21 point 4): SQLite runs no DELETE trigger for a row that REPLACE conflict
 *    resolution deletes (`recursive_triggers` is off), so every v3 table with write-once, frozen or
 *    state rules, and the v2 `outbox_op`, refuses an insert that conflicts on any of its keys
 *    (`<table>_no_replace`, created by migration 3);
 *  - v4 (Phase 9 direct messages, docs/design/faza9-dm.md §13.6 steps 0–4, the sync and entitlement
 *    half): the unused v1 DM tables are dropped behind a fail-closed guard; `outbox_op` and
 *    `outbox_delivery` are rebuilt to admit the 1-hour TTL bucket (SQLite cannot alter a CHECK) with
 *    every index, trigger and guard recreated from [OutboxObjects]; `inbox_blob` keeps the relay
 *    expiry of a fetched blob; `sync_namespace` records who obtains its capabilities and refuses to
 *    turn the send delay off for a DM namespace; `relay_key_registration` holds the bearer-key
 *    registrations the owner keeps at its relays (§4.8). The `dm_*` and `olm_*` tables are migration
 *    5 (§21.13 point 3), so every slice leaves a schema [MigrationRunner.verifyIntegrity] accepts;
 *  - v5 (Phase 9 direct messages, §13.6 steps 5–6, the DM tables themselves): the `dm_*` and
 *    `olm_*` tables. Every table has a random key (WITHOUT ROWID) or a random generation id, no
 *    created or last-activity column, and time columns `*_minute` (Unix seconds, `% 60 = 0`),
 *    `*_hour` (`% 3600 = 0`) or `*_day` (a day index) with `typeof` CHECKs (T33). Content columns
 *    are envelopes under the content key (28 bytes of overhead); the secret-bearing `*_env`
 *    columns of `olm_*`, `dm_pair_key`, `dm_pair_offer` and `dm_held` are envelopes under
 *    `session_state_key` (§2.5), so a SQLCipher row is doubly encrypted and the JVM heap never
 *    holds a ratchet, KEM or seal opening secret. The round-9 `sig_*` tables and
 *    `dm_self.registration_id` are not created (§22).
 *  - v6 (Phase 10 forum, docs/design/faza10-forum.md §9 "Migration 6", the `:sync` half): the
 *    funding flag `sync_namespace_fund` (a side table, because the CHECK of
 *    `sync_namespace.capability_source` cannot be altered), `relay_register_capability` (the
 *    redeemed capabilities of funded namespaces, which only the registration step reads), the two
 *    triggers that refuse `send_delay = 'off'` for a channel namespace, and the REPLACE guards of
 *    the two new tables.
 *  - v7 (Phase 10 forum, docs/design/faza10-forum.md §9 "Migration 7", as corrected by §19.28,
 *    §19.29 and §19.35; slice S3): the channel tables. The unused v1 `channels`,
 *    `channel_pseudonyms`, `mls_state` and `posts` are dropped behind a fail-closed guard; the 26
 *    new tables are `ch_*` (the channel's state, generations, epochs, candidates, posts, joins,
 *    invites, members and keys) and `mls_kv` / `mls_global_kv` (the rows OpenMLS writes through
 *    `GhostKv`, §3.4). The rules are those of v5, rowid layout included (T33: "random WITHOUT ROWID
 *    keys", F9 §13.6 step 5): a table is WITHOUT ROWID unless a rule of the design needs an
 *    insertion order or the rows are too large for it, which are exactly two tables — `mls_kv` (S0-6:
 *    values of 0.1 to 125 KB) and `ch_join_request` (§6.2.3: the committer serves requests "in
 *    arrival order") — so the other 24 keep no order of their own (§19.35, F-7 resolved); `typeof`
 *    beside every integer's range and
 *    every time column's grid (`*_minute`, `*_hour`, `*_day`, and the weekly `ch_seen.until_day`, as
 *    `dm_seen`'s); no created or last-activity column
 *    beyond the ones §9 declares; no full-text index; bounded counts and the state machines of §6.11 as
 *    triggers; a `*_no_replace` guard on every table whose writers do not use `INSERT OR IGNORE`.
 *
 * A change to an existing version is forbidden: add a new [Migration] and bump [CURRENT_VERSION].
 * The one exception is a version no release has carried: v3 has never shipped and is amended in
 * place (§19.20); from the first release that carries it, v3 is frozen like v1 and v2. v7 has not
 * shipped either, so the slices that build the channel engine (S4 to S9) may amend it in place
 * where their reading of §9 needs a column or a rule this slice could not know.
 */
object Schema {
    const val CURRENT_VERSION = 7

    class Migration(val version: Int, val statements: List<String>)

    val migrations: List<Migration> = listOf(
        Migration(
            version = 1,
            statements = listOf(
                """CREATE TABLE schema_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                )""",
                """CREATE TABLE identity (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    public_identity TEXT NOT NULL UNIQUE,
                    identity_public_key BLOB NOT NULL CHECK (length(identity_public_key) = 32),
                    derivation_version INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                )""",
                """CREATE TABLE devices (
                    device_id BLOB PRIMARY KEY NOT NULL CHECK (length(device_id) = 16),
                    signing_public_key BLOB NOT NULL CHECK (length(signing_public_key) = 32),
                    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
                    added_at INTEGER NOT NULL,
                    revoked_at INTEGER
                )""",
                """CREATE TABLE contacts (
                    contact_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    public_identity TEXT NOT NULL UNIQUE,
                    identity_public_key BLOB NOT NULL CHECK (length(identity_public_key) = 32),
                    display_name TEXT,
                    trust_state TEXT NOT NULL CHECK (trust_state IN ('unverified', 'verified', 'changed', 'blocked')),
                    trust_changed_at INTEGER,
                    created_at INTEGER NOT NULL
                )""",
                """CREATE TABLE conversations (
                    conversation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contact_id INTEGER NOT NULL UNIQUE REFERENCES contacts(contact_id) ON DELETE CASCADE,
                    protocol_version INTEGER NOT NULL,
                    disappearing_seconds INTEGER NOT NULL DEFAULT 604800,
                    created_at INTEGER NOT NULL
                )""",
                """CREATE TABLE signal_state (
                    address TEXT PRIMARY KEY NOT NULL,
                    record BLOB NOT NULL,
                    skipped_keys INTEGER NOT NULL DEFAULT 0 CHECK (skipped_keys >= 0 AND skipped_keys <= 2000),
                    updated_at INTEGER NOT NULL
                )""",
                """CREATE TABLE messages (
                    operation_id BLOB PRIMARY KEY NOT NULL CHECK (length(operation_id) = 16),
                    conversation_id INTEGER NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
                    direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
                    envelope BLOB NOT NULL,
                    content_type TEXT NOT NULL,
                    sent_at_minute INTEGER NOT NULL CHECK (sent_at_minute % 60 = 0),
                    state TEXT NOT NULL CHECK (state IN ('queued', 'sent', 'delivered', 'failed', 'received')),
                    expires_at INTEGER
                )""",
                "CREATE INDEX idx_messages_conversation ON messages(conversation_id, sent_at_minute)",
                "CREATE INDEX idx_messages_expiry ON messages(expires_at) WHERE expires_at IS NOT NULL",
                """CREATE TABLE channels (
                    channel_id BLOB PRIMARY KEY NOT NULL CHECK (length(channel_id) = 32),
                    display_name TEXT,
                    policy BLOB,
                    current_epoch INTEGER NOT NULL DEFAULT 0,
                    history_policy TEXT NOT NULL CHECK (history_policy IN ('none', 'since_join', 'full')),
                    created_at INTEGER NOT NULL
                )""",
                """CREATE TABLE channel_pseudonyms (
                    channel_id BLOB PRIMARY KEY NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
                    pseudonym_public_key BLOB NOT NULL UNIQUE CHECK (length(pseudonym_public_key) = 32),
                    revealed INTEGER NOT NULL DEFAULT 0 CHECK (revealed IN (0, 1))
                )""",
                """CREATE TABLE mls_state (
                    channel_id BLOB PRIMARY KEY NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
                    group_state BLOB NOT NULL,
                    pending_commit BLOB,
                    resync_marker INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL
                )""",
                """CREATE TABLE posts (
                    operation_id BLOB PRIMARY KEY NOT NULL CHECK (length(operation_id) = 16),
                    channel_id BLOB NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
                    author_pseudonym BLOB NOT NULL CHECK (length(author_pseudonym) = 32),
                    envelope BLOB NOT NULL,
                    content_type TEXT NOT NULL,
                    posted_at_minute INTEGER NOT NULL CHECK (posted_at_minute % 60 = 0),
                    state TEXT NOT NULL CHECK (state IN ('queued', 'published', 'received', 'hidden')),
                    expires_at INTEGER
                )""",
                "CREATE INDEX idx_posts_channel ON posts(channel_id, posted_at_minute)",
                """CREATE TABLE media (
                    media_id BLOB PRIMARY KEY NOT NULL CHECK (length(media_id) = 16),
                    owner_operation_id BLOB NOT NULL CHECK (length(owner_operation_id) = 16),
                    manifest BLOB NOT NULL,
                    wrapped_file_key BLOB NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 52428800),
                    mime TEXT NOT NULL,
                    cache_state TEXT NOT NULL CHECK (cache_state IN ('none', 'partial', 'complete'))
                )""",
                """CREATE TABLE media_blobs (
                    media_id BLOB NOT NULL REFERENCES media(media_id) ON DELETE CASCADE,
                    ordinal INTEGER NOT NULL,
                    blob_hash BLOB NOT NULL CHECK (length(blob_hash) = 32),
                    PRIMARY KEY (media_id, ordinal)
                )""",
                """CREATE TABLE relay_queue (
                    operation_id BLOB PRIMARY KEY NOT NULL CHECK (length(operation_id) = 16),
                    kind TEXT NOT NULL,
                    payload BLOB NOT NULL CHECK (length(payload) <= 65536),
                    target_policy TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at INTEGER NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1))
                )""",
                "CREATE INDEX idx_relay_queue_due ON relay_queue(acknowledged, next_retry_at)",
                """CREATE TABLE sync_cursor (
                    namespace_id BLOB PRIMARY KEY NOT NULL CHECK (length(namespace_id) = 32),
                    cursor BLOB,
                    last_success_at INTEGER
                )""",
                """CREATE TABLE entitlement (
                    period_id BLOB PRIMARY KEY NOT NULL,
                    issuer_key_id BLOB NOT NULL,
                    tokens_envelope BLOB NOT NULL,
                    valid_from INTEGER NOT NULL,
                    valid_until INTEGER NOT NULL CHECK (valid_until > valid_from)
                )""",
                """CREATE TABLE referral (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    commitment BLOB NOT NULL CHECK (length(commitment) = 32),
                    payout_view BLOB
                )""",
                """CREATE TABLE invite_nonces (
                    nonce BLOB PRIMARY KEY NOT NULL CHECK (length(nonce) = 16),
                    seen_at INTEGER NOT NULL
                )""",
                """CREATE TABLE revocations (
                    identity_public_key BLOB PRIMARY KEY NOT NULL CHECK (length(identity_public_key) = 32),
                    certificate BLOB NOT NULL,
                    received_at INTEGER NOT NULL
                )""",
                "INSERT INTO schema_meta(key, value) VALUES ('created_schema_version', '1')",
            ),
        ),
        Migration(
            version = 2,
            statements = listOf(
                // (0) Fail-closed guard: the pre-multi-relay tables never had a writer. A CHECK
                // failure aborts the migration transaction and the database stays at v1.
                "CREATE TABLE v2_migration_guard (row_count INTEGER NOT NULL CHECK (row_count = 0))",
                "INSERT INTO v2_migration_guard(row_count) SELECT count(*) FROM relay_queue",
                "INSERT INTO v2_migration_guard(row_count) SELECT count(*) FROM sync_cursor",
                "DROP TABLE v2_migration_guard",
                // idx_relay_queue_due is dropped with its table.
                "DROP TABLE relay_queue",
                "DROP TABLE sync_cursor",
                // (1) Local relay directory. Phase 14 fills it from the signed manifest; until then
                // source = 'config'. A retired onion re-added later reactivates the same row
                // (UNIQUE), keeping its cursors. onion_address is OnionAddress.toString() = host:port.
                """CREATE TABLE relay_directory (
                    relay_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    onion_address TEXT NOT NULL UNIQUE
                                  CHECK (length(onion_address) BETWEEN 64 AND 68
                                         AND substr(onion_address, 57, 7) = '.onion:'),
                    operator_id   BLOB NOT NULL CHECK (length(operator_id) = 16),
                    state         TEXT NOT NULL CHECK (state IN ('active', 'retired')),
                    source        TEXT NOT NULL CHECK (source IN ('manifest', 'config')),
                    retired_day   INTEGER CHECK (retired_day IS NULL OR retired_day >= 0),
                    CHECK ((state = 'retired') = (retired_day IS NOT NULL))
                )""",
                // listening = 0: write-only (a contact's DM inbox). send_delay: per-namespace
                // override of the send delay; 'default' follows the global privacy mode (§11.2 #15).
                """CREATE TABLE sync_namespace (
                    namespace_id BLOB PRIMARY KEY NOT NULL CHECK (length(namespace_id) = 32),
                    consumer     TEXT NOT NULL CHECK (consumer IN ('dm', 'prekeys', 'channel', 'media', 'identity')),
                    listening    INTEGER NOT NULL CHECK (listening IN (0, 1)),
                    send_delay   TEXT NOT NULL DEFAULT 'default' CHECK (send_delay IN ('default', 'on', 'off'))
                ) WITHOUT ROWID""",
                // Relays are retired, not deleted: no cascade from relay_directory.
                """CREATE TABLE namespace_relay (
                    namespace_id BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
                    relay_id     INTEGER NOT NULL REFERENCES relay_directory(relay_id),
                    PRIMARY KEY (namespace_id, relay_id)
                ) WITHOUT ROWID""",
                "CREATE INDEX idx_namespace_relay_relay ON namespace_relay(relay_id)",
                // Capabilities are stored and used, never minted (Phase 8 mints; Phase 10 may add
                // MLS-derived read tokens). The v1 token is 82 bytes; the length is not fixed here.
                // expires_hour is floored, NULL = unknown. generation is +1 on every put (race guard).
                """CREATE TABLE relay_capability (
                    relay_id     INTEGER NOT NULL REFERENCES relay_directory(relay_id) ON DELETE CASCADE,
                    namespace_id BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
                    kind         TEXT NOT NULL CHECK (kind IN ('read', 'write')),
                    token        BLOB NOT NULL CHECK (length(token) BETWEEN 1 AND 512),
                    expires_hour INTEGER CHECK (expires_hour IS NULL OR expires_hour % 3600 = 0),
                    state        TEXT NOT NULL CHECK (state IN ('usable', 'rejected', 'exhausted')),
                    generation   INTEGER NOT NULL CHECK (generation >= 1),
                    PRIMARY KEY (relay_id, namespace_id, kind)
                ) WITHOUT ROWID""",
                // Opaque per-(relay, namespace) cursor. Absent = from the beginning. Only non-empty
                // cursors are stored.
                """CREATE TABLE relay_cursor (
                    relay_id     INTEGER NOT NULL REFERENCES relay_directory(relay_id) ON DELETE CASCADE,
                    namespace_id BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
                    cursor       BLOB NOT NULL CHECK (length(cursor) = 8),
                    PRIMARY KEY (relay_id, namespace_id)
                ) WITHOUT ROWID""",
                // No cascade from sync_namespace: ops pin the namespace. not_before_minute is the
                // ADR-15 delay, sampled once. deadline_hour NULL = none (default). required_operators
                // is the ADR-11 quorum.
                """CREATE TABLE outbox_op (
                    operation_id       BLOB PRIMARY KEY NOT NULL CHECK (length(operation_id) = 16),
                    namespace_id       BLOB NOT NULL REFERENCES sync_namespace(namespace_id),
                    blob_hash          BLOB NOT NULL CHECK (length(blob_hash) = 32),
                    ciphertext         BLOB CHECK (ciphertext IS NULL OR length(ciphertext) IN (1024, 4096, 16384, 65536)),
                    ttl_seconds        INTEGER NOT NULL CHECK (ttl_seconds IN (86400, 604800, 2592000, 7776000)),
                    not_before_minute  INTEGER NOT NULL CHECK (not_before_minute % 60 = 0),
                    deadline_hour      INTEGER CHECK (deadline_hour IS NULL OR deadline_hour % 3600 = 0),
                    required_operators INTEGER NOT NULL CHECK (required_operators >= 2),
                    outcome            TEXT NOT NULL CHECK (outcome IN ('pending', 'sent', 'degraded', 'failed', 'indeterminate')),
                    released           INTEGER NOT NULL DEFAULT 0 CHECK (released IN (0, 1)),
                    CHECK (deadline_hour IS NULL OR deadline_hour > not_before_minute),
                    CHECK (released = 0 OR outcome <> 'pending'),
                    UNIQUE (namespace_id, blob_hash)
                )""",
                OutboxObjects.IDX_OP_OPEN,
                // inflight is the write-ahead lease marker. copy_hour is the earliest attempt that
                // may have stored; ack_minute the latest receipt; strikes the absent-after-ack count.
                """CREATE TABLE outbox_delivery (
                    operation_id        BLOB NOT NULL REFERENCES outbox_op(operation_id) ON DELETE CASCADE,
                    relay_id            INTEGER NOT NULL REFERENCES relay_directory(relay_id),
                    state               TEXT NOT NULL
                                        CHECK (state IN ('pending', 'wait_capability', 'acked', 'verified', 'failed', 'closed')),
                    attempts            INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                    next_attempt_minute INTEGER NOT NULL CHECK (next_attempt_minute % 60 = 0),
                    inflight            INTEGER NOT NULL DEFAULT 0 CHECK (inflight IN (0, 1)),
                    lease_hour          INTEGER CHECK (lease_hour IS NULL OR lease_hour % 3600 = 0),
                    copy_hour           INTEGER CHECK (copy_hour IS NULL OR copy_hour % 3600 = 0),
                    ack_minute          INTEGER CHECK (ack_minute IS NULL OR ack_minute % 60 = 0),
                    strikes             INTEGER NOT NULL DEFAULT 0 CHECK (strikes BETWEEN 0 AND 2),
                    CHECK (inflight = 0 OR lease_hour IS NOT NULL),
                    CHECK (state <> 'acked' OR (ack_minute IS NOT NULL AND copy_hour IS NOT NULL)),
                    PRIMARY KEY (operation_id, relay_id)
                ) WITHOUT ROWID""",
                OutboxObjects.IDX_DELIVERY_DUE,
                OutboxObjects.IDX_DELIVERY_RELAY,
                // Dedup key and tombstone. WITHOUT ROWID: rows are ordered by (namespace, hash), not
                // by arrival. fetch_seq is the local hand-off order, only while fetched; offers is
                // the write-ahead poison guard; a done tombstone carries nothing else.
                // retain_until_day is rounded up to a 7-day boundary (ceil7, §11.2 #8).
                """CREATE TABLE inbox_blob (
                    namespace_id       BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
                    blob_hash          BLOB NOT NULL CHECK (length(blob_hash) = 32),
                    state              TEXT NOT NULL CHECK (state IN ('listed', 'unavailable', 'fetched', 'done')),
                    ciphertext         BLOB CHECK (ciphertext IS NULL OR length(ciphertext) IN (1024, 4096, 16384, 65536)),
                    fetch_seq          INTEGER,
                    fetch_attempts     INTEGER NOT NULL DEFAULT 0 CHECK (fetch_attempts >= 0),
                    next_fetch_minute  INTEGER NOT NULL DEFAULT 0 CHECK (next_fetch_minute % 60 = 0),
                    offers             INTEGER NOT NULL DEFAULT 0 CHECK (offers >= 0),
                    offer_after_minute INTEGER NOT NULL DEFAULT 0 CHECK (offer_after_minute % 60 = 0),
                    retain_until_day   INTEGER NOT NULL CHECK (retain_until_day >= 0 AND retain_until_day % 7 = 0),
                    CHECK ((state = 'fetched') = (ciphertext IS NOT NULL)),
                    CHECK ((state = 'fetched') = (fetch_seq IS NOT NULL)),
                    CHECK (state <> 'done' OR (fetch_attempts = 0 AND next_fetch_minute = 0
                                                AND offers = 0 AND offer_after_minute = 0)),
                    PRIMARY KEY (namespace_id, blob_hash)
                ) WITHOUT ROWID""",
                "CREATE UNIQUE INDEX idx_inbox_fetch_seq ON inbox_blob(fetch_seq) WHERE fetch_seq IS NOT NULL",
                "CREATE INDEX idx_inbox_work ON inbox_blob(namespace_id, state, next_fetch_minute)",
                "CREATE INDEX idx_inbox_retention ON inbox_blob(retain_until_day)",
                // Which relays listed a not-yet-fetched hash.
                """CREATE TABLE inbox_source (
                    namespace_id BLOB NOT NULL,
                    blob_hash    BLOB NOT NULL,
                    relay_id     INTEGER NOT NULL REFERENCES relay_directory(relay_id) ON DELETE CASCADE,
                    state        TEXT NOT NULL CHECK (state IN ('candidate', 'not_found', 'bad')),
                    PRIMARY KEY (namespace_id, blob_hash, relay_id),
                    FOREIGN KEY (namespace_id, blob_hash) REFERENCES inbox_blob(namespace_id, blob_hash) ON DELETE CASCADE
                ) WITHOUT ROWID""",
                "CREATE INDEX idx_inbox_source_relay ON inbox_source(relay_id, state)",
                // State machines enforced by the schema (D8). Row triggers fire only on rows actually
                // updated, and an UPDATE OF trigger fires whenever its column is in the SET list.
                // The outbox texts live in [OutboxObjects], which migration 4 recreates them from.
                *OutboxObjects.V2_TRIGGERS.toTypedArray(),
                """CREATE TRIGGER inbox_blob_insert
                BEFORE INSERT ON inbox_blob
                WHEN NEW.state NOT IN ('listed', 'done')
                BEGIN SELECT RAISE(ABORT, 'inbox rows start listed (or done for own blobs)'); END""",
                """CREATE TRIGGER inbox_blob_identity
                BEFORE UPDATE OF namespace_id, blob_hash ON inbox_blob
                BEGIN SELECT RAISE(ABORT, 'inbox identity is immutable'); END""",
                // 'done' is final.
                """CREATE TRIGGER inbox_blob_state
                BEFORE UPDATE OF state ON inbox_blob
                WHEN NOT ((OLD.state = 'listed'      AND NEW.state IN ('fetched', 'unavailable'))
                       OR (OLD.state = 'unavailable' AND NEW.state = 'listed')
                       OR (OLD.state = 'fetched'     AND NEW.state = 'done'))
                BEGIN SELECT RAISE(ABORT, 'illegal inbox transition'); END""",
                """CREATE TRIGGER inbox_blob_sources
                AFTER UPDATE OF state ON inbox_blob
                WHEN NEW.state IN ('fetched', 'done')
                BEGIN DELETE FROM inbox_source WHERE namespace_id = NEW.namespace_id AND blob_hash = NEW.blob_hash; END""",
            ),
        ),
        Migration(
            version = 3,
            statements = listOf(
                // v3 has never shipped in a release, so the design's corrections (§19.20) amend this
                // migration in place instead of adding a v4: no device holds an earlier v3.
                // (0) Fail-closed guard: the v1 entitlement and referral tables never had a writer (RC
                // G15). A CHECK failure aborts the migration transaction and the database stays at v2.
                "CREATE TABLE v3_migration_guard (row_count INTEGER NOT NULL CHECK (row_count = 0))",
                "INSERT INTO v3_migration_guard(row_count) SELECT count(*) FROM entitlement",
                "INSERT INTO v3_migration_guard(row_count) SELECT count(*) FROM referral",
                "DROP TABLE v3_migration_guard",
                "DROP TABLE entitlement",
                "DROP TABLE referral",
                // Every time column and grid index (week, epoch) also CHECKs typeof(x) = 'integer':
                // SQLite's % casts a REAL to INTEGER first, so `x % 60 = 0` alone would accept
                // 1757491200.5, a time finer than a minute (never persisted, design §11.3; the typeof
                // CHECKs are §19.20 point 1).
                // (1) Accepted ES keys: the device's append-only memory of (kind, epoch) -> key id (ES
                // rule 5). epoch is a week or epoch index of the grid, not a time.
                """CREATE TABLE ent_key (
                    kind    TEXT    NOT NULL CHECK (kind IN ('access', 'invite', 'credit')),
                    epoch   INTEGER NOT NULL CHECK (typeof(epoch) = 'integer' AND epoch >= 0),
                    key_id  BLOB    NOT NULL CHECK (length(key_id) = 32),
                    PRIMARY KEY (kind, epoch)
                ) WITHOUT ROWID""",
                // (1b) The other facts of ES rule 5 (design §19.2, §19.20 point 2), append-only like
                // ent_key: 'slots' = SHA-256 of the slot-number set of a covered week; 'price' =
                // SHA-256 of the price of a covered price epoch; 'revoked_<kind>' = a (kind, epoch)
                // that an accepted ES revoked, whose digest is the revoked key's id (its
                // ent_key.key_id: an ES revokes only keys it lists). A later ES that drops a
                // remembered revocation is refused (SCHEDULE_CONFLICT), or a leaked key's tokens
                // would become valid again. The token kind is part of the fact name because
                // (fact, epoch) is the key and access weeks, invite epochs and credit epochs are
                // separate indices that can share a number. epoch is a grid index, not a time.
                """CREATE TABLE ent_schedule_fact (
                    fact    TEXT    NOT NULL CHECK (fact IN ('slots', 'price', 'revoked_access', 'revoked_invite', 'revoked_credit')),
                    epoch   INTEGER NOT NULL CHECK (typeof(epoch) = 'integer' AND epoch >= 0),
                    digest  BLOB    NOT NULL CHECK (length(digest) = 32),
                    PRIMARY KEY (fact, epoch)
                ) WITHOUT ROWID""",
                // (2) Singleton. payout_salt is created with the row (SecureRandom) and never leaves the
                // device. alarm_flags = SCHEDULE_CONFLICT | ISSUER_MISMATCH | REFUSED_BY_RELAY.
                // payment_shown_minute = the minute the payment screen was last visible, rounded up
                // (S9b): a new process restores the relay-session hold of §19.11 from it
                // (SyncController.restorePaymentHold); the engine nulls it once the longest hold
                // (60 min) has passed. restore_scan_root = SHA-256 commitment to the restored root
                // (by its invite-0 drop namespace): a restore's drop scan is owed for that root
                // only; restore_scan_until_day = the scan's end, fixed at its install under a
                // trusted clock (NULL while owed and not installed; design §19.26 point 15).
                """CREATE TABLE ent_state (
                    id                     INTEGER PRIMARY KEY CHECK (id = 1),
                    schedule_seq           INTEGER NOT NULL CHECK (schedule_seq >= 1),
                    schedule_digest        BLOB    NOT NULL CHECK (length(schedule_digest) = 32),
                    next_invite_index      INTEGER NOT NULL DEFAULT 0 CHECK (next_invite_index BETWEEN 0 AND 65535),
                    payout_salt            BLOB    NOT NULL CHECK (length(payout_salt) = 32),
                    restore_scan_root      BLOB    CHECK (restore_scan_root IS NULL OR length(restore_scan_root) = 32),
                    restore_scan_until_day INTEGER CHECK (restore_scan_until_day IS NULL OR (typeof(restore_scan_until_day) = 'integer' AND restore_scan_until_day >= 0)),
                    auto_renew_credits     INTEGER NOT NULL DEFAULT 0 CHECK (auto_renew_credits IN (0, 1)),
                    alarm_flags            INTEGER NOT NULL DEFAULT 0 CHECK (alarm_flags BETWEEN 0 AND 7),
                    payment_shown_minute   INTEGER CHECK (payment_shown_minute IS NULL OR (typeof(payment_shown_minute) = 'integer' AND payment_shown_minute % 60 = 0)),
                    CHECK (restore_scan_until_day IS NULL OR restore_scan_root IS NOT NULL)
                )""",
                // (3) Issuance flows (packs, the trial, and refreshes of received credits, §19.8). Live
                // rows carry their secrets; terminal rows carry none and are deleted by GC at
                // terminal_day + 7. purchase_id is local only, never sent. sent = the current request
                // has left the device at least once; shown = payment instructions ever shown;
                // prev_state = the latest InvoiceState (UX, lost vs expired); input_token = the invite
                // (trial) or the received credit (refresh); created_hour is NULL in terminal states
                // (§19.15); receipt_minute = invoice receipt (deadline = + 24 h); outstanding_atomic =
                // amount − credited − seen.
                """CREATE TABLE ent_purchase (
                    purchase_id        BLOB    PRIMARY KEY NOT NULL CHECK (length(purchase_id) = 16),
                    kind               TEXT    NOT NULL CHECK (kind IN ('pack', 'trial', 'refresh')),
                    pay_with           TEXT    NOT NULL CHECK (pay_with IN ('xmr', 'credits', 'invite', 'credit')),
                    state              TEXT    NOT NULL CHECK (state IN ('prepared', 'invoiced', 'finalized', 'expired', 'failed', 'lost')),
                    seed               BLOB    CHECK (seed IS NULL OR length(seed) = 32),
                    claim_key          BLOB    CHECK (claim_key IS NULL OR length(claim_key) = 32),
                    invoice_id         BLOB    CHECK (invoice_id IS NULL OR length(invoice_id) = 16),
                    subaddress         TEXT    CHECK (subaddress IS NULL OR length(subaddress) = 95),
                    amount_atomic      INTEGER CHECK (amount_atomic IS NULL OR amount_atomic >= 0),
                    input_token        BLOB    CHECK (input_token IS NULL OR length(input_token) = 354),
                    base_week          INTEGER CHECK (base_week IS NULL OR (typeof(base_week) = 'integer' AND base_week >= 0)),
                    schedule_seq       INTEGER CHECK (schedule_seq IS NULL OR schedule_seq >= 1),
                    layout_digest      BLOB    CHECK (layout_digest IS NULL OR length(layout_digest) = 32),
                    sent               INTEGER NOT NULL DEFAULT 0 CHECK (sent IN (0, 1)),
                    disclosed          INTEGER NOT NULL DEFAULT 0 CHECK (disclosed IN (0, 1)),
                    shown              INTEGER NOT NULL DEFAULT 0 CHECK (shown IN (0, 1)),
                    prev_state         INTEGER NOT NULL DEFAULT 0 CHECK (prev_state BETWEEN 0 AND 6),
                    created_hour       INTEGER CHECK (created_hour IS NULL OR (typeof(created_hour) = 'integer' AND created_hour % 3600 = 0)),
                    receipt_minute     INTEGER CHECK (receipt_minute IS NULL OR (typeof(receipt_minute) = 'integer' AND receipt_minute % 60 = 0)),
                    outstanding_atomic INTEGER CHECK (outstanding_atomic IS NULL OR outstanding_atomic >= 0),
                    next_due_minute    INTEGER CHECK (next_due_minute IS NULL OR (typeof(next_due_minute) = 'integer' AND next_due_minute % 60 = 0)),
                    attempt            INTEGER NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 40),
                    terminal_day       INTEGER CHECK (terminal_day IS NULL OR (typeof(terminal_day) = 'integer' AND terminal_day >= 0)),
                    CHECK ((kind = 'trial') = (pay_with = 'invite')),
                    CHECK ((kind = 'refresh') = (pay_with = 'credit')),
                    CHECK (kind = 'pack' OR (claim_key IS NULL AND invoice_id IS NULL AND subaddress IS NULL AND amount_atomic IS NULL
                                             AND receipt_minute IS NULL AND outstanding_atomic IS NULL)),
                    CHECK (kind <> 'pack' OR input_token IS NULL),
                    CHECK (kind = 'pack' OR state <> 'invoiced'),
                    CHECK (state IN ('finalized', 'expired', 'failed', 'lost')
                           OR (terminal_day IS NULL AND seed IS NOT NULL AND base_week IS NOT NULL AND schedule_seq IS NOT NULL
                               AND layout_digest IS NOT NULL AND created_hour IS NOT NULL AND (kind <> 'pack' OR claim_key IS NOT NULL)
                               AND (kind = 'pack' OR input_token IS NOT NULL))),
                    CHECK (state NOT IN ('finalized', 'expired', 'failed', 'lost')
                           OR (terminal_day IS NOT NULL AND seed IS NULL AND claim_key IS NULL AND invoice_id IS NULL
                               AND subaddress IS NULL AND amount_atomic IS NULL AND input_token IS NULL AND next_due_minute IS NULL
                               AND created_hour IS NULL AND receipt_minute IS NULL AND outstanding_atomic IS NULL)),
                    CHECK (state <> 'invoiced' OR (invoice_id IS NOT NULL AND amount_atomic IS NOT NULL AND receipt_minute IS NOT NULL
                           AND ((amount_atomic = 0) = (subaddress IS NULL))))
                ) WITHOUT ROWID""",
                // (4) Tokens. Keyed by the (random) nullifier: no insertion order, no purchase link at
                // rest. A token leaves the table when spent, lost or out of its window; it is never
                // marked "spent". reserved_relay = relay_directory.relay_id, without a foreign key
                // (Phase 7 GC of retired relays).
                """CREATE TABLE ent_token (
                    nullifier          BLOB    PRIMARY KEY NOT NULL CHECK (length(nullifier) = 32),
                    kind               TEXT    NOT NULL CHECK (kind IN ('access', 'invite', 'credit')),
                    epoch              INTEGER NOT NULL CHECK (typeof(epoch) = 'integer' AND epoch >= 0),
                    slot               INTEGER CHECK (slot IS NULL OR slot BETWEEN 0 AND 31),
                    token              BLOB    NOT NULL CHECK (length(token) = 354),
                    state              TEXT    NOT NULL CHECK (state IN ('fresh', 'reserved')),
                    eligible_minute    INTEGER NOT NULL CHECK (typeof(eligible_minute) = 'integer' AND eligible_minute % 60 = 0),
                    reserved_for       TEXT    CHECK (reserved_for IS NULL OR reserved_for IN ('relay', 'purchase', 'claim')),
                    reserved_relay     INTEGER,
                    reserved_namespace BLOB    CHECK (reserved_namespace IS NULL OR length(reserved_namespace) = 32),
                    request_id         BLOB    CHECK (request_id IS NULL OR length(request_id) = 16),
                    reserved_ref       BLOB    CHECK (reserved_ref IS NULL OR length(reserved_ref) = 16),
                    CHECK ((kind = 'access') = (slot IS NOT NULL)),
                    CHECK ((state = 'reserved') = (reserved_for IS NOT NULL)),
                    CHECK (reserved_for IS NULL OR reserved_for <> 'relay'
                           OR (kind = 'access' AND reserved_relay IS NOT NULL AND reserved_namespace IS NOT NULL
                               AND request_id IS NOT NULL AND reserved_ref IS NULL)),
                    CHECK (reserved_for IS NULL OR reserved_for = 'relay'
                           OR (kind = 'credit' AND reserved_ref IS NOT NULL AND reserved_relay IS NULL
                               AND reserved_namespace IS NULL AND request_id IS NULL))
                ) WITHOUT ROWID""",
                """CREATE UNIQUE INDEX idx_ent_token_one_reservation
                    ON ent_token(reserved_relay, reserved_namespace, epoch) WHERE reserved_for = 'relay'""",
                // (5) Invites this identity created (inviter side), with the refresh time of a credit
                // sent to the drop, drawn at creation, never at a read (§19.29).
                """CREATE TABLE ent_invite (
                    invite_index        INTEGER NOT NULL PRIMARY KEY CHECK (invite_index BETWEEN 0 AND 65535),
                    state               TEXT    NOT NULL CHECK (state IN ('created', 'credited', 'closed')),
                    payload             BLOB    CHECK (payload IS NULL OR length(payload) = 538),
                    drop_namespace      BLOB    NOT NULL CHECK (length(drop_namespace) = 32),
                    listen_until_day    INTEGER NOT NULL CHECK (typeof(listen_until_day) = 'integer' AND listen_until_day >= 0),
                    refresh_minute      INTEGER NOT NULL CHECK (typeof(refresh_minute) = 'integer' AND refresh_minute % 60 = 0),
                    CHECK (state = 'created' OR payload IS NULL)
                ) WITHOUT ROWID""",
                // (6) The inviter's drop this identity owes its first XMR-pack credit to (invited
                // identities only). drop_minute = t_drop, drawn at activation (§19.12).
                """CREATE TABLE ent_drop_target (
                    id             INTEGER PRIMARY KEY CHECK (id = 1),
                    drop_namespace BLOB    NOT NULL CHECK (length(drop_namespace) = 32),
                    drop_key       BLOB    NOT NULL CHECK (length(drop_key) = 32),
                    drop_slots     BLOB    NOT NULL CHECK (length(drop_slots) = 3),
                    state          TEXT    NOT NULL CHECK (state IN ('waiting', 'enqueued')),
                    operation_id   BLOB    CHECK (operation_id IS NULL OR length(operation_id) = 16),
                    drop_minute    INTEGER NOT NULL CHECK (typeof(drop_minute) = 'integer' AND drop_minute % 60 = 0),
                    until_day      INTEGER NOT NULL CHECK (typeof(until_day) = 'integer' AND until_day >= 0),
                    CHECK ((state = 'enqueued') = (operation_id IS NOT NULL))
                )""",
                // (7) Payout claims (write-ahead).
                """CREATE TABLE ent_claim (
                    claim_id        BLOB    PRIMARY KEY NOT NULL CHECK (length(claim_id) = 16),
                    state           TEXT    NOT NULL CHECK (state IN ('prepared', 'queued', 'failed')),
                    payout_address  TEXT    CHECK (payout_address IS NULL OR length(payout_address) = 95),
                    queued_atomic   INTEGER CHECK (queued_atomic IS NULL OR queued_atomic > 0),
                    sent            INTEGER NOT NULL DEFAULT 0 CHECK (sent IN (0, 1)),
                    next_due_minute INTEGER CHECK (next_due_minute IS NULL OR (typeof(next_due_minute) = 'integer' AND next_due_minute % 60 = 0)),
                    attempt         INTEGER NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 20),
                    terminal_day    INTEGER CHECK (terminal_day IS NULL OR (typeof(terminal_day) = 'integer' AND terminal_day >= 0)),
                    CHECK ((state = 'prepared') = (payout_address IS NOT NULL AND next_due_minute IS NOT NULL AND terminal_day IS NULL)),
                    CHECK ((state = 'queued') = (queued_atomic IS NOT NULL)),
                    CHECK (state = 'prepared' OR terminal_day IS NOT NULL)
                ) WITHOUT ROWID""",
                "CREATE UNIQUE INDEX idx_ent_claim_one_open ON ent_claim(state) WHERE state = 'prepared'",
                // (8) Salted hashes of payout addresses already used (refuse reuse, RP V11):
                // HMAC-SHA256(payout_salt, address).
                """CREATE TABLE ent_payout_used (
                    address_hash BLOB    PRIMARY KEY NOT NULL CHECK (length(address_hash) = 32),
                    until_day    INTEGER NOT NULL CHECK (typeof(until_day) = 'integer' AND until_day >= 0)
                ) WITHOUT ROWID""",
                // State machines and write-once rules enforced in SQL (Phase 7 D8 precedent; G-12).
                """CREATE TRIGGER ent_key_append_only BEFORE UPDATE ON ent_key
                BEGIN SELECT RAISE(ABORT, 'ent_key is append-only'); END""",
                """CREATE TRIGGER ent_key_no_delete BEFORE DELETE ON ent_key
                BEGIN SELECT RAISE(ABORT, 'ent_key is append-only'); END""",
                """CREATE TRIGGER ent_schedule_fact_append_only BEFORE UPDATE ON ent_schedule_fact
                BEGIN SELECT RAISE(ABORT, 'ent_schedule_fact is append-only'); END""",
                """CREATE TRIGGER ent_schedule_fact_no_delete BEFORE DELETE ON ent_schedule_fact
                BEGIN SELECT RAISE(ABORT, 'ent_schedule_fact is append-only'); END""",
                """CREATE TRIGGER ent_purchase_transitions BEFORE UPDATE OF state ON ent_purchase
                WHEN NOT ((OLD.state = NEW.state)
                       OR (OLD.state = 'prepared' AND NEW.state IN ('invoiced', 'finalized', 'failed'))
                       OR (OLD.state = 'invoiced' AND NEW.state IN ('finalized', 'expired', 'failed', 'lost')))
                BEGIN SELECT RAISE(ABORT, 'illegal purchase transition'); END""",
                // Seed, claim key, layout and base week may change only while nothing has been sent
                // (prepared, sent = 0); sent never goes back; the id, kind and pay_with never change (the
                // id also because an UPDATE OR REPLACE onto another purchase's id would delete that row
                // past ent_purchase_delete_terminal_only, §19.21 point 4). Wiping at a terminal state is
                // allowed. `sent` is compared NULL-safely (§19.20 point 1): under
                // UPDATE OR REPLACE a NULL becomes the column DEFAULT (0) after this trigger ran, and
                // `NULL < 1` would make the whole WHEN NULL, so SQLite would skip the trigger and
                // unfreeze a sent request.
                """CREATE TRIGGER ent_purchase_frozen BEFORE UPDATE ON ent_purchase
                WHEN NEW.purchase_id IS NOT OLD.purchase_id OR NEW.kind IS NOT OLD.kind OR NEW.pay_with IS NOT OLD.pay_with
                  OR (NEW.state NOT IN ('finalized', 'expired', 'failed', 'lost')
                      AND (NEW.sent IS NULL OR NEW.sent < OLD.sent
                           OR ((OLD.sent = 1 OR OLD.state <> 'prepared')
                               AND (NEW.seed IS NOT OLD.seed OR NEW.claim_key IS NOT OLD.claim_key
                                    OR NEW.base_week IS NOT OLD.base_week OR NEW.schedule_seq IS NOT OLD.schedule_seq
                                    OR NEW.layout_digest IS NOT OLD.layout_digest OR NEW.input_token IS NOT OLD.input_token))))
                BEGIN SELECT RAISE(ABORT, 'issuance secrets and layout are frozen once sent'); END""",
                """CREATE TRIGGER ent_purchase_invoice_frozen BEFORE UPDATE OF invoice_id, subaddress, amount_atomic ON ent_purchase
                WHEN NEW.state NOT IN ('finalized', 'expired', 'failed', 'lost') AND OLD.invoice_id IS NOT NULL
                 AND (NEW.invoice_id IS NOT OLD.invoice_id OR NEW.subaddress IS NOT OLD.subaddress
                      OR NEW.amount_atomic IS NOT OLD.amount_atomic)
                BEGIN SELECT RAISE(ABORT, 'an invoice is recorded once'); END""",
                """CREATE TRIGGER ent_purchase_delete_terminal_only BEFORE DELETE ON ent_purchase
                WHEN OLD.state NOT IN ('finalized', 'expired', 'failed', 'lost')
                BEGIN SELECT RAISE(ABORT, 'a live purchase is never deleted'); END""",
                // A reservation ends only by deletion, except that credits of a failed flow return to
                // fresh. The flow's state is compared with IS, not = (§19.20 point 1): for a reference
                // to no row (a flow deleted by GC) the subquery is NULL, `NULL = 'failed'` would make
                // the whole WHEN NULL and SQLite would skip the trigger, releasing a credit of no
                // failed flow.
                """CREATE TRIGGER ent_token_state BEFORE UPDATE OF state ON ent_token
                WHEN NOT ((OLD.state = NEW.state)
                       OR (OLD.state = 'fresh' AND NEW.state = 'reserved')
                       OR (OLD.state = 'reserved' AND NEW.state = 'fresh' AND OLD.kind = 'credit' AND
                           ((OLD.reserved_for = 'purchase'
                             AND (SELECT state FROM ent_purchase WHERE purchase_id = OLD.reserved_ref) IS 'failed')
                         OR (OLD.reserved_for = 'claim'
                             AND (SELECT state FROM ent_claim WHERE claim_id = OLD.reserved_ref) IS 'failed'))))
                BEGIN SELECT RAISE(ABORT, 'a reservation ends only by deletion'); END""",
                // R8 in SQL: a token never changes, and a reserved token keeps its relay, namespace,
                // request id and reference.
                """CREATE TRIGGER ent_token_binding BEFORE UPDATE ON ent_token
                WHEN NEW.nullifier IS NOT OLD.nullifier OR NEW.kind IS NOT OLD.kind OR NEW.epoch IS NOT OLD.epoch
                  OR NEW.slot IS NOT OLD.slot OR NEW.token IS NOT OLD.token OR NEW.eligible_minute IS NOT OLD.eligible_minute
                  OR (OLD.state = 'reserved' AND NEW.state = 'reserved'
                      AND (NEW.reserved_for IS NOT OLD.reserved_for OR NEW.reserved_relay IS NOT OLD.reserved_relay
                           OR NEW.reserved_namespace IS NOT OLD.reserved_namespace OR NEW.request_id IS NOT OLD.request_id
                           OR NEW.reserved_ref IS NOT OLD.reserved_ref))
                BEGIN SELECT RAISE(ABORT, 'a token and its reservation keep their binding'); END""",
                """CREATE TRIGGER ent_invite_transitions BEFORE UPDATE OF state ON ent_invite
                WHEN NOT ((OLD.state = NEW.state)
                       OR (OLD.state = 'created'  AND NEW.state IN ('credited', 'closed'))
                       OR (OLD.state = 'credited' AND NEW.state = 'closed'))
                BEGIN SELECT RAISE(ABORT, 'illegal invite transition'); END""",
                // `sent` is compared NULL-safely, as in ent_purchase_frozen (§19.20 point 1).
                """CREATE TRIGGER ent_claim_guard BEFORE UPDATE ON ent_claim
                WHEN NOT ((OLD.state = NEW.state AND (NEW.payout_address IS OLD.payout_address)
                           AND NEW.sent IS NOT NULL AND NEW.sent >= OLD.sent)
                       OR (OLD.state = 'prepared' AND NEW.state IN ('queued', 'failed')))
                BEGIN SELECT RAISE(ABORT, 'a claim keeps its address and is decided once'); END""",
                """CREATE TRIGGER ent_drop_target_transitions BEFORE UPDATE ON ent_drop_target
                WHEN NOT ((OLD.state = NEW.state AND NEW.operation_id IS OLD.operation_id)
                       OR (OLD.state = 'waiting' AND NEW.state = 'enqueued'))
                BEGIN SELECT RAISE(ABORT, 'illegal drop target transition'); END""",
                // (9) REPLACE guards (§19.21 point 4). With recursive_triggers off (SQLite's default), a
                // row that INSERT OR REPLACE or UPDATE OR REPLACE deletes to resolve a key conflict fires
                // no DELETE trigger, and the row written in its place passes no UPDATE trigger. A BEFORE
                // INSERT trigger runs before the conflict is resolved, so every table with write-once,
                // frozen or state rules refuses an insert that conflicts on any of its keys (primary key,
                // unique index, hidden rowid): REPLACE neither deletes nor overwrites one of its rows.
                // INSERT OR IGNORE and UPSERT are refused alike (a trigger cannot tell them apart), so
                // these tables take plain INSERTs. A table whose DELETE is restricted also never changes
                // a key in an UPDATE: ent_key and ent_schedule_fact refuse every UPDATE,
                // ent_purchase_frozen keeps purchase_id, outbox_op_immutable and outbox_op_rowid keep the
                // keys of outbox_op. Elsewhere a DELETE is legal, so an UPDATE OR REPLACE that deletes a
                // row there does nothing a DELETE followed by the UPDATE could not.
                """CREATE TRIGGER ent_key_no_replace BEFORE INSERT ON ent_key
                WHEN EXISTS (SELECT 1 FROM ent_key WHERE kind = NEW.kind AND epoch = NEW.epoch)
                BEGIN SELECT RAISE(ABORT, 'ent_key is append-only'); END""",
                """CREATE TRIGGER ent_schedule_fact_no_replace BEFORE INSERT ON ent_schedule_fact
                WHEN EXISTS (SELECT 1 FROM ent_schedule_fact WHERE fact = NEW.fact AND epoch = NEW.epoch)
                BEGIN SELECT RAISE(ABORT, 'ent_schedule_fact is append-only'); END""",
                """CREATE TRIGGER ent_purchase_no_replace BEFORE INSERT ON ent_purchase
                WHEN EXISTS (SELECT 1 FROM ent_purchase WHERE purchase_id = NEW.purchase_id)
                BEGIN SELECT RAISE(ABORT, 'ent_purchase rows are never replaced'); END""",
                // Also the one-reservation index: REPLACE would delete the token holding it.
                """CREATE TRIGGER ent_token_no_replace BEFORE INSERT ON ent_token
                WHEN EXISTS (SELECT 1 FROM ent_token WHERE nullifier = NEW.nullifier
                             OR (NEW.reserved_for = 'relay' AND reserved_for = 'relay' AND reserved_relay = NEW.reserved_relay
                                 AND reserved_namespace = NEW.reserved_namespace AND epoch = NEW.epoch))
                BEGIN SELECT RAISE(ABORT, 'ent_token rows are never replaced'); END""",
                """CREATE TRIGGER ent_invite_no_replace BEFORE INSERT ON ent_invite
                WHEN EXISTS (SELECT 1 FROM ent_invite WHERE invite_index = NEW.invite_index)
                BEGIN SELECT RAISE(ABORT, 'ent_invite rows are never replaced'); END""",
                """CREATE TRIGGER ent_drop_target_no_replace BEFORE INSERT ON ent_drop_target
                WHEN EXISTS (SELECT 1 FROM ent_drop_target WHERE id = NEW.id)
                BEGIN SELECT RAISE(ABORT, 'ent_drop_target rows are never replaced'); END""",
                // Also the one-open index: REPLACE would delete the open claim.
                """CREATE TRIGGER ent_claim_no_replace BEFORE INSERT ON ent_claim
                WHEN EXISTS (SELECT 1 FROM ent_claim WHERE claim_id = NEW.claim_id OR (NEW.state = 'prepared' AND state = 'prepared'))
                BEGIN SELECT RAISE(ABORT, 'ent_claim rows are never replaced'); END""",
                // outbox_op is a v2 table, released in Phase 7, whose DELETE rule REPLACE could skip; v2
                // stays unchanged, so its guards are created here. Enqueue deletes a released, wiped op
                // before the same bytes enter again (Phase 7 design §9), so it never meets the guard. An
                // insert that names no rowid has a NEW.rowid that names no existing row. outbox_delivery
                // and inbox_blob (v2) get none: they restrict transitions, not deletion, so a REPLACE
                // there does what a DELETE followed by an INSERT (whose trigger still runs) may do, and
                // the Phase 7 design writes them with INSERT OR IGNORE (§3.9) and UPSERTs (§3.1, §4.1),
                // which a guard would refuse.
                *OutboxObjects.V3_GUARDS.toTypedArray(),
            ),
        ),
        Migration(
            version = 4,
            statements = migration4(),
        ),
        Migration(
            version = 5,
            statements = migration5Tables() + migration5Triggers(),
        ),
        Migration(
            version = 6,
            statements = migration6(),
        ),
        Migration(
            version = 7,
            statements = migration7Guard() + migration7Tables() + migration7Triggers(),
        ),
    )

    /**
     * Steps 0–4 of Phase 9 design §13.6 (the sync and entitlement half of schema v4; the `dm_*` and
     * `olm_*` tables are migration 5, §21.13 point 3). One transaction, append-only, fail-closed.
     */
    private fun migration4(): List<String> = listOf(
        // (0a) `ALTER TABLE ... RENAME TO` must rewrite the references of the rebuilt outbox tables
        // (step 1 point 6), which `legacy_alter_table` would turn off. The pragma function reports
        // the setting of this connection; the guard is 0 only when it returns exactly one row
        // holding 0, and a build without pragma functions fails the statement, so both fail closed.
        "CREATE TABLE v4_alter_guard (legacy_alter_table INTEGER NOT NULL CHECK (legacy_alter_table = 0))",
        "INSERT INTO v4_alter_guard(legacy_alter_table) " +
            "SELECT (SELECT count(*) FROM pragma_legacy_alter_table WHERE legacy_alter_table <> 0) " +
            "+ (SELECT 1 - count(*) FROM pragma_legacy_alter_table)",
        "DROP TABLE v4_alter_guard",
        // (0b) Fail-closed guard and drop of the unused v1 DM tables: Repositories writes only
        // `identity`, `invite_nonces` and `revocations`, so these four never had a writer. A CHECK
        // failure aborts the migration transaction and the database stays at v3.
        "CREATE TABLE v4_migration_guard (row_count INTEGER NOT NULL CHECK (row_count = 0))",
        "INSERT INTO v4_migration_guard(row_count) SELECT count(*) FROM messages",
        "INSERT INTO v4_migration_guard(row_count) SELECT count(*) FROM conversations",
        "INSERT INTO v4_migration_guard(row_count) SELECT count(*) FROM contacts",
        "INSERT INTO v4_migration_guard(row_count) SELECT count(*) FROM signal_state",
        "DROP TABLE v4_migration_guard",
        "DROP INDEX idx_messages_conversation",
        "DROP INDEX idx_messages_expiry",
        "DROP TABLE messages",
        "DROP TABLE conversations",
        "DROP TABLE contacts",
        "DROP TABLE signal_state",
        // (1) Rebuild outbox_op and outbox_delivery to admit TTL 3600 (SQLite cannot alter a CHECK;
        // the v2 CHECK is frozen). Everything else is the v2 definition verbatim.
        """CREATE TABLE outbox_op_v4 (
                    operation_id       BLOB PRIMARY KEY NOT NULL CHECK (length(operation_id) = 16),
                    namespace_id       BLOB NOT NULL REFERENCES sync_namespace(namespace_id),
                    blob_hash          BLOB NOT NULL CHECK (length(blob_hash) = 32),
                    ciphertext         BLOB CHECK (ciphertext IS NULL OR length(ciphertext) IN (1024, 4096, 16384, 65536)),
                    ttl_seconds        INTEGER NOT NULL CHECK (ttl_seconds IN (3600, 86400, 604800, 2592000, 7776000)),
                    not_before_minute  INTEGER NOT NULL CHECK (not_before_minute % 60 = 0),
                    deadline_hour      INTEGER CHECK (deadline_hour IS NULL OR deadline_hour % 3600 = 0),
                    required_operators INTEGER NOT NULL CHECK (required_operators >= 2),
                    outcome            TEXT NOT NULL CHECK (outcome IN ('pending', 'sent', 'degraded', 'failed', 'indeterminate')),
                    released           INTEGER NOT NULL DEFAULT 0 CHECK (released IN (0, 1)),
                    CHECK (deadline_hour IS NULL OR deadline_hour > not_before_minute),
                    CHECK (released = 0 OR outcome <> 'pending'),
                    UNIQUE (namespace_id, blob_hash)
                )""",
        """CREATE TABLE outbox_delivery_v4 (
                    operation_id        BLOB NOT NULL REFERENCES outbox_op_v4(operation_id) ON DELETE CASCADE,
                    relay_id            INTEGER NOT NULL REFERENCES relay_directory(relay_id),
                    state               TEXT NOT NULL
                                        CHECK (state IN ('pending', 'wait_capability', 'acked', 'verified', 'failed', 'closed')),
                    attempts            INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                    next_attempt_minute INTEGER NOT NULL CHECK (next_attempt_minute % 60 = 0),
                    inflight            INTEGER NOT NULL DEFAULT 0 CHECK (inflight IN (0, 1)),
                    lease_hour          INTEGER CHECK (lease_hour IS NULL OR lease_hour % 3600 = 0),
                    copy_hour           INTEGER CHECK (copy_hour IS NULL OR copy_hour % 3600 = 0),
                    ack_minute          INTEGER CHECK (ack_minute IS NULL OR ack_minute % 60 = 0),
                    strikes             INTEGER NOT NULL DEFAULT 0 CHECK (strikes BETWEEN 0 AND 2),
                    CHECK (inflight = 0 OR lease_hour IS NOT NULL),
                    CHECK (state <> 'acked' OR (ack_minute IS NOT NULL AND copy_hour IS NOT NULL)),
                    PRIMARY KEY (operation_id, relay_id)
                ) WITHOUT ROWID""",
        // Explicit column lists (E-5), rowids preserved (the v3 guard outbox_op_rowid protects them).
        // The new tables have no triggers yet, so outbox_delivery_insert does not refuse a copied row.
        """INSERT INTO outbox_op_v4(rowid, operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute,
                                          deadline_hour, required_operators, outcome, released)
                SELECT rowid, operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute,
                       deadline_hour, required_operators, outcome, released
                FROM outbox_op""",
        """INSERT INTO outbox_delivery_v4(operation_id, relay_id, state, attempts, next_attempt_minute, inflight, lease_hour,
                                                copy_hour, ack_minute, strikes)
                SELECT operation_id, relay_id, state, attempts, next_attempt_minute, inflight, lease_hour, copy_hour, ack_minute, strikes
                FROM outbox_delivery""",
        // The child goes first: with foreign_keys = ON, dropping the parent first would cascade-delete
        // the deliveries (an implicit DELETE runs foreign-key actions, but no triggers).
        "DROP TABLE outbox_delivery",
        // This removes the five v2 triggers of outbox_op and the two v3 guards with it.
        "DROP TABLE outbox_op",
        // With legacy_alter_table off (guarded above), SQLite rewrites the delivery table's
        // foreign-key reference to the renamed parent.
        "ALTER TABLE outbox_op_v4 RENAME TO outbox_op",
        "ALTER TABLE outbox_delivery_v4 RENAME TO outbox_delivery",
        *OutboxObjects.INDEXES.toTypedArray(),
        *OutboxObjects.V2_TRIGGERS.toTypedArray(),
        *OutboxObjects.V3_GUARDS.toTypedArray(),
        // Step 1 point 8: the rebuild leaves no dangling reference, or the migration rolls back.
        "CREATE TABLE v4_fk_guard (violations INTEGER NOT NULL CHECK (violations = 0))",
        "INSERT INTO v4_fk_guard(violations) SELECT count(*) FROM pragma_foreign_key_check",
        "DROP TABLE v4_fk_guard",
        // (2) Relay expiry of fetched blobs (§10.3): kept only while the row is fetched, so a
        // tombstone carries no relay time.
        """ALTER TABLE inbox_blob ADD COLUMN relay_expiry_hour INTEGER
                  CHECK (relay_expiry_hour IS NULL OR (typeof(relay_expiry_hour) = 'integer' AND relay_expiry_hour % 3600 = 0))""",
        """CREATE TRIGGER inbox_blob_relay_expiry_insert BEFORE INSERT ON inbox_blob
                WHEN NEW.relay_expiry_hour IS NOT NULL
                BEGIN SELECT RAISE(ABORT, 'relay expiry is kept only while fetched'); END""",
        """CREATE TRIGGER inbox_blob_relay_expiry_update BEFORE UPDATE OF state, relay_expiry_hour ON inbox_blob
                WHEN NEW.relay_expiry_hour IS NOT NULL AND NEW.state <> 'fetched'
                BEGIN SELECT RAISE(ABORT, 'relay expiry is kept only while fetched'); END""",
        // A row already fetched at the upgrade recorded no relay expiry, and 0 is a legal expiry
        // hour, so the column is filled instead of left NULL: the retention of a fetched row is
        // ceil7(day(E) + 24), hence day(E) <= retain_until_day - 24 and (retain_until_day - 23) days
        // is above every expiry the row can have had. A consumer that bounds a message's life by
        // min(E, its own rule) then falls back to its own rule, never deleting on arrival.
        """UPDATE inbox_blob SET relay_expiry_hour = max(0, (retain_until_day - 23) * 86400)
                WHERE state = 'fetched' AND relay_expiry_hour IS NULL""",
        // (3) Capability source and the DM send-delay rule. LOCAL namespaces (a contact's inbox or
        // bundle) install their credentials themselves and are never redeemed (§13.3 item 3).
        """ALTER TABLE sync_namespace ADD COLUMN capability_source TEXT NOT NULL DEFAULT 'redeem'
                  CHECK (capability_source IN ('redeem', 'local'))""",
        """CREATE TRIGGER sync_namespace_dm_delay BEFORE UPDATE OF send_delay ON sync_namespace
                WHEN NEW.consumer = 'dm' AND NEW.send_delay = 'off'
                BEGIN SELECT RAISE(ABORT, 'DM namespaces cannot turn the send delay off'); END""",
        """CREATE TRIGGER sync_namespace_dm_delay_insert BEFORE INSERT ON sync_namespace
                WHEN NEW.consumer = 'dm' AND NEW.send_delay = 'off'
                BEGIN SELECT RAISE(ABORT, 'DM namespaces cannot turn the send delay off'); END""",
        // (4) Key registrations (§4.4, §4.8): what the owner keeps registered at each relay of its
        // own namespaces. `kind` admits 'fetch' (the bundle namespace's shared secret, §22.8.7).
        """CREATE TABLE relay_key_registration (
                  relay_id            INTEGER NOT NULL REFERENCES relay_directory(relay_id) ON DELETE CASCADE,
                  namespace_id        BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
                  period_id           INTEGER NOT NULL CHECK (typeof(period_id) = 'integer' AND period_id >= 0),
                  kind                TEXT NOT NULL CHECK (kind IN ('read', 'deposit', 'fetch')),
                  verifier            BLOB NOT NULL CHECK (length(verifier) = 32),
                  request_id          BLOB NOT NULL CHECK (length(request_id) = 16),
                  state               TEXT NOT NULL CHECK (state IN ('pending', 'done')),
                  inflight            INTEGER NOT NULL DEFAULT 0 CHECK (inflight IN (0, 1)),
                  lease_hour          INTEGER CHECK (lease_hour IS NULL OR (typeof(lease_hour) = 'integer' AND lease_hour % 3600 = 0)),
                  attempts            INTEGER NOT NULL DEFAULT 0 CHECK (typeof(attempts) = 'integer' AND attempts >= 0),
                  next_attempt_minute INTEGER NOT NULL CHECK (typeof(next_attempt_minute) = 'integer' AND next_attempt_minute % 60 = 0),
                  valid_until_hour    INTEGER CHECK (valid_until_hour IS NULL OR (typeof(valid_until_hour) = 'integer' AND valid_until_hour % 3600 = 0)),
                  CHECK ((state = 'done') = (valid_until_hour IS NOT NULL)),
                  CHECK (inflight = 0 OR lease_hour IS NOT NULL),
                  CHECK (state = 'pending' OR inflight = 0),
                  PRIMARY KEY (relay_id, namespace_id, period_id, kind)
                ) WITHOUT ROWID""",
        """CREATE TRIGGER relay_key_registration_state BEFORE UPDATE ON relay_key_registration
                WHEN NEW.relay_id IS NOT OLD.relay_id OR NEW.namespace_id IS NOT OLD.namespace_id
                  OR NEW.period_id IS NOT OLD.period_id OR NEW.kind IS NOT OLD.kind OR NEW.verifier IS NOT OLD.verifier
                  OR NOT ((OLD.state = NEW.state)
                       OR (OLD.state = 'pending' AND NEW.state = 'done')
                       OR (OLD.state = 'done' AND NEW.state = 'pending'))
                BEGIN SELECT RAISE(ABORT, 'a registration keeps its key and verifier and moves only between pending and done'); END""",
        """CREATE TRIGGER relay_key_registration_no_replace BEFORE INSERT ON relay_key_registration
                WHEN EXISTS (SELECT 1 FROM relay_key_registration WHERE relay_id = NEW.relay_id
                             AND namespace_id = NEW.namespace_id AND period_id = NEW.period_id AND kind = NEW.kind)
                BEGIN SELECT RAISE(ABORT, 'relay_key_registration rows are never replaced'); END""",
    )

    /**
     * Step 5 of Phase 9 design §13.6: the messaging and Olm tables. One transaction, append-only,
     * fail-closed, like every migration before it.
     */
    private fun migration5Tables(): List<String> = listOf(
        """CREATE TABLE dm_self (
                  id                  INTEGER PRIMARY KEY CHECK (id = 1),
                  card_index          INTEGER NOT NULL CHECK (typeof(card_index) = 'integer' AND card_index BETWEEN 0 AND 65535),
                  seen_key            BLOB NOT NULL CHECK (length(seen_key) = 32),
                  content_key_wrapped BLOB NOT NULL CHECK (length(content_key_wrapped) BETWEEN 40 AND 256),
                  state_key_wrapped   BLOB NOT NULL CHECK (length(state_key_wrapped) BETWEEN 40 AND 256),
                  bundle_week         INTEGER CHECK (bundle_week IS NULL OR (typeof(bundle_week) = 'integer' AND bundle_week >= 0)),
                  expiry_clock_minute INTEGER NOT NULL CHECK (typeof(expiry_clock_minute) = 'integer' AND expiry_clock_minute % 60 = 0),
                  accept_after_minute INTEGER CHECK (accept_after_minute IS NULL
                                                     OR (typeof(accept_after_minute) = 'integer' AND accept_after_minute % 60 = 0)),
                  bundle_published_week INTEGER CHECK (bundle_published_week IS NULL
                                                       OR (typeof(bundle_published_week) = 'integer' AND bundle_published_week >= 0))
                )""",
        """CREATE TABLE dm_own_namespace (
                  namespace_id BLOB PRIMARY KEY NOT NULL CHECK (length(namespace_id) = 32),
                  role         TEXT NOT NULL CHECK (role IN ('inbox', 'bundle')),
                  card_index   INTEGER NOT NULL CHECK (typeof(card_index) = 'integer' AND card_index BETWEEN 0 AND 65535),
                  UNIQUE (role, card_index)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_contact (
                  contact_id        BLOB PRIMARY KEY NOT NULL CHECK (length(contact_id) = 16),
                  identity_pk       BLOB NOT NULL UNIQUE CHECK (length(identity_pk) = 32),
                  card_env          BLOB CHECK (card_env IS NULL OR length(card_env) = 159),
                  card_index        INTEGER NOT NULL CHECK (typeof(card_index) = 'integer' AND card_index BETWEEN 0 AND 65535),
                  pinned_identity   BLOB CHECK (pinned_identity IS NULL OR length(pinned_identity) = 32),
                  pending_identity  BLOB CHECK (pending_identity IS NULL OR length(pending_identity) = 32),
                  bundle_week_seen  INTEGER CHECK (bundle_week_seen IS NULL
                                                   OR (typeof(bundle_week_seen) = 'integer' AND bundle_week_seen >= 0)),
                  trust_state       TEXT NOT NULL
                                    CHECK (trust_state IN ('request', 'unverified', 'verified', 'changed', 'blocked', 'revoked')),
                  source            TEXT NOT NULL CHECK (source IN ('qr_in_person', 'link', 'request')),
                  establishment     TEXT NOT NULL CHECK (establishment IN ('card_only', 'fetching', 'ready', 'unreachable')),
                  fetch_attempts    INTEGER NOT NULL DEFAULT 0 CHECK (fetch_attempts BETWEEN 0 AND 3),
                  fetch_listen_until_minute INTEGER CHECK (fetch_listen_until_minute IS NULL
                                                           OR (typeof(fetch_listen_until_minute) = 'integer'
                                                               AND fetch_listen_until_minute % 60 = 0)),
                  reset_needed      INTEGER NOT NULL DEFAULT 0 CHECK (reset_needed IN (0, 1)),
                  verified_fp       BLOB CHECK (verified_fp IS NULL OR length(verified_fp) = 32),
                  name_env          BLOB CHECK (name_env IS NULL OR length(name_env) BETWEEN 29 AND 284),
                  request_until_day INTEGER CHECK (request_until_day IS NULL
                                                   OR (typeof(request_until_day) = 'integer' AND request_until_day >= 0)),
                  pq_announced_week INTEGER CHECK (pq_announced_week IS NULL
                                                   OR (typeof(pq_announced_week) = 'integer' AND pq_announced_week >= 0)),
                  CHECK ((trust_state = 'changed') = (pending_identity IS NOT NULL)),
                  CHECK ((trust_state = 'request') = (request_until_day IS NOT NULL)),
                  CHECK (trust_state IN ('blocked', 'revoked') OR card_env IS NOT NULL),
                  CHECK (trust_state <> 'changed' OR pinned_identity IS NOT NULL),
                  CHECK (pending_identity IS NULL OR pending_identity IS NOT pinned_identity),
                  CHECK ((establishment = 'fetching') = (fetch_listen_until_minute IS NOT NULL))
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_pair_key (
                  contact_id BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
                  direction  TEXT NOT NULL CHECK (direction IN ('in', 'out')),
                  root_gen   INTEGER NOT NULL CHECK (typeof(root_gen) = 'integer' AND root_gen BETWEEN 0 AND 65535),
                  week       INTEGER NOT NULL CHECK (typeof(week) = 'integer' AND week >= 0),
                  recog_key  BLOB NOT NULL CHECK (length(recog_key) = 32),
                  open_env   BLOB NOT NULL CHECK (length(open_env) = 60),
                  PRIMARY KEY (contact_id, direction, root_gen, week)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_pair_offer (
                  contact_id   BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
                  root_gen     INTEGER NOT NULL CHECK (typeof(root_gen) = 'integer' AND root_gen BETWEEN 0 AND 65535),
                  root_env     BLOB CHECK (root_env IS NULL OR length(root_env) = 60),
                  offer_env    BLOB CHECK (offer_env IS NULL OR length(offer_env) IN (70, 1194)),
                  base_week    INTEGER NOT NULL CHECK (typeof(base_week) = 'integer' AND base_week >= 0),
                  acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
                  PRIMARY KEY (contact_id, root_gen)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_conversation (
                  conversation_id BLOB PRIMARY KEY NOT NULL CHECK (length(conversation_id) = 16),
                  contact_id      BLOB NOT NULL UNIQUE REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
                  timer_code      INTEGER NOT NULL DEFAULT 4 CHECK (timer_code BETWEEN 0 AND 5),
                  timer_version   INTEGER NOT NULL DEFAULT 0 CHECK (typeof(timer_version) = 'integer' AND timer_version >= 0)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_message (
                  message_id             BLOB PRIMARY KEY NOT NULL CHECK (length(message_id) = 16),
                  conversation_id        BLOB NOT NULL REFERENCES dm_conversation(conversation_id) ON DELETE CASCADE,
                  direction              TEXT NOT NULL CHECK (direction IN ('in', 'out')),
                  kind                   INTEGER NOT NULL CHECK (kind IN (1, 2)),
                  author_minute          INTEGER NOT NULL CHECK (typeof(author_minute) = 'integer' AND author_minute % 60 = 0),
                  sort_minute            INTEGER NOT NULL CHECK (typeof(sort_minute) = 'integer' AND sort_minute % 60 = 0
                                                                 AND sort_minute <= author_minute),
                  minute_index           INTEGER NOT NULL CHECK (minute_index BETWEEN 0 AND 65535),
                  timer_code             INTEGER NOT NULL CHECK (timer_code BETWEEN 0 AND 5),
                  body_env               BLOB CHECK (body_env IS NULL OR length(body_env) BETWEEN 30 AND 61485),
                  state                  TEXT NOT NULL
                                         CHECK (state IN ('queued', 'sent', 'degraded', 'failed', 'indeterminate', 'unread', 'read')),
                  expire_at_minute       INTEGER CHECK (expire_at_minute IS NULL
                                                        OR (typeof(expire_at_minute) = 'integer' AND expire_at_minute % 60 = 0)),
                  unread_deadline_minute INTEGER CHECK (unread_deadline_minute IS NULL
                                                        OR (typeof(unread_deadline_minute) = 'integer'
                                                            AND unread_deadline_minute % 60 = 0)),
                  delete_at_minute       INTEGER CHECK (delete_at_minute IS NULL
                                                        OR (typeof(delete_at_minute) = 'integer' AND delete_at_minute % 60 = 0)),
                  CHECK ((direction = 'out') = (state IN ('queued', 'sent', 'degraded', 'failed', 'indeterminate'))),
                  CHECK (direction = 'in' OR sort_minute = author_minute),
                  CHECK ((kind = 1) = (body_env IS NOT NULL)),
                  CHECK (timer_code <> 0 OR (expire_at_minute IS NULL AND unread_deadline_minute IS NULL)),
                  CHECK (timer_code = 0 OR direction = 'in' OR expire_at_minute IS NOT NULL),
                  CHECK (timer_code = 0 OR direction = 'out' OR unread_deadline_minute IS NOT NULL),
                  CHECK (state <> 'read' OR timer_code = 0 OR expire_at_minute IS NOT NULL),
                  CHECK (delete_at_minute IS (CASE WHEN expire_at_minute IS NOT NULL
                                                   THEN expire_at_minute ELSE unread_deadline_minute END))
                ) WITHOUT ROWID""",
        "CREATE INDEX idx_dm_message_order ON dm_message(conversation_id, sort_minute, minute_index, message_id)",
        "CREATE INDEX idx_dm_message_delete ON dm_message(delete_at_minute) WHERE delete_at_minute IS NOT NULL",
        """CREATE TABLE dm_outbound_item (
                  item_id       BLOB PRIMARY KEY NOT NULL CHECK (length(item_id) = 16),
                  contact_id    BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
                  message_ref   BLOB REFERENCES dm_message(message_id) ON DELETE CASCADE,
                  kind          INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 4),
                  control       TEXT CHECK (control IS NULL OR control IN ('reconnect', 'revocation', 'reset')),
                  l0_env        BLOB CHECK (l0_env IS NULL OR length(l0_env) BETWEEN 29 AND 65564),
                  deadline_hour INTEGER NOT NULL CHECK (typeof(deadline_hour) = 'integer' AND deadline_hour % 3600 = 0),
                  state         TEXT NOT NULL
                                CHECK (state IN ('pending', 'enqueued', 'sent', 'degraded', 'failed', 'indeterminate')),
                  CHECK ((kind = 4) = (control IS NOT NULL)),
                  CHECK (kind = 4 OR message_ref IS NOT NULL)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_outbound_op (
                  operation_id  BLOB PRIMARY KEY NOT NULL CHECK (length(operation_id) = 16),
                  purpose       TEXT NOT NULL CHECK (purpose IN ('item', 'bundle')),
                  item_id       BLOB REFERENCES dm_outbound_item(item_id) ON DELETE CASCADE,
                  bundle_week   INTEGER CHECK (bundle_week IS NULL OR (typeof(bundle_week) = 'integer' AND bundle_week >= 0)),
                  blob          BLOB CHECK (blob IS NULL OR length(blob) IN (4096, 16384, 65536)),
                  resend_count  INTEGER NOT NULL DEFAULT 0 CHECK (resend_count BETWEEN 0 AND 2),
                  deadline_hour INTEGER NOT NULL CHECK (typeof(deadline_hour) = 'integer' AND deadline_hour % 3600 = 0),
                  CHECK ((purpose = 'item') = (item_id IS NOT NULL)),
                  CHECK ((purpose = 'bundle') = (bundle_week IS NOT NULL))
                ) WITHOUT ROWID""",
        "CREATE INDEX idx_dm_outbound_op_item ON dm_outbound_op(item_id) WHERE item_id IS NOT NULL",
        """CREATE TABLE dm_pending_send (
                  item_id         BLOB PRIMARY KEY NOT NULL REFERENCES dm_outbound_item(item_id) ON DELETE CASCADE,
                  contact_id      BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
                  fail_after_hour INTEGER NOT NULL CHECK (typeof(fail_after_hour) = 'integer' AND fail_after_hour % 3600 = 0)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_bundle_candidate (
                  contact_id   BLOB PRIMARY KEY NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
                  bundle_env   BLOB NOT NULL CHECK (length(bundle_env) = 1421),
                  bundle_week  INTEGER NOT NULL CHECK (typeof(bundle_week) = 'integer' AND bundle_week >= 0),
                  bundle_rank  INTEGER NOT NULL CHECK (typeof(bundle_rank) = 'integer' AND bundle_rank BETWEEN 0 AND 65535)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_orphan_namespace (
                  namespace_id BLOB PRIMARY KEY NOT NULL CHECK (length(namespace_id) = 32)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_scheduled (
                  sched_id   BLOB PRIMARY KEY NOT NULL CHECK (length(sched_id) = 16),
                  contact_id BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
                  what       TEXT NOT NULL CHECK (what IN ('reconnect', 'revocation')),
                  payload    BLOB CHECK (payload IS NULL OR length(payload) = 102),
                  due_minute INTEGER NOT NULL CHECK (typeof(due_minute) = 'integer' AND due_minute % 60 = 0),
                  CHECK ((what = 'revocation') = (payload IS NOT NULL)),
                  UNIQUE (contact_id, what)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_held (
                  held_id           BLOB PRIMARY KEY NOT NULL CHECK (length(held_id) = 16),
                  contact_id        BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
                  identity          BLOB NOT NULL CHECK (length(identity) = 32),
                  l1_env            BLOB NOT NULL CHECK (length(l1_env) BETWEEN 29 AND 65564),
                  gen_id            INTEGER NOT NULL CHECK (typeof(gen_id) = 'integer' AND gen_id BETWEEN 0 AND 4294967295),
                  prov_env          BLOB CHECK (prov_env IS NULL OR length(prov_env) = 60),
                  hold_until_minute INTEGER NOT NULL CHECK (typeof(hold_until_minute) = 'integer' AND hold_until_minute % 60 = 0),
                  relay_expiry_hour INTEGER NOT NULL CHECK (typeof(relay_expiry_hour) = 'integer' AND relay_expiry_hour % 3600 = 0),
                  consume_minute    INTEGER NOT NULL CHECK (typeof(consume_minute) = 'integer' AND consume_minute % 60 = 0)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_reaction (
                  target_id    BLOB NOT NULL REFERENCES dm_message(message_id) ON DELETE CASCADE,
                  from_self    INTEGER NOT NULL CHECK (from_self IN (0, 1)),
                  grapheme_env BLOB NOT NULL CHECK (length(grapheme_env) BETWEEN 29 AND 60),
                  PRIMARY KEY (target_id, from_self)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_seen (
                  tag       BLOB PRIMARY KEY NOT NULL CHECK (length(tag) = 16),
                  until_day INTEGER NOT NULL CHECK (typeof(until_day) = 'integer' AND until_day >= 0 AND until_day % 7 = 0)
                ) WITHOUT ROWID""",
        """CREATE TABLE olm_session (
                  contact_id        BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
                  slot              TEXT NOT NULL CHECK (slot IN ('current', 'previous')),
                  session_id        BLOB NOT NULL CHECK (length(session_id) = 32),
                  role              TEXT NOT NULL CHECK (role IN ('initiator', 'responder')),
                  acknowledged      INTEGER NOT NULL CHECK (acknowledged IN (0, 1)),
                  state_env         BLOB NOT NULL CHECK (length(state_env) BETWEEN 29 AND 65564),
                  prov_env          BLOB CHECK (prov_env IS NULL OR length(prov_env) = 60),
                  prov_erase_minute INTEGER CHECK (prov_erase_minute IS NULL
                                                   OR (typeof(prov_erase_minute) = 'integer' AND prov_erase_minute % 60 = 0)),
                  peer_gen_id       INTEGER CHECK (peer_gen_id IS NULL
                                                   OR (typeof(peer_gen_id) = 'integer' AND peer_gen_id BETWEEN 0 AND 4294967295)),
                  unack_since_day   INTEGER CHECK (unack_since_day IS NULL
                                                   OR (typeof(unack_since_day) = 'integer' AND unack_since_day >= 0)),
                  retire_day        INTEGER CHECK (retire_day IS NULL
                                                   OR (typeof(retire_day) = 'integer' AND retire_day >= 0)),
                  peer_bind_minute  INTEGER CHECK (peer_bind_minute IS NULL
                                                   OR (typeof(peer_bind_minute) = 'integer' AND peer_bind_minute % 60 = 0)),
                  prov_anchor_minute INTEGER CHECK (prov_anchor_minute IS NULL
                                                    OR (typeof(prov_anchor_minute) = 'integer' AND prov_anchor_minute % 60 = 0)),
                  pair_sent         INTEGER NOT NULL DEFAULT 0 CHECK (pair_sent IN (0, 1)),
                  CHECK ((role = 'responder') = (peer_bind_minute IS NOT NULL)),
                  CHECK (role = 'initiator' OR acknowledged = 1),
                  CHECK ((role = 'initiator' AND acknowledged = 0) = (unack_since_day IS NOT NULL)),
                  CHECK ((role = 'initiator') = (peer_gen_id IS NOT NULL)),
                  CHECK ((slot = 'previous') = (retire_day IS NOT NULL)),
                  CHECK (prov_erase_minute IS NULL OR prov_env IS NOT NULL),
                  PRIMARY KEY (contact_id, slot),
                  UNIQUE (contact_id, session_id)
                ) WITHOUT ROWID""",
        """CREATE TABLE olm_prekey_gen (
                  gen_id           INTEGER PRIMARY KEY NOT NULL
                                   CHECK (typeof(gen_id) = 'integer' AND gen_id BETWEEN 0 AND 4294967295),
                  bundle_week      INTEGER NOT NULL CHECK (typeof(bundle_week) = 'integer' AND bundle_week >= 0),
                  fallback_pub     BLOB NOT NULL UNIQUE CHECK (length(fallback_pub) = 32),
                  secrets_env      BLOB NOT NULL CHECK (length(secrets_env) = 92),
                  superseded_day   INTEGER CHECK (superseded_day IS NULL
                                                  OR (typeof(superseded_day) = 'integer' AND superseded_day >= 0)),
                  delete_after_day INTEGER CHECK (delete_after_day IS NULL
                                                  OR (typeof(delete_after_day) = 'integer' AND delete_after_day >= 0)),
                  CHECK ((superseded_day IS NULL) = (delete_after_day IS NULL)),
                  CHECK (delete_after_day IS NULL OR delete_after_day = superseded_day + 91)
                ) WITHOUT ROWID""",
        "CREATE UNIQUE INDEX idx_olm_prekey_gen_current ON olm_prekey_gen((superseded_day IS NULL)) WHERE superseded_day IS NULL",
        """CREATE TABLE olm_prekey_used (
                  gen_id     INTEGER NOT NULL REFERENCES olm_prekey_gen(gen_id) ON DELETE CASCADE,
                  session_id BLOB NOT NULL CHECK (length(session_id) = 32),
                  PRIMARY KEY (gen_id, session_id)
                ) WITHOUT ROWID""",
        """CREATE TABLE dm_peer_pq (
                  contact_id  BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
                  gen_id      INTEGER NOT NULL CHECK (typeof(gen_id) = 'integer' AND gen_id BETWEEN 0 AND 4294967295),
                  bundle_week INTEGER NOT NULL CHECK (typeof(bundle_week) = 'integer' AND bundle_week >= 0),
                  source      TEXT NOT NULL CHECK (source IN ('bundle', 'in_band')),
                  xwing_pk    BLOB NOT NULL CHECK (length(xwing_pk) = 1216),
                  PRIMARY KEY (contact_id, gen_id)
                ) WITHOUT ROWID""",
    )

    /**
     * Step 6 of §13.6: the state-machine, write-once and REPLACE guards of v5.
     *
     * Comparisons are NULL-safe (`IS NOT`, R-T6): SQLite's `<>` is NULL for a NULL operand, and a
     * `WHEN` clause that evaluates to NULL does not fire, which would let a write-once column go
     * from a value to NULL unnoticed.
     */
    private fun migration5Triggers(): List<String> = listOf(
        """CREATE TRIGGER dm_self_fixed BEFORE UPDATE ON dm_self
                WHEN NEW.id IS NOT OLD.id OR NEW.seen_key IS NOT OLD.seen_key OR NEW.card_index IS NOT OLD.card_index
                BEGIN SELECT RAISE(ABORT, 'the identity row keeps its id, seen key and card index'); END""",
        """CREATE TRIGGER dm_self_monotonic BEFORE UPDATE OF bundle_week, expiry_clock_minute ON dm_self
                WHEN (NEW.bundle_week IS NOT NULL AND OLD.bundle_week IS NOT NULL AND NEW.bundle_week < OLD.bundle_week)
                  OR (NEW.bundle_week IS NULL AND OLD.bundle_week IS NOT NULL)
                  OR NEW.expiry_clock_minute < OLD.expiry_clock_minute
                BEGIN SELECT RAISE(ABORT, 'the bundle week and the expiry clock never go backwards'); END""",
        """CREATE TRIGGER dm_contact_identity BEFORE UPDATE ON dm_contact
                WHEN NEW.contact_id IS NOT OLD.contact_id OR NEW.identity_pk IS NOT OLD.identity_pk
                BEGIN SELECT RAISE(ABORT, 'a contact keeps its id and its Ed25519 identity'); END""",
        """CREATE TRIGGER dm_contact_pin BEFORE UPDATE OF pinned_identity ON dm_contact
                WHEN NEW.pinned_identity IS NOT OLD.pinned_identity
                  AND NOT (OLD.pinned_identity IS NULL AND NEW.pinned_identity IS NOT NULL)
                  AND NOT (OLD.trust_state = 'changed' AND NEW.pinned_identity IS OLD.pending_identity)
                BEGIN SELECT RAISE(ABORT, 'the pinned identity is set once and changes only through KEYDEC'); END""",
        """CREATE TRIGGER dm_contact_trust BEFORE UPDATE OF trust_state ON dm_contact
                WHEN NOT ((OLD.trust_state = NEW.trust_state)
                       OR (OLD.trust_state = 'request'    AND NEW.trust_state IN ('unverified', 'blocked', 'revoked'))
                       OR (OLD.trust_state = 'unverified' AND NEW.trust_state IN ('verified', 'changed', 'blocked', 'revoked'))
                       -- No verified -> unverified edge: §8.3 clears a verification only through a
                       -- key change, which goes verified -> changed -> unverified.
                       OR (OLD.trust_state = 'verified'   AND NEW.trust_state IN ('changed', 'blocked', 'revoked'))
                       OR (OLD.trust_state = 'changed'    AND NEW.trust_state IN ('unverified', 'verified', 'blocked', 'revoked'))
                       OR (OLD.trust_state = 'blocked'    AND NEW.trust_state = 'revoked'))
                BEGIN SELECT RAISE(ABORT, 'illegal trust transition'); END""",
        """CREATE TRIGGER dm_message_identity BEFORE UPDATE ON dm_message
                WHEN NEW.message_id IS NOT OLD.message_id OR NEW.conversation_id IS NOT OLD.conversation_id
                  OR NEW.direction IS NOT OLD.direction OR NEW.kind IS NOT OLD.kind
                  OR NEW.author_minute IS NOT OLD.author_minute OR NEW.sort_minute IS NOT OLD.sort_minute
                  OR NEW.minute_index IS NOT OLD.minute_index OR NEW.timer_code IS NOT OLD.timer_code
                  OR NEW.body_env IS NOT OLD.body_env
                BEGIN SELECT RAISE(ABORT, 'only the state and the three expiry columns of a message change'); END""",
        """CREATE TRIGGER dm_message_state BEFORE UPDATE OF state ON dm_message
                WHEN NOT ((OLD.state = NEW.state)
                       OR (OLD.state = 'queued' AND NEW.state IN ('sent', 'degraded', 'failed', 'indeterminate'))
                       OR (OLD.state = 'failed' AND NEW.state = 'queued')
                       OR (OLD.state = 'unread' AND NEW.state = 'read'))
                BEGIN SELECT RAISE(ABORT, 'illegal message state transition'); END""",
        """CREATE TRIGGER dm_message_expiry
                BEFORE UPDATE OF expire_at_minute, unread_deadline_minute ON dm_message
                WHEN (OLD.expire_at_minute IS NOT NULL
                      AND (NEW.expire_at_minute IS NULL OR NEW.expire_at_minute > OLD.expire_at_minute))
                  OR (OLD.unread_deadline_minute IS NOT NULL
                      AND (NEW.unread_deadline_minute IS NULL OR NEW.unread_deadline_minute > OLD.unread_deadline_minute))
                BEGIN SELECT RAISE(ABORT, 'an expiry time only moves earlier'); END""",
        """CREATE TRIGGER dm_held_expiry BEFORE UPDATE OF hold_until_minute ON dm_held
                WHEN NEW.hold_until_minute > OLD.hold_until_minute
                BEGIN SELECT RAISE(ABORT, 'a hold deadline only moves earlier'); END""",
        """CREATE TRIGGER dm_conversation_timer BEFORE UPDATE OF timer_version ON dm_conversation
                WHEN NEW.timer_version < OLD.timer_version
                BEGIN SELECT RAISE(ABORT, 'the timer version never decreases'); END""",
        """CREATE TRIGGER dm_held_limit BEFORE INSERT ON dm_held
                WHEN (SELECT count(*) FROM dm_held WHERE contact_id = NEW.contact_id) >= 256
                BEGIN SELECT RAISE(ABORT, 'at most 256 held rows per contact'); END""",
        """CREATE TRIGGER dm_pair_offer_root BEFORE UPDATE ON dm_pair_offer
                WHEN (OLD.root_env IS NOT NULL AND NEW.root_env IS NOT NULL AND NEW.root_env IS NOT OLD.root_env)
                  OR (OLD.root_env IS NULL AND NEW.root_env IS NOT NULL)
                  OR (OLD.offer_env IS NOT NULL AND NEW.offer_env IS NOT NULL AND NEW.offer_env IS NOT OLD.offer_env)
                  OR (OLD.offer_env IS NULL AND NEW.offer_env IS NOT NULL)
                  OR NEW.acknowledged < OLD.acknowledged
                BEGIN SELECT RAISE(ABORT, 'an offered root is erased, never replaced, and is acknowledged once'); END""",
        """CREATE TRIGGER olm_session_identity BEFORE UPDATE ON olm_session
                WHEN NEW.session_id IS NOT OLD.session_id OR NEW.role IS NOT OLD.role
                  OR NEW.peer_gen_id IS NOT OLD.peer_gen_id
                  OR NEW.acknowledged < OLD.acknowledged
                  OR (OLD.unack_since_day IS NOT NULL AND NEW.unack_since_day IS NOT NULL
                      AND NEW.unack_since_day IS NOT OLD.unack_since_day)
                  OR (OLD.unack_since_day IS NULL AND NEW.unack_since_day IS NOT NULL)
                  OR (OLD.prov_env IS NOT NULL AND NEW.prov_env IS NOT NULL AND NEW.prov_env IS NOT OLD.prov_env)
                  OR (OLD.prov_env IS NULL AND NEW.prov_env IS NOT NULL)
                  OR (OLD.peer_bind_minute IS NOT NULL
                      AND (NEW.peer_bind_minute IS NULL OR NEW.peer_bind_minute < OLD.peer_bind_minute))
                  OR (OLD.prov_anchor_minute IS NOT NULL AND NEW.prov_anchor_minute IS NOT OLD.prov_anchor_minute)
                  OR NEW.pair_sent < OLD.pair_sent
                BEGIN SELECT RAISE(ABORT, 'a session keeps its identity; a slot change is a delete and an insert'); END""",
        """CREATE TRIGGER olm_prekey_gen_fixed BEFORE UPDATE ON olm_prekey_gen
                WHEN NEW.gen_id IS NOT OLD.gen_id OR NEW.fallback_pub IS NOT OLD.fallback_pub
                  OR NEW.secrets_env IS NOT OLD.secrets_env OR NEW.bundle_week IS NOT OLD.bundle_week
                  OR (OLD.superseded_day IS NOT NULL AND NEW.superseded_day IS NOT OLD.superseded_day)
                  OR (OLD.delete_after_day IS NOT NULL AND NEW.delete_after_day IS NOT OLD.delete_after_day)
                BEGIN SELECT RAISE(ABORT, 'a generation is immutable and is superseded once'); END""",
        """CREATE TRIGGER olm_prekey_used_append_only BEFORE UPDATE ON olm_prekey_used
                BEGIN SELECT RAISE(ABORT, 'the first-flight reuse set is append-only'); END""",
        """CREATE TRIGGER dm_peer_pq_limit BEFORE INSERT ON dm_peer_pq
                WHEN (SELECT count(*) FROM dm_peer_pq WHERE contact_id = NEW.contact_id) >= 3
                BEGIN SELECT RAISE(ABORT, 'at most 3 peer X-Wing keys per contact'); END""",
        // REPLACE guards (§19.21 point 4): SQLite runs no DELETE trigger for a row that REPLACE
        // conflict resolution deletes, so every table with write-once, frozen or state rules
        // refuses an insert that conflicts on any of its keys. `dm_seen` is inserted with
        // INSERT OR IGNORE, which deletes nothing, and `dm_pair_key` is written with
        // UPDATE-then-INSERT pairs, so neither needs one.
        replaceGuard("dm_self", "id = NEW.id"),
        replaceGuard("dm_own_namespace", "namespace_id = NEW.namespace_id OR (role = NEW.role AND card_index = NEW.card_index)"),
        replaceGuard("dm_contact", "contact_id = NEW.contact_id OR identity_pk = NEW.identity_pk"),
        replaceGuard("dm_conversation", "conversation_id = NEW.conversation_id OR contact_id = NEW.contact_id"),
        replaceGuard("dm_message", "message_id = NEW.message_id"),
        replaceGuard("dm_outbound_item", "item_id = NEW.item_id"),
        replaceGuard("dm_outbound_op", "operation_id = NEW.operation_id"),
        replaceGuard("dm_pending_send", "item_id = NEW.item_id"),
        replaceGuard("dm_bundle_candidate", "contact_id = NEW.contact_id"),
        replaceGuard("dm_orphan_namespace", "namespace_id = NEW.namespace_id"),
        replaceGuard("dm_scheduled", "sched_id = NEW.sched_id OR (contact_id = NEW.contact_id AND what = NEW.what)"),
        replaceGuard("dm_held", "held_id = NEW.held_id"),
        replaceGuard("dm_reaction", "target_id = NEW.target_id AND from_self = NEW.from_self"),
        replaceGuard("dm_pair_offer", "contact_id = NEW.contact_id AND root_gen = NEW.root_gen"),
        replaceGuard("olm_session", "(contact_id = NEW.contact_id AND slot = NEW.slot) OR (contact_id = NEW.contact_id AND session_id = NEW.session_id)"),
        // `idx_olm_prekey_gen_current` is a **partial unique index on an expression**: a REPLACE
        // that conflicts only on it would delete the live generation and cascade away its
        // `olm_prekey_used` reuse tuples, which is exactly the D2b state a replayed first flight
        // needs to create a second session (§7.6). The guard therefore refuses a second live
        // generation as well as a repeated id or fallback key.
        replaceGuard(
            "olm_prekey_gen",
            "gen_id = NEW.gen_id OR fallback_pub = NEW.fallback_pub " +
                "OR (NEW.superseded_day IS NULL AND superseded_day IS NULL)",
        ),
        replaceGuard("olm_prekey_used", "gen_id = NEW.gen_id AND session_id = NEW.session_id"),
        replaceGuard("dm_peer_pq", "contact_id = NEW.contact_id AND gen_id = NEW.gen_id"),
    )

    private fun replaceGuard(table: String, conflict: String): String =
        """CREATE TRIGGER ${table}_no_replace BEFORE INSERT ON $table
                WHEN EXISTS (SELECT 1 FROM $table WHERE $conflict)
                BEGIN SELECT RAISE(ABORT, '$table rows are never replaced'); END"""

    /**
     * A [replaceGuard] for a table that has a hidden rowid: it conflicts on the rowid too, because an insert
     * that names an existing rowid would make REPLACE delete that other row, whatever its keys (the
     * `outbox_op` guard of migration 3 does the same).
     *
     * **An insert that names no rowid has none to compare, and SQLite gives it -1** (`NEW.rowid` in a BEFORE
     * trigger is undefined until the row is stored; in practice -1). The comparison `rowid = NEW.rowid` is
     * therefore right only while no row of the table holds a rowid of -1: one row inserted with an explicit
     * rowid of -1 made every later plain insert "conflict" with it (the review of S3: the first version of this
     * comment said the rowid "matches no row", which holds only until such a row exists). So the table keeps
     * the invariant instead of the guard guessing: [rowidPositive] refuses a row stored with a rowid below 1 and
     * [rowidFixed] a change of the rowid of a row that is there — which is also what an arrival order needs,
     * since `UPDATE t SET rowid = …` would reorder it. The DAOs never name a rowid.
     */
    private fun rowidGuard(table: String, conflict: String): String =
        replaceGuard(table, "($conflict) OR rowid = NEW.rowid")

    /** The AFTER INSERT half of the invariant of [rowidGuard]: a row with a rowid below 1 is never stored. */
    private fun rowidPositive(table: String): String =
        """CREATE TRIGGER ${table}_rowid_positive AFTER INSERT ON $table
                WHEN NEW.rowid < 1
                BEGIN SELECT RAISE(ABORT, '$table rows have a rowid of 1 or more'); END"""

    /** The UPDATE half: a row keeps the rowid it was numbered with (`outbox_op_rowid` of migration 3 does the same). */
    private fun rowidFixed(table: String): String =
        """CREATE TRIGGER ${table}_rowid_fixed BEFORE UPDATE ON $table
                WHEN NEW.rowid IS NOT OLD.rowid
                BEGIN SELECT RAISE(ABORT, '$table rows keep their rowid'); END"""

    /**
     * Phase 10 design §9, "Migration 6 (`:sync`)" (slice S1a). One transaction, append-only,
     * fail-closed like every migration before it; the channel tables are migration 7.
     */
    private fun migration6(): List<String> = listOf(
        // (0) The rule of step 3 is about rows, not only about writes: no channel namespace may be
        // left with the send delay off, whatever wrote it (before this version only a test could
        // register a CHANNEL namespace, and the one thing a row with `off` does is store at once
        // in HIGH mode, so `default`, which follows the global mode, is the strict reading). The
        // triggers below are created after this statement, so it fires none of them.
        "UPDATE sync_namespace SET send_delay = 'default' WHERE consumer = 'channel' AND send_delay = 'off'",
        // (1) A namespace this client funds (§7.5): presence is the flag. A side table because
        // `sync_namespace.capability_source` has a CHECK that SQLite cannot alter without
        // rebuilding a table the outbox and the inbox reference. The cascade ends the flag with
        // the namespace row.
        """CREATE TABLE sync_namespace_fund (
                  namespace_id BLOB PRIMARY KEY NOT NULL CHECK (length(namespace_id) = 32)
                               REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE
                ) WITHOUT ROWID""",
        // (2) The capabilities a funder redeems for `RegisterKey` alone (§7.4, §7.5 item 2): the
        // columns of `relay_capability` (v2) without `kind`, because a pair holds at most one. Only
        // the registration step reads it; store, list, get and check never do, so a token-bought
        // capability is never presented as a writer. `expires_hour` follows the v4 and v5 rule
        // (`typeof` beside the granularity), `generation` is the rejection race guard of §3.8.
        """CREATE TABLE relay_register_capability (
                  relay_id     INTEGER NOT NULL REFERENCES relay_directory(relay_id) ON DELETE CASCADE,
                  namespace_id BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
                  token        BLOB NOT NULL CHECK (length(token) BETWEEN 1 AND 512),
                  expires_hour INTEGER CHECK (expires_hour IS NULL OR (typeof(expires_hour) = 'integer' AND expires_hour % 3600 = 0)),
                  state        TEXT NOT NULL CHECK (state IN ('usable', 'rejected', 'exhausted')),
                  generation   INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 1),
                  PRIMARY KEY (relay_id, namespace_id)
                ) WITHOUT ROWID""",
        // (3) A channel namespace keeps its send delay (§7.5 item 3), as a DM namespace does (v4):
        // without it a store would name the minute the member pressed send. Unlike the v4 update
        // trigger this one also watches `consumer`, so a row cannot reach `channel` with `off` by
        // changing the consumer instead of the delay.
        """CREATE TRIGGER sync_namespace_channel_delay_update BEFORE UPDATE OF send_delay, consumer ON sync_namespace
                WHEN NEW.consumer = 'channel' AND NEW.send_delay = 'off'
                BEGIN SELECT RAISE(ABORT, 'Channel namespaces cannot turn the send delay off'); END""",
        """CREATE TRIGGER sync_namespace_channel_delay_insert BEFORE INSERT ON sync_namespace
                WHEN NEW.consumer = 'channel' AND NEW.send_delay = 'off'
                BEGIN SELECT RAISE(ABORT, 'Channel namespaces cannot turn the send delay off'); END""",
        // (4) REPLACE guards (§19.21 point 4 of Phase 8, §9 of Phase 10). A REPLACE of a capability
        // row would write generation 1 over the generation of the token it replaces, and the
        // rejection race guard compares generations, so a stale refusal could mark the new token
        // rejected; the flag has no rule to skip, but the guard is what makes "no REPLACE in sync
        // SQL for these tables" a property of the database. Neither table is therefore ever written
        // by an upsert or a REPLACE (a guard refuses every insert of a key that exists): the
        // registration capability by an UPDATE of the row that exists, else an INSERT, and the flag,
        // which has no column to update, by an INSERT that finds no row (`WHERE NOT EXISTS`).
        replaceGuard("sync_namespace_fund", "namespace_id = NEW.namespace_id"),
        replaceGuard("relay_register_capability", "relay_id = NEW.relay_id AND namespace_id = NEW.namespace_id"),
    )

    /**
     * Phase 10 design §9, "Migration 7 (channels)", **step 0** (slice S3): the fail-closed guard and
     * the drop of the unused v1 channel tables. `ChannelPseudonymRepository` had no caller outside
     * tests and its rows need a `channels` row that nothing writes, so the four tables never had a
     * writer; the guard fails the migration, and leaves the database at v6, if one holds a row anyway.
     * `media` and `media_blobs` stay for Phase 11. Children go first, so no foreign-key cascade
     * hides a row the guard would have counted.
     */
    private fun migration7Guard(): List<String> = listOf(
        "CREATE TABLE v7_migration_guard (row_count INTEGER NOT NULL CHECK (row_count = 0))",
        "INSERT INTO v7_migration_guard(row_count) SELECT count(*) FROM channels",
        "INSERT INTO v7_migration_guard(row_count) SELECT count(*) FROM channel_pseudonyms",
        "INSERT INTO v7_migration_guard(row_count) SELECT count(*) FROM mls_state",
        "INSERT INTO v7_migration_guard(row_count) SELECT count(*) FROM posts",
        "DROP TABLE v7_migration_guard",
        "DROP INDEX idx_posts_channel",
        "DROP TABLE posts",
        "DROP TABLE mls_state",
        "DROP TABLE channel_pseudonyms",
        "DROP TABLE channels",
    )

    /**
     * Migration 7, **step 1**: the 26 tables of §9 and `mls_self`, amended by slice S4 (Phase 10 design §19.37: the
     * wrapped channel state key, §19.35 F-9; the invite state of `ch_join`, F-8; `ch_candidate.removes`, F-1;
     * `ch_channel.committers_digest`, F-S4-2; `ch_generation.open_epoch`, F-S4-7) and by slice S6 (§19.41:
     * `ch_generation.own_rotation`, the marker of a generation the member's own commit opened — its funding is the
     * rotating committer's at the switch — migration 7 had not shipped, so it is amended in place, still one
     * transaction). Conventions (v5, "following the v4/v5 split of F9
     * §13.6"): **a table is WITHOUT ROWID** (T33 and F9 §13.6 step 5: "random WITHOUT ROWID keys"; the hidden
     * rowid of a rowid table is the order its rows arrived in, and the gaps between the rowids that survive
     * count the rows that were swept — of every channel, since the rowid space is the table's), **except two**:
     * `mls_kv`, which §9 says outright is not (S0-6: its values are 0.1 to 125 KB), and `ch_join_request`,
     * whose rows the committer serves "in arrival order" (§6.2.3) and which therefore needs the order a rowid
     * is. Both are declared exceptions to T33 (§19.35, F-7 resolved), both are guarded against a REPLACE that
     * names a rowid ([rowidGuard]), and neither stores a rowid below 1 ([rowidPositive]) or changes one ([rowidFixed]);
     * an integer's `typeof` is checked beside its range, because `BETWEEN` and `%` admit `x.5`; a time column is a
     * `*_minute` (`% 60`), a `*_hour` (`% 3600`) or a `*_day` (the weekly `ch_seen.until_day` is `% 7`, as
     * `dm_seen`'s: §6.3.4 retains it "as `dm_seen`", F9 §7.6 D3 — a seizer learns the week and not the day);
     * an envelope column is `nonce(12) ‖
     * ChaCha20-Poly1305 ‖ tag(16)`, so a value of n bytes takes n + 28 (60 for a 32-byte key, 68 for
     * an epoch key, whose plaintext names its epoch). Secret-bearing columns are wrapped under the
     * channel state key, the ones that hold the user's text under the content key (§9).
     */
    private fun migration7Tables(): List<String> = listOf(
        // ---- the channel, its liveness window and its schedule
        """CREATE TABLE ch_channel (
                  channel_id          BLOB PRIMARY KEY NOT NULL CHECK (length(channel_id) = 32),
                  state               TEXT NOT NULL
                                      CHECK (state IN ('joining', 'active', 'leaving', 'left', 'removed', 'replaced',
                                                       'resync_needed', 'reinvite_needed', 'join_expired')),
                  split_suspected     INTEGER NOT NULL DEFAULT 0 CHECK (split_suspected IN (0, 1)),
                  partition_suspected INTEGER NOT NULL DEFAULT 0 CHECK (partition_suspected IN (0, 1)),
                  stale_suspected     INTEGER NOT NULL DEFAULT 0 CHECK (stale_suspected IN (0, 1)),
                  pw_required         INTEGER NOT NULL DEFAULT 0 CHECK (pw_required IN (0, 1)),
                  suite               INTEGER NOT NULL DEFAULT 3 CHECK (suite = 3),
                  generation          INTEGER NOT NULL
                                      CHECK (typeof(generation) = 'integer' AND generation BETWEEN 0 AND 4294967295),
                  epoch               INTEGER NOT NULL CHECK (typeof(epoch) = 'integer' AND epoch >= 0),
                  joined_epoch        INTEGER NOT NULL CHECK (typeof(joined_epoch) = 'integer' AND joined_epoch >= 0),
                  size_class          INTEGER NOT NULL CHECK (size_class IN (0, 1)),
                  timer_code          INTEGER NOT NULL CHECK (typeof(timer_code) = 'integer' AND timer_code BETWEEN 0 AND 5),
                  my_pseudonym        BLOB NOT NULL CHECK (length(my_pseudonym) = 32),
                  name_env            BLOB CHECK (name_env IS NULL OR length(name_env) BETWEEN 29 AND 76),
                  last_committer_commit_day INTEGER CHECK (last_committer_commit_day IS NULL
                                      OR (typeof(last_committer_commit_day) = 'integer' AND last_committer_commit_day >= 0)),
                  committers_digest   BLOB CHECK (committers_digest IS NULL OR length(committers_digest) = 32)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_liveness (
                  channel_id              BLOB PRIMARY KEY NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  unopenable_count        INTEGER NOT NULL DEFAULT 0
                                          CHECK (typeof(unopenable_count) = 'integer' AND unopenable_count BETWEEN 0 AND 255),
                  unopenable_operators    INTEGER NOT NULL DEFAULT 0
                                          CHECK (typeof(unopenable_operators) = 'integer' AND unopenable_operators BETWEEN 0 AND 255),
                  sessions                INTEGER NOT NULL DEFAULT 0
                                          CHECK (typeof(sessions) = 'integer' AND sessions BETWEEN 0 AND 255),
                  progress_env            BLOB NOT NULL CHECK (length(progress_env) BETWEEN 28 AND 256),
                  unopenable_first_minute INTEGER CHECK (unopenable_first_minute IS NULL
                                          OR (typeof(unopenable_first_minute) = 'integer' AND unopenable_first_minute % 60 = 0)),
                  CHECK ((unopenable_count = 0) = (unopenable_first_minute IS NULL))
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_schedule (
                  channel_id          BLOB PRIMARY KEY NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  next_selfupdate_day INTEGER NOT NULL
                                      CHECK (typeof(next_selfupdate_day) = 'integer' AND next_selfupdate_day >= 0),
                  last_own_commit_day INTEGER CHECK (last_own_commit_day IS NULL
                                      OR (typeof(last_own_commit_day) = 'integer' AND last_own_commit_day >= 0)),
                  next_pass_minute    INTEGER CHECK (next_pass_minute IS NULL
                                      OR (typeof(next_pass_minute) = 'integer' AND next_pass_minute % 60 = 0))
                ) WITHOUT ROWID""",
        // ---- generations, epochs and the commit candidates (§6.4, §6.5)
        """CREATE TABLE ch_generation (
                  channel_id      BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  generation      INTEGER NOT NULL
                                  CHECK (typeof(generation) = 'integer' AND generation BETWEEN 0 AND 4294967295),
                  namespace_id    BLOB NOT NULL UNIQUE CHECK (length(namespace_id) = 32),
                  state           TEXT NOT NULL CHECK (state IN ('pending_switch', 'current', 'draining')),
                  g_env           BLOB NOT NULL CHECK (length(g_env) = 60),
                  jk_env          BLOB NOT NULL CHECK (length(jk_env) = 60),
                  r_join          BLOB NOT NULL CHECK (length(r_join) = 32),
                  open_epoch      INTEGER NOT NULL CHECK (typeof(open_epoch) = 'integer' AND open_epoch >= 0),
                  own_rotation    INTEGER NOT NULL DEFAULT 0 CHECK (own_rotation IN (0, 1)),
                  switch_hour     INTEGER CHECK (switch_hour IS NULL
                                  OR (typeof(switch_hour) = 'integer' AND switch_hour % 3600 = 0)),
                  drain_until_day INTEGER CHECK (drain_until_day IS NULL
                                  OR (typeof(drain_until_day) = 'integer' AND drain_until_day >= 0)),
                  CHECK (state = 'pending_switch' OR switch_hour IS NULL),
                  CHECK ((state = 'draining') = (drain_until_day IS NOT NULL)),
                  PRIMARY KEY (channel_id, generation)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_epoch (
                  channel_id     BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  epoch          INTEGER NOT NULL CHECK (typeof(epoch) = 'integer' AND epoch >= 0),
                  state          TEXT NOT NULL CHECK (state IN ('open', 'final')),
                  k_env          BLOB NOT NULL CHECK (length(k_env) = 68),
                  r_ep           BLOB NOT NULL CHECK (length(r_ep) = 32),
                  winner_hash    BLOB CHECK (winner_hash IS NULL OR length(winner_hash) = 32),
                  own_seq        INTEGER NOT NULL DEFAULT 0
                                 CHECK (typeof(own_seq) = 'integer' AND own_seq BETWEEN 0 AND 4294967295),
                  anchor_minute  INTEGER CHECK (anchor_minute IS NULL
                                 OR (typeof(anchor_minute) = 'integer' AND anchor_minute % 60 = 0)),
                  final_day      INTEGER CHECK (final_day IS NULL OR (typeof(final_day) = 'integer' AND final_day >= 0)),
                  keep_until_day INTEGER CHECK (keep_until_day IS NULL
                                 OR (typeof(keep_until_day) = 'integer' AND keep_until_day >= 0)),
                  CHECK ((state = 'final') = (final_day IS NOT NULL)),
                  CHECK (keep_until_day IS NULL OR final_day IS NOT NULL),
                  CHECK (state = 'open' OR own_seq = 0),
                  PRIMARY KEY (channel_id, epoch)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_epoch_log (
                  channel_id  BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  epoch       INTEGER NOT NULL CHECK (typeof(epoch) = 'integer' AND epoch >= 0),
                  winner_hash BLOB NOT NULL CHECK (length(winner_hash) = 32),
                  final_day   INTEGER NOT NULL CHECK (typeof(final_day) = 'integer' AND final_day >= 0),
                  PRIMARY KEY (channel_id, epoch)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_candidate (
                  channel_id        BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  epoch             INTEGER NOT NULL CHECK (typeof(epoch) = 'integer' AND epoch >= 0),
                  hash              BLOB NOT NULL CHECK (length(hash) = 32),
                  sender            BLOB NOT NULL CHECK (length(sender) = 32),
                  rank              INTEGER NOT NULL CHECK (typeof(rank) = 'integer' AND rank BETWEEN 0 AND 255),
                  own               INTEGER NOT NULL CHECK (own IN (0, 1)),
                  verified          INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0, 1)),
                  body_env          BLOB NOT NULL CHECK (length(body_env) BETWEEN 29 AND 16777216),
                  welcome_env       BLOB CHECK (welcome_env IS NULL OR length(welcome_env) BETWEEN 29 AND 67108864),
                  box_env           BLOB CHECK (box_env IS NULL OR length(box_env) = 60),
                  first_seen_minute INTEGER NOT NULL
                                    CHECK (typeof(first_seen_minute) = 'integer' AND first_seen_minute % 60 = 0),
                  store_hour        INTEGER CHECK (store_hour IS NULL
                                    OR (typeof(store_hour) = 'integer' AND store_hour % 3600 = 0)),
                  removes           INTEGER NOT NULL DEFAULT 0 CHECK (removes IN (0, 1)),
                  CHECK (own = 1 OR (welcome_env IS NULL AND box_env IS NULL)),
                  CHECK (own = 1 OR verified = 0),
                  PRIMARY KEY (channel_id, epoch, hash),
                  UNIQUE (channel_id, epoch, sender)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_fork_signal (
                  channel_id     BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  epoch          INTEGER NOT NULL CHECK (typeof(epoch) = 'integer' AND epoch >= 0),
                  hash           BLOB NOT NULL CHECK (length(hash) = 32),
                  first_seen_day INTEGER NOT NULL CHECK (typeof(first_seen_day) = 'integer' AND first_seen_day >= 0),
                  PRIMARY KEY (channel_id, epoch, hash)
                ) WITHOUT ROWID""",
        // ---- the OpenMLS rows (GhostKv, §3.4). `mls_kv` is an ordinary rowid table (S0-6: its values are
        // 0.1 to 125 KB, which SQLite's advice for WITHOUT ROWID rules out); `mls_global_kv` holds KeyPackage and
        // key-pair rows of a few hundred bytes and is WITHOUT ROWID like the rest.
        """CREATE TABLE mls_kv (
                  channel_id BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  k          BLOB NOT NULL CHECK (length(k) BETWEEN 2 AND 1024),
                  v_env      BLOB NOT NULL CHECK (length(v_env) BETWEEN 28 AND 4194304),
                  PRIMARY KEY (channel_id, k)
                )""",
        """CREATE TABLE mls_global_kv (
                  k                BLOB PRIMARY KEY NOT NULL CHECK (length(k) BETWEEN 2 AND 1024),
                  v_env            BLOB NOT NULL CHECK (length(v_env) BETWEEN 28 AND 4194304),
                  channel_id       BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  delete_after_day INTEGER CHECK (delete_after_day IS NULL
                                   OR (typeof(delete_after_day) = 'integer' AND delete_after_day >= 0))
                ) WITHOUT ROWID""",
        "CREATE INDEX idx_mls_global_kv_channel ON mls_global_kv(channel_id)",
        // The channel state key (§10.4 "State key", amended by slice S4, §19.37, §19.35 F-9): 32 random bytes created at
        // the first channel use, stored wrapped by a non-exportable Keystore key with the database key's authentication
        // policy — the F9 §2.5 `session_state_key` pattern, one row as `dm_self` holds the DM's — and unwrapped only into
        // the native channel context. One key for all channels; a wipe deletes it with the database.
        """CREATE TABLE mls_self (
                  id                INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
                  state_key_wrapped BLOB NOT NULL CHECK (length(state_key_wrapped) BETWEEN 40 AND 256)
                ) WITHOUT ROWID""",
        // ---- posts and what hangs on them (§8.2, §8.5)
        // `relay_expiry_hour` (E) is a deadline of an *unread* post only (§8.2: "an unread post is deleted at
        // min(E, consume + bucket + 1 h)") and a display forgets it: the CHECK ties it to `state = 'unread'`, and
        // `ch_post_expiry` lets it go only together with the state. It is a second deadline beside
        // `delete_at_minute` and is **not folded into it**, because in a channel whose timer is off a read post
        // has no deadline while an unread one still dies at E; every read, the sweep and the next-deletion query
        // of `PostStore` apply both (the first version applied `delete_at_minute` alone: review of S3).
        // `displayed_minute` is kept only while a countdown needs it, a read post of a channel with a timer: with
        // the timer off F9's `dm_message` stores no time at all (T33), and a read minute that lives as long as the
        // post would be the one record of when the user opened it.
        """CREATE TABLE ch_post (
                  op_id             BLOB PRIMARY KEY NOT NULL CHECK (length(op_id) = 16),
                  channel_id        BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  direction         TEXT NOT NULL CHECK (direction IN ('out', 'in')),
                  author            BLOB NOT NULL CHECK (length(author) = 32),
                  kind              INTEGER NOT NULL CHECK (kind IN (1, 2)),
                  reply_to          BLOB CHECK (reply_to IS NULL OR length(reply_to) = 16),
                  timer_code        INTEGER NOT NULL CHECK (typeof(timer_code) = 'integer' AND timer_code BETWEEN 0 AND 5),
                  epoch             INTEGER NOT NULL CHECK (typeof(epoch) = 'integer' AND epoch >= 0),
                  body_env          BLOB NOT NULL CHECK (length(body_env) BETWEEN 29 AND 65564),
                  state             TEXT NOT NULL
                                    CHECK (state IN ('queued', 'sent', 'degraded', 'failed', 'indeterminate', 'unread', 'read')),
                  author_minute     INTEGER NOT NULL CHECK (typeof(author_minute) = 'integer' AND author_minute % 60 = 0),
                  displayed_minute  INTEGER CHECK (displayed_minute IS NULL
                                    OR (typeof(displayed_minute) = 'integer' AND displayed_minute % 60 = 0)),
                  delete_at_minute  INTEGER CHECK (delete_at_minute IS NULL
                                    OR (typeof(delete_at_minute) = 'integer' AND delete_at_minute % 60 = 0)),
                  relay_expiry_hour INTEGER CHECK (relay_expiry_hour IS NULL
                                    OR (typeof(relay_expiry_hour) = 'integer' AND relay_expiry_hour % 3600 = 0)),
                  CHECK ((direction = 'out') = (state IN ('queued', 'sent', 'degraded', 'failed', 'indeterminate'))),
                  CHECK (relay_expiry_hour IS NULL OR state = 'unread'),
                  CHECK (displayed_minute IS NULL OR (state = 'read' AND timer_code <> 0))
                ) WITHOUT ROWID""",
        "CREATE INDEX idx_ch_post_order ON ch_post(channel_id, author_minute, author, op_id)",
        "CREATE INDEX idx_ch_post_delete ON ch_post(delete_at_minute) WHERE delete_at_minute IS NOT NULL",
        "CREATE INDEX idx_ch_post_expiry ON ch_post(relay_expiry_hour) WHERE relay_expiry_hour IS NOT NULL",
        """CREATE TABLE ch_reaction (
                  target       BLOB NOT NULL REFERENCES ch_post(op_id) ON DELETE CASCADE,
                  author       BLOB NOT NULL CHECK (length(author) = 32),
                  channel_id   BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  grapheme_env BLOB NOT NULL CHECK (length(grapheme_env) BETWEEN 29 AND 60),
                  PRIMARY KEY (target, author)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_pending_post (
                  op_id           BLOB PRIMARY KEY NOT NULL CHECK (length(op_id) = 16),
                  channel_id      BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  kind            INTEGER NOT NULL CHECK (typeof(kind) = 'integer' AND kind BETWEEN 1 AND 7),
                  content_env     BLOB NOT NULL CHECK (length(content_env) BETWEEN 29 AND 65564),
                  fail_after_hour INTEGER NOT NULL
                                  CHECK (typeof(fail_after_hour) = 'integer' AND fail_after_hour % 3600 = 0)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_outbound_op (
                  operation_id BLOB PRIMARY KEY NOT NULL CHECK (length(operation_id) = 16),
                  channel_id   BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  purpose      TEXT NOT NULL CHECK (purpose IN ('post', 'commit', 'welcome', 'join', 'rejoin', 'request')),
                  ref          BLOB CHECK (ref IS NULL OR length(ref) BETWEEN 1 AND 64)
                ) WITHOUT ROWID""",
        // `until_day` is a week, `ceil7(…)`, as `dm_seen`'s (F9 §7.6 D3; §6.3.4 retains the tag "as `dm_seen`"): a
        // seizer learns the week a post was displayed in and not the day (L7-D7).
        """CREATE TABLE ch_seen (
                  channel_id BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  tag        BLOB NOT NULL CHECK (length(tag) = 16),
                  until_day  INTEGER NOT NULL CHECK (typeof(until_day) = 'integer' AND until_day >= 0 AND until_day % 7 = 0),
                  PRIMARY KEY (channel_id, tag)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_reveal (
                  channel_id       BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  direction        TEXT NOT NULL CHECK (direction IN ('out', 'in')),
                  peer             BLOB NOT NULL CHECK (length(peer) = 32),
                  delete_at_minute INTEGER CHECK (delete_at_minute IS NULL
                                   OR (typeof(delete_at_minute) = 'integer' AND delete_at_minute % 60 = 0)),
                  PRIMARY KEY (channel_id, direction, peer)
                ) WITHOUT ROWID""",
        // ---- joins, invites and the committer's work (§6.2)
        // `ns`, `jk_env`, `r_join` and `committers_digest` are the invitee's join state (amended by slice S4, §19.37,
        // §19.35 F-8): what an invite carries and nothing else keeps, because a password invite's link is never
        // stored (Q50 (a)) and an invite never carries `G_g` (§5.2 rule 3), so no `ch_generation` row can hold it.
        // The namespace routes the blobs fetched from it, `JK_g` (an invite's class-6 envelope) opens the Welcome,
        // `R_join` recognises it, and the digest is the committers anchor (§6.2.5). A rejoin has no invite and none
        // of the four: it listens to its own generations (§6.7).
        """CREATE TABLE ch_join (
                  channel_id BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  kp_ref     BLOB NOT NULL CHECK (length(kp_ref) = 32),
                  type       TEXT NOT NULL CHECK (type IN ('join', 'rejoin', 'restore')),
                  invite_id  BLOB CHECK (invite_id IS NULL OR length(invite_id) = 16),
                  generation INTEGER NOT NULL
                             CHECK (typeof(generation) = 'integer' AND generation BETWEEN 0 AND 4294967295),
                  expiry_day INTEGER NOT NULL CHECK (typeof(expiry_day) = 'integer' AND expiry_day >= 0),
                  ns         BLOB UNIQUE CHECK (ns IS NULL OR length(ns) = 32),
                  jk_env     BLOB CHECK (jk_env IS NULL OR length(jk_env) = 60),
                  r_join     BLOB CHECK (r_join IS NULL OR length(r_join) = 32),
                  committers_digest BLOB CHECK (committers_digest IS NULL OR length(committers_digest) = 32),
                  -- `CH-REJOIN`'s absolute give-up day (first attempt day + 14, §6.7): `expiry_day`
                  -- is the next re-send (attempt day + 7); past the deadline an unanswered rejoin
                  -- ends at `reinvite_needed`. Rejoin rows only (slice S7).
                  rejoin_deadline_day INTEGER CHECK (rejoin_deadline_day IS NULL
                                      OR (typeof(rejoin_deadline_day) = 'integer' AND rejoin_deadline_day >= 0)),
                  CHECK ((type = 'rejoin') = (invite_id IS NULL)),
                  CHECK ((type = 'rejoin') = (rejoin_deadline_day IS NOT NULL)),
                  CHECK ((type = 'rejoin') = (ns IS NULL)),
                  CHECK ((ns IS NULL) = (jk_env IS NULL) AND (ns IS NULL) = (r_join IS NULL)
                         AND (ns IS NULL) = (committers_digest IS NULL)),
                  PRIMARY KEY (channel_id, kp_ref)
                ) WITHOUT ROWID""",
        // The second rowid table (beside `mls_kv`): the committer serves its requests "in arrival order" (§6.2.3) and
        // the hidden rowid is that order — a new row is numbered after every row that is still there. A declared
        // exception to T33 (§19.35, F-7): committer side only, at most 64 rows per channel, each deleted at its
        // invite's expiry or 7 days after its day.
        """CREATE TABLE ch_join_request (
                  channel_id   BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  hash         BLOB NOT NULL CHECK (length(hash) = 32),
                  generation   INTEGER NOT NULL
                               CHECK (typeof(generation) = 'integer' AND generation BETWEEN 0 AND 4294967295),
                  type         TEXT NOT NULL CHECK (type IN ('join', 'rejoin', 'restore')),
                  invite_id    BLOB CHECK (invite_id IS NULL OR length(invite_id) = 16),
                  body_env     BLOB NOT NULL CHECK (length(body_env) BETWEEN 29 AND 4096),
                  -- The requester's pseudonym, set at recording for every type (slice S7): a rejoin
                  -- names no invite, so the admission pass reads it from here (and the live-leaf
                  -- check of §6.7 needs it before any native re-verification).
                  member       BLOB CHECK (member IS NULL OR length(member) = 32),
                  until_day    INTEGER NOT NULL CHECK (typeof(until_day) = 'integer' AND until_day >= 0),
                  -- The day the request was first recorded (§19.35 F-11 (a), amended by slice S5): CO-8's work-age
                  -- rule (§19.13 item 4) measures the age of the work from it; `until_day` is the expiry, not the age.
                  recorded_day INTEGER NOT NULL CHECK (typeof(recorded_day) = 'integer' AND recorded_day >= 0),
                  CHECK ((type = 'rejoin') = (invite_id IS NULL)),
                  PRIMARY KEY (channel_id, hash)
                )""",
        """CREATE TABLE ch_invite_issued (
                  channel_id        BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  invite_id         BLOB NOT NULL CHECK (length(invite_id) = 16),
                  invite_pk         BLOB NOT NULL CHECK (length(invite_pk) = 32),
                  sponsor           BLOB NOT NULL CHECK (length(sponsor) = 32),
                  sponsor_sig       BLOB NOT NULL CHECK (length(sponsor_sig) = 64),
                  committers_digest BLOB NOT NULL CHECK (length(committers_digest) = 32),
                  pw_version        INTEGER CHECK (pw_version IS NULL
                                    OR (typeof(pw_version) = 'integer' AND pw_version BETWEEN 1 AND 65535)),
                  consumed          INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1)),
                  void              INTEGER NOT NULL DEFAULT 0 CHECK (void IN (0, 1)),
                  expiry_day        INTEGER NOT NULL CHECK (typeof(expiry_day) = 'integer' AND expiry_day >= 0),
                  PRIMARY KEY (channel_id, invite_id)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_kp_seen (
                  channel_id BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  tag        BLOB NOT NULL CHECK (length(tag) = 16),
                  until_day  INTEGER NOT NULL CHECK (typeof(until_day) = 'integer' AND until_day >= 0),
                  PRIMARY KEY (channel_id, tag)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_member_seen (
                  channel_id BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  member     BLOB NOT NULL CHECK (length(member) = 32),
                  last_epoch INTEGER NOT NULL CHECK (typeof(last_epoch) = 'integer' AND last_epoch >= 0),
                  PRIMARY KEY (channel_id, member)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_invite_own (
                  invite_id  BLOB PRIMARY KEY NOT NULL CHECK (length(invite_id) = 16),
                  channel_id BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  invite_env BLOB CHECK (invite_env IS NULL OR length(invite_env) BETWEEN 29 AND 1024),
                  expiry_day INTEGER NOT NULL CHECK (typeof(expiry_day) = 'integer' AND expiry_day >= 0)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_sponsor (
                  channel_id   BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  member       BLOB NOT NULL CHECK (length(member) = 32),
                  sponsor      BLOB NOT NULL CHECK (length(sponsor) = 32),
                  invite_id    BLOB NOT NULL CHECK (length(invite_id) = 16),
                  admitted_day INTEGER NOT NULL CHECK (typeof(admitted_day) = 'integer' AND admitted_day >= 0),
                  PRIMARY KEY (channel_id, member)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_member_refresh (
                  channel_id  BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  member      BLOB NOT NULL CHECK (length(member) = 32),
                  refresh_day INTEGER NOT NULL CHECK (typeof(refresh_day) = 'integer' AND refresh_day >= 0),
                  PRIMARY KEY (channel_id, member)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_request (
                  channel_id   BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  kind         TEXT NOT NULL CHECK (kind IN ('leave', 'remove', 'policy', 'class')),
                  subject      BLOB NOT NULL CHECK (length(subject) BETWEEN 1 AND 32),
                  payload_env  BLOB CHECK (payload_env IS NULL OR length(payload_env) BETWEEN 29 AND 4096),
                  until_day    INTEGER NOT NULL CHECK (typeof(until_day) = 'integer' AND until_day >= 0),
                  -- The day the work was first recorded (§19.35 F-11 (a), amended by slice S5): CO-8's work-age rule
                  -- (§19.13 item 4) measures from it; `until_day` is the expiry, not the age. A row is recorded once
                  -- (the store keeps the first), so the day is the first recording's.
                  recorded_day INTEGER NOT NULL CHECK (typeof(recorded_day) = 'integer' AND recorded_day >= 0),
                  PRIMARY KEY (channel_id, kind, subject)
                ) WITHOUT ROWID""",
        """CREATE TABLE ch_box_key (
                  channel_id BLOB NOT NULL REFERENCES ch_channel(channel_id) ON DELETE CASCADE,
                  box_pk     BLOB NOT NULL CHECK (length(box_pk) = 32),
                  sk_env     BLOB NOT NULL CHECK (length(sk_env) = 60),
                  last_epoch INTEGER CHECK (last_epoch IS NULL OR (typeof(last_epoch) = 'integer' AND last_epoch >= 0)),
                  PRIMARY KEY (channel_id, box_pk)
                ) WITHOUT ROWID""",
    )

    /**
     * Migration 7, **step 2**: the state-machine, write-once, bound and REPLACE-guard triggers.
     * Comparisons are NULL-safe (`IS NOT`, R-T6): a `WHEN` that evaluates to NULL does not fire, which
     * would let a write-once column go from a value to NULL unnoticed.
     *
     * The bounds are those of §6.3.5 (CS-C8) and §9: the engine keeps its tables under them by
     * deleting the oldest or the worst row first, and the trigger is the backstop that turns an
     * engine defect into an abort instead of a table that grows. Every state machine is §6.11's.
     */
    private fun migration7Triggers(): List<String> = listOf(
        // ---- the channel (§6.11: Channel, member view). Entering `joining` again is how a new
        // invitation reaches a channel the client left, was removed from or let expire (§6.2.2); the
        // restore of a channel in `resync_needed`, `reinvite_needed` or `replaced` leaves the row in its
        // state until the Welcome makes it `active`.
        """CREATE TRIGGER ch_channel_identity BEFORE UPDATE ON ch_channel
                WHEN NEW.channel_id IS NOT OLD.channel_id OR NEW.suite IS NOT OLD.suite
                  OR NEW.my_pseudonym IS NOT OLD.my_pseudonym
                BEGIN SELECT RAISE(ABORT, 'a channel keeps its id, its suite and its pseudonym'); END""",
        """CREATE TRIGGER ch_channel_state BEFORE UPDATE OF state ON ch_channel
                WHEN NOT ((OLD.state = NEW.state)
                       OR (OLD.state = 'joining' AND NEW.state IN ('active', 'join_expired'))
                       OR (OLD.state = 'active' AND NEW.state IN ('leaving', 'removed', 'replaced', 'resync_needed', 'reinvite_needed'))
                       OR (OLD.state = 'leaving' AND NEW.state IN ('left', 'removed'))
                       OR (OLD.state = 'resync_needed' AND NEW.state IN ('active', 'reinvite_needed', 'joining'))
                       OR (OLD.state IN ('reinvite_needed', 'replaced') AND NEW.state = 'active')
                       OR (OLD.state IN ('resync_needed', 'reinvite_needed', 'left', 'removed', 'replaced', 'join_expired') AND NEW.state = 'joining'))
                BEGIN SELECT RAISE(ABORT, 'illegal channel state transition'); END""",
        // ---- generations (§6.5, §6.11): pending_switch -> current -> draining, one of each kind at a time
        """CREATE TRIGGER ch_generation_identity BEFORE UPDATE ON ch_generation
                WHEN NEW.channel_id IS NOT OLD.channel_id OR NEW.generation IS NOT OLD.generation
                  OR NEW.namespace_id IS NOT OLD.namespace_id OR NEW.g_env IS NOT OLD.g_env
                  OR NEW.jk_env IS NOT OLD.jk_env OR NEW.r_join IS NOT OLD.r_join
                  OR NEW.open_epoch IS NOT OLD.open_epoch OR NEW.own_rotation IS NOT OLD.own_rotation
                BEGIN SELECT RAISE(ABORT, 'a generation keeps its namespace and its secrets'); END""",
        """CREATE TRIGGER ch_generation_state BEFORE UPDATE OF state ON ch_generation
                WHEN NOT ((OLD.state = NEW.state)
                       OR (OLD.state = 'pending_switch' AND NEW.state = 'current')
                       OR (OLD.state = 'current' AND NEW.state = 'draining'))
                BEGIN SELECT RAISE(ABORT, 'illegal generation transition'); END""",
        // The end of a drain only moves earlier and is never forgotten while the generation drains: a later one would
        // keep `G_g` and `JK_g` (what opens the generation's join traffic) past the day the design deletes them
        // (§6.5, T25, T38). A row that leaves `draining` is the state machine's to refuse (it has no such edge).
        """CREATE TRIGGER ch_generation_drain BEFORE UPDATE OF drain_until_day ON ch_generation
                WHEN OLD.drain_until_day IS NOT NULL AND NEW.state IS OLD.state
                  AND (NEW.drain_until_day IS NULL OR NEW.drain_until_day > OLD.drain_until_day)
                BEGIN SELECT RAISE(ABORT, 'the end of a drain only moves earlier'); END""",
        """CREATE TRIGGER ch_generation_one_current_insert BEFORE INSERT ON ch_generation
                WHEN NEW.state = 'current'
                  AND EXISTS (SELECT 1 FROM ch_generation WHERE channel_id = NEW.channel_id AND state = 'current')
                BEGIN SELECT RAISE(ABORT, 'at most one current generation per channel'); END""",
        """CREATE TRIGGER ch_generation_one_current_update BEFORE UPDATE OF state ON ch_generation
                WHEN NEW.state = 'current' AND OLD.state <> 'current'
                  AND EXISTS (SELECT 1 FROM ch_generation WHERE channel_id = NEW.channel_id AND state = 'current')
                BEGIN SELECT RAISE(ABORT, 'at most one current generation per channel'); END""",
        """CREATE TRIGGER ch_generation_one_draining_insert BEFORE INSERT ON ch_generation
                WHEN NEW.state = 'draining'
                  AND EXISTS (SELECT 1 FROM ch_generation WHERE channel_id = NEW.channel_id AND state = 'draining')
                BEGIN SELECT RAISE(ABORT, 'at most one draining generation per channel'); END""",
        """CREATE TRIGGER ch_generation_one_draining_update BEFORE UPDATE OF state ON ch_generation
                WHEN NEW.state = 'draining' AND OLD.state <> 'draining'
                  AND EXISTS (SELECT 1 FROM ch_generation WHERE channel_id = NEW.channel_id AND state = 'draining')
                BEGIN SELECT RAISE(ABORT, 'at most one draining generation per channel'); END""",
        // ---- epochs (§6.11: open -> final, sticky; §19.21: the anchor is cleared at finality; §9: 17 rows)
        """CREATE TRIGGER ch_epoch_limit BEFORE INSERT ON ch_epoch
                WHEN (SELECT count(*) FROM ch_epoch WHERE channel_id = NEW.channel_id) >= 17
                BEGIN SELECT RAISE(ABORT, 'at most 17 epochs per channel: the current one and 16 past'); END""",
        """CREATE TRIGGER ch_epoch_anchor_insert BEFORE INSERT ON ch_epoch
                WHEN NEW.state = 'final' AND NEW.anchor_minute IS NOT NULL
                BEGIN SELECT RAISE(ABORT, 'the anchor of a final epoch is cleared'); END""",
        """CREATE TRIGGER ch_epoch_anchor_update BEFORE UPDATE ON ch_epoch
                WHEN NEW.state = 'final' AND NEW.anchor_minute IS NOT NULL
                BEGIN SELECT RAISE(ABORT, 'the anchor of a final epoch is cleared'); END""",
        """CREATE TRIGGER ch_epoch_identity BEFORE UPDATE ON ch_epoch
                WHEN NEW.channel_id IS NOT OLD.channel_id OR NEW.epoch IS NOT OLD.epoch
                  OR NEW.k_env IS NOT OLD.k_env OR NEW.r_ep IS NOT OLD.r_ep
                  OR (OLD.winner_hash IS NOT NULL AND NEW.winner_hash IS NOT OLD.winner_hash)
                  OR (NEW.own_seq < OLD.own_seq AND NOT (OLD.state = 'open' AND NEW.state = 'final' AND NEW.own_seq = 0))
                BEGIN SELECT RAISE(ABORT, 'an epoch keeps its keys and its winner, and its sequence never goes back (but to 0 at finality)'); END""",
        """CREATE TRIGGER ch_epoch_final BEFORE UPDATE ON ch_epoch
                WHEN OLD.state = 'final'
                  AND (NEW.state IS NOT 'final' OR NEW.winner_hash IS NOT OLD.winner_hash OR NEW.own_seq IS NOT OLD.own_seq
                       OR NEW.final_day IS NOT OLD.final_day
                       OR (OLD.keep_until_day IS NOT NULL
                           AND (NEW.keep_until_day IS NULL OR NEW.keep_until_day > OLD.keep_until_day)))
                BEGIN SELECT RAISE(ABORT, 'a final epoch is sticky; only its retention moves, and only earlier'); END""",
        """CREATE TRIGGER ch_epoch_log_limit BEFORE INSERT ON ch_epoch_log
                WHEN (SELECT count(*) FROM ch_epoch_log WHERE channel_id = NEW.channel_id) >= 1024
                BEGIN SELECT RAISE(ABORT, 'at most 1024 epoch log rows per channel'); END""",
        """CREATE TRIGGER ch_epoch_log_append_only BEFORE UPDATE ON ch_epoch_log
                BEGIN SELECT RAISE(ABORT, 'the epoch log is append-only'); END""",
        // ---- commit candidates (§6.3.5: at most 8 per epoch and one per sender, plus the own commit)
        """CREATE TRIGGER ch_candidate_limit BEFORE INSERT ON ch_candidate
                WHEN (NEW.own = 0 AND (SELECT count(*) FROM ch_candidate
                                       WHERE channel_id = NEW.channel_id AND epoch = NEW.epoch AND own = 0) >= 8)
                  OR (NEW.own = 1 AND EXISTS (SELECT 1 FROM ch_candidate
                                              WHERE channel_id = NEW.channel_id AND epoch = NEW.epoch AND own = 1))
                BEGIN SELECT RAISE(ABORT, 'at most 8 foreign candidates and one own commit per epoch'); END""",
        """CREATE TRIGGER ch_candidate_identity BEFORE UPDATE ON ch_candidate
                WHEN NEW.channel_id IS NOT OLD.channel_id OR NEW.epoch IS NOT OLD.epoch OR NEW.hash IS NOT OLD.hash
                  OR NEW.sender IS NOT OLD.sender OR NEW.rank IS NOT OLD.rank OR NEW.own IS NOT OLD.own
                  OR NEW.removes IS NOT OLD.removes
                  OR NEW.body_env IS NOT OLD.body_env
                  OR NEW.first_seen_minute > OLD.first_seen_minute
                  OR NEW.verified < OLD.verified
                  OR (OLD.welcome_env IS NULL AND NEW.welcome_env IS NOT NULL)
                  OR (OLD.welcome_env IS NOT NULL AND NEW.welcome_env IS NOT NULL AND NEW.welcome_env IS NOT OLD.welcome_env)
                  OR (OLD.box_env IS NULL AND NEW.box_env IS NOT NULL)
                  OR (OLD.box_env IS NOT NULL AND NEW.box_env IS NOT NULL AND NEW.box_env IS NOT OLD.box_env)
                  OR (OLD.store_hour IS NOT NULL AND (NEW.store_hour IS NULL OR NEW.store_hour > OLD.store_hour))
                BEGIN SELECT RAISE(ABORT, 'a candidate changes only by a verified copy, an earlier sighting or store hour and the erasure of its Welcomes'); END""",
        """CREATE TRIGGER ch_fork_signal_limit BEFORE INSERT ON ch_fork_signal
                WHEN (SELECT count(*) FROM ch_fork_signal WHERE channel_id = NEW.channel_id) >= 16
                BEGIN SELECT RAISE(ABORT, 'at most 16 fork signals per channel'); END""",
        """CREATE TRIGGER ch_fork_signal_append_only BEFORE UPDATE ON ch_fork_signal
                BEGIN SELECT RAISE(ABORT, 'fork signals are diagnostics and are never rewritten'); END""",
        // ---- posts (§8.2: deadlines only move earlier; the F9 dm_message triggers, for the columns ch_post has).
        // A retry (failed -> queued) re-encrypts the post under the epoch and the timer then current.
        """CREATE TRIGGER ch_post_identity BEFORE UPDATE ON ch_post
                WHEN NEW.op_id IS NOT OLD.op_id OR NEW.channel_id IS NOT OLD.channel_id
                  OR NEW.direction IS NOT OLD.direction OR NEW.author IS NOT OLD.author
                  OR NEW.kind IS NOT OLD.kind OR NEW.reply_to IS NOT OLD.reply_to OR NEW.body_env IS NOT OLD.body_env
                  OR ((NEW.timer_code IS NOT OLD.timer_code OR NEW.epoch IS NOT OLD.epoch
                       OR NEW.author_minute IS NOT OLD.author_minute)
                      AND NOT (OLD.state = 'failed' AND NEW.state = 'queued'))
                BEGIN SELECT RAISE(ABORT, 'only the state and the display and expiry columns of a post change; a retry re-encrypts it'); END""",
        """CREATE TRIGGER ch_post_state BEFORE UPDATE OF state ON ch_post
                WHEN NOT ((OLD.state = NEW.state)
                       OR (OLD.state = 'queued' AND NEW.state IN ('sent', 'degraded', 'failed', 'indeterminate'))
                       OR (OLD.state = 'failed' AND NEW.state = 'queued')
                       OR (OLD.state = 'unread' AND NEW.state = 'read'))
                BEGIN SELECT RAISE(ABORT, 'illegal post state transition'); END""",
        // The relay expiry E of an unread post is a live deadline (§8.2), so it is held like `delete_at_minute`: it only
        // moves earlier, and it is never forgotten while the post is unread — the comparison `NEW > OLD` is NULL for a
        // NULL, which the first version let through (`SET relay_expiry_hour = NULL` on an unread post, then `NULL ->
        // E + 30 d`). A display forgets it in the same statement that makes the post `read`; the CHECK of
        // `ch_post` then keeps a read post from getting one back.
        """CREATE TRIGGER ch_post_expiry
                BEFORE UPDATE OF displayed_minute, delete_at_minute, relay_expiry_hour ON ch_post
                WHEN (OLD.displayed_minute IS NOT NULL AND NEW.displayed_minute IS NOT OLD.displayed_minute)
                  OR (OLD.delete_at_minute IS NOT NULL AND (NEW.delete_at_minute IS NULL OR NEW.delete_at_minute > OLD.delete_at_minute))
                  OR (OLD.relay_expiry_hour IS NOT NULL
                      AND (NEW.relay_expiry_hour > OLD.relay_expiry_hour
                           OR (NEW.relay_expiry_hour IS NULL AND NEW.state IS NOT 'read')))
                BEGIN SELECT RAISE(ABORT, 'a post is displayed once and its deletion time only moves earlier'); END""",
        """CREATE TRIGGER ch_pending_post_limit BEFORE INSERT ON ch_pending_post
                WHEN (SELECT count(*) FROM ch_pending_post WHERE channel_id = NEW.channel_id) >= 256
                BEGIN SELECT RAISE(ABORT, 'at most 256 pending posts per channel'); END""",
        // The bounds above count at INSERT, so an UPDATE of `channel_id` would move rows into a channel that is
        // full (256 pending posts into one that holds 256 made 512: review of S3). The tables whose bound is a
        // count and whose rows nothing else keeps in place refuse the move; `ch_epoch`, `ch_candidate` and
        // `ch_box_key` do already (their identity triggers) and `ch_epoch_log` and `ch_fork_signal` refuse every
        // UPDATE. No store updates the channel of a row.
        """CREATE TRIGGER ch_pending_post_channel BEFORE UPDATE OF channel_id ON ch_pending_post
                WHEN NEW.channel_id IS NOT OLD.channel_id
                BEGIN SELECT RAISE(ABORT, 'a pending post never moves to another channel'); END""",
        // ---- joins, invites and keys (§6.2, §6.3.5, §19.17)
        """CREATE TRIGGER ch_join_request_limit BEFORE INSERT ON ch_join_request
                WHEN (SELECT count(*) FROM ch_join_request WHERE channel_id = NEW.channel_id) >= 64
                BEGIN SELECT RAISE(ABORT, 'at most 64 pending join requests per channel'); END""",
        """CREATE TRIGGER ch_join_request_channel BEFORE UPDATE OF channel_id ON ch_join_request
                WHEN NEW.channel_id IS NOT OLD.channel_id
                BEGIN SELECT RAISE(ABORT, 'a join request never moves to another channel'); END""",
        // A join keeps its KeyPackage, its invite and its generation, and its expiry — the day the KeyPackage's
        // private keys die (§6.2.2) — only moves earlier.
        """CREATE TRIGGER ch_join_fixed BEFORE UPDATE ON ch_join
                WHEN NEW.channel_id IS NOT OLD.channel_id OR NEW.kp_ref IS NOT OLD.kp_ref OR NEW.type IS NOT OLD.type
                  OR NEW.invite_id IS NOT OLD.invite_id OR NEW.generation IS NOT OLD.generation
                  OR NEW.ns IS NOT OLD.ns OR NEW.jk_env IS NOT OLD.jk_env OR NEW.r_join IS NOT OLD.r_join
                  OR NEW.committers_digest IS NOT OLD.committers_digest
                  OR NEW.expiry_day > OLD.expiry_day
                BEGIN SELECT RAISE(ABORT, 'a join keeps its KeyPackage and its invite, and its expiry only moves earlier'); END""",
        // The sponsor's own link (Q50 (a)): a password invite stores none, and a row that stored none never gets
        // one later (a stored password link would be an Argon2id-priced oracle on a seized unlocked device);
        // the link may be erased, and its expiry only moves earlier.
        """CREATE TRIGGER ch_invite_own_fixed BEFORE UPDATE ON ch_invite_own
                WHEN NEW.invite_id IS NOT OLD.invite_id OR NEW.channel_id IS NOT OLD.channel_id
                  OR NEW.expiry_day > OLD.expiry_day
                  OR (NEW.invite_env IS NOT OLD.invite_env AND NEW.invite_env IS NOT NULL)
                BEGIN SELECT RAISE(ABORT, 'an own invite is erased, never rewritten, and its expiry only moves earlier'); END""",
        """CREATE TRIGGER ch_invite_issued_identity BEFORE UPDATE ON ch_invite_issued
                WHEN NEW.channel_id IS NOT OLD.channel_id OR NEW.invite_id IS NOT OLD.invite_id
                  OR NEW.invite_pk IS NOT OLD.invite_pk OR NEW.sponsor IS NOT OLD.sponsor
                  OR NEW.sponsor_sig IS NOT OLD.sponsor_sig OR NEW.committers_digest IS NOT OLD.committers_digest
                  OR NEW.pw_version IS NOT OLD.pw_version OR NEW.expiry_day IS NOT OLD.expiry_day
                BEGIN SELECT RAISE(ABORT, 'an issued invite is immutable but for its consumed and void flags'); END""",
        """CREATE TRIGGER ch_invite_issued_flags BEFORE UPDATE OF consumed, void ON ch_invite_issued
                WHEN NEW.consumed < OLD.consumed OR NEW.void < OLD.void
                BEGIN SELECT RAISE(ABORT, 'an invite is consumed once and voided once'); END""",
        """CREATE TRIGGER ch_kp_seen_limit BEFORE INSERT ON ch_kp_seen
                WHEN (SELECT count(*) FROM ch_kp_seen WHERE channel_id = NEW.channel_id) >= 1024
                  AND NOT EXISTS (SELECT 1 FROM ch_kp_seen WHERE channel_id = NEW.channel_id AND tag = NEW.tag)
                BEGIN SELECT RAISE(ABORT, 'at most 1024 KeyPackage tags per channel'); END""",
        """CREATE TRIGGER ch_kp_seen_channel BEFORE UPDATE OF channel_id ON ch_kp_seen
                WHEN NEW.channel_id IS NOT OLD.channel_id
                BEGIN SELECT RAISE(ABORT, 'a KeyPackage tag never moves to another channel'); END""",
        // The rows of `GhostKv` that are global (a KeyPackage and its private keys) die on a day, and the day is
        // held like every other death day: it only moves earlier and, once set, is never forgotten (the first
        // version let a re-put move it later, or clear it, which kept the private keys of a KeyPackage). The
        // key and the channel of a row never change.
        """CREATE TRIGGER mls_global_kv_fixed BEFORE UPDATE ON mls_global_kv
                WHEN NEW.k IS NOT OLD.k OR NEW.channel_id IS NOT OLD.channel_id
                  OR (OLD.delete_after_day IS NOT NULL
                      AND (NEW.delete_after_day IS NULL OR NEW.delete_after_day > OLD.delete_after_day))
                BEGIN SELECT RAISE(ABORT, 'a global row keeps its key and its channel, and its day only moves earlier'); END""",
        // The channel state key is written once, at the first channel use, and never rewritten (slice S4, §19.37): every
        // envelope of every channel is bound to it, so a second key would orphan them all.
        """CREATE TRIGGER mls_self_fixed BEFORE UPDATE ON mls_self
                BEGIN SELECT RAISE(ABORT, 'the channel state key is written once and never rewritten'); END""",
        """CREATE TRIGGER ch_box_key_limit BEFORE INSERT ON ch_box_key
                WHEN (SELECT count(*) FROM ch_box_key WHERE channel_id = NEW.channel_id) >= 18
                BEGIN SELECT RAISE(ABORT, 'at most 18 box keys per channel'); END""",
        """CREATE TRIGGER ch_box_key_replaced BEFORE UPDATE ON ch_box_key
                WHEN NEW.channel_id IS NOT OLD.channel_id OR NEW.box_pk IS NOT OLD.box_pk OR NEW.sk_env IS NOT OLD.sk_env
                  OR (OLD.last_epoch IS NOT NULL AND NEW.last_epoch IS NOT OLD.last_epoch)
                BEGIN SELECT RAISE(ABORT, 'a box key is replaced once, in the epoch that replaced it'); END""",
        // REPLACE guards (§19.21 point 4 of Phase 8, §9 of Phase 10): SQLite runs no DELETE trigger for a
        // row that REPLACE conflict resolution deletes, and the foreign-key cascades of `ch_channel` and
        // `ch_post` would run: a REPLACE of a channel row would delete its posts, keys and generations
        // without one trigger. Every table but the two written with INSERT OR IGNORE (`ch_seen` and
        // `ch_kp_seen`, whose rows carry no rule) refuses an insert that conflicts on any of its keys,
        // so its writers are UPDATE-then-INSERT pairs. `ch_generation` and `ch_candidate` conflict on a
        // UNIQUE constraint as well (the namespace; one candidate per sender and epoch). The two rowid
        // tables, `mls_kv` and `ch_join_request`, also refuse an insert that names an existing rowid
        // ([rowidGuard]): REPLACE would delete that other row, whatever its keys; their rowids are positive
        // and never change ([rowidPositive], [rowidFixed]). The guards cover INSERT
        // forms only; `UPDATE OR REPLACE … SET <key> = <another row's key>` deletes the other row with no
        // trigger, as it does in every table of this database since migration 3 — gate G-DM4 refuses the
        // verb in source (an UPDATE OR REPLACE is an `OR REPLACE`).
        replaceGuard("ch_channel", "channel_id = NEW.channel_id"),
        replaceGuard("ch_liveness", "channel_id = NEW.channel_id"),
        replaceGuard("ch_schedule", "channel_id = NEW.channel_id"),
        replaceGuard(
            "ch_generation",
            "(channel_id = NEW.channel_id AND generation = NEW.generation) OR namespace_id = NEW.namespace_id",
        ),
        replaceGuard("ch_epoch", "channel_id = NEW.channel_id AND epoch = NEW.epoch"),
        replaceGuard("ch_epoch_log", "channel_id = NEW.channel_id AND epoch = NEW.epoch"),
        replaceGuard(
            "ch_candidate",
            "(channel_id = NEW.channel_id AND epoch = NEW.epoch AND hash = NEW.hash) " +
                "OR (channel_id = NEW.channel_id AND epoch = NEW.epoch AND sender = NEW.sender)",
        ),
        replaceGuard("ch_fork_signal", "channel_id = NEW.channel_id AND epoch = NEW.epoch AND hash = NEW.hash"),
        rowidGuard("mls_kv", "channel_id = NEW.channel_id AND k = NEW.k"),
        rowidPositive("mls_kv"),
        rowidFixed("mls_kv"),
        replaceGuard("mls_global_kv", "k = NEW.k"),
        replaceGuard("mls_self", "id = NEW.id"),
        replaceGuard("ch_post", "op_id = NEW.op_id"),
        replaceGuard("ch_reaction", "target = NEW.target AND author = NEW.author"),
        replaceGuard("ch_pending_post", "op_id = NEW.op_id"),
        replaceGuard("ch_outbound_op", "operation_id = NEW.operation_id"),
        replaceGuard("ch_reveal", "channel_id = NEW.channel_id AND direction = NEW.direction AND peer = NEW.peer"),
        replaceGuard("ch_join", "(channel_id = NEW.channel_id AND kp_ref = NEW.kp_ref) OR ns = NEW.ns"),
        rowidGuard("ch_join_request", "channel_id = NEW.channel_id AND hash = NEW.hash"),
        rowidPositive("ch_join_request"),
        rowidFixed("ch_join_request"),
        replaceGuard("ch_invite_issued", "channel_id = NEW.channel_id AND invite_id = NEW.invite_id"),
        replaceGuard("ch_member_seen", "channel_id = NEW.channel_id AND member = NEW.member"),
        replaceGuard("ch_invite_own", "invite_id = NEW.invite_id"),
        replaceGuard("ch_sponsor", "channel_id = NEW.channel_id AND member = NEW.member"),
        replaceGuard("ch_member_refresh", "channel_id = NEW.channel_id AND member = NEW.member"),
        replaceGuard("ch_request", "channel_id = NEW.channel_id AND kind = NEW.kind AND subject = NEW.subject"),
        replaceGuard("ch_box_key", "channel_id = NEW.channel_id AND box_pk = NEW.box_pk"),
    )

    /** Tables that must exist after all migrations; used by tests and by the integrity self-check. */
    val expectedTables: Set<String> = setOf(
        "schema_meta", "identity", "devices",
        "media", "media_blobs",
        "invite_nonces", "revocations",
        // v2 (sync)
        "relay_directory", "sync_namespace", "namespace_relay", "relay_capability", "relay_cursor",
        "outbox_op", "outbox_delivery", "inbox_blob", "inbox_source",
        // v3 (entitlement; v1 entitlement and referral are dropped)
        "ent_key", "ent_schedule_fact", "ent_state", "ent_purchase", "ent_token", "ent_invite",
        "ent_drop_target", "ent_claim", "ent_payout_used",
        // v4 (Phase 9 §13.6 steps 0-4; the v1 DM tables contacts, conversations, messages and
        // signal_state are dropped, the `dm_*` and `olm_*` tables arrive with migration 5)
        "relay_key_registration",
        // v5 (Phase 9 §13.6 steps 5-6): the DM tables themselves.
        "dm_self", "dm_own_namespace", "dm_contact", "dm_pair_key", "dm_pair_offer",
        "dm_conversation", "dm_message", "dm_outbound_item", "dm_outbound_op", "dm_pending_send",
        "dm_bundle_candidate", "dm_orphan_namespace", "dm_scheduled", "dm_held", "dm_reaction",
        "dm_seen", "olm_session", "olm_prekey_gen", "olm_prekey_used", "dm_peer_pq",
        // v6 (Phase 10 §9, the `:sync` half): the funding flag and the registration capabilities.
        "sync_namespace_fund", "relay_register_capability",
        // v7 (Phase 10 §9 "Migration 7"): the v1 channels, channel_pseudonyms, mls_state and posts are
        // dropped (they are no longer expected), and the channel tables arrive.
        "ch_channel", "ch_liveness", "ch_schedule", "ch_generation", "ch_epoch", "ch_epoch_log", "ch_candidate",
        "ch_fork_signal", "mls_kv", "mls_global_kv", "ch_post", "ch_reaction", "ch_pending_post", "ch_outbound_op",
        "ch_seen", "ch_reveal", "ch_join", "ch_join_request", "ch_invite_issued", "ch_kp_seen", "ch_member_seen",
        "ch_invite_own", "ch_sponsor", "ch_member_refresh", "ch_request", "ch_box_key",
        // ... and the channel state key's row (amended by slice S4, §19.37).
        "mls_self",
    )

    /** State-machine, write-once and REPLACE-guard triggers of v2 and v3; a missing one fails [MigrationRunner.verifyIntegrity]. */
    val expectedTriggers: Set<String> = setOf(
        "outbox_op_immutable", "outbox_op_payload", "outbox_op_outcome", "outbox_op_release", "outbox_op_delete",
        "outbox_delivery_insert", "outbox_delivery_state", "outbox_delivery_copy",
        "inbox_blob_insert", "inbox_blob_identity", "inbox_blob_state", "inbox_blob_sources",
        // v3 (entitlement)
        "ent_key_append_only", "ent_key_no_delete", "ent_schedule_fact_append_only", "ent_schedule_fact_no_delete",
        "ent_purchase_transitions", "ent_purchase_frozen", "ent_purchase_invoice_frozen", "ent_purchase_delete_terminal_only",
        "ent_token_state", "ent_token_binding", "ent_invite_transitions", "ent_claim_guard", "ent_drop_target_transitions",
        // v3 REPLACE guards (§19.21 point 4), including those of the v2 table outbox_op
        "ent_key_no_replace", "ent_schedule_fact_no_replace", "ent_purchase_no_replace", "ent_token_no_replace",
        "ent_invite_no_replace", "ent_claim_no_replace", "ent_drop_target_no_replace",
        "outbox_op_no_replace", "outbox_op_rowid",
        // v4 (Phase 9 §13.6 steps 2-4)
        "inbox_blob_relay_expiry_insert", "inbox_blob_relay_expiry_update",
        "sync_namespace_dm_delay", "sync_namespace_dm_delay_insert",
        "relay_key_registration_state", "relay_key_registration_no_replace",
        // v5 (Phase 9 §13.6 step 6): state, write-once and limit rules of the DM tables
        "dm_self_fixed", "dm_self_monotonic",
        "dm_contact_identity", "dm_contact_pin", "dm_contact_trust",
        "dm_message_identity", "dm_message_state", "dm_message_expiry", "dm_held_expiry",
        "dm_conversation_timer", "dm_held_limit", "dm_pair_offer_root",
        "olm_session_identity", "olm_prekey_gen_fixed", "olm_prekey_used_append_only",
        "dm_peer_pq_limit",
        // v5 REPLACE guards
        "dm_self_no_replace", "dm_own_namespace_no_replace", "dm_contact_no_replace",
        "dm_conversation_no_replace", "dm_message_no_replace", "dm_outbound_item_no_replace",
        "dm_outbound_op_no_replace", "dm_pending_send_no_replace", "dm_bundle_candidate_no_replace",
        "dm_orphan_namespace_no_replace", "dm_scheduled_no_replace", "dm_held_no_replace",
        "dm_reaction_no_replace", "dm_pair_offer_no_replace", "olm_session_no_replace",
        "olm_prekey_gen_no_replace", "olm_prekey_used_no_replace", "dm_peer_pq_no_replace",
        // v6 (Phase 10 §9): the channel send-delay rule and the REPLACE guards of the two new tables
        "sync_namespace_channel_delay_update", "sync_namespace_channel_delay_insert",
        "sync_namespace_fund_no_replace", "relay_register_capability_no_replace",
        // v7 (Phase 10 §9 "Migration 7"): the state-machine, write-once and bound triggers of the channel
        // tables ...
        "ch_channel_identity", "ch_channel_state",
        "ch_generation_identity", "ch_generation_state", "ch_generation_drain", "ch_generation_one_current_insert",
        "ch_generation_one_current_update", "ch_generation_one_draining_insert", "ch_generation_one_draining_update",
        "ch_epoch_limit", "ch_epoch_anchor_insert", "ch_epoch_anchor_update", "ch_epoch_identity", "ch_epoch_final",
        "ch_epoch_log_limit", "ch_epoch_log_append_only",
        "ch_candidate_limit", "ch_candidate_identity", "ch_fork_signal_limit", "ch_fork_signal_append_only",
        "ch_post_identity", "ch_post_state", "ch_post_expiry", "ch_pending_post_limit", "ch_pending_post_channel",
        "ch_join_request_limit", "ch_join_request_channel", "ch_join_fixed", "ch_invite_own_fixed",
        "ch_invite_issued_identity", "ch_invite_issued_flags", "ch_kp_seen_limit", "ch_kp_seen_channel",
        "mls_global_kv_fixed", "ch_box_key_limit", "ch_box_key_replaced",
        // (slice S4, §19.37: the channel state key is written once)
        "mls_self_fixed",
        // ... their REPLACE guards (every channel table but ch_seen and ch_kp_seen, which are written with
        // INSERT OR IGNORE) ...
        "ch_channel_no_replace", "ch_liveness_no_replace", "ch_schedule_no_replace", "ch_generation_no_replace",
        "ch_epoch_no_replace", "ch_epoch_log_no_replace", "ch_candidate_no_replace", "ch_fork_signal_no_replace",
        "mls_kv_no_replace", "mls_global_kv_no_replace", "mls_self_no_replace", "ch_post_no_replace", "ch_reaction_no_replace",
        "ch_pending_post_no_replace", "ch_outbound_op_no_replace", "ch_reveal_no_replace", "ch_join_no_replace",
        "ch_join_request_no_replace", "ch_invite_issued_no_replace", "ch_member_seen_no_replace",
        "ch_invite_own_no_replace", "ch_sponsor_no_replace", "ch_member_refresh_no_replace", "ch_request_no_replace",
        "ch_box_key_no_replace",
        // ... and the rowid invariant of the only two tables that have a rowid (positive, never changed)
        "mls_kv_rowid_positive", "mls_kv_rowid_fixed", "ch_join_request_rowid_positive", "ch_join_request_rowid_fixed",
    )

    /**
     * Settings every connection must carry before its first statement (§11.2 #9): durable commits
     * (the crash model is process death; power-loss durability rests on synchronous = FULL),
     * foreign keys for the v2 cascades, and overwrite-on-delete. Applied by SQLCipher `onConfigure`
     * and by the JDBC test executor on open.
     */
    val connectionPragmas: List<String> = listOf(
        "PRAGMA foreign_keys = ON",
        "PRAGMA synchronous = FULL",
        "PRAGMA secure_delete = ON",
    )

    /** Values [MigrationRunner.verifyIntegrity] reads back for [connectionPragmas] (synchronous FULL = 2). */
    val expectedPragmaValues: Map<String, Long> = mapOf(
        "foreign_keys" to 1L,
        "synchronous" to 2L,
        "secure_delete" to 1L,
    )
}
