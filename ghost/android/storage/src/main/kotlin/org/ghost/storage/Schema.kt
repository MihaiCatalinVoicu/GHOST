package org.ghost.storage

/**
 * Versioned schema (spec v2.0 §8, amended by ADR-04 pseudonyms, ADR-05 invite nonces, ADR-14
 * revocations). Rules enforced here rather than in application code:
 *  - protocol state (libsignal, OpenMLS) lives in dedicated tables as opaque serialized records;
 *  - every content column is a ciphertext envelope; no plaintext content column exists;
 *  - author/sent times are stored at minute granularity (`*_minute`, ADR-08);
 *  - foreign keys and uniqueness guard conversation/channel/message integrity (§8.1);
 *  - v2 (Phase 7 sync, docs/design/faza7-sync-engine.md §2 and §11): sync state lives in
 *    SQLCipher only, persisted times are minute/hour/day values checked by CHECK constraints, and
 *    the outbox/inbox state machines are enforced by triggers ([expectedTriggers]).
 *
 * A change to an existing version is forbidden: add a new [Migration] and bump [CURRENT_VERSION].
 */
object Schema {
    const val CURRENT_VERSION = 2

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
                "CREATE INDEX idx_outbox_op_open ON outbox_op(outcome, released)",
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
                "CREATE INDEX idx_outbox_delivery_due ON outbox_delivery(state, next_attempt_minute)",
                "CREATE INDEX idx_outbox_delivery_relay ON outbox_delivery(relay_id, state)",
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
    )

    /** Tables that must exist after all migrations; used by tests and by the integrity self-check. */
    val expectedTables: Set<String> = setOf(
        "schema_meta", "identity", "devices", "contacts", "conversations", "signal_state", "messages",
        "channels", "channel_pseudonyms", "mls_state", "posts", "media", "media_blobs",
        "entitlement", "referral", "invite_nonces", "revocations",
        // v2 (sync)
        "relay_directory", "sync_namespace", "namespace_relay", "relay_capability", "relay_cursor",
        "outbox_op", "outbox_delivery", "inbox_blob", "inbox_source",
    )

    /** State-machine triggers of v2; a missing one fails [MigrationRunner.verifyIntegrity]. */
    val expectedTriggers: Set<String> = setOf(
        "outbox_op_immutable", "outbox_op_payload", "outbox_op_outcome", "outbox_op_release", "outbox_op_delete",
        "outbox_delivery_insert", "outbox_delivery_state", "outbox_delivery_copy",
        "inbox_blob_insert", "inbox_blob_identity", "inbox_blob_state", "inbox_blob_sources",
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
