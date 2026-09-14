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
 *    (`<table>_no_replace`, created by migration 3).
 *
 * A change to an existing version is forbidden: add a new [Migration] and bump [CURRENT_VERSION].
 * The one exception is a version no release has carried: v3 has never shipped and is amended in
 * place (§19.20); from the first release that carries it, v3 is frozen like v1 and v2.
 */
object Schema {
    const val CURRENT_VERSION = 3

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
                // (5) Invites this identity created (inviter side), with the two refresh times of a
                // credit sent to the drop, drawn at creation, never at a read (§19.26, Q31).
                """CREATE TABLE ent_invite (
                    invite_index        INTEGER NOT NULL PRIMARY KEY CHECK (invite_index BETWEEN 0 AND 65535),
                    state               TEXT    NOT NULL CHECK (state IN ('created', 'credited', 'closed')),
                    payload             BLOB    CHECK (payload IS NULL OR length(payload) = 538),
                    drop_namespace      BLOB    NOT NULL CHECK (length(drop_namespace) = 32),
                    listen_until_day    INTEGER NOT NULL CHECK (typeof(listen_until_day) = 'integer' AND listen_until_day >= 0),
                    refresh_minute      INTEGER NOT NULL CHECK (typeof(refresh_minute) = 'integer' AND refresh_minute % 60 = 0),
                    late_refresh_minute INTEGER NOT NULL CHECK (typeof(late_refresh_minute) = 'integer' AND late_refresh_minute % 60 = 0),
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
                """CREATE TRIGGER outbox_op_no_replace BEFORE INSERT ON outbox_op
                WHEN EXISTS (SELECT 1 FROM outbox_op WHERE operation_id = NEW.operation_id
                             OR (namespace_id = NEW.namespace_id AND blob_hash = NEW.blob_hash) OR rowid = NEW.rowid)
                BEGIN SELECT RAISE(ABORT, 'outbox_op rows are never replaced'); END""",
                """CREATE TRIGGER outbox_op_rowid BEFORE UPDATE ON outbox_op
                WHEN NEW.rowid IS NOT OLD.rowid
                BEGIN SELECT RAISE(ABORT, 'outbox_op identity is immutable'); END""",
            ),
        ),
    )

    /** Tables that must exist after all migrations; used by tests and by the integrity self-check. */
    val expectedTables: Set<String> = setOf(
        "schema_meta", "identity", "devices", "contacts", "conversations", "signal_state", "messages",
        "channels", "channel_pseudonyms", "mls_state", "posts", "media", "media_blobs",
        "invite_nonces", "revocations",
        // v2 (sync)
        "relay_directory", "sync_namespace", "namespace_relay", "relay_capability", "relay_cursor",
        "outbox_op", "outbox_delivery", "inbox_blob", "inbox_source",
        // v3 (entitlement; v1 entitlement and referral are dropped)
        "ent_key", "ent_schedule_fact", "ent_state", "ent_purchase", "ent_token", "ent_invite",
        "ent_drop_target", "ent_claim", "ent_payout_used",
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
