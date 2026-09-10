package org.ghost.storage

/**
 * Versioned schema (spec v2.0 §8, amended by ADR-04 pseudonyms, ADR-05 invite nonces, ADR-14
 * revocations). Rules enforced here rather than in application code:
 *  - protocol state (libsignal, OpenMLS) lives in dedicated tables as opaque serialized records;
 *  - every content column is a ciphertext envelope; no plaintext content column exists;
 *  - author/sent times are stored at minute granularity (`*_minute`, ADR-08);
 *  - foreign keys and uniqueness guard conversation/channel/message integrity (§8.1).
 *
 * A change to an existing version is forbidden: add a new [Migration] and bump [CURRENT_VERSION].
 */
object Schema {
    const val CURRENT_VERSION = 1

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
    )

    /** Tables that must exist after all migrations; used by tests and by the integrity self-check. */
    val expectedTables: Set<String> = setOf(
        "schema_meta", "identity", "devices", "contacts", "conversations", "signal_state", "messages",
        "channels", "channel_pseudonyms", "mls_state", "posts", "media", "media_blobs", "relay_queue",
        "sync_cursor", "entitlement", "referral", "invite_nonces", "revocations",
    )
}
