package org.ghost.storage

import org.ghost.identity.GhostIdentity
import org.ghost.identity.Invite
import org.ghost.identity.RevocationCertificate

/** Persistent invite replay protection (FR-1.6). Replaces the in-memory store from Phase 3. */
class InviteNonceRepository(private val db: SqlExecutor, private val clock: () -> Long) : Invite.NonceStore {
    override fun recordIfFresh(nonce: ByteArray): Boolean {
        require(nonce.size == 16)
        var fresh = false
        db.transaction {
            val seen = db.queryLong("SELECT 1 FROM invite_nonces WHERE nonce = ?", listOf(nonce)) != null
            if (!seen) {
                db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, ?)", listOf(nonce, clock()))
                fresh = true
            }
        }
        return fresh
    }
}

/** The single local identity row (public data only; the seed lives in the Keystore envelope). */
class IdentityRepository(private val db: SqlExecutor) {
    data class Record(val identity: GhostIdentity, val identityPublicKey: ByteArray, val derivationVersion: Int, val createdAt: Long)

    fun save(identity: GhostIdentity, identityPublicKey: ByteArray, derivationVersion: Int, createdAt: Long) {
        db.exec(
            "INSERT INTO identity(id, public_identity, identity_public_key, derivation_version, created_at) VALUES (1, ?, ?, ?, ?)",
            listOf(identity.encode(), identityPublicKey, derivationVersion.toLong(), createdAt),
        )
    }

    fun load(): Record? {
        var out: Record? = null
        db.query("SELECT public_identity, identity_public_key, derivation_version, created_at FROM identity WHERE id = 1") {
            out = Record(GhostIdentity.parse(it.string(0)), it.blob(1), it.long(2).toInt(), it.long(3))
        }
        return out
    }
}

/** Verified revocation certificates received for contacts (ADR-14). Only verified certificates are stored. */
class RevocationRepository(private val db: SqlExecutor, private val clock: () -> Long) {
    fun store(certificateBytes: ByteArray): RevocationCertificate {
        val cert = RevocationCertificate.parseAndVerify(certificateBytes)
        db.exec(
            "INSERT OR REPLACE INTO revocations(identity_public_key, certificate, received_at) VALUES (?, ?, ?)",
            listOf(cert.identityPublicKey, cert.bytes(), clock()),
        )
        return cert
    }

    fun isRevoked(identityPublicKey: ByteArray): Boolean =
        db.queryLong("SELECT 1 FROM revocations WHERE identity_public_key = ?", listOf(identityPublicKey)) != null
}

/**
 * The user-provided bridge lines (Phase 12 transports, design `faza12-transports.md` §6.3; ADR-62
 * point 4): the only writer of `transport_bridge`. The lines that arrive here were validated by
 * the single Rust validator (`nativeValidateBridgeLines`) in `:network`'s repository class before
 * any call — this DAO trusts its input, stores at day granularity (T33), dedups with
 * `INSERT OR IGNORE` (exact-string duplicates collapse, §6.2 point 4) and lists in insertion
 * order (`added_day`, then the line — deterministic, rowid-free). Deletion is by exact line (the
 * future UI's remove action and the host-side test entry). Nothing here ever logs a line (T58).
 */
class TransportBridgeRepository(private val db: SqlExecutor, private val clockDay: () -> Long) {

    /** Replaces the whole configured set with [lines] (the settings screen writes the full list). */
    fun replaceAll(lines: List<String>) {
        db.transaction {
            db.exec("DELETE FROM transport_bridge")
            for (line in lines) {
                db.exec("INSERT OR IGNORE INTO transport_bridge(line, added_day) VALUES (?, ?)", listOf(line, clockDay()))
            }
        }
    }

    /** The configured lines in insertion order (§6.3), empty when none are configured. */
    fun list(): List<String> {
        val out = ArrayList<String>()
        db.query("SELECT line FROM transport_bridge ORDER BY added_day, line") { out += it.string(0) }
        return out
    }

    /** Deletes one exact line; returns true when a row was removed. */
    fun delete(line: String): Boolean =
        db.execUpdate("DELETE FROM transport_bridge WHERE line = ?", listOf(line)) > 0
}
