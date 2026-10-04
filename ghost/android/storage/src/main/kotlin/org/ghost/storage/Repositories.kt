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
