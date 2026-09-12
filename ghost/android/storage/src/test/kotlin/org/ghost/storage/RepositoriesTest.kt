package org.ghost.storage

import org.ghost.identity.InMemoryWrappedSecretStore
import org.ghost.identity.Invite
import org.ghost.identity.RevocationCertificate
import org.ghost.identity.RootEntropy
import org.ghost.identity.SecretWrapper
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

class RepositoriesTest {
    private val root = RootEntropy.fromRaw(ByteArray(32) { it.toByte() })
    private var now = 1_757_491_200L

    private fun db(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    @Test
    fun inviteNonceRepositoryBlocksReplayAcrossInstances() {
        val db = db()
        // The token is opaque to :identity; the schedule check belongs to the native library. This
        // stand-in accepts it as an INVITE token of epoch 726, the invite epoch of `now` (Phase 8 §4.1).
        val token = ByteArray(Invite.TOKEN_BYTES) { (if (it == 0) 0 else if (it == 1) 2 else 7).toByte() }
        val schedule = Invite.TokenCheck { if (it.contentEquals(token)) 726L else null }
        val invite = Invite.create(token, 726L, now / 86_400 + 7, listOf(5, 0, 17), root.inviteKeys(0))
        Invite.parseAndVerify(invite.encode(), now, schedule, InviteNonceRepository(db) { now })
        // A "restart": a new repository over the same database still remembers the nonce.
        assertThrows(Invite.Rejection.Replayed::class.java) {
            Invite.parseAndVerify(invite.encode(), now, schedule, InviteNonceRepository(db) { now })
        }
    }

    @Test
    fun identityRepositoryRoundTripAndSingleRow() {
        val db = db()
        val repo = IdentityRepository(db)
        repo.save(root.publicIdentity(), root.identityKeyPair().publicKey, 1, now)
        val rec = repo.load()
        assertNotNull(rec)
        assertEquals(root.publicIdentity(), rec!!.identity)
        assertArrayEquals(root.identityKeyPair().publicKey, rec.identityPublicKey)
        assertThrows(Exception::class.java) { repo.save(RootEntropy.generate().publicIdentity(), ByteArray(32), 1, now) }
    }

    @Test
    fun channelPseudonymRepositoryTracksRevealState() {
        val db = db()
        val channelId = ByteArray(32) { 3 }
        db.exec("INSERT INTO channels(channel_id, history_policy, created_at) VALUES (?, 'none', ?)", listOf(channelId, now))
        val repo = ChannelPseudonymRepository(db)
        val pub = root.channelPseudonymKeyPair(channelId).publicKey
        repo.upsert(channelId, pub)
        assertArrayEquals(pub, repo.publicKeyFor(channelId))
        assertFalse(repo.isRevealed(channelId))
        repo.markRevealed(channelId)
        assertTrue(repo.isRevealed(channelId))
        // Same pseudonym cannot be registered for another channel (unlinkability guard, T14).
        val other = ByteArray(32) { 4 }
        db.exec("INSERT INTO channels(channel_id, history_policy, created_at) VALUES (?, 'none', ?)", listOf(other, now))
        assertThrows(Exception::class.java) { repo.upsert(other, pub) }
    }

    @Test
    fun revocationRepositoryStoresOnlyVerifiedCertificates() {
        val db = db()
        val repo = RevocationRepository(db) { now }
        val cert = RevocationCertificate.issue(root.identityKeyPair(), now, RevocationCertificate.Reason.DEVICE_COMPROMISED)
        repo.store(cert.bytes())
        assertTrue(repo.isRevoked(root.identityKeyPair().publicKey))
        val tampered = cert.bytes().also { it[40] = (it[40].toInt() xor 1).toByte() }
        assertThrows(IllegalArgumentException::class.java) { repo.store(tampered) }
        assertFalse(repo.isRevoked(RootEntropy.generate().identityKeyPair().publicKey))
    }

    @Test
    fun databaseKeyIsStableWrappedAndDestroyable() {
        val wrapper = object : SecretWrapper {
            private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
            override fun wrap(plaintext: ByteArray): ByteArray {
                val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, key); return c.iv + c.doFinal(plaintext)
            }
            override fun unwrap(envelope: ByteArray): ByteArray {
                val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, envelope.copyOfRange(0, 12))); return c.doFinal(envelope.copyOfRange(12, envelope.size))
            }
        }
        val store = InMemoryWrappedSecretStore()
        val provider = DatabaseKeyProvider(wrapper, store)
        assertFalse(provider.exists())
        val k1 = provider.getOrCreate()
        assertEquals(32, k1.size)
        assertArrayEquals(k1, DatabaseKeyProvider(wrapper, store).getOrCreate())
        assertFalse(store.read(DatabaseKeyProvider.ENVELOPE_NAME)!!.contentEquals(k1))
        provider.destroy()
        assertFalse(provider.exists())
        assertFalse(provider.getOrCreate().contentEquals(k1))
    }
}
