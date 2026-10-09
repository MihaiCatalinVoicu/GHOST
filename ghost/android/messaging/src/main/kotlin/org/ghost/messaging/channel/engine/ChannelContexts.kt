package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.messaging.channel.store.ChannelStores
import org.ghost.messaging.port.ChannelSeeds
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.KeyWrapper
import org.ghost.sync.api.SyncDatabase

/**
 * The native channel context and the channels opened on it (Phase 10 design §10.2 fns 1 and 2, §10.4 "State key").
 *
 * **The state key** is 32 random bytes created at the first channel use, stored in `mls_self` wrapped by a
 * non-exportable Keystore key ([KeyWrapper], the F9 §2.5 pattern) and unwrapped only into `ctxOpen`; the Kotlin copy is
 * zeroed in the same frame. Its creation is a transaction of its own that runs before the step that needs it
 * (`CH-CREATE`, `CH-ACCEPT`): every envelope the step writes is bound to the key, so the key must be durable before any of
 * them is. A second creator — a crash between the insert's commit and its use — finds the first key and keeps it.
 *
 * **A channel is opened once per context** with its pseudonym seed (`channelOpen`), which becomes the member's signer in
 * native memory; the seed's Kotlin copy is zeroed at once. The pseudonym `P` the call returns is cached for the life of
 * the context, and a caller that holds a stored `my_pseudonym` compares it (§10.2 fn 2: "Kotlin compares P with
 * `:identity`'s value").
 *
 * **Actor thread only**, like every step: nothing here is locked. [close] zeroises the native context (`ctxClose`) at
 * lock and wipe.
 */
internal class ChannelContexts(
    private val database: SyncDatabase,
    private val stores: ChannelStores,
    private val stateKeys: KeyWrapper,
    private val random: DmRandom,
    private val seeds: ChannelSeeds,
) {
    private var crypto: ChannelCrypto? = null
    private val pseudonyms = HashMap<List<Byte>, ByteArray>()

    /** A channel open on the context, and the member's pseudonym in it. */
    class Opened(val crypto: ChannelCrypto, pseudonym: ByteArray) {
        private val p = pseudonym.copyOf()

        /** `P`, the member's Ed25519 pseudonym key in the channel (public to its members). */
        val pseudonym: ByteArray get() = p.copyOf()

        override fun toString(): String = "Opened(redacted)"
    }

    /**
     * The context, opened from the stored state key. Null when no key is stored and [create] is false, when the stored
     * key does not unwrap (a Keystore key a device reset deleted), or when the library is missing.
     */
    fun crypto(create: Boolean): ChannelCrypto? {
        crypto?.let { return it }
        var wrapped = database.transaction { tx -> stores.self.stateKeyWrapped(tx.sql) }
        if (wrapped == null) {
            if (!create) return null
            val fresh = random.bytes(STATE_KEY_BYTES)
            val sealed = try {
                stateKeys.wrap(fresh)
            } catch (e: IllegalStateException) {
                // The Keystore cannot create or use the key (KeyWrapper.wrap's documented failure): no channel use.
                return null
            } finally {
                fresh.fill(0)
            }
            database.transaction { tx -> stores.self.insertIfAbsent(tx, sealed) }
            wrapped = database.transaction { tx -> stores.self.stateKeyWrapped(tx.sql) } ?: return null
        }
        val key = try {
            stateKeys.unwrap(wrapped)
        } catch (e: IllegalArgumentException) {
            // KeyWrapper.unwrap's one failure type: the stored key does not open here (CRYPTO_UNAVAILABLE).
            return null
        }
        val opened = try {
            ChannelCrypto.open(key)
        } finally {
            key.fill(0)
        }
        val context = opened.valueOrNull() ?: return null
        crypto = context
        return context
    }

    /**
     * Opens [channelId] on the context with its pseudonym seed, once per context, and returns it with `P`. Null when the
     * context or the seed is not available, or the native side refuses the seed.
     */
    fun open(channelId: ByteArray, create: Boolean = false): Opened? {
        val context = crypto(create) ?: return null
        pseudonyms[channelId.toList()]?.let { return Opened(context, it) }
        val seed = seeds.pseudonymSeed(channelId) ?: return null
        val p = try {
            context.openChannel(channelId, seed).valueOrNull()
        } finally {
            seed.fill(0)
        }
        p ?: return null
        pseudonyms[channelId.toList()] = p
        return Opened(context, p)
    }

    /** Closes the native channel and forgets the cached pseudonym (§6.6: a leaver's MLS state at its op's outcome). */
    fun closeChannel(channelId: ByteArray) {
        crypto?.closeChannel(channelId)
        pseudonyms.remove(channelId.toList())
    }

    /** Closes the native context — every channel opened on it with it — and forgets the pseudonyms (lock, wipe). */
    fun close() {
        crypto?.close()
        crypto = null
        pseudonyms.clear()
    }

    override fun toString(): String = "ChannelContexts"

    companion object {
        const val STATE_KEY_BYTES: Int = 32
    }
}
