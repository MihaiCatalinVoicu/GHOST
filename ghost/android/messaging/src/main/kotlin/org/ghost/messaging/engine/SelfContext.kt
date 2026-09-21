package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.KeyWrapper
import org.ghost.messaging.store.ContentCipher
import org.ghost.messaging.store.OwnerStore
import org.ghost.sync.api.SyncDatabase

/**
 * What every send and receive step needs about **this** identity (Phase 9 design §3.1, §13.8).
 *
 * It is built once and kept in memory for as long as the DM context is open, because two of its
 * three parts cost something to produce: the own card is a derivation across the JNI boundary, and
 * the content key has to come back through the Keystore wrapper. Neither changes while an identity
 * lives — the card is a pure function of the seed and the card index (§3.3), and the content key is
 * created once at ACTIVATE — so caching them is caching a constant, not a snapshot that can go
 * stale.
 *
 * What is deliberately **not** here: anything with a lifetime shorter than the identity's. Trust
 * states, sessions, pair keys and namespaces are read from their rows inside the transaction that
 * uses them, so a step never acts on a value another transaction has since changed.
 */
internal class SelfContext(
    /** The card index; 0 in Phase 9 (§12.5). */
    val cardIndex: Int,
    /** The own card and everything it derives (§2.6 function 2). */
    val card: DmSessions.OwnCard,
    /** The content key of §13.8, for `body_env`, `card_env`, `name_env` and `l0_env`. */
    val content: ContentCipher,
    seenKey: ByteArray,
) {
    private val seen: ByteArray = seenKey.copyOf()

    /** `dm_self.seen_key`: the key of the D3 dedup tags (§7.6). */
    val seenKey: ByteArray get() = seen.copyOf()

    /** The own inbox namespace `X_0`, which `RECV` checks every blob arrived in (R3). */
    val inboxNamespace: ByteArray get() = card.inboxNamespace

    /** The own Olm identity, which `pair_ad` binds on both sides (rule R-S7). */
    val olmIdentity: ByteArray get() = card.olmIdentity

    /**
     * The own Ed25519 `identity_pk`, read out of the own card at the offset §3.3 fixes.
     *
     * It exists so the **`identity_pk ≠ own`** half of §3.3's fail-closed parse can run wherever a
     * card of another person is parsed: `card::parse_foreign` is the crate's own form of the rule,
     * and the closed surface exports `cardParse` alone (§2.6 function 3 keeps this comparison in
     * Kotlin deliberately, because it is a byte comparison against what `ownCard` already returns).
     * Both the user-add path and the inbound intro path complete the parse with it.
     */
    val identityPk: ByteArray
        get() = card.card.copyOfRange(IDENTITY_PK_OFFSET, IDENTITY_PK_OFFSET + IDENTITY_PK_BYTES)

    /** Never shows a key (T3). */
    override fun toString(): String = "SelfContext(cardIndex=$cardIndex)"

    companion object {
        /**
         * `card = version(1) || card_index(2) || identity_pk(32) || …` (§3.3), so the identity key
         * starts at byte 3.
         */
        const val IDENTITY_PK_OFFSET: Int = 3

        /** An Ed25519 public key. */
        const val IDENTITY_PK_BYTES: Int = 32
    }
}

/**
 * Builds [SelfContext] on demand and keeps it while the identity and the DM context live.
 *
 * Null means one of two things, and both are the facade's `CRYPTO_UNAVAILABLE` or
 * `NOT_ACTIVATED`: the DM context is closed (locked, wiped, library missing), or ACTIVATE has not
 * run so there is no `dm_self` row yet (§21.12 point 2 runs it again at the next actor start).
 */
internal class SelfContexts(
    private val database: SyncDatabase,
    private val crypto: DmCrypto,
    private val keyWrapper: KeyWrapper,
    private val cardIndex: Int = 0,
) {
    private val store = OwnerStore()

    @Volatile
    private var cached: SelfContext? = null

    /** The context, or null when the identity or the DM context is not there. */
    fun get(): SelfContext? {
        cached?.let { return it }
        if (!crypto.isAvailable()) return null
        val row = database.transaction { tx -> store.self(tx.sql) } ?: return null
        val card = crypto.ownCard(cardIndex) ?: return null
        val contentKey = try {
            keyWrapper.unwrap(row.contentKeyWrapped)
        } catch (e: IllegalArgumentException) {
            // A wrapped column that does not unwrap is a corrupted `dm_self`, not a routine
            // outcome; the facade answers `CRYPTO_UNAVAILABLE` and the actor stops claiming
            // blobs (§21.12 point 1) rather than crashing every pass.
            return null
        }
        val context = try {
            SelfContext(
                cardIndex = row.cardIndex,
                card = card,
                content = ContentCipher(contentKey),
                seenKey = row.seenKey,
            )
        } finally {
            contentKey.fill(0)
        }
        cached = context
        return context
    }

    /** Drops the cached context: the identity changed, or the DM context closed (§2.5). */
    fun invalidate() {
        cached?.content?.clear()
        cached = null
    }
}
