package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmSessions
import org.ghost.identity.DerivationLabels
import org.ghost.identity.RootEntropy
import org.ghost.messaging.port.DmContext
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.KeyWrapper
import org.ghost.messaging.store.OwnerStore
import org.ghost.sync.api.SyncDatabase
import java.security.GeneralSecurityException

/**
 * The **DM context's lifecycle** (Phase 9 design §2.5, §13.7 "Wiring", §13.8): the one object that
 * holds the native handle `ghost-client-dm` keeps the MESSAGING branch, the `ghost1` seed and the
 * `session_state_key` behind, and the wrapped copy of that state key ACTIVATE persists.
 *
 * **Placement (slice S12, a recorded deviation from §13.1).** §13.1 lists a `DmKeys` in
 * `:crypto-bridge`. The bridge half of it is there — `DmSessions.openContext` and `closeContext`
 * are the only callers of `ctxOpen`/`ctxClose` — but the lifecycle needs three things
 * `:crypto-bridge` may not reach (§22.9 item 3: it keeps no production dependency): the root
 * entropy of `:identity`, the stored `dm_self.state_key_wrapped` of `:messaging`'s schema, and the
 * Keystore wrapper of `…messaging.android`. So the lifecycle is here, beside the steps that read
 * the context, and the bridge keeps exactly the two JNI calls.
 *
 * **Opening** ([open]) derives `m = HKDF(root, "ghost/v1/messaging")` and the Ed25519 identity seed
 * `HKDF(root, "ghost/v1/identity")` (§3.1's first two rows), unwraps the stored
 * `session_state_key` — or, before ACTIVATE has written `dm_self`, draws a fresh one and wraps it,
 * so ACTIVATE persists the wrapped copy it reads from [stateKeyWrapped] (§22.9's recorded deviation
 * in `DmContext`) — and hands the three to the native context, which zeroises its copies when the
 * call returns (R2-04). The Kotlin copies are zeroised here, in `finally`, on every path: the
 * branch, the seed, the state key, and the root entropy the caller handed over.
 *
 * **Closing** ([close]) calls `ctxClose`, which zeroises the native keys (§2.5). The caller —
 * `MessagingRuntime` — drops the Kotlin-side key material in the same actor turn: the cached
 * [SelfContext] (its content key) and the recognition and provisional keys (§13.7's "zeroize the
 * Kotlin-side key material").
 *
 * **Threading (corrected by the review of S9, FIX 4).** [open] and [close] run on the DM actor,
 * but since Phase 10's channels they are **not** the only callers of the native context: the
 * channel actor calls `revealSeal` → `reveal_identity_material` (§6.9's reveal), so DM-native
 * session functions arrive on more than one actor thread. The invariant that makes this safe is
 * the native side's, not this class's: the DM crate's registry mutex serialises every call that
 * holds a context (a `ctxClose` racing a call simply loses the slot — the answer is
 * `CRYPTO_UNAVAILABLE`, §13.2), and the dependency between the two crates is one-way —
 * `ghost-client-mls` may run under the DM registry guard, `ghost-client-dm` never calls into the
 * MLS crate — so the lock order is acyclic and no deadlock is possible. What this coupling costs
 * is latency: a channel receive that opens a reveal waits on the registry behind whatever DM
 * call holds it. [handleOrNull] is read by steps on either actor, and is `@Volatile` only so a
 * status read from another thread sees a closed context as closed.
 *
 * **A state key that no longer unwraps** — the Keystore key was deleted by a device reset, or an
 * authentication-bound key is outside its window — leaves the context **closed**
 * ([Opened.STATE_KEY_UNAVAILABLE]): every stored session, generation and pair key is wrapped under
 * that key, so opening with a fresh one would make them `STATE_CORRUPT` one by one while the
 * facade reported success. Closed is `CRYPTO_UNAVAILABLE` at the facade (§13.2), which is the
 * answer the design gives for "the keys are not there".
 */
class DmKeys(
    /** The Keystore wrapper of `session_state_key` (`KeystoreStateKeyWrapper` on a device). */
    private val stateKeys: KeyWrapper,
    private val random: DmRandom,
    /**
     * The MESSAGING branch of an identity. It is `HKDF(root, "ghost/v1/messaging")` everywhere but
     * in the `gate` build type, whose debug key-change hook (`crypto-bridge/src/gate`, §15.1,
     * §21.13 point 7) derives an alternate branch from it — the "stolen seed on a modified client"
     * of §15.1: another Olm identity, bound by the same Ed25519 key. `:app` passes `DmBranch`'s,
     * which the release and debug source sets define as this default and only `src/gate` defines
     * otherwise (gate G-DM5); a constructor argument, not a member a subclass could override.
     */
    private val messagingBranch: (RootEntropy) -> ByteArray = { it.deriveBranch(DerivationLabels.MESSAGING) },
) : DmContext {

    /** What [open] did. Enums only (T3). */
    enum class Opened {
        /** The context is open for the identity that was handed over. */
        OPENED,

        /** No identity is stored: nothing to open (before onboarding, or after a wipe). */
        NO_IDENTITY,

        /** The native library is missing or refused the keys (§2.7): `CRYPTO_UNAVAILABLE`. */
        CRYPTO_UNAVAILABLE,

        /**
         * `dm_self.state_key_wrapped` exists and does not unwrap on this device (see the class note),
         * or — before ACTIVATE has written it — the Keystore cannot wrap a fresh one here.
         */
        STATE_KEY_UNAVAILABLE,
    }

    private val store = OwnerStore()

    @Volatile
    private var handle: Long? = null

    @Volatile
    private var wrapped: ByteArray? = null

    override fun handleOrNull(): Long? = handle

    override fun stateKeyWrapped(): ByteArray? = if (handle != null) wrapped?.copyOf() else null

    /** True while a context is open. */
    val isOpen: Boolean get() = handle != null

    /**
     * Opens the context for [root], closing a previous one first (the identity may have changed:
     * the K20 hook after an onboarding wipe, or the `gate` key-change hook). [root] is zeroised
     * whatever happens. Must run on the DM actor and **outside** any transaction: it reads
     * `dm_self` in one of its own.
     */
    internal fun open(database: SyncDatabase, root: RootEntropy?): Opened {
        close()
        if (root == null) return Opened.NO_IDENTITY
        var branch: ByteArray? = null
        var seed: ByteArray? = null
        var stateKey: ByteArray? = null
        try {
            val stored = database.transaction { tx -> store.self(tx.sql)?.stateKeyWrapped }
            val wrappedKey: ByteArray
            if (stored != null) {
                stateKey = try {
                    stateKeys.unwrap(stored)
                } catch (e: GeneralSecurityException) {
                    return Opened.STATE_KEY_UNAVAILABLE
                } catch (e: IllegalArgumentException) {
                    return Opened.STATE_KEY_UNAVAILABLE
                }
                if (stateKey.size != STATE_KEY_BYTES) return Opened.STATE_KEY_UNAVAILABLE
                wrappedKey = stored
            } else {
                stateKey = random.bytes(STATE_KEY_BYTES)
                wrappedKey = try {
                    stateKeys.wrap(stateKey)
                } catch (e: IllegalStateException) {
                    // The Keystore cannot create or use the state key on this device (the
                    // wrappers' documented failure, S12 review): the context stays closed, which is
                    // `CRYPTO_UNAVAILABLE` at the facade, rather than an exception that ended the
                    // process at every start that had an identity and no `dm_self` row yet.
                    return Opened.STATE_KEY_UNAVAILABLE
                }
            }
            branch = messagingBranch(root)
            seed = root.deriveBranch(DerivationLabels.IDENTITY)
            // `openContext` zeroises all three arrays itself, on every path (DmSessions): the
            // `finally` below is the second wipe, for the paths that return before it is called.
            val opened = DmSessions.openContext(branch, seed, stateKey) ?: return Opened.CRYPTO_UNAVAILABLE
            wrapped = wrappedKey
            handle = opened
            return Opened.OPENED
        } finally {
            branch?.fill(0)
            seed?.fill(0)
            stateKey?.fill(0)
            root.zeroize()
        }
    }

    /**
     * Closes the context (§2.5: "Lock and wipe call it"). A second close is a no-op. Must run on the
     * DM actor.
     */
    internal fun close() {
        val open = handle ?: return
        handle = null
        wrapped = null
        DmSessions.closeContext(open)
    }

    /** Never shows a key or the handle (T3). */
    override fun toString(): String = "DmKeys(open=$isOpen)"

    companion object {
        /** `session_state_key`: 32 random bytes (§2.5, §3.1). */
        const val STATE_KEY_BYTES: Int = 32
    }
}
