package org.ghost.messaging.device

import android.content.Context
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.bouncycastle.crypto.digests.SHA3Digest
import org.ghost.identity.RootEntropy
import org.ghost.messaging.android.KeystoreContentKeyWrapper
import org.ghost.messaging.android.KeystoreStateKeyWrapper
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.engine.DmKeys
import org.ghost.messaging.engine.MessagingRuntime
import org.ghost.messaging.port.DmCheckpoint
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.port.ExpiryWake
import org.ghost.network.OnionAddress
import org.ghost.storage.Checkpoint
import org.ghost.storage.MigrationRunner
import org.ghost.storage.Schema
import org.ghost.storage.SqlExecutor
import org.ghost.storage.SupportSqlExecutor
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SchedulePurpose
import org.ghost.sync.port.SyncClock
import org.ghost.sync.store.SyncStores
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * **Two DM devices on the emulator** (Phase 9 design §15.9 items 2, 4 and 5; slice S12): each a
 * real SQLCipher database file opened the way `GhostDatabase` opens one (the hardening pragmas, WAL,
 * the open checkpoint of R-K1, `verifyIntegrity`), a real `MessagingRuntime` with its actor, the
 * real Keystore wrappers of §13.8, and the Android build of the DM library inside
 * `libghost_client_net.so`; between them the **loopback model relay** of §15.9 item 4.
 *
 * The relay is the same delivery model `DmWorld` uses on the JVM and S10 declared as the transport
 * seam (§22.15 item 4): every op one device enqueued lands in the other's inbox when that inbox
 * listens on its namespace. It is test code in the `androidTest` APK only (gate G-DM5), and it does
 * not pretend to be Tor or the sync engine: those are the `live-tor` job's and `sync-exit-gate`'s.
 *
 * The clock is a movable one, shared by both devices and by `:sync`, because the establishment
 * steps wait minutes and the timers wait longer; the actor, the Keystore, SQLCipher and the native
 * library are the device's own.
 */
class DeviceWorld(private val context: Context, private val tag: String) : AutoCloseable {

    /** One clock for `:sync` and the DM layer of both devices. */
    class Clock(var now: Long) : DmClock, SyncClock {
        var monotonic: Long = 1_000_000L

        override fun nowEpochSeconds(): Long = now

        override fun epochSeconds(): Long = now

        override fun monotonicMillis(): Long = monotonic
    }

    val clock = Clock(WEEK_ORIGIN + 2_870 * WEEK + 2 * DAY)
    val alice = Device("a", 0x41)
    val bob = Device("b", 0x51)

    private val delivered = HashSet<Pair<List<Byte>, Device>>()
    private var sequence = 1L

    /** One device: its database file, its stores, its DM stack and its identity. */
    inner class Device(name: String, seedByte: Int) : AutoCloseable {
        private val fileName = "dm-gate-$tag-$name.db"

        /**
         * The database file **SQLCipher has open**, read back from the connection — not a path
         * this class assumes. The first version assumed `noBackupFilesDir`, which the helper's
         * `noBackupDirectory(true)` asks for and SQLCipher's `SupportOpenHelperFactory` ignores:
         * the file is `getDatabasePath(name)`, under `databases/` (first emulator run, design
         * §22.32). So SCN-F measured the `-wal` of a file that did not exist — 0 bytes, whatever the
         * sweep did — and the leftovers of an earlier run were never deleted.
         */
        val file: File
        val sql: SqlExecutor
        private val helper: SupportSQLiteOpenHelper
        val database: SyncDatabase
        val stores: SyncStores
        private val rootBytes = ByteArray(32) { (seedByte + it).toByte() }

        /** The MESSAGING branch transform: identity unless [keyChanged] (§15.1's debug hook, test form). */
        @Volatile
        var keyChanged: Boolean = false

        val keys: DmKeys
        val runtime: MessagingRuntime

        /**
         * Every checkpoint SWEEP asked for through its port (the only caller of `DmCheckpoint`),
         * with the answer and the -wal's length **right after** `Checkpoint.truncate` returned, on
         * the actor thread, before any later step of the pass wrote again. That instant is the one
         * §10.9 point 3's "the WAL is 0 bytes" is about (SCN-F; design §22.32).
         */
        val checkpoints: MutableList<CheckpointSeen> = java.util.Collections.synchronizedList(ArrayList())

        init {
            deleteDatabase(context, fileName)
            System.loadLibrary("sqlcipher")
            helper = openHelper(context, fileName, ByteArray(32) { (seedByte * 3 + it).toByte() }, Schema.CURRENT_VERSION, Schema.migrations)
            file = File(requireNotNull(helper.writableDatabase.path) { "the open database has a file" })
            sql = SupportSqlExecutor(helper.writableDatabase)
            finishOpen(sql)
            database = SyncDatabase(sql)
            stores = SyncStores(database, clock, FixedSources) { PrivacyMode.STANDARD }
            val ids = database.transaction { tx ->
                stores.relayDirectory.upsert(tx, (0 until 4).map { i -> RelayEntry(onion(i), operator(i % 2), RelayEntry.Source.CONFIG) })
            }
            val slots = (0 until 4).map { i -> EsSlot(i, ids.getValue(onion(i)), operator(i % 2)) }
            keys = DmKeys(
                stateKeys = KeystoreStateKeyWrapper(requireUserAuthentication = false),
                random = SecureDmRandom,
                messagingBranch = { root ->
                    val derived = root.deriveBranch(org.ghost.identity.DerivationLabels.MESSAGING)
                    if (!keyChanged) derived else alternate(derived).also { derived.fill(0) }
                },
            )
            runtime = MessagingRuntime(
                stores = stores,
                keys = keys,
                contentKeys = KeystoreContentKeyWrapper(requireUserAuthentication = false),
                esSlots = EsSlots { slots },
                clock = clock,
                random = SecureDmRandom,
                alarm = ExpiryWake.NONE,
                // The production line, `Checkpoint.truncate(sql)`, and a record of the -wal's length
                // the moment it returns (see [checkpoints]).
                checkpoint = DmCheckpoint {
                    Checkpoint.truncate(sql).also { truncated -> checkpoints += CheckpointSeen(truncated, walFile.length()) }
                },
            )
            stores.inbox.setListener(runtime.listener)
        }

        val messaging: Messaging get() = runtime.messaging

        fun root(): RootEntropy = RootEntropy.fromRaw(rootBytes)

        fun unlock(): DmKeys.Opened = runtime.unlock(::root)

        /** A time-triggered pass (§21.9 rule 1), run to its end: a facade call queues behind it. */
        fun timePass() {
            runtime.onTimeTrigger()
            messaging.status()
        }

        /** A hint pass (an arriving blob), run to its end. */
        fun hintPass() {
            runtime.onChange(SyncChange.INBOX)
            messaging.status()
        }

        fun card(): ByteArray = requireNotNull(messaging.myCard()) { "the DM context is open" }.card

        fun contact(): ContactId = messaging.contacts().single().id

        fun stores(): Int = count("SELECT count(*) FROM outbox_op")

        fun count(query: String): Int {
            var n = 0
            sql.query(query) { n = it.long(0).toInt() }
            return n
        }

        val walFile: File get() = File(file.path + "-wal")

        override fun close() {
            runtime.lock()
            runtime.cancelWakes()
            stores.inbox.setListener(null)
            runtime.close()
            helper.close()
        }
    }

    /** One checkpoint SWEEP ran: its answer, and the -wal's length the moment it returned. */
    data class CheckpointSeen(val truncated: Boolean, val walBytes: Long)

    /** Advances the shared clock (and the monotonic one, as time passing does). */
    fun advance(seconds: Long) {
        clock.now += seconds
        clock.monotonic += seconds * 1_000L
    }

    /**
     * One loopback relay round (§15.9 item 4): every op either device enqueued lands in the other's
     * inbox if that inbox listens on the op's namespace, once. [shuffle] delivers in an order drawn
     * from it (SCN-B's reorder).
     */
    fun deliver(shuffle: java.util.Random? = null): Int {
        var moved = 0
        for ((from, to) in listOf(alice to bob, bob to alice)) {
            val blobs = ArrayList<Triple<ByteArray, ByteArray, ByteArray>>()
            from.sql.query("SELECT operation_id, namespace_id, ciphertext FROM outbox_op ORDER BY rowid") {
                blobs += Triple(it.blob(0), it.blob(1), it.blob(2))
            }
            if (shuffle != null) blobs.shuffle(shuffle)
            for ((op, namespace, ciphertext) in blobs) {
                if (!listens(to, namespace)) continue
                if (!delivered.add(op.toList() to to)) continue
                insert(to, namespace, ciphertext)
                moved += 1
            }
        }
        return moved
    }

    private fun listens(device: Device, namespace: ByteArray): Boolean {
        var found = false
        device.sql.query("SELECT 1 FROM sync_namespace WHERE namespace_id = ? AND listening = 1", listOf(namespace)) { found = true }
        return found
    }

    /** The two-step `listed` → `fetched` transition the Phase 7 schema requires (as `DmWorld`). */
    private fun insert(device: Device, namespace: ByteArray, ciphertext: ByteArray) {
        val hash = MessageDigest.getInstance("SHA-256").digest(ciphertext)
        val now = clock.now
        val retain = -Math.floorDiv(-(Math.floorDiv(now, DAY) + 24), 7L) * 7L
        device.database.transaction { tx ->
            tx.sql.exec(
                "INSERT INTO inbox_blob(namespace_id, blob_hash, state, ciphertext, fetch_seq, fetch_attempts, " +
                    "next_fetch_minute, offers, offer_after_minute, retain_until_day) VALUES (?, ?, 'listed', NULL, NULL, 0, 0, 0, 0, ?)",
                listOf(namespace, hash, retain),
            )
            tx.sql.exec(
                "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = ?, relay_expiry_hour = ? " +
                    "WHERE namespace_id = ? AND blob_hash = ?",
                listOf(ciphertext, sequence++, -Math.floorDiv(-(now + 30 * DAY), HOUR) * HOUR, namespace, hash),
            )
        }
    }

    override fun close() {
        alice.close()
        bob.close()
    }

    companion object {
        const val WEEK_ORIGIN: Long = 345_600L
        const val MINUTE: Long = 60L
        const val HOUR: Long = 3_600L
        const val DAY: Long = 86_400L
        const val WEEK: Long = 604_800L

        /** The label of the gate variant's key-change hook (`GateKeyChange`), restated here: test code. */
        private const val KEY_CHANGE_LABEL = "ghost/v1/gate/key-change"

        fun alternate(branch: ByteArray): ByteArray {
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(javax.crypto.spec.SecretKeySpec(branch, "HmacSHA256"))
            return mac.doFinal(KEY_CHANGE_LABEL.toByteArray(Charsets.US_ASCII))
        }

        /**
         * Deletes database [name] and its `-wal`, `-shm` and `-journal` where SQLCipher's helper
         * puts it: `getDatabasePath(name)` (`databases/`), whatever `noBackupDirectory` says.
         */
        fun deleteDatabase(context: Context, name: String) {
            val main = context.getDatabasePath(name)
            for (suffix in listOf("", "-wal", "-shm", "-journal")) File(main.path + suffix).delete()
        }

        /**
         * A SQLCipher helper opened the way `GhostDatabase.open` opens the app's one database — the
         * connection pragmas in `onConfigure`, the migrations inside the helper's transaction — under
         * a file name of the test's, because two devices share this process. Like
         * `GhostDatabase`'s, its file is in `databases/`: SQLCipher 4.19.0's factory ignores
         * `noBackupDirectory(true)` (design §22.32 records it for the app's database).
         */
        fun openHelper(
            context: Context,
            name: String,
            key: ByteArray,
            version: Int,
            migrations: List<Schema.Migration>,
        ): SupportSQLiteOpenHelper {
            val config = SupportSQLiteOpenHelper.Configuration.builder(context)
                .name(name)
                .noBackupDirectory(true)
                .callback(object : SupportSQLiteOpenHelper.Callback(version) {
                    override fun onConfigure(db: SupportSQLiteDatabase) {
                        db.setForeignKeyConstraintsEnabled(true)
                        for (pragma in Schema.connectionPragmas) db.query(pragma).use { it.moveToFirst() }
                    }

                    override fun onCreate(db: SupportSQLiteDatabase) {
                        MigrationRunner(SupportSqlExecutor(db), migrations).migrateWithinTransaction(installed = 0)
                    }

                    override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                        MigrationRunner(SupportSqlExecutor(db), migrations).migrateWithinTransaction(installed = oldVersion)
                    }
                })
                .build()
            return SupportOpenHelperFactory(key).create(config)
        }

        /** `GhostDatabase.finishOpen`'s steps: memory security, WAL, R-K1's checkpoint, integrity. */
        fun finishOpen(sql: SqlExecutor) {
            sql.exec("PRAGMA cipher_memory_security = ON")
            sql.query("PRAGMA journal_mode = WAL") { }
            Checkpoint.truncate(sql)
            MigrationRunner(sql).verifyIntegrity()
        }

        /**
         * A valid v3 onion address for relay [seed]. The checksum is SHA3-256 through Bouncy
         * Castle's `SHA3Digest`, the digest `OnionAddress.parse` itself checks it with: Android's
         * providers have no `MessageDigest` "SHA3-256" (the JVM's has), and the first emulator run
         * failed every test of this suite in its setup on it (design §22.32).
         */
        fun onion(seed: Int): OnionAddress {
            val publicKey = ByteArray(32) { (seed * 13 + it * 5 + 1).toByte() }
            val prefix = ".onion checksum".toByteArray(Charsets.US_ASCII)
            val md = SHA3Digest(256)
            md.update(prefix, 0, prefix.size)
            md.update(publicKey, 0, publicKey.size)
            md.update(3.toByte())
            val checksum = ByteArray(32).also { md.doFinal(it, 0) }
            val raw = publicKey + byteArrayOf(checksum[0], checksum[1], 3)
            return OnionAddress.parse(base32(raw) + ".onion:443")
        }

        fun operator(i: Int): ByteArray = ByteArray(16) { (0x40 + i).toByte() }

        private fun base32(bytes: ByteArray): String {
            val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
            val out = StringBuilder()
            var buffer = 0
            var bits = 0
            for (b in bytes) {
                buffer = (buffer shl 8) or (b.toInt() and 0xff)
                bits += 8
                while (bits >= 5) {
                    bits -= 5
                    out.append(alphabet[(buffer shr bits) and 31])
                }
            }
            if (bits > 0) out.append(alphabet[(buffer shl (5 - bits)) and 31])
            return out.toString()
        }
    }

    /** The platform CSPRNG, as the app wires it. */
    object SecureDmRandom : DmRandom {
        private val random = SecureRandom()

        override fun bytes(count: Int): ByteArray = ByteArray(count).also(random::nextBytes)
    }

    /** `:sync`'s random port with fixed draws: no assertion here depends on a schedule draw. */
    object FixedSources : RandomSources {
        override fun schedule(pair: PairKey, purpose: SchedulePurpose, index: Long): Double = 0.5

        override fun readBreaker(relay: org.ghost.sync.api.RelayId, index: Long): Double = 0.5

        override fun sendDelay(): Double = 0.0

        override fun selection(): Double = 0.5

        override fun quietRun(index: Long): Double = 0.5

        override fun paymentHold(index: Long): Double = 0.5

        override fun requestId(): ByteArray = ByteArray(16).also(SecureRandom()::nextBytes)
    }
}
