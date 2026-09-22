package org.ghost.app

import org.ghost.network.OnionAddress
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.port.SyncClock
import org.ghost.sync.store.SyncStores
import java.security.MessageDigest

/** A clock the test moves by hand, for `:sync` and the DM layer at once. */
class TestClock(var now: Long) : SyncClock, org.ghost.messaging.port.DmClock {
    var monotonic: Long = 0

    override fun epochSeconds(): Long = now

    override fun monotonicMillis(): Long = monotonic

    override fun nowEpochSeconds(): Long = now
}

/** A real migrated database and the sync stores over it: what the sync runtime opens on a device. */
class TestDatabase(clock: TestClock = TestClock(1_800_000_000L)) : AutoCloseable {
    val sql: JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
    val database = SyncDatabase(sql)
    val stores = SyncStores(database, clock, KeyedRandomSources(ByteArray(32) { 5 })) { PrivacyMode.STANDARD }

    override fun close() = sql.close()
}

object Onions {
    /** A syntactically valid v3 onion address (checksum and version byte) for [seed]. */
    fun onion(seed: Int, port: Int = 443): OnionAddress {
        val publicKey = ByteArray(32) { (seed * 13 + it * 5 + 1).toByte() }
        val md = MessageDigest.getInstance("SHA3-256")
        md.update(".onion checksum".toByteArray(Charsets.US_ASCII))
        md.update(publicKey)
        md.update(3.toByte())
        val checksum = md.digest()
        val raw = publicKey + byteArrayOf(checksum[0], checksum[1], 3)
        return OnionAddress.parse(base32(raw) + ".onion:" + port)
    }

    fun operatorId(i: Int): ByteArray = ByteArray(16) { (0x40 + i).toByte() }

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
