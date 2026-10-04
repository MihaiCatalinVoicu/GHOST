package org.ghost.messaging.channel.store

import org.ghost.storage.chBytes
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * `mls_kv` and `mls_global_kv` through [MlsKvStore] (Phase 10 design §3.4, §9; slice S3): the rows `GhostKv`
 * reads and writes, **applied as a change-set in the caller's transaction** and **loaded whole for a call**.
 * The first test pins the store to `ghost-client-mls`'s own source (`client-core/mls/src/kv.rs`, read here and
 * not changed), so a scope byte or a key alphabet that moves on the Rust side fails this build.
 */
class MlsKvStoreTest {

    private val today = 20_000L

    /** A key as `GhostKv` writes it: `label ‖ 0x00 ‖ json` (the JSON of a group id is a list of 32 numbers). */
    private fun groupKey(label: String, i: Int = 0): ByteArray =
        label.toByteArray() + byteArrayOf(0) + """{"value":{"vec":[${(0 until 32).joinToString(",") { ((it + i) % 256).toString() }}]}}""".toByteArray()

    private fun env(size: Int, fill: Int) = chBytes(size, fill)

    private fun change(scope: MlsKvStore.Scope, key: ByteArray, env: ByteArray?) = MlsKvStore.KvChange(scope, key, env)

    // ---------------------------------------------------------------- the contract with kv.rs

    private val kvRs = File("../../client-core/mls/src/kv.rs")

    @Test
    fun theScopeBytesAndTheKeyAlphabetsAreTheOnesOfTheRustAdapter() {
        assertTrue("the adapter's source is not where the contract test reads it: ${kvRs.absolutePath}", kvRs.isFile)
        val source = kvRs.readText()
        // `enum Scope { Group = 1, Global = 2 }`: the byte that binds the envelope's associated data
        val scope = Regex("pub enum Scope \\{([^}]*)\\}").find(source)!!.groupValues[1]
        assertEquals(1, Regex("Group = (\\d+)").find(scope)!!.groupValues[1].toInt())
        assertEquals(2, Regex("Global = (\\d+)").find(scope)!!.groupValues[1].toInt())
        assertEquals(MlsKvStore.Scope.GROUP.tag, 1)
        assertEquals(MlsKvStore.Scope.GLOBAL.tag, 2)
        // the labels: 15 group-scoped, 4 global, each a quoted ASCII word; a key is `label NUL json` (a BLOB)
        fun labels(array: String): List<String> {
            val body = Regex("const $array: \\[&\\[u8\\]; (\\d+)\\] = \\[([^\\]]*)\\];").find(source)!!
            val names = Regex("L_[A-Z_]+").findAll(body.groupValues[2]).map { it.value }.toList()
            assertEquals(body.groupValues[1].toInt(), names.size)
            return names.map { name -> Regex("const $name: &\\[u8\\] = b\"([A-Za-z]+)\";").find(source)!!.groupValues[1] }
        }
        val group = labels("GROUP_LABELS")
        val global = labels("GLOBAL_LABELS")
        assertEquals(15, group.size)
        assertEquals(setOf("KeyPackage", "EncryptionKeyPair", "SignatureKeyPair", "Psk"), global.toSet())
        assertTrue("MessageSecretsPast" in group && "Tree" in group && "GroupContext" in group)
        // the associated data of a wrapped row: scope, channel id and the hash of the key, under this label
        assertTrue(source.contains("b\"ghost/v1/mls-kv\""))
        // One representative key of each label (the JSON of a 32-byte id) fits the column and has its NUL after the
        // label. This is what is measured, and no more: kv.rs enforces no bound on a key, so the column's CHECK
        // (2 to 1 024 bytes, a bound of this slice's) is the only one, and a key of a label whose argument is longer
        // than a 32-byte id would fail the transaction that writes it (the review of S3: the first version of this
        // comment said that every key the adapter writes fits).
        for (label in group + global) {
            val key = groupKey(label)
            assertTrue("$label key of ${key.size} bytes", key.size in 2..MlsKvStore.MAX_KEY)
            assertEquals(0, key[label.length].toInt())
        }
        // the one global label whose rows are a KeyPackage's, and so die on a day, is the adapter's L_KEY_PACKAGE
        assertEquals(
            String(MlsKvStore.KEY_PACKAGE_LABEL),
            Regex("const L_KEY_PACKAGE: &\\[u8\\] = b\"([A-Za-z]+)\";").find(source)!!.groupValues[1],
        )
        // the envelope's floor: nonce(12) ‖ tag(16)
        assertTrue(source.contains("env.len() < 12 + 16"))
        assertEquals(28, MlsKvStore.MIN_ENV)
    }

    // ---------------------------------------------------------------- applying a change-set

    @Test
    fun aChangeSetIsAppliedAsPutsAndDeletesAndTheNulOfTheKeyIsKept() = StoreWorld().use { w ->
        w.channel()
        val tree = groupKey("Tree")
        val context = groupKey("GroupContext")
        val applied = w.tx {
            w.stores.mls.apply(
                it, w.ch,
                listOf(change(MlsKvStore.Scope.GROUP, tree, env(5_000, 1)), change(MlsKvStore.Scope.GROUP, context, env(300, 2))),
            )
        }
        assertEquals(2, applied.puts)
        assertEquals(0, applied.deletes)
        // the key is a BLOB that holds a NUL byte, and comes back byte for byte
        val rows = w.stores.mls.rows(w.db, w.ch, today)
        assertEquals(2, rows.size)
        assertTrue(rows.all { it.scope == MlsKvStore.Scope.GROUP })
        assertArrayEquals(env(5_000, 1), rows.single { it.key.contentEquals(tree) }.env)
        assertEquals("blob", w.db.queryString("SELECT typeof(k) FROM mls_kv LIMIT 1"))
        // a later call overwrites the one and deletes the other (the net change-set of that call)
        val second = w.tx {
            w.stores.mls.apply(
                it, w.ch,
                listOf(change(MlsKvStore.Scope.GROUP, tree, env(5_100, 3)), change(MlsKvStore.Scope.GROUP, context, null)),
            )
        }
        assertEquals(1, second.puts)
        assertEquals(1, second.deletes)
        assertEquals(1L, w.count("mls_kv"))
        assertArrayEquals(env(5_100, 3), w.stores.mls.rows(w.db, w.ch, today).single().env)
        // a delete of a row that is not there is no error: the call created and removed it
        assertEquals(0, w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GROUP, groupKey("Tree", 9), null))) }.deletes)
        assertEquals(1, w.stores.mls.groupRowCount(w.db, w.ch))
        assertRedacted(rows.first(), tree, env(5_000, 1), w.ch)
        assertRedacted(change(MlsKvStore.Scope.GROUP, tree, env(5_000, 1)), tree, env(5_000, 1))
    }

    @Test
    fun theChangeSetSharesTheCallersTransactionAndIsUndoneWithIt() = StoreWorld().use { w ->
        w.channel()
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GROUP, groupKey("Tree"), env(100, 1)))) }
        assertThrows(IllegalStateException::class.java) {
            w.tx {
                w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GROUP, groupKey("Tree"), env(100, 2)), change(MlsKvStore.Scope.GROUP, groupKey("GroupContext"), env(100, 3))))
                // the post row of the same transaction fails: nothing of the change-set stays
                error("the transaction failed after the change-set")
            }
        }
        assertEquals(1L, w.count("mls_kv"))
        assertArrayEquals(env(100, 1), w.stores.mls.rows(w.db, w.ch, today).single().env)
    }

    @Test
    fun globalRowsAreTaggedWithTheChannelCarryTheirDayAndAreNotLoadedPastIt() = StoreWorld().use { w ->
        w.channel()
        w.channel(w.ch2)
        val keyPackage = groupKey("KeyPackage", 1)
        val keyPair = groupKey("EncryptionKeyPair", 2)
        w.tx {
            w.stores.mls.apply(
                it, w.ch,
                listOf(change(MlsKvStore.Scope.GLOBAL, keyPackage, env(900, 1)), change(MlsKvStore.Scope.GLOBAL, keyPair, env(120, 2))),
                globalDeleteAfterDay = 20_007,
            )
        }
        w.tx { w.stores.mls.apply(it, w.ch2, listOf(change(MlsKvStore.Scope.GLOBAL, groupKey("KeyPackage", 3), env(900, 3))), globalDeleteAfterDay = 20_010) }
        assertEquals(2L, w.db.queryLong("SELECT count(*) FROM mls_global_kv WHERE channel_id = ?", listOf(w.ch)))
        assertEquals(20_007L, w.db.queryLong("SELECT delete_after_day FROM mls_global_kv WHERE channel_id = ? LIMIT 1", listOf(w.ch)))
        assertEquals(20_010L, w.db.queryLong("SELECT delete_after_day FROM mls_global_kv WHERE channel_id = ?", listOf(w.ch2)))
        // a call on a channel loads its group rows and the global rows tagged with it, and no other channel's
        val rows = w.stores.mls.rows(w.db, w.ch, today)
        assertEquals(2, rows.size)
        assertTrue(rows.all { it.scope == MlsKvStore.Scope.GLOBAL })
        assertEquals(1, w.stores.mls.rows(w.db, w.ch2, today).size)
        // the day: kept through it, gone from the next day on (the private keys of an expired KeyPackage are not handed to a call)
        assertEquals(2, w.stores.mls.globalRows(w.db, w.ch, 20_007).size)
        assertEquals(0, w.stores.mls.globalRows(w.db, w.ch, 20_008).size)
        assertEquals(1, w.stores.mls.rows(w.db, w.ch2, 20_010).size)
        assertEquals(0, w.stores.mls.rows(w.db, w.ch2, 20_011).size)
        assertEquals(2, w.stores.mls.expiredGlobal(w.db, 20_008, 10).size)
        assertEquals(1, w.stores.mls.expiredGlobal(w.db, 20_008, 1).size)
        assertEquals(0, w.stores.mls.expiredGlobal(w.db, 20_007, 10).size)
        // an update keeps the row's day unless the call gives an earlier one
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, keyPackage, env(901, 4)))) }
        assertEquals(20_007L, w.db.queryLong("SELECT delete_after_day FROM mls_global_kv WHERE k = ?", listOf(keyPackage)))
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, keyPackage, env(902, 5))), globalDeleteAfterDay = 20_003) }
        assertEquals(20_003L, w.db.queryLong("SELECT delete_after_day FROM mls_global_kv WHERE k = ?", listOf(keyPackage)))
        assertTrue(w.tx { w.stores.mls.deleteGlobal(it, keyPackage) })
        assertEquals(1L, w.db.queryLong("SELECT count(*) FROM mls_global_kv WHERE channel_id = ?", listOf(w.ch)))
    }

    /**
     * The private keys of a KeyPackage live until it is used or expires, and a day that moves later - or is missing -
     * keeps them. The review of S3 showed both: a re-put moved the day later (`COALESCE` took the call's), and a
     * `KeyPackage` row stored with no day was loaded at any day and kept until the channel went. A put now keeps the
     * earlier of the two days, and a new `KeyPackage` row without a day is refused.
     */
    @Test
    fun aKeyPackageRowAlwaysHasADayAndADayNeverMovesLater() = StoreWorld().use { w ->
        w.channel()
        val keyPackage = groupKey("KeyPackage", 1)
        val keyPair = groupKey("EncryptionKeyPair", 2)
        // no day, no KeyPackage row; nothing of the change-set before or after it stays
        assertEquals(
            ChannelStoreError.BAD_VALUE,
            assertThrows(ChannelStoreException::class.java) {
                w.tx {
                    w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, keyPair, env(120, 1)), change(MlsKvStore.Scope.GLOBAL, keyPackage, env(900, 2))))
                }
            }.error,
        )
        assertEquals(0L, w.count("mls_global_kv"))
        // a key pair written by a commit's update path has no day of its own: it is deleted when the commit is merged
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, keyPair, env(120, 1)))) }
        assertEquals(null, w.db.queryLong("SELECT delete_after_day FROM mls_global_kv WHERE k = ?", listOf(keyPair)))
        // the KeyPackage with its day
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, keyPackage, env(900, 2))), globalDeleteAfterDay = 20_007) }
        // a re-put that names a later day, or none, leaves the day; an earlier one lowers it
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, keyPackage, env(901, 3))), globalDeleteAfterDay = 20_030) }
        assertEquals(20_007L, w.db.queryLong("SELECT delete_after_day FROM mls_global_kv WHERE k = ?", listOf(keyPackage)))
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, keyPackage, env(902, 4)))) }
        assertEquals(20_007L, w.db.queryLong("SELECT delete_after_day FROM mls_global_kv WHERE k = ?", listOf(keyPackage)))
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, keyPackage, env(903, 5))), globalDeleteAfterDay = 20_001) }
        assertEquals(20_001L, w.db.queryLong("SELECT delete_after_day FROM mls_global_kv WHERE k = ?", listOf(keyPackage)))
        // a row that was written with no day gets the call's first day
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, keyPair, env(121, 6))), globalDeleteAfterDay = 20_005) }
        assertEquals(20_005L, w.db.queryLong("SELECT delete_after_day FROM mls_global_kv WHERE k = ?", listOf(keyPair)))
        assertArrayEquals(env(903, 5), w.stores.mls.globalRows(w.db, w.ch, 20_001).single { it.key.contentEquals(keyPackage) }.env)
    }

    @Test
    fun aGlobalKeyBelongsToOneChannelAndAGroupRowToItsOwn() = StoreWorld().use { w ->
        w.channel()
        w.channel(w.ch2)
        val shared = groupKey("KeyPackage", 5)
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, shared, env(100, 1))), globalDeleteAfterDay = 20_007) }
        // the same key under another channel is the key of someone else's KeyPackage: refused, nothing written
        assertEquals(
            ChannelStoreError.ROW_EXISTS,
            assertThrows(ChannelStoreException::class.java) {
                w.tx { w.stores.mls.apply(it, w.ch2, listOf(change(MlsKvStore.Scope.GLOBAL, shared, env(100, 2))), globalDeleteAfterDay = 20_007) }
            }.error,
        )
        // another channel's delete of it matches nothing
        assertEquals(0, w.tx { w.stores.mls.apply(it, w.ch2, listOf(change(MlsKvStore.Scope.GLOBAL, shared, null))) }.deletes)
        assertEquals(1L, w.count("mls_global_kv"))
        // group rows are per channel: the same key under two channels is two rows
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GROUP, groupKey("Tree"), env(100, 1)))) }
        w.tx { w.stores.mls.apply(it, w.ch2, listOf(change(MlsKvStore.Scope.GROUP, groupKey("Tree"), env(100, 2)))) }
        assertEquals(2L, w.count("mls_kv"))
        assertArrayEquals(env(100, 2), w.stores.mls.rows(w.db, w.ch2, today).single { it.scope == MlsKvStore.Scope.GROUP }.env)
    }

    @Test
    fun aRejoinReplacesTheGroupRowsAndKeepsTheKeyPackageRowsForTheWelcome() = StoreWorld().use { w ->
        w.channel()
        w.tx {
            w.stores.mls.apply(
                it, w.ch,
                (0 until 11).map { i -> change(MlsKvStore.Scope.GROUP, groupKey("Tree", i), env(200, i)) } +
                    change(MlsKvStore.Scope.GLOBAL, groupKey("KeyPackage", 1), env(900, 1)),
                globalDeleteAfterDay = 20_007,
            )
        }
        assertEquals(11, w.stores.mls.groupRowCount(w.db, w.ch))
        // CH-JOIN of a rejoin: the old group's rows are not passed to welcomeJoin and are deleted in the same transaction ...
        val passed = w.stores.mls.globalRows(w.db, w.ch, today)
        assertEquals(1, passed.size)
        w.tx {
            assertEquals(11, w.stores.mls.deleteGroupRows(it, w.ch))
            // ... then the Welcome's change-set is applied: the new group's rows, and the KeyPackage's rows deleted
            w.stores.mls.apply(
                it, w.ch,
                listOf(change(MlsKvStore.Scope.GROUP, groupKey("Tree", 99), env(300, 9)), change(MlsKvStore.Scope.GLOBAL, groupKey("KeyPackage", 1), null)),
            )
        }
        assertEquals(1, w.stores.mls.groupRowCount(w.db, w.ch))
        assertEquals(0L, w.count("mls_global_kv"))
        // a join that expires: the KeyPackage's private keys go
        w.tx { w.stores.mls.apply(it, w.ch, listOf(change(MlsKvStore.Scope.GLOBAL, groupKey("KeyPackage", 2), env(900, 2))), globalDeleteAfterDay = 20_007) }
        assertEquals(1, w.tx { w.stores.mls.deleteGlobalRows(it, w.ch) })
        assertFalse(w.stores.mls.rows(w.db, w.ch, today).any { it.scope == MlsKvStore.Scope.GLOBAL })
    }

    @Test
    fun theSizesOfAKeyAndAnEnvelopeAreCheckedBeforeAnyRowIsWritten(): Unit = StoreWorld().use { w ->
        w.channel()
        fun refused(vararg changes: MlsKvStore.KvChange) {
            val e = assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.mls.apply(it, w.ch, changes.toList()) } }
            assertEquals(ChannelStoreError.BAD_VALUE, e.error)
        }
        val ok = change(MlsKvStore.Scope.GROUP, groupKey("Tree"), env(100, 1))
        refused(ok, change(MlsKvStore.Scope.GROUP, byteArrayOf(1), env(100, 1)))
        refused(ok, change(MlsKvStore.Scope.GROUP, chBytes(1025, 1), env(100, 1)))
        refused(ok, change(MlsKvStore.Scope.GROUP, groupKey("Context"), env(27, 1)))
        refused(ok, change(MlsKvStore.Scope.GLOBAL, groupKey("Psk"), env(4_194_305, 1)))
        assertEquals("the valid change before a refused one was not written either", 0L, w.count("mls_kv"))
        // the bounds themselves are accepted
        w.tx {
            w.stores.mls.apply(
                it, w.ch,
                listOf(
                    change(MlsKvStore.Scope.GROUP, chBytes(2, 1), env(28, 1)),
                    change(MlsKvStore.Scope.GROUP, chBytes(1024, 2), env(4_194_304, 2)),
                ),
            )
        }
        assertEquals(2L, w.count("mls_kv"))
        assertNotNull(w.stores.mls.rows(w.db, w.ch, today).firstOrNull { it.key.size == 1024 })
        // GhostKv's Scope has two values; any other byte is no scope
        assertEquals(MlsKvStore.Scope.GLOBAL, MlsKvStore.Scope.of(2))
        assertThrows(NoSuchElementException::class.java) { MlsKvStore.Scope.of(3) }
    }
}
