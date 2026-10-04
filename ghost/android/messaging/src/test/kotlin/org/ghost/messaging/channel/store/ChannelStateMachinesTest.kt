package org.ghost.messaging.channel.store

import org.ghost.storage.ChannelFixture
import org.ghost.storage.chBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Kotlin state machines of [ChannelStates] against the triggers of migration 7, pair by pair (Phase 10
 * design §6.11): for every (from, to) the enum's `allows` and the database must say the same, so the two
 * statements of one machine cannot drift. And [Fields] against the CHECKs it mirrors, on the boundary values:
 * a value the store lets through must be one the schema stores, and one it refuses must be one the schema would
 * refuse (a store that is stricter than the schema is fine, one that is looser is a typed error lost).
 */
class ChannelStateMachinesTest {

    private fun attempt(f: ChannelFixture, sql: String, vararg args: Any?): Boolean =
        try {
            f.db.exec(sql, args.toList())
            true
        } catch (e: java.sql.SQLException) {
            false
        }

    @Test
    fun theChannelMachineAgreesWithItsTriggerOnEveryPair() {
        var agreed = 0
        for (from in ChannelState.entries) for (to in ChannelState.entries) ChannelFixture().use { f ->
            f.put("ch_channel", "state" to from.sql)
            val accepted = attempt(f, "UPDATE ch_channel SET state = ? WHERE channel_id = ?", to.sql, ChannelFixture.CH)
            assertEquals("${from.sql} -> ${to.sql}", from.allows(to), accepted)
            agreed++
        }
        assertEquals(81, agreed)
    }

    @Test
    fun theGenerationMachineAgreesWithItsTriggerOnEveryPair() {
        for (from in GenerationState.entries) for (to in GenerationState.entries) ChannelFixture().use { f ->
            f.put(
                "ch_generation", "state" to from.sql,
                "switch_hour" to if (from == GenerationState.PENDING_SWITCH) 3_600L else null,
                "drain_until_day" to if (from == GenerationState.DRAINING) 20_014L else null,
            )
            val set = when (to) {
                GenerationState.PENDING_SWITCH -> "state = 'pending_switch', switch_hour = 3600, drain_until_day = NULL"
                GenerationState.CURRENT -> "state = 'current', switch_hour = NULL, drain_until_day = NULL"
                GenerationState.DRAINING -> "state = 'draining', switch_hour = NULL, drain_until_day = 20014"
            }
            assertEquals("${from.sql} -> ${to.sql}", from.allows(to), attempt(f, "UPDATE ch_generation SET $set"))
        }
    }

    @Test
    fun theEpochMachineAgreesWithItsTriggerOnEveryPair() {
        for (from in EpochState.entries) for (to in EpochState.entries) ChannelFixture().use { f ->
            f.put(
                "ch_epoch", "state" to from.sql, "final_day" to if (from == EpochState.FINAL) 20_000L else null,
            )
            val set = if (to == EpochState.FINAL) "state = 'final', final_day = 20000" else "state = 'open', final_day = NULL"
            assertEquals("${from.sql} -> ${to.sql}", from.allows(to), attempt(f, "UPDATE ch_epoch SET $set"))
        }
    }

    @Test
    fun thePostMachineAgreesWithItsTriggerOnEveryPairTheDisplayEdgeIncluded() {
        for (from in PostState.entries) for (to in PostState.entries) ChannelFixture().use { f ->
            f.put(
                "ch_post", "direction" to if (from.outgoing) "out" else "in", "state" to from.sql,
                "displayed_minute" to if (from == PostState.READ) 660L else null,
            )
            val set = if (to == PostState.READ) "state = 'read', displayed_minute = 660" else "state = '${to.sql}'"
            assertEquals("${from.sql} -> ${to.sql}", from.allows(to), attempt(f, "UPDATE ch_post SET $set"))
        }
    }

    @Test
    fun everyEnumNamesExactlyTheValuesOfItsColumnsCheck() {
        ChannelFixture().use { f ->
            fun accepted(table: String, column: String, value: String, vararg with: Pair<String, Any?>): Boolean {
                f.db.exec("DELETE FROM ch_channel")
                f.parents(table)
                val (sql, args) = f.sql(table, mapOf(column to value, *with))
                return attempt(f, sql, *args.toTypedArray())
            }
            // every value of the enum is stored by its column, and a value outside is refused
            for (s in ChannelState.entries) assertTrue(s.sql, accepted("ch_channel", "state", s.sql))
            assertEquals(false, accepted("ch_channel", "state", "bogus"))
            for (s in GenerationState.entries) {
                val with = when (s) {
                    GenerationState.PENDING_SWITCH -> arrayOf("switch_hour" to 3_600L)
                    GenerationState.DRAINING -> arrayOf("drain_until_day" to 20_014L)
                    else -> emptyArray()
                }
                assertTrue(s.sql, accepted("ch_generation", "state", s.sql, *with))
            }
            for (s in EpochState.entries) {
                val with = if (s == EpochState.FINAL) arrayOf<Pair<String, Any?>>("final_day" to 20_000L) else emptyArray()
                assertTrue(s.sql, accepted("ch_epoch", "state", s.sql, *with))
            }
            for (s in PostState.entries) {
                val with = arrayOf<Pair<String, Any?>>(
                    "direction" to if (s.outgoing) "out" else "in",
                    "displayed_minute" to if (s == PostState.READ) 660L else null,
                )
                assertTrue(s.sql, accepted("ch_post", "state", s.sql, *with))
            }
            for (d in Direction.entries) assertTrue(d.sql, accepted("ch_reveal", "direction", d.sql))
            for (t in JoinType.entries) {
                val with = arrayOf<Pair<String, Any?>>("invite_id" to if (t.hasInvite) chBytes(16, 27) else null)
                // Slice S4 (§19.35 F-8): a join or a restore carries its invite's state, a rejoin none of it.
                val state = if (t.hasInvite) {
                    emptyArray()
                } else {
                    arrayOf<Pair<String, Any?>>("ns" to null, "jk_env" to null, "r_join" to null, "committers_digest" to null)
                }
                assertTrue(t.sql, accepted("ch_join", "type", t.sql, *with, *state))
                assertTrue(t.sql, accepted("ch_join_request", "type", t.sql, *with))
            }
            for (p in OpPurpose.entries) assertTrue(p.sql, accepted("ch_outbound_op", "purpose", p.sql))
            for (k in RequestKind.entries) assertTrue(k.sql, accepted("ch_request", "kind", k.sql))
        }
        assertEquals(9, ChannelState.entries.size)
        assertEquals(7, PostState.entries.size)
        assertEquals(setOf("queued", "sent", "degraded", "failed", "indeterminate"), PostState.entries.filter { it.outgoing }.map { it.sql }.toSet())
    }

    // ------------------------------------------------------------------ Fields against the CHECKs

    private class Probe(
        val table: String,
        val column: String,
        val values: List<Any?>,
        val with: Map<String, Any?> = emptyMap(),
        val check: (Any?) -> Unit,
    )

    @Test
    fun theStoresInputChecksNeverLetThroughWhatTheSchemaRefuses() {
        val probes = listOf(
            Probe("ch_channel", "generation", listOf(-1L, 0L, 4_294_967_295L, 4_294_967_296L)) { Fields.u32("x", it as Long) },
            Probe("ch_channel", "epoch", listOf(-1L, 0L, Long.MAX_VALUE)) { Fields.nonNegative("x", it as Long) },
            Probe("ch_post", "author_minute", listOf(0L, 60L, 61L, 3_599L, 1_800_000_000L, 1_800_000_030L)) { Fields.minute("x", it as Long) },
            Probe("ch_pending_post", "fail_after_hour", listOf(0L, 3_600L, 3_601L, 1_800_000_000L, 1_800_000_060L)) { Fields.hour("x", it as Long) },
            Probe("ch_seen", "until_day", listOf(-7L, 0L, 1L, 6L, 7L, 19_999L, 20_000L, 20_006L)) { Fields.week("x", it as Long) },
            Probe("ch_candidate", "rank", listOf(-1L, 0L, 255L, 256L)) { Fields.rangeInt("x", (it as Long).toInt(), 0, 255) },
            Probe("ch_channel", "timer_code", listOf(-1L, 0L, 5L, 6L)) { Fields.rangeInt("x", (it as Long).toInt(), 0, 5) },
            Probe("ch_channel", "name_env", listOf(28, 29, 76, 77).map { chBytes(it, 1) }) { Fields.bytesBetween("x", it as ByteArray, 29, 76) },
            Probe("ch_request", "subject", listOf(0, 1, 32, 33).map { chBytes(it, 1) }) { Fields.bytesBetween("x", it as ByteArray, 1, 32) },
            Probe("ch_generation", "g_env", listOf(59, 60, 61).map { chBytes(it, 1) }) { Fields.bytes("x", it as ByteArray, 60) },
            Probe("ch_epoch", "k_env", listOf(67, 68, 69).map { chBytes(it, 1) }) { Fields.bytes("x", it as ByteArray, 68) },
        )
        var compared = 0
        for (p in probes) for (value in p.values) ChannelFixture().use { f ->
            f.parents(p.table)
            val (sql, args) = f.sql(p.table, p.with + (p.column to value))
            val schemaAccepts = attempt(f, sql, *args.toTypedArray())
            val fieldsAccept = try {
                p.check(value)
                true
            } catch (e: ChannelStoreException) {
                false
            }
            assertEquals("${p.table}.${p.column} = ${if (value is ByteArray) "${value.size} bytes" else value}", schemaAccepts, fieldsAccept)
            compared++
        }
        assertTrue(compared > 35)
    }
}
