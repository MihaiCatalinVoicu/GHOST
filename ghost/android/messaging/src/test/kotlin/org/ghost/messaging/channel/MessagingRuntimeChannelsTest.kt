package org.ghost.messaging.channel

import org.ghost.identity.RootEntropy
import org.ghost.messaging.DmWorld
import org.ghost.messaging.FakeKeyWrapper
import org.ghost.messaging.FixedRandomSources
import org.ghost.messaging.MovableClock
import org.ghost.messaging.OwnerWorld
import org.ghost.messaging.RecordingCheckpoint
import org.ghost.messaging.RecordingWake
import org.ghost.messaging.SequentialRandom
import org.ghost.messaging.api.CreateResult
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.store.ChannelStores
import org.ghost.messaging.engine.DmKeys
import org.ghost.messaging.engine.MessagingRuntime
import org.ghost.messaging.port.ChannelPorts
import org.ghost.messaging.port.ChannelSeeds
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.store.SyncStores
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * The channel engine **inside the stack `:app` runs** (Phase 10 design §10.1, D16; slice S4): `MessagingRuntime` built
 * with [ChannelPorts] puts it on the DM actor, over the DM database and the DM content key. Its user actions run on the
 * actor; its pass runs at the end of every actor pass; a lock closes its context with the DM's. Without the ports the
 * runtime is the Phase 9 stack, which `MessagingRuntimeTest` keeps covering.
 */
class MessagingRuntimeChannelsTest {

    private lateinit var sql: JdbcSqlExecutor
    private lateinit var runtime: MessagingRuntime

    /** Every pass ends by re-arming the alarm (`ExpirySchedule.afterCommit`): its requests count the actor's passes. */
    private val alarm = RecordingWake()

    private val rootBytes = ByteArray(32) { (it * 11 + 5).toByte() }

    private fun root(): RootEntropy = RootEntropy.fromRaw(rootBytes)

    @Before
    fun setUp() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", DmWorld.nativeAvailable() && ChannelWorld.nativeAvailable())
        sql = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
        val database = SyncDatabase(sql)
        val clock = MovableClock(DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY)
        val stores = SyncStores(database, clock, FixedRandomSources()) { PrivacyMode.STANDARD }
        val ids = database.transaction { tx ->
            stores.relayDirectory.upsert(
                tx,
                (0 until 4).map { i -> RelayEntry(OwnerWorld.onion(i), OwnerWorld.operatorId(i % 2), RelayEntry.Source.CONFIG) },
            )
        }
        val slots = (0 until 4).map { i -> EsSlot(i, ids.getValue(OwnerWorld.onion(i)), OwnerWorld.operatorId(i % 2)) }
        runtime = MessagingRuntime(
            stores = stores,
            keys = DmKeys(stateKeys = FakeKeyWrapper(), random = SequentialRandom(stream = "runtime-channels-state")),
            contentKeys = FakeKeyWrapper(),
            esSlots = EsSlots { slots },
            clock = clock,
            random = SequentialRandom(stream = "runtime-channels"),
            alarm = alarm,
            checkpoint = RecordingCheckpoint { org.ghost.storage.Checkpoint.truncate(sql) },
            channelPorts = ChannelPorts(
                seeds = ChannelSeeds { c -> ChannelWorld.sha256("seed:" + ChannelWorld.hex(c)) },
                stateKeys = FakeKeyWrapper(),
            ),
        )
    }

    @After
    fun tearDown() {
        if (::runtime.isInitialized) runtime.close()
        if (::sql.isInitialized) sql.close()
    }

    private fun count(table: String, where: String = "1 = 1"): Long {
        var n = 0L
        sql.query("SELECT count(*) FROM $table WHERE $where") { n = it.long(0) }
        return n
    }

    /** A facade call queues behind every pass posted before it: the actor's single thread. */
    private fun barrier() {
        runtime.messaging.status()
    }

    @Test
    fun theChannelEngineRunsOnTheActorAndItsPassEndsEveryActorPass() {
        assertEquals(DmKeys.Opened.OPENED, runtime.unlock(::root))
        // a database open: ACTIVATE writes dm_self, whose content and seen keys the channel engine shares
        runtime.onTimeTrigger()
        barrier()
        val engine = requireNotNull(runtime.channelEngine) { "the ports build the channel engine" }
        val created = engine.create("salon".toByteArray(), 4, 0, false)
        assertEquals(CreateResult.Status.CREATED, created.status)
        val id = requireNotNull(created.channel)
        val summary = requireNotNull(runtime.channels).channels().single()
        assertEquals("salon", summary.name)
        assertEquals(false, summary.passwordProtected)
        assertEquals(ChannelWorld.hex(id.toByteArray()), ChannelWorld.hex(summary.channelId))
        val members = requireNotNull(runtime.channels).members(id)
        assertEquals(1, members.size)
        assertEquals(true, members.single().committer)
        assertEquals(true, members.single().mine)
        val fingerprint = requireNotNull(runtime.channels).fingerprint(id)!!
        assertEquals(0L, fingerprint.epoch)
        assertEquals(8, fingerprint.code.size)
        assertEquals("CH-CREATE registered the channel's namespace", 1L, count("sync_namespace", "consumer = 'channel' AND listening = 1"))
        // A post the removal hold keeps pending (CO-13) …
        val c = id.toByteArray()
        val stores = ChannelStores()
        val hash = ChannelWorld.sha256("a removing candidate")
        SyncDatabase(sql).transaction { tx ->
            stores.candidates.insert(tx, c, 0, hash, ChannelWorld.sha256("someone"), 0, false, ByteArray(64), 0, removes = true)
        }
        assertEquals(PostResult.QUEUED, engine.post(id, "salut".toByteArray(), null))
        assertEquals(1L, count("ch_pending_post"))
        // … is encrypted by the channel pass that ends the actor's next pass, once the hold is gone
        SyncDatabase(sql).transaction { tx -> stores.candidates.delete(tx, c, 0, hash) }
        runtime.onTimeTrigger()
        barrier()
        assertEquals(0L, count("ch_pending_post"))
        assertEquals(1L, count("ch_post", "state = 'queued'"))
        // the lock closes the channel context with the DM's
        runtime.lock()
        assertEquals(PostResult.CRYPTO_UNAVAILABLE, engine.post(id, "après".toByteArray(), null))
    }

    /**
     * §19.38 (the review of S4, finding 3), on the runtime's real actor and in-process timer: an own commit still waiting
     * for its outcome past its settle point. The first version made the settle point a wake at once after every pass — the
     * review counted 638 actor passes in two seconds; a quiet runtime makes none.
     */
    @Test
    fun anOwnCommitWaitingForItsOutcomeDoesNotSpinTheActor() {
        assertEquals(DmKeys.Opened.OPENED, runtime.unlock(::root))
        runtime.onTimeTrigger()
        barrier()
        val engine = requireNotNull(runtime.channelEngine)
        val created = engine.create("salon".toByteArray(), 4, 0, false)
        assertEquals(CreateResult.Status.CREATED, created.status)
        val c = requireNotNull(created.channel).toByteArray()
        // the state every admission commit is in between its pass and its outcome, an hour past its settle point
        val minute = Math.floorDiv(DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY, DmWorld.MINUTE) * DmWorld.MINUTE
        val stores = ChannelStores()
        SyncDatabase(sql).transaction { tx ->
            stores.candidates.insert(tx, c, 0, ChannelWorld.sha256("an own commit"), ChannelWorld.sha256("me"), 0, true, ByteArray(64), minute - 3_600)
            stores.epochs.setAnchor(tx, c, 0, minute - 3_600)
        }
        runtime.onTimeTrigger()
        barrier()
        val before = alarm.requested.size
        Thread.sleep(1_500)
        barrier()
        val passes = alarm.requested.size - before
        assertTrue("the actor spun: $passes passes in 1.5 s", passes <= 3)
    }
}
