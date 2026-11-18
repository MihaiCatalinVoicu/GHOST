package org.ghost.messaging.device

import android.content.Context
import android.os.ParcelFileDescriptor
import org.ghost.device.DeviceRunner
import org.ghost.messaging.android.ExpiryAlarm
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.Establishment
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.messaging.api.TrustState
import org.ghost.messaging.engine.DmKeys
import org.ghost.storage.MigrationRunner
import org.ghost.storage.Schema
import org.ghost.storage.SupportSqlExecutor
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest

/**
 * **`DeviceGateSuite`** (Phase 9 design §15.9; slice S12): what the emulator adds to the JVM worlds
 * — real SQLCipher, the Android Keystore wrappers, the real `DmActor` threads, `AlarmManager`,
 * logcat, and the Android build of the DM library inside `libghost_client_net.so` (x86_64 on the
 * emulator images of `dm-emulator.yml`).
 *
 * What each case covers, by §15.9 item:
 *  - item 2 **CS-9 on the real engine**: a v3 database migrates to v4 and v5 in SQLCipher and
 *    passes `verifyIntegrity` ([aV3DatabaseMigratesToV5OnSqlcipher]);
 *  - items 2 and 4, **SCN-A**: the one-scan flow over the loopback relay, from a card to pair mode
 *    in both directions, with equal order digests on both devices ([scnA]);
 *  - item 2, **SCN-B**: six messages delivered in a shuffled order render in one order on both
 *    devices ([scnB]);
 *  - items 2 and 5, **SCN-F / T25**: a five-minute timer, SWEEP, and the SQLCipher `-wal` at zero
 *    bytes after its `TRUNCATE` ([scnF]);
 *  - item 5, **the alarm**: scheduled in the system's alarm table and cancelled, through `dumpsys
 *    alarm` ([theOneAlarmIsScheduledAndCancelled]);
 *  - items 2 and 6, **SCN-D** and the **logcat scan**: a bound new Olm identity on B holds A's view
 *    at `changed`, refuses A's send, releases on acknowledgement, and no key or plaintext canary
 *    reaches logcat ([scnDAndTheLogcatScan]).
 *
 * **Not here, recorded in §22.17:** item 1's `:peer` process and its SIGKILL at scripted points —
 * both devices share this process — and SCN-D's forged variant, which is the JVM's (`KeyChangeTest`).
 * Item 3's release smoke test is `:app`'s; item 7, the equivalence test, is `:crypto-bridge`'s.
 */
class DeviceGateSuite {

    private val context: Context get() = DeviceRunner.current.targetContext
    private lateinit var world: DeviceWorld

    @Before
    fun setUp() {
        System.loadLibrary("ghost_client_net")
        world = DeviceWorld(context, Integer.toHexString(System.identityHashCode(this)))
        assertEquals(DmKeys.Opened.OPENED, world.alice.unlock())
        assertEquals(DmKeys.Opened.OPENED, world.bob.unlock())
    }

    @After
    fun tearDown() {
        if (::world.isInitialized) world.close()
    }

    private fun activate() {
        assertEquals(ActivationOutcome.ACTIVATED, world.alice.messaging.onActivated())
        assertEquals(ActivationOutcome.ACTIVATED, world.bob.messaging.onActivated())
    }

    /** §12.2 steps 1–5: A adds B's card, sends, B accepts the request and answers. */
    private fun introduce(): Pair<ContactId, ContactId> {
        val (a, b) = world.alice to world.bob
        activate()
        assertEquals(AddContactResult.ADDED, a.messaging.addContact(b.card(), CardSource.QR_IN_PERSON))
        val contactB = a.contact()
        assertEquals(SendResult.QUEUED, a.messaging.send(contactB, "hello", null))
        assertTrue("B's bundle reaches A's P_B", world.deliver() > 0)
        a.timePass()
        world.advance(3 * DeviceWorld.MINUTE)
        a.timePass()
        assertEquals(Establishment.READY, a.messaging.contacts().single().establishment)
        world.deliver()
        b.hintPass()
        val request = b.messaging.contacts().single()
        assertEquals(TrustState.REQUEST, request.trust)
        assertTrue(b.messaging.acceptRequest(request.id))
        assertEquals(SendResult.QUEUED, b.messaging.send(request.id, "hi back", null))
        world.deliver()
        a.hintPass()
        return contactB to request.id
    }

    private fun texts(messaging: Messaging, contact: ContactId): List<String?> =
        messaging.conversation(contact, 100, null).map { it.text }

    private fun orderDigest(messaging: Messaging, contact: ContactId): String {
        val md = MessageDigest.getInstance("SHA-256")
        for (view in messaging.conversation(contact, 100, null).asReversed()) md.update(view.id.toByteArray())
        return md.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    @Test
    fun aV3DatabaseMigratesToV5OnSqlcipher() {
        System.loadLibrary("sqlcipher")
        val name = "dm-gate-migration.db"
        // Where SQLCipher's helper really puts it (`databases/`, DeviceWorld.Device.file): a
        // leftover v5 file of an earlier run made the v3 open fail with "Can't downgrade".
        DeviceWorld.deleteDatabase(context, name)
        val key = ByteArray(32) { 0x33 }
        val v3 = DeviceWorld.openHelper(context, name, key.copyOf(), 3, Schema.migrations.filter { it.version <= 3 })
        val sql3 = SupportSqlExecutor(v3.writableDatabase)
        assertEquals(3, sql3.userVersion)
        v3.close()

        val v5 = DeviceWorld.openHelper(context, name, key.copyOf(), Schema.CURRENT_VERSION, Schema.migrations)
        val sql5 = SupportSqlExecutor(v5.writableDatabase)
        DeviceWorld.finishOpen(sql5)
        assertEquals(Schema.CURRENT_VERSION, sql5.userVersion)
        MigrationRunner(sql5).verifyIntegrity()
        var check = ""
        sql5.query("PRAGMA integrity_check") { check = it.string(0) }
        assertEquals("ok", check)
        var fk = 0
        sql5.query("PRAGMA foreign_key_check") { fk += 1 }
        assertEquals(0, fk)
        v5.close()
        DeviceRunner.report("dm-device: sqlcipher v3 -> current ok")
    }

    /**
     * The next minute of the shared clock, before a send that must render after the ones before
     * it. §7.7 R-O1 orders a conversation by `(sort_minute, minute_index, message_id)`, and
     * "within one minute the two directions interleave by index and id, not by causality": a reply
     * written in the minute of the message it answers renders before or after it by its random
     * `message_id`. The first emulator run failed SCN-A and SCN-B on exactly that — the product
     * ordered by the rule, the test expected causality inside one minute (design §22.32). Each
     * causally later send therefore takes a later minute, and the full order stays asserted.
     */
    private fun nextMinute() = world.advance(DeviceWorld.MINUTE)

    @Test
    fun scnA() {
        val (contactB, contactA) = introduce()
        val (a, b) = world.alice to world.bob
        assertEquals(listOf("hi back", "hello"), texts(a.messaging, contactB))
        // Pair mode both ways (§6.3).
        nextMinute()
        assertEquals(SendResult.QUEUED, a.messaging.send(contactB, "pair now", null))
        world.deliver()
        b.hintPass()
        nextMinute()
        assertEquals(SendResult.QUEUED, b.messaging.send(contactA, "and back", null))
        world.deliver()
        a.hintPass()
        assertEquals(listOf("and back", "pair now", "hi back", "hello"), texts(a.messaging, contactB))
        assertEquals(texts(a.messaging, contactB), texts(b.messaging, contactA))
        assertEquals(orderDigest(a.messaging, contactB), orderDigest(b.messaging, contactA))
        DeviceRunner.report("dm-device: SCN-A one-scan flow to pair mode, order digests equal")
    }

    @Test
    fun scnB() {
        val (contactB, contactA) = introduce()
        val (a, b) = world.alice to world.bob
        for (i in 1..6) {
            // m1 in the next minute too: in the minute of "hi back" it would interleave with it
            // by id (§7.7; see nextMinute).
            nextMinute()
            assertEquals(SendResult.QUEUED, a.messaging.send(contactB, "m$i", null))
        }
        val random = java.util.Random(0x5c4b)
        var rounds = 0
        while (world.deliver(random) > 0 && rounds < 10) {
            b.hintPass()
            rounds += 1
        }
        b.timePass()
        val atB = texts(b.messaging, contactA)
        assertEquals((6 downTo 1).map { "m$it" } + listOf("hi back", "hello"), atB)
        assertEquals(orderDigest(a.messaging, contactB), orderDigest(b.messaging, contactA))
        DeviceRunner.report("dm-device: SCN-B shuffled delivery, one rendered order")
    }

    @Test
    fun scnF() {
        val (contactB, contactA) = introduce()
        val (a, b) = world.alice to world.bob
        assertEquals(SendResult.QUEUED, a.messaging.setTimer(contactB, Timer.MIN_5))
        world.deliver()
        b.hintPass()
        assertEquals(SendResult.QUEUED, a.messaging.send(contactB, "ephemeral", null))
        world.deliver()
        b.hintPass()
        val shown = b.messaging.conversation(contactA, 100, null).filter { it.text == "ephemeral" }
        assertEquals(1, shown.size)
        assertEquals(1, b.messaging.markDisplayed(shown.map { it.id }))
        world.advance(6 * DeviceWorld.MINUTE)
        // The -wal of the file SQLCipher has open, which exists (a missing file's length is 0 too,
        // which is how the first version passed over a path the database was not at, §22.32) and
        // holds the frames of everything since the open: the truncation below is not vacuous.
        assertTrue("the open database's -wal exists: ${b.walFile}", b.walFile.isFile)
        assertTrue("the -wal holds frames before the sweep", b.walFile.length() > 0L)
        val before = b.checkpoints.size
        b.timePass()
        assertTrue("the expired message is gone", texts(b.messaging, contactA).none { it == "ephemeral" })
        // §10.9 point 3's "the WAL is 0 bytes" is about the instant after SWEEP's TRUNCATE: the rest
        // of the pass writes to the log again (the owner steps, measured on the first emulator run:
        // one page each of `relay_capability` and `relay_key_registration`, 8 272 bytes), which is
        // why the JVM's EphemeralTest drives SWEEP alone. Here the pass is the real one and the
        // checkpoint port records the -wal length the moment the real `Checkpoint.truncate`
        // returns on the real SQLCipher connection (DeviceWorld.Device.checkpoints; §22.32).
        val swept = b.checkpoints.subList(before, b.checkpoints.size).toList()
        assertTrue("SWEEP ran its checkpoint after deleting (ME-11)", swept.isNotEmpty())
        assertTrue("the checkpoint truncated, busy = 0 (ME-10)", swept.last().truncated)
        assertEquals("§10.7: the -wal is 0 bytes after SWEEP's TRUNCATE", 0L, swept.last().walBytes)
        DeviceRunner.report("dm-device: SCN-F five-minute timer swept, WAL 0 bytes")
    }

    @Test
    fun theOneAlarmIsScheduledAndCancelled() {
        val alarm = ExpiryAlarm(context)
        alarm.wakeIn(3_600L)
        assertTrue("the alarm is in the system's pending alarms", pendingAlarms().contains(ACTION))
        alarm.wakeIn(null)
        assertFalse("§10.7: cancelled when nothing is pending and at wipe", pendingAlarms().contains(ACTION))
        DeviceRunner.report("dm-device: alarm scheduled and cancelled")
    }

    /**
     * The **pending** section of `dumpsys alarm`, not the whole dump (first emulator run, design
     * §22.32): on API 35 the dump also keeps a "Removal history" whose snapshot of a cancelled alarm
     * carries its tag (`*walarm*:<action>`, "Reason=alarm_cancelled"), so a scan of the whole text
     * found the action after a successful cancel and failed on API 35 while passing on API 29. The
     * section is "Pending alarm batches: N" on API 29 and "N pending alarms:" on API 35, and it runs
     * to the next two-space-indented header. A dump without either is a failure, not an empty
     * section; and the scheduled half above must find the alarm in it.
     */
    private fun pendingAlarms(): String {
        val lines = dumpsysAlarm().lines()
        val header = Regex("^  (Pending alarm batches: \\d+|\\d+ pending alarms:)\\s*$")
        val start = lines.indexOfFirst { header.matches(it) }
        check(start >= 0) { "dumpsys alarm has no pending-alarm section" }
        val section = StringBuilder()
        for (line in lines.drop(start + 1)) {
            if (line.startsWith("  ") && !line.startsWith("   ") && line.isNotBlank()) break
            section.append(line).append('\n')
        }
        return section.toString()
    }

    @Test
    fun scnDAndTheLogcatScan() {
        shell("logcat -c")
        val (contactB, _) = introduce()
        val (a, b) = world.alice to world.bob
        // B switches to a bound new Olm identity (§15.1's debug hook, test form): the context
        // reopens and ACTIVATE replaces the old identity's DM rows (§22.13 item 7). The restore
        // variant is the one that checks the stored own namespaces and clears a foreign identity's
        // rows; `onActivated()` answers ALREADY_ACTIVE for any `dm_self` row (S12 review).
        b.keyChanged = true
        assertEquals(DmKeys.Opened.OPENED, b.unlock())
        assertEquals(ActivationOutcome.ACTIVATED, b.messaging.onRestored())
        assertEquals(AddContactResult.ADDED, b.messaging.addContact(a.card(), CardSource.QR_IN_PERSON))
        val newA = b.contact()
        assertEquals(SendResult.QUEUED, b.messaging.send(newA, "after the change", null))
        repeat(3) {
            world.deliver()
            b.timePass()
            world.advance(3 * DeviceWorld.MINUTE)
            b.timePass()
            world.deliver()
            a.hintPass()
        }
        val atA = a.messaging.contacts().single { it.id == contactB }
        assertEquals("§8.3: a bound new identity holds the contact", TrustState.CHANGED, atA.trust)
        assertEquals("A's send is refused while the change is undecided", SendResult.KEY_CHANGED, a.messaging.send(contactB, "x", null))
        assertTrue(texts(a.messaging, contactB).none { it == "after the change" })
        assertTrue(a.messaging.acknowledgeKeyChange(contactB))
        assertTrue("released once, after the decision", texts(a.messaging, contactB).count { it == "after the change" } == 1)

        // The scan must read this process's log, or "no canary" is true of an empty read (the first
        // emulator run found two such vacuous device checks, §22.32): a marker logged here, after
        // the whole scenario, has to be in the dump the canaries are looked for in.
        val marker = "ghost-device-gate-logcat-marker-" + java.util.UUID.randomUUID()
        android.util.Log.i("GhostDeviceGate", marker)
        var log = shell("logcat -d")
        for (attempt in 1..20) {
            if (log.contains(marker)) break
            Thread.sleep(100)
            log = shell("logcat -d")
        }
        assertTrue("the logcat dump holds this process's lines (a marker logged just before it)", log.contains(marker))
        val canaries = listOf(
            hex(world.alice.root().deriveBranch(org.ghost.identity.DerivationLabels.MESSAGING)),
            hex(world.bob.root().deriveBranch(org.ghost.identity.DerivationLabels.MESSAGING)),
            hex(DeviceWorld.alternate(world.bob.root().deriveBranch(org.ghost.identity.DerivationLabels.MESSAGING))),
            "after the change",
            hex("after the change".toByteArray()),
        )
        for (canary in canaries) assertFalse("a canary reached logcat", log.contains(canary, ignoreCase = true))
        DeviceRunner.report("dm-device: SCN-D key change held and released; logcat holds no canary (${canaries.size} canaries)")
    }

    /**
     * The channel create path on the phone, not only in the host world: the shipped JNI library,
     * the real channel Keystore wrapper, native context/channel/group creation, then the complete
     * runtime transaction and its read models. Fixed test bytes only; no generated key is reported.
     */
    @Test
    fun channelCreationUsesShippedCryptoAndKeystore() {
        assertTrue(
            "libghost_client_net did not load (${org.ghost.crypto.bridge.MlsNative.loadFailure()?.javaClass?.name ?: "none"})",
            org.ghost.crypto.bridge.MlsNative.isAvailable(),
        )
        val stateKey = ByteArray(32) { (it * 3 + 1).toByte() }
        val channelId = ByteArray(32) { (it * 5 + 2).toByte() }
        val pseudonymSeed = ByteArray(32) { (it * 7 + 3).toByte() }
        try {
            val wrapper = org.ghost.messaging.android.KeystoreChannelStateKeyWrapper(false)
            val unwrapped = wrapper.unwrap(wrapper.wrap(stateKey))
            assertTrue("the channel state-key envelope does not round-trip", stateKey.contentEquals(unwrapped))
            unwrapped.fill(0)

            val opened = org.ghost.crypto.bridge.ChannelCrypto.open(stateKey)
            assertEquals(org.ghost.crypto.bridge.MlsCode.OK, opened.code)
            val crypto = (opened as org.ghost.crypto.bridge.MlsOutcome.Ok).value
            try {
                val channel = crypto.openChannel(channelId, pseudonymSeed)
                assertEquals(org.ghost.crypto.bridge.MlsCode.OK, channel.code)
                val pseudonym = (channel as org.ghost.crypto.bridge.MlsOutcome.Ok).value
                val policy = org.ghost.crypto.bridge.ChannelPolicy(
                    channelId = channelId,
                    sizeClass = 0,
                    timerCode = 4,
                    timerVersion = 0,
                    historyPolicy = 0,
                    flags = 1,
                    idleEvictDays = 63,
                    pwVersion = 0,
                    name = "device probe".toByteArray(),
                    committers = listOf(pseudonym),
                    funders = listOf(pseudonym),
                )
                assertEquals(
                    org.ghost.crypto.bridge.MlsCode.OK,
                    crypto.groupCreate(channelId, policy, 20_000).code,
                )
            } finally {
                crypto.close()
            }
        } finally {
            stateKey.fill(0)
            channelId.fill(0)
            pseudonymSeed.fill(0)
        }

        activate()
        val channels = requireNotNull(world.alice.runtime.channels)
        val created = channels.create("device channel".toByteArray(), 4, 0, false)
        assertEquals(org.ghost.messaging.api.CreateResult.Status.CREATED, created.status)
        val id = requireNotNull(created.channel)
        assertEquals("device channel", channels.channels().single().name)
        assertEquals(1, channels.members(id).size)
        assertTrue(channels.members(id).single().mine)
        assertEquals(8, requireNotNull(channels.fingerprint(id)).code.size)
        DeviceRunner.report("channel-device: shipped native, Keystore and runtime create passed")
    }

    private fun dumpsysAlarm(): String = shell("dumpsys alarm")

    private fun shell(command: String): String {
        val fd: ParcelFileDescriptor = DeviceRunner.current.uiAutomation.executeShellCommand(command)
        return ParcelFileDescriptor.AutoCloseInputStream(fd).bufferedReader().use { it.readText() }
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        const val ACTION = "org.ghost.messaging.EXPIRY_SWEEP"
    }
}

/** The `:messaging` device suite (§15.9 items 2, 4, 5 and 6). */
// The S5 media smoke joins the device suite (Phase 11 design §17.1 row S5: one image and one
// video on an emulator, one a matching source); the runner's list is fixed, so it is named here.
class MessagingDeviceRunner : DeviceRunner(
    listOf(
        DeviceGateSuite::class.java,
        org.ghost.messaging.media.MediaDeviceSmokeTest::class.java,
        // Slice S7's playback run (§15.8 item 3's device half): the real sealer/reader/player
        // stack over the golden, in the FLAG_SECURE window.
        org.ghost.messaging.media.MediaPlaybackDeviceTest::class.java,
        // Slice S7's host-driven restart run: part one records, the host kills the process,
        // part two resumes (scripts/device/media-playback-restart.sh drives it).
        org.ghost.messaging.media.MediaPlaybackRestartTest::class.java,
    ),
)
