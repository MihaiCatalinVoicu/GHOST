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
import java.io.File
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
        for (suffix in listOf("", "-wal", "-shm", "-journal")) File(context.noBackupFilesDir, name + suffix).delete()
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
        DeviceRunner.report("dm-device: sqlcipher v3 -> v4 -> v5 ok")
    }

    @Test
    fun scnA() {
        val (contactB, contactA) = introduce()
        val (a, b) = world.alice to world.bob
        assertEquals(listOf("hi back", "hello"), texts(a.messaging, contactB))
        // Pair mode both ways (§6.3).
        assertEquals(SendResult.QUEUED, a.messaging.send(contactB, "pair now", null))
        world.deliver()
        b.hintPass()
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
            assertEquals(SendResult.QUEUED, a.messaging.send(contactB, "m$i", null))
            world.advance(DeviceWorld.MINUTE)
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
        b.timePass()
        assertTrue("the expired message is gone", texts(b.messaging, contactA).none { it == "ephemeral" })
        assertEquals("§10.7: the -wal is truncated after the sweep", 0L, b.walFile.length())
        DeviceRunner.report("dm-device: SCN-F five-minute timer swept, WAL 0 bytes")
    }

    @Test
    fun theOneAlarmIsScheduledAndCancelled() {
        val alarm = ExpiryAlarm(context)
        alarm.wakeIn(3_600L)
        assertTrue("the alarm is in the system table", dumpsysAlarm().contains(ACTION))
        alarm.wakeIn(null)
        assertFalse("§10.7: cancelled when nothing is pending and at wipe", dumpsysAlarm().contains(ACTION))
        DeviceRunner.report("dm-device: alarm scheduled and cancelled")
    }

    @Test
    fun scnDAndTheLogcatScan() {
        shell("logcat -c")
        val (contactB, _) = introduce()
        val (a, b) = world.alice to world.bob
        // B switches to a bound new Olm identity (§15.1's debug hook, test form): the context
        // reopens and ACTIVATE replaces the old identity's DM rows (§22.13 item 7).
        b.keyChanged = true
        assertEquals(DmKeys.Opened.OPENED, b.unlock())
        b.messaging.onActivated()
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

        val log = shell("logcat -d")
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
class MessagingDeviceRunner : DeviceRunner(listOf(DeviceGateSuite::class.java))
