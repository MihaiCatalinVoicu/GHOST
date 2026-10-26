package org.ghost.app.gate

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import android.os.SystemClock
import org.ghost.app.DmBranch
import org.ghost.app.GhostApp
import org.ghost.app.UpdateLoopback
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.api.Timer
import org.ghost.sync.api.PrivacyMode
import org.ghost.update.UpdateStatus
import org.ghost.update.Updates

/**
 * **The gate variant's instrumentation** (Phase 9 design §15.10, §21.13 point 4; slice S12): the one
 * way `scripts/device/dm-gate.sh` drives a gate phone, through `adb shell am instrument`, with no
 * camera, no UI and no new permission.
 *
 * > the release candidate APK and its `gate` debug variant (never released) for the steps marked †,
 * > which exposes `Messaging` to an instrumentation runner and includes the debug key-change hook and
 * > the debug-only order digest export
 *
 * One command per run, named by the `cmd` argument; every answer is an enum, a count, an id or a
 * digest in the instrumentation's result bundle — **never message content**. The only secret that
 * crosses is the contact card of `card`, which step 1 exists to move from one phone to the other
 * ("injected into the other by adb as `addContact(card, qr_in_person)`"); the orchestrator holds it
 * in memory and never writes it to its log.
 *
 * Running an instrumentation restarts the app's process, so every command also exercises a cold
 * start: the first database open's pass (§21.12 point 2) runs before the command does. It also
 * means **no command but `pass` moves anything over the network** (S12 review): a process started
 * for an instrumentation has no activity, so it never has a foreground session, and the periodic
 * job's next run is minutes away in a process the next command replaces. `pass` is therefore what
 * the app does when the user opens it: a foreground relay session for `seconds` (its relay session
 * start is the DM time trigger, and its lanes deposit and fetch), optionally in HIGH privacy mode —
 * which is in memory only, so it is set in the same process as the session it applies to — and the
 * drop counters of this process's passes afterwards, because those are in memory too.
 */
class GateInstrumentation : Instrumentation() {

    private var arguments: Bundle = Bundle()

    override fun onCreate(arguments: Bundle?) {
        this.arguments = arguments ?: Bundle()
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        super.onStart()
        val out = Bundle()
        val code = try {
            run(arguments.getString(ARG_CMD) ?: "", out)
            Activity.RESULT_OK
        } catch (e: IllegalArgumentException) {
            out.putString(KEY_ERROR, "bad-argument:${e.message?.take(120)}")
            Activity.RESULT_CANCELED
        } catch (e: IllegalStateException) {
            out.putString(KEY_ERROR, "unavailable:${e.message?.take(120)}")
            Activity.RESULT_CANCELED
        } catch (e: RuntimeException) {
            // Never a crash from a gate command: the drill records the failure class instead.
            out.putString(KEY_ERROR, "${e.javaClass.simpleName}:${e.message?.take(120)}")
            Activity.RESULT_CANCELED
        }
        finish(code, out)
    }

    private fun app(): GhostApp {
        val deadline = SystemClock.elapsedRealtime() + WAIT_MILLIS
        while (true) {
            val app = targetContext.applicationContext
            if (app is GhostApp) return app
            check(SystemClock.elapsedRealtime() < deadline) { "the gate application did not start" }
            SystemClock.sleep(POLL_MILLIS)
        }
    }

    /** The facade once the first database open has built the stack and opened the context. */
    private fun messaging(app: GhostApp): Messaging {
        val deadline = SystemClock.elapsedRealtime() + WAIT_MILLIS
        while (true) {
            val messaging = app.messaging
            if (messaging != null && messaging.myCard() != null) return messaging
            check(SystemClock.elapsedRealtime() < deadline) { "the DM layer did not open" }
            SystemClock.sleep(POLL_MILLIS)
        }
    }

    private fun contact(): ContactId = ContactId(unhex(require(ARG_CONTACT)))

    private fun require(name: String): String =
        requireNotNull(arguments.getString(name)) { "missing argument $name" }

    @Suppress("LongMethod", "CyclomaticComplexMethod")
    private fun run(cmd: String, out: Bundle) {
        val app = app()
        when (cmd) {
            "card" -> out.putString("card", OrderDigests.hex(requireNotNull(messaging(app).myCard()).card))
            "add-contact" -> {
                val messaging = messaging(app)
                val before = messaging.contacts().map { OrderDigests.hex(it.id.toByteArray()) }.toSet()
                val source = if (arguments.getString("source") == "link") CardSource.LINK else CardSource.QR_IN_PERSON
                out.putString("result", messaging.addContact(unhex(require("card")), source).name)
                val added = messaging.contacts().map { OrderDigests.hex(it.id.toByteArray()) }.filter { it !in before }
                out.putString(ARG_CONTACT, added.singleOrNull() ?: "")
            }
            "contacts" -> out.putString(
                "contacts",
                messaging(app).contacts().joinToString(",") {
                    OrderDigests.hex(it.id.toByteArray()) + ":" + it.trust.name + ":" + it.establishment.name
                },
            )
            "send" -> {
                val messaging = messaging(app)
                val contact = contact()
                val count = require("count").toInt()
                require(count in 1..MAX_BURST) { "count out of range" }
                val results = LinkedHashMap<String, Int>()
                // The text is a counter and a run tag no digest covers (§15.10: "records digests,
                // never content"). The tag is random unless the orchestrator names one: step 6
                // does, so that its host scan of the exported database can look for it; the
                // orchestrator never logs it.
                val tag = arguments.getString("tag")?.also {
                    require(it.length in 8..32 && it.all { c -> c in '0'..'9' || c in 'a'..'f' }) { "tag is 8-32 lowercase hex" }
                } ?: OrderDigests.hex(java.security.SecureRandom().generateSeed(4))
                for (i in 1..count) {
                    val r = messaging.send(contact, "gate $tag $i", null).name
                    results[r] = (results[r] ?: 0) + 1
                }
                for ((name, n) in results) out.putInt("send.$name", n)
            }
            "digest" -> {
                val d = OrderDigests.of(messaging(app), contact())
                out.putString("order", d.order)
                out.putString("multiset", d.multiset)
                out.putInt("count", d.count)
                out.putInt("duplicates", d.duplicates)
            }
            "safety" -> {
                val messaging = messaging(app)
                val view = messaging.safetyNumber(contact()) ?: messaging.pendingSafetyNumber(contact())
                out.putString("safety", view?.let { OrderDigests.safetyDigest(it.digits) } ?: "none")
            }
            "verify-manually" -> out.putString("result", messaging(app).markVerifiedManually(contact()).name)
            // D26's updater half (faza14 design §11.4): the gate build drives the real updater
            // against the drill root's bundles on the real staging mirrors. Answers are status
            // names and codes in the result bundle — never content.
            "update-probe" -> {
                // The drill's decisive probe: runs the update ENGINE directly on this thread with a
                // hand-built session (trusted clock, the loopback mirror) — bypassing the sync
                // runtime's dispatch entirely. Tests exactly engine + native seam + persistence;
                // the runtime-plumbed path is `update-check`'s own coverage.
                val mirror = UpdateLoopback.mirror(app)
                if (mirror == null) {
                    out.putString("update.probe", "no-loopback")
                } else {
                    val engine = app.updateEngineForProbe()
                    val session = object : org.ghost.sync.api.UpdateSession {
                        override fun updateDraw(): ByteArray = ByteArray(32)
                        override val userInitiated: Boolean = true
                        override fun clockTrusted(): Boolean = true
                        override val deadlineMonotonicMillis: Long =
                            SystemClock.elapsedRealtime() + 240_000L
                        override val closed: Boolean get() = false
                        override val mirror: org.ghost.sync.api.MirrorAccess = mirror
                    }
                    val error = try {
                        engine.onUpdateRun(session)
                        null
                    } catch (e: RuntimeException) {
                        val at = e.stackTrace.firstOrNull { it.className.startsWith("org.ghost") }
                        "${e.javaClass.simpleName}:${e.message?.take(100)}@${at?.className?.substringAfterLast('.')}.${at?.methodName}:${at?.lineNumber}"
                    }
                    val sql = app.openDatabaseDirectly()
                    var stateRows = 0
                    var staged = 0
                    if (sql != null) {
                        sql.query("SELECT count(*) FROM upd_state") { r -> stateRows = r.long(0).toInt() }
                        sql.query("SELECT count(*) FROM upd_staged") { r -> staged = r.long(0).toInt() }
                    }
                    val dir = java.io.File(app.noBackupFilesDir, "update")
                    out.putString(
                        "update.probe",
                        "error=${error ?: "none"} state=$stateRows staged=$staged files=${dir.list()?.toList() ?: emptyList()}",
                    )
                }
            }
            "update-status" -> {
                val status = app.updates.status
                out.putString("update.status", updateStatusName(status))
                when (status) {
                    is org.ghost.update.UpdateStatus.Available -> {
                        out.putString("update.name", status.name)
                        out.putInt("update.versionCode", status.versionCode)
                    }
                    is org.ghost.update.UpdateStatus.Ready -> {
                        out.putString("update.name", status.name)
                        out.putInt("update.versionCode", status.versionCode)
                    }
                    is org.ghost.update.UpdateStatus.Downloading -> {
                        out.putLong("update.received", status.received)
                        out.putLong("update.total", status.total)
                    }
                    is org.ghost.update.UpdateStatus.Failed -> out.putInt("update.code", status.code)
                    is org.ghost.update.UpdateStatus.Stale -> out.putInt("update.day", status.day)
                    is org.ghost.update.UpdateStatus.Unsupported -> out.putInt("update.floor", status.floor)
                    else -> Unit
                }
            }
            // §7.3: user update calls run in the foreground only — a process started for an
            // instrumentation has no activity, so the gate marks the app foreground explicitly
            // (what `pass` does for relay sessions) and waits for the runtime to go idle before
            // returning, exactly like ON_START/ON_STOP.
            "update-check" -> {
                app.syncController.onAppForeground()
                try {
                    out.putString(
                        "update.check",
                        when (val r = app.updates.requestCheck()) {
                            is Updates.CheckOutcome.Ok -> "OK"
                            is Updates.CheckOutcome.Refused -> "REFUSED:${r.code}"
                            is Updates.CheckOutcome.Unchanged -> "UNCHANGED:${r.code}"
                        },
                    )
                    app.syncController.awaitIdle(UPDATE_IDLE_WAIT_MILLIS)
                } finally {
                    app.syncController.onAppBackground()
                }
            }
            "update-download" -> {
                app.syncController.onAppForeground()
                try {
                    out.putString(
                        "update.download",
                        when (val r = app.updates.requestDownload()) {
                            is Updates.DownloadOutcome.Started -> "STARTED"
                            Updates.DownloadOutcome.NothingToDownload -> "NOTHING"
                            is Updates.DownloadOutcome.Refused -> "REFUSED:${r.code}"
                        },
                    )
                    app.syncController.awaitIdle(UPDATE_IDLE_WAIT_MILLIS)
                } finally {
                    app.syncController.onAppBackground()
                }
            }
            "update-install" -> {
                // commit() streams the native-verified APK into a PackageInstaller session and
                // asks the platform for its confirmation; the orchestrator confirms the platform
                // dialog over UI Automator while this command holds the app foreground (the
                // dialog surfaces for a foreground app; the hold keeps the process alive so the
                // committed session isn't abandoned).
                app.syncController.onAppForeground()
                try {
                    app.updates.install().commit()
                    out.putString("update.install", "COMMITTED")
                    SystemClock.sleep(45_000L)
                } finally {
                    app.syncController.onAppBackground()
                }
            }
            "update-loopback" -> {
                // §11.4's emulator seam: "off" restores the Tor mirror; anything else is the
                // model mirror's "host:port" (10.0.2.2 with adb forward, from the emulator).
                val endpoint = arguments.getString("endpoint") ?: require("endpoint")
                UpdateLoopback.set(app, if (endpoint == "off") null else endpoint)
                out.putString("update.loopback", endpoint)
            }
            "probe" -> {
                // One-shot diagnostic for the drill's onboarding prerequisite: the state before
                // and, with activate=true, after ensureDatabaseKey + activate, in the same process.
                out.putString("probe.before", app.gateProbe())
                if (arguments.getString("activate") == "true") {
                    app.ensureDatabaseKey()
                    // D19's bootstrap after the key exists, before the directory's first read.
                    app.bootstrapRelayDirectory()
                    val restored = arguments.getString("restored") == "true"
                    val deadline = SystemClock.elapsedRealtime() + WAIT_MILLIS
                    var result: String? = null
                    while (SystemClock.elapsedRealtime() < deadline) {
                        result = app.messagingWiring.activate(restored)?.name
                        if (result != null) break
                        SystemClock.sleep(POLL_MILLIS)
                    }
                    out.putString("probe.activate", result ?: "UNAVAILABLE")
                }
                out.putString("probe.after", app.gateProbe())
            }
            "activate" -> {                // The drill's onboarding equivalent: creates the database key if the install is
                // fresh (the update facade opens the database only once a key exists), then the
                // identity + the K20 activation hook. Polls: the database opens on the sync
                // runtime's thread, which the first open's pass may still be migrating.
                app.ensureDatabaseKey()
                val restored = arguments.getString("restored") == "true"
                val deadline = SystemClock.elapsedRealtime() + WAIT_MILLIS
                var result: String? = null
                while (SystemClock.elapsedRealtime() < deadline) {
                    result = app.messagingWiring.activate(restored)?.name
                    if (result != null) break
                    SystemClock.sleep(POLL_MILLIS)
                }
                out.putString("result", result ?: "UNAVAILABLE")
            }
            "ack-key-change" -> out.putBoolean("result", messaging(app).acknowledgeKeyChange(contact()))
            "key-change" -> {
                // §15.10 step 5: switch to the bound alternate Olm identity (or back) and run the
                // K20 path the switch stands for — the context reopens, then ACTIVATE in the same
                // actor turn. **`restored = true`** (S12 review): this phone already has a
                // `dm_self` row, and ACTIVATE with `restored = false` answers ALREADY_ACTIVE for
                // any row at all, leaving the new identity running over the old one's rows. The
                // restore variant checks the stored own namespaces against the ones the new
                // context derives — every value of §3.1 derived from `m` changes with the switch —
                // and, finding somebody else's, clears the DM tables and activates for real
                // (§22.13 item 7). A switch that changed nothing answers ALREADY_ACTIVE, which the
                // orchestrator refuses.
                val on = require("on") == "true"
                DmBranch.setKeyChanged(app, on)
                out.putString("result", app.messagingWiring.activate(restored = true)?.name ?: "UNAVAILABLE")
            }
            "timer" -> {
                val timer = Timer.entries.first { it.code == require("code").toInt() }
                out.putString("result", messaging(app).setTimer(contact(), timer).name)
            }
            "reset" -> out.putString("result", messaging(app).resetSession(contact()).name)
            "reconnect" -> out.putInt("result", messaging(app).reconnect(listOf(contact())))
            "pass" -> {
                val messaging = messaging(app)
                val seconds = (arguments.getString("seconds") ?: DEFAULT_SESSION_SECONDS.toString()).toLong()
                require(seconds in 1..MAX_SESSION_SECONDS) { "seconds out of range" }
                arguments.getString("privacy")?.let { app.syncController.setPrivacyMode(PrivacyMode.valueOf(it)) }
                // What the app's ON_START does (`SyncWiring.onVisible`): a foreground relay session,
                // whose relay session start is the DM time trigger (`MessagingWiring.sessionHooks`)
                // and whose lanes deposit and fetch. Held for `seconds`, then ON_STOP.
                app.syncController.onAppForeground()
                try {
                    SystemClock.sleep(seconds * MILLIS)
                } finally {
                    app.syncController.onAppBackground()
                }
                app.syncController.awaitIdle(IDLE_WAIT_MILLIS)
                val status = messaging.status()
                out.putString("result", "PASSED")
                out.putString("privacy", app.syncController.privacyMode.name)
                for ((reason, n) in status.drops) out.putInt("drop.$reason", n)
            }
            "export-deposits" -> exportDeposits(app, out)
            "status" -> {
                val status = messaging(app).status()
                out.putInt("poisoned", status.poisoned)
                out.putInt("establishing", status.establishing)
                out.putInt("pendingSends", status.pendingSends)
                for ((reason, n) in status.drops) out.putInt("drop.$reason", n)
                for ((trust, n) in status.contactsByTrust) out.putInt("trust.${trust.name}", n)
            }
            else -> throw IllegalArgumentException("unknown command")
        }
    }

    /**
     * §15.10 step 4's capture, for the host re-store tool (`client-core/net/examples/dm_restore`):
     * the last `count` DM ciphertexts this phone enqueued for `contact` while their bytes are still
     * in the outbox, the inbox namespace they went to, and this phone's deposit credential for it at
     * one relay of that namespace with its onion. The orchestrator runs it with the sending phone in
     * airplane mode right after the burst, so the ops have not been released and wiped yet, writes
     * the answer to a private capture file and deletes the file after the re-store; nothing of it is
     * logged. Ciphertext and a bearer credential, never plaintext.
     */
    private fun exportDeposits(app: GhostApp, out: Bundle) {
        messaging(app)
        val contact = unhex(require(ARG_CONTACT))
        val count = require("count").toInt()
        require(count in 1..MAX_BURST) { "count out of range" }
        val stores = checkNotNull(app.syncController.stores) { "no database is open" }
        stores.database.transaction { tx ->
            val blobs = ArrayList<Pair<ByteArray, ByteArray>>()
            var ttl = 0L
            tx.sql.query(
                "SELECT o.namespace_id, o.ciphertext, o.ttl_seconds FROM outbox_op o " +
                    "JOIN dm_outbound_op d ON d.operation_id = o.operation_id " +
                    "JOIN dm_outbound_item i ON i.item_id = d.item_id " +
                    "WHERE i.contact_id = ? AND o.ciphertext IS NOT NULL ORDER BY o.rowid DESC LIMIT ?",
                listOf(contact, count.toLong()),
            ) { row ->
                blobs += row.blob(0) to row.blob(1)
                ttl = row.long(2)
            }
            check(blobs.size == count) { "only ${blobs.size} of $count ops still hold their bytes" }
            val namespace = blobs.first().first
            check(blobs.all { it.first.contentEquals(namespace) }) { "the ops went to more than one namespace" }
            var onion: String? = null
            var credential: ByteArray? = null
            tx.sql.query(
                "SELECT r.onion_address, c.token FROM relay_capability c " +
                    "JOIN relay_directory r ON r.relay_id = c.relay_id " +
                    "WHERE c.namespace_id = ? AND c.kind = 'write' AND c.state = 'usable' ORDER BY r.relay_id LIMIT 1",
                listOf(namespace),
            ) { row ->
                onion = row.string(0)
                credential = row.blob(1)
            }
            out.putString("namespace", OrderDigests.hex(namespace))
            out.putString("onion", checkNotNull(onion) { "no usable deposit credential" })
            out.putString("credential", OrderDigests.hex(checkNotNull(credential)))
            out.putLong("ttl", ttl)
            blobs.asReversed().forEachIndexed { i, (_, blob) -> out.putString("blob.$i", OrderDigests.hex(blob)) }
        }
    }

    private fun unhex(text: String): ByteArray {
        require(text.length % 2 == 0 && text.all { it in '0'..'9' || it in 'a'..'f' }) { "not lowercase hex" }
        return ByteArray(text.length / 2) { i -> text.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }

    /** The status wire name the orchestrator compares against the drill's expectations. */
    private fun updateStatusName(s: UpdateStatus): String = when (s) {
        UpdateStatus.UpToDate -> "UP_TO_DATE"
        is UpdateStatus.Available -> "AVAILABLE"
        is UpdateStatus.Downloading -> "DOWNLOADING"
        is UpdateStatus.Ready -> "READY"
        UpdateStatus.Installing -> "INSTALLING"
        is UpdateStatus.Installed -> "INSTALLED"
        is UpdateStatus.Stale -> "STALE"
        is UpdateStatus.Unsupported -> "UNSUPPORTED"
        UpdateStatus.SdkUnsupported -> "SDK_UNSUPPORTED"
        UpdateStatus.NoManifest -> "NO_MANIFEST"
        UpdateStatus.Conflict -> "CONFLICT"
        UpdateStatus.RootConflict -> "ROOT_CONFLICT"
        UpdateStatus.NoChannel -> "NO_CHANNEL"
        is UpdateStatus.Failed -> "FAILED"
    }

    private companion object {
        const val ARG_CMD = "cmd"
        const val ARG_CONTACT = "contact"
        const val KEY_ERROR = "error"
        const val WAIT_MILLIS = 60_000L
        const val POLL_MILLIS = 250L

        /** §15.10 step 2 sends 30-message bursts; the bound only refuses a typo. */
        const val MAX_BURST = 200

        /** How long `pass` holds its foreground session by default, and at most. */
        const val DEFAULT_SESSION_SECONDS = 30L
        const val MAX_SESSION_SECONDS = 600L
        const val MILLIS = 1_000L

        /** How long `pass` waits for the session to close after ON_STOP. */
        const val IDLE_WAIT_MILLIS = 60_000L

        /** The update run's idle wait: Tor bootstrap (up to ~180 s) plus the fixed run duration. */
        const val UPDATE_IDLE_WAIT_MILLIS = 300_000L
    }
}
