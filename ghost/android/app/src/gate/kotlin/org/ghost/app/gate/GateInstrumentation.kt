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

    /** The channel facade after the same cold-start barrier used by the DM probes. */
    private fun channels(app: GhostApp): org.ghost.messaging.api.Channels {
        messaging(app)
        return checkNotNull(app.channels)
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
            "purchase-start" -> {
                messaging(app)
                val payWith = org.ghost.entitlement.api.PayWith.valueOf(arguments.getString("with") ?: "XMR")
                val id = app.entitlement.startPurchase(payWith)
                out.putString("purchase.start", if (id == null) "REFUSED" else "PREPARED")
                id?.let { out.putString("purchase.id", OrderDigests.hex(it.toByteArray())) }
            }
            "purchase-check" -> {
                messaging(app)
                val id = org.ghost.entitlement.api.PurchaseId(unhex(require("purchase")))
                app.syncController.onAppForeground()
                try {
                    app.entitlement.checkNow(id)
                    val deadline = SystemClock.elapsedRealtime() + 240_000L
                    while (SystemClock.elapsedRealtime() < deadline) {
                        val purchase = app.entitlement.openPurchases().firstOrNull { it.id == id }
                        if (purchase != null && purchase.sync != org.ghost.entitlement.api.PurchaseSyncState.LOCAL_ONLY) break
                        val stage = app.syncController.diagnostics().stage
                        if (stage == org.ghost.sync.api.DiagnosticStage.FAILED ||
                            stage == org.ghost.sync.api.DiagnosticStage.UNAVAILABLE ||
                            stage == org.ghost.sync.api.DiagnosticStage.CLOSED
                        ) break
                        SystemClock.sleep(POLL_MILLIS)
                    }
                } finally {
                    app.syncController.onAppBackground()
                }
                app.syncController.awaitIdle(IDLE_WAIT_MILLIS)
                out.putString("purchase.diagnostic", app.syncController.diagnostics().toString())
                out.putString(
                    "purchase.state",
                    app.entitlement.openPurchases().firstOrNull { it.id == id }?.let { "${it.state}:${it.sync}" } ?: "MISSING",
                )
            }
            "purchase-instructions" -> {
                messaging(app)
                val id = org.ghost.entitlement.api.PurchaseId(unhex(require("purchase")))
                val disclosures = app.entitlement.requiredDisclosures(id)
                app.entitlement.acknowledge(id, disclosures)
                app.entitlement.paymentScreenShown(id)
                try {
                    val instructions = app.entitlement.paymentInstructions(id)
                    if (instructions == null) {
                        out.putString("payment.ready", "false")
                    } else {
                        out.putString("payment.ready", "true")
                        out.putString("payment.address", instructions.subaddress)
                        out.putLong("payment.amount", instructions.outstandingAtomic)
                    }
                } finally {
                    app.entitlement.paymentScreenHidden(id)
                }
            }
            "purchase-status" -> {
                // Read-only payment drill: fixed states only, never purchase ids, addresses or amounts.
                val opened = java.util.concurrent.CountDownLatch(1)
                app.syncController.runWhenStoresOpen {
                    val wanted = arguments.getString("purchase")
                    out.putString(
                        "purchase.states",
                        app.entitlement.openPurchases().filter {
                            wanted == null || OrderDigests.hex(it.id.toByteArray()) == wanted
                        }.joinToString(",") { it.state.name + ":" + it.sync.name },
                    )
                    val schedule = ArrayList<String>()
                    app.openDatabaseDirectly()?.query(
                        "SELECT state, attempt, next_due_minute FROM ent_purchase ORDER BY purchase_id",
                    ) { row ->
                        schedule += row.string(0) + ":" + row.long(1) + ":" + (if (row.isNull(2)) "none" else row.long(2).toString())
                    }
                    out.putString("purchase.schedule", schedule.joinToString(","))
                    opened.countDown()
                }
                check(opened.await(WAIT_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS)) { "the database did not open" }
                val diagnostic = app.syncController.diagnostics()
                out.putString("purchase.diagnostic", diagnostic.stage.name + ":" + (diagnostic.lastError ?: "none"))
            }
            "purchase-request" -> {
                // The same user RequestInvoice path as the UI, in an explicit foreground session.
                app.syncController.onAppForeground()
                val requested = java.util.concurrent.CountDownLatch(1)
                app.syncController.runWhenStoresOpen {
                    val purchase = app.entitlement.openPurchases().firstOrNull {
                        it.state == org.ghost.entitlement.api.PurchaseUiState.PREPARED ||
                            it.state == org.ghost.entitlement.api.PurchaseUiState.INVOICE_PENDING
                    }
                    if (purchase != null) app.entitlement.requestInvoiceNow(purchase.id)
                    requested.countDown()
                }
                check(requested.await(WAIT_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS)) { "the database did not open" }
                app.syncController.onAppBackground()
                app.syncController.awaitIdle(UPDATE_IDLE_WAIT_MILLIS)
                val read = java.util.concurrent.CountDownLatch(1)
                app.syncController.runWhenStoresOpen {
                    out.putString(
                        "purchase.states",
                        app.entitlement.openPurchases().joinToString(",") { it.state.name + ":" + it.sync.name },
                    )
                    read.countDown()
                }
                check(read.await(WAIT_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS)) { "the result could not be read" }
                val diagnostic = app.syncController.diagnostics()
                out.putString("purchase.diagnostic", diagnostic.stage.name + ":" + (diagnostic.lastError ?: "none"))
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
            "clipboard-probe" -> {
                // Android refuses clipboard reads to a process without a focused window, so this
                // probe opens the real activity first. No payload crosses the result.
                app.startActivity(
                    android.content.Intent(app, org.ghost.app.MainActivity::class.java)
                        .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK),
                )
                SystemClock.sleep(2_000L)
                val text = "ghost://channel/gate-clipboard"
                app.clipboardOwner.copy(
                    org.ghost.ui.protect.SensitiveClipboard.CopyKind.CHANNEL_INVITE_LINK,
                    org.ghost.ui.protect.SensitiveText(text),
                )
                val manager = app.getSystemService(android.content.ClipboardManager::class.java)
                val present = manager.primaryClip?.getItemAt(0)?.text?.toString() == text
                val sensitive = manager.primaryClipDescription?.extras?.getBoolean(
                    android.content.ClipDescription.EXTRA_IS_SENSITIVE,
                ) == true
                out.putString("clipboard.before", "present=$present sensitive=$sensitive")
                SystemClock.sleep(32_000L)
                out.putString("clipboard.after", "cleared=${manager.primaryClip == null}")
            }
            "channel-by-name" -> {
                val channels = channels(app)
                val view = channels.channels().lastOrNull { it.name == require("name") }
                if (view == null) {
                    out.putString("channel.id", "")
                } else {
                    out.putString("channel.id", OrderDigests.hex(view.channelId))
                    out.putInt("channel.members", channels.members(org.ghost.messaging.api.ChannelId(view.channelId)).size)
                    app.openDatabaseDirectly()?.query(
                        "SELECT state FROM ch_channel WHERE channel_id = ?", listOf(view.channelId),
                    ) { out.putString("channel.state", it.string(0)) }
                }
            }
            "channel-create-invite" -> {
                val channels = channels(app)
                val created = channels.create(require("name").toByteArray(), 0, 0, false)
                out.putString("channel.create", created.status.name)
                val id = checkNotNull(created.channel)
                val invited = channels.invite(id, 7, null)
                out.putString("channel.inviteStatus", invited.status.name)
                out.putString("channel.id", OrderDigests.hex(id.toByteArray()))
                invited.link?.let {
                    out.putString("channel.invite", String(it, Charsets.US_ASCII))
                    it.fill(0)
                }
            }
            "channel-invite-existing" -> {
                val channels = channels(app)
                val id = org.ghost.messaging.api.ChannelId(unhex(require("channel")))
                val invited = channels.invite(id, 7, null)
                out.putString("channel.inviteStatus", invited.status.name)
                invited.link?.let {
                    out.putString("channel.invite", String(it, Charsets.US_ASCII))
                    it.fill(0)
                }
            }
            "channel-accept" -> {
                val bytes = require("invite").toByteArray(Charsets.US_ASCII)
                val result = try {
                    channels(app).accept(bytes, null)
                } finally {
                    bytes.fill(0)
                }
                out.putString("channel.accept", result.name)
                val expected = unhex(require("channel"))
                out.putString(
                    "channel.known",
                    channels(app).channels().any { it.channelId.contentEquals(expected) }.toString(),
                )
            }
            "channel-post" -> {
                val id = org.ghost.messaging.api.ChannelId(unhex(require("channel")))
                val reply = arguments.getString("reply")?.let { org.ghost.messaging.api.PostId(unhex(it)) }
                val result = channels(app).post(id, require("text").toByteArray(), reply)
                out.putString("channel.post", result.name)
            }
            "channel-read" -> {
                val channels = channels(app)
                out.putString("channel.names", channels.channels().joinToString(",") { it.name })
                val id = org.ghost.messaging.api.ChannelId(unhex(require("channel")))
                out.putInt("channel.members", channels.members(id).size)
                out.putString(
                    "channel.posts",
                    channels.posts(id, 120).joinToString(" | ") { "${it.kind}:${it.state}:${it.body}" },
                )
                out.putString(
                    "channel.postIds",
                    channels.posts(id, 120).joinToString(",") { OrderDigests.hex(it.opId) },
                )
                app.openDatabaseDirectly()?.let { sql ->
                    sql.query("SELECT state FROM ch_channel WHERE channel_id = ?", listOf(id.toByteArray())) { row ->
                        out.putString("channel.state", row.string(0))
                    }
                    sql.query("SELECT count(*) FROM ch_join_request WHERE channel_id = ?", listOf(id.toByteArray())) { row ->
                        out.putInt("channel.joinRequests", row.long(0).toInt())
                    }
                    sql.query("SELECT count(*) FROM ch_join WHERE channel_id = ?", listOf(id.toByteArray())) { row ->
                        out.putInt("channel.pendingJoin", row.long(0).toInt())
                    }
                    val capabilities = ArrayList<String>()
                    sql.query(
                        "SELECT g.generation, g.state, c.kind, c.state, count(*) FROM ch_generation g " +
                            "JOIN relay_capability c ON c.namespace_id = g.namespace_id " +
                            "WHERE g.channel_id = ? GROUP BY g.generation, g.state, c.kind, c.state ORDER BY g.generation, c.kind, c.state",
                        listOf(id.toByteArray()),
                    ) { row ->
                        capabilities += "${row.long(0)}:${row.string(1)}:${row.string(2)}:${row.string(3)}=${row.long(4)}"
                    }
                    out.putString("channel.capabilities", capabilities.joinToString(","))
                    sql.query(
                        "SELECT next_pass_minute, next_selfupdate_day, last_own_commit_day FROM ch_schedule WHERE channel_id = ?",
                        listOf(id.toByteArray()),
                    ) { row ->
                        out.putString("channel.schedule", "${if (row.isNull(0)) "none" else row.long(0)}:${row.long(1)}:${if (row.isNull(2)) "none" else row.long(2)}")
                    }
                    val allCapabilities = ArrayList<String>()
                    sql.query("SELECT kind, state, count(*) FROM relay_capability GROUP BY kind, state") { row ->
                        allCapabilities += "${row.string(0)}:${row.string(1)}=${row.long(2)}"
                    }
                    out.putString("channel.allCapabilities", allCapabilities.joinToString(","))
                    sql.query("SELECT epoch, own, verified, first_seen_minute, rank FROM ch_candidate WHERE channel_id = ?", listOf(id.toByteArray())) { row ->
                        out.putString("channel.candidates", "${row.long(0)}:${row.long(1)}:${row.long(2)}:${row.long(3)}:${row.long(4)}")
                    }
                    val channelOps = ArrayList<String>()
                    sql.query(
                        "SELECT o.outcome, count(*) FROM outbox_op o JOIN ch_generation g ON g.namespace_id = o.namespace_id " +
                            "WHERE g.channel_id = ? GROUP BY o.outcome", listOf(id.toByteArray()),
                    ) { row -> channelOps += "${row.string(0)}=${row.long(1)}" }
                    out.putString("channel.operations", channelOps.joinToString(","))
                    sql.query("SELECT namespace_id FROM ch_generation WHERE channel_id = ? AND state = 'current'", listOf(id.toByteArray())) { row ->
                        val namespace = org.ghost.sync.api.NamespaceId(row.blob(0))
                        out.putInt("channel.listingTails", app.syncController.stores?.inbox?.listingTails(namespace)?.size ?: -1)
                    }
                    sql.query("SELECT recorded_day, type FROM ch_join_request WHERE channel_id = ?", listOf(id.toByteArray())) { row ->
                        out.putString("channel.requestState", "${row.long(0)}:${row.string(1)}")
                    }
                    val outbox = ArrayList<String>()
                    sql.query("SELECT outcome, count(*) FROM outbox_op GROUP BY outcome") { row ->
                        outbox += "${row.string(0)}=${row.long(0)}"
                    }
                    out.putString("channel.outbox", outbox.joinToString(","))
                    val inbox = ArrayList<String>()
                    sql.query("SELECT state, count(*) FROM inbox_blob GROUP BY state") { row ->
                        inbox += "${row.string(0)}=${row.long(0)}"
                    }
                    out.putString("channel.inbox", inbox.joinToString(","))
                    val deliveries = ArrayList<String>()
                    sql.query("SELECT state, count(*) FROM outbox_delivery GROUP BY state") { row ->
                        deliveries += "${row.string(0)}=${row.long(0)}"
                    }
                    out.putString("channel.deliveries", deliveries.joinToString(","))
                    sql.query(
                        "SELECT listening, count(*) FROM sync_namespace WHERE consumer = 'channel' GROUP BY listening",
                    ) { row -> out.putString("channel.listening", "${row.long(0)}=${row.long(1)}") }
                }
                out.putString("channel.sync", app.syncController.diagnostics().let { "${it.stage}:${it.lastError ?: "none"}" })
                out.putString("channel.syncStatus", app.syncController.status().toString())
            }
            "relay-probe" -> {
                messaging(app)
                val sql = checkNotNull(app.openDatabaseDirectly())
                var relayText: String? = null
                var namespace: ByteArray? = null
                var period = -1L
                var kind = ""
                var verifier: ByteArray? = null
                var requestId: ByteArray? = null
                var registerCap: ByteArray? = null
                sql.query(
                    "SELECT r.onion_address, g.namespace_id, g.period_id, g.kind, g.verifier, g.request_id, c.token " +
                        "FROM relay_key_registration g " +
                        "JOIN relay_directory r ON r.relay_id = g.relay_id " +
                        "JOIN relay_register_capability c ON c.relay_id = g.relay_id AND c.namespace_id = g.namespace_id " +
                        "WHERE g.state = 'done' AND c.state = 'usable' AND EXISTS (" +
                        "SELECT 1 FROM relay_capability x WHERE x.relay_id = g.relay_id " +
                        "AND x.namespace_id = g.namespace_id AND x.state = 'rejected') LIMIT 1",
                ) { row ->
                    relayText = row.string(0)
                    namespace = row.blob(1)
                    period = row.long(2)
                    kind = row.string(3)
                    verifier = row.blob(4)
                    requestId = row.blob(5)
                    registerCap = row.blob(6)
                }
                if (relayText == null) {
                    out.putString("relay.probe", "NO_WORK")
                } else {
                    val base = java.io.File(app.noBackupFilesDir, "tor-relay-probe")
                    val transport = org.ghost.network.TorRelayTransport.create(
                        java.io.File(base, "state"), java.io.File(base, "cache"),
                    )
                    try {
                        transport.bootstrap()
                        val keyKind = when (kind) {
                            "read" -> org.ghost.network.TorRelayTransport.KeyKind.READ
                            "deposit" -> org.ghost.network.TorRelayTransport.KeyKind.DEPOSIT
                            else -> org.ghost.network.TorRelayTransport.KeyKind.FETCH
                        }
                        val answer = transport.registerKey(
                            org.ghost.network.OnionAddress.parse(checkNotNull(relayText)),
                            checkNotNull(namespace), checkNotNull(registerCap), period, keyKind,
                            checkNotNull(verifier), checkNotNull(requestId),
                        )
                        out.putString("relay.register", answer.result.toString())
                        if (answer.result == org.ghost.network.TorRelayTransport.REGISTER_OK) {
                            var readCap: ByteArray? = null
                            sql.query(
                                "SELECT token FROM relay_capability WHERE relay_id = (" +
                                    "SELECT relay_id FROM relay_directory WHERE onion_address = ?) " +
                                    "AND namespace_id = ? AND kind = 'read' AND state = 'rejected' LIMIT 1",
                                listOf(relayText, namespace),
                            ) { readCap = it.blob(0) }
                            if (readCap != null) {
                                val page = transport.list(
                                    org.ghost.network.OnionAddress.parse(checkNotNull(relayText)),
                                    checkNotNull(namespace), checkNotNull(readCap), ByteArray(0), 1, 60_000,
                                )
                                out.putString("relay.list", "OK:${page.hashes.size}")
                            }
                        }
                    } catch (e: org.ghost.network.NetworkException) {
                        out.putString("relay.error", e.category)
                    } finally {
                        transport.close()
                    }
                }
            }
            "tor-probe" -> {
                val base = java.io.File(app.noBackupFilesDir, arguments.getString("directory") ?: "tor-probe")
                val transport = org.ghost.network.TorRelayTransport.create(
                    java.io.File(base, "state"), java.io.File(base, "cache"),
                )
                try {
                    transport.bootstrap()
                    out.putString("tor.bootstrap", "READY")
                } catch (e: org.ghost.network.NetworkException) {
                    out.putString("tor.bootstrap", e.category)
                } finally {
                    transport.close()
                }
            }
            "capability-needs" -> {
                messaging(app)
                val needs = checkNotNull(app.syncController.stores).capabilities.needed()
                out.putString(
                    "capability.needs",
                    needs.groupingBy { Triple(it.source, it.kind, it.reason) }.eachCount().entries.joinToString(",") {
                        "${it.key.first}:${it.key.second}:${it.key.third}=${it.value}"
                    },
                )
            }
            "access-status" -> {
                messaging(app)
                val status = app.entitlement.status()
                out.putString(
                    "access.status",
                    "credits=${status.credits} invites=${status.invites} coverage=${status.coverageEndWeek} " +
                        "fresh=${status.freshTokensPerWeek} flags=${status.flags}",
                )
                val nowSeconds = System.currentTimeMillis() / 1_000L
                var eligible = 0L
                var reserved = 0L
                var earliest = -1L
                var latest = -1L
                app.openDatabaseDirectly()?.let { sql ->
                    sql.query("SELECT count(*) FROM ent_token WHERE kind = 'access' AND state = 'fresh' AND eligible_minute <= ?", listOf(nowSeconds)) { eligible = it.long(0) }
                    sql.query("SELECT count(*) FROM ent_token WHERE kind = 'access' AND state = 'reserved'") { reserved = it.long(0) }
                    sql.query("SELECT min(eligible_minute), max(eligible_minute) FROM ent_token WHERE kind = 'access' AND state = 'fresh'") {
                        earliest = it.long(0)
                        latest = it.long(1)
                    }
                }
                out.putString("access.liquidity", "eligible=$eligible reserved=$reserved earliest=$earliest latest=$latest now=$nowSeconds")
            }
            "access-invite" -> {
                messaging(app)
                val expiryDay = (System.currentTimeMillis() / 86_400_000L).toInt() + 14
                out.putString("access.invite", app.entitlement.createInvite(expiryDay) ?: "NONE")
            }
            "access-invite-existing" -> {
                messaging(app)
                val sql = checkNotNull(app.openDatabaseDirectly())
                var payload: ByteArray? = null
                sql.query(
                    "SELECT payload FROM ent_invite WHERE state = 'created' AND payload IS NOT NULL " +
                        "ORDER BY invite_index ASC LIMIT 1",
                ) { payload = it.blob(0) }
                if (payload == null) {
                    out.putString("access.invite", "NONE")
                } else {
                    val buffer = java.nio.ByteBuffer.wrap(payload)
                    check(buffer.get().toInt() == org.ghost.identity.Invite.VERSION)
                    val token = ByteArray(org.ghost.identity.Invite.TOKEN_BYTES).also(buffer::get)
                    val nonce = ByteArray(org.ghost.identity.Invite.NONCE_BYTES).also(buffer::get)
                    val expiry = buffer.int.toLong() and 0xffff_ffffL
                    val namespace = ByteArray(org.ghost.identity.Invite.NAMESPACE_BYTES).also(buffer::get)
                    val slots = List(org.ghost.identity.Invite.DROP_SLOTS) { buffer.get().toInt() and 0xff }
                    val drop = ByteArray(32).also(buffer::get)
                    val signing = ByteArray(32).also(buffer::get)
                    val signature = ByteArray(64).also(buffer::get)
                    out.putString(
                        "access.invite",
                        org.ghost.identity.Invite(token, nonce, expiry, namespace, slots, drop, signing, signature).encode(),
                    )
                    payload.fill(0)
                }
            }
            "invite-onboard" -> {
                app.ensureDatabaseKey()
                app.syncController.onAppForeground()
                try {
                    val deadline = SystemClock.elapsedRealtime() + WAIT_MILLIS
                    while (app.syncController.stores == null) {
                        check(SystemClock.elapsedRealtime() < deadline) { "the sync stores did not open" }
                        SystemClock.sleep(POLL_MILLIS)
                    }
                    app.bootstrapRelayDirectory()
                    out.putString("onboard.trial", app.entitlement.activate(require("invite")).name)
                    SystemClock.sleep((arguments.getString("seconds") ?: "45").toLong() * MILLIS)
                } finally {
                    app.syncController.onAppBackground()
                }
                app.syncController.awaitIdle(IDLE_WAIT_MILLIS)
                val pin = (arguments.getString("pin") ?: "24681357").toCharArray()
                org.ghost.app.ui.GateLock.configureIfNeeded(app.uiGateways.lock(), pin)
                pin.fill('0')
                out.putString("onboard.identity", app.identityManager.hasIdentity().toString())
                out.putString("onboard.activation", app.entitlement.activationState().name)
                out.putString("onboard.sync", app.syncController.diagnostics().toString())
            }
            "onboard" -> {
                // Fresh local test installs only: create the database and identity, bootstrap the
                // directory, activate DM and set the test PIN through the real gateway.
                app.ensureDatabaseKey()
                if (!app.identityManager.hasIdentity()) {
                    val created = app.identityManager.create(
                        org.ghost.identity.IdentityManager.Activation.Genesis(policyAcknowledged = true),
                    )
                    created.root.zeroize()
                }
                app.bootstrapRelayDirectory()
                val deadline = SystemClock.elapsedRealtime() + WAIT_MILLIS
                var activation: String? = null
                while (SystemClock.elapsedRealtime() < deadline) {
                    activation = app.messagingWiring.activate(restored = false)?.name
                    if (activation != null) break
                    SystemClock.sleep(POLL_MILLIS)
                }
                val pin = (arguments.getString("pin") ?: "24681357").toCharArray()
                require(pin.size in 8..16 && pin.all { it.isDigit() }) { "the test PIN needs 8-16 digits" }
                org.ghost.app.ui.GateLock.configureIfNeeded(app.uiGateways.lock(), pin)
                pin.fill('0')
                out.putString("onboard.identity", app.identityManager.hasIdentity().toString())
                out.putString("onboard.activate", activation ?: "UNAVAILABLE")
            }
            "media-send" -> {
                val messaging = messaging(app)
                val contact = contact()
                val file = java.io.File(require("path"))
                val uri = android.net.Uri.fromFile(file)
                val source = if (require("kind") == "video") {
                    val head = file.inputStream().use { input ->
                        val bytes = ByteArray(64)
                        val read = input.read(bytes)
                        if (read < 0) ByteArray(0) else bytes.copyOf(read)
                    }
                    org.ghost.messaging.api.MediaSource.video(org.ghost.app.media.PickedVideo(app, uri), head)
                } else {
                    org.ghost.messaging.api.MediaSource.image(file.readBytes())
                }
                when (val result = messaging.sendMedia(contact, source, caption = null, viewOnce = false)) {
                    is org.ghost.messaging.api.MediaSendResult.Refused -> {
                        out.putString("media.result", result.result.name)
                    }
                    is org.ghost.messaging.api.MediaSendResult.Queued -> {
                        val deadline = SystemClock.elapsedRealtime() + 180_000L
                        var message: org.ghost.messaging.api.MessageId? = null
                        var failure: String? = null
                        while (message == null && failure == null && SystemClock.elapsedRealtime() < deadline) {
                            when (val state = messaging.preparationState(result.preparation)) {
                                is org.ghost.messaging.api.PreparationView.Committed -> message = state.message
                                is org.ghost.messaging.api.PreparationView.Failed -> {
                                    val cause = state.failure
                                    failure = if (cause is org.ghost.media.send.PrepFailure.UnsupportedSource) {
                                        "UnsupportedSource:${cause.detail}"
                                    } else {
                                        cause.javaClass.simpleName
                                    }
                                }
                                else -> SystemClock.sleep(250L)
                            }
                        }
                        if (message != null) {
                            out.putString("media.result", "COMMITTED")
                            out.putString("media.id", OrderDigests.hex(message.toByteArray()))
                            out.putString("media.state", messaging.mediaState(message).toString())
                            val handle = messaging.openMedia(message)
                            out.putString("media.open", handle?.toString() ?: "UNAVAILABLE")
                            handle?.close()
                        } else {
                            out.putString("media.result", failure ?: "PREPARATION_TIMEOUT")
                        }
                    }
                }
            }
            "media-namespace" -> {
                messaging(app)
                val sql = checkNotNull(app.openDatabaseDirectly())
                val expected = arguments.getString("namespace")?.let(::unhex)
                var namespace: ByteArray? = null
                if (arguments.getString("own") == "true") {
                    sql.query("SELECT namespace_id FROM dm_own_namespace WHERE role = 'media'") { namespace = it.blob(0) }
                } else {
                    sql.query("SELECT namespace_id FROM media_upload ORDER BY object_id DESC LIMIT 1") { namespace = it.blob(0) }
                }
                out.putString("media.namespace", namespace?.let(OrderDigests::hex) ?: "NONE")
                out.putString("media.matches", (namespace == null || expected == null || namespace.contentEquals(expected)).toString())
                namespace?.let { ns ->
                    val registrations = ArrayList<String>()
                    sql.query(
                        "SELECT kind, state, count(*) FROM relay_key_registration WHERE namespace_id = ? GROUP BY kind, state",
                        listOf(ns),
                    ) { registrations += "${it.string(0)}:${it.string(1)}=${it.long(2)}" }
                    out.putString("media.registrations", registrations.joinToString(","))
                }
            }
            "media-relay-probe" -> {
                messaging(app)
                val sql = checkNotNull(app.openDatabaseDirectly())
                val namespace = unhex(require("namespace"))
                val kind = arguments.getString("kind") ?: "read"
                val probes = ArrayList<Triple<String, ByteArray, ByteArray>>()
                sql.query(
                    "SELECT d.onion_address, c.token FROM relay_capability c " +
                        "JOIN relay_directory d ON d.relay_id = c.relay_id " +
                        "WHERE c.namespace_id = ? AND c.kind = ? AND c.state = 'usable'",
                    listOf(namespace, kind),
                ) { probes += Triple(it.string(0), it.blob(1), namespace) }
                val base = java.io.File(app.noBackupFilesDir, "tor-media-probe")
                val transport = org.ghost.network.TorRelayTransport.create(java.io.File(base, "state"), java.io.File(base, "cache"))
                try {
                    transport.bootstrap()
                    val results = ArrayList<String>()
                    for ((relay, credential, ns) in probes) {
                        var verifierMatches = -1L
                        if (kind == "write" && credential.size == org.ghost.crypto.bridge.CredentialV3.CREDENTIAL_BYTES) {
                            val verifier = org.ghost.crypto.bridge.CredentialV3.verifier(
                                org.ghost.crypto.bridge.CredentialV3.Kind.DEPOSIT,
                                credential[2].toInt() and 0xff, ns, credential.copyOfRange(35, 67),
                            )
                            sql.query(
                                "SELECT count(*) FROM relay_key_registration WHERE relay_id = " +
                                    "(SELECT relay_id FROM relay_directory WHERE onion_address = ?) " +
                                    "AND namespace_id = ? AND kind = 'deposit' AND verifier = ?",
                                listOf(relay, ns, verifier),
                            ) { verifierMatches = it.long(0) }
                            verifier.fill(0)
                        }
                        try {
                            val address = org.ghost.network.OnionAddress.parse(relay)
                            if (kind == "write") {
                                val present = transport.check(address, ns, credential, listOf(ByteArray(32) { 0x5a }), 60_000)
                                results += "OK:${present.size}"
                            } else {
                                val page = transport.list(address, ns, credential, ByteArray(0), 1, 60_000)
                                results += "OK:${page.hashes.size}"
                            }
                        } catch (e: org.ghost.network.NetworkException) {
                            results += "${e.category}:verifierMatches=$verifierMatches"
                        }
                    }
                    out.putString("media.relay", results.joinToString(","))
                } finally {
                    transport.close()
                }
            }
            "media-open" -> {
                val messaging = messaging(app)
                val contact = contact()
                val message = org.ghost.messaging.api.MessageId(unhex(require("message")))
                messaging.setConversationOnScreen(contact)
                try {
                    out.putString("media.state", messaging.mediaState(message).toString())
                    val preview = messaging.mediaPreview(message)
                    out.putString("media.preview", preview?.let { "${it.width}x${it.height}" } ?: "UNAVAILABLE")
                    val handle = messaging.openMedia(message)
                    out.putString("media.open", handle?.toString() ?: "UNAVAILABLE")
                    handle?.close()
                } finally {
                    messaging.setConversationOnScreen(null)
                }
            }
            "channel-probe" -> {
                // Phase 13's real composition root, on the phone: distinguish the native library,
                // the stored identity and the channel Keystore from the complete create transaction.
                messaging(app)
                val identity = try {
                    app.identityManager.unlock()
                } catch (e: RuntimeException) {
                    null
                }
                val identityAvailable = identity != null
                identity?.zeroize()
                val keystoreAvailable = try {
                    val key = ByteArray(32) { 0x47 }
                    val wrapper = org.ghost.messaging.android.KeystoreChannelStateKeyWrapper(false)
                    val opened = wrapper.unwrap(wrapper.wrap(key))
                    val roundTrips = opened.contentEquals(key)
                    key.fill(0)
                    opened.fill(0)
                    roundTrips
                } catch (e: RuntimeException) {
                    false
                }
                out.putString(
                    "channel.prereq",
                    "identity=$identityAvailable keystore=$keystoreAvailable facade=${app.channels != null}",
                )
                var contentLength = -1
                var contentOpens = false
                var stateLength = -1
                var stateOpens = false
                var contextCode = "NONE"
                var openCode = "NONE"
                var groupCode = "NONE"
                var scheduleRows = -1
                var activeRelays = -1
                app.openDatabaseDirectly()?.let { sql ->
                    sql.query("SELECT count(*) FROM ent_state") { row -> scheduleRows = row.long(0).toInt() }
                    sql.query("SELECT count(*) FROM relay_directory WHERE state = 'active'") { row -> activeRelays = row.long(0).toInt() }
                    sql.query("SELECT content_key_wrapped FROM dm_self WHERE id = 1") { row ->
                        val wrapped = row.blob(0)
                        contentLength = wrapped.size
                        contentOpens = try {
                            val key = org.ghost.messaging.android.KeystoreContentKeyWrapper(false).unwrap(wrapped)
                            key.fill(0)
                            true
                        } catch (e: RuntimeException) {
                            false
                        }
                    }
                    sql.query("SELECT state_key_wrapped FROM mls_self WHERE id = 1") { row ->
                        val wrapped = row.blob(0)
                        stateLength = wrapped.size
                        val stateKey = try {
                            org.ghost.messaging.android.KeystoreChannelStateKeyWrapper(false).unwrap(wrapped)
                        } catch (e: RuntimeException) {
                            null
                        }
                        if (stateKey != null) {
                            stateOpens = true
                            val opened = org.ghost.crypto.bridge.ChannelCrypto.open(stateKey)
                            contextCode = opened.code.name
                            (opened as? org.ghost.crypto.bridge.MlsOutcome.Ok)?.value?.let { crypto ->
                                try {
                                    val id = ByteArray(32) { 0x19 }
                                    val seed = ByteArray(32) { 0x29 }
                                    val channel = crypto.openChannel(id, seed)
                                    openCode = channel.code.name
                                    (channel as? org.ghost.crypto.bridge.MlsOutcome.Ok)?.value?.let { p ->
                                        val policy = org.ghost.crypto.bridge.ChannelPolicy(
                                            id, 0, 0, 0, 0, 1, 63, 0, byteArrayOf(), listOf(p), listOf(p),
                                        )
                                        groupCode = crypto.groupCreate(id, policy, 20_000).code.name
                                    }
                                } finally {
                                    crypto.close()
                                }
                            }
                            stateKey.fill(0)
                        }
                    }
                }
                out.putString(
                    "channel.stored",
                    "content=$contentLength:$contentOpens state=$stateLength:$stateOpens " +
                        "ctx=$contextCode open=$openCode group=$groupCode scheduleRows=$scheduleRows relays=$activeRelays",
                )
                val channels = channels(app)
                val password = arguments.getString("password") == "true"
                val name = if (password) "gate password channel" else "gate channel"
                val result = channels.create(name.toByteArray(), 0, 0, password)
                out.putString("channel.create", result.status.name)
                out.putInt("channel.count", channels.channels().size)
                result.channel?.let { id ->
                    out.putInt("channel.members", channels.members(id).size)
                    out.putInt("channel.fingerprint", channels.fingerprint(id)?.code?.size ?: 0)
                }
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
                if (arguments.getString("due") == "true" || arguments.getString("settle") == "true") {
                    val channel = unhex(require("channel"))
                    val now = System.currentTimeMillis() / 60_000L * 60L
                    val sql = checkNotNull(app.openDatabaseDirectly())
                    if (arguments.getString("due") == "true") {
                        check(sql.execUpdate("UPDATE ch_schedule SET next_pass_minute = ? WHERE channel_id = ?", listOf(now, channel)) == 1)
                    }
                    if (arguments.getString("settle") == "true") {
                        sql.execUpdate(
                            "UPDATE ch_epoch SET anchor_minute = ? WHERE channel_id = ? AND state = 'open'",
                            listOf(now - 20 * 60L, channel),
                        )
                    }
                }
                // What the app's ON_START does (`SyncWiring.onVisible`): a foreground relay session,
                // whose relay session start is the DM time trigger (`MessagingWiring.sessionHooks`)
                // and whose lanes deposit and fetch. Held for `seconds`, then ON_STOP.
                app.syncController.onAppForeground()
                try {
                    SystemClock.sleep(seconds * MILLIS)
                    out.putString("sync.foreground", app.syncController.status().toString())
                    val settled = java.util.concurrent.CountDownLatch(1)
                    app.messagingWiring.onAlarm { settled.countDown() }
                    check(settled.await(WAIT_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS)) { "the final channel pass did not finish" }
                } finally {
                    app.syncController.onAppBackground()
                }
                app.syncController.awaitIdle(IDLE_WAIT_MILLIS)
                val status = messaging.status()
                out.putString("result", "PASSED")
                out.putString("sync.status", app.syncController.status().toString())
                out.putString("sync.diagnostic", app.syncController.diagnostics().toString())
                out.putString("entitlement.counters", entitlementCounters(app))
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

    /** Reads only the existing fixed-name entitlement counters for the gate's live diagnosis. */
    private fun entitlementCounters(app: GhostApp): String {
        val memoryField = app.entitlement.javaClass.getDeclaredField("memory").apply { isAccessible = true }
        val memory = memoryField.get(app.entitlement)
        val countersField = memory.javaClass.getDeclaredField("counters").apply { isAccessible = true }
        val counters = countersField.get(memory) as Map<*, *>
        return counters.entries.joinToString(",") { "${it.key}=${it.value}" }
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
