package org.ghost.messaging.media

import org.ghost.crypto.bridge.DmCards
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.engine.DmTimers
import org.ghost.messaging.engine.MediaEngineSupport
import org.ghost.messaging.engine.MediaPipelinePorts
import org.ghost.messaging.engine.MediaSteps
import org.ghost.messaging.engine.Sweeper
import org.ghost.messaging.FakeDmCrypto
import org.ghost.messaging.port.DmCrypto
import org.ghost.media.send.MediaPreparer
import org.ghost.media.send.Preparations
import org.ghost.media.send.VideoSource
import org.ghost.media.store.MediaKind
import org.ghost.media.store.MediaLimits
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.ghost.sync.api.Outcome
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.util.SplittableRandom
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** The scale of the media privacy world (Phase 11 design §15.6; the F9 PrivacyScale pattern). */
internal enum class MediaPrivacyScale(val clients: Int, val days: Int, val mediaPerClientDay: Double) {
    SMALL(8, 4, 0.5),
    PR(60, 14, 0.5),
    GATE(300, 28, 0.3),
    ;

    companion object {
        /** `-Dghost.media.privacy=gate|small` selects; anything else is the PR scale. */
        fun selected(): MediaPrivacyScale = when (System.getProperty("ghost.media.privacy")) {
            "gate" -> GATE
            "small" -> SMALL
            else -> PR
        }
    }
}

/** The honest world's exemptions to JM1's exact-count rule (design §15.6's LM exemptions). */
internal enum class MediaExemption(val wire: String) {
    FAILED("FAILED"),
    DEADLINE("deadline"),
    USER_DELETED("user deletion"),
}

internal class TruthObject(
    val sender: Int,
    val recipient: Int,
    val objectId: ByteArray,
    val kindIsImage: Boolean,
    val viewOnce: Boolean,
    val classCode: Int,
    val manifestHash: ByteArray,
    val fragmentHashes: List<ByteArray>,
    val keyEnv: ByteArray,
    val ttlSeconds: Long,
    /** The upload deadline in epoch seconds (R-T4: author + min(bucket, 7 d), or the PM-M20 shape). */
    val deadlineSecond: Long,
    val commitMinute: Long,
    val contentLen: Long,
    /** The conversation timer's own length (0 = off: the object never expires). */
    val timerSeconds: Long,
    var exemption: MediaExemption? = null,
    var viewed: Boolean = false,
    var inRequest: Boolean = false,
    /** The plan's view act: [viewed] is what the world actually did (recorded at endOfWorld). */
    var viewPlanned: Boolean = false,
    var recipientMessageId: ByteArray? = null,
) {
    fun allHashes(): List<ByteArray> = listOf(manifestHash) + fragmentHashes
}

/** The ground truth, recorded from the engine's own calls (the F9 GroundTruth discipline). */
internal class MediaTruth {
    val objects = ArrayList<TruthObject>()
    private val byHash = HashMap<String, TruthObject>()
    private val ownMediaByClient = HashMap<Int, ByteArray>()
    private val inboxByClient = HashMap<Int, ByteArray>()

    fun record(o: TruthObject) {
        objects += o
        for (h in o.allHashes()) byHash[hexOf(h)] = o
    }

    fun objectByHash(hashHex: String): TruthObject? = byHash[hashHex]
    fun ownMedia(client: Int): ByteArray = ownMediaByClient[client]!!
    fun ownInbox(client: Int): ByteArray = inboxByClient[client]!!
    fun recordIdentity(client: Int, media: ByteArray, inbox: ByteArray) {
        ownMediaByClient[client] = media
        inboxByClient[client] = inbox
    }

    fun exemptionBreakdown(): String {
        val counts = objects.filter { it.exemption != null }.groupingBy { it.exemption!! }.eachCount()
        if (counts.isEmpty()) return "none"
        return counts.entries.joinToString(", ") { "${it.value} ${it.key.wire}" }
    }
}

/**
 * Per-client identity for the privacy world: [FakeDmCrypto] gives every device the same card, so
 * all namespaces would collide across clients. [SaltedCrypto] gives each client its own card and
 * derives every card-bound namespace from the *card itself* — so a sender computing `M_c` from
 * the recipient's card and the recipient computing its own `M_0` agree, which is the production
 * property (§5.1). Everything else delegates to the fake.
 */
internal class SaltedCrypto(private val ownIndex: Int) : DmCrypto {
    private val inner = FakeDmCrypto()

    companion object {
        fun worldCard(index: Int): ByteArray = expand(digestOf("ghost-media-world card $index".toByteArray()), 131)

        private fun idSalt(card: ByteArray): ByteArray =
            digestOf("ghost-media-world identity".toByteArray() + card.copyOfRange(0, 16))

        private fun ns(card: ByteArray, label: String, slot: Int = 0, size: Int = 32): ByteArray =
            expand(digestOf(idSalt(card) + label.toByteArray() + byteArrayOf(slot.toByte())), size)

        private fun expand(seed: ByteArray, size: Int): ByteArray {
            val out = ByteArray(size)
            var at = 0
            var ctr = 0
            while (at < size) {
                val block = digestOf(seed + byteArrayOf(ctr++.toByte()))
                val n = minOf(block.size, size - at)
                block.copyInto(out, at, 0, n)
                at += n
            }
            return out
        }

        private fun digestOf(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    }

    override fun isAvailable(): Boolean = inner.isAvailable()

    override fun beginMediaSealer(
        destId: ByteArray,
        kind: org.ghost.crypto.bridge.MediaCrypto.Kind,
        viewOnce: Boolean,
        maxClass: Int,
    ) = inner.beginMediaSealer(destId, kind, viewOnce, maxClass)

    override fun ownCard(cardIndex: Int): DmSessions.OwnCard? {
        if (!inner.isAvailable()) return null
        val card = worldCard(ownIndex)
        return DmSessions.OwnCard(
            card = card,
            inboxNamespace = ns(card, "inbox-ns"),
            bundleNamespace = ns(card, "bundle-ns"),
            mediaNamespace = ns(card, "media-ns"),
            recognitionIntro = ns(card, "rec-intro"),
            recognitionBundle = ns(card, "rec-bundle"),
            olmIdentity = ns(card, "olm"),
            publicationOffsetSeconds = 3 * 86_400L + 1_200L,
        )
    }

    override fun ownSecrets(cardIndex: Int, slot: Int): DmSessions.OwnSecrets? = inner.ownSecrets(cardIndex, slot)

    override fun bundleCreate(cardIndex: Int, bundleWeek: Long, bundleRank: Int, genId: Int): DmSessions.BundleGeneration? =
        inner.bundleCreate(cardIndex, bundleWeek, bundleRank, genId)

    override fun stateKeyWrapped(): ByteArray? = inner.stateKeyWrapped()

    override fun parseCard(card: ByteArray): DmCards.ParseResult = inner.parseCard(card)

    override fun deriveCard(card: ByteArray, slot: Int): DmCards.DeriveResult {
        if (!inner.isAvailable()) return DmCards.DeriveResult.Unavailable
        if (card.size != 131) return DmCards.DeriveResult.InvalidCard
        return DmCards.DeriveResult.Ok(
            DmCards.Derived(
                inboxNamespace = ns(card, "inbox-ns"),
                bundleNamespace = ns(card, "bundle-ns"),
                mediaNamespace = ns(card, "media-ns"),
                deposit = ns(card, "deposit", slot),
                fetch = ns(card, "fetch", slot),
                mediaDeposit = ns(card, "media-deposit", slot),
                recognitionIntro = ns(card, "rec-intro"),
                recognitionBundle = ns(card, "rec-bundle"),
                introKeyEnv = ns(card, "intro-env", size = 60),
                bundleKeyEnv = ns(card, "bundle-env", size = 60),
            )
        )
    }

    override fun safetyNumber(
        ownIdentityPk: ByteArray,
        ownOlm: ByteArray,
        peerIdentityPk: ByteArray,
        peerOlm: ByteArray,
    ): DmSessions.SafetyNumber? = inner.safetyNumber(ownIdentityPk, ownOlm, peerIdentityPk, peerOlm)

    override fun issueRevocation(issuedMinute: Long, reason: org.ghost.crypto.bridge.DmRevocations.Reason) =
        inner.issueRevocation(issuedMinute, reason)

    override fun verifyRevocation(certificate: ByteArray, expectedIdentityPk: ByteArray) =
        inner.verifyRevocation(certificate, expectedIdentityPk)
}

/** One scripted send of the world's plan (the stochastic model compiles to these, like F9). */
internal class ScriptedSend(
    val day: Int,
    val minuteOfDay: Int,
    val sender: Int,
    val recipient: Int,
    val kindIsImage: Boolean,
    val classCode: Int,
    val viewOnce: Boolean,
    val withCaption: Boolean,
    /** The conversation's timer code (§7.1: 0 off, 1 = 5 min, 2 = 1 h, 3 = 1 d, 4 = 7 d, 5 = 30 d). */
    val timerCode: Int,
    val deliverDescriptor: Boolean = true,
    /** Scripted exemption: fail this fragment ordinal, reach the deadline, or delete by the user. */
    val failAtOrdinal: Int? = null,
    val reachDeadline: Boolean = false,
    val userDeleted: Boolean = false,
    /** Viewed by the recipient after verification (NI-M2, the seizure check). */
    val viewed: Boolean = false,
    /** The upload rides background sessions spread over the hour (NI-M7's shape, D26). */
    val backgroundOnly: Boolean = false,
    /** A request conversation's object: never delivered, never opened (the seizure list). */
    val inRequest: Boolean = false,
)

/** The twin/mutant knobs; the honest world's is the default of every field. */
internal class MediaWorldVariant(
    val name: String = "honest",
    /** NI-M1: these objects' descriptors (hex object id) are withheld by the relays of X. */
    val withholdDescriptors: Set<String> = emptySet(),
    /** NI-M2: the recipient views nothing (vs everything). */
    val viewNothing: Boolean = false,
    /** The scripted sends; null = the stochastic plan of [MediaPrivacyScale]. */
    val scriptedSends: List<ScriptedSend>? = null,
    /** PM-M16: `M_0` is registered at the first media use, not at activation. */
    val registerAtFirstMediaUse: Boolean = false,
    /** PM-M7: the sender redeems its own capability for the recipient's `M_c`. */
    val senderRedeemsRecipientMedia: Boolean = false,
    /** PM-M19: ingest stops claiming at the pool cap. */
    val stopIngestAtPoolCap: Boolean = false,
    /** PM-M5: the recipient fetches the moment a descriptor arrives (no listing first). */
    val fetchOnDescriptor: Boolean = false,
    /** PM-M1: the last fragment of every object is stored in the 1-hour bucket. */
    val lastFragmentSmallBucket: Boolean = false,
    /** PM-M8: view-once objects are stored with the 1-hour TTL. */
    val viewOnceHourTtl: Boolean = false,
    /** PM-M25: the object's TTL is taken from the conversation's timer at SEND, not at commit. */
    val ttlFromSendTimer: Boolean = false,
    /** PM-M20: the sender's countdown starts at the commit (D26 violated). */
    val countdownAtCommit: Boolean = false,
    /** PM-M2: no class padding — only the content's chunks are stored. */
    val noClassPadding: Boolean = false,
    /** PM-M4: the manifest is stored as a half-size blob (sized by its hash list). */
    val manifestByHashList: Boolean = false,
) {
    /** The twins vary one knob at a time (data class semantics without the generated copy's noise). */
    fun copy(
        name: String = this.name,
        withholdDescriptors: Set<String> = this.withholdDescriptors,
        viewNothing: Boolean = this.viewNothing,
        scriptedSends: List<ScriptedSend>? = this.scriptedSends,
        registerAtFirstMediaUse: Boolean = this.registerAtFirstMediaUse,
        senderRedeemsRecipientMedia: Boolean = this.senderRedeemsRecipientMedia,
        stopIngestAtPoolCap: Boolean = this.stopIngestAtPoolCap,
        fetchOnDescriptor: Boolean = this.fetchOnDescriptor,
        lastFragmentSmallBucket: Boolean = this.lastFragmentSmallBucket,
        viewOnceHourTtl: Boolean = this.viewOnceHourTtl,
        ttlFromSendTimer: Boolean = this.ttlFromSendTimer,
        countdownAtCommit: Boolean = this.countdownAtCommit,
        noClassPadding: Boolean = this.noClassPadding,
        manifestByHashList: Boolean = this.manifestByHashList,
    ) = MediaWorldVariant(
        name, withholdDescriptors, viewNothing, scriptedSends, registerAtFirstMediaUse,
        senderRedeemsRecipientMedia, stopIngestAtPoolCap, fetchOnDescriptor, lastFragmentSmallBucket,
        viewOnceHourTtl, ttlFromSendTimer, countdownAtCommit, noClassPadding, manifestByHashList,
    )
}

/**
 * The media privacy world (Phase 11 design §15.6): [scale]'s clients, each a real `:messaging` +
 * `:media` media stack ([MediaWorld]'s assembly — real stores, steps, feeder, preparer and sealer
 * seams) on its own database and ciphertext directory, driven by a scripted behaviour model over
 * the [MediaModelRelay] that records the effective relay view with blobs as recipes. The joins
 * (JM1–JM7) and the twins (NI-M1–NI-M7) read the recorded view and [MediaTruth].
 *
 * **What is modeled, and what is not** (each narrowing named in the report and §22.12, the
 * F-S11-1 discipline): the traffic is the media lane — media stores into `M_c`, the descriptor
 * deposit into `X`, the recipient's `M_0` list/get passes, the owner's `M_0` registers. The
 * per-client `:sync` engine underneath (pair events, work bundles, the redeem lane) is not run:
 * registers/redeems are modeled events, JM7's "work bundle" is the world's fetch pass, and
 * NI-M5's register trace is `M_0`'s alone (the redeem lane is the entitlement world's JD8). The
 * sealer is the deterministic stand-in; the gate fidelity of re-deriving relay blobs by re-sealing
 * through the host build's `testSealBeginWithKey` is the recorded follow-up. Native randomness is
 * the OS's (§15.1): every check is on shapes, joins and truth.
 */
internal class MediaPrivacyWorld(
    val scale: MediaPrivacyScale,
    val seed: Long,
    val variant: MediaWorldVariant = MediaWorldVariant(),
) : AutoCloseable {

    val truth = MediaTruth()
    val relay = MediaModelRelay()

    private val root: File = Files.createTempDirectory("ghost-media-privacy").toFile()
    private val devices = HashMap<Int, Device>()
    private var passCounter = 0

    /** The world's shared readers registry (the devices judge incoming wires by it, like the native reader). */
    private val sharedReaders = FakeReaders()
    val readers: FakeReaders get() = sharedReaders

    /** The world's end (the sweeps ran past every bound), for the seizure check's expiry test. */
    private var endSecondsValue: Long = MediaWorld.NOW + scale.days * 86_400L
    fun endSeconds(): Long = endSecondsValue

    /** A per-client device: the [MediaWorld] assembly plus the support and sweeper for views/expiry. */
    private inner class Device(val index: Int) : AutoCloseable {
        val dir: File = File(root, "c$index").also { it.mkdirs() }
        val world: MediaWorld = MediaWorld(
            File(dir, "world.db").absolutePath,
            dir,
            cryptoFactory = { SaltedCrypto(index) },
            sealerClientIndex = index,
            sharedReaders = sharedReaders,
        )
        private val worker: ExecutorService = Executors.newSingleThreadExecutor()

        val support: MediaEngineSupport = MediaEngineSupport(
            database = world.database,
            steps = world.steps,
            receiveSteps = world.receiveSteps,
            preparations = Preparations(),
            pipeline = MediaPipelinePorts(
                world.files, world.preparing, FakeStripper, FakeVideoExport, world.readers, world.decoder,
            ),
            worker = worker,
            random = world.random,
            contexts = world.contexts,
            actorCall = { it() },
            checkpoint = { world.realCheckpoint() },
        )

        val sweeper: Sweeper = Sweeper(
            database = world.database,
            namespaces = world.stores.namespaces,
            envelopes = world.envelopes,
            pairKeys = org.ghost.messaging.engine.PairKeySteps(world.envelopes),
            checkpoint = { world.realCheckpoint() },
            clock = world.clock,
            contexts = world.contexts,
            media = org.ghost.messaging.engine.MessagingRuntime.SweepMediaPort(),
            mediaOrphans = org.ghost.messaging.engine.MediaOrphanSteps(world.crypto, world.clock),
            mediaCheckpoint = org.ghost.messaging.engine.MediaCheckpointState(),
        )

        var registered = false

        /** Hashes already deposited (listings repeat them until relay expiry — insert-once). */
        val fetchedHashes = HashSet<String>()

        init {
            world.activate()
            val card = world.crypto.ownCard(0)!!
            truth.recordIdentity(index, card.mediaNamespace.copyOf(), card.inboxNamespace.copyOf())
        }

        /** The owner's `M_0` register at its relays (activation, or the first media use — PM-M16). */
        fun registerOwnMedia(minute: Long) {
            if (registered) return
            registered = true
            for (slot in 0 until 2) {
                relay.record(
                    MediaViewEvent(
                        op = MediaViewOp.REGISTER, minute = minute, client = index, relaySlot = slot,
                        role = MediaNsRole.OWN_MEDIA, namespace = truth.ownMedia(index),
                        circuit = "c$index",
                    )
                )
            }
        }

        override fun close() {
            worker.shutdown()
            world.close()
        }
    }

    private fun device(index: Int): Device = devices.getOrPut(index) { Device(index) }

    init {
        // Activation registers: every client of the scale at minute 0, unless the variant defers
        // registration to the first media use (PM-M16).
        if (!variant.registerAtFirstMediaUse) {
            repeat(scale.clients) { device(it).registerOwnMedia(minute = 0L) }
        }
    }

    /** The plan: scripted sends, or the seeded stochastic model at the media rate (§15.1). */
    private fun plan(): List<ScriptedSend> {
        variant.scriptedSends?.let { return it.sortedWith(compareBy({ it.day }, { it.minuteOfDay })) }
        val rnd = SplittableRandom(seed)
        val sends = ArrayList<ScriptedSend>()
        val edges = HashMap<Int, MutableList<Int>>()
        // A sparse contact graph: each client picks 3–5 contacts.
        repeat(scale.clients) { a ->
            val degree = 3 + rnd.nextInt(3)
            repeat(degree) {
                val b = rnd.nextInt(scale.clients)
                if (b != a) edges.computeIfAbsent(a) { ArrayList() }.add(b)
            }
        }
        val timers = intArrayOf(1, 2, 2, 3, 4, 4, 4, 4, 5, 0) // 5-min … 30-day, off; 7-day modal
        val dayMinutes = 24 * 60
        for (day in 0 until scale.days) {
            for (client in 0 until scale.clients) {
                // The media rate: a mean of mediaPerClientDay sends per client per day.
                var remaining = scale.mediaPerClientDay
                while (remaining > 0) {
                    if (rnd.nextDouble() >= remaining) break
                    remaining -= 1.0
                    val peers = edges[client] ?: continue
                    val peer = peers[rnd.nextInt(peers.size)]
                    val roll = rnd.nextInt(100)
                    val classCode = when {
                        roll < 90 -> 0
                        roll < 99 -> 1 + rnd.nextInt(4)
                        else -> 5 + rnd.nextInt(6)
                    }
                    sends += ScriptedSend(
                        day = day,
                        minuteOfDay = rnd.nextInt(dayMinutes),
                        sender = client,
                        recipient = peer,
                        kindIsImage = classCode == 0 && rnd.nextBoolean(),
                        classCode = classCode,
                        viewOnce = rnd.nextInt(100) < 5,
                        withCaption = rnd.nextInt(100) < 50,
                        timerCode = timers[rnd.nextInt(timers.size)],
                        viewed = rnd.nextInt(100) < 40,
                    )
                }
            }
        }
        // The seizure control's anchor: one off-timer, never-viewed object whose key legitimately
        // survives to the horizon (the JC-5 floor — a control that found no live object would
        // prove nothing). The stochastic plan does not guarantee one at every scale.
        sends += ScriptedSend(
            day = 0, minuteOfDay = 1, sender = 0, recipient = 1,
            kindIsImage = true, classCode = 0, viewOnce = false, withCaption = true,
            timerCode = 0, viewed = false,
        )
        return sends.sortedWith(compareBy({ it.day }, { it.minuteOfDay }))
    }

    /** Run the world to its horizon; returns the joins over the recorded view. */
    fun run(): MediaJoins {
        val sends = plan()
        for (send in sends) {
            driveSend(send)
            // The recipient's scheduled fetch pass runs after the send's minute.
            fetchPass(send.recipient, send.day, send.minuteOfDay + 30)
        }
        endOfWorld()
        return MediaJoins(relay.events, truth, relay)
    }

    private fun setClock(device: Device, day: Int, minuteOfDay: Int) {
        device.world.clock.now = MediaWorld.NOW + day * 86_400L + minuteOfDay * 60L
    }

    private fun driveSend(send: ScriptedSend) {
        val sender = device(send.sender)
        val recipient = device(send.recipient)
        setClock(sender, send.day, send.minuteOfDay)
        setClock(recipient, send.day, send.minuteOfDay)
        val commitMinute = minuteOfDay(send.day, send.minuteOfDay)
        sender.registerOwnMedia(commitMinute)
        recipient.registerOwnMedia(commitMinute)

        val contact = contactId(send.sender, send.recipient)
        val recipientContact = contactId(send.recipient, send.sender)
        ensureContact(sender, send.recipient, contact)
        ensureContact(recipient, send.sender, recipientContact)
        // The conversation's timer for this send (a TIMER_SET's row shape).
        sender.world.sql.exec(
            "UPDATE dm_conversation SET timer_code = ?, timer_version = timer_version + 1 WHERE contact_id = ?",
            listOf(send.timerCode, contact),
        )

        sender.world.sealerFactory.forceClass = send.classCode
        val prepared: MediaPreparer.Prepared = if (send.kindIsImage) {
            sender.world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = send.viewOnce)
        } else {
            sender.world.preparer.prepareVideo(
                FakeVideoSource, contact, viewOnce = send.viewOnce, maxClass = MediaLimits.CLASSES.size - 1,
            )
        }
        sender.world.sealerFactory.forceClass = null

        val sealed = prepared.sealed
        val authorMinuteSeconds = DmTime.floorMinute(sender.world.clock.now)
        val bucket = DmTimers.bucketOf(send.timerCode)
        // PM-M25: the TTL is taken from the conversation's timer at SEND — modeled as the 1-hour
        // bucket for every non-hour timer (the SEND-time read of a changed conversation).
        val recordedTtl: Long = if (variant.ttlFromSendTimer && send.timerCode !in 1..2) 3_600L
                                else bucket.seconds.toLong()
        // R-T4: author + min(bucket, 7 d). PM-M20 (D26 violated): commit + timer instead.
        val deadlineSecond = if (variant.countdownAtCommit) {
            authorMinuteSeconds + DmTimers.timerSeconds(send.timerCode)
        } else {
            DmTimers.deadlineSeconds(authorMinuteSeconds, bucket)
        }
        val truthObject = TruthObject(
            sender = send.sender,
            recipient = send.recipient,
            objectId = sealedObjectId(prepared),
            kindIsImage = send.kindIsImage,
            viewOnce = send.viewOnce,
            classCode = sealed.classCode,
            manifestHash = sealed.manifestHash.copyOf(),
            fragmentHashes = sealed.fragmentHashes.map { it.copyOf() },
            keyEnv = sealed.keyEnv.copyOf(),
            // The ground truth is the commit-time bucket (R-MT4) — a mutant taking the TTL from
            // the SEND-time timer stores a different value, and JM4's equality names it.
            ttlSeconds = bucket.seconds.toLong(),
            deadlineSecond = deadlineSecond,
            commitMinute = commitMinute,
            contentLen = sealed.contentLen,
            timerSeconds = DmTimers.timerSeconds(send.timerCode),
        )
        truthObject.inRequest = send.inRequest
        truthObject.viewPlanned = send.viewed

        val request = MediaSteps.CommitRequest(
            contactId = contact,
            kind = if (send.kindIsImage) MediaKind.IMAGE else MediaKind.VIDEO,
            viewOnce = send.viewOnce,
            classCode = sealed.classCode,
            objectId = truthObject.objectId,
            manifestHash = sealed.manifestHash,
            caption = if (send.withCaption) "caption".toByteArray() else ByteArray(0),
            keyEnv = sealed.keyEnv,
            manifestBlob = sealed.manifestBlob,
            manifestFile = sealed.manifestFile,
            fragmentHashes = sealed.fragmentHashes,
            fragmentFiles = sealed.fragmentFiles,
        )
        val committed = sender.world.steps.commit(sender.world.contexts.get()!!, request)
        check(committed is MediaSteps.CommitResult.Committed) { "the world commits: $committed" }

        // PM-M7: the sender redeems its own capability for the recipient's M_c.
        if (variant.senderRedeemsRecipientMedia) {
            for (slot in 0 until 2) {
                relay.record(
                    MediaViewEvent(
                        op = MediaViewOp.REDEEM, minute = commitMinute, client = send.sender, relaySlot = slot,
                        role = MediaNsRole.CONTACT_MEDIA, namespace = truth.ownMedia(send.recipient),
                        circuit = "c${send.sender}",
                    )
                )
            }
        }

        // The upload: feed, drain, repeat — the work lane's window is 32 OPEN ordinals per object,
        // so a pass enqueues only until the window is full and the next pass proceeds only after
        // outcomes drain it. Ops a previous object left pending (a FAILED sibling's leftovers)
        // match nothing and are refused, exactly as the relay would refuse bytes it cannot place.
        // FAILED/deadline exemptions store fewer ordinals and get no descriptor (JM1's LM list).
        val allNew = LinkedHashSet<String>()
        val ordinalOf = HashMap<String, Int>()
        var passes = 0
        while (passes < 64) {
            val before = sender.world.relay.held.keys.toSet()
            sender.world.steps.feed()
            val fresh = sender.world.relay.held.keys.filter { it !in before && it !in allNew }
            if (fresh.isEmpty()) break
            passes++
            for (opHex in fresh) {
                val blobHash = sender.world.sql.let { sql ->
                    var h = ByteArray(0)
                    sql.query("SELECT blob_hash FROM outbox_op WHERE operation_id = ?", listOf(unhex(opHex))) { r ->
                        h = r.blob(0)
                    }
                    h
                }
                val hex = hexOf(blobHash)
                ordinalOf[opHex] = when {
                    hex == hexOf(sealed.manifestHash) -> MediaLimits.MANIFEST_ORDINAL
                    else -> sealed.fragmentHashes.indexOfFirst { hexOf(it) == hex }
                        .let { if (it < 0) Int.MIN_VALUE else it }
                }
            }
            allNew += fresh
            // SENT for this round's accepted ordinals (the FAILED one, if scripted, lands last);
            // the outcomes drain the window for the next pass.
            for (op in fresh.sortedBy { ordinalOf[it] }) {
                val ord = ordinalOf[op]!!
                if (ord == Int.MIN_VALUE) continue
                if (send.failAtOrdinal != null && ord == send.failAtOrdinal) continue
                sender.world.relay.script(opId(op), Outcome.SENT)
            }
            sender.world.steps.outcomes()
        }
        val newOps = allNew.toList()
        val failAt = send.failAtOrdinal
        val accepted = newOps.filter { op ->
            val ord = ordinalOf[op] ?: Int.MIN_VALUE
            ord != Int.MIN_VALUE && ord >= MediaLimits.MANIFEST_ORDINAL && (failAt == null || ord < failAt)
        }
        val contentGroups = contentGroupCount(sealed.contentLen)
        // An upload that rides background sessions (NI-M7) or reaches its deadline (the LM
        // exemption) spreads its group stores over the following minutes and stops at the upload
        // deadline (R-T4) — the burst is never cut by the timer, D26.
        val spreadMinutes = when {
            send.reachDeadline -> 20L
            send.backgroundOnly -> 8L
            else -> 0L
        }
        val storedOrdinals = accepted.filter { op ->
            val ord = ordinalOf[op]!!
            if (spreadMinutes > 0) {
                // The store's absolute second against the upload deadline (R-T4) — both epoch.
                MediaWorld.NOW + (commitMinute + spreadMinutes * (ord / 4)) * 60 < deadlineSecond
            } else {
                true
            }
        }.filter { op ->
            val ord = ordinalOf[op]!!
            !variant.noClassPadding || ord == MediaLimits.MANIFEST_ORDINAL || ord / 4 < contentGroups
        }

        for (op in storedOrdinals.sortedBy { ordinalOf[it] }) {
            val ord = ordinalOf[op]!!
            val isManifest = ord == MediaLimits.MANIFEST_ORDINAL
            val ttl: Long = when {
                variant.viewOnceHourTtl && send.viewOnce -> 3_600L
                variant.lastFragmentSmallBucket && ord == sealed.fragmentHashes.size - 1 -> 3_600L
                else -> recordedTtl
            }
            val recipe = if (isManifest) {
                MediaRecipe.Manifest(
                    objectId = truthObject.objectId,
                    kindCode = if (send.kindIsImage) 1 else 2,
                    viewOnce = send.viewOnce,
                    classCode = sealed.classCode,
                    contentLen = sealed.contentLen,
                    width = 1_280,
                    height = 720,
                    durationMs = 0,
                    preview = sealed.preview.copyOf(),
                    hashes = sealed.fragmentHashes.map { it.copyOf() },
                )
            } else {
                MediaRecipe.Fragment(truthObject.objectId, ord / 4, ord % 4)
            }
            val blobBytes = recipe.bytes()
            val storeMinute = if (spreadMinutes > 0) commitMinute + spreadMinutes * (ord / 4) else commitMinute
            for (slot in 0 until 2) {
                relay.store(
                    MediaViewEvent(
                        op = MediaViewOp.STORE, minute = storeMinute, client = send.sender, relaySlot = slot,
                        role = MediaNsRole.CONTACT_MEDIA, namespace = truth.ownMedia(send.recipient),
                        circuit = "c${send.sender}->m${send.recipient}",
                        size = if (variant.manifestByHashList && isManifest) MediaLimits.FRAGMENT_BYTES / 2
                               else MediaLimits.FRAGMENT_BYTES,
                        ttlSeconds = ttl, hash = digest(blobBytes),
                        credentialScope = "md(${send.recipient})",
                        deadlineSeconds = deadlineSecond,
                    ),
                    recipe,
                )
            }
        }
        val uploadComplete = storedOrdinals.count { ordinalOf[it]!! >= 0 } ==
            MediaLimits.CLASSES[truthObject.classCode]

        // The scripted failure lands last (every other ordinal was acked in the feed loop).
        if (failAt != null) {
            val failedOp = newOps.firstOrNull { ordinalOf[it] == failAt }
            if (failedOp != null) sender.world.relay.script(opId(failedOp), Outcome.FAILED)
        }
        sender.world.steps.outcomes()

        when {
            send.failAtOrdinal != null -> {
                truthObject.exemption = MediaExemption.FAILED
                truth.record(truthObject)
                prepared.releaseNames()
                return
            }
            send.reachDeadline || (send.backgroundOnly && !uploadComplete) -> {
                // The upload reaches its deadline before READY: the object fails, no descriptor.
                truthObject.exemption = MediaExemption.DEADLINE
                truth.record(truthObject)
                prepared.releaseNames()
                return
            }
            send.userDeleted -> {
                truthObject.exemption = MediaExemption.USER_DELETED
                truth.record(truthObject)
                prepared.releaseNames()
                return
            }
        }
        truth.record(truthObject)

        // The descriptor: the sender deposits it into the recipient's X in both twins — "withheld"
        // (NI-M1) is the relays of X not delivering it, which never changes the relay view. The
        // object's bucket rides it (JM4's descriptor clause, R-MT4). A request's descriptor is
        // never delivered and never opened (D28).
        val descriptorSent = send.deliverDescriptor && !send.inRequest
        if (descriptorSent) {
            for (slot in 0 until 2) {
                relay.record(
                    MediaViewEvent(
                        op = MediaViewOp.STORE, minute = commitMinute + 1, client = send.recipient, relaySlot = slot,
                        role = MediaNsRole.OWN_INBOX, namespace = truth.ownInbox(send.recipient),
                        circuit = "c${send.sender}->x${send.recipient}",
                        size = 4_096, ttlSeconds = recordedTtl, hash = sealed.manifestHash.copyOf(),
                    )
                )
            }
            val withheld = variant.withholdDescriptors.contains(hexOf(truthObject.objectId))
            if (!withheld) {
                val messageId = recipient.world.receiveDescriptor(
                    recipientContact,
                    org.ghost.media.store.MediaDescriptor(
                        truthObject.objectId,
                        if (send.kindIsImage) MediaKind.IMAGE else MediaKind.VIDEO,
                        viewOnce = send.viewOnce,
                        classCode = sealed.classCode,
                        manifestHash = sealed.manifestHash,
                    ),
                    keyEnv = sealed.keyEnv,
                    relayExpiryHour = DmTime.ceilHour(deadlineSecond) + 24 * 3_600L,
                    // The recipient countdown (§10.3's unread cap, the never-read upper bound):
                    // the sweep at expiry erases the key — the seizure check's premise.
                    timerCode = send.timerCode,
                    unreadDeadlineMinute = if (send.timerCode == 0) null else minOf(
                        DmTime.ceilHour(deadlineSecond) + 24 * 3_600L,
                        DmTime.floorMinute(recipient.world.clock.now) +
                            DmTimers.timerSeconds(send.timerCode) + 3_600L,
                    ),
                )
                truthObject.recipientMessageId = messageId
                // PM-M5: the recipient fetches the moment the descriptor arrives — no listing first.
                if (variant.fetchOnDescriptor) {
                    for (hash in truthObject.allHashes()) {
                        relay.get(send.recipient, 0, truth.ownMedia(send.recipient), hash, commitMinute + 1, pass = 0)
                    }
                }
            }
        }
        prepared.releaseNames()
    }

    /** The recipient's scheduled pass: list `M_0`, get the new hashes, ingest, bind, verify. */
    private fun fetchPass(recipient: Int, day: Int, minuteOfDay: Int) {
        val device = devices[recipient] ?: return
        setClock(device, day, minuteOfDay)
        val minute = minuteOfDay(day, minuteOfDay)
        val pass = ++passCounter
        val ns = truth.ownMedia(recipient)
        for (slot in 0 until 2) {
            val listed = relay.list(recipient, slot, ns, minute, pass)
            for (hash in listed) {
                if (variant.stopIngestAtPoolCap && pooledBytes(device) >= MediaLimits.POOL_CAP_BYTES) continue
                if (!device.fetchedHashes.add(hexOf(hash))) continue
                val bytes = relay.get(recipient, slot, ns, hash, minute, pass) ?: continue
                device.world.depositMedia(bytes, relayExpirySeconds = (minute / 60 + 24 * 7) * 3_600L)
            }
            device.world.receiveSteps.ingest()
        }
        device.world.receiveSteps.bind()
        device.world.receiveSteps.verify()
    }

    /** The bytes a device holds that no fragment row names yet (§7.5's pool — MC-M10's oracle). */
    private fun pooledBytes(device: Device): Long =
        device.world.sql.queryLong(
            "SELECT count(*) FROM media_blob b WHERE b.origin = 'ingested' AND NOT EXISTS " +
                "(SELECT 1 FROM media_fragment f WHERE f.blob_hash = b.blob_hash)",
            emptyList(),
        )!! * MediaLimits.FRAGMENT_BYTES

    private fun endOfWorld() {
        for ((index, device) in devices) {
            // Views at the horizon (verified, unexpired objects the plan marks viewed; the local
            // act, NI-M2). An object that expired before the view is not viewable — production's
            // expiry-filtered lookup refuses it, and the sweep takes it as expired.
            device.world.clock.now = MediaWorld.NOW + scale.days * 86_400L
            for (o in truth.objects) {
                if (o.recipient != index || !o.viewPlanned || o.viewed || o.exemption != null || o.inRequest) continue
                if (variant.viewNothing) continue
                val state = device.world.sql.queryString(
                    "SELECT state FROM media_object WHERE object_id = ?",
                    listOf(o.objectId),
                )
                if (state != "verified") continue
                if (o.viewOnce) {
                    val messageId = o.recipientMessageId ?: continue
                    val handle = device.support.openViewOnce(messageId) ?: continue
                    o.viewed = true
                    handle.close()
                } else {
                    o.viewed = true
                }
            }
            // Then just past the horizon: the sweeper runs (expiry erases the keys — the seizure
            // list), the pool GC and the reconcile. The horizon, not a far jump: the seizure at
            // day N tries keys against blobs of objects expired *by* day N — archived blobs of
            // still-live objects (a 30-day bucket expiring on the horizon) must not meet a stored
            // key, and the control needs live objects whose blobs the relay still holds.
            device.world.clock.now = MediaWorld.NOW + (scale.days + 2L) * 86_400L
            device.sweeper.sweep()
            device.world.receiveSteps.gc()
            device.world.reconcile()
        }
        relay.expire(minuteOfDay(scale.days + 2, 0))
        endSecondsValue = MediaWorld.NOW + (scale.days + 2L) * 86_400L
    }

    /** Every `key_env` byte string still stored in any client's database (the seizure check's set). */
    internal fun storedKeyEnvs(): List<Pair<Int, ByteArray>> {
        val out = ArrayList<Pair<Int, ByteArray>>()
        for ((index, device) in devices) {
            device.world.sql.query(
                "SELECT key_env FROM media_object WHERE key_env IS NOT NULL",
                emptyList(),
            ) { r -> out += index to r.blob(0).copyOf() }
        }
        return out
    }

    /** The per-relay normalized views the twins compare (§15.6's normalized-view rule). */
    fun normalizedViews(stripCircuit: Boolean = false): Map<Int, List<String>> {
        val hashRank = HashMap<String, Int>()
        val views = HashMap<Int, MutableList<String>>()
        for (e in relay.events.sortedWith(compareBy({ it.minute }, { it.op.ordinal }, { it.client }))) {
            val rank = e.hash?.let { h -> hashRank.computeIfAbsent(hexOf(h)) { hashRank.size } } ?: -1
            val circuit = if (stripCircuit) "-" else e.circuit
            val line = "${e.minute} ${e.op} ${e.role.wire} sz=${e.size}" +
                (e.ttlSeconds?.let { " ttl=$it" } ?: "") +
                " cs=${e.credentialScope ?: "-"}" +
                (if (e.op == MediaViewOp.LIST) " n=${e.listed?.size ?: 0}" else "") +
                (if (e.op == MediaViewOp.GET || e.op == MediaViewOp.STORE) " h#$rank" else "") +
                " c=$circuit p=${e.pass}"
            views.getOrPut(e.relaySlot) { ArrayList() } += line
        }
        return views
    }

    /** The projected view for NI-M3/NI-M5: the given roles' events (one client's, when given),
     *  circuit and harness pass ids off — neither is relay-visible. */
    fun projectedView(roles: Set<MediaNsRole>, client: Int? = null, stripTtl: Boolean = false): List<String> =
        relay.events
            .filter { it.role in roles && (client == null || it.client == client) }
            .sortedWith(compareBy({ it.minute }, { it.op.ordinal }, { it.client }))
            .map { e ->
                "${e.minute} ${e.op} ${e.role.wire} sz=${e.size}" +
                    (if (!stripTtl) e.ttlSeconds?.let { " ttl=$it" } ?: "" else "")
            }

    private fun minuteOfDay(day: Int, minuteOfDay: Int): Long = day * 24 * 60L + minuteOfDay.toLong()

    /** The sealer's own id (the request names it, so the readers' registry stays consistent). */
    private fun sealedObjectId(prepared: MediaPreparer.Prepared): ByteArray = prepared.objectId

    private fun contactId(a: Int, b: Int): ByteArray =
        digest("ghost-media-world contact $a->$b".toByteArray()).copyOfRange(0, 16)

    /** The contact row for [peer] on [device], with the peer's card sealed in (M_c agreement). */
    private fun ensureContact(device: Device, peer: Int, contactId: ByteArray) {
        val existing = device.world.sql.queryLong(
            "SELECT count(*) FROM dm_contact WHERE contact_id = ?",
            listOf(contactId),
        )!!
        if (existing > 0) return
        val self = device.world.contexts.get()!!
        val peerCard = SaltedCrypto.worldCard(peer)
        val cardEnv = self.content.seal(device.world.random.bytes(12), contactId, peerCard)
        device.world.sql.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, " +
                "source, establishment) VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(
                contactId,
                digest("ghost-media-world identity-pk $contactId".toByteArray()).copyOfRange(0, 32),
                cardEnv,
            ),
        )
        device.world.sql.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(digest("ghost-media-world conversation $contactId".toByteArray()).copyOfRange(0, 16), contactId),
        )
    }

    /** How many chunk groups the content alone fills (PM-M2 stores only these). */
    private fun contentGroupCount(contentLen: Long): Int {
        val chunks = (contentLen / MediaLimits.CHUNK_PLAINTEXT).toInt()
        val tail = contentLen % MediaLimits.CHUNK_PLAINTEXT != 0L
        return (if (tail || chunks == 0) chunks + 1 else chunks).coerceAtLeast(1)
    }

    private fun opId(opHex: String): org.ghost.sync.api.OperationId = org.ghost.sync.api.OperationId(unhex(opHex))

    private fun unhex(hex: String): ByteArray {
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) out[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    override fun close() {
        for ((_, device) in devices) device.close()
        root.deleteRecursively()
    }
}

private val FakeVideoSource: VideoSource = object : VideoSource {
    override fun mediaItem(): androidx.media3.common.MediaItem =
        androidx.media3.common.MediaItem.Builder().setUri("file:///ghost/fake-video.mp4").build()

    override fun durationUs(): Long = 30_000_000L

    override fun rotationDegrees(): Int = 0
}
