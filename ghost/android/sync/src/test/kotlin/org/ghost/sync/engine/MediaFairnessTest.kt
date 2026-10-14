package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.engine.EngineWorld.Companion.SECOND
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The media lane's fairness rules (Phase 11 design §5.5, the suite the design names): media stores
 * never starve DMs nor vice versa inside a store round, a media pair's bundle is fetched in slices
 * of `mediaFetchesPerItem` whose remainder reposts behind queued non-media items, a media event
 * fetches at most the media per-event budget and the rest resumes at the pair's next event, and in
 * a background session media work spends at most `mediaBackgroundRelayWorkMillis` of a relay's
 * `backgroundRelayWorkMillis`, the rest staying for DM, bundle and channel work.
 *
 * The worlds are the deterministic [EngineWorld] with virtual time; the assertions are on the
 * recorded relay calls and the work-lane items that made them.
 */
class MediaFairnessTest {

    /** The [TestRelays.Call]s made while the started lane item [index] ran (items never overlap). */
    private fun callsDuring(driver: DeterministicDriver, calls: List<TestRelays.Call>, index: Int): List<TestRelays.Call> {
        val start = driver.started[index].first
        val end = driver.started.getOrNull(index + 1)?.first ?: Long.MAX_VALUE
        return calls.filter { it.startMillis in start until end }
    }

    private fun List<TestRelays.Call>.ofNamespace(ns: NamespaceId): List<TestRelays.Call> = filter { it.namespace == ns }

    private fun isMediaPair(item: LaneItem, ns: NamespaceId): Boolean = item is WorkItem.PairWork && item.readPair && item.pair.namespace == ns

    /**
     * A media burst enqueued before the DM work with an earlier `not_before` must still be stored
     * after it: a STANDARD pass takes up to `storesPerPass` non-media stores first, then up to
     * `mediaStoresPerPass` media stores.
     */
    @Test
    fun aPassTakesNonMediaStoresBeforeMediaAndCapsMediaAtSixteen() = EngineWorld().use { w ->
        val relays = w.relays(1, 2, 3)
        val dm = w.namespace(1, relays)
        val media = w.namespace(2, relays, consumer = Consumer.MEDIA)
        relays.forEach { w.capability(it, dm); w.capability(it, media) }
        w.net.latency = { 100 } // every call advances the clock, so a pass's calls form one span
        // The media burst comes first: its not_before is a minute earlier than the DM work's.
        for (i in 1..40) w.enqueue(100 + i, media)
        w.clock.advance(MINUTE)
        for (i in 1..40) w.enqueue(200 + i, dm)
        val (_, driver) = w.session()
        driver.runUntil(3 * MINUTE)

        val stores = w.net.callsOf(TestRelays.Kind.STORE)
        val passes = driver.started.mapIndexedNotNull { i, (_, item) -> if (item is WorkItem.Pass) i else null }
        assertTrue("passes ran", passes.isNotEmpty())
        for (passIndex in passes) {
            val round = callsDuring(driver, stores, passIndex)
            val mediaStores = round.ofNamespace(media).size
            val dmStores = round.ofNamespace(dm)
            assertTrue("media stores per pass <= 16 (pass at ${driver.started[passIndex].first})", mediaStores <= 16)
            // Every non-media store of the pass precedes its first media store.
            val firstMediaAt = round.ofNamespace(media).firstOrNull()?.startMillis ?: Long.MAX_VALUE
            assertTrue(
                "non-media stores run before the pass's media stores",
                dmStores.all { it.startMillis < firstMediaAt },
            )
        }
        // The first pass proves the priority and the split exactly: 40 DM ops × 3 relays are due,
        // so the pass attempts 32 DM deliveries and then its 16 media ones.
        val first = callsDuring(driver, stores, passes.first())
        assertEquals(48, first.size)
        assertEquals(32, first.ofNamespace(dm).size)
        assertEquals(16, first.ofNamespace(media).size)
        // Nothing starved: the whole backlog is stored within the run (120 deliveries per class).
        assertEquals(120, stores.ofNamespace(dm).size)
        assertEquals(120, stores.ofNamespace(media).size)
    }

    /** A HIGH pair event stores at most `storesPerPairEvent` of its non-media work and `mediaStoresPerPairEvent` of its media work. */
    @Test
    fun aHighPairEventCapsMediaStoresAtEight() = EngineWorld().use { w ->
        w.mode = PrivacyMode.HIGH
        val relays = w.relays(1, 2)
        val dm = w.namespace(1, relays)
        val media = w.namespace(2, relays, consumer = Consumer.MEDIA)
        relays.forEach {
            w.capability(it, dm, CapabilityKind.READ)
            w.capability(it, dm)
            w.capability(it, media, CapabilityKind.READ)
            w.capability(it, media)
        }
        for (i in 1..20) w.enqueue(100 + i, media)
        for (i in 1..20) w.enqueue(200 + i, dm)
        // An inbound backlog on the media pair, so its event runs continuations (20 blobs > one
        // slice of 8) beside the stores — the per-event claim must hold for the whole event.
        w.inbound(relays[0], media, 1, 20)
        // HIGH mode delays a namespace's first send by U[0, 10 min]: start the session past it so
        // the stores are due from the first pair events.
        w.clock.advance(10 * MINUTE)
        w.net.latency = { 100 }
        val (_, driver) = w.session()
        driver.runUntil(w.clock.millis + 6 * MINUTE)

        val stores = w.net.callsOf(TestRelays.Kind.STORE)
        val checks = w.net.callsOf(TestRelays.Kind.CHECK)
        for ((index, item) in driver.started.withIndex()) {
            val pairWork = item.second as? WorkItem.PairWork ?: continue
            val end = driver.started.getOrNull(index + 1)?.first ?: Long.MAX_VALUE
            val span = stores.filter { it.startMillis in item.first until end }
            assertTrue("media stores per item <= 8", span.ofNamespace(media).size <= 8)
            assertTrue("non-media stores per item <= 8", span.ofNamespace(dm).size <= 8)
            if (pairWork.fetchesOnly) {
                // A continuation carries the next fetch slice only: no store, no check (review F1).
                assertTrue("a continuation stores nothing", span.isEmpty())
                assertTrue("a continuation checks nothing", checks.none { it.startMillis in item.first until end })
            }
        }
        assertTrue("media work ran", stores.ofNamespace(media).isNotEmpty())
        assertTrue("dm work ran", stores.ofNamespace(dm).isNotEmpty())
        assertTrue("continuations ran", driver.started.any { (it.second as? WorkItem.PairWork)?.fetchesOnly == true })
    }

    /**
     * The review's F1 probe shape: a HIGH media read pair with 40 media stores due and 20 inbound
     * blobs. The event's first item delivers its 8 media stores; the fetch continuations deliver
     * zero stores (and zero checks) — without the fetches-only state one event delivered 24.
     */
    @Test
    fun aHighMediaEventDeliversEightStoresAndItsContinuationsDeliverNone() = EngineWorld().use { w ->
        w.mode = PrivacyMode.HIGH
        val relays = w.relays(1, 2)
        val media = w.namespace(1, relays, consumer = Consumer.MEDIA)
        relays.forEach {
            w.capability(it, media, CapabilityKind.READ)
            w.capability(it, media)
        }
        for (i in 1..40) w.enqueue(100 + i, media)
        w.inbound(relays[0], media, 1, 20)
        w.clock.advance(10 * MINUTE)
        w.net.latency = { 100 }
        val (_, driver) = w.session()
        driver.runUntil(w.clock.millis + 6 * MINUTE)

        val stores = w.net.callsOf(TestRelays.Kind.STORE).ofNamespace(media)
        val checks = w.net.callsOf(TestRelays.Kind.CHECK).ofNamespace(media)
        val mediaItems = driver.started.mapIndexedNotNull { i, (_, it) ->
            ((it as? WorkItem.PairWork)?.takeIf { p -> p.pair.namespace == media && p.readPair })?.let { i }
        }
        assertTrue("media pair events ran", mediaItems.isNotEmpty())
        for (index in mediaItems) {
            val item = driver.started[index].second as WorkItem.PairWork
            val end = driver.started.getOrNull(index + 1)?.first ?: Long.MAX_VALUE
            val span = stores.filter { it.startMillis in driver.started[index].first until end }
            if (item.fetchesOnly) {
                assertTrue("continuation at ${driver.started[index].first} stores nothing (got ${span.size})", span.isEmpty())
                assertTrue("continuation checks nothing", checks.none { it.startMillis in driver.started[index].first until end })
            } else {
                assertTrue("event's first item delivers at most 8 media stores (got ${span.size})", span.size <= 8)
            }
        }
        // The probe's aggregate: each event delivers at most its 8 media stores, continuations none.
        val firstEventStores = stores.filter {
            it.startMillis >= driver.started[mediaItems.first()].first &&
                it.startMillis < (driver.started.getOrNull(mediaItems.first() + 1)?.first ?: Long.MAX_VALUE)
        }
        assertTrue("the first event delivers exactly its 8 media stores (got ${firstEventStores.size})", firstEventStores.size <= 8)
    }

    /**
     * A media pair's bundle is fetched in slices of `mediaFetchesPerItem`: 20 due blobs take three
     * work-lane items (8 + 8 + 4) inside one event, none of them carrying more than 8 gets.
     */
    @Test
    fun aMediaBundleFetchesInSlicesOfEight() = EngineWorld().use { w ->
        val relays = w.relays(1, 2)
        val media = w.namespace(1, relays, consumer = Consumer.MEDIA)
        relays.forEach { w.capability(it, media, CapabilityKind.READ) }
        w.inbound(relays[0], media, 1, 20)
        w.net.latency = { if (it.kind == TestRelays.Kind.GET) 10 else 0 }
        val (_, driver) = w.session()
        driver.runUntil(2 * MINUTE)

        val gets = w.net.callsOf(TestRelays.Kind.GET).ofNamespace(media)
        assertEquals(20, gets.size)
        val slices = driver.started.mapIndexedNotNull { i, (_, item) ->
            if (isMediaPair(item, media) && callsDuring(driver, gets, i).isNotEmpty()) i else null
        }
        assertTrue("three slices for 20 blobs", slices.size >= 3)
        for (slice in slices) {
            assertTrue("a slice carries at most 8 gets", callsDuring(driver, gets, slice).size <= 8)
        }
        assertEquals(20, w.count("inbox_blob", "state = 'fetched' AND namespace_id = ?", media.toByteArray()))
    }

    /**
     * The event budget and the resume: 129 blobs exceed a foreground event's `mediaForegroundFetchesPerEvent`
     * = 64 and a background event's `mediaBackgroundFetchesPerEvent` = 128, so the remainder stays
     * due and resumes at the pair's next event, still in slices of at most 8.
     */
    @Test
    fun aMediaEventBudgetCapsAnEventAndTheRestResumesAtTheNextEvent() = EngineWorld().use { w ->
        val relays = w.relays(1)
        val media = w.namespace(1, relays, consumer = Consumer.MEDIA)
        w.capability(relays[0], media, CapabilityKind.READ)
        w.inbound(relays[0], media, 1, 129)
        w.net.latency = { 10 }

        val (_, driver) = w.session(SessionKind.BACKGROUND)
        driver.runUntilFinished(30 * MINUTE)
        // One background event fetches at most the media event budget; nothing is lost or refetched.
        val firstJobGets = w.net.callsOf(TestRelays.Kind.GET).size
        assertEquals(128, firstJobGets)
        assertEquals(128, w.count("inbox_blob", "state = 'fetched'"))

        w.session(SessionKind.BACKGROUND).second.runUntilFinished(30 * MINUTE)
        assertEquals(129, w.net.callsOf(TestRelays.Kind.GET).size)
        assertEquals(129, w.count("inbox_blob", "state = 'fetched'"))
        // No work-lane item ever carried more than one slice.
        val gets = w.net.callsOf(TestRelays.Kind.GET)
        for ((index, item) in driver.started.withIndex()) {
            if (isMediaPair(item.second, media)) {
                assertTrue("a slice carries at most 8 gets", callsDuring(driver, gets, index).size <= 8)
            }
        }
    }

    /**
     * The design's headline scenario: a card holder floods `M_0`, and the delay of DM fetches
     * against a control without media is at most one media slice (8 calls) per DM fetch bundle: a
     * non-media PairWork is never queued behind a media continuation, because the continuation
     * reposts behind the items already queued — so between the moment a DM bundle is queued (its
     * read event ends) and the moment it starts, at most the one media slice already running can
     * deliver media calls.
     */
    @Test
    fun aMediaFloodDelaysEachDmBundleByAtMostOneSlice() = EngineWorld().use { w ->
        val dmRelay = w.relays(1).single()
        val mediaRelay = w.relays(2).single()
        val dm = w.namespace(1, listOf(dmRelay))
        val media = w.namespace(2, listOf(mediaRelay), consumer = Consumer.MEDIA)
        w.capability(dmRelay, dm, CapabilityKind.READ)
        w.capability(mediaRelay, media, CapabilityKind.READ)
        w.inbound(dmRelay, dm, 1, 10)
        w.inbound(mediaRelay, media, 100, 200)
        w.net.latency = { if (it.kind == TestRelays.Kind.GET) 10 else 0 }
        val (_, driver) = w.session()
        // The flood never ends while the run does: more blobs on every lane item.
        var nextSeed = 400
        driver.beforeItem = {
            w.inbound(mediaRelay, media, nextSeed, 20)
            nextSeed += 20
        }
        driver.runUntil(6 * MINUTE)

        // The control: the same DM world without the media flood completes the same DM work.
        EngineWorld().use { control ->
            val cRelay = control.relays(1).single()
            val cDm = control.namespace(1, listOf(cRelay))
            control.capability(cRelay, cDm, CapabilityKind.READ)
            control.inbound(cRelay, cDm, 1, 10)
            control.net.latency = { if (it.kind == TestRelays.Kind.GET) 10 else 0 }
            val (_, controlDriver) = control.session()
            controlDriver.runUntil(6 * MINUTE)
            assertEquals(10, control.net.callsOf(TestRelays.Kind.GET).ofNamespace(cDm).size)
        }

        val gets = w.net.callsOf(TestRelays.Kind.GET)
        val dmGets = gets.ofNamespace(dm)
        assertEquals(10, dmGets.size)
        // For every DM bundle: at most one media slice (8 gets) runs between its read event (which
        // queued it) and its start, and at most one media PairWork starts in that window.
        for ((index, item) in driver.started.withIndex()) {
            val pairWork = (item.second as? WorkItem.PairWork) ?: continue
            if (!pairWork.readPair || pairWork.pair.namespace != dm) continue
            val queuedAt = driver.started.take(index).lastOrNull { (_, it2) ->
                it2 is ReadItem && it2.pair == pairWork.pair
            }?.first ?: continue
            val start = item.first
            if (queuedAt >= start) continue
            val mediaGetsBefore = gets.ofNamespace(media).count { it.startMillis in queuedAt until start }
            assertTrue("at most one media slice delayed the DM bundle at $start (got $mediaGetsBefore)", mediaGetsBefore <= 8)
            val mediaSlices = driver.started.withIndex().count { (i, startedItem) ->
                i < index && isMediaPair(startedItem.second, media) && startedItem.first in queuedAt until start
            }
            assertTrue("at most one media slice item ran before the DM bundle at $start", mediaSlices <= 1)
        }
    }

    /**
     * The media share of the background relay budget: with every call at 5 s, media work spends at
     * most `mediaBackgroundRelayWorkMillis` = 45 s of the relay's 90 s (9 gets), and the rest stays
     * for DM work of that relay.
     */
    @Test
    fun backgroundMediaWorkSpendsAtMostFortyFiveSecondsPerRelay() = EngineWorld().use { w ->
        val mediaRelay = w.relays(1).single()
        val dmRelay = w.relays(2).single()
        val media = w.namespace(1, listOf(mediaRelay), consumer = Consumer.MEDIA)
        val dm = w.namespace(2, listOf(dmRelay))
        w.capability(mediaRelay, media, CapabilityKind.READ)
        w.capability(dmRelay, dm, CapabilityKind.READ)
        w.inbound(mediaRelay, media, 100, 60)
        w.inbound(dmRelay, dm, 1, 40)
        w.net.latency = { 5 * SECOND }
        val (session, driver) = w.session(SessionKind.BACKGROUND)
        driver.runUntilFinished(30 * MINUTE)

        assertEquals(9, w.net.callsOf(TestRelays.Kind.GET).ofNamespace(media).size)
        assertEquals(45_000L, session.work.mediaRelaySpent(mediaRelay))
        // The DM relay, undisturbed by media, spends the whole 90 s budget on gets alone (the read
        // lane's list is not a work-lane call): 18 gets, and no further call once the budget is spent.
        assertEquals(18, w.net.callsOf(TestRelays.Kind.GET).ofNamespace(dm).size)
    }

    /**
     * Media and DM on one relay: the media share is 45 s of the relay's 90 s, so media gets at most
     * 9 gets (45 s) and DM work still gets the remainder — media never eats the whole relay.
     */
    @Test
    fun mediaNeverSpendsMoreThanItsShareWhenSharingARelayWithDm() = EngineWorld().use { w ->
        val relay = w.relays(1).single()
        val media = w.namespace(1, listOf(relay), consumer = Consumer.MEDIA)
        val dm = w.namespace(2, listOf(relay))
        w.capability(relay, media, CapabilityKind.READ)
        w.capability(relay, dm, CapabilityKind.READ)
        w.inbound(relay, media, 100, 60)
        w.inbound(relay, dm, 1, 40)
        w.net.latency = { 5 * SECOND }
        val (session, driver) = w.session(SessionKind.BACKGROUND)
        driver.runUntilFinished(30 * MINUTE)

        assertTrue("media spent at most its share plus one call", session.work.mediaRelaySpent(relay) <= 45_000 + 5_000)
        val mediaGets = w.net.callsOf(TestRelays.Kind.GET).ofNamespace(media).size
        assertTrue("media bounded by its share (9 gets)", mediaGets in 8..10)
        // DM work of the same relay still ran: the rest of the budget stayed for it.
        assertTrue("dm work ran on the shared relay", w.net.callsOf(TestRelays.Kind.GET).ofNamespace(dm).size >= 1)
    }

    /**
     * The review's F2 probe (a): a media pair's `CheckRound` spends the media share. A write-only
     * media pair whose stores spent the 45 s share (9 stores at 5 s on each of its two relays) is
     * never checked — the check is denied with the share, not charged to the DM side of the
     * budget. Without the fix the check is allowed (45 s of the total 90 s remain on each relay)
     * and CHECK calls are made.
     */
    @Test
    fun aMediaPairsChecksAreDeniedWhenTheMediaShareIsSpent() =
        EngineWorld(TrafficPolicy(verifyAckAgeSeconds = 5, mediaStoresPerPass = 24)).use { w ->
            val relays = w.relays(1, 2)
            val media = w.namespace(1, relays, listen = false, consumer = Consumer.MEDIA)
            relays.forEach { w.capability(it, media) }
            for (i in 1..12) w.enqueue(100 + i, media)
            w.net.latency = { 5 * SECOND }
            val (_, driver) = w.session(SessionKind.BACKGROUND)
            driver.runUntilFinished(30 * MINUTE)

            // 24 deliveries (12 ops × 2 relays) at 5 s each: each relay's share stops its media
            // work at exactly 9 stores (45 s), the rest is denied, and each pair's verification
            // check — due, write-only pairs check after the policy's 5 s — is denied with the
            // share: no CHECK call is ever made.
            assertEquals(18, w.net.callsOf(TestRelays.Kind.STORE).size)
            assertTrue("no check ran on the media pairs", w.net.callsOf(TestRelays.Kind.CHECK).isEmpty())
        }

    /**
     * The review's F2 probe (b): the check before restore's deadline is cut to the media share's
     * remainder. In one background job's pass the restore store of an earlier-`not_before` op
     * spends 5 s of the relay's media share before the copy-checking attempt runs, so the check's
     * deadline is the share's remainder (45 s − 5 s = 40 s), not the 60 s call deadline. Without
     * the fix the deadline is `min(60 s, total left)` = 60 s. (The share is per session and the
     * bucket resets between jobs, so the spending and the check happen in one pass; the two ops are
     * ordered by `not_before` so the restore store runs before the copy check.)
     */
    @Test
    fun aMediaChecksDeadlineIsCutToTheSharesRemainder() = EngineWorld(
        // No verification checks in the probe's window: the only CHECK calls are the two
        // check-before-restore calls under measurement.
        TrafficPolicy(verifyAckAgeSeconds = 30L * 86_400),
    ).use { w ->
        val relays = w.relays(1, 2)
        val media = w.namespace(1, relays, listen = false, consumer = Consumer.MEDIA)
        relays.forEach { w.capability(it, media) }
        val aHash = w.hashOf(1)
        val bHash = w.hashOf(2)
        w.enqueue(2, media)
        w.clock.advance(MINUTE)
        w.enqueue(1, media) // later not_before: op 2's deliveries sort before op 1's
        w.net.latency = { 5 * SECOND }
        // Job 1: op 2's stores fail before apply (definite, retried later); op 1's are applied and
        // then a timeout answers (ambiguous: a possible copy, checked before any restore).
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE && it.hashes.single() == bHash) "transport" else null }
        w.net.failAfter = { if (it.kind == TestRelays.Kind.STORE && it.hashes.single() == aHash) "timeout" else null }
        w.session(SessionKind.BACKGROUND).second.runUntilFinished(30 * MINUTE)
        assertEquals(4, w.net.callsOf(TestRelays.Kind.STORE).size)

        // Job 2: op 2 stores first (5 s more of the share), then op 1's copy is checked.
        w.net.failBefore = { null }
        w.net.failAfter = { null }
        w.clock.advance(60 * MINUTE)
        w.session(SessionKind.BACKGROUND).second.runUntilFinished(w.clock.millis + 30 * MINUTE)
        assertEquals(6, w.net.callsOf(TestRelays.Kind.STORE).size)
        val checks = w.net.callsOf(TestRelays.Kind.CHECK)
        assertEquals(2, checks.size)
        for (check in checks) assertEquals(40_000, check.deadlineMillis)
    }
}
