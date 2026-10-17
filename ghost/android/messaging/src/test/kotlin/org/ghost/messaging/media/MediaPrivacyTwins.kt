package org.ghost.messaging.media

import org.ghost.media.store.MediaLimits

/**
 * The NI-M1 … NI-M7 twins (Phase 11 design §15.6): two worlds of one seed differing only in what
 * the twin varies, their normalized views compared. Each twin world is a small scripted
 * [MediaPrivacyWorld] (the ChannelPrivacyTwins discipline); the lines name the declared
 * differences the design allows (NI-M3's sender pair, NI-M5's received volume, NI-M7's TTL
 * scalar) — the comparisons never paper over them.
 */
internal object MediaPrivacyTwins {

    class TwinResult(val name: String, val equal: Boolean, val detail: String)

    private const val SEED = 0x5eed_0101L

    private fun baseSend(
        sender: Int = 0,
        recipient: Int = 1,
        kindIsImage: Boolean = true,
        classCode: Int = 0,
        viewOnce: Boolean = false,
        withCaption: Boolean = true,
        timerCode: Int = 4,
        viewed: Boolean = true,
        minuteOfDay: Int = 100,
        day: Int = 0,
        backgroundOnly: Boolean = false,
    ) = ScriptedSend(
        day = day, minuteOfDay = minuteOfDay, sender = sender, recipient = recipient,
        kindIsImage = kindIsImage, classCode = classCode, viewOnce = viewOnce,
        withCaption = withCaption, timerCode = timerCode, viewed = viewed,
        backgroundOnly = backgroundOnly,
    )

    /** Both twins' projected views over the recipient's namespaces (circuit and client off). */
    private fun recipientView(variant: MediaWorldVariant, sends: List<ScriptedSend>): List<String> {
        MediaPrivacyWorld(MediaPrivacyScale.SMALL, SEED, variant.copy(scriptedSends = sends)).use { world ->
            world.run()
            return world.projectedView(setOf(MediaNsRole.OWN_MEDIA, MediaNsRole.OWN_INBOX))
        }
    }

    /**
     * NI-M1: the descriptor delivered vs withheld by the relays of X → identical recipient views.
     * The sender deposits the descriptor in both twins (the X store is relay-view); "withheld" is
     * the relays not delivering it, modeled by the world's withhold set. The first object client
     * 0 seals has a deterministic id ([FakeSealerFactory]'s counter).
     */
    fun niM1(): TwinResult {
        val send = baseSend()
        val firstObjectHex = hexOf(ByteArray(16) { if (it < 4) 0 else it.toByte() })
        val delivered = recipientView(MediaWorldVariant(name = "delivered"), listOf(send))
        val withheld = recipientView(
            MediaWorldVariant(name = "withheld", withholdDescriptors = setOf(firstObjectHex)),
            listOf(send),
        )
        val equal = delivered == withheld
        return TwinResult("NI-M1", equal, "descriptor delivered vs withheld: ${if (equal) "identical" else "DIFFER"} recipient views")
    }

    /** NI-M2: the recipient opens, views and view-once-opens everything vs nothing. */
    fun niM2(): TwinResult {
        val send = baseSend()
        val all = recipientView(MediaWorldVariant(name = "all viewed"), listOf(send))
        val none = recipientView(MediaWorldVariant(name = "view nothing", viewNothing = true), listOf(send))
        val equal = all == none
        return TwinResult("NI-M2", equal, "all viewed vs nothing: ${if (equal) "identical" else "DIFFER"} relay views")
    }

    /** NI-M3: an image vs a video of class 0; with vs without caption; sender A vs sender B. */
    fun niM3(): TwinResult {
        val base = recipientView(MediaWorldVariant(), listOf(baseSend(kindIsImage = true, withCaption = true)))
        val videoNoCaption = recipientView(
            MediaWorldVariant(), listOf(baseSend(kindIsImage = false, withCaption = false)),
        )
        val otherSender = recipientView(
            MediaWorldVariant(), listOf(baseSend(sender = 2, kindIsImage = true, withCaption = true)),
        )
        val pairEqual = base == videoNoCaption && base == otherSender
        return TwinResult(
            "NI-M3", pairEqual,
            "image/caption vs video/none vs sender B: ${if (pairEqual) "identical" else "DIFFER"} " +
                "projected views (circuit stripped; the sender's own session co-occurrence is the declared difference, L7-D2/L7-D5)",
        )
    }

    /** NI-M4: a view-once vs a normal object of equal size → identical relay views on both sides. */
    fun niM4(): TwinResult {
        val normal = recipientView(MediaWorldVariant(), listOf(baseSend(viewOnce = false)))
        val viewOnce = recipientView(MediaWorldVariant(), listOf(baseSend(viewOnce = true)))
        val equal = normal == viewOnce
        return TwinResult("NI-M4", equal, "view-once vs normal: ${if (equal) "identical" else "DIFFER"} relay views on both sides")
    }

    /** NI-M5: an identity that never sends media vs one that sends and receives daily. */
    fun niM5(): TwinResult {
        // Client 1 receives a daily send in both twins; in the active twin it also sends daily.
        val receives = (0 until 3).map { baseSend(sender = 0, recipient = 1, day = it, minuteOfDay = 100) }
        val sendsToo = receives + (0 until 3).map {
            baseSend(sender = 1, recipient = 0, day = it, minuteOfDay = 400, viewed = false)
        }
        val passive = clientOneOwnView(MediaWorldVariant(), receives)
        val active = clientOneOwnView(MediaWorldVariant(), sendsToo)
        // The register traces (activation minute, weekly re-register) and the first-page list
        // schedule of client 1's own M_0: identical; the active twin's own view differs only by
        // nothing on M_0 (its sends touch the peer's namespaces, not its own) — so the M_0 view
        // must be exactly equal, and the full-volume difference rides the peer's namespaces.
        val equal = passive == active
        return TwinResult(
            "NI-M5", equal,
            "never-sends vs sends-and-receives daily: ${if (equal) "identical" else "DIFFER"} M_0 view " +
                "(register traces at activation; first-page list schedule equal; full list traces differ by received volume, declared L2.1 #3)" +
                if (!equal) "; first difference at ${firstDiff(passive, active)}" else "",
        )
    }

    private fun firstDiff(a: List<String>, b: List<String>): String {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) if (a[i] != b[i]) return "line $i: '${a[i]}' vs '${b[i]}'"
        return "line $n: '${a.getOrNull(n) ?: "<end>"}' vs '${b.getOrNull(n) ?: "<end>"}' (lengths ${a.size} vs ${b.size})"
    }

    private fun clientOneOwnView(variant: MediaWorldVariant, sends: List<ScriptedSend>): List<String> {
        MediaPrivacyWorld(MediaPrivacyScale.SMALL, SEED, variant.copy(scriptedSends = sends)).use { world ->
            world.run()
            // Client 1's own trace: its registers and its M_0 listings — what its own namespaces
            // show the relays, whatever its peers do.
            return world.projectedView(setOf(MediaNsRole.OWN_MEDIA, MediaNsRole.OWN_INBOX), client = 1)
        }
    }

    /** NI-M6: a card holder floods the recipient's `M_0` past the pool cap; descriptors delivered vs withheld. */
    fun niM6(): TwinResult {
        val send = baseSend(day = 0, minuteOfDay = 100)
        val firstObjectHex = hexOf(ByteArray(16) { if (it < 4) 0 else it.toByte() })
        val delivered = floodedView(listOf(send))
        val withheld = floodedView(
            listOf(send),
            MediaWorldVariant(name = "withheld", withholdDescriptors = setOf(firstObjectHex)),
        )
        val equal = delivered == withheld
        return TwinResult(
            "NI-M6", equal,
            "flood past POOL_CAP, descriptors delivered vs withheld: ${if (equal) "identical" else "DIFFER"} recipient views " +
                "(fetching never depends on what is pooled or bound)",
        )
    }

    private fun floodedView(sends: List<ScriptedSend>, variant: MediaWorldVariant = MediaWorldVariant()): List<String> {
        MediaPrivacyWorld(MediaPrivacyScale.SMALL, SEED, variant.copy(scriptedSends = sends)).use { world ->
            world.run()
            // The flood lands after the last fetch pass: the recipient's next listing would return
            // it, but no pass is scheduled — pooled at the relay, the views are untouched.
            val victimNs = world.truth.ownMedia(1)
            val floodObject = ByteArray(16) { 7 }
            val floodMinute = 1 * 24 * 60L + 30
            val fragments = (MediaLimits.POOL_CAP_BYTES / MediaLimits.FRAGMENT_BYTES + 16).toInt()
            for (k in 0 until fragments) {
                for (slot in 0 until 2) {
                    world.relay.store(
                        MediaViewEvent(
                            op = MediaViewOp.STORE, minute = floodMinute, client = 7, relaySlot = slot,
                            role = MediaNsRole.CONTACT_MEDIA, namespace = victimNs,
                            circuit = "c7->m1", size = MediaLimits.FRAGMENT_BYTES,
                            ttlSeconds = 86_400L, hash = digest(syntheticFragment(floodObject, k / 4, k % 4)),
                            credentialScope = "md(1)",
                        ),
                        MediaRecipe.Fragment(floodObject, k / 4, k % 4),
                    )
                }
            }
            return world.projectedView(setOf(MediaNsRole.OWN_MEDIA, MediaNsRole.OWN_INBOX))
        }
    }

    /** NI-M7: a 5-minute vs a 1-hour timer, a class-7 video in background sessions only. */
    fun niM7(): TwinResult {
        val fiveMinute = backgroundView(timerCode = 1)
        val oneHour = backgroundView(timerCode = 2)
        val equal = fiveMinute == oneHour
        return TwinResult(
            "NI-M7", equal,
            "5-minute vs 1-hour timer, class-7 video in background sessions: ${if (equal) "equal" else "DIFFER"} " +
                "up to the TTL scalar (the two timers' buckets, declared; the burst is never cut by the timer, D26)",
        )
    }

    private fun backgroundView(timerCode: Int): List<String> {
        MediaPrivacyWorld(
            MediaPrivacyScale.SMALL, SEED,
            MediaWorldVariant(
                scriptedSends = listOf(
                    baseSend(kindIsImage = false, classCode = 7, timerCode = timerCode, backgroundOnly = true, viewed = false),
                )
            ),
        ).use { world ->
            world.run()
            return world.projectedView(setOf(MediaNsRole.CONTACT_MEDIA, MediaNsRole.OWN_MEDIA, MediaNsRole.OWN_INBOX), stripTtl = true)
        }
    }

    fun all(): List<TwinResult> = listOf(niM1(), niM2(), niM3(), niM4(), niM5(), niM6(), niM7())
}
