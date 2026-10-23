package org.ghost.staging

import java.io.File

/**
 * Staging harness CLI (tools/staging-harness/README.md). Commands:
 *
 *   activate --state <dir>            the genesis bootstrap stages, idempotent and resumable
 *   activate --state <dir> --invite-file <file>   the second identity's real trial (invite text)
 *   dm --with <other state dir> --state <dir>
 *   t6-twin --state <dir> --out <dir>
 *
 * One fixed line per stage, no keys, no addresses, no plaintext (T3). Exit 0 only when the step's
 * criterion holds. The staging endpoints below are data, not code: they name the live deployment
 * on ghost-runner (issuer + slots 0/1/2 of the accepted ES).
 */
object StagingConfig {
    const val ISSUER_ONION: String = "yc5kgo3q6eyexdscqt7lhwlhxqni4a6b3p2yzcfalmmaxbgbggvya3ad.onion"
    const val RELAY_A: String = "dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion"
    const val RELAY_B: String = "zlaedoy2kjoq6kybq4lidy2mvsvnnfbgfn4cgzowwqtpmg624xpni3ad.onion"
    const val RELAY_C: String = "dlwabzl7bh6x3xotfnujdi7poevpkvu7u5yz22bkhm32a6gs4mufolyd.onion"
}

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        usage()
        kotlin.system.exitProcess(2)
    }
    when (args[0]) {
        "activate" -> activate(args.drop(1))
        "trial" -> trial(args.drop(1))
        "dm" -> println("dm: NOT_YET_WIRED")
        "t6-twin" -> println("t6-twin: NOT_YET_WIRED")
        else -> {
            usage()
            kotlin.system.exitProcess(2)
        }
    }
}

/**
 * Drive a pending invite activation to ACTIVE: the redemption is a quiet-run issuer call (like
 * BlindSign), and HostSync has no periodic jobs - so run quiet-run steps until the state settles.
 */
private fun trial(args: List<String>) {
    val state = File(args.option("--state") ?: run { usage(); return })
    StagingWorld(state).use { world ->
        System.load(System.getProperty("ghost.dm.native"))
        for (i in 1..8) {
            val s = world.entitlement.activationState()
            println("trial: state=$s (round $i)")
            if (s == org.ghost.entitlement.api.ActivationState.ACTIVE ||
                s == org.ghost.entitlement.api.ActivationState.FAILED
            ) {
                return
            }
            if (s == org.ghost.entitlement.api.ActivationState.PENDING) {
                // An onboarding trial runs as a USER issuer call at foreground (§8.3), never as
                // quiet-run work - that lane serves only revocations with a due time.
                world.foreground()
                world.controller.awaitIdle(150_000)
                println("trial: FOREGROUND_STEP")
            } else {
                Thread.sleep(15_000)
            }
        }
    }
}

/**
 * The activation chain (owner directive, 2026-10-21): genesis is zero (E6), so the bootstrap is
 * staged and resumable - the asynchronous protocol windows (BlindSign ~4 h Q22, activation slot
 * ~28 h §12.3) never block a session: each run advances what is due and prints the stage.
 */
private fun activate(args: List<String>) {
    val state = File(args.option("--state") ?: run { usage(); return })
    val inviteFile = args.option("--invite-file")?.let(::File)
    StagingWorld(state).use { world ->
        val loadProbe = try {
            System.load(System.getProperty("ghost.dm.native"))
            "LOAD_OK"
        } catch (e: Throwable) {
            "LOAD_FAIL ${e.javaClass.simpleName}: ${e.message}"
        }
        println("activate: $loadProbe")
        val probe = try {
            val s = org.ghost.entitlement.android.NativeTokenCrypto().scheduleSummary()
            "PROBE_OK network=${s.network} weeks=${s.firstWeek}..${s.lastWeek} keys=${s.keys.size}"
        } catch (e: Exception) {
            "PROBE_FAIL ${e.javaClass.simpleName}: ${e.message}"
        }
        println("activate: $probe")
        if (inviteFile != null) {
            val result = world.entitlement.activate(inviteFile.readText().trim())
            println("activate: trial result=$result")
            // The RedeemInvite runs as a user issuer call on a callback thread; keep the world
            // alive until the runtime is idle so the call completes (or fails) in this run.
            world.controller.awaitIdle(5 * 60_000)
            println("activate: IDLE state=${world.entitlement.activationState()}")
            return
        }
        if (!world.hasIdentity()) {
            world.genesis()
            println("activate: GENESIS_OK")
        } else {
            println("activate: GENESIS_ALREADY")
        }
        val status = world.entitlement.status()
        println("activate: engine=${status.javaClass.simpleName}")
        // Terminal rows stay in openPurchases() (the list is "all purchases", §3.6); a run after
        // an expiry must not resurrect them - drive the first live row, or start a fresh one.
        val terminal = setOf(
            org.ghost.entitlement.api.PurchaseUiState.EXPIRED_SEEN,
            org.ghost.entitlement.api.PurchaseUiState.EXPIRED_UNPAID,
            org.ghost.entitlement.api.PurchaseUiState.LOST,
            org.ghost.entitlement.api.PurchaseUiState.CANCELLED,
            org.ghost.entitlement.api.PurchaseUiState.FINALIZED,
        )
        val purchase = world.entitlement.openPurchases().firstOrNull { it.state !in terminal }
        val id = if (purchase == null) {
            if (world.entitlement.openPurchases().any { it.state == org.ghost.entitlement.api.PurchaseUiState.FINALIZED }) {
                // The pack is paid and signed: mint the invite for the second identity (§8.6).
                val day = (System.currentTimeMillis() / 86_400_000L).toInt()
                val invite = world.entitlement.createInvite(day + 14)
                if (invite == null) {
                    println("activate: INVITE_NOT_READY (no fresh token or no usable drop relays)")
                } else {
                    val out = File(state, "invite.txt")
                    out.writeText(invite)
                    println("activate: INVITE_WRITTEN ${out.absolutePath}")
                }
                return
            }
            val fresh = world.entitlement.startPurchase(org.ghost.entitlement.api.PayWith.XMR)
            if (fresh == null) {
                println("activate: PURCHASE_REFUSED (schedule window or engine not ready)")
                return
            }
            world.entitlement.requestInvoiceNow(fresh)
            println("activate: PURCHASE_REQUESTED")
            fresh
        } else {
            println("activate: PURCHASE_EXISTS state=${purchase.state}")
            if (purchase.state == org.ghost.entitlement.api.PurchaseUiState.PREPARED) {
                world.entitlement.requestInvoiceNow(purchase.id)
                println("activate: INVOICE_REQUESTED")
            }
            purchase.id
        }
        if (id != null) {
            // Poll for the invoice: Tor bootstrap + the issuer call take minutes, not seconds.
            val deadline = System.currentTimeMillis() + 6 * 60_000
            while (System.currentTimeMillis() < deadline) {
                Thread.sleep(10_000)
                // J2's order: the instructions exist only after every required disclosure is
                // acknowledged - the harness acknowledges them all (staging has no UI gate).
                val disclosures = world.entitlement.requiredDisclosures(id)
                if (disclosures.isNotEmpty()) {
                    world.entitlement.acknowledge(id, disclosures)
                    println("activate: DISCLOSURES_ACKNOWLEDGED count=${disclosures.size}")
                }
                // The app calls checkNow when the payer returns from the wallet; without it the
                // issuer-side credit reaches this engine only on a later quiet run.
                world.entitlement.checkNow(id)
                println("activate: CHECK_NOW")
                // HostSync runs WakeScheduler.NO_WAKE: no periodic job ever fires in this process,
                // so the quiet-run issuer call (BlindSign attempts, credit sync past the
                // invoiceStatus range) must be driven by hand, one due item per run. The call runs
                // on a callback thread, so wait for the runtime to go idle before touching the
                // state again - otherwise the world closes the database under the in-flight call.
                world.controller.runUserIssuerCall { session ->
                    world.participant.onQuietRun(session)
                }
                world.controller.awaitIdle(5 * 60_000)
                println("activate: QUIET_RUN_STEP")
                val now = world.entitlement.openPurchases().firstOrNull { it.state !in terminal }
                if (now != null) println("activate: PURCHASE_NOW state=${now.state}")
                if (world.entitlement.openPurchases().any { it.state == org.ghost.entitlement.api.PurchaseUiState.FINALIZED }) {
                    println("activate: PACK_FINALIZED")
                    return
                }
                val instructions = world.entitlement.paymentInstructions(id)
                if (instructions != null) {
                    // The invoice address is public data (it is what the payer pays to); print it
                    // whole and also drop it in the state dir for the payment step.
                    val invoice = File(state, "invoice.txt")
                    val nl = System.lineSeparator()
                    invoice.writeText(
                        "subaddress=" + instructions.subaddress + nl +
                            "amount_atomic=" + instructions.amountAtomic + nl +
                            "deadline_minute=" + instructions.deadlineMinute + nl +
                            "uri=" + (instructions.uri ?: "") + nl,
                    )
                    println("activate: AWAITING_PAYMENT subaddress=${instructions.subaddress} amount=${instructions.amountAtomic}")
                    println("activate: invoice written to ${invoice.absolutePath}")
                    return
                }
                val state = world.entitlement.openPurchases().firstOrNull { it.state !in terminal }?.state
                if (state == org.ghost.entitlement.api.PurchaseUiState.LOST || state == org.ghost.entitlement.api.PurchaseUiState.EXPIRED_UNPAID || state == org.ghost.entitlement.api.PurchaseUiState.CANCELLED) {
                    println("activate: INVOICE_FAILED state=$state")
                    kotlin.system.exitProcess(1)
                }
            }
            println("activate: INVOICE_PENDING (re-run to continue polling; the request is resumable)")
        }
    }
}

private fun List<String>.option(name: String): String? {
    val i = indexOf(name)
    return if (i >= 0 && i + 1 < size) this[i + 1] else null
}

private fun usage() {
    System.err.println("usage: staging-harness <activate|dm|t6-twin> --state <dir> [opts]")
}
