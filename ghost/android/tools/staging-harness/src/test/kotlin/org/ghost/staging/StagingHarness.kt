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
        "dm" -> println("dm: NOT_YET_WIRED")
        "t6-twin" -> println("t6-twin: NOT_YET_WIRED")
        else -> {
            usage()
            kotlin.system.exitProcess(2)
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
        val purchase = world.entitlement.openPurchases().firstOrNull()
        val id = if (purchase == null) {
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
                val instructions = world.entitlement.paymentInstructions(id)
                if (instructions != null) {
                    println("activate: AWAITING_PAYMENT subaddress=${instructions.subaddress.take(8)}… amount=${instructions.amountAtomic} uri=${instructions.uri != null}")
                    return
                }
                val state = world.entitlement.openPurchases().firstOrNull()?.state
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
