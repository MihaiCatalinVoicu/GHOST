package org.ghost.staging

/**
 * Staging harness CLI (tools/staging-harness/README.md). Three commands:
 *
 *   activate --issuer <onion:port> --state <dir>
 *   dm --with <other state dir> --state <dir>
 *   t6-twin --state <dir> --out <dir>
 *
 * One line fixed per step, no keys, no addresses, no plaintext (T3). Exit 0 only on the step's
 * criterion. The staging endpoints below are data, not code: they name the live deployment on
 * ghost-runner (issuer + slots 0/1/2 of the accepted ES).
 */
object StagingConfig {
    const val ISSUER_ONION: String = "yc5kgo3q6eyexdscqt7lhwlhxqni4a6b3p2yzcfalmmaxbgbggvya3ad.onion"
    const val RELAY_A: String = "dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion"
    const val RELAY_B: String = "zlaedoy2kjoq6kybq4lidy2mvsvnnfbgfn4cgzowwqtpmg624xpni3ad.onion"
    const val RELAY_C: String = "dlwabzl7bh6x3xotfnujdi7poevpkvu7u5yz22bkhm32a6gs4mufolyd.onion"
}

fun main(args: Array<String>) {
    val command = args.firstOrNull() ?: run { usage(); kotlin.system.exitProcess(2) }
    when (command) {
        "activate" -> println("activate: NOT_YET_WIRED (skeleton: issuer=${StagingConfig.ISSUER_ONION.take(12)}…)")
        "dm" -> println("dm: NOT_YET_WIRED")
        "t6-twin" -> println("t6-twin: NOT_YET_WIRED")
        else -> { usage(); kotlin.system.exitProcess(2) }
    }
}

private fun usage() {
    System.err.println("usage: staging-harness <activate|dm|t6-twin> --state <dir> [opts]")
}
