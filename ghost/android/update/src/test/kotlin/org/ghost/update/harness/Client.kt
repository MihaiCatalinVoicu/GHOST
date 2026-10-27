package org.ghost.update.harness

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.MirrorAccess
import org.ghost.sync.api.UpdateSession
import org.ghost.update.UpdateCodec
import org.ghost.update.UpdateEngine
import org.ghost.update.UpdateStateStore
import org.ghost.update.UpdatesImpl
import java.io.File

/**
 * One world client (Phase 14 design §11.2): the real [UpdateEngine] over the real storage
 * (a file-backed SQLite JDBC database, migrated to schema U — a durable file, so the crash
 * slices restart it), the [UpdatesImpl] facade on top, the world's per-device clock through
 * `dayNow`, and a [RecordingInstaller] where a platform installer would sit.
 *
 * A fresh client holds no `upd_state` row; [firstStart] performs §7.4 step 0 exactly as the
 * engine's private `start()` does — `nativeStart(empty, embedded, installed)` then
 * `insertFirst` — with the fixture chain in place of the compiled-in one: the world models
 * devices whose APK embeds the fixture chain, so the shipped host library needs no rebuild.
 */
internal class Client(
    val world: World,
    val index: Int,
    val name: String,
    val installed: Int,
    val sdk: Int,
    /** Test-only SQL wrapper (the crash-enumeration slice's fault injector); the identity by
     *  default, and reapplied on every [reopen]. */
    private val wrap: (org.ghost.storage.SqlExecutor) -> org.ghost.storage.SqlExecutor = { it },
) : AutoCloseable {

    /** The durable database file (a restart reopens it, the crash model's unit of survival). */
    private var rawDb: JdbcSqlExecutor = openDb()

    /** What the engine and the facade speak to; [wrap] of [rawDb]. */
    var db: org.ghost.storage.SqlExecutor = wrap(rawDb)
        private set

    private fun openDb(): JdbcSqlExecutor =
        JdbcSqlExecutor(File(world.dir, "$name.db").absolutePath).also { MigrationRunner(it).migrate() }

    /** `noBackupFilesDir/update` (X-D10's one directory). */
    val files: File = File(world.dir, "$name-update").apply { mkdirs() }

    /** The recording installer port (§11.2). */
    val installer = RecordingInstaller()

    private var runs: Int = 0

    private val engine = UpdateEngine(
        db = { db },
        files = files,
        native = world.config.native,
        installedVersionCode = { installed },
        sdk = sdk,
        dayNow = { world.clock.day() to world.clock.nowSeconds() },
        directory = { _, manifest -> applyDirectory(manifest) },
    )

    /** The facade Phase 13 builds on; the world's user calls run through it. */
    val updates = UpdatesImpl(
        db = { db },
        native = world.config.native,
        engine = engine,
        installedVersionCode = { installed },
        sdk = sdk,
        clockTrusted = { world.clock.trusted },
        dayNow = { world.clock.day() to world.clock.nowSeconds() },
        userCall = { block -> block(session(userInitiated = true)) },
        files = files,
        installer = installer,
    )

    val store: UpdateStateStore get() = UpdateStateStore(db)

    /**
     * The world's half of ACCEPT's directory transaction (§7.8, §9.6.1): fresh manifests apply
     * their relay list through the real native decoder; an expired manifest applies nothing
     * (MC-D30); a relabeled known onion is refused by the write-once guard (MC-D31). On the
     * device this logic lives in `:sync`'s wiring — the world models the design's rule.
     */
    private fun applyDirectory(manifest: ByteArray?) {
        if (manifest == null) return
        val expiry = if (manifest.size >= 58 && manifest[0] == 'G'.code.toByte()) be32(manifest, 54) else null
        // The world's wiring model applies what the acceptance reported. MC-D8/MC-D30's
        // native sites make an expired manifest report its directory changes; the JNI
        // exposes no changes list, so the gate mirrors the selector — the layer where the
        // mutation's effect is observable on this seam.
        val expired = expiry == null || world.clock.day() > expiry
        val changesReported = !expired || world.config.mutant == 8 || world.config.mutant == 30
        if (!changesReported) {
            world.directory.recordStaleSuppression()
            return
        }
        for (relay in world.config.native.manifestRelays(manifest)) {
            // MC-D31 (§11.3, a Kotlin-side row): the write-once guard is skipped — a manifest
            // overwrites a known onion's operator id. The world's port of the row.
            if ("MC-D31" in world.config.kotlinMutants) {
                world.directory.entries["${relay.host}.onion:${relay.port}"] =
                    WorldRelayDirectory.Entry("${relay.host}.onion:${relay.port}", relay.operatorId, "manifest")
            } else {
                world.directory.upsert("${relay.host}.onion:${relay.port}", relay.operatorId)
            }
        }
    }

    /**
     * MC-D22's port (§11.3, a Kotlin-side row): an install session committed without the
     * native check's OK — the current `.part` file (mid-download, unverified) is streamed into
     * the installer. Only the mutant world calls this; the recording installer is the oracle
     * (its bytes differ from the verified image).
     */
    fun installUnverifiedPart() {
        check("MC-D22" in world.config.kotlinMutants) { "only the MC-D22 world commits unverified bytes" }
        val row = store.staged() ?: throw IllegalStateException("nothing staged")
        val part = java.io.File(files, row.sha256.toHex() + ".part")
        check(part.isFile) { "no partial file to misuse" }
        installer.install(part)
    }

    private fun ByteArray.toHex(): String {
        val alphabet = "0123456789abcdef"
        return joinToString("") { b -> "${alphabet[(b.toInt() shr 4) and 15]}${alphabet[b.toInt() and 15]}" }
    }

    private fun be32(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xff) shl 24) or ((b[at + 1].toInt() and 0xff) shl 16) or
            ((b[at + 2].toInt() and 0xff) shl 8) or (b[at + 3].toInt() and 0xff)

    /** §7.4 step 0 of the fixture-chain install: the epoch the engine's `start()` would build. */
    fun firstStart() {
        check(store.isEmpty()) { "$name already started its epoch" }
        val stored = world.config.native.start(ByteArray(0), world.fixtures.chain, installed)
        val facts = UpdateCodec.decode(stored, world.fixtures.network)
        store.insertFirst(facts, rolloutKey = sha256Bytes("${world.seed}|rollout|$name"))
    }

    /** One update run over the two given mirrors (§7.3's run: the fixed draw, the fixed end). */
    /** One update run over the two given mirrors (§7.3's run: the fixed draw, the fixed end).
     *  [draw] and [pick] override the seeded draw and the slot-to-mirror mapping for the
     *  draw-mutant worlds (the test computes the pick the native draw makes — the world's
     *  oracle; the harness never names an onion itself). */
    fun updateRun(
        first: ModelMirror,
        second: ModelMirror,
        draw: ByteArray? = null,
        pick: Pair<ModelMirror, ModelMirror>? = null,
    ) {
        engine.onUpdateRun(
            WorldSession(world, userInitiated = false, draw ?: this.draw(), listOf(first, second), pick),
        )
    }

    /**
     * Process death and reboot (the F7 §8.3 crash model): the connection closes uncommitted
     * transactions (SQLite rolls back), the file survives; the client reopens and the engine
     * continues against the durable state.
     */
    fun reopen() {
        rawDb.close()
        rawDb = openDb()
        db = wrap(rawDb)
    }

    /** The session the engine sees: the world's clock, the run's draw, the run's two mirrors. */
    private fun session(userInitiated: Boolean, runMirrors: List<ModelMirror> = emptyList()): UpdateSession =
        WorldSession(world, userInitiated, draw(), runMirrors)

    /** The run's 32-byte draw (§7.8: from the process key and the run index — modeled seeded). */
    private fun draw(): ByteArray = sha256Bytes("${world.seed}|draw|$name|${runs++}")

    /** The per-device clock offset inside ±σ (T50's premise), deterministic from the seed. */
    fun skewWithinSigma() {
        world.clock.skewDevice("${world.seed}|skew|$name")
    }

    override fun close() = rawDb.close()

    override fun toString(): String = "Client($name)"
}

/**
 * The [UpdateSession] of one run (the `:sync` lease, modeled): the run's fixed end is
 * [deadlineMonotonicMillis] after the session opens; the mirror access serves the run's two
 * model mirrors by slot — the native side built the set, the harness only answers with bytes
 * (PM-D9, PM-D10 hold: no path, no range, no onion is named here).
 */
private class WorldSession(
    private val world: World,
    override val userInitiated: Boolean,
    private val draw: ByteArray,
    private val runMirrors: List<ModelMirror>,
    /** The slot-to-mirror mapping of the run's actual draw (the draw-mutant worlds' oracle);
     *  null maps by position, the honest default. */
    private val pick: Pair<ModelMirror, ModelMirror>? = null,
) : UpdateSession {

    /** D_U: the run's fixed end (§7.3); the world never advances the clock inside a run. */
    override val deadlineMonotonicMillis: Long = world.clock.nowMillis + RUN_MILLIS

    override val closed: Boolean get() = world.clock.nowMillis >= deadlineMonotonicMillis

    override fun updateDraw(): ByteArray = draw

    override fun clockTrusted(): Boolean = world.clock.trusted

    override val mirror: MirrorAccess = object : MirrorAccess {
        override fun fetchBundle(mirrorSet: Long, slot: Int, deadlineMillis: Int): ByteArray =
            mirror(slot).serveBundle(world.fixtures)

        override fun fetchApkChunk(mirrorSet: Long, slot: Int, chunkIndex: Long, deadlineMillis: Int): ByteArray =
            mirror(slot).serveApkChunk(world.fixtures, chunkIndex)

        private fun mirror(slot: Int): ModelMirror {
            if (pick != null) return if (slot == 0) pick.first else pick.second
            val set = if (runMirrors.isEmpty()) world.mirrors else runMirrors
            if (slot !in 0..1 || slot >= set.size) {
                throw org.ghost.network.NetworkException("invalid_argument")
            }
            return set[slot]
        }
    }

    companion object {
        /** The run's fixed duration in the world (an update run lasts D_U; the model of the OS
         *  job limits that bounds it is a later slice). */
        const val RUN_MILLIS: Long = 60_000
    }
}
