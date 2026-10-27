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
) : AutoCloseable {

    /** The durable database file (a restart reopens it, the crash model's unit of survival). */
    val db: JdbcSqlExecutor = JdbcSqlExecutor(File(world.dir, "$name.db").absolutePath)
        .also { MigrationRunner(it).migrate() }

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

    /** §7.4 step 0 of the fixture-chain install: the epoch the engine's `start()` would build. */
    fun firstStart() {
        check(store.isEmpty()) { "$name already started its epoch" }
        val stored = world.config.native.start(ByteArray(0), world.fixtures.chain, installed)
        val facts = UpdateCodec.decode(stored, world.fixtures.network)
        store.insertFirst(facts, rolloutKey = sha256Bytes("${world.seed}|rollout|$name"))
    }

    /** One update run over the two given mirrors (§7.3's run: the fixed draw, the fixed end). */
    fun updateRun(first: ModelMirror, second: ModelMirror) {
        engine.onUpdateRun(session(userInitiated = false, runMirrors = listOf(first, second)))
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

    override fun close() = db.close()

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
