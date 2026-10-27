package org.ghost.update.harness

import java.io.File
import java.nio.file.Files

/**
 * The update world (Phase 14 design §11.2): 2–50 clients, each the real `:update` engine over
 * the real `:storage` (SQLite JDBC, migrated to schema U) and the real native decision core
 * through the host library; model mirrors with hostile modes; a model log with generated
 * witness keys; a stepped virtual clock with per-device offsets within ±σ; and the recording
 * installer port. The world runs synchronously on the test thread — the job model with the
 * OS's limits (§11.2) and crash enumeration are later slices; this core is the benign world's
 * stage and the hostile worlds' foundation.
 */
internal class World(
    val name: String,
    val seed: Long,
    val config: WorldConfig = WorldConfig(),
) : AutoCloseable {

    val dir: File = Files.createTempDirectory(baseDir(), "ghost-update-world").toFile()

    /** The committed fixture world the mirrors serve. */
    val fixtures: WorldFixtures = WorldFixtures.load()

    /** The world's stepped clock, starting inside the fixture validity window (the meta's
     *  issued_day + 1, so the fresh manifest is current and the stale one is expired). */
    val clock = VirtualClock(seed).also { it.startAt((fixtures.issuedDay + 1L) * VirtualClock.DAY_MILLIS) }

    /** The model transparency log and its witnesses (generated throwaway keys). */
    val log = ModelLog(seed)

    /** The relay directory the ACCEPT transaction applies to (seeded with the committed
     *  bootstrap relays; the client's directory hook is the world's half of §9.6.1's ACCEPT). */
    val directory = WorldRelayDirectory()

    val mirrors = ArrayList<ModelMirror>()
    val clients = ArrayList<Client>()

    /** The mirror view (T51's observatory): every request, in serve order — the twin worlds
     *  compare these transcripts. Format: `time|bundle|slot=n` / `time|chunk|slot=n|index=i`. */
    val mirrorTranscript = ArrayList<String>()

    init {
        // §11.3: the world selects its mutant once, before the first native call; [close]
        // resets the selector to 0 (the shipped behaviour, the control's build).
        if (config.mutant != 0) org.ghost.network.UpdateMutants.select(config.mutant)
        // Seed from the committed bootstrap (the same file the native library compiles in).
        val text = String(WorldFixtures.resource("bootstrap-relays.txt"), Charsets.US_ASCII)
        for (line in text.lineSequence()) {
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size == 3 && parts[0] == "relay") {
                directory.seed(parts[1], hexBytes(parts[2]))
            }
        }
    }

    /** One model mirror of the world. */
    fun mirror(mode: MirrorMode = MirrorMode.NONE): ModelMirror {
        val m = ModelMirror(mirrors.size, mode, clock)
        mirrors += m
        return m
    }

    /** One client: a fresh fixture-chain install of [installed] (versionCode), running the real
     *  engine. The per-device clock offset lands inside ±σ, deterministic from the seed. */
    fun client(
        name: String? = null,
        installed: Int = 1,
        sdk: Int = 29,
        wrap: (org.ghost.storage.SqlExecutor) -> org.ghost.storage.SqlExecutor = { it },
    ): Client {
        check(clients.size < MAX_CLIENTS) { "a world holds at most $MAX_CLIENTS clients" }
        val c = Client(this, clients.size, name ?: "client-${clients.size}", installed, sdk, wrap)
        c.skewWithinSigma()
        clients += c
        return c
    }

    /** Sum of what every mirror served (the mirror view the twin worlds compare, T51). */
    fun mirrorView(): List<String> = mirrors.map {
        "m${it.index}:${it.mode}:bundles=${it.bundleRequests}:chunks=${it.chunkRequests}"
    }

    override fun close() {
        clients.forEach { it.close() }
        if (config.mutant != 0) org.ghost.network.UpdateMutants.select(0)
        dir.deleteRecursively()
    }

    override fun toString(): String = "World($name, seed=$seed)"

    companion object {
        /** §11.2's 2–50 clients. */
        const val MAX_CLIENTS: Int = 50

        fun baseDir(): java.nio.file.Path {
            val configured = System.getProperty("ghost.update.harness.dir")
            val dir = when {
                !configured.isNullOrBlank() -> File(configured)
                else -> File(System.getProperty("java.io.tmpdir"))
            }
            dir.mkdirs()
            return dir.toPath()
        }
    }
}
