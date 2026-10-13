package org.ghost.messaging.channel.engine

import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.ChannelStore
import org.ghost.messaging.channel.store.GenerationState
import org.ghost.messaging.channel.store.GenerationStore
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.store.ContentCipher
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.InboundBlob
import org.ghost.sync.api.SyncTransaction

/**
 * **`CH-RECV`'s liveness half: CO-11 (branch death) and CO-12 (`split_suspected`,
 * `partition_suspected`, `stale_suspected`)** (Phase 10 design §6.4 CO-11/CO-12, §19.1 rule 4/5,
 * §19.15; slice S5c). The window of unopenable foreign blobs and the progress seen in it live in
 * `ch_liveness`; the evaluation runs at the end of every pass. What S5 builds is the machinery
 * reachable without `CH-SWITCH` (MM-36's silent-orphan scenario and MM-37's draining-namespace
 * spam are S6/S7's; the draining half of the split flag's count arrives with them — the split flag
 * counts the current generation's namespace here, which is all a no-rotation channel has).
 *
 * **CO-11 (a).** A foreign blob of the channel's **current** generation's namespace (MM-37: a
 * draining namespace never counts, §19.15 (c)) whose recognition matched a real epoch key but
 * then failed — the seal's hint matched a real key but the AEAD refused (`FORGED_SEAL`, consumed
 * at once, CS-S5), or a header that names another epoch than the key's (`NON_CANONICAL`) — is
 * counted when its determination is final (F-S5-11, §19.39 row 16: only the
 * recognition-matched-then-failed blobs count; a no-key blob's expiry (`UNOPENABLE`) stays a
 * counted drop, never branch evidence — it is also the honest shape of future-epoch traffic).
 * The blob's operators are attributed through `inbox_source` × `relay_directory` (the relays that
 * listed it); the row keeps the widest per-blob attribution seen in the window.
 *
 * **CO-11 (b).** Progress is a commit by another member merged, or authenticated messages of the
 * member's **current** epoch first opened in the window from at least `min(2, branch members − 1)`
 * distinct other members (§19.34.1 item 1: a message counts once, when first opened; the model's
 * "of the epoch current at the opening" is the batch's epoch — the receive step passes only
 * current-epoch senders). The window's senders and the merged bit travel sealed in
 * `ch_liveness.progress_env`; the last day a foreign message of any epoch opened travels there
 * too — CO-12's clocks read it.
 *
 * **The transitions.** The window matures at 72 h from its first unopenable and 3 sessions (one
 * session per pass, counted only while the window is open). At maturity, with at least 3 unopenable
 * blobs from at least 2 operators and no progress, an `active` member enters `resync_needed`
 * (shown; the rejoin of §6.7 is a user action, S6/S7); with progress (or fewer blobs) the member
 * stays and raises `split_suspected` — the adopted D-3 wording: the flag must not wait for
 * progress, and it counts the current (here, only) generation's namespace (EM-3 `Fix::SplitCountsDraining`).
 * Progress afterwards returns a `resync_needed` member to `active` and closes the window; progress
 * at evaluation closes a mature window without a transition. In `resync_needed` the window keeps
 * running (the model counts progress "since the member entered it") with its senders cleared at
 * the entry.
 *
 * **CO-12 (the 9-day flags).** With `last_committer_commit_day` (a settle writes it, rank < 255)
 * 9 days back: `partition_suspected` when a foreign message opened after that commit (the weekly
 * PCS plus two days marks a live channel; EM-3's adopted `PartitionOneOther` — one other member
 * suffices, D-3), `stale_suspected` when none opened for 9 days either and `committers` names
 * someone other than the member (§19.15: it fires, harmlessly, in an idle channel). The flags latch
 * (the UI shows them with the fingerprint and `resync`); nothing posts and nothing traffic-changes
 * by itself.
 *
 * **No relay-visible call** (T40, gate G-M5): local rows only.
 */
internal class ChannelLivenessStep(
    private val env: ChannelEnv,
) {
    private val stores = env.stores

    /** The window's progress, sealed in `ch_liveness.progress_env` under [ChannelAd.liveness]. */
    private class Progress(
        val senders: List<ByteArray>,
        /** The day a foreign message last **opened**; [NO_FOREIGN_MESSAGE_DAY] (0) = none yet — a window
         *  opened by an unopenable stamps the sentinel, never the opening day (§19.40: one junk blob
         *  must not read as an arrived message to CO-12's clocks; real days are > 0). */
        val lastForeignMessageDay: Long,
        val foreignMerged: Boolean,
        /**
         * The day of this member's last rejoin/restore restart (the join's completion, [reset]);
         * [NO_FOREIGN_MESSAGE_DAY] = never. F-S10-8's freshness quarantine of the rejoin admission
         * reads it (§19.56): a catch-up request recorded before the restart was recorded by a
         * state that no longer exists (a dead stack's copy) — its answering admission lived on a
         * branch this device never merged.
         */
        val restartDay: Long,
    ) {
        fun cleared(): Progress = Progress(emptyList(), lastForeignMessageDay, false, restartDay)

        override fun toString(): String = "Progress(${senders.size} senders, merged=$foreignMerged)"
    }

    // --------------------------------------------------------------------------------------------- events

    /**
     * CO-11 (a): [blob] — foreign, of the channel's **current** generation — stayed unopenable and
     * was consumed. Opens the window (first minute, one session) or counts into it. The caller's
     * transaction; the blob's operators are read before nothing of it remains.
     */
    fun noteUnopenable(
        tx: SyncTransaction,
        channel: ChannelStore.ChannelRow,
        generation: GenerationStore.GenerationRow,
        blob: InboundBlob,
        now: Long,
        day: Long,
    ) {
        if (generation.state != GenerationState.CURRENT) return
        val content = env.keys.content() ?: return
        val operators = operatorsOf(tx.sql, blob)
        val c = channel.channelId
        val row = stores.channels.liveness(tx.sql, c)
        if (row == null || row.unopenableFirstMinute == null) {
            // No message opened here: the last-foreign-message day is the sentinel, not today —
            // a junk blob opening the window must not raise CO-12's partition clock (§19.40).
            // The restart day is carried through, never reset: it is the F-S10-8 quarantine's
            // stamp, and a hostile window-opening (SPAM_UNOPENABLE is a designed mode) must not
            // silently disable the guard (the review's F-1, fixed + probed).
            val restartDay = row?.let { decode(content, c, it.progressEnv)?.restartDay } ?: NO_FOREIGN_MESSAGE_DAY
            val progress = Progress(emptyList(), NO_FOREIGN_MESSAGE_DAY, false, restartDay)
            stores.channels.putLiveness(
                tx, c, 1, operators, 1, encode(content, c, progress), DmTime.floorMinute(now),
            )
        } else {
            stores.channels.putLiveness(
                tx, c,
                minOf(row.unopenableCount + 1, 255), maxOf(row.unopenableOperators, operators), row.sessions,
                row.progressEnv, row.unopenableFirstMinute,
            )
        }
    }

    /**
     * CO-11 (b)/CO-12: authenticated messages of [senders] (already filtered to foreign ones of
     * the member's current epoch by the receive step) opened in this batch. Senders first opened
     * in the window join it; the last-foreign-message day always advances. The caller's
     * transaction.
     */
    fun noteOpened(
        tx: SyncTransaction,
        channelId: ByteArray,
        senders: List<ByteArray>,
        content: ContentCipher,
        day: Long,
    ) {
        if (senders.isEmpty()) return
        val row = stores.channels.liveness(tx.sql, channelId)
        val progress = row?.let { decode(content, channelId, it.progressEnv) }
            ?: Progress(emptyList(), day, false, NO_FOREIGN_MESSAGE_DAY)
        // A value-keyed union, capped: ByteArray identity is not equality.
        val byKey = LinkedHashMap<String, ByteArray>()
        for (s in progress.senders) byKey[s.toList().toString()] = s
        for (s in senders) byKey.putIfAbsent(s.toList().toString(), s)
        val updated = Progress(
            byKey.values.take(MAX_TRACKED_SENDERS), maxOf(progress.lastForeignMessageDay, day),
            progress.foreignMerged, progress.restartDay,
        )
        stores.channels.putLiveness(
            tx, channelId,
            row?.unopenableCount ?: 0, row?.unopenableOperators ?: 0, row?.sessions ?: 0,
            encode(content, channelId, updated), row?.unopenableFirstMinute,
        )
    }

    /** CO-11 (b): a commit by another member merged (the settle re-ran CO-2 and wrote it). */
    fun noteMerged(tx: SyncTransaction, channelId: ByteArray, content: ContentCipher, day: Long) {
        val row = stores.channels.liveness(tx.sql, channelId)
        val progress = row?.let { decode(content, channelId, it.progressEnv) }
            ?: Progress(emptyList(), day, false, NO_FOREIGN_MESSAGE_DAY)
        if (row != null && progress.foreignMerged) return
        stores.channels.putLiveness(
            tx, channelId,
            row?.unopenableCount ?: 0, row?.unopenableOperators ?: 0, row?.sessions ?: 0,
            encode(content, channelId, Progress(progress.senders, progress.lastForeignMessageDay, true, progress.restartDay)),
            row?.unopenableFirstMinute,
        )
    }

    /**
     * F-S10-8 (§19.56): the day of this member's last rejoin/restore restart, what the rejoin
     * admission's freshness quarantine reads ([NO_FOREIGN_MESSAGE_DAY] when none — no restart,
     * no constraint). Own transaction.
     */
    fun lastRestartDay(content: ContentCipher, channelId: ByteArray): Long =
        env.database.transaction { tx ->
            stores.channels.liveness(tx.sql, channelId)
                ?.let { decode(content, channelId, it.progressEnv)?.restartDay }
                ?: NO_FOREIGN_MESSAGE_DAY
        }

    /**
     * A rejoin or a restore restarts the channel (§6.7, §6.12): CO-11's window state — the
     * unopenable count, the operators, the sessions, the window's first minute — belonged to the
     * old leaf and its branch; carried over, a window that had matured before the rejoin refires
     * the moment the channel returns to `active` (the review of S7, §19.44 F-S7-6). The join's
     * transaction clears it; the progress record starts over too (the displayed posts stay, but
     * every authenticated message they carried was the old branch's).
     */
    fun reset(tx: SyncTransaction, channelId: ByteArray, content: ContentCipher, day: Long) {
        stores.channels.putLiveness(
            tx, channelId, 0, 0, 0,
            encode(
                content, channelId,
                Progress(emptyList(), NO_FOREIGN_MESSAGE_DAY, false, day),
            ),
            null,
        )
    }

    /** The operators that listed [blob], counted through `relay_directory` (CO-11's "2 operators"). */
    private fun operatorsOf(sql: SqlExecutor, blob: InboundBlob): Int {
        var n = 0
        sql.query(
            "SELECT count(DISTINCT rd.operator_id) FROM inbox_source s " +
                "JOIN relay_directory rd ON rd.relay_id = s.relay_id " +
                "WHERE s.namespace_id = ? AND s.blob_hash = ?",
            listOf(blob.namespace.toByteArray(), blob.hash.toByteArray()),
        ) { n = it.long(0).toInt() }
        return n
    }

    // ------------------------------------------------------------------------------------------ evaluation

    /** The end-of-pass sweep: one transaction over the `active` and `resync_needed` channels. */
    fun evaluate() {
        val now = env.now()
        val day = DmTime.day(now)
        val content = env.keys.content() ?: return
        env.database.transaction { tx ->
            val channels = stores.channels.channelsIn(tx.sql, ChannelState.ACTIVE) +
                stores.channels.channelsIn(tx.sql, ChannelState.RESYNC_NEEDED)
            for (channel in channels) evaluateOne(tx, channel, content, now, day)
        }
    }

    private fun evaluateOne(
        tx: SyncTransaction,
        channel: ChannelStore.ChannelRow,
        content: ContentCipher,
        now: Long,
        day: Long,
    ) {
        val c = channel.channelId
        val row = stores.channels.liveness(tx.sql, c)
        val progress = row?.let { decode(content, c, it.progressEnv) } ?: Progress(emptyList(), day, false, NO_FOREIGN_MESSAGE_DAY)
        val first = row?.unopenableFirstMinute
        val windowOpen = first != null
        val sessions = if (windowOpen) minOf((row?.sessions ?: 0) + 1, 255) else 0
        val count = row?.unopenableCount ?: 0
        val operators = row?.unopenableOperators ?: 0

        // CO-11 (b): the branch's membership, for min(2, members − 1) and "committers names another".
        val opened = env.contexts.open(c)
        val rows = opened?.let { MlsRows.of(stores.mls.rows(tx.sql, c, day)) }
        val roster = opened?.let { o ->
            rows?.let { o.crypto.roster(c, it, day.toInt()).valueOrNull() }
        }
        val members = roster?.members?.size ?: 0
        val need = minOf(MIN_PROGRESS_SENDERS, members - 1)
        val hasProgress = progress.foreignMerged || (need > 0 && progress.senders.size >= need)

        val mature = windowOpen && now - first!! >= LIVENESS_WINDOW_SECONDS && sessions >= MIN_SESSIONS
        var enterResync = false
        var raiseSplit = false
        var closeWindow = false
        if (mature) {
            if (count >= MIN_UNOPENABLE && operators >= MIN_OPERATORS && !hasProgress) {
                // CO-11: branch death. In resync_needed already the window just keeps running.
                if (channel.state == ChannelState.ACTIVE) enterResync = true
            } else if (count >= MIN_UNOPENABLE && operators >= MIN_OPERATORS) {
                // CO-12 (adopted D-3): the split flag does not wait for progress; the current
                // generation's namespace is the count (the draining half arrives with S6/S7).
                raiseSplit = true
            }
            if (hasProgress) closeWindow = true
        }
        // Progress returns a resync_needed member to active (CO-11); its window restarts. The
        // recovery also clears the pending rejoin attempt (§6.7, the review of S7 §19.44): the
        // member caught up in band, its rejoin request is obsolete — the row and the KeyPackage's
        // private keys go in this same transaction.
        if (hasProgress && channel.state == ChannelState.RESYNC_NEEDED) {
            stores.channels.transition(tx, c, ChannelState.RESYNC_NEEDED, ChannelState.ACTIVE)
            val pending = stores.joins.rejoinsUntilDeadline(tx.sql, c, day)
            for (j in pending) stores.joins.deleteJoin(tx, c, j.kpRef)
            if (pending.isNotEmpty()) stores.mls.deleteKeyPackages(tx, c)
            closeWindow = true
        }

        // CO-12's 9-day clocks (last_committer_commit_day a settle writes; a null never fires).
        var partition = channel.partitionSuspected
        var stale = channel.staleSuspected
        val lastCommitDay = channel.lastCommitterCommitDay
        if (lastCommitDay != null && day - lastCommitDay >= STALE_DAYS) {
            // The quiet baseline is the later of the last committer commit and the last foreign
            // message — with no liveness row (a joiner who never merged a foreign commit and
            // never received a message) the commit day alone bounds the quiet: §19.15's "it
            // fires, harmlessly, in a channel whose committers and members are all idle".
            val lastMsgDay = if (row != null) progress.lastForeignMessageDay else null
            val quietSince = maxOf(lastCommitDay, lastMsgDay ?: lastCommitDay)
            val someoneElse = roster?.context?.committers?.any { k -> opened != null && !k.contentEquals(opened.pseudonym) } ?: false
            if (day - quietSince >= STALE_DAYS && someoneElse) stale = true
            else if (lastMsgDay != null && lastMsgDay > lastCommitDay) partition = true
        }
        val split = channel.splitSuspected || raiseSplit
        if (split != channel.splitSuspected || partition != channel.partitionSuspected || stale != channel.staleSuspected) {
            stores.channels.setFlags(tx, c, split, partition, stale)
        }

        // The window's next state.
        when {
            enterResync -> {
                stores.channels.transition(tx, c, ChannelState.ACTIVE, ChannelState.RESYNC_NEEDED)
                // In resync_needed the window keeps running with its senders cleared (the model
                // counts progress from the entry).
                stores.channels.putLiveness(
                    tx, c, count, operators, sessions, encode(content, c, progress.cleared()), first!!,
                )
            }
            closeWindow -> stores.channels.resetLiveness(tx, c, encode(content, c, progress.cleared()))
            windowOpen && sessions != (row?.sessions ?: 0) -> stores.channels.putLiveness(
                tx, c, count, operators, sessions, row!!.progressEnv, first!!,
            )
        }
    }

    // ----------------------------------------------------------------------------------------------- codec

    /**
     * `[version u32 senders u32 lastForeignMessageDay u8 foreignMerged u32 restartDay
     * senders(32 each)]`, sealed (version 2; version 1 records decode with the restart day at
     * its sentinel — no constraint, what a pre-fix device honestly has).
     */
    private fun encode(content: ContentCipher, channelId: ByteArray, progress: Progress): ByteArray {
        val plain = java.io.ByteArrayOutputStream()
        plain.write(2)
        plain.write(u32(progress.senders.size.toLong()))
        plain.write(u32(progress.lastForeignMessageDay))
        plain.write(if (progress.foreignMerged) 1 else 0)
        plain.write(u32(progress.restartDay))
        for (s in progress.senders) plain.write(s)
        return env.seal(content, ChannelAd.liveness(channelId), plain.toByteArray())
    }

    private fun decode(content: ContentCipher, channelId: ByteArray, envBytes: ByteArray): Progress? {
        val plain = content.open(envBytes, ChannelAd.liveness(channelId)) ?: return null
        if (plain.size < 10 || (plain[0].toInt() != 1 && plain[0].toInt() != 2)) return null
        val n = readU32(plain, 1)
        val lastDay = readU32(plain, 5).toLong()
        val merged = plain[9].toInt() == 1
        val restartDay = if (plain[0].toInt() == 2) {
            if (plain.size < 14) return null
            readU32(plain, 10).toLong()
        } else {
            NO_FOREIGN_MESSAGE_DAY
        }
        val at = if (plain[0].toInt() == 2) 14 else 10
        if (plain.size < at + n * PSEUDONYM_BYTES) return null
        val senders = ArrayList<ByteArray>(n)
        for (i in 0 until n) senders += plain.copyOfRange(at + i * PSEUDONYM_BYTES, at + (i + 1) * PSEUDONYM_BYTES)
        return Progress(senders, lastDay, merged, restartDay)
    }

    private fun u32(value: Long): ByteArray = ByteArray(4) { i -> (value ushr (24 - 8 * i)).toByte() }

    private fun readU32(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 0xff) shl 24) or ((bytes[at + 1].toInt() and 0xff) shl 16) or
            ((bytes[at + 2].toInt() and 0xff) shl 8) or (bytes[at + 3].toInt() and 0xff)

    override fun toString(): String = "ChannelLivenessStep"

    companion object {
        /** CO-11: at least this many unopenable foreign blobs … */
        const val MIN_UNOPENABLE: Int = 3

        /** … from at least this many operators … */
        const val MIN_OPERATORS: Int = 2

        /** … over at least this many sessions … */
        const val MIN_SESSIONS: Int = 3

        /** … spanning at least 72 h from the window's first unopenable. */
        const val LIVENESS_WINDOW_SECONDS: Long = 3 * DmTime.DAY

        /** CO-11 (b): progress = a foreign merge, or this many distinct foreign senders (floored at 2, by members − 1). */
        const val MIN_PROGRESS_SENDERS: Int = 2

        /** CO-12: the 9-day clocks (the weekly PCS commit plus two days). */
        const val STALE_DAYS: Long = 9

        /**
         * At most this many window senders are remembered. The progress env is bounded by the
         * column (`ch_liveness.progress_env` ≤ 256): the sealed record is 42 bytes of framing
         * (version, count, day, flag, restart day, nonce, tag) plus 32 per sender, so 6 senders
         * seal to about 234 bytes; 7 would seal to 266 and break the bound — SCN-M20 (20
         * clients, slice S10) reached 7 distinct window senders at the first try (F-S10-2), when
         * the framing was 38 bytes and the cap was computed at 7 → 262.
         */
        const val MAX_TRACKED_SENDERS: Int = 6

        /** `Progress.lastForeignMessageDay`'s sentinel: no foreign message has opened yet (real days are > 0). */
        const val NO_FOREIGN_MESSAGE_DAY: Long = 0

        private const val PSEUDONYM_BYTES: Int = 32
    }
}
