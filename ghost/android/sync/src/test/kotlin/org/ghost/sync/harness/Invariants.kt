package org.ghost.sync.harness

import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.RelayId
import org.ghost.sync.store.RetentionPolicy
import java.security.MessageDigest

/**
 * The invariants of design §8.4, read straight from a client's database file (through the raw
 * connection, so checking never produces events) and from the model relays and harness records.
 *
 * Structural invariants hold after every reboot and at the end; quiescence invariants hold once a
 * fault-free tail has run. [quiescenceProblems] returns the unmet ones as text, so the tail can
 * run until it is empty.
 */
internal object Invariants {

    private fun <T> rows(sql: SqlExecutor, query: String, args: List<Any?> = emptyList(), map: (SqlExecutor.Row) -> T): List<T> {
        val out = ArrayList<T>()
        sql.query(query, args) { out += map(it) }
        return out
    }

    private fun nodeOf(c: Client, relayId: Long): RelayNode? {
        val index = c.relayIds.entries.firstOrNull { it.value.value == relayId }?.key ?: return null
        return c.world.relays[index]
    }

    private class OpRow(val op: ByteArray, val ns: NamespaceId, val hash: BlobHash, val outcome: String, val required: Int, val payload: Boolean)

    /** Design §8.4 "Structural": integrity, payload rule, outcome truth, acked/fetched rows, IN-3. */
    fun structural(c: Client, where: String, heavy: Boolean = true) {
        val w = c.world
        val sql = c.jdbc
        fun fail(msg: String): Nothing = violation("[$where, ${c.name}] $msg")

        if (heavy) {
            val integrity = rows(sql, "PRAGMA integrity_check") { it.string(0) }
            if (integrity != listOf("ok")) fail("integrity_check: $integrity")
            if (rows(sql, "PRAGMA foreign_key_check") { it.string(0) }.isNotEmpty()) fail("foreign_key_check is not empty")
            MigrationRunner(sql).verifyIntegrity()
        }
        truth(c, where)

        // Fetched rows carry the bytes of their hash.
        sql.query("SELECT blob_hash, ciphertext FROM inbox_blob WHERE state = 'fetched'") { r ->
            if (ModelRelay.sha256(r.blob(1)) != BlobHash(r.blob(0))) fail("a fetched row does not match its hash")
        }

        // IN-3: every live membership an honest relay listed at or below the stored cursor has a row.
        val cursors = rows(sql, "SELECT relay_id, namespace_id, cursor FROM relay_cursor") { Triple(it.long(0), NamespaceId(it.blob(1)), it.blob(2)) }
        for ((relayId, ns, cursor) in cursors) {
            val node = nodeOf(c, relayId) ?: continue
            if (!node.honest) continue
            val seq = ModelRelay.seqOf(cursor)
            val now = w.relayNow(node)
            for (m in node.model.liveMembers(ns, now)) {
                if (m.seq > seq) continue
                val present = rows(sql, "SELECT 1 FROM inbox_blob WHERE namespace_id = ?1 AND blob_hash = ?2", listOf(ns.toByteArray(), m.hash.toByteArray())) { 1 }
                if (present.isEmpty()) fail("IN-3: ${node.name}'s cursor passed a live membership that has no row")
            }
        }
    }

    /**
     * The cheap part of the structural invariants, checked after every commit that wrote rows (and
     * at every reboot and at the end): the payload rule, the truth of every outcome and delivery
     * state (OUT-4, acked ⇒ membership) and of every refused capability.
     */
    fun truth(c: Client, where: String) {
        val w = c.world
        val sql = c.jdbc
        fun fail(msg: String): Nothing = violation("[$where, ${c.name}] $msg")

        // Payload present ⇔ some delivery can still store or become verified (pending, parked, acked, in flight).
        val payloadMismatch = rows(
            sql,
            "SELECT count(*) FROM outbox_op o WHERE (o.ciphertext IS NOT NULL) <> EXISTS (SELECT 1 FROM outbox_delivery d " +
                "WHERE d.operation_id = o.operation_id AND (d.state IN ('pending', 'wait_capability', 'acked') OR d.inflight = 1))",
        ) { it.long(0) }.single()
        if (payloadMismatch != 0L) fail("payload rule broken for $payloadMismatch op(s)")

        // One query for every op and its deliveries (this runs after every commit).
        val byOp = LinkedHashMap<String, Pair<OpRow, MutableList<Pair<Long, String>>>>()
        sql.query(
            "SELECT o.operation_id, o.namespace_id, o.blob_hash, o.outcome, o.required_operators, d.relay_id, d.state " +
                "FROM outbox_op o LEFT JOIN outbox_delivery d ON d.operation_id = o.operation_id",
        ) {
            val id = it.blob(0)
            val entry = byOp.getOrPut(id.hex()) {
                Pair(OpRow(id, NamespaceId(it.blob(1)), BlobHash(it.blob(2)), it.string(3), it.long(4).toInt(), false), ArrayList())
            }
            if (!it.isNull(5)) entry.second += Pair(it.long(5), it.string(6))
        }
        for ((op, deliveries) in byOp.values) {
            val label = w.ops.values.firstOrNull { it.operationId.toByteArray().contentEquals(op.op) }?.label ?: "?"
            val verifiedOperators = HashSet<String>()
            for ((relayId, state) in deliveries) {
                val node = nodeOf(c, relayId) ?: fail("delivery to an unknown relay")
                if (state == "verified") {
                    if (listOf(c.name, node.name, op.ns, op.hash) !in w.records.inventory) {
                        fail("op $label verified on ${node.name} without that relay showing the hash (OUT-4)")
                    }
                    verifiedOperators += node.operatorId.hex()
                }
                if (state == "acked" && Pair(op.ns, op.hash) !in node.model.everHeld) {
                    fail("op $label acked on ${node.name}, which never held it (acked ⇒ membership)")
                }
            }
            when (op.outcome) {
                "sent" -> if (verifiedOperators.size < op.required) fail("op $label sent with ${verifiedOperators.size} verified operator(s) (OUT-4)")
                "failed" -> w.relays.firstOrNull { Pair(op.ns, op.hash) in it.model.everHeld }?.let {
                    fail("op $label failed while ${it.name} held a copy (OUT-4 failed-but-delivered)")
                }
                "indeterminate" -> if (Pair(op.ns, op.hash) !in w.records.ambiguous) {
                    fail("op $label indeterminate without an ambiguous attempt (OUT-4)")
                }
                "degraded" -> if (verifiedOperators.isEmpty()) fail("op $label degraded without a verified copy")
            }
        }

        // A capability is marked rejected (exhausted) only if its relay refused that token as unauthorized (quota).
        sql.query("SELECT relay_id, token, state FROM relay_capability WHERE state IN ('rejected', 'exhausted')") { r ->
            val node = nodeOf(c, r.long(0)) ?: fail("capability of an unknown relay")
            val category = if (r.string(2) == "rejected") "unauthorized" else "quota"
            if (listOf(node.name, ModelRelay.sha256(r.blob(1)), category) !in w.records.refused) {
                fail("a capability of ${node.name} is ${r.string(2)} although the relay never refused that token ($category)")
            }
        }
    }

    /** What the client knows about one op (for failure messages); [opHex] is its id in hex. */
    fun diagnoseOp(c: Client, opHex: String): String {
        val sql = c.jdbc
        val now = c.world.clock.epochSeconds()
        val parts = ArrayList<String>()
        val op = c.world.ops.values.firstOrNull { it.operationId.toByteArray().hex() == opHex }
        parts += "op ${op?.label}"
        sql.query("SELECT outcome, released, ciphertext IS NOT NULL, not_before_minute, deadline_hour FROM outbox_op WHERE hex(operation_id) = upper(?1)", listOf(opHex)) {
            parts += "outcome=${it.string(0)} released=${it.long(1)} payload=${it.long(2)} notBefore=${it.long(3) - now}s deadline=${if (it.isNull(4)) null else it.long(4) - now}"
        }
        sql.query(
            "SELECT relay_id, state, attempts, next_attempt_minute, inflight, copy_hour, ack_minute, strikes FROM outbox_delivery WHERE hex(operation_id) = upper(?1)",
            listOf(opHex),
        ) {
            parts += "${nodeOf(c, it.long(0))?.name}:${it.string(1)} attempts=${it.long(2)} next=${it.long(3) - now}s inflight=${it.long(4)} " +
                "copy=${if (it.isNull(5)) null else it.long(5) - now} ack=${if (it.isNull(6)) null else it.long(6) - now} strikes=${it.long(7)}"
        }
        sql.query("SELECT relay_id, kind, state, expires_hour FROM relay_capability") {
            parts += "cap ${nodeOf(c, it.long(0))?.name}/${it.string(1)}=${it.string(2)} exp=${if (it.isNull(3)) null else it.long(3) - now}"
        }
        parts += "offset=${c.world.clock.deviceOffsetSeconds}s transport=${c.engine.transportStatus} ready=${c.engine.readyInProcess} " +
            "session=${c.session?.kind}/online=${c.session?.online}/finished=${c.session?.isFinished()} offline=${c.offline()} " +
            "t=${c.world.clock.millis / 60_000}min fgUntil=${c.foregroundUntil / 60_000} boots=${c.boots} aborts=${c.transport.aborts} " +
            (c.session?.let { dumpFields(it) + " work=" + dumpFields(it.work) + " read=" + dumpFields(it.read) } ?: "")
        return parts.joinToString("; ")
    }

    /** Private scalar fields of an engine object, by reflection (failure messages only). */
    fun dumpFields(o: Any): String = o.javaClass.declaredFields.filter { !java.lang.reflect.Modifier.isStatic(it.modifiers) }.joinToString(",", "{", "}") { f ->
        f.isAccessible = true
        val v = f.get(o)
        val shown = when (v) {
            is Number, is Boolean, is Enum<*> -> v.toString()
            is Collection<*> -> "size=${v.size}:" + v.take(6).joinToString("/") { it.toString().take(40) }
            is Map<*, *> -> "size=${v.size}:" + v.values.take(6).joinToString("/") { e -> e?.let { dumpScalars(it) } ?: "null" }
            else -> v?.javaClass?.simpleName ?: "null"
        }
        "${f.name}=$shown"
    }

    private fun dumpScalars(o: Any): String = if (!o.javaClass.name.startsWith("org.ghost")) o.toString() else o.javaClass.declaredFields.filter { !java.lang.reflect.Modifier.isStatic(it.modifiers) }
        .mapNotNull { f -> f.isAccessible = true; f.get(o)?.takeIf { it is Number || it is Boolean }?.let { "${f.name}=$it" } }.joinToString(",", "[", "]")

    /** What the client knows about one blob (for failure messages). */
    fun diagnose(c: Client, node: RelayNode, ns: NamespaceId, hash: BlobHash): String {
        val sql = c.jdbc
        val parts = ArrayList<String>()
        sql.query(
            "SELECT state, fetch_attempts, next_fetch_minute, offers, offer_after_minute, retain_until_day FROM inbox_blob WHERE namespace_id = ?1 AND blob_hash = ?2",
            listOf(ns.toByteArray(), hash.toByteArray()),
        ) { parts += "row=${it.string(0)} attempts=${it.long(1)} nextFetch=${it.long(2) - c.world.clock.epochSeconds()}s offers=${it.long(3)} retain=${it.long(5)}" }
        if (parts.isEmpty()) parts += "no row"
        sql.query("SELECT relay_id, state FROM inbox_source WHERE namespace_id = ?1 AND blob_hash = ?2", listOf(ns.toByteArray(), hash.toByteArray())) {
            parts += "source ${nodeOf(c, it.long(0))?.name}=${it.string(1)}"
        }
        val m = node.model.member(ns, hash)
        var cursor: Long? = null
        sql.query("SELECT cursor FROM relay_cursor WHERE relay_id = ?1 AND namespace_id = ?2", listOf(c.id(node).value, ns.toByteArray())) { cursor = ModelRelay.seqOf(it.blob(0)) }
        parts += "seq=${m?.seq} cursor=$cursor expiresIn=${m?.let { it.expiry - c.world.relayNow(node) }}s"
        sql.query(
            "SELECT kind, state, expires_hour FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2",
            listOf(c.id(node).value, ns.toByteArray()),
        ) { parts += "cap ${it.string(0)}=${it.string(1)}" }
        sql.query("SELECT listening FROM sync_namespace WHERE namespace_id = ?1", listOf(ns.toByteArray())) { parts += "listening=${it.long(0)}" }
        return parts.joinToString(", ")
    }

    /** Records leases a dead process left in flight: their attempts ended ambiguous (C4, C5). */
    fun recordLeftInFlight(c: Client) {
        c.jdbc.query(
            "SELECT o.namespace_id, o.blob_hash FROM outbox_delivery d JOIN outbox_op o ON o.operation_id = d.operation_id WHERE d.inflight = 1",
        ) { c.world.records.ambiguous(NamespaceId(it.blob(0)), BlobHash(it.blob(1))) }
    }

    /**
     * Design §8.4 "At quiescence" for one client; empty when every one holds. [allowed] gives the
     * outcomes a scenario accepts for an op (SENT unless the script made it infeasible).
     */
    fun quiescenceProblems(c: Client, allowed: (OpRecord) -> Set<Outcome>): List<String> {
        val w = c.world
        val sql = c.jdbc
        val out = ArrayList<String>()
        val enqueued = rows(sql, "SELECT operation_id FROM oracle_enqueued") { it.blob(0).hex() }.toSet()
        val released = rows(sql, "SELECT operation_id, outcome FROM oracle_outcome") { Pair(it.blob(0).hex(), it.string(1)) }.toMap()
        if (enqueued != released.keys) {
            val first = (enqueued - released.keys).firstOrNull()
            out += "OUT-1: ${(enqueued - released.keys).size} enqueued op(s) without a released outcome, ${(released.keys - enqueued).size} outcome(s) without an enqueue" +
                (first?.let { " [${diagnoseOp(c, it)}]" } ?: "")
        }
        for (op in w.ops.values.filter { it.client === c }) {
            val outcome = released[op.operationId.toByteArray().hex()] ?: continue
            val allowedSet = allowed(op)
            if (Outcome.valueOf(outcome) !in allowedSet) out += "op ${op.label}: outcome $outcome, expected one of $allowedSet"
        }
        val unreleased = rows(sql, "SELECT count(*) FROM outbox_op WHERE outcome <> 'pending' AND released = 0") { it.long(0) }.single()
        if (unreleased > 0) out += "$unreleased decided outcome(s) not released"
        val fetched = rows(sql, "SELECT count(*) FROM inbox_blob WHERE state = 'fetched'") { it.long(0) }.single()
        if (fetched > 0) out += "$fetched fetched blob(s) not consumed (claim would return them)"
        val stuck = rows(
            sql,
            "SELECT count(*) FROM outbox_delivery d JOIN outbox_op o ON o.operation_id = d.operation_id JOIN relay_capability c " +
                "ON c.relay_id = d.relay_id AND c.namespace_id = o.namespace_id AND c.kind = 'write' AND c.state = 'usable' " +
                "WHERE d.state = 'wait_capability'",
        ) { it.long(0) }.single()
        if (stuck > 0) out += "liveness: $stuck delivery(ies) wait for a capability while a usable one exists"

        // IN-1: live memberships on honest relays of listened namespaces (with a read path) were consumed.
        val consumed = rows(sql, "SELECT namespace_id, blob_hash FROM oracle_consumed") { Pair(NamespaceId(it.blob(0)), BlobHash(it.blob(1))) }.toSet()
        val listened = rows(sql, "SELECT namespace_id FROM sync_namespace WHERE listening = 1") { NamespaceId(it.blob(0)) }
        val own = w.ops.values.filter { it.client === c }.map { Pair(it.namespace, it.hash) }.toSet()
        for (ns in listened) {
            val relays = rows(
                sql,
                "SELECT nr.relay_id FROM namespace_relay nr JOIN relay_directory rd ON rd.relay_id = nr.relay_id " +
                    "WHERE nr.namespace_id = ?1 AND rd.state = 'active' AND EXISTS (SELECT 1 FROM relay_capability c WHERE c.relay_id = nr.relay_id " +
                    "AND c.namespace_id = nr.namespace_id AND ((c.kind = 'read' AND c.state = 'usable') OR (c.kind = 'write' AND c.state IN ('usable', 'exhausted'))) " +
                    "AND (c.expires_hour IS NULL OR c.expires_hour > ?2))",
                listOf(ns.toByteArray(), w.clock.epochSeconds()),
            ) { it.long(0) }
            for (relayId in relays) {
                val node = nodeOf(c, relayId) ?: continue
                if (!node.honest) continue
                val missing = node.model.liveMembers(ns, w.relayNow(node)).map { Pair(ns, it.hash) }.filter { it !in own && it !in consumed }
                if (missing.isNotEmpty()) out += "IN-1: ${missing.size} live blob(s) on ${node.name} not consumed (${diagnose(c, node, missing.first().first, missing.first().second)})"
            }
        }
        for (k in consumed) {
            if (w.relays.none { k in it.model.everHeld }) out += "IN-2: a consumed blob no relay ever held"
        }

        return out
    }

    /**
     * OUT-3 at the end (design §8.4): a relay holds at most one membership per (namespace, hash)
     * (the model keys them so), and the stores an honest relay charged for an op are at most one,
     * plus one per store that reached it without a receipt reaching the engine (a crash window or an
     * ambiguous answer), plus one per check that found the op absent (a repair after the copy
     * expired unverified), plus one per drop.
     */
    fun quotaCharges(c: Client) {
        val w = c.world
        for (op in w.ops.values.filter { it.client === c }) {
            for (node in w.relays.filter { it.honest }) {
                val key = Pair(op.namespace, op.hash)
                val charges = node.model.charges[key] ?: 0
                val k = listOf<Any>(node.name, op.namespace, op.hash)
                val bound = 1 + (w.records.unanswered[k] ?: 0) + (w.records.drops[k] ?: 0) + (w.records.absent[k] ?: 0)
                if (charges > bound) {
                    val history = c.port.calls.filter { (it.kind == CallKind.STORE || it.kind == CallKind.CHECK) && it.relay == node.name && op.hash in it.hashes }
                        .joinToString(" ") { "${it.kind}@${it.startMillis}:${it.item}:${it.result}" }
                    violation("OUT-3: op ${op.label} charged $charges times on ${node.name} (bound $bound) calls=[$history]")
                }
            }
        }
    }

    /**
     * Store window (the premise of the retention derivation, design §2.3): every store that changed
     * an honest relay's membership of an own op happened within H + 1 h (+ 2 × the clock skews) of
     * the first one. Mutant M11 breaks it.
     */
    fun storeWindow(w: World) {
        val skew = w.relays.maxOfOrNull { Math.abs(it.skewSeconds) } ?: 0L
        val bound = RetentionPolicy.STORE_WINDOW_SECONDS + 3_600 + 2 * (skew + Math.abs(w.clock.deviceOffsetSeconds))
        for (op in w.ops.values) {
            val times = w.relays.filter { it.honest }.flatMap { it.model.changingStores[Pair(op.namespace, op.hash)].orEmpty() }
            if (times.isEmpty()) continue
            if (times.max() - times.min() > bound) violation("store window: op ${op.label} stored ${(times.max() - times.min()) / 3600} h after its first copy (H = 7 d)")
        }
    }

    /**
     * Retention safety (design §8.4): a garbage-collection delete of an inbox row while an honest
     * relay still holds a live membership of that hash could let it be listed and delivered again.
     * Wired to every executed update of every client.
     */
    fun retentionWatch(c: Client, sql: String, args: List<Any?>, changed: Int) {
        val w = c.world
        if (!w.retentionCheck || changed != 1) return
        if (!sql.startsWith("DELETE FROM inbox_blob WHERE namespace_id = ?1 AND blob_hash = ?2")) return
        val ns = NamespaceId(args[0] as ByteArray)
        val hash = BlobHash(args[1] as ByteArray)
        for (node in w.relays) {
            if (!node.honest) continue
            if (node.model.live(ns, hash, w.relayNow(node))) {
                violation("retention: ${c.name} deleted a row while ${node.name} still holds a live membership of that hash")
            }
        }
    }

    /**
     * Digest of everything that survives a crash: the subject's logical database content, every
     * relay and the harness records. Crash points with equal classification keys must have equal
     * digests (the classification is checked, not assumed).
     */
    fun digest(w: World): String {
        val md = MessageDigest.getInstance("SHA-256")
        dump(w).forEach { md.update(it.toByteArray()); md.update(10) }
        return md.digest().hex()
    }

    /** The lines [digest] hashes (for diagnosing a classification mismatch). */
    fun dump(w: World): List<String> {
        val out = ArrayList<String>()
        for (c in w.clients) {
            val sql = c.jdbc
            val tables = rows(sql, "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name") { it.string(0) }
            for (t in tables) {
                val cols = rows(sql, "PRAGMA table_info($t)") { it.string(1) }
                val lines = ArrayList<String>()
                sql.query("SELECT ${cols.joinToString(", ") { "quote($it)" }} FROM $t") { r ->
                    lines += "${c.name}.$t: " + cols.indices.joinToString("|") { r.string(it) }
                }
                lines.sort()
                out += lines
            }
        }
        w.relays.forEach { out += "relay ${it.name} ${it.model.digest()}" }
        out += "records ${w.records.digest()}"
        return out
    }

    fun relayIdOf(c: Client, node: RelayNode): RelayId = c.id(node)
}
