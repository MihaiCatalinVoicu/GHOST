package org.ghost.messaging.harness

/**
 * The stored Olm session states of a crash-world device, read on the JVM independently of the native
 * code that wrote them (§2.5, §7.7 point 4; design §22.38): [open] is `wrap.rs`'s envelope,
 * [decode] is `olm/state.rs`'s plaintext layout, and [skippedKeys] reads vodozemac 0.11's JSON
 * pickle at the two paths `olm/pickle.rs` reads (`/receiving_chains/inner`, and in each chain
 * `ratchet_key` and `/skipped_message_keys/inner/…/index`).
 *
 * ```text
 * state_env = nonce(12) ‖ ChaCha20-Poly1305(state, ad = "ghost/v1/wrap/olm-session" ‖ contact_id ‖ session_id)
 * state     = u32_be(pickle_len) ‖ pickle ‖ sidecar
 * sidecar   = u8(chains) ‖ per chain: ratchet_key(32) ‖ u8(n) ‖ n × (u64_be chain_index ‖ u32_be first_seen_day)
 * ```
 */
internal object DmSessionStates {

    /** A skipped message key: the receiver chain's ratchet key and the index it is for. */
    data class Key(val ratchetKey: String, val index: Long) {
        override fun toString(): String = "${ratchetKey.take(8)}…#$index"
    }

    /** One stored session, opened: its row, the keys its pickle holds, and its sidecar's entries. */
    class Opened(val contactId: ByteArray, val slot: String, val pickleKeys: List<Key>, val sidecar: Map<Key, Long>)

    private val WRAP_AD_PREFIX = "ghost/v1/wrap/olm-session".toByteArray(Charsets.US_ASCII)

    /** The plaintext of an envelope, or null when it does not open under [key] and its binding. */
    fun open(key: ByteArray, contactId: ByteArray, sessionId: ByteArray, env: ByteArray): ByteArray? {
        if (env.size < 12 + 16) return null
        val cipher = org.bouncycastle.crypto.modes.ChaCha20Poly1305()
        cipher.init(
            false,
            org.bouncycastle.crypto.params.AEADParameters(
                org.bouncycastle.crypto.params.KeyParameter(key), 128, env.copyOfRange(0, 12),
                WRAP_AD_PREFIX + contactId + sessionId,
            ),
        )
        val out = ByteArray(cipher.getOutputSize(env.size - 12))
        return runCatching {
            val n = cipher.processBytes(env, 12, env.size - 12, out, 0)
            cipher.doFinal(out, n)
            out
        }.getOrNull()
    }

    /** Every session of [node], opened; a state that does not open is the caller's finding. */
    fun all(node: DmNode, where: String): List<Opened> {
        val key = node.device.sessionStateKey
        val out = ArrayList<Opened>()
        node.raw.query("SELECT contact_id, slot, session_id, state_env FROM olm_session") { r ->
            val state = open(key, r.blob(0), r.blob(2), r.blob(3))
                ?: dmViolation(
                    "${node.name} @ $where: a stored session state does not open under the device's state key " +
                        "(§2.5; the session's keys are in the file in the clear)",
                )
            val (pickle, sidecar) = decode(state)
            out += Opened(r.blob(0), r.string(1), skippedKeys(pickle), sidecar)
        }
        return out
    }

    /** `u32_be(pickle_len) ‖ pickle ‖ sidecar`, the sidecar as key → first-seen day. */
    fun decode(state: ByteArray): Pair<ByteArray, Map<Key, Long>> {
        require(state.size >= 4) { "a session state shorter than its length prefix" }
        val length = ((state[0].toLong() and 0xff) shl 24) or ((state[1].toLong() and 0xff) shl 16) or
            ((state[2].toLong() and 0xff) shl 8) or (state[3].toLong() and 0xff)
        val end = 4 + length.toInt()
        require(end <= state.size) { "a session state whose pickle overruns it" }
        val pickle = state.copyOfRange(4, end)
        val sidecar = LinkedHashMap<Key, Long>()
        var at = end
        fun take(n: Int): ByteArray {
            require(at + n <= state.size) { "a sidecar that overruns its state" }
            return state.copyOfRange(at, at + n).also { at += n }
        }
        fun number(bytes: ByteArray): Long = bytes.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
        val chains = take(1)[0].toInt() and 0xff
        repeat(chains) {
            val ratchetKey = hex(take(32))
            val count = take(1)[0].toInt() and 0xff
            repeat(count) {
                val index = number(take(8))
                val day = number(take(4))
                sidecar[Key(ratchetKey, index)] = day
            }
        }
        require(at == state.size) { "a sidecar with trailing bytes" }
        return pickle to sidecar
    }

    /** The skipped keys vodozemac's pickle holds, in stored order. */
    fun skippedKeys(pickle: ByteArray): List<Key> {
        val root = Json(String(pickle, Charsets.UTF_8)).value() as? Map<*, *>
            ?: error("a pickle that is not a JSON object")
        val chains = ((root["receiving_chains"] as? Map<*, *>)?.get("inner") as? List<*>)
            ?: error("a pickle without receiving_chains.inner")
        val out = ArrayList<Key>()
        for (chain in chains) {
            chain as Map<*, *>
            val ratchetKey = (chain["ratchet_key"] as List<*>).map { (it as Long).toByte() }.toByteArray()
            require(ratchetKey.size == 32) { "a ratchet key of ${ratchetKey.size} bytes" }
            val keys = ((chain["skipped_message_keys"] as? Map<*, *>)?.get("inner") as? List<*>)
                ?: error("a chain without skipped_message_keys.inner")
            for (key in keys) out += Key(hex(ratchetKey), (key as Map<*, *>)["index"] as Long)
        }
        return out
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    /**
     * The smallest JSON reader the pickle needs: objects, arrays, integers, strings, booleans and
     * null — vodozemac's pickle has no fractions and no escapes but the plain ones.
     */
    private class Json(private val text: String) {
        private var at = 0

        fun value(): Any? {
            space()
            return when (val c = text[at]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c.isDigit()) num() else error("unexpected '$c' at $at")
            }
        }

        private fun obj(): Map<String, Any?> {
            val out = LinkedHashMap<String, Any?>()
            at++
            space()
            if (text[at] == '}') return out.also { at++ }
            while (true) {
                space()
                val key = str()
                space()
                check(text[at++] == ':') { "':' expected at ${at - 1}" }
                out[key] = value()
                space()
                when (text[at++]) {
                    ',' -> continue
                    '}' -> return out
                    else -> error("',' or '}' expected at ${at - 1}")
                }
            }
        }

        private fun arr(): List<Any?> {
            val out = ArrayList<Any?>()
            at++
            space()
            if (text[at] == ']') return out.also { at++ }
            while (true) {
                out += value()
                space()
                when (text[at++]) {
                    ',' -> continue
                    ']' -> return out
                    else -> error("',' or ']' expected at ${at - 1}")
                }
            }
        }

        private fun str(): String {
            check(text[at++] == '"') { "'\"' expected at ${at - 1}" }
            val out = StringBuilder()
            while (true) {
                val c = text[at++]
                when (c) {
                    '"' -> return out.toString()
                    '\\' -> {
                        val e = text[at++]
                        when (e) {
                            'n' -> out.append('\n')
                            't' -> out.append('\t')
                            'r' -> out.append('\r')
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000c')
                            'u' -> out.append(text.substring(at, at + 4).toInt(16).toChar()).also { at += 4 }
                            else -> out.append(e)
                        }
                    }
                    else -> out.append(c)
                }
            }
        }

        private fun num(): Long {
            val start = at
            if (text[at] == '-') at++
            while (at < text.length && text[at].isDigit()) at++
            check(at >= text.length || text[at] !in ".eE") { "a fraction at $at: the pickle has none" }
            return text.substring(start, at).toLong()
        }

        private fun literal(word: String, value: Any?): Any? {
            check(text.startsWith(word, at)) { "'$word' expected at $at" }
            at += word.length
            return value
        }

        private fun space() {
            while (at < text.length && text[at].isWhitespace()) at++
        }
    }
}
