package org.ghost.entitlement.harness

/**
 * Monero-like addresses of the harness: 95 characters, a type character (`5` a standard address,
 * `7` a subaddress, `9` an address of another network), 92 hex characters of body and a 2-hex-character
 * checksum over the rest. The Kotlin engine never parses an address (the Rust core does, design
 * §7.7); the harness needs a checksum and a network only to model the refusals the vectors pin
 * (`address=checksum`, `address=stagenet` of `issuer_semantics.txt`).
 */
internal object HarnessAddresses {
    const val CHARS = 95
    private const val BODY = 92

    fun make(label: String, type: Char): String {
        val body = Bytes.hex(Bytes.sha256(Bytes.ascii("harness-address/$label"))).repeat(2).substring(0, BODY)
        val head = "$type$body"
        return head + checksum(head)
    }

    private fun checksum(head: String): String = Bytes.hex(Bytes.sha256(Bytes.ascii(head))).substring(0, 2)

    /** The type character of a valid address of the harness network (`5` or `7`), or null. */
    fun type(address: String): Char? {
        if (address.length != CHARS) return null
        val type = address[0]
        if (type != '5' && type != '7') return null
        val head = address.substring(0, CHARS - 2)
        if (head.drop(1).any { it !in "0123456789abcdef" }) return null
        return if (address.substring(CHARS - 2) == checksum(head)) type else null
    }

    fun subaddress(minor: Int): String = make("subaddress/$minor", '7')

    fun standard(label: String): String = make(label, '5')

    fun otherNetwork(label: String): String = make(label, '9')

    /** [address] with its last character changed: the checksum no longer matches. */
    fun badChecksum(address: String): String {
        val last = address.last()
        return address.dropLast(1) + (if (last == '0') '1' else '0')
    }
}
