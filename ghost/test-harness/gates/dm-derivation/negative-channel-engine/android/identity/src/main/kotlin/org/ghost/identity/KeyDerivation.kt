package org.ghost.identity

// The one deriveBranch declaration the gate accepts: the member of RootEntropy.
class RootEntropy private constructor(private val bytes: ByteArray) {
    fun deriveBranch(label: String, length: Int = 32): ByteArray = bytes.copyOf(length)

    companion object {
        fun fromRaw(bytes: ByteArray): RootEntropy = RootEntropy(bytes.copyOf())
    }
}

object DerivationLabels {
    const val MESSAGING = "ghost/v1/messaging"
    const val IDENTITY = "ghost/v1/identity"
}
