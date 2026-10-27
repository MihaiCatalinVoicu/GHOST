package org.ghost.update.harness

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature

/**
 * The model transparency log and its witnesses (Phase 14 design §11.2): generated throwaway
 * Ed25519 keys per world (the fixtures' proofs come from the committed closed fixture log;
 * hostile modes that touch the log — WITHHOLD_PROOF, WRONG_PROOF — build their variants from
 * [leaves] and [checkpoint] later). The tree is a flat SHA-256 chain: one leaf per submitted
 * file's checksum, one checkpoint message the log key signs and the witnesses cosign, in the
 * `cosignature/v1` vocabulary the proofs carry.
 */
internal class ModelLog(seed: Long) {

    private val logKey: KeyPair = generate()
    val witnesses: List<KeyPair> = listOf(generate(), generate())

    /** The submitted leaves (SHA-256 of the file, the Sigsum message). */
    val leaves: MutableList<ByteArray> = mutableListOf()

    /** Submits [file]'s bytes as one leaf; returns the message the leaf checksum binds. */
    fun submit(file: ByteArray): ByteArray {
        val message = MessageDigest.getInstance("SHA-256").digest(file)
        leaves += message
        return message
    }

    /** The checkpoint the log and the witnesses sign over the current [leaves]. */
    fun checkpoint(): ModelCheckpoint {
        val tree = MessageDigest.getInstance("SHA-256")
        tree.update(leaves.size.toString().toByteArray())
        leaves.forEach { tree.update(it) }
        val head = tree.digest()
        return ModelCheckpoint(
            head = head,
            logSignature = sign(logKey, checkpointMessage(head)),
            witnessSignatures = witnesses.map { sign(it, cosignatureMessage(head)) },
        )
    }

    private fun checkpointMessage(head: ByteArray): ByteArray =
        "ghost-model-log/v1\ntree ".toByteArray() + head

    private fun cosignatureMessage(head: ByteArray): ByteArray =
        "cosignature/v1\ntime 0\n".toByteArray() + head

    private fun generate(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private fun sign(key: KeyPair, message: ByteArray): ByteArray {
        val s = Signature.getInstance("Ed25519")
        s.initSign(key.private)
        s.update(message)
        return s.sign()
    }
}

/** One signed tree head of the [ModelLog]: the head and the log's and witnesses' signatures. */
internal class ModelCheckpoint(
    val head: ByteArray,
    val logSignature: ByteArray,
    val witnessSignatures: List<ByteArray>,
)
