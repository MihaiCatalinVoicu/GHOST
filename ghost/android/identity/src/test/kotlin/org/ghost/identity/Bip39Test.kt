package org.ghost.identity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class Bip39Test {
    private fun hex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private val vectors: List<Pair<ByteArray, String>> by lazy {
        val text = javaClass.getResourceAsStream("/bip39_vectors.txt")!!.bufferedReader().readText()
        text.lines().filter { it.isNotBlank() }.map { line ->
            val (e, m) = line.split("|")
            hex(e) to m
        }
    }

    @Test
    fun wordlistIsTheOfficialEnglishList() {
        assertEquals(2048, Bip39.wordlist.size)
        assertEquals("abandon", Bip39.wordlist.first())
        assertEquals("zoo", Bip39.wordlist.last())
        assertEquals(Bip39.wordlist, Bip39.wordlist.sorted())
    }

    @Test
    fun trezorVectorsEncode() {
        assertTrue("vector file must not be empty", vectors.isNotEmpty())
        for ((entropy, mnemonic) in vectors) {
            assertEquals(mnemonic, Bip39.encode(entropy).joinToString(" "))
        }
    }

    @Test
    fun trezorVectorsDecode() {
        for ((entropy, mnemonic) in vectors) {
            assertArrayEquals(entropy, Bip39.decode(mnemonic))
        }
    }

    @Test
    fun ghostEntropyIs24Words() {
        val root = RootEntropy.generate()
        val words = root.toMnemonic()
        assertEquals(24, words.size)
        assertArrayEquals(root.rawForWrapping(), RootEntropy.fromMnemonic(words).rawForWrapping())
    }

    @Test
    fun rejectsChecksumErrors() {
        val words = RootEntropy.generate().toMnemonic().toMutableList()
        // Replace the last word with a different valid word: the checksum no longer matches
        // (with overwhelming probability for a random alternative; we pick deterministically).
        val alt = Bip39.wordlist.first { it != words.last() && Bip39.wordlist.indexOf(it) != Bip39.wordlist.indexOf(words.last()) xor 1 }
        words[23] = alt
        val threw = try { Bip39.decode(words); false } catch (e: IllegalArgumentException) { true }
        assertTrue("a substituted final word must fail checksum or be a different entropy", threw || !Bip39.decode(words).contentEquals(Bip39.decode(words)))
    }

    @Test
    fun rejectsUnknownWordAndWrongLength() {
        val words = RootEntropy.generate().toMnemonic().toMutableList()
        words[3] = "notaword"
        assertThrows(IllegalArgumentException::class.java) { Bip39.decode(words) }
        assertThrows(IllegalArgumentException::class.java) { Bip39.decode(words.subList(0, 23)) }
        assertThrows(IllegalArgumentException::class.java) { RootEntropy.fromMnemonic(Bip39.encode(ByteArray(16))) }
    }
}
