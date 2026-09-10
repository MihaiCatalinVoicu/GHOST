package org.ghost.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** Kotlin half of invariant T6: no non-onion destination can be constructed. */
class OnionAddressTest {
    private val good = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:443"

    @Test
    fun acceptsV3AndNormalizes() {
        val a = OnionAddress.parse(good)
        assertEquals(443, a.port)
        assertEquals(a, OnionAddress.parse(good.uppercase()))
        assertEquals(good, a.toString())
    }

    @Test
    fun rejectsClearnetIpsUrlsAndV2() {
        for (bad in listOf(
            "relay.example.com:443",
            "203.0.113.5:443",
            "https://$good",
            good.substringBefore(':'),
            "${good.substringBefore(':')}:0",
            "$good/path",
            "facebookcorewwwi.onion:443",
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscry1.onion:443",
        )) {
            assertThrows(bad, IllegalArgumentException::class.java) { OnionAddress.parse(bad) }
            assertNull(OnionAddress.parseOrNull(bad))
        }
    }

    @Test
    fun pageDecodingIsStrict() {
        val cursor = ByteArray(8) { 1 }
        val h1 = ByteArray(32) { 2 }
        val raw = byteArrayOf(8) + cursor + h1
        val page = TorRelayTransport.decodePage(raw)
        assertEquals(1, page.hashes.size)
        assertEquals(8, page.nextCursor.size)
        assertThrows(NetworkException::class.java) { TorRelayTransport.decodePage(byteArrayOf(0, 1, 2)) }
        assertThrows(NetworkException::class.java) { TorRelayTransport.decodePage(ByteArray(0)) }
    }
}
