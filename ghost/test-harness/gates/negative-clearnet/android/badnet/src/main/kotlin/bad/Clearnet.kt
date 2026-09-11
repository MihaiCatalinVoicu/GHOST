package bad

import java.net.Socket // reported: 1
import java.net.* // reported: 2
import java.net.URI
import javax.net.ssl.SSLSocketFactory // reported: 3

fun open() {
    Socket("example.org", 80)
    val u = java.net.URL("http://example.org") // reported: 4
    java.net.InetAddress.getByName("example.org") // reported: 5
    (u.openConnection() as java.net.HttpURLConnection).connect() // reported: 6
    java.net.DatagramSocket() // reported: 7
    java.net.ServerSocket(0) // reported: 8
    URI("http://example.org").toURL() // reported: 9
    java.net.InetSocketAddress("example.org", 80) // reported: 10
    SSLSocketFactory.getDefault()
}
