package com.config.allowlistprobe

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class Target(val name: String, val host: String, val port: Int, val https: Boolean)

class ProbeEngine(private val ctx: Context, private val log: SessionLogger) {

    fun loadTargets(): List<Target> {
        val list = ArrayList<Target>()
        try {
            val arr = JSONArray(ctx.assets.open("probe_targets.json").bufferedReader().readText())
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                list.add(Target(
                    o.optString("name", "t$i"),
                    o.getString("host"),
                    o.optInt("port", 443),
                    o.optBoolean("https", true)
                ))
            }
        } catch (e: Exception) {
            log.log("targets load FAIL: " + e.message)
        }
        if (list.isEmpty()) list.add(Target("example.com", "example.com", 443, true))
        return list
    }

    // ---------- Network info ----------
    fun networkInfo(): String {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val n: Network = cm.activeNetwork ?: return "active network: NONE"
        val sb = StringBuilder()
        val caps = cm.getNetworkCapabilities(n)
        val lp = cm.getLinkProperties(n)
        sb.append("active network: ").append(n).append('\n')
        if (caps != null) {
            sb.append("transport: ").append(
                when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WIFI"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "CELLULAR"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ETHERNET"
                    else -> "OTHER"
                }).append('\n')
            sb.append("validated: ").append(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)).append('\n')
            sb.append("internet: ").append(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)).append('\n')
            sb.append("metered: ").append(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)).append('\n')
            sb.append("vpn transport: ").append(caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)).append('\n')
        }
        if (lp != null) {
            val v4 = lp.linkAddresses.filter { it.address is java.net.Inet4Address }.map { it.address.hostAddress }
            val v6 = lp.linkAddresses.filter { it.address is java.net.Inet6Address }.map { it.address.hostAddress?.split("%")?.get(0) }
            sb.append("IPv4: ").append(if (v4.isEmpty()) "none" else v4.joinToString(", ")).append('\n')
            sb.append("IPv6: ").append(if (v6.isEmpty()) "none" else v6.joinToString(", ")).append('\n')
            sb.append("DNS: ").append(lp.dnsServers.joinToString(", ") { it.hostAddress ?: "?" }).append('\n')
            sb.append("routes: ").append(lp.routes.joinToString(", ") { it.destination.toString() }).append('\n')
        }
        return sb.toString()
    }

    fun localAddresses(): Pair<String, String> {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val lp = cm.getLinkProperties(cm.activeNetwork) ?: return "none" to "none"
        val v4 = lp.linkAddresses.firstOrNull { it.address is java.net.Inet4Address }?.address?.hostAddress ?: "none"
        val v6 = lp.linkAddresses.firstOrNull { it.address is java.net.Inet6Address }?.address?.hostAddress?.split("%")?.get(0) ?: "none"
        return v4 to v6
    }

    // ---------- DNS ----------
    fun dnsSystem(host: String): Triple<Boolean, String, Long> {
        val t0 = System.nanoTime()
        return try {
            val all = InetAddress.getAllByName(host)
            val ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
            val fam = all.joinToString(",") { if (it is java.net.Inet6Address) "v6" else "v4" }
            Triple(true, all.joinToString(",") { it.hostAddress ?: "?" } + " [" + fam + "]", ms)
        } catch (e: Exception) {
            Triple(false, e.javaClass.simpleName + ": " + (e.message ?: "?"), TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
        }
    }

    fun udp53(server: String): Pair<Boolean, Long> {
        val t0 = System.nanoTime()
        return try {
            DatagramSocket().use { s ->
                s.soTimeout = 3000
                val query = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7) +
                    "example".toByteArray(StandardCharsets.US_ASCII) + byteArrayOf(3) +
                    "com".toByteArray(StandardCharsets.US_ASCII) + byteArrayOf(0, 0, 1, 0, 1)
                s.send(DatagramPacket(query, query.size, InetSocketAddress(server, 53)))
                val buf = ByteArray(512)
                s.receive(DatagramPacket(buf, buf.size))
                Pair(true, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
            }
        } catch (e: Exception) {
            Pair(false, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
        }
    }

    fun dot(server: String, sni: String): Pair<Boolean, Long> {
        val t0 = System.nanoTime()
        return try {
            val f = SSLContext.getDefault().socketFactory
            (f.createSocket(server, 853) as SSLSocket).use { s ->
                s.soTimeout = 5000
                s.startHandshake()
                Pair(true, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
            }
        } catch (e: Exception) {
            Pair(false, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
        }
    }

    fun doh(url: String): Pair<Boolean, Pair<Int, Long>> {
        val t0 = System.nanoTime()
        return try {
            val c = URL(url).openConnection() as HttpURLConnection
            c.connectTimeout = 5000
            c.readTimeout = 5000
            c.requestMethod = "GET"
            val code = c.responseCode
            c.inputStream.use { it.readBytes() }
            Pair(true, code to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
        } catch (e: Exception) {
            Pair(false, -1 to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
        }
    }

    // ---------- TCP ----------
    fun tcp(host: String, port: Int, timeoutMs: Int = 5000): Pair<Boolean, Long> {
        val t0 = System.nanoTime()
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), timeoutMs)
                Pair(true, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
            }
        } catch (e: Exception) {
            Pair(false, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
        }
    }

    // ---------- TLS ----------
    data class TlsResult(
        val ok: Boolean, val version: String, val alpn: String,
        val connectMs: Long, val tlsMs: Long, val error: String?
    )

    fun tls(host: String, port: Int, forceVersion: String? = null, alpnList: List<String> = emptyList()): TlsResult {
        val t0 = System.nanoTime()
        return try {
            val f: SSLSocketFactory = SSLContext.getDefault().socketFactory
            val s = f.createSocket() as SSLSocket
            s.soTimeout = 6000
            s.connect(InetSocketAddress(host, port), 5000)
            val connectMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
            if (forceVersion != null) {
                s.enabledProtocols = arrayOf(forceVersion)
            }
            if (alpnList.isNotEmpty()) {
                try {
                    val m = s.javaClass.getMethod("setApplicationProtocols", Array<String>::class.java)
                    m.invoke(s, alpnList.toTypedArray())
                } catch (_: Exception) {
                    // API < 29: ALPN через публичный API недоступен — SKIP на уровне вызова
                }
            }
            val t1 = System.nanoTime()
            s.startHandshake()
            val tlsMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t1)
            val ver = s.session.protocol ?: "?"
            var alpn = "-"
            try {
                val m = s.javaClass.getMethod("getApplicationProtocol")
                alpn = (m.invoke(s) as? String) ?: "-"
            } catch (_: Exception) {}
            s.close()
            TlsResult(true, ver, alpn, connectMs, tlsMs, null)
        } catch (e: Exception) {
            TlsResult(false, "-", "-",
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0), -1,
                e.javaClass.simpleName + ": " + (e.message ?: "?"))
        }
    }

    // ---------- HTTPS ----------
    data class HttpResult(
        val ok: Boolean, val status: Int, val connectMs: Long, val totalMs: Long,
        val bytes: Int, val error: String?
    )

    fun httpsGet(url: String): HttpResult {
        val t0 = System.nanoTime()
        return try {
            val c = URL(url).openConnection() as HttpURLConnection
            c.connectTimeout = 5000
            c.readTimeout = 8000
            c.requestMethod = "GET"
            c.instanceFollowRedirects = false
            val status = c.responseCode
            val body = c.inputStream.use { it.readBytes() }
            HttpResult(true, status, -1,
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0), body.size, null)
        } catch (e: Exception) {
            HttpResult(false, -1, -1,
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0), 0,
                e.javaClass.simpleName + ": " + (e.message ?: "?"))
        }
    }

    // ---------- QUIC/UDP 443 (диагностика) ----------
    fun quicProbe(host: String): Pair<String, Long> {
        val t0 = System.nanoTime()
        return try {
            DatagramSocket().use { s ->
                s.soTimeout = 3000
                val payload = ByteArray(1200)
                SecureRandom().nextBytes(payload)
                payload[0] = (0xC0).toByte() // long header похоже на QUIC Initial
                s.send(DatagramPacket(payload, payload.size, InetSocketAddress(host, 443)))
                val buf = ByteArray(1500)
                s.receive(DatagramPacket(buf, buf.size))
                "OK" to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
            }
        } catch (e: Exception) {
            "TIMEOUT" to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
        }
    }

    fun v6Tcp443(): Boolean {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress("2001:4860:4860::8888", 443), 5000)
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}
