package com.config.allowlistprobe

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class Target(val name: String, val host: String, val port: Int, val https: Boolean)

class ProbeEngine(private val ctx: Context, private val log: SessionLogger) {

    private val cm: ConnectivityManager
        get() = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    // ---------- Активная сеть: ВСЕ тесты обязаны идти через неё ----------
    fun activeNetwork(): Network? = cm.activeNetwork

    fun transportName(n: Network?): String {
        if (n == null) return "NONE"
        val caps = cm.getNetworkCapabilities(n) ?: return "UNKNOWN"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WIFI"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "CELLULAR"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ETHERNET"
            else -> "OTHER"
        }
    }

    fun networkInfo(): String {
        val n: Network = cm.activeNetwork ?: return "active network: NONE"
        val sb = StringBuilder()
        val caps = cm.getNetworkCapabilities(n)
        val lp = cm.getLinkProperties(n)
        sb.append("active network: ").append(n).append('\n')
        sb.append("handle: ").append(n.networkHandle).append('\n')
        sb.append("transport: ").append(transportName(n)).append('\n')
        if (caps != null) {
            sb.append("validated: ").append(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)).append('\n')
            sb.append("internet: ").append(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)).append('\n')
            sb.append("metered: ").append(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)).append('\n')
            sb.append("vpn transport: ").append(caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)).append('\n')
        }
        if (lp != null) {
            val v4 = lp.linkAddresses.filter { it.address is Inet4Address }.map { it.address.hostAddress }
            val v6 = lp.linkAddresses.filter { it.address is Inet6Address }.map { it.address.hostAddress?.split("%")?.get(0) }
            sb.append("IPv4: ").append(if (v4.isEmpty()) "none" else v4.joinToString(", ")).append('\n')
            sb.append("IPv6: ").append(if (v6.isEmpty()) "none" else v6.joinToString(", ")).append('\n')
            sb.append("DNS: ").append(lp.dnsServers.joinToString(", ") { it.hostAddress ?: "?" }).append('\n')
            sb.append("routes: ").append(lp.routes.joinToString(", ") { it.destination.toString() }).append('\n')
        }
        return sb.toString()
    }

    fun localAddresses(): Pair<String, String> {
        val lp = cm.getLinkProperties(cm.activeNetwork) ?: return "none" to "none"
        val v4 = lp.linkAddresses.firstOrNull { it.address is Inet4Address }?.address?.hostAddress ?: "none"
        val v6 = lp.linkAddresses.firstOrNull { it.address is Inet6Address }?.address?.hostAddress?.split("%")?.get(0) ?: "none"
        return v4 to v6
    }

    // ---------- DNS ----------
    fun resolveFamily(network: Network, host: String): Pair<List<InetAddress>, List<InetAddress>> {
        return try {
            val all = network.getAllByName(host)
            all.filterIsInstance<Inet4Address>() to all.filterIsInstance<Inet6Address>()
        } catch (e: Exception) {
            emptyList<InetAddress>() to emptyList()
        }
    }

    fun dnsSystem(network: Network, host: String): Triple<Boolean, String, Long> {
        val t0 = System.nanoTime()
        return try {
            val all = network.getAllByName(host)
            val ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
            val fam = all.joinToString(",") { if (it is Inet6Address) "v6" else "v4" }
            Triple(true, all.joinToString(",") { it.hostAddress ?: "?" } + " [" + fam + "]", ms)
        } catch (e: Exception) {
            Triple(false, e.javaClass.simpleName + ": " + (e.message ?: "?"), TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
        }
    }

    fun udp53(network: Network, server: String): Pair<Boolean, Long> {
        val t0 = System.nanoTime()
        return try {
            DatagramSocket().use { s ->
                network.bindSocket(s)
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

    // DoT: TCP853 через activeNetwork + TLS с настоящим SNI + валидация сертификата
    data class DotResult(val ok: Boolean, val tlsVersion: String, val ms: Long, val error: String?)

    fun dot(network: Network, serverIp: String, sni: String): DotResult {
        val t0 = System.nanoTime()
        return try {
            val plain = network.socketFactory.createSocket()
            plain.connect(InetSocketAddress(serverIp, 853), 5000)
            val f: SSLSocketFactory = SSLContext.getDefault().socketFactory
            val s = f.createSocket(plain, sni, 853, true) as SSLSocket
            s.soTimeout = 6000
            val p = s.sslParameters
            p.endpointIdentificationAlgorithm = "HTTPS"
            s.sslParameters = p
            s.startHandshake()
            val ver = s.session.protocol ?: "?"
            s.close()
            DotResult(true, ver, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0), null)
        } catch (e: Exception) {
            DotResult(false, "-", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0),
                e.javaClass.simpleName + ": " + (e.message ?: "?"))
        }
    }

    fun doh(network: Network, url: String): Pair<Boolean, Pair<Int, Long>> {
        val t0 = System.nanoTime()
        return try {
            val c = network.openConnection(URL(url)) as HttpURLConnection
            c.connectTimeout = 5000
            c.readTimeout = 5000
            c.requestMethod = "GET"
            val code = c.responseCode
            c.inputStream.use { inp ->
                val buf = ByteArray(8192)
                var total = 0
                while (total < 65536) {
                    val r = inp.read(buf, 0, minOf(buf.size, 65536 - total))
                    if (r < 0) break
                    total += r
                }
            }
            Pair(true, code to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
        } catch (e: Exception) {
            Pair(false, -1 to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
        }
    }

    // ---------- TCP через activeNetwork ----------
    fun tcpIp(network: Network, ip: InetAddress, port: Int, timeoutMs: Int = 5000): Pair<Boolean, Long> {
        val t0 = System.nanoTime()
        return try {
            network.socketFactory.createSocket().use { s ->
                s.connect(InetSocketAddress(ip, port), timeoutMs)
                Pair(true, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
            }
        } catch (e: Exception) {
            Pair(false, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0))
        }
    }

    fun tcpHost(network: Network, host: String, port: Int, timeoutMs: Int = 5000): Pair<Boolean, Long> {
        val (v4, v6) = resolveFamily(network, host)
        val ip = v4.firstOrNull() ?: v6.firstOrNull() ?: return false to 0
        return tcpIp(network, ip, port, timeoutMs)
    }

    // ---------- TLS через activeNetwork, SNI = host даже при коннекте к IP ----------
    data class TlsResult(
        val ok: Boolean, val version: String, val alpn: String,
        val connectMs: Long, val tlsMs: Long, val error: String?
    )

    fun tlsToIp(network: Network, ip: InetAddress, host: String, port: Int,
                alpnList: List<String> = listOf("h2", "http/1.1"),
                forceVersion: String? = null): TlsResult {
        val t0 = System.nanoTime()
        return try {
            val plain = network.socketFactory.createSocket()
            plain.connect(InetSocketAddress(ip, port), 5000)
            val connectMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
            val f: SSLSocketFactory = SSLContext.getDefault().socketFactory
            val s = f.createSocket(plain, host, port, true) as SSLSocket
            s.soTimeout = 6000
            if (forceVersion != null) s.enabledProtocols = arrayOf(forceVersion)
            val p = s.sslParameters
            p.endpointIdentificationAlgorithm = "HTTPS"
            if (Build.VERSION.SDK_INT >= 29 && alpnList.isNotEmpty()) {
                p.applicationProtocols = alpnList.toTypedArray()
            }
            s.sslParameters = p
            val t1 = System.nanoTime()
            s.startHandshake()
            val tlsMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t1)
            val ver = s.session.protocol ?: "?"
            val alpn = if (Build.VERSION.SDK_INT >= 29) (s.applicationProtocol ?: "-") else "-"
            s.close()
            TlsResult(true, ver, alpn, connectMs, tlsMs, null)
        } catch (e: Exception) {
            TlsResult(false, "-", "-",
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0), -1,
                e.javaClass.simpleName + ": " + (e.message ?: "?"))
        }
    }

    // ---------- HTTPS к конкретному IP (SNI = hostname), body максимум 64 KB ----------
    data class HttpResult(
        val ok: Boolean, val status: Int, val connectMs: Long, val tlsMs: Long,
        val ttfbMs: Long, val totalMs: Long, val bytes: Int, val alpn: String, val error: String?
    )

    fun httpsIp(network: Network, ip: InetAddress, host: String, port: Int = 443): HttpResult {
        val t0 = System.nanoTime()
        return try {
            val plain = network.socketFactory.createSocket()
            plain.connect(InetSocketAddress(ip, port), 5000)
            val connectMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
            val f: SSLSocketFactory = SSLContext.getDefault().socketFactory
            val s = f.createSocket(plain, host, port, true) as SSLSocket
            s.soTimeout = 8000
            val p = s.sslParameters
            p.endpointIdentificationAlgorithm = "HTTPS"
            if (Build.VERSION.SDK_INT >= 29) p.applicationProtocols = arrayOf("http/1.1")
            s.sslParameters = p
            val t1 = System.nanoTime()
            s.startHandshake()
            val tlsMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t1)
            val alpn = if (Build.VERSION.SDK_INT >= 29) (s.applicationProtocol ?: "-") else "-"
            if (alpn == "h2") {
                s.close()
                return HttpResult(false, -1, connectMs, tlsMs, -1,
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0), 0, alpn,
                    "server picked h2, http/1.1 required for probe")
            }
            val req = ("GET / HTTP/1.1\r\nHost: " + host + "\r\n" +
                "User-Agent: ConfigAllowlistProbe/0.1.1\r\n" +
                "Accept: */*\r\nConnection: close\r\n\r\n").toByteArray(StandardCharsets.US_ASCII)
            s.getOutputStream().write(req)
            s.getOutputStream().flush()
            val inp = s.getInputStream()
            val t2 = System.nanoTime()
            var ttfbMs = -1L
            var total = 0
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (total < 65536) {
                val r = inp.read(buf, 0, minOf(buf.size, 65536 - total))
                if (r < 0) break
                if (ttfbMs < 0) ttfbMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t2)
                out.write(buf, 0, r)
                total += r
            }
            s.close()
            val data = out.toByteArray()
            var status = -1
            var i = 0
            while (i < data.size && data[i].toInt() != 10) i++
            if (i > 0) {
                val line = String(data, 0, i, StandardCharsets.ISO_8859_1).trim()
                val parts = line.split(' ')
                if (parts.size >= 2) status = parts[1].toIntOrNull() ?: -1
            }
            if (status < 0) {
                HttpResult(false, -1, connectMs, tlsMs, ttfbMs,
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0), total, alpn,
                    "no HTTP status line")
            } else {
                HttpResult(true, status, connectMs, tlsMs, ttfbMs,
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0), total, alpn, null)
            }
        } catch (e: Exception) {
            HttpResult(false, -1, -1, -1, -1,
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0), 0, "-",
                e.javaClass.simpleName + ": " + (e.message ?: "?"))
        }
    }

    // ---------- UDP443: не QUIC, просто probe ----------
    fun udp443Probe(network: Network, host: String): Pair<String, Long> {
        val t0 = System.nanoTime()
        return try {
            DatagramSocket().use { s ->
                network.bindSocket(s)
                s.soTimeout = 3000
                val payload = ByteArray(1200)
                SecureRandom().nextBytes(payload)
                payload[0] = 0xC0.toByte()
                s.send(DatagramPacket(payload, payload.size, InetSocketAddress(network.getAllByName(host).first(), 443)))
                val buf = ByteArray(1500)
                s.receive(DatagramPacket(buf, buf.size))
                "RESPONSE" to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
            }
        } catch (e: SocketTimeoutException) {
            "TIMEOUT" to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
        } catch (e: Exception) {
            "ERROR" to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
        }
    }

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
}
