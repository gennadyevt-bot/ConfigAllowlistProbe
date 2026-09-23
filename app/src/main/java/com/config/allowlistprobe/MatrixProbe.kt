package com.config.allowlistprobe

import android.net.Network
import android.os.Build
import android.os.SystemClock
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.cert.CertificateException
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

/** Controlled comparisons: same IP/port, fresh connection per case, no trust bypass. */
object MatrixProbe {
    data class Case(val label: String, val sni: String?, val host: String)
    data class Result(val outcome: String, val detail: String)

    fun cases(host: String): List<Case> {
        val other = if (host == "example.com") "google.com" else "example.com"
        return listOf(
            Case("CONTROL_BEFORE", host, host),
            Case("NO_SNI", null, host),
            Case("OTHER_SNI", other, host),
            Case("OTHER_HOST", host, other),
            Case("CONTROL_AFTER", host, host)
        )
    }

    fun run(network: Network, ip: InetAddress, target: String, case: Case): Result {
        val started = SystemClock.elapsedRealtime()
        val deadline = started + 12000
        var stage = "TCP"
        val detail = StringBuilder("ip=${ip.hostAddress}:443 target=$target sni=${case.sni ?: "NONE"} host=${case.host}\nnetwork=${network.networkHandle}\n")
        fun remaining(): Int = (deadline - SystemClock.elapsedRealtime()).coerceAtMost(5000).toInt().also {
            if (it <= 0) throw SocketTimeoutException("probe deadline")
        }
        fun result(outcome: String): Result {
            detail.append("elapsedMs=${SystemClock.elapsedRealtime() - started}\n")
            return Result(outcome, detail.toString())
        }
        return try {
            network.socketFactory.createSocket().use { plain ->
                plain.connect(InetSocketAddress(ip, 443), remaining())
                detail.append("TCP=OK ${SystemClock.elapsedRealtime() - started}ms\n")
                stage = "TLS"
                // Certificate verification follows the SNI name, or the original target without SNI.
                val peer = case.sni ?: target
                val factory = SSLContext.getDefault().socketFactory
                (factory.createSocket(plain, peer, 443, true) as SSLSocket).use { tls ->
                    tls.soTimeout = remaining()
                    val params = tls.sslParameters
                    params.endpointIdentificationAlgorithm = "HTTPS"
                    params.serverNames = case.sni?.let { listOf(SNIHostName(it)) } ?: emptyList()
                    if (Build.VERSION.SDK_INT >= 29) params.applicationProtocols = arrayOf("http/1.1")
                    tls.sslParameters = params
                    tls.startHandshake()
                    detail.append("TLS=OK protocol=${tls.session.protocol} certificate=VALID peer=$peer\n")
                    if (Build.VERSION.SDK_INT >= 29) detail.append("ALPN=${tls.applicationProtocol}\n")
                    stage = "HTTP"
                    val request = "HEAD / HTTP/1.1\r\nHost: ${case.host}\r\nUser-Agent: ConfigAllowlistProbe/0.1.4\r\nConnection: close\r\n\r\n"
                    tls.getOutputStream().write(request.toByteArray(Charsets.US_ASCII))
                    tls.getOutputStream().flush()
                    val input = tls.getInputStream()
                    val line = StringBuilder()
                    while (line.length < 4096) {
                        tls.soTimeout = remaining()
                        val b = input.read()
                        if (b == -1 || b == 10) break
                        line.append(b.toChar())
                    }
                    val status = Regex("^HTTP/1\\.[01] ([0-9]{3})(?: |\\r|$)").find(line.toString())
                        ?.groupValues?.get(1)?.toIntOrNull()
                    detail.append("HTTP_STATUS=${status ?: -1}\n")
                    result(if (status != null) "HTTP_$status" else "HTTP_INVALID")
                }
            }
        } catch (e: Exception) {
            detail.append("stage=$stage error=${e.javaClass.simpleName}: ${e.message}\n")
            val certificateError = generateSequence<Throwable>(e) { it.cause }
                .take(12).any { it is CertificateException }
            result(when {
                certificateError -> "CERT_ERROR"
                e is SocketTimeoutException -> "${stage}_TIMEOUT"
                else -> "${stage}_ERROR"
            })
        }
    }
}
