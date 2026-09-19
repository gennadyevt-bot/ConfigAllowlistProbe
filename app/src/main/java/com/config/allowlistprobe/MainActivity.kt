package com.config.allowlistprobe

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject

class MainActivity : Activity() {
    private lateinit var engine: ProbeEngine
    private lateinit var logger: SessionLogger
    private lateinit var out: TextView
    private lateinit var btnRun: Button
    private val ui = Handler(Looper.getMainLooper())
    private var running = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        logger = SessionLogger(this)
        engine = ProbeEngine(this, logger)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
        }
        btnRun = Button(this).apply { text = "ЗАПУСТИТЬ ПРОВЕРКУ" }
        val btnBaseline = Button(this).apply { text = "СОХРАНИТЬ BASELINE" }
        val btnExport = Button(this).apply { text = "СОХРАНИТЬ ОТЧЁТ" }
        out = TextView(this).apply {
            textSize = 13f
            typeface = android.graphics.Typeface.MONOSPACE
        }
        root.addView(btnRun)
        root.addView(btnBaseline)
        root.addView(btnExport)
        root.addView(ScrollView(this).apply {
            addView(out)
        }, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))

        btnRun.setOnClickListener { runAll() }
        btnBaseline.setOnClickListener { saveBaseline() }
        btnExport.setOnClickListener {
            val name = logger.exportToDownloads()
            Toast.makeText(this, if (name != null) "Отчёт: Download/$name" else "Ошибка экспорта", Toast.LENGTH_LONG).show()
        }

        setContentView(root)
        val last = logger.loadLastSession()
        out.text = if (last.isNotEmpty()) last.substring(0, minOf(last.length, 4000)) + "\n\n(последняя сессия — нажми ЗАПУСТИТЬ ПРОВЕРКУ для новой)"
        else "Готово. Нажми ЗАПУСТИТЬ ПРОВЕРКУ. v0.1.1"
    }

    private fun saveBaseline() {
        val sp = getSharedPreferences("baseline", MODE_PRIVATE)
        val o = JSONObject()
        for ((k, v) in logger.summary) o.put(k, v)
        sp.edit().putString("snap", o.toString()).putLong("at", System.currentTimeMillis()).apply()
        Toast.makeText(this, "BASELINE сохранён (${logger.summary.size} тестов)", Toast.LENGTH_SHORT).show()
    }

    private fun baselineSnap(): JSONObject? {
        return try {
            JSONObject(getSharedPreferences("baseline", MODE_PRIVATE).getString("snap", "{}") ?: "{}")
        } catch (_: Exception) { null }
    }

    private fun runAll() {
        if (running) return
        running = true
        btnRun.isEnabled = false
        btnRun.text = "ПРОВЕРКА ИДЁТ..."
        out.text = "Сеть:\n" + engine.networkInfo() + "\nРаботаю..."
        Thread {
            try {
                runProbe()
            } finally {
                ui.post {
                    running = false
                    btnRun.isEnabled = true
                    btnRun.text = "ЗАПУСТИТЬ ПРОВЕРКУ"
                }
            }
        }.start()
    }

    private fun publish(s: String) {
        ui.post { out.text = s }
    }

    private fun runProbe() {
        logger.raw { setLength(0) }
        logger.detail.setLength(0)
        logger.summary.clear()
        val (lv4, lv6) = engine.localAddresses()
        val sb = StringBuilder()
        sb.append("Сеть:\n").append(engine.networkInfo()).append('\n')

        val net = engine.activeNetwork()
        val transport = engine.transportName(net)
        if (net == null) {
            logger.test("VERDICT", "NO CONNECTIVITY") { it.append("active network отсутствует\n") }
            sb.append("Итог: NO CONNECTIVITY (active network отсутствует)\n")
            logger.saveLastSession()
            publish(sb.toString())
            return
        }
        val handle = net.networkHandle

        // ---------- DNS ----------
        sb.append("DNS:\n")
        val (dnsOk, dnsInfo, dnsMs) = engine.dnsSystem("example.com")
        logger.test("DNS_SYSTEM", if (dnsOk) "OK" else "FAIL") {
            it.append("host=example.com\nresult=").append(dnsInfo).append('\n')
            it.append("time=").append(dnsMs).append("ms\n")
        }
        sb.append("  SYSTEM: ").append(if (dnsOk) "OK ${dnsMs}ms" else "FAIL").append('\n')

        val (exV4, exV6) = engine.resolveFamily("example.com")
        logger.test("DNS_A", if (exV4.isNotEmpty()) "OK" else "FAIL") {
            it.append("host=example.com\nfamily=v4\n")
            it.append("ips=").append(exV4.joinToString(",") { a -> a.hostAddress ?: "?" }).append('\n')
        }
        logger.test("DNS_AAAA", if (exV6.isNotEmpty()) "OK" else "FAIL") {
            it.append("host=example.com\nfamily=v6\n")
            it.append("ips=").append(exV6.joinToString(",") { a -> a.hostAddress ?: "?" }).append('\n')
        }

        val (u53, u53ms) = engine.udp53(net, "8.8.8.8")
        logger.test("DNS_UDP53", if (u53) "OK" else "FAIL") {
            it.append("server=8.8.8.8:53\nnetwork=").append(transport).append(" handle=").append(handle).append('\n')
            it.append("time=").append(u53ms).append("ms\n")
        }
        sb.append("  UDP53: ").append(if (u53) "OK" else "FAIL").append('\n')

        val dotR = engine.dot(net, "1.1.1.1", "cloudflare-dns.com")
        logger.test("DNS_DOT", if (dotR.ok) "OK" else "FAIL") {
            it.append("server=1.1.1.1:853\nsni=cloudflare-dns.com\n")
            it.append("network=").append(transport).append(" handle=").append(handle).append('\n')
            it.append("tcp=853 tls=").append(dotR.tlsVersion).append('\n')
            it.append("time=").append(dotR.ms).append("ms\n")
            if (dotR.error != null) it.append("error=").append(dotR.error).append('\n')
        }
        sb.append("  DoT: ").append(if (dotR.ok) "OK " + dotR.tlsVersion else "FAIL").append('\n')

        val (dohOk, dohInfo) = engine.doh(net, "https://dns.google/resolve?name=example.com&type=A")
        logger.test("DNS_DOH", if (dohOk) "OK" else "FAIL") {
            it.append("url=https://dns.google/resolve\nstatus=").append(dohInfo.first)
            it.append("\nnetwork=").append(transport).append('\n')
            it.append("time=").append(dohInfo.second).append("ms\n")
        }
        sb.append("  DoH: ").append(if (dohOk) "OK http=" + dohInfo.first else "FAIL").append('\n')

        // ---------- Targets: IPv4/IPv6 независимо ----------
        sb.append("\nTargets:\n")
        val targets = engine.loadTargets()
        var anyHttps = false
        var anyTcp443 = false

        for (t in targets) {
            sb.append(t.name).append(" (").append(t.host).append(':').append(t.port).append("):\n")
            val (v4s, v6s) = engine.resolveFamily(t.host)
            val v4 = v4s.firstOrNull()
            val v6 = v6s.firstOrNull()

            logger.test("DNS_A_" + t.name, if (v4s.isNotEmpty()) "OK" else "FAIL") {
                it.append("host=").append(t.host).append("\nfamily=v4\n")
                it.append("ips=").append(v4s.joinToString(",") { a -> a.hostAddress ?: "?" }).append('\n')
            }
            logger.test("DNS_AAAA_" + t.name, if (v6s.isNotEmpty()) "OK" else "FAIL") {
                it.append("host=").append(t.host).append("\nfamily=v6\n")
                it.append("ips=").append(v6s.joinToString(",") { a -> a.hostAddress ?: "?" }).append('\n')
            }

            // TCP v4
            if (v4 != null) {
                val (tcpOk, tcpMs) = engine.tcpIp(net, v4, t.port)
                logger.test("TCP_V4_" + t.name, if (tcpOk) "OK" else "FAIL") {
                    it.append("host=").append(t.host).append('\n')
                    it.append("resolved_ip=").append(v4.hostAddress).append('\n')
                    it.append("family=v4\nnetwork=").append(transport).append(" handle=").append(handle).append('\n')
                    it.append("tcp=").append(if (tcpOk) "OK" else "FAIL").append(' ').append(tcpMs).append("ms\n")
                }
                sb.append("  TCP_V4: ").append(if (tcpOk) "OK ${tcpMs}ms" else "FAIL").append('\n')
                if (t.port == 443 && tcpOk) anyTcp443 = true
            } else {
                logger.test("TCP_V4_" + t.name, "SKIP") { it.append("no A record\n") }
                sb.append("  TCP_V4: SKIP (no A)\n")
            }

            // TCP v6
            if (v6 != null) {
                val (tcpOk6, tcpMs6) = engine.tcpIp(net, v6, t.port)
                logger.test("TCP_V6_" + t.name, if (tcpOk6) "OK" else "FAIL") {
                    it.append("host=").append(t.host).append('\n')
                    it.append("resolved_ip=").append(v6.hostAddress).append('\n')
                    it.append("family=v6\nnetwork=").append(transport).append(" handle=").append(handle).append('\n')
                    it.append("tcp=").append(if (tcpOk6) "OK" else "FAIL").append(' ').append(tcpMs6).append("ms\n")
                }
                sb.append("  TCP_V6: ").append(if (tcpOk6) "OK ${tcpMs6}ms" else "FAIL").append('\n')
                if (t.port == 443 && tcpOk6) anyTcp443 = true
            } else {
                logger.test("TCP_V6_" + t.name, "SKIP") { it.append("no AAAA record\n") }
                sb.append("  TCP_V6: SKIP (no AAAA)\n")
            }

            // TLS v4 + ALPN отдельно
            if (v4 != null) {
                val tls4 = engine.tlsToIp(net, v4, t.host, t.port)
                logger.test("TLS_V4_" + t.name, if (tls4.ok) "OK" else "FAIL") {
                    it.append("host=").append(t.host).append('\n')
                    it.append("resolved_ip=").append(v4.hostAddress).append('\n')
                    it.append("family=v4\nnetwork=").append(transport).append(" handle=").append(handle).append('\n')
                    it.append("tcp=OK tls=").append(if (tls4.ok) tls4.version else "FAIL")
                    it.append(" alpn=").append(tls4.alpn).append('\n')
                    it.append("connect=").append(tls4.connectMs).append("ms tls=").append(tls4.tlsMs).append("ms\n")
                    if (tls4.error != null) it.append("error=").append(tls4.error).append('\n')
                }
                sb.append("  TLS_V4: ").append(if (tls4.ok) "OK " + tls4.version + " alpn=" + tls4.alpn else "FAIL").append('\n')

                val h2 = engine.tlsToIp(net, v4, t.host, t.port, listOf("h2"))
                logger.test("ALPN_H2_" + t.name, if (h2.ok && h2.alpn == "h2") "OK" else "FAIL") {
                    it.append("host=").append(t.host).append('\n')
                    it.append("resolved_ip=").append(v4.hostAddress).append('\n')
                    it.append("family=v4\nnetwork=").append(transport).append('\n')
                    it.append("tls=").append(h2.version).append(" alpn=").append(h2.alpn).append('\n')
                    if (h2.error != null) it.append("error=").append(h2.error).append('\n')
                }

                val h11 = engine.tlsToIp(net, v4, t.host, t.port, listOf("http/1.1"))
                logger.test("ALPN_HTTP11_" + t.name, if (h11.ok && h11.alpn == "http/1.1") "OK" else "FAIL") {
                    it.append("host=").append(t.host).append('\n')
                    it.append("resolved_ip=").append(v4.hostAddress).append('\n')
                    it.append("family=v4\nnetwork=").append(transport).append('\n')
                    it.append("tls=").append(h11.version).append(" alpn=").append(h11.alpn).append('\n')
                    if (h11.error != null) it.append("error=").append(h11.error).append('\n')
                }
            } else {
                logger.test("TLS_V4_" + t.name, "SKIP") { it.append("no A record\n") }
                logger.test("ALPN_H2_" + t.name, "SKIP") { it.append("no A record\n") }
                logger.test("ALPN_HTTP11_" + t.name, "SKIP") { it.append("no A record\n") }
            }

            // TLS v6
            if (v6 != null) {
                val tls6 = engine.tlsToIp(net, v6, t.host, t.port)
                logger.test("TLS_V6_" + t.name, if (tls6.ok) "OK" else "FAIL") {
                    it.append("host=").append(t.host).append('\n')
                    it.append("resolved_ip=").append(v6.hostAddress).append('\n')
                    it.append("family=v6\nnetwork=").append(transport).append(" handle=").append(handle).append('\n')
                    it.append("tcp=OK tls=").append(if (tls6.ok) tls6.version else "FAIL")
                    it.append(" alpn=").append(tls6.alpn).append('\n')
                    if (tls6.error != null) it.append("error=").append(tls6.error).append('\n')
                }
                sb.append("  TLS_V6: ").append(if (tls6.ok) "OK " + tls6.version else "FAIL").append('\n')
            } else {
                logger.test("TLS_V6_" + t.name, "SKIP") { it.append("no AAAA record\n") }
            }

            // HTTPS v4
            if (v4 != null && t.https) {
                val http4 = engine.httpsIp(net, v4, t.host, t.port)
                logger.test("HTTPS_V4_" + t.name, if (http4.ok) "OK" else "FAIL") {
                    it.append("host=").append(t.host).append('\n')
                    it.append("resolved_ip=").append(v4.hostAddress).append('\n')
                    it.append("family=v4\nnetwork=").append(transport).append(" handle=").append(handle).append('\n')
                    it.append("tcp=OK tls=").append(if (http4.tlsMs >= 0) "OK" else "FAIL")
                    it.append(" alpn=").append(http4.alpn).append('\n')
                    it.append("http=").append(http4.status).append('\n')
                    it.append("connect=").append(http4.connectMs).append("ms tls=").append(http4.tlsMs)
                    it.append("ms ttfb=").append(http4.ttfbMs).append("ms total=").append(http4.totalMs).append("ms\n")
                    it.append("bytes=").append(http4.bytes).append('\n')
                    if (http4.error != null) it.append("error=").append(http4.error).append('\n')
                }
                sb.append("  HTTPS_V4: ").append(if (http4.ok) "OK status=" + http4.status + " ttfb=" + http4.ttfbMs + "ms" else "FAIL").append('\n')
                if (http4.ok && http4.status in 200..399) anyHttps = true
            } else if (t.https) {
                logger.test("HTTPS_V4_" + t.name, "SKIP") { it.append("no A record\n") }
            }

            // HTTPS v6
            if (v6 != null && t.https) {
                val http6 = engine.httpsIp(net, v6, t.host, t.port)
                logger.test("HTTPS_V6_" + t.name, if (http6.ok) "OK" else "FAIL") {
                    it.append("host=").append(t.host).append('\n')
                    it.append("resolved_ip=").append(v6.hostAddress).append('\n')
                    it.append("family=v6\nnetwork=").append(transport).append(" handle=").append(handle).append('\n')
                    it.append("tcp=OK tls=").append(if (http6.tlsMs >= 0) "OK" else "FAIL")
                    it.append(" alpn=").append(http6.alpn).append('\n')
                    it.append("http=").append(http6.status).append('\n')
                    it.append("connect=").append(http6.connectMs).append("ms tls=").append(http6.tlsMs)
                    it.append("ms ttfb=").append(http6.ttfbMs).append("ms total=").append(http6.totalMs).append("ms\n")
                    it.append("bytes=").append(http6.bytes).append('\n')
                    if (http6.error != null) it.append("error=").append(http6.error).append('\n')
                }
                sb.append("  HTTPS_V6: ").append(if (http6.ok) "OK status=" + http6.status else "FAIL").append('\n')
                if (http6.ok && http6.status in 200..399) anyHttps = true
            } else if (t.https) {
                logger.test("HTTPS_V6_" + t.name, "SKIP") { it.append("no AAAA record\n") }
            }
        }

        // ---------- TCP 80 ----------
        val (t80, t80ms) = engine.tcpHost(net, "example.com", 80)
        logger.test("TCP_80", if (t80) "OK" else "FAIL") {
            it.append("host=example.com:80\nnetwork=").append(transport).append(" handle=").append(handle).append('\n')
            it.append("time=").append(t80ms).append("ms\n")
        }
        sb.append("\nTCP 80: ").append(if (t80) "OK" else "FAIL").append('\n')

        sb.append("IPv4: ").append(lv4).append('\n')
        sb.append("IPv6: ").append(lv6).append('\n')

        // ---------- UDP443 (не QUIC) ----------
        val (q, qms) = engine.udp443Probe(net, "google.com")
        logger.test("UDP443_PROBE", q) {
            it.append("host=google.com:443 udp\nnetwork=").append(transport).append(" handle=").append(handle).append('\n')
            it.append("time=").append(qms).append("ms\n")
        }
        sb.append("UDP443_PROBE: ").append(q).append('\n')

        // ---------- Итог: без ALLOWLIST CONFIRMED ----------
        val verdict = when {
            anyHttps && dnsOk && dohOk -> "FULL INTERNET"
            anyHttps -> "PARTIAL"
            anyTcp443 -> "RESTRICTED SUSPECTED (TCP проходит, TLS/HTTPS режется)"
            else -> "NO CONNECTIVITY"
        }
        logger.test("VERDICT", verdict) { it.append(verdict).append('\n') }
        sb.append("\nИтог: ").append(verdict).append('\n')

        // BASELINE diff
        val base = baselineSnap()
        if (base != null && base.length() > 0) {
            sb.append("\nСравнение с BASELINE:\n")
            for ((k, v) in logger.summary) {
                if (base.has(k)) {
                    val b = base.getString(k)
                    if (b != v) sb.append("  ").append(k).append(": BASELINE ").append(b).append(" -> ").append(v).append('\n')
                }
            }
        }

        sb.append("\n--- журнал: СОХРАНИТЬ ОТЧЁТ ---\n")
        logger.saveLastSession()
        publish(sb.toString())
    }
}
