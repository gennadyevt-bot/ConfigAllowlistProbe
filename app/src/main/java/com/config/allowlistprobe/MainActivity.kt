package com.config.allowlistprobe

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
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
        else "Готово. Нажми ЗАПУСТИТЬ ПРОВЕРКУ."
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

        // DNS
        sb.append("DNS:\n")
        val (dnsOk, dnsInfo, dnsMs) = engine.dnsSystem("example.com")
        logger.test("DNS_SYSTEM", if (dnsOk) "OK" else "FAIL") {
            it.append("host=example.com\nresult=").append(dnsInfo).append('\n')
            it.append("time=").append(dnsMs).append("ms\n")
        }
        sb.append("  SYSTEM: ").append(if (dnsOk) "OK ${dnsMs}ms" else "FAIL").append('\n')

        val (u53, u53ms) = engine.udp53("8.8.8.8")
        logger.test("DNS_UDP53", if (u53) "OK" else "FAIL") {
            it.append("server=8.8.8.8:53\n").append("time=").append(u53ms).append("ms\n")
        }
        sb.append("  UDP53: ").append(if (u53) "OK" else "FAIL").append('\n')

        val (dotOk, dotMs) = engine.dot("1.1.1.1", "1.1.1.1")
        logger.test("DNS_DOT", if (dotOk) "OK" else "FAIL") {
            it.append("server=1.1.1.1:853\n").append("time=").append(dotMs).append("ms\n")
        }
        sb.append("  DoT: ").append(if (dotOk) "OK" else "FAIL").append('\n')

        val (dohOk, dohInfo) = engine.doh("https://dns.google/resolve?name=example.com&type=A")
        logger.test("DNS_DOH", if (dohOk) "OK" else "FAIL") {
            it.append("url=https://dns.google/resolve\nstatus=").append(dohInfo.first)
            it.append("\ntime=").append(dohInfo.second).append("ms\n")
        }
        sb.append("  DoH: ").append(if (dohOk) "OK http=" + dohInfo.first else "FAIL").append('\n')

        // TCP / TLS / HTTPS по каждому target
        sb.append("\nTargets:\n")
        val targets = engine.loadTargets()
        var anyHttps = false
        var anyTcp443 = false
        for (t in targets) {
            sb.append(t.name).append(" (").append(t.host).append(':').append(t.port).append("):\n")
            val (tcpOk, tcpMs) = engine.tcp(t.host, t.port)
            logger.test("TCP_" + t.name, if (tcpOk) "OK" else "FAIL") {
                it.append("host=").append(t.host).append(':').append(t.port).append('\n')
                it.append("time=").append(tcpMs).append("ms\n")
            }
            sb.append("  TCP ").append(t.port).append(": ").append(if (tcpOk) "OK ${tcpMs}ms" else "FAIL").append('\n')
            if (t.port == 443 && tcpOk) anyTcp443 = true

            if (t.https) {
                val tls13 = engine.tls(t.host, t.port, "TLSv1.3", listOf("h2", "http/1.1"))
                logger.test("TLS13_" + t.name, if (tls13.ok) "OK" else "FAIL") {
                    it.append("host=").append(t.host).append('\n')
                    it.append("version=").append(tls13.version).append(" alpn=").append(tls13.alpn).append('\n')
                    it.append("connect=").append(tls13.connectMs).append("ms tls=").append(tls13.tlsMs).append("ms\n")
                    if (tls13.error != null) it.append("error=").append(tls13.error).append('\n')
                }
                sb.append("  TLS1.3: ").append(if (tls13.ok) "OK " + tls13.version + " alpn=" + tls13.alpn else "FAIL").append('\n')

                val tls12 = engine.tls(t.host, t.port, "TLSv1.2", listOf("http/1.1"))
                logger.test("TLS12_" + t.name, if (tls12.ok) "OK" else "FAIL") {
                    it.append("host=").append(t.host).append('\n')
                    it.append("version=").append(tls12.version).append('\n')
                    if (tls12.error != null) it.append("error=").append(tls12.error).append('\n')
                }
                sb.append("  TLS1.2: ").append(if (tls12.ok) "OK" else "FAIL").append('\n')

                val http = engine.httpsGet("https://" + t.host + "/")
                logger.test("HTTPS_" + t.name, if (http.ok) "OK" else "FAIL") {
                    it.append("url=https://").append(t.host).append('/').append('\n')
                    it.append("status=").append(http.status).append(" bytes=").append(http.bytes).append('\n')
                    it.append("total=").append(http.totalMs).append("ms\n")
                    if (http.error != null) it.append("error=").append(http.error).append('\n')
                }
                sb.append("  HTTP: ").append(if (http.ok) "OK status=" + http.status + " " + http.totalMs + "ms" else "FAIL").append('\n')
                if (http.ok && http.status in 200..399) anyHttps = true
            }
        }

        // TCP 80
        val (t80, t80ms) = engine.tcp("example.com", 80)
        logger.test("TCP_80", if (t80) "OK" else "FAIL") {
            it.append("host=example.com:80\ntime=").append(t80ms).append("ms\n")
        }
        sb.append("\nTCP 80: ").append(if (t80) "OK" else "FAIL").append('\n')

        // IPv6
        val hasV6 = lv6 != "none"
        val v6ok = engine.v6Tcp443()
        logger.test("IPV6", if (v6ok) "OK" else "FAIL") {
            it.append("local_v6=").append(lv6).append('\n')
            it.append("target=2001:4860:4860::8888:443\n")
        }
        sb.append("IPv4: ").append(lv4).append('\n')
        sb.append("IPv6: ").append(lv6).append(if (hasV6) (if (v6ok) " (TCP443 OK)" else " (TCP443 FAIL)") else "").append('\n')

        // QUIC
        val (q, qms) = engine.quicProbe("google.com")
        logger.test("QUIC443", q) {
            it.append("host=google.com:443 udp\n").append("time=").append(qms).append("ms\n")
        }
        sb.append("QUIC udp443: ").append(q).append('\n')

        // Итог
        val verdict = when {
            anyHttps && dnsOk && dohOk -> "FULL INTERNET"
            anyHttps -> "PARTIAL"
            anyTcp443 -> "ALLOWLIST SUSPECTED (TCP проходит, TLS/HTTPS режется)"
            else -> "NO INTERNET"
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
