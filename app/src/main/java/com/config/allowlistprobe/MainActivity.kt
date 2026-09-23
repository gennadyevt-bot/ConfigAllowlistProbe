package com.config.allowlistprobe

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private lateinit var engine: ProbeEngine
    private lateinit var logger: SessionLogger
    private lateinit var out: TextView
    private lateinit var btnRun: Button
    private lateinit var spinner: Spinner
    private val ui = Handler(Looper.getMainLooper())
    private var running = false
    private var completed = false

    companion object {
        const val VERSION = "0.1.4"
        val CONTEXTS = listOf("NORMAL", "ALLOWLIST_SURFACE", "METRO")
        val CONTEXT_LABELS = listOf("Обычный", "Белый список (поверхность)", "Метро")
        val FIXED_GOOGLE_IPS = listOf("8.8.8.8", "142.250.74.46")
        val CONTROLS = listOf("ya.ru", "vk.com", "lenta.ru")
        val DIFF_KEYS = listOf(
            "GOOGLE_DNS_A", "GOOGLE_TCP_V4", "GOOGLE_TLS_V4", "GOOGLE_HTTPS_V4",
            "GOOGLE_TCP_V6", "GOOGLE_TLS_V6", "GOOGLE_HTTPS_V6",
            "GOOGLE_FIXED_IP_TCP_8.8.8.8", "GOOGLE_FIXED_IP_TCP_142.250.74.46",
            "GOOGLE_TCP_80", "EXAMPLE_TCP_V4", "EXAMPLE_HTTPS_V4",
            "CONTROL_YA_RU", "CONTROL_VK_COM", "CONTROL_LENTA_RU",
            "DNS_SYSTEM", "DNS_UDP53", "DNS_DOT", "DNS_DOH", "UDP443_PROBE",
            "VERDICT_CLASSIFIER"
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        logger = SessionLogger(this)
        engine = ProbeEngine(this, logger)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
        }
        spinner = Spinner(this)
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, CONTEXT_LABELS)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinner.adapter = adapter
        btnRun = Button(this).apply { text = "ЗАПУСТИТЬ ПРОВЕРКУ" }
        val btnBaseline = Button(this).apply { text = "СОХРАНИТЬ BASELINE" }
        val btnExport = Button(this).apply { text = "СОХРАНИТЬ ОТЧЁТ" }
        out = TextView(this).apply {
            textSize = 13f
            typeface = android.graphics.Typeface.MONOSPACE
        }
        root.addView(spinner)
        root.addView(btnRun)
        root.addView(btnBaseline)
        root.addView(btnExport)
        root.addView(ScrollView(this).apply { addView(out) },
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))

        btnRun.setOnClickListener { runAll() }
        btnBaseline.setOnClickListener { saveBaseline() }
        btnExport.setOnClickListener {
            if (running) return@setOnClickListener
            val name = logger.exportToDownloads()
            Toast.makeText(this, if (name != null) "Отчёт: Download/$name" else "Ошибка экспорта", Toast.LENGTH_LONG).show()
        }

        setContentView(root)
        val last = logger.loadLastSession()
        out.text = if (last.isNotEmpty()) last.substring(0, minOf(last.length, 4000)) +
            "\n\n(последняя сессия — нажми ЗАПУСТИТЬ ПРОВЕРКУ для новой)"
        else "Готово. Нажми ЗАПУСТИТЬ ПРОВЕРКУ. v$VERSION"
    }

    private fun contextValue(): String = CONTEXTS[spinner.selectedItemPosition]

    private fun saveBaseline() {
        if (running || !completed) {
            Toast.makeText(this, "Сначала дождись завершения проверки", Toast.LENGTH_SHORT).show()
            return
        }
        val sp = getSharedPreferences("baseline", MODE_PRIVATE)
        val o = JSONObject()
        for ((k, v) in logger.summary) o.put(k, v)
        sp.edit().putString("snap", o.toString()).putString("report", logger.buildReport())
            .putLong("at", System.currentTimeMillis()).apply()
        Toast.makeText(this, "BASELINE сохранён (${logger.summary.size} тестов)", Toast.LENGTH_SHORT).show()
    }

    private fun baselineSnap(): JSONObject? {
        return try {
            JSONObject(getSharedPreferences("baseline", MODE_PRIVATE).getString("snap", "{}") ?: "{}")
        } catch (_: Exception) { null }
    }

    private fun previousTest(): JSONObject? {
        return try {
            JSONObject(getSharedPreferences("prevtest", MODE_PRIVATE).getString("snap", "{}") ?: "{}")
        } catch (_: Exception) { null }
    }

    private fun savePrevious(context: String, snap: NetSnapshot) {
        val o = JSONObject()
        o.put("context", context)
        o.put("at", System.currentTimeMillis())
        val netObj = JSONObject()
        for ((k, v) in snap.core()) netObj.put(k, v)
        o.put("net", netObj)
        val s = JSONObject()
        for ((k, v) in logger.summary) s.put(k, v)
        o.put("summary", s)
        getSharedPreferences("prevtest", MODE_PRIVATE).edit().putString("snap", o.toString()).apply()
    }

    private fun runAll() {
        if (running) return
        running = true
        completed = false
        btnRun.isEnabled = false
        btnRun.text = "ПРОВЕРКА ИДЁТ..."
        Thread {
            try {
                runProbe()
            } catch (e: Exception) {
                logger.log("SESSION_ERROR ${e.javaClass.simpleName}: ${e.message}")
                logger.saveLastSession()
                publish("Проверка прервана: ${e.message}. Сохрани отчёт.")
            } finally {
                ui.post {
                    running = false
                    btnRun.isEnabled = true
                    btnRun.text = "ЗАПУСТИТЬ ПРОВЕРКУ"
                }
            }
        }.start()
    }

    private fun publish(s: String) { ui.post { out.text = s } }

    private fun runProbe() {
        logger.raw { setLength(0) }
        logger.detail.setLength(0)
        logger.summary.clear()
        val context = contextValue()
        logger.testContext = context
        val sb = StringBuilder()
        val net = engine.activeNetwork()
        val transport = engine.transportName(net)

        logger.log("version=$VERSION")
        logger.log("TEST_CONTEXT=$context")
        logger.log("timestamp=" + SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date()))
        val snapStart = engine.snapshot()
        logger.test("NETWORK_SNAPSHOT_START", "OK") { it.append(snapStart.describe()) }
        sb.append("Сеть (старт):\n").append(snapStart.describe()).append('\n')

        if (net == null) {
            logger.test("VERDICT", "NO CONNECTIVITY") { it.append("active network отсутствует\n") }
            sb.append("Итог: NO CONNECTIVITY\n")
            logger.saveLastSession()
            publish(sb.toString())
            return
        }
        val handle = net.networkHandle
        val vpnOn = snapStart.vpn == "true"
        val validated = snapStart.validated == "true"

        // ========== 1. DNS: system + google/example families ==========
        publish(sb.toString() + "DNS…\n")
        val (sysOk, sysInfo, sysMs) = engine.dnsSystem(net, "example.com")
        logger.test("DNS_SYSTEM", if (sysOk) "OK" else "FAIL") {
            it.append("host=example.com\nresult=").append(sysInfo).append('\n')
            it.append("time=").append(sysMs).append("ms\n")
        }
        val (gV4s, gV6s) = engine.resolveFamily(net, "google.com")
        val googleV4 = gV4s.firstOrNull()
        val googleV6 = gV6s.firstOrNull()
        logger.test("GOOGLE_DNS_A", if (gV4s.isNotEmpty()) "OK" else "FAIL") {
            it.append("host=google.com family=v4\nips=")
                .append(gV4s.joinToString(",") { a -> a.hostAddress ?: "?" }).append('\n')
        }
        logger.test("GOOGLE_DNS_AAAA", if (gV6s.isNotEmpty()) "OK" else "FAIL") {
            it.append("host=google.com family=v6\nips=")
                .append(gV6s.joinToString(",") { a -> a.hostAddress ?: "?" }).append('\n')
        }
        val (exV4s, exV6s) = engine.resolveFamily(net, "example.com")
        val exampleV4 = exV4s.firstOrNull()
        val exampleV6 = exV6s.firstOrNull()
        logger.test("EXAMPLE_DNS_A", if (exV4s.isNotEmpty()) "OK" else "FAIL") {
            it.append("host=example.com family=v4\nips=")
                .append(exV4s.joinToString(",") { a -> a.hostAddress ?: "?" }).append('\n')
        }
        logger.test("EXAMPLE_DNS_AAAA", if (exV6s.isNotEmpty()) "OK" else "FAIL") {
            it.append("host=example.com family=v6\nips=")
                .append(exV6s.joinToString(",") { a -> a.hostAddress ?: "?" }).append('\n')
        }
        sb.append("DNS system: ").append(if (sysOk) "OK ${sysMs}ms" else "FAIL").append('\n')
        sb.append("Google DNS v4: ").append(
            if (gV4s.isNotEmpty()) gV4s.joinToString(",") { a -> a.hostAddress ?: "?" } else "FAIL"
        ).append('\n')

        // ========== 2. Google TCP v4: 3 attempts ==========
        var gTcpOkCount = 0
        if (googleV4 != null) {
            for (i in 1..3) {
                publish(sb.toString() + "Google TCP 443, попытка $i/3…\n")
                val a = engine.tcpAttempt(net, googleV4, 443)
                if (a.result == "OK") gTcpOkCount++
                logger.test("GOOGLE_TCP_V4_ATTEMPT_$i", a.result) {
                    it.append("ip=").append(googleV4.hostAddress).append(":443 network=").append(handle).append('\n')
                    it.append("time=").append(a.ms).append("ms\n")
                    if (a.error != null) it.append("error=").append(a.error).append('\n')
                }
            }
            val agg = if (gTcpOkCount == 3) "OK" else if (gTcpOkCount == 0) "FAIL 3/3" else "PARTIAL $gTcpOkCount/3"
            logger.test("GOOGLE_TCP_V4", agg) {
                it.append("ip=").append(googleV4.hostAddress).append(":443 network=").append(handle).append('\n')
                it.append("ok=").append(gTcpOkCount).append("/3\n")
            }
            sb.append("Google TCP 443: ").append(agg).append('\n')
        } else {
            logger.test("GOOGLE_TCP_V4", "SKIP") { it.append("no A record\n") }
            sb.append("Google TCP 443: SKIP (no A)\n")
        }
        val googleTcpV4State = when {
            googleV4 == null -> "SKIP"
            gTcpOkCount == 3 -> "OK"
            gTcpOkCount == 0 -> "FAIL_3/3"
            else -> "PARTIAL"
        }

        // ========== 3. Google TLS/HTTPS v4 (только если TCP проходил) ==========
        var gTlsOk = false
        var gHttpOk = false
        if (googleV4 != null && gTcpOkCount > 0) {
            val t = engine.tlsToIp(net, googleV4, "google.com", 443)
            gTlsOk = t.ok
            logger.test("GOOGLE_TLS_V4", engine.classifyTls(t)) {
                it.append("host=google.com ip=").append(googleV4.hostAddress).append(":443\n")
                it.append("tls=").append(if (t.ok) t.version else "FAIL").append(" alpn=").append(t.alpn).append('\n')
                it.append("connect=").append(t.connectMs).append("ms tls=").append(t.tlsMs).append("ms\n")
                if (t.error != null) it.append("error=").append(t.error).append('\n')
            }
            val h = engine.httpsIp(net, googleV4, "google.com", 443)
            gHttpOk = h.ok
            logger.test("GOOGLE_HTTPS_V4", if (h.ok) "REACHABLE ${h.status}" else "FAIL") {
                it.append("host=google.com ip=").append(googleV4.hostAddress).append(":443\n")
                it.append("status=").append(h.status).append(" ttfb=").append(h.ttfbMs)
                    .append("ms total=").append(h.totalMs).append("ms bytes=").append(h.bytes).append('\n')
                if (h.error != null) it.append("error=").append(h.error).append('\n')
            }
            sb.append("Google TLS: ").append(logger.summary["GOOGLE_TLS_V4"]).append('\n')
            sb.append("Google HTTPS: ").append(logger.summary["GOOGLE_HTTPS_V4"]).append('\n')
        } else {
            val skip = if (googleV4 == null) "SKIP" else "SKIP_AFTER_TCP_FAIL"
            logger.test("GOOGLE_TLS_V4", skip) { it.append(skip).append('\n') }
            logger.test("GOOGLE_HTTPS_V4", skip) { it.append(skip).append('\n') }
            sb.append("Google TLS/HTTPS: ").append(skip).append('\n')
        }

        // ========== 4. TLS без SNI + SNI matrix (Google) ==========
        if (googleV4 != null && gTcpOkCount > 0) {
            val ns = engine.tlsNoSni(net, googleV4)
            logger.test("GOOGLE_TLS_NOSNI_V4", engine.classifyTls(ns)) {
                it.append("ip=").append(googleV4.hostAddress).append(":443 sni=NONE\n")
                it.append("connect=").append(ns.connectMs).append("ms tls=").append(ns.tlsMs).append("ms\n")
                if (ns.error != null) it.append("error=").append(ns.error).append('\n')
            }
            for (case in MatrixProbe.cases("google.com")) {
                publish(sb.toString() + "Google matrix ${case.label}…\n")
                val r = MatrixProbe.run(net, googleV4, "google.com", case)
                logger.test("MATRIX_GOOGLE_${case.label}", r.outcome) { it.append(r.detail) }
            }
        } else {
            logger.test("GOOGLE_TLS_NOSNI_V4", "SKIP_AFTER_TCP_FAIL") {}
        }

        // ========== 5. Google IPv6 ==========
        if (googleV6 != null) {
            val a6 = engine.tcpAttempt(net, googleV6, 443)
            logger.test("GOOGLE_TCP_V6", a6.result) {
                it.append("ip=").append(googleV6.hostAddress).append(":443\n")
                it.append("time=").append(a6.ms).append("ms\n")
                if (a6.error != null) it.append("error=").append(a6.error).append('\n')
            }
            if (a6.result == "OK") {
                val t6 = engine.tlsToIp(net, googleV6, "google.com", 443)
                logger.test("GOOGLE_TLS_V6", engine.classifyTls(t6)) {
                    it.append("ip=").append(googleV6.hostAddress).append(":443\n")
                    if (t6.error != null) it.append("error=").append(t6.error).append('\n')
                }
                val h6 = engine.httpsIp(net, googleV6, "google.com", 443)
                logger.test("GOOGLE_HTTPS_V6", if (h6.ok) "REACHABLE ${h6.status}" else "FAIL") {
                    it.append("ip=").append(googleV6.hostAddress).append(":443 status=").append(h6.status).append('\n')
                }
            } else {
                logger.test("GOOGLE_TLS_V6", "SKIP_AFTER_TCP_FAIL") {}
                logger.test("GOOGLE_HTTPS_V6", "SKIP_AFTER_TCP_FAIL") {}
            }
        } else {
            logger.test("GOOGLE_TCP_V6", "SKIP_NO_AAAA") { it.append("no AAAA record\n") }
            logger.test("GOOGLE_TLS_V6", "SKIP_NO_AAAA") {}
            logger.test("GOOGLE_HTTPS_V6", "SKIP_NO_AAAA") {}
        }

        // ========== 6. Fixed reference IP + порт 80 ==========
        for (ipStr in FIXED_GOOGLE_IPS) {
            val addr = try { java.net.InetAddress.getByName(ipStr) } catch (_: Exception) { null }
            if (addr == null) {
                logger.test("GOOGLE_FIXED_IP_TCP_$ipStr", "SKIP") { it.append("unparseable\n") }
                continue
            }
            publish(sb.toString() + "Fixed IP $ipStr…\n")
            val f443 = engine.tcpAttempt(net, addr, 443)
            logger.test("GOOGLE_FIXED_IP_TCP_$ipStr", f443.result) {
                it.append("ip=").append(ipStr).append(":443 (no DNS lookup)\n")
                it.append("time=").append(f443.ms).append("ms\n")
                if (f443.error != null) it.append("error=").append(f443.error).append('\n')
            }
            val f80 = engine.tcpAttempt(net, addr, 80)
            logger.test("GOOGLE_FIXED_TCP_80_$ipStr", f80.result) {
                it.append("ip=").append(ipStr).append(":80 (no DNS lookup)\n")
                it.append("time=").append(f80.ms).append("ms\n")
            }
        }
        if (googleV4 != null) {
            val a80 = engine.tcpAttempt(net, googleV4, 80)
            logger.test("GOOGLE_TCP_80", a80.result) {
                it.append("ip=").append(googleV4.hostAddress).append(":80\n")
                it.append("time=").append(a80.ms).append("ms\n")
                if (a80.error != null) it.append("error=").append(a80.error).append('\n')
            }
        } else {
            logger.test("GOOGLE_TCP_80", "SKIP") { it.append("no A record\n") }
        }

        // ========== 7. example.com ==========
        var exTcpOk = false
        var exHttpOk = false
        if (exampleV4 != null) {
            val a = engine.tcpAttempt(net, exampleV4, 443)
            exTcpOk = a.result == "OK"
            logger.test("EXAMPLE_TCP_V4", a.result) {
                it.append("ip=").append(exampleV4.hostAddress).append(":443 time=").append(a.ms).append("ms\n")
                if (a.error != null) it.append("error=").append(a.error).append('\n')
            }
            if (exTcpOk) {
                val t = engine.tlsToIp(net, exampleV4, "example.com", 443)
                logger.test("EXAMPLE_TLS_V4", engine.classifyTls(t)) {
                    if (t.error != null) it.append("error=").append(t.error).append('\n')
                }
                val h = engine.httpsIp(net, exampleV4, "example.com", 443)
                exHttpOk = h.ok
                logger.test("EXAMPLE_HTTPS_V4", if (h.ok) "REACHABLE ${h.status}" else "FAIL") {
                    it.append("status=").append(h.status).append('\n')
                }
            } else {
                logger.test("EXAMPLE_TLS_V4", "SKIP_AFTER_TCP_FAIL") {}
                logger.test("EXAMPLE_HTTPS_V4", "SKIP_AFTER_TCP_FAIL") {}
            }
        } else {
            logger.test("EXAMPLE_TCP_V4", "SKIP") { it.append("no A record\n") }
        }

        // ========== 8. Контрольные ресурсы ==========
        var controlReachable = false
        for (host in CONTROLS) {
            publish(sb.toString() + "Контроль: $host…\n")
            val (v4s, v6s) = engine.resolveFamily(net, host)
            val v4 = v4s.firstOrNull()
            val v6 = v6s.firstOrNull()
            logger.test("CONTROL_DNS_$host", if (v4s.isNotEmpty() || v6s.isNotEmpty()) "OK" else "FAIL") {
                it.append("host=").append(host).append('\n')
                it.append("v4=").append(v4s.joinToString(",") { a -> a.hostAddress ?: "?" }).append('\n')
                it.append("v6=").append(v6s.joinToString(",") { a -> a.hostAddress ?: "?" }).append('\n')
            }
            var reachable = false
            if (v4 != null) {
                val a = engine.tcpAttempt(net, v4, 443)
                logger.test("CONTROL_${host}_TCP_V4", a.result) {
                    it.append("host=").append(host).append(" ip=").append(v4.hostAddress)
                        .append(":443 time=").append(a.ms).append("ms\n")
                }
                if (a.result == "OK") {
                    val t = engine.tlsToIp(net, v4, host, 443)
                    logger.test("CONTROL_${host}_TLS_V4", engine.classifyTls(t)) {
                        if (t.error != null) it.append("error=").append(t.error).append('\n')
                    }
                    val h = engine.httpsIp(net, v4, host, 443)
                    logger.test("CONTROL_${host}_HTTPS_V4", if (h.ok) "REACHABLE ${h.status}" else "FAIL") {
                        it.append("status=").append(h.status).append('\n')
                    }
                    if (t.ok || h.ok) reachable = true
                } else {
                    logger.test("CONTROL_${host}_TLS_V4", "SKIP_AFTER_TCP_FAIL") {}
                    logger.test("CONTROL_${host}_HTTPS_V4", "SKIP_AFTER_TCP_FAIL") {}
                }
            }
            if (v6 != null) {
                val a6 = engine.tcpAttempt(net, v6, 443)
                logger.test("CONTROL_${host}_TCP_V6", a6.result) {
                    it.append("host=").append(host).append(" ip=").append(v6.hostAddress).append(":443\n")
                }
                if (a6.result == "OK") reachable = true
            }
            val key = "CONTROL_" + host.uppercase().replace('.', '_')
            logger.test(key, if (reachable) "REACHABLE" else "FAIL") {
                it.append("host=").append(host).append(" network=").append(handle).append('\n')
            }
            sb.append(host).append(": ").append(if (reachable) "доступен" else "НЕДОСТУПЕН").append('\n')
            controlReachable = controlReachable || reachable
            logger.saveLastSession()
        }

        // ========== 9. Внешние DNS: UDP53 / DoT / DoH ==========
        val u53 = engine.udp53Ex(net, "8.8.8.8")
        logger.test("DNS_UDP53", u53.first) {
            it.append("server=8.8.8.8:53 network=").append(transport).append(" handle=").append(handle).append('\n')
            it.append("time=").append(u53.second).append("ms\n")
            if (u53.third != null) it.append("error=").append(u53.third).append('\n')
        }
        val dotR = engine.dot(net, "1.1.1.1", "cloudflare-dns.com")
        val dotState = if (dotR.ok) "OK" else if ((dotR.error ?: "").contains("SocketTimeout")) "TIMEOUT" else "FAIL"
        logger.test("DNS_DOT", dotState) {
            it.append("server=1.1.1.1:853 sni=cloudflare-dns.com network=").append(transport).append('\n')
            it.append("time=").append(dotR.ms).append("ms\n")
            if (dotR.error != null) it.append("error=").append(dotR.error).append('\n')
        }
        val (dohOk, dohInfo) = engine.doh(net, "https://dns.google/resolve?name=example.com&type=A")
        logger.test("DNS_DOH", if (dohOk) "OK" else "FAIL") {
            it.append("url=https://dns.google/resolve status=").append(dohInfo.first)
                .append(" time=").append(dohInfo.second).append("ms\n")
        }
        val externalDnsOk = u53.first == "OK" || dotR.ok || dohOk
        sb.append("Внешние DNS: UDP53=").append(u53.first)
            .append(" DoT=").append(dotState).append(" DoH=").append(if (dohOk) "OK" else "FAIL").append('\n')

        // ========== 10. UDP443 ==========
        val (q, qms) = engine.udp443Probe(net, "google.com")
        logger.test("UDP443_PROBE", q) {
            it.append("host=google.com:443 udp network=").append(transport).append('\n')
            it.append("time=").append(qms).append("ms\n")
        }
        sb.append("UDP443: ").append(q).append(" (TIMEOUT не доказывает блокировку QUIC)\n")

        // ========== 11. Снапшот конца + network change ==========
        val snapEnd = engine.snapshot()
        logger.test("NETWORK_SNAPSHOT_END", "OK") { it.append(snapEnd.describe()) }
        val changes = snapStart.diff(snapEnd)
        val networkChanged = changes.isNotEmpty()
        logger.test("NETWORK_CHANGED", networkChanged.toString()) {
            if (changes.isEmpty()) it.append("unchanged\n")
            else for (c in changes) it.append(c).append('\n')
        }

        // ========== 12. TLS/SNI suspect из matrix ==========
        val before = logger.summary["MATRIX_GOOGLE_CONTROL_BEFORE"] ?: ""
        val noSni = logger.summary["MATRIX_GOOGLE_NO_SNI"] ?: ""
        val otherSni = logger.summary["MATRIX_GOOGLE_OTHER_SNI"] ?: ""
        fun tlsFailed(s: String) = s.startsWith("TLS_") || s.startsWith("TCP_") || s == "CERT_ERROR"
        fun tlsPassed(s: String) = !tlsFailed(s)
        val tlsSniSuspect = tlsFailed(before) && (tlsPassed(noSni) || tlsPassed(otherSni))

        // ========== 13. Classifier ==========
        val input = Classifier.Input(
            transport = transport,
            vpn = vpnOn,
            validated = validated,
            networkChanged = networkChanged,
            googleDnsOk = gV4s.isNotEmpty() || gV6s.isNotEmpty(),
            systemDnsOk = sysOk,
            externalDnsOk = externalDnsOk,
            externalDnsRan = true,
            googleTcpV4 = googleTcpV4State,
            googleTlsV4Ok = gTlsOk,
            googleHttpsV4Ok = gHttpOk,
            exampleTcpOk = exTcpOk,
            exampleHttpsOk = exHttpOk,
            controlReachable = controlReachable,
            tlsSniSuspect = tlsSniSuspect
        )
        val (verdict, explanation) = Classifier.classify(input)
        logger.test("VERDICT_CLASSIFIER", verdict) { it.append(explanation).append('\n') }

        // ========== 14. Сравнение с предыдущим тестом ==========
        val prev = previousTest()
        if (prev != null && prev.length() > 0) {
            val pd = StringBuilder()
            pd.append("previous context=").append(prev.optString("context", "?")).append('\n')
            val pNet = prev.optJSONObject("net")
            if (pNet != null) {
                for ((k, v) in snapStart.core()) {
                    val pv = if (pNet.has(k)) pNet.getString(k) else "?"
                    if (pv != v) pd.append("$k: $pv -> $v\n")
                }
            }
            val pSum = prev.optJSONObject("summary")
            if (pSum != null) {
                for (k in DIFF_KEYS) {
                    val cur = logger.summary[k] ?: "-"
                    val old = if (pSum.has(k)) pSum.getString(k) else "-"
                    if (pSum.has(k) || logger.summary.containsKey(k)) {
                        if (old != cur) pd.append("$k: $old -> $cur\n")
                    }
                }
            }
            logger.log("COMPARE_PREVIOUS=true\n" + pd.toString())
            sb.append("\n=== СРАВНЕНИЕ С ПРЕДЫДУЩИМ ТЕСТОМ ===\n").append(pd.toString())
        }
        savePrevious(context, snapStart)

        // ========== 15. Сводка на экран ==========
        sb.append("\n=== СВОДКА ===\n")
        sb.append("Сеть: ").append(transport).append(" (").append(snapStart.networkType).append(")")
            .append("  VPN: ").append(if (vpnOn) "вкл" else "выкл").append('\n')
        sb.append("Контекст: ").append(context).append('\n')
        sb.append("Google: DNS=").append(if (gV4s.isNotEmpty() || gV6s.isNotEmpty()) "OK" else "FAIL")
            .append(" TCP443=").append(googleTcpV4State.replace("_", "/"))
            .append(" TLS=").append(logger.summary["GOOGLE_TLS_V4"] ?: "-")
            .append(" HTTPS=").append(logger.summary["GOOGLE_HTTPS_V4"] ?: "-").append('\n')
        sb.append("Fixed 8.8.8.8: TCP443=").append(logger.summary["GOOGLE_FIXED_IP_TCP_8.8.8.8"] ?: "-")
            .append(" TCP80=").append(logger.summary["GOOGLE_FIXED_TCP_80_8.8.8.8"] ?: "-").append('\n')
        sb.append("example.com: TCP=").append(logger.summary["EXAMPLE_TCP_V4"] ?: "-")
            .append(" HTTPS=").append(logger.summary["EXAMPLE_HTTPS_V4"] ?: "-").append('\n')
        sb.append("Яндекс: ").append(logger.summary["CONTROL_YA_RU"] ?: "-")
            .append("  VK: ").append(logger.summary["CONTROL_VK_COM"] ?: "-")
            .append("  Lenta: ").append(logger.summary["CONTROL_LENTA_RU"] ?: "-").append('\n')
        sb.append("Результат: ").append(verdict).append('\n').append(explanation).append('\n')
        if (networkChanged) {
            sb.append("Сеть изменилась во время теста:\n")
            for (c in changes) sb.append("  ").append(c).append('\n')
        }

        // ========== 16. BASELINE diff (без перезаписи) ==========
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

        completed = !networkChanged
        logger.saveLastSession()
        sb.append("\n--- журнал: СОХРАНИТЬ ОТЧЁТ ---\n")
        publish(sb.toString())
    }
}
