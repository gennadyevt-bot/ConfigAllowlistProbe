package com.config.allowlistprobe.transport

/**
 * Заготовка под экспериментальные транспорты (Этап 2 по ТЗ).
 * Пока не реализуем ничего — только контракт, чтобы архитектура
 * не вырастала лапшой: каждый будущий транспорт (DIRECT_TCP, TLS_443,
 * HTTP_CONNECT, WEBSOCKET_HTTPS) — отдельный модуль с единым интерфейсом.
 */
interface ProbeTransport {
    val name: String
    fun probe(host: String, port: Int, timeoutMs: Int): TransportResult
}

data class TransportResult(
    val ok: Boolean,
    val stage: String,
    val error: String?,
    val connectMs: Long
)

class TransportEngine {
    private val transports = LinkedHashMap<String, ProbeTransport>()

    fun register(t: ProbeTransport) {
        transports[t.name] = t
    }

    fun available(): List<String> = transports.keys.toList()
}
