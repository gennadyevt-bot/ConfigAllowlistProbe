package com.config.allowlistprobe.transport

/**
 * Заготовка под экспериментальные транспорты (Этап 2 по ТЗ).
 * Пока не реализуем ничего — только контракт, чтобы архитектура
 * не вырастала лапшой: каждый будущий транспорт (DIRECT_TCP, TLS_443,
 * HTTP_CONNECT, WEBSOCKET_HTTPS) — отдельный модуль с единым интерфейсом.
 */
interface TransportEngine {
    val name: String
    fun probe(): TransportResult
}

data class TransportResult(
    val ok: Boolean,
    val stage: String,
    val error: String?,
    val connectMs: Long
)

/** Реестр будущих транспортов. Пока пуст — без реализации обхода. */
class TransportRegistry {
    private val engines = LinkedHashMap<String, TransportEngine>()

    fun register(e: TransportEngine) {
        engines[e.name] = e
    }

    fun available(): List<String> = engines.keys.toList()
}
