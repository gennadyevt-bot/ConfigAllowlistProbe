package com.config.allowlistprobe

object Classifier {
    data class Input(
        val transport: String,
        val vpn: Boolean,
        val validated: Boolean,
        val networkChanged: Boolean,
        val googleDnsOk: Boolean,
        val systemDnsOk: Boolean,
        val externalDnsOk: Boolean,
        val externalDnsRan: Boolean,
        val googleTcpV4: String,   // OK | FAIL_3/3 | PARTIAL | SKIP
        val googleTlsV4Ok: Boolean,
        val googleHttpsV4Ok: Boolean,
        val exampleTcpOk: Boolean,
        val exampleHttpsOk: Boolean,
        val controlReachable: Boolean,
        val tlsSniSuspect: Boolean
    )

    fun classify(i: Input): Pair<String, String> = when {
        i.networkChanged ->
            "INCONCLUSIVE_NETWORK_CHANGED" to
                "Активная сеть изменилась во время теста. Лог сохранён полностью, вывод недействителен."
        i.vpn ->
            "INCONCLUSIVE" to
                "VPN transport активен — этот запуск не отражает режим белого списка оператора."
        i.transport != "CELLULAR" ->
            if (i.googleHttpsV4Ok && i.controlReachable)
                "NORMAL_NETWORK" to "Не cellular: ограничение оператора здесь не измеряется, ресурсы доступны."
            else
                "INCONCLUSIVE" to "Не cellular-транспорт. Для диагностики белого списка нужна мобильная сеть."
        i.googleTcpV4 == "FAIL_3/3" && i.googleDnsOk && i.controlReachable && i.validated ->
            "POSSIBLE_ALLOWLIST_TCP" to
                ("Контрольные сайты доступны, Google резолвится, но TCP 443 к внешнему узлу " +
                 "не устанавливается 3/3. Ограничение начинается на TCP-уровне.")
        i.controlReachable && i.systemDnsOk && i.externalDnsRan && !i.externalDnsOk ->
            "POSSIBLE_ALLOWLIST_DNS" to
                ("Системный DNS жив, контрольные сайты работают, но внешние DNS " +
                 "(UDP53/DoT/DoH) систематически падают.")
        i.tlsSniSuspect && i.googleTcpV4 == "OK" ->
            "POSSIBLE_TLS_SNI_FILTER" to
                "TCP проходит, различие воспроизводится на TLS при разных SNI к одному IP."
        i.googleDnsOk && i.googleTcpV4 == "OK" && i.googleTlsV4Ok && !i.googleHttpsV4Ok ->
            "HTTPS_LAYER_FAILURE" to "DNS + TCP + TLS проходят, HTTPS падает."
        i.googleHttpsV4Ok && i.exampleHttpsOk && i.controlReachable ->
            "NORMAL_NETWORK" to "Google, example.com и контрольные сайты доступны — обычная сеть."
        else ->
            "INCONCLUSIVE" to "Данных недостаточно для классификации."
    }
}
