# ConfigAllowlistProbe

Экспериментальный Android-прототип для исследования сети в периоды
ограниченного доступа / белого списка оператора.

Пакет: `com.config.allowlistprobe`. Отдельный проект — Config\_dns и
ConfigAdBlock не используются и не изменяются.

## Что умеет 0.1.1
- ВСЕ тесты идут через `ConnectivityManager.activeNetwork` (TCP — `network.socketFactory`, UDP — `network.bindSocket`, HTTP/HTTPS — `network.openConnection`); в отчёте handle сети + transport WIFI/CELLULAR
- DNS: системный резолв, UDP/53, DoT/853, DoH
- DoT: TCP853 через activeNetwork + TLS с настоящим SNI + валидация сертификата (endpointIdentificationAlgorithm=HTTPS), логируется negotiated TLS version
- TLS: SNI = hostname даже при подключении к конкретному IP, валидация сертификата
- ALPN без reflection: `SSLParameters.applicationProtocols` (API >= 29), отдельные тесты ALPN_H2 и ALPN_HTTP11, после handshake пишется `applicationProtocol`
- IPv4/IPv6 независимо для каждого target: DNS_A, DNS_AAAA, TCP_V4, TCP_V6, TLS_V4, TLS_V6, HTTPS_V4, HTTPS_V6
- HTTPS: body не более 64 KB, важны status/TTFB/bytes, а не скачивание страницы
- UDP443_PROBE (RESPONSE/TIMEOUT/ERROR) — это НЕ QUIC, настоящий QUIC будет отдельным transport-модулем позже
- подробный журнал, сохранение последней сессии, экспорт отчёта в Downloads
- BASELINE-снимок и сравнение с ним

## Итоги (verdict)
- FULL INTERNET / PARTIAL / RESTRICTED SUSPECTED / NO CONNECTIVITY
- ALLOWLIST CONFIRMED не выводится по одному тесту — только сравнением BASELINE и RESTRICTED по нескольким endpoint

## Архитектура
- `ProbeEngine` — все сетевые тесты (через activeNetwork)
- `SessionLogger` — журнал, last-session, экспорт отчёта
- `MainActivity` — UI и оркестрация
- `transport/TransportEngine` — интерфейс-заготовка под будущие экспериментальные транспорты (пока без реализации обхода)

## Сборка
GitHub Actions: push в main -> APK как artifact релиза.
