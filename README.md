# ConfigAllowlistProbe

Экспериментальный Android-прототип для исследования сети в периоды
ограниченного доступа / белого списка оператора.

Пакет: `com.config.allowlistprobe`. Отдельный проект — Config\_dns и
ConfigAdBlock не используются и не изменяются.

## Новое в 0.1.2
- Матрица IP/SNI/Host запускается первой: lenta.ru, ya.ru, vk.com — кандидаты, а не гарантированно разрешённые сайты.
- Первый IPv4 и IPv6 каждого сайта, один фиксированный IP на все варианты: контроль → без SNI → другой SNI → другой Host → повторный контроль.
- Каждый вариант использует новое соединение через одну захваченную Android Network, дедлайн 12 секунд, HEAD без загрузки тела и без редиректов.
- TCP/TLS/HTTP ошибки и таймауты различаются; CERT_ERROR не считается доказательством фильтрации. Проверка доверия сертификатам не отключается.
- Отказ при другом SNI/Host может исходить от сервера/CDN. Для интерпретации сравнивайте ту же матрицу на том же IP с baseline без ограничений. Изменение IP означает другую пару измерений.
- DNS теперь также привязан к захваченной Network. При смене сети baseline не сохраняется.
- Экспорт включает подробный baseline; нельзя сохранить пустой или незавершённый baseline. UDP443_PROBE не является QUIC-тестом.

## Проверка на телефоне
1. Без VPN, на мобильной сети без ограничений: запустить проверку, дождаться конца, сохранить BASELINE.
2. Во время ограничений на той же мобильной сети: запустить проверку, НЕ перезаписывать baseline, сохранить отчёт.
3. Передать TXT-отчёт: там есть IP, семейство адресов, сеть, SNI, Host, стадия ошибки, контроль до/после и baseline. Не публикуйте его без проверки: отчёт содержит сетевые адреса.

## Что умела 0.1.1
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
GitHub Actions: push в main или diagnostics/** → lint, APK как workflow artifact (не GitHub Release). Автоматических unit-тестов в проекте пока нет; сетевую матрицу нужно проверить на телефоне.
