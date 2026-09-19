# ConfigAllowlistProbe

Экспериментальный Android-прототип для исследования сети в периоды
ограниченного доступа / белого списка оператора.

Пакет: `com.config.allowlistprobe`. Отдельный проект — Config_dns и
ConfigAdBlock не используются и не изменяются.

## Что умеет 0.1.0
- определяет активную сеть (Wi-Fi/Cellular, validated, VPN, DNS, routes)
- DNS: системный резолв, UDP/53, DoT/853, DoH
- TCP: 80, 443, настраиваемые порты из probe_targets.json
- TLS 1.2/1.3 + SNI + ALPN (h2/http1.1)
- HTTPS GET: status, connect/TLS время, размер ответа
- IPv4/IPv6 раздельно
- QUIC/UDP-443 диагностика (OK/TIMEOUT)
- подробный журнал, сохранение последней сессии, экспорт отчёта в Downloads
- BASELINE-снимок и сравнение с ним

## Архитектура
- `ProbeEngine` — все сетевые тесты
- `SessionLogger` — журнал, last-session, экспорт отчёта
- `MainActivity` — UI и оркестрация
- `TransportEngine` — заготовка под будущие экспериментальные транспорты (пока пустой)

## Сборка
GitHub Actions: push в main -> APK как artifact релиза.
