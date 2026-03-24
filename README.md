# Pied Piper

Pied Piper — это Windows-first платформа для анализа вредоносных объектов с единым non-ML пайплайном: статический анализ, наблюдение за runtime-поведением, извлечение IoC, поведенческое профилирование, сопоставление с MITRE ATT&CK, рекомендации D3FEND, обогащение threat intelligence, внешний ретрохант и генерация отчётов в нескольких форматах.

ML-подсистема остаётся в репозитории, но данное обновление выравнивания сосредоточено именно на non-ML контуре, который используется GUI, REST API и стеком отчётности.

## Канонический Пайплайн

Основной путь анализа общий для GUI и API:

`static -> dynamic -> IoC -> behavioral -> MITRE -> D3FEND -> threat intel -> retro-hunt -> report`

Точка входа реализации:

- `services/analysis_pipeline.py`

Ключевые выходы:

- `static`: метаданные файла, форматно-зависимый анализ, совпадения YARA, статус движка YARA
- `dynamic`: возможности Frida/runtime, вызовы API, таймлайн, дифф системных снимков
- `iocs`: извлечённые индикаторы из статических и динамических артефактов
- `behavioral`: подозрительные поведенческие паттерны
- `mitre`: техники ATT&CK
- `d3fend`: сопоставленные защитные меры
- `ti_enrichment`: проверки IoC через настроенные TI-провайдеры
- `retro_hunt`: результаты внешнего поиска в SIEM/EDR/sandbox
- `fusion`: агрегированная сводка для аналитика
- `risk`: базовая оценка, скорректированная оценка и усиление уверенности от retro-hunt

## Основные Компоненты

- `analyzer/static_analysis.py`
  - анализ PE, ELF, PDF, OOXML (`docx`, `docm`), OLE и скриптов
  - инспекция OOXML-пакета на наличие `vbaProject.bin`, embedded OLE, внешних `.rels` и подозрительных шаблонов/связей
  - статус загрузки YARA всегда включается в результат

- `analyzer/dynamic_analysis.py`
  - runtime-анализ на базе Frida с расширенным каталогом хуков (`50+` API)
  - дифференциальные снимки процессов, файловой системы и реестра на Windows, когда это возможно
  - явный degraded mode, если Frida недоступна

- `services/retro_hunt.py`
  - оркестрация коннекторов SIEM, EDR и sandbox
  - агрегация, устойчивая к частичным сбоям

- `services/intel_fusion.py`
  - workspace для MITRE/D3FEND fusion и выдачи защитных рекомендаций

- `analyzer/ai_analyst.py`
  - сценарии для аналитика через AITUNNEL: объяснение угрозы и генерация YARA
  - явный fallback-режим, если `AITUNNEL_API_KEY` не настроен

- `api/server.py`
  - Flask API
  - Swagger/OpenAPI по адресу `/api/openapi.json`
  - Swagger UI по адресу `/api/docs`

- `gui/modern_gui.py`
  - desktop GUI со вкладками анализа, MITRE, D3FEND, статуса подсистем и ретроханта/fusion

- `reports/report_generator.py`
  - генерация PDF, HTML и JSON-отчётов из унифицированного result payload

## Конфигурация

Несекретные значения по умолчанию хранятся в `config.json`.
Секреты и операционные токены рекомендуется передавать через переменные окружения.

### AITUNNEL

- `AITUNNEL_API_KEY`
- `AITUNNEL_BASE_URL`
- `AITUNNEL_MODEL`
- `AITUNNEL_TIMEOUT`
- `AITUNNEL_MAX_RETRIES`
- `AITUNNEL_TEMPERATURE`
- `AITUNNEL_VERIFY_SSL`

Базовый URL по умолчанию:

- `https://api.aitunnel.ru/v1/`

Модель по умолчанию:

- `gemini-3-flash-preview`

### Внешний Retro-Hunt

- `RETRO_HUNT_SIEM_ENDPOINT`
- `RETRO_HUNT_SIEM_TOKEN`
- `RETRO_HUNT_SIEM_TIMEOUT`
- `RETRO_HUNT_SIEM_VERIFY_SSL`
- `RETRO_HUNT_SIEM_ENABLED`
- `RETRO_HUNT_EDR_ENDPOINT`
- `RETRO_HUNT_EDR_TOKEN`
- `RETRO_HUNT_EDR_TIMEOUT`
- `RETRO_HUNT_EDR_VERIFY_SSL`
- `RETRO_HUNT_EDR_ENABLED`
- `RETRO_HUNT_SANDBOX_ENDPOINT`
- `RETRO_HUNT_SANDBOX_TOKEN`
- `RETRO_HUNT_SANDBOX_TIMEOUT`
- `RETRO_HUNT_SANDBOX_VERIFY_SSL`
- `RETRO_HUNT_SANDBOX_ENABLED`

## YARA

В репозиторий включены примерные правила:

- `yara_rules/generic_suspicious_strings.yar`
- `yara_rules/office_ooxml_macro.yar`

Если движок YARA недоступен или каталог правил пуст, платформа явно сообщает degraded state через:

- результаты статического анализа
- payload API
- панели статуса в GUI
- сгенерированные отчёты

## Поверхность API

Основные endpoint'ы:

- `POST /api/analyze`
- `GET /api/status/<job_id>`
- `GET /api/report/<job_id>`
- `POST /api/hunt`
- `POST /api/retro-hunt`
- `POST /api/yara`
- `GET /api/openapi.json`
- `GET /api/docs`

## Поверхность GUI

Desktop-приложение предоставляет:

- статический анализ
- динамический анализ
- AI-описание угрозы и генерацию YARA
- MITRE ATT&CK вместе с D3FEND
- статус подсистем Frida, YARA, threat intel, retro-hunt и AITUNNEL
- workflow fusion и внешнего ретроханта
- экспорт отчётов

## Проверка

Рекомендуемые локальные проверки:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe main.py gui --diagnose
```

## Примечания

- Windows — основная целевая платформа для полного runtime-покрытия.
- Linux/macOS поддерживаются в degraded mode там, где недоступен Windows-специфичный runtime capture.
- Это обновление non-ML части не меняет код обучения, метрики, датасеты и научные утверждения для ML-подсистемы.
