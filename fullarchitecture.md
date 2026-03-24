# Архитектура Pied Piper

## 1. Runtime-модель

Pied Piper использует один канонический non-ML пайплайн анализа, общий для API и desktop GUI:

```text
static -> dynamic -> IoC -> behavioral -> MITRE -> D3FEND -> threat intel -> retro-hunt -> report
```

Главный оркестратор:

- `services/analysis_pipeline.py`

Это устраняет расхождения между отдельными модулями, действиями GUI и поведением REST API.

## 2. Статический слой

Точка входа:

- `analyzer/static_analysis.py`

Задачи:

- хеширование файлов
- сигнатурное определение типа
- анализ PE/ELF/PDF/скриптов
- инспекция OOXML на предмет:
  - различения `docx` и `docm`
  - `vbaProject.bin`
  - embedded OLE-объектов
  - внешних и подозрительных relationships
  - шаблонов и автооткрытия
- разбор OLE/VBA для legacy-форматов Office
- загрузка YARA, выполнение совпадений и репортинг degraded state
- извлечение строк и эвристическое обогащение

Контракт результата статического анализа включает:

- `hashes`
- `file_type`
- `analysis`
- `yara_matches`
- `yara_status`
- `enhanced_checks`

## 3. Динамический слой

Точка входа:

- `analyzer/dynamic_analysis.py`

Задачи:

- перехват API на базе Frida
- расширенный Windows-каталог хуков (`50+` позиций)
- построение таймлайна процесса
- представление файловой, реестровой и сетевой активности
- дифференциальные снимки Windows:
  - список процессов
  - состояние файловой системы
  - состояние реестра
- явный репортинг runtime-возможностей
- degraded mode при недоступности Frida

Контракт результата динамического анализа включает:

- `api_calls`
- `behavioral_patterns`
- `file_operations`
- `registry_operations`
- `network`
- `timeline`
- `hook_catalog`
- `hook_catalog_size`
- `runtime_capabilities`
- `system_snapshots`
- `errors`

## 4. Слой обогащения

### Извлечение IoC

- `analyzer/ioc_extractor.py`

### Поведенческое профилирование

- `analyzer/behavioral_analysis.py`

### MITRE ATT&CK

- `analyzer/mitre_attack.py`

### D3FEND

- `services/intel_fusion.py`

Техники MITRE преобразуются в защитные меры и отображаются как в machine-readable payload, так и в GUI.

## 5. Threat Intelligence

Точка входа:

- `core/threat_intel.py`

Используется из:

- `services/analysis_pipeline.py`

Поведение:

- обогащает поддерживаемые типы IoC
- отслеживает доступность провайдеров
- корректно деградирует при отсутствии ключей или недоступности внешних сервисов

Контракт результата:

- `status`
- `lookups`
- `summary`
- `service_status`

## 6. Внешний Retro-Hunt

Точка входа:

- `services/retro_hunt.py`

Поддерживаемые роли коннекторов:

- SIEM
- EDR
- sandbox

Поведение:

- параллельный запуск коннекторов
- учёт таймаутов
- изоляция частичных ошибок
- агрегированный `confidence_boost`

Доступен через:

- канонический пайплайн
- `POST /api/retro-hunt`
- вкладку fusion/ретроханта в GUI

## 7. Fusion Workspace

Точка входа:

- `services/intel_fusion.py`

Fusion агрегирует наблюдения из:

- статического анализа
- динамического анализа
- threat intel
- retro-hunt

Выходы включают:

- сводки наблюдений
- metadata с учётом критичности
- данные для MITRE heatmap
- рекомендации D3FEND

## 8. AI Adapter Layer

Точки входа:

- `services/ai_provider.py`
- `analyzer/ai_analyst.py`

Дизайн:

- AITUNNEL используется как единый OpenAI-совместимый provider adapter для non-ML AI-функций
- секреты не хранятся в репозитории
- fallback-режим явный и наблюдаемый

Возможности:

- описание угрозы для аналитика
- объяснение угрозы
- генерация YARA-правил

## 9. Слой API

Точка входа:

- `api/server.py`

Стек:

- Flask
- CORS
- JWT
- rate limiting
- генерация OpenAPI
- опциональные уведомления через Socket.IO

Ключевые endpoint'ы:

- `POST /api/analyze`
- `GET /api/status/<job_id>`
- `GET /api/report/<job_id>`
- `POST /api/hunt`
- `POST /api/retro-hunt`
- `POST /api/yara`
- `GET /api/openapi.json`
- `GET /api/docs`

Модель выполнения job:

- запрос ставится в очередь
- фоновый worker запускает канонический пайплайн
- генерация отчётов вызывается с запрошенными форматами
- `report_errors` сохраняются в состоянии job и возвращаются клиентам

## 10. Слой GUI

Точка входа:

- `gui/modern_gui.py`

GUI — это desktop frontend, а не web frontend.
Он использует те же базовые сервисы анализа, что и API, и отображает:

- статические результаты
- динамические результаты
- MITRE ATT&CK
- D3FEND
- статус AITUNNEL
- статус подсистем
- fusion summary
- внешний ретрохант
- экспорт отчётов

## 11. Слой отчётности

Точки входа:

- `reports/report_generator.py`
- `core/reporting.py`

Форматы:

- PDF
- HTML
- JSON

Payload отчёта включает:

- статические данные
- динамические данные
- IoC
- risk
- behavioral
- MITRE
- D3FEND
- threat intel
- retro-hunt
- fusion
- `report_errors`

## 12. Стратегия конфигурации

Базовая конфигурация:

- `config.json`

Runtime-переопределения:

- `core/config.py`

Секреты ожидаются только через переменные окружения для:

- доступа к AITUNNEL API
- внешних retro-hunt коннекторов
- провайдеров threat intelligence
- опциональной авторизации API

## 13. Платформенная стратегия

- Windows: основная платформа для полного runtime-capture и snapshotting
- Linux/macOS: degraded mode с явным репортингом возможностей

Это удерживает научную и продуктовую документацию в соответствии с тем, что код реально выполняет вне ML-подсистемы.
