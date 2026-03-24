# Pied Piper Architecture

## 1. Runtime Model

Pied Piper uses one canonical non-ML analysis pipeline shared by the API and the desktop GUI:

```text
static -> dynamic -> IoC -> behavioral -> MITRE -> D3FEND -> threat intel -> retro-hunt -> report
```

Primary orchestrator:

- `services/analysis_pipeline.py`

This avoids divergence between standalone modules, GUI actions, and REST behavior.

## 2. Static Layer

Entry point:

- `analyzer/static_analysis.py`

Responsibilities:

- file hashing
- signature-based type detection
- PE/ELF/PDF/script inspection
- OOXML inspection for:
  - `docx` vs `docm`
  - `vbaProject.bin`
  - embedded OLE objects
  - external and suspicious relationships
  - template/auto-open indicators
- OLE/VBA parsing for legacy Office formats
- YARA loading, match execution, and degraded-state reporting
- string extraction and heuristic enrichment

Static result contract includes:

- `hashes`
- `file_type`
- `analysis`
- `yara_matches`
- `yara_status`
- `enhanced_checks`

## 3. Dynamic Layer

Entry point:

- `analyzer/dynamic_analysis.py`

Responsibilities:

- Frida-based API interception
- expanded Windows hook catalog (`50+` entries)
- process timeline construction
- file, registry, and network activity views
- Windows differential snapshots:
  - process inventory
  - filesystem state
  - registry state
- explicit runtime capability reporting
- degraded mode when Frida is unavailable

Dynamic result contract includes:

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

## 4. Enrichment Layer

### IoC Extraction

- `analyzer/ioc_extractor.py`

### Behavioral Profiling

- `analyzer/behavioral_analysis.py`

### MITRE ATT&CK

- `analyzer/mitre_attack.py`

### D3FEND

- `services/intel_fusion.py`

MITRE techniques are mapped into defensive controls and surfaced in both the machine-readable payload and the GUI.

## 5. Threat Intelligence

Entry point:

- `core/threat_intel.py`

Used by:

- `services/analysis_pipeline.py`

Behavior:

- enriches supported IoC types
- tracks provider availability
- degrades cleanly when keys or external services are unavailable

Result contract:

- `status`
- `lookups`
- `summary`
- `service_status`

## 6. External Retro-Hunt

Entry point:

- `services/retro_hunt.py`

Supported connector roles:

- SIEM
- EDR
- sandbox

Behavior:

- concurrent connector execution
- timeout-aware requests
- partial error isolation
- aggregated `confidence_boost`

Exposed through:

- canonical pipeline
- `POST /api/retro-hunt`
- GUI fusion/retrohunt tab

## 7. Fusion Workspace

Entry point:

- `services/intel_fusion.py`

Fusion aggregates observations from:

- static analysis
- dynamic analysis
- threat intel
- retro-hunt

Outputs include:

- observation summaries
- severity-aware metadata
- MITRE heatmap input
- D3FEND recommendations

## 8. AI Adapter Layer

Entry points:

- `services/ai_provider.py`
- `analyzer/ai_analyst.py`

Design:

- AITUNNEL is used as the single OpenAI-compatible provider adapter for non-ML AI features
- secrets are not stored in the repository
- fallback mode is explicit and observable

Capabilities:

- analyst description
- threat explanation
- YARA rule generation

## 9. API Layer

Entry point:

- `api/server.py`

Stack:

- Flask
- CORS
- JWT
- rate limiting
- OpenAPI generation
- optional Socket.IO notifications

Important endpoints:

- `POST /api/analyze`
- `GET /api/status/<job_id>`
- `GET /api/report/<job_id>`
- `POST /api/hunt`
- `POST /api/retro-hunt`
- `POST /api/yara`
- `GET /api/openapi.json`
- `GET /api/docs`

Job execution model:

- request is queued
- background worker runs canonical pipeline
- report generation is invoked with requested formats
- `report_errors` are preserved in job state and returned to clients

## 10. GUI Layer

Entry point:

- `gui/modern_gui.py`

The GUI is a desktop frontend, not a web frontend.
It consumes the same underlying analysis services used by the API and surfaces:

- static results
- dynamic results
- MITRE ATT&CK
- D3FEND
- AITUNNEL status
- subsystem status
- fusion summary
- external retro-hunt
- report export

## 11. Reporting Layer

Entry points:

- `reports/report_generator.py`
- `core/reporting.py`

Formats:

- PDF
- HTML
- JSON

Report payload includes:

- static data
- dynamic data
- IoCs
- risk
- behavioral
- MITRE
- D3FEND
- threat intel
- retro-hunt
- fusion
- `report_errors`

## 12. Configuration Strategy

Base configuration:

- `config.json`

Runtime overrides:

- `core/config.py`

Secrets are expected through environment variables only for:

- AITUNNEL API access
- external retro-hunt connectors
- threat-intelligence providers
- optional API auth

## 13. Platform Strategy

- Windows: full target platform for runtime capture and snapshotting
- Linux/macOS: degraded mode with explicit capability reporting

This keeps the scientific and product documentation aligned with what the code actually executes outside the ML subsystem.
