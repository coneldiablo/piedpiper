# Pied Piper

Pied Piper is a Windows-first malware analysis platform with a unified non-ML pipeline for static analysis, runtime observation, IoC extraction, behavioral profiling, MITRE ATT&CK mapping, D3FEND recommendations, threat-intelligence enrichment, external retro-hunt, and multi-format reporting.

The ML subsystem remains in the repository, but this alignment update focuses only on the non-ML contour used by the GUI, REST API, and reporting stack.

## Canonical Pipeline

The main analysis path is shared by the GUI and the API:

`static -> dynamic -> IoC -> behavioral -> MITRE -> D3FEND -> threat intel -> retro-hunt -> report`

Implementation entry point:

- `services/analysis_pipeline.py`

Key outputs:

- `static`: file metadata, format-specific analysis, YARA matches, YARA engine status
- `dynamic`: Frida/runtime capabilities, API calls, timeline, system snapshot diff
- `iocs`: extracted indicators from static and dynamic artifacts
- `behavioral`: suspicious behavioral patterns
- `mitre`: ATT&CK techniques
- `d3fend`: mapped defensive controls
- `ti_enrichment`: IOC lookups against configured TI providers
- `retro_hunt`: external SIEM/EDR/sandbox replay results
- `fusion`: aggregated analyst-facing summary
- `risk`: score, adjusted score, and retro-hunt confidence boost

## Main Components

- `analyzer/static_analysis.py`
  - PE, ELF, PDF, OOXML (`docx`, `docm`), OLE, and script inspection
  - OOXML package inspection for `vbaProject.bin`, embedded OLE, external `.rels`, and suspicious template/link relations
  - YARA loading status is always included in results

- `analyzer/dynamic_analysis.py`
  - Frida-based runtime analysis with an expanded hook catalog (`50+` APIs)
  - Windows differential snapshots for processes, filesystem, and registry when available
  - explicit degraded mode when Frida is unavailable

- `services/retro_hunt.py`
  - connector orchestration for SIEM, EDR, and sandbox backends
  - partial-failure tolerant aggregation

- `services/intel_fusion.py`
  - MITRE/D3FEND fusion workspace and defensive recommendations

- `analyzer/ai_analyst.py`
  - AITUNNEL-backed analyst workflows for explanation and YARA generation
  - explicit fallback mode when `AITUNNEL_API_KEY` is not configured

- `api/server.py`
  - Flask API
  - Swagger/OpenAPI at `/api/openapi.json`
  - Swagger UI at `/api/docs`

- `gui/modern_gui.py`
  - desktop GUI with tabs for analysis, MITRE, D3FEND, subsystem status, and retro-hunt/fusion

- `reports/report_generator.py`
  - PDF, HTML, and JSON report generation from the unified result payload

## Configuration

Non-secret defaults live in `config.json`.
Secrets and operational tokens should be supplied via environment variables.

### AITUNNEL

- `AITUNNEL_API_KEY`
- `AITUNNEL_BASE_URL`
- `AITUNNEL_MODEL`
- `AITUNNEL_TIMEOUT`
- `AITUNNEL_MAX_RETRIES`
- `AITUNNEL_TEMPERATURE`
- `AITUNNEL_VERIFY_SSL`

Default base URL:

- `https://api.aitunnel.ru/v1/`

Default model:

- `gemini-3-flash-preview`

### External Retro-Hunt

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

The repository now includes example rules in:

- `yara_rules/generic_suspicious_strings.yar`
- `yara_rules/office_ooxml_macro.yar`

If the YARA engine is unavailable or the rules directory is empty, the platform reports the degraded state explicitly through:

- static-analysis results
- API payloads
- GUI status panes
- generated reports

## API Surface

Core endpoints:

- `POST /api/analyze`
- `GET /api/status/<job_id>`
- `GET /api/report/<job_id>`
- `POST /api/hunt`
- `POST /api/retro-hunt`
- `POST /api/yara`
- `GET /api/openapi.json`
- `GET /api/docs`

## GUI Surface

The desktop application exposes:

- static analysis
- dynamic analysis
- AI-assisted description and YARA generation
- MITRE ATT&CK plus D3FEND
- subsystem health for Frida, YARA, threat intel, retro-hunt, and AITUNNEL
- fusion and external retro-hunt workflow
- report export

## Verification

Recommended local checks:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe main.py gui --diagnose
```

## Notes

- Windows is the primary target for full runtime coverage.
- Linux/macOS are supported in degraded mode where Windows-specific runtime capture is unavailable.
- This non-ML alignment work does not change the training code, metrics, datasets, or scientific claims for the ML subsystem.
