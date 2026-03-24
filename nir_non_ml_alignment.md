# NIR Non-ML Alignment Summary

This document records the non-ML features that are now directly backed by code, API payloads, GUI elements, and tests.

## Implemented and Surfaced

- Unified non-ML analysis pipeline in `services/analysis_pipeline.py`
- Windows-first dynamic analysis with explicit degraded mode
- Expanded Frida hook catalog (`50+` APIs declared)
- Differential runtime snapshots for processes, filesystem, and registry
- OOXML inspection for:
  - `docx` / `docm`
  - `vbaProject.bin`
  - embedded objects
  - external and suspicious relationships
  - auto-open indicators
- YARA engine status propagation to:
  - static results
  - GUI
  - API
  - generated reports
- AITUNNEL provider adapter with env-only secrets
- External retro-hunt orchestration for SIEM, EDR, and sandbox connectors
- MITRE to D3FEND mapping included in result payloads and GUI
- Unified report generation with PDF, HTML, and JSON outputs
- Swagger/OpenAPI exposure for the REST surface

## Explicitly Out of Scope for This Alignment Pass

- ML training code
- ML metrics
- dataset changes
- ML-related scientific claims

## Verification Targets

- `pytest`
- `main.py gui --diagnose`
- API/OpenAPI smoke checks
- compile/import hygiene for project files outside virtual environments
