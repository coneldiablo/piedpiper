from pathlib import Path

import pytest

import api.server as server_module


class _ImmediateExecutor:
    def submit(self, fn, *args, **kwargs):
        fn(*args, **kwargs)

        class _DoneFuture:
            def done(self):
                return True

        return _DoneFuture()


class _DummyRetroHuntOrchestrator:
    def run(self, iocs, context=None):
        return {
            "status": "completed",
            "results": [
                {
                    "connector": "siem",
                    "status": "success",
                    "hits": [{"ioc": iocs[0]["value"]}],
                    "metadata": {"context": context or {}},
                }
            ],
            "confidence_boost": 0.6,
            "total_hits": 1,
        }


@pytest.fixture
def non_ml_app(monkeypatch, tmp_path):
    monkeypatch.setattr(server_module, "job_store", server_module.JobStore())
    monkeypatch.setattr(server_module, "executor", _ImmediateExecutor())
    monkeypatch.setattr(server_module, "RetroHuntOrchestrator", _DummyRetroHuntOrchestrator)

    def fake_pipeline(file_path, **kwargs):
        return {
            "static": {
                "filepath": str(file_path),
                "file_type": "docm",
                "yara_matches": [],
                "yara_status": {"status": "ready", "rules_loaded": 2},
            },
            "dynamic": {
                "api_calls": [{"api": "CreateProcessW"}],
                "behavioral_patterns": [{"pattern": "process_spawn"}],
                "runtime_capabilities": {"frida_available": False},
            },
            "iocs": [{"type": "domain", "value": "evil.example", "source": "static"}],
            "behavioral": [{"pattern": "process_spawn"}],
            "mitre": {"techniques": [{"id": "T1059"}]},
            "d3fend": {"controls": ["D3-CH"]},
            "ti_enrichment": {
                "status": "completed",
                "lookups": [{"type": "domain", "value": "evil.example", "verdict": "malicious"}],
                "summary": {"malicious": 1, "suspicious": 0, "unknown": 0},
                "service_status": {"virustotal": False},
            },
            "retro_hunt": {
                "status": "completed",
                "results": [],
                "confidence_boost": 0.4,
                "total_hits": 1,
            },
            "fusion": {
                "observations": [{"source": "static"}],
                "meta": {"d3fend_recommendations": {"D3-CH": 1}},
            },
            "risk": {
                "score": 70,
                "adjusted_score": 74,
                "adjusted_level": "high",
                "confidence_boost": 0.4,
            },
            "system_status": {
                "aitunnel": {"mode": "fallback", "model": "gemini-3-flash-preview"},
            },
            "report_errors": [],
        }

    def fake_generate_report(*, output_dir, base_name, formats=None, **kwargs):
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        generated = {}
        for fmt in formats or ["json"]:
            file_path = output_path / f"{base_name}.{fmt}"
            file_path.write_text(f"{fmt} report", encoding="utf-8")
            generated[fmt] = str(file_path)
        return generated

    monkeypatch.setattr(server_module, "run_canonical_pipeline", fake_pipeline)
    monkeypatch.setattr(server_module, "generate_report", fake_generate_report)
    return server_module.create_app()


def test_analyze_status_and_report_expose_non_ml_payload(non_ml_app, tmp_path):
    client = non_ml_app.test_client()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"demo")

    queued = client.post(
        "/api/analyze",
        json={
            "file": str(sample),
            "dynamic": False,
            "report_format": ["json", "html"],
            "generate_report": True,
        },
    )
    assert queued.status_code == 202

    job_id = queued.get_json()["job_id"]

    status = client.get(f"/api/status/{job_id}?details=true")
    assert status.status_code == 200
    status_payload = status.get_json()
    assert status_payload["status"] == "completed"
    assert "ti_enrichment" in status_payload["result"]
    assert "d3fend" in status_payload["result"]
    assert "fusion" in status_payload["result"]
    assert status_payload["report_errors"] == []

    report = client.get(f"/api/report/{job_id}")
    assert report.status_code == 200
    report_payload = report.get_json()
    assert len(report_payload["report_paths"]) == 2
    assert report_payload["result"]["retro_hunt"]["total_hits"] == 1


def test_openapi_and_retro_hunt_endpoint(non_ml_app):
    client = non_ml_app.test_client()

    openapi = client.get("/api/openapi.json")
    assert openapi.status_code == 200
    spec = openapi.get_json()
    analyze_props = spec["components"]["schemas"]["AnalyzeRequest"]["properties"]
    assert "/api/retro-hunt" in spec["paths"]
    assert "threat_intel" in analyze_props
    assert "retro_hunt" in analyze_props
    assert "json" in analyze_props["report_format"]["items"]["enum"]

    response = client.post(
        "/api/retro-hunt",
        json={"iocs": [{"type": "domain", "value": "evil.example"}], "context": {"case_id": "INC-1"}},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "completed"
    assert payload["confidence_boost"] == 0.6
    assert payload["results"][0]["connector"] == "siem"
