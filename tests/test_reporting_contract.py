import json
from pathlib import Path

from reports.report_generator import generate_report


def test_generate_report_respects_requested_formats_and_extra_sections(tmp_path):
    generated = generate_report(
        output_dir=str(tmp_path),
        base_name="case001",
        static_data={
            "filepath": "C:/samples/case001.docm",
            "file_type": "docm",
            "yara_status": {"status": "ready"},
        },
        dynamic_data={"api_calls": [{"api": "CreateProcessW"}]},
        ioc_data=[{"type": "domain", "value": "evil.example", "source": "static"}],
        risk_data={"score": 70, "adjusted_score": 74},
        formats=["json", "html"],
        behavioral_data=[{"pattern": "process_spawn"}],
        mitre_data={"techniques": [{"id": "T1059"}]},
        d3fend_data={"controls": ["D3-CH"]},
        ti_enrichment={"lookups": [{"value": "evil.example", "verdict": "malicious"}]},
        fusion_data={"observations": [{"source": "static"}]},
        retro_hunt={"status": "completed", "total_hits": 2},
        report_errors=[{"stage": "report_generation", "message": "none"}],
    )

    assert set(generated) == {"json", "html"}

    json_payload = json.loads(Path(generated["json"]).read_text(encoding="utf-8"))
    assert json_payload["d3fend"]["controls"] == ["D3-CH"]
    assert json_payload["ti_enrichment"]["lookups"][0]["value"] == "evil.example"
    assert json_payload["report_errors"][0]["stage"] == "report_generation"

    html_payload = Path(generated["html"]).read_text(encoding="utf-8")
    assert "MITRE / D3FEND / Threat Intel / Fusion" in html_payload
    assert "evil.example" in html_payload
