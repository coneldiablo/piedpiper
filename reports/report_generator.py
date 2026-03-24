#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unified multi-format report generation.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from jinja2 import Template
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

logger = logging.getLogger("report_generator")
logger.setLevel(logging.DEBUG)

PRODUCT_NAME = "Pied Piper"
PRODUCT_SUBTITLE = (
    "Integrated multi-level malware analysis platform with canonical non-ML "
    "pipeline, threat intelligence enrichment, retro-hunt, MITRE ATT&CK and D3FEND."
)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _normalise_iocs(ioc_data: Any) -> List[Dict[str, Any]]:
    return ioc_data if isinstance(ioc_data, list) else []


def _compose_analysis_bundle(
    *,
    static_data: Dict[str, Any],
    dynamic_data: Dict[str, Any],
    ioc_data: List[Dict[str, Any]],
    risk_data: Dict[str, Any],
    behavioral_data: Optional[List[Dict[str, Any]]] = None,
    mitre_data: Optional[Dict[str, Any]] = None,
    d3fend_data: Optional[Dict[str, Any]] = None,
    ti_enrichment: Optional[Dict[str, Any]] = None,
    fusion_data: Optional[Dict[str, Any]] = None,
    retro_hunt: Optional[Dict[str, Any]] = None,
    report_errors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    bundle = {
        "generated_at": _timestamp(),
        "static": static_data or {},
        "dynamic": dynamic_data or {},
        "iocs": _normalise_iocs(ioc_data),
        "risk": risk_data or {},
        "behavioral": behavioral_data or dynamic_data.get("behavioral_patterns", []) if isinstance(dynamic_data, dict) else [],
        "mitre": mitre_data or {},
        "d3fend": d3fend_data or {},
        "ti_enrichment": ti_enrichment or {},
        "fusion": fusion_data or {},
        "retro_hunt": retro_hunt or {},
        "report_errors": report_errors or [],
    }
    return bundle


def _build_summary_lines(bundle: Dict[str, Any]) -> List[str]:
    static_data = bundle.get("static") or {}
    dynamic_data = bundle.get("dynamic") or {}
    risk_data = bundle.get("risk") or {}
    mitre = bundle.get("mitre") or {}
    ti_enrichment = bundle.get("ti_enrichment") or {}
    retro_hunt = bundle.get("retro_hunt") or {}
    d3fend = bundle.get("d3fend") or {}

    lines = [
        f"Generated at: {bundle.get('generated_at')}",
        f"File path: {static_data.get('filepath') or dynamic_data.get('process_path') or 'n/a'}",
        f"File type: {static_data.get('file_type', 'unknown')}",
        f"Risk score: {risk_data.get('score', 'n/a')} (adjusted: {risk_data.get('adjusted_score', 'n/a')})",
        f"YARA status: {(static_data.get('yara_status') or {}).get('status', 'unknown')}",
        f"API calls: {len(dynamic_data.get('api_calls') or [])}",
        f"IoCs: {len(bundle.get('iocs') or [])}",
        f"MITRE techniques: {len(mitre.get('techniques') or [])}",
        f"D3FEND controls: {len(d3fend.get('controls') or [])}",
        f"Threat-intel lookups: {len(ti_enrichment.get('lookups') or [])}",
        f"Retro-hunt hits: {retro_hunt.get('total_hits', 0)}",
    ]
    return lines


def generate_pdf_report(
    filepath: str,
    static_data: Dict[str, Any],
    dynamic_data: Dict[str, Any],
    ioc_data: List[Dict[str, Any]],
    risk_data: Dict[str, Any],
    *,
    logo_path: Optional[str] = None,
    behavioral_data: Optional[List[Dict[str, Any]]] = None,
    mitre_data: Optional[Dict[str, Any]] = None,
    d3fend_data: Optional[Dict[str, Any]] = None,
    ti_enrichment: Optional[Dict[str, Any]] = None,
    fusion_data: Optional[Dict[str, Any]] = None,
    retro_hunt: Optional[Dict[str, Any]] = None,
    report_errors: Optional[List[Dict[str, Any]]] = None,
) -> str:
    bundle = _compose_analysis_bundle(
        static_data=static_data,
        dynamic_data=dynamic_data,
        ioc_data=ioc_data,
        risk_data=risk_data,
        behavioral_data=behavioral_data,
        mitre_data=mitre_data,
        d3fend_data=d3fend_data,
        ti_enrichment=ti_enrichment,
        fusion_data=fusion_data,
        retro_hunt=retro_hunt,
        report_errors=report_errors,
    )

    doc = SimpleDocTemplate(filepath, pagesize=A4)
    styles = getSampleStyleSheet()
    code_style = ParagraphStyle("CodeSmall", parent=styles["Code"], fontSize=8, leading=10)
    story: List[Any] = []

    story.append(Paragraph(f"{PRODUCT_NAME} Report", styles["Title"]))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(PRODUCT_SUBTITLE, styles["BodyText"]))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    for line in _build_summary_lines(bundle):
        story.append(Paragraph(line, styles["BodyText"]))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Static Analysis", styles["Heading2"]))
    story.append(Paragraph(json.dumps(static_data, ensure_ascii=False, indent=2), code_style))
    story.append(Spacer(1, 0.2 * cm))

    story.append(Paragraph("Dynamic Analysis", styles["Heading2"]))
    story.append(Paragraph(json.dumps(dynamic_data, ensure_ascii=False, indent=2), code_style))
    story.append(Spacer(1, 0.2 * cm))

    iocs = _normalise_iocs(ioc_data)
    story.append(Paragraph("Indicators of Compromise", styles["Heading2"]))
    if iocs:
        table_data = [["Type", "Value", "Source"]]
        for entry in iocs[:25]:
            table_data.append([
                str(entry.get("type", "")),
                str(entry.get("value", "")),
                str(entry.get("source", "")),
            ])
        table = Table(table_data, colWidths=[3 * cm, 8 * cm, 6 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)
    else:
        story.append(Paragraph("No IoCs found.", styles["BodyText"]))

    story.append(PageBreak())
    story.append(Paragraph("MITRE ATT&CK / D3FEND / Threat Intel", styles["Heading2"]))
    story.append(Paragraph(json.dumps({
        "mitre": bundle.get("mitre"),
        "d3fend": bundle.get("d3fend"),
        "ti_enrichment": bundle.get("ti_enrichment"),
        "retro_hunt": bundle.get("retro_hunt"),
        "fusion": bundle.get("fusion"),
        "report_errors": bundle.get("report_errors"),
    }, ensure_ascii=False, indent=2), code_style))

    doc.build(story)
    return os.path.abspath(filepath)


def generate_html_report(
    filepath: str,
    static_data: Dict[str, Any],
    dynamic_data: Dict[str, Any],
    ioc_data: List[Dict[str, Any]],
    risk_data: Dict[str, Any],
    *,
    behavioral_data: Optional[List[Dict[str, Any]]] = None,
    mitre_data: Optional[Dict[str, Any]] = None,
    d3fend_data: Optional[Dict[str, Any]] = None,
    ti_enrichment: Optional[Dict[str, Any]] = None,
    fusion_data: Optional[Dict[str, Any]] = None,
    retro_hunt: Optional[Dict[str, Any]] = None,
    report_errors: Optional[List[Dict[str, Any]]] = None,
) -> str:
    bundle = _compose_analysis_bundle(
        static_data=static_data,
        dynamic_data=dynamic_data,
        ioc_data=ioc_data,
        risk_data=risk_data,
        behavioral_data=behavioral_data,
        mitre_data=mitre_data,
        d3fend_data=d3fend_data,
        ti_enrichment=ti_enrichment,
        fusion_data=fusion_data,
        retro_hunt=retro_hunt,
        report_errors=report_errors,
    )
    template = Template(
        """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Pied Piper Report</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #0f1419; color: #e6edf3; }
    h1, h2 { color: #7ee787; }
    section { margin-bottom: 24px; padding: 16px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; }
    pre { white-space: pre-wrap; word-break: break-word; background: #0d1117; padding: 12px; border-radius: 6px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #30363d; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #21262d; }
  </style>
</head>
<body>
  <h1>{{ product_name }}</h1>
  <p>{{ subtitle }}</p>
  <section>
    <h2>Executive Summary</h2>
    <ul>
      {% for line in summary_lines %}
      <li>{{ line }}</li>
      {% endfor %}
    </ul>
  </section>
  <section>
    <h2>Static Analysis</h2>
    <pre>{{ static_data }}</pre>
  </section>
  <section>
    <h2>Dynamic Analysis</h2>
    <pre>{{ dynamic_data }}</pre>
  </section>
  <section>
    <h2>Indicators of Compromise</h2>
    {% if iocs %}
    <table>
      <thead><tr><th>Type</th><th>Value</th><th>Source</th></tr></thead>
      <tbody>
        {% for ioc in iocs %}
        <tr><td>{{ ioc.type }}</td><td>{{ ioc.value }}</td><td>{{ ioc.source }}</td></tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p>No IoCs found.</p>
    {% endif %}
  </section>
  <section>
    <h2>MITRE / D3FEND / Threat Intel / Fusion</h2>
    <pre>{{ extra_data }}</pre>
  </section>
</body>
</html>
        """
    )
    html = template.render(
        product_name=PRODUCT_NAME,
        subtitle=PRODUCT_SUBTITLE,
        summary_lines=_build_summary_lines(bundle),
        static_data=json.dumps(bundle["static"], ensure_ascii=False, indent=2),
        dynamic_data=json.dumps(bundle["dynamic"], ensure_ascii=False, indent=2),
        iocs=bundle["iocs"],
        extra_data=json.dumps(
            {
                "risk": bundle["risk"],
                "behavioral": bundle["behavioral"],
                "mitre": bundle["mitre"],
                "d3fend": bundle["d3fend"],
                "ti_enrichment": bundle["ti_enrichment"],
                "retro_hunt": bundle["retro_hunt"],
                "fusion": bundle["fusion"],
                "report_errors": bundle["report_errors"],
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    with open(filepath, "w", encoding="utf-8") as handle:
        handle.write(html)
    return os.path.abspath(filepath)


def generate_json_report(filepath: str, bundle: Dict[str, Any]) -> str:
    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2, ensure_ascii=False)
    return os.path.abspath(filepath)


def generate_report(
    output_dir: str,
    base_name: str,
    static_data: Dict[str, Any],
    dynamic_data: Dict[str, Any],
    ioc_data: List[Dict[str, Any]],
    risk_data: Dict[str, Any],
    logo_path: Optional[str] = None,
    *,
    formats: Optional[Iterable[str]] = None,
    behavioral_data: Optional[List[Dict[str, Any]]] = None,
    mitre_data: Optional[Dict[str, Any]] = None,
    d3fend_data: Optional[Dict[str, Any]] = None,
    ti_enrichment: Optional[Dict[str, Any]] = None,
    fusion_data: Optional[Dict[str, Any]] = None,
    retro_hunt: Optional[Dict[str, Any]] = None,
    report_errors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, str]:
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    bundle = _compose_analysis_bundle(
        static_data=static_data,
        dynamic_data=dynamic_data,
        ioc_data=ioc_data,
        risk_data=risk_data,
        behavioral_data=behavioral_data,
        mitre_data=mitre_data,
        d3fend_data=d3fend_data,
        ti_enrichment=ti_enrichment,
        fusion_data=fusion_data,
        retro_hunt=retro_hunt,
        report_errors=report_errors,
    )

    requested_formats = [str(fmt).lower() for fmt in (formats or ["pdf", "html"])]
    requested_formats = [fmt for fmt in requested_formats if fmt in {"pdf", "html", "json"}]
    if not requested_formats:
        requested_formats = ["pdf", "html"]

    generated: Dict[str, str] = {}
    for fmt in requested_formats:
        if fmt == "pdf":
            path = os.path.join(output_dir, base_name + ".pdf")
            generated["pdf"] = generate_pdf_report(
                path,
                static_data,
                dynamic_data,
                ioc_data,
                risk_data,
                logo_path=logo_path,
                behavioral_data=behavioral_data,
                mitre_data=mitre_data,
                d3fend_data=d3fend_data,
                ti_enrichment=ti_enrichment,
                fusion_data=fusion_data,
                retro_hunt=retro_hunt,
                report_errors=report_errors,
            )
        elif fmt == "html":
            path = os.path.join(output_dir, base_name + ".html")
            generated["html"] = generate_html_report(
                path,
                static_data,
                dynamic_data,
                ioc_data,
                risk_data,
                behavioral_data=behavioral_data,
                mitre_data=mitre_data,
                d3fend_data=d3fend_data,
                ti_enrichment=ti_enrichment,
                fusion_data=fusion_data,
                retro_hunt=retro_hunt,
                report_errors=report_errors,
            )
        elif fmt == "json":
            path = os.path.join(output_dir, base_name + ".json")
            generated["json"] = generate_json_report(path, bundle)

    return generated


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Generate Pied Piper report from analysis JSON files.")
    parser.add_argument("--static-json", required=True)
    parser.add_argument("--dynamic-json", required=True)
    parser.add_argument("--ioc-json", required=True)
    parser.add_argument("--risk-json", required=True)
    parser.add_argument("--output-dir", default="./reports_out")
    parser.add_argument("--base-name", default="PiedPiper_CliReport")
    parser.add_argument("--logo")
    parser.add_argument("--formats", nargs="+", default=["pdf", "html"])
    args = parser.parse_args()

    def load_json(path: str) -> Any:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and "result" in data:
            return data["result"]
        return data

    results = generate_report(
        output_dir=args.output_dir,
        base_name=args.base_name,
        static_data=load_json(args.static_json),
        dynamic_data=load_json(args.dynamic_json),
        ioc_data=load_json(args.ioc_json),
        risk_data=load_json(args.risk_json),
        logo_path=args.logo,
        formats=args.formats,
    )
    print("Report generated:", results)
