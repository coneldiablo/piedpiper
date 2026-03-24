#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GUI-friendly report wrappers.
"""

from __future__ import annotations

from typing import Any, Dict

from reports.report_generator import generate_html_report as _generate_html_report
from reports.report_generator import generate_pdf_report as _generate_pdf_report


def _split_sections(analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "static": analysis_results.get("static") or {},
        "dynamic": analysis_results.get("dynamic") or {},
        "iocs": analysis_results.get("iocs") or [],
        "risk": analysis_results.get("risk") or {},
        "behavioral": analysis_results.get("behavioral") or analysis_results.get("dynamic", {}).get("behavioral_patterns", []),
        "mitre": analysis_results.get("mitre") or {},
        "d3fend": analysis_results.get("d3fend") or {},
        "ti_enrichment": analysis_results.get("ti_enrichment") or {},
        "fusion": analysis_results.get("fusion") or {},
        "retro_hunt": analysis_results.get("retro_hunt") or {},
        "report_errors": analysis_results.get("report_errors") or [],
    }


def generate_pdf_report(analysis_results: Dict[str, Any], output_path: str):
    sections = _split_sections(analysis_results)
    return _generate_pdf_report(
        output_path,
        sections["static"],
        sections["dynamic"],
        sections["iocs"],
        sections["risk"],
        behavioral_data=sections["behavioral"],
        mitre_data=sections["mitre"],
        d3fend_data=sections["d3fend"],
        ti_enrichment=sections["ti_enrichment"],
        fusion_data=sections["fusion"],
        retro_hunt=sections["retro_hunt"],
        report_errors=sections["report_errors"],
    )


def generate_html_report(analysis_results: Dict[str, Any], output_path: str):
    sections = _split_sections(analysis_results)
    return _generate_html_report(
        output_path,
        sections["static"],
        sections["dynamic"],
        sections["iocs"],
        sections["risk"],
        behavioral_data=sections["behavioral"],
        mitre_data=sections["mitre"],
        d3fend_data=sections["d3fend"],
        ti_enrichment=sections["ti_enrichment"],
        fusion_data=sections["fusion"],
        retro_hunt=sections["retro_hunt"],
        report_errors=sections["report_errors"],
    )
