#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Collaborative intelligence fusion workspace.

Correlates findings across engines, maps them against ATT&CK / D3FEND,
and produces exportable briefs for blue-team consumers.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("intel_fusion")


DEFAULT_MITRE_TO_D3FEND = {
    "TA0001": ["D3-Detect", "D3-Protect"],
    "TA0002": ["D3-Isolate"],
    "TA0003": ["D3-Contain"],
    "T1059": ["D3-Command"],
    "T1105": ["D3-Channel"],
    "T1486": ["D3-Recover"],
}


def map_mitre_to_d3fend_controls(mitre_techniques: List[str]) -> List[str]:
    controls: List[str] = []
    for technique in mitre_techniques:
        controls.extend(DEFAULT_MITRE_TO_D3FEND.get(technique, []))
    deduped: List[str] = []
    for control in controls:
        if control not in deduped:
            deduped.append(control)
    return deduped


@dataclass
class FusionObservation:
    source: str
    summary: str
    severity: str = "medium"
    mitre_techniques: List[str] = field(default_factory=list)
    d3fend_controls: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "summary": self.summary,
            "severity": self.severity,
            "mitre_techniques": sorted(set(self.mitre_techniques)),
            "d3fend_controls": sorted(set(self.d3fend_controls)),
            "artifacts": self.artifacts,
            "extra": self.extra,
        }


class IntelFusionWorkspace:
    """In-memory workspace for building a fused picture of ongoing incidents."""

    def __init__(self) -> None:
        self._observations: List[FusionObservation] = []
        self._created_at = datetime.now(timezone.utc)
        self._tags: set[str] = set()

    def add_observation(
        self,
        source: str,
        summary: str,
        *,
        severity: str = "medium",
        mitre_techniques: Optional[List[str]] = None,
        artifacts: Optional[List[str]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> FusionObservation:
        mitre = mitre_techniques or []
        d3fend = map_mitre_to_d3fend_controls(mitre)
        observation = FusionObservation(
            source=source,
            summary=summary,
            severity=severity,
            mitre_techniques=mitre,
            d3fend_controls=d3fend,
            artifacts=artifacts or [],
            extra=extra or {},
        )
        self._observations.append(observation)
        self._tags.update(observation.extra.get("tags", []))
        logger.debug("Observation from %s added", source)
        return observation

    def correlate(self) -> Dict[str, Any]:
        """Return aggregated view of all observations."""
        mitre_counter: Dict[str, int] = {}
        d3fend_counter: Dict[str, int] = {}
        severity_counter: Dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        for obs in self._observations:
            for tech in obs.mitre_techniques:
                mitre_counter[tech] = mitre_counter.get(tech, 0) + 1
            for control in obs.d3fend_controls:
                d3fend_counter[control] = d3fend_counter.get(control, 0) + 1
            sev = obs.severity.lower()
            if sev not in severity_counter:
                severity_counter[sev] = 0
            severity_counter[sev] += 1

        return {
            "created_at": self._created_at.isoformat() + "Z",
            "observation_count": len(self._observations),
            "mitre_heatmap": mitre_counter,
            "d3fend_recommendations": d3fend_counter,
            "severity_distribution": severity_counter,
            "tags": sorted(self._tags),
        }

    def export_summary(self) -> Dict[str, Any]:
        return {
            "meta": self.correlate(),
            "observations": [obs.to_dict() for obs in self._observations],
        }

    def generate_report(self, output_path: Path) -> Path:
        """
        Generate a PDF report if reportlab is available; otherwise fall back to Markdown.
        """
        try:
            from reportlab.lib.pagesizes import A4  # type: ignore
            from reportlab.lib.units import mm  # type: ignore
            from reportlab.pdfgen import canvas  # type: ignore

            output_path = output_path.with_suffix(".pdf")
            c = canvas.Canvas(str(output_path), pagesize=A4)
            width, height = A4

            y = height - 20 * mm
            c.setFont("Helvetica-Bold", 14)
            c.drawString(20 * mm, y, "ThreatInquisitor Fusion Workspace")
            y -= 10 * mm
            c.setFont("Helvetica", 10)
            meta = self.correlate()
            c.drawString(20 * mm, y, f"Создано: {meta['created_at']}")
            y -= 7 * mm
            c.drawString(20 * mm, y, f"Всего наблюдений: {meta['observation_count']}")
            y -= 7 * mm
            c.drawString(20 * mm, y, f"Метки: {', '.join(meta['tags']) or 'нет'}")
            y -= 10 * mm

            for obs in self._observations:
                if y < 40 * mm:
                    c.showPage()
                    y = height - 20 * mm
                    c.setFont("Helvetica", 10)
                c.setFont("Helvetica-Bold", 11)
                c.drawString(20 * mm, y, f"[{obs.severity.upper()}] {obs.source}")
                y -= 6 * mm
                c.setFont("Helvetica", 10)
                c.drawString(22 * mm, y, obs.summary)
                y -= 5 * mm
                c.drawString(22 * mm, y, f"MITRE: {', '.join(obs.mitre_techniques) or 'n/a'}")
                y -= 5 * mm
                c.drawString(22 * mm, y, f"D3FEND: {', '.join(obs.d3fend_controls) or 'n/a'}")
                y -= 6 * mm

            c.save()
            logger.info("PDF отчет сохранен: %s", output_path)
            return output_path
        except ImportError:
            logger.warning("reportlab недоступен, создаю Markdown отчет")
            return self._generate_markdown_report(output_path)

    def _generate_markdown_report(self, output_path: Path) -> Path:
        output_path = output_path.with_suffix(".md")
        summary = self.export_summary()
        lines: List[str] = [
            "# ThreatInquisitor Fusion Workspace",
            f"*Создано:* {summary['meta']['created_at']}",
            f"*Наблюдений:* {summary['meta']['observation_count']}",
            "",
            "## Сводка MITRE ATT&CK",
            json.dumps(summary["meta"]["mitre_heatmap"], indent=2, ensure_ascii=False),
            "",
            "## Рекомендации MITRE D3FEND",
            json.dumps(summary["meta"]["d3fend_recommendations"], indent=2, ensure_ascii=False),
            "",
            "## Наблюдения",
        ]
        for obs in summary["observations"]:
            lines.append(f"- **{obs['source']}** ({obs['severity']}) — {obs['summary']}")
            lines.append(f"  - MITRE: {', '.join(obs['mitre_techniques']) or 'n/a'}")
            lines.append(f"  - D3FEND: {', '.join(obs['d3fend_controls']) or 'n/a'}")
            if obs["artifacts"]:
                lines.append(f"  - Артефакты: {', '.join(obs['artifacts'])}")
            if obs["extra"]:
                lines.append(f"  - Дополнительно: {json.dumps(obs['extra'], ensure_ascii=False)}")
        output_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown отчет сохранен: %s", output_path)
        return output_path

    def _map_to_d3fend(self, mitre_techniques: List[str]) -> List[str]:
        return map_mitre_to_d3fend_controls(mitre_techniques)
