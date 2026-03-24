#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Periodic retraining helper for the ThreatInquisitor ML detector.

This script wraps `scripts.train_model` so that it can be invoked by the host
task scheduler (cron, Windows Task Scheduler, systemd timers, etc.). Each run:
    * trains the model using labelled telemetry when available,
    * copies the freshly generated artifacts into a timestamped archive, and
    * enforces a rolling retention window so disk usage stays bounded.

Example (Windows Task Scheduler):
    schtasks /Create /SC DAILY /TN "ThreatInquisitor ML Retrain" ^
        /TR "python C:\\path\\to\\repo\\scripts\\scheduled_retrain.py --dataset C:\\telemetry\\labeled.json" ^
        /ST 02:30
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scripts.train_model import (  # noqa: E402
    METRICS_PATH,
    MODEL_PATH,
    discover_dataset_path,
    train_model,
)

VERSIONS_DIR = ROOT_DIR / "models" / "versions"
LATEST_METADATA_PATH = ROOT_DIR / "models" / "malware_model_latest.json"


def _normalise_timestamp(iso_timestamp: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    except ValueError:
        dt = datetime.utcnow()
    return dt.strftime("%Y%m%dT%H%M%SZ")


def _archive_artifacts(version_tag: str) -> tuple[Path, Path]:
    VERSIONS_DIR.mkdir(parents=True, exist_ok=True)
    model_dest = VERSIONS_DIR / f"malware_model_{version_tag}.pkl"
    metrics_dest = VERSIONS_DIR / f"malware_model_{version_tag}_metrics.json"
    shutil.copy2(MODEL_PATH, model_dest)
    shutil.copy2(METRICS_PATH, metrics_dest)
    return model_dest, metrics_dest


def _write_latest_metadata(metadata: dict, version_tag: str) -> None:
    metadata = dict(metadata)
    metadata["version"] = version_tag
    metadata["model_path"] = str(MODEL_PATH.resolve())
    metadata["metrics_path"] = str(METRICS_PATH.resolve())
    metadata["archived_model_path"] = str((VERSIONS_DIR / f"malware_model_{version_tag}.pkl").resolve())
    metadata["archived_metrics_path"] = str(
        (VERSIONS_DIR / f"malware_model_{version_tag}_metrics.json").resolve()
    )
    with METRICS_PATH.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2, ensure_ascii=False)
    with LATEST_METADATA_PATH.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2, ensure_ascii=False)


def _enforce_retention(retention: int) -> None:
    if retention <= 0:
        return
    archives = sorted(VERSIONS_DIR.glob("malware_model_*.pkl"), key=lambda p: p.stat().st_mtime, reverse=True)
    for stale in archives[retention:]:
        try:
            stale.unlink()
        except FileNotFoundError:
            pass
        metrics_candidate = stale.with_name(stale.name.replace(".pkl", "_metrics.json"))
        if metrics_candidate.exists():
            try:
                metrics_candidate.unlink()
            except FileNotFoundError:
                pass


def run_scheduled_retrain(
    *,
    dataset_path: Optional[str],
    samples: int,
    retention: int,
) -> dict:
    resolved_dataset = discover_dataset_path(dataset_path)
    metadata = train_model(sample_count=max(200, samples), dataset_path=str(resolved_dataset) if resolved_dataset else None)

    version_tag = _normalise_timestamp(metadata.get("trained_at", datetime.utcnow().isoformat() + "Z"))
    _archive_artifacts(version_tag)
    _write_latest_metadata(metadata, version_tag)
    _enforce_retention(retention)

    metadata["version"] = version_tag
    metadata["archived_versions_dir"] = str(VERSIONS_DIR.resolve())
    metadata["retention"] = retention
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Schedule-friendly ML retraining helper.")
    parser.add_argument(
        "--dataset",
        help="Path to labelled telemetry dataset. Defaults to the first recognised file in ./datasets/.",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=4000,
        help="Synthetic sample budget used when dataset is missing or needs top-up.",
    )
    parser.add_argument(
        "--retention",
        type=int,
        default=10,
        help="How many archived model versions to keep (default: 10). Set to 0 to keep everything.",
    )
    args = parser.parse_args()

    metadata = run_scheduled_retrain(
        dataset_path=args.dataset,
        samples=args.samples,
        retention=args.retention,
    )

    print("Retraining completed.")
    print(f"Version: {metadata['version']}")
    print(f"Data source: {metadata.get('data_source', 'unknown')}")
    print(f"Archived directory: {metadata['archived_versions_dir']}")
    print(f"Current retention: {metadata['retention']}")


if __name__ == "__main__":
    main()

