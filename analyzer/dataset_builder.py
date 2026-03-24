#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dataset builder for ThreatInquisitor ML experiments.

Features:
    * Fetch metadata and samples from MalwareBazaar.
    * Optional integration hooks for VirusShare (manual API key support).
    * Feature extraction using existing analysis pipelines.
    * Balanced dataset generation ready for ML training.
"""

from __future__ import annotations

import csv
import logging
import os
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from zipfile import ZipFile

import requests

from analyzer.behavioral_analysis import analyze_behavior
from analyzer.dynamic_analysis import dynamic_analysis
from analyzer.ioc_extractor import extract_iocs
from analyzer.static_analysis import static_analysis
from analyzer.scoring import calculate_risk
from core.config import config_manager

logger = logging.getLogger("dataset_builder")
logging.basicConfig(level=logging.INFO)

MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
DEMO_MALWARE_SAMPLES: List[Dict[str, Optional[str]]] = [
    {
        "sha256": "demo0000000000000000000000000000000000000000000000000000000000001",
        "file_name": "demo_ransomware.exe",
        "file_type": "pe",
        "signature": "DemoRansom",
        "first_seen": "2024-01-02",
        "malware_family": "DemoLocker",
    },
    {
        "sha256": "demo0000000000000000000000000000000000000000000000000000000000002",
        "file_name": "demo_loader.dll",
        "file_type": "pe",
        "signature": "DemoLoader",
        "first_seen": "2024-01-05",
        "malware_family": "DemoDropper",
    },
    {
        "sha256": "demo0000000000000000000000000000000000000000000000000000000000003",
        "file_name": "demo_macro.docm",
        "file_type": "ole_doc",
        "signature": "DemoMacro",
        "first_seen": "2024-01-08",
        "malware_family": "DemoPhish",
    },
]


@dataclass
class SampleMetadata:
    sha256: str
    file_name: str
    file_type: str
    signature: Optional[str]
    first_seen: Optional[str]
    malware_family: Optional[str]


class DatasetBuilder:
    """Utility class for constructing ML-ready datasets."""

    def __init__(
        self,
        *,
        work_dir: Optional[str] = None,
        malwarebazaar_api_key: Optional[str] = None,
        virusshare_api_key: Optional[str] = None,
    ) -> None:
        self.work_dir = Path(work_dir or config_manager.get("DATASET_WORK_DIR", "./dataset_work"))
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.malwarebazaar_api_key = malwarebazaar_api_key or config_manager.get("MALWAREBAZAAR_API_KEY", "")
        self.virusshare_api_key = virusshare_api_key or config_manager.get("VIRUSSHARE_API_KEY", "")

    # ------------------------------------------------------------------ #
    # MalwareBazaar integration                                          #
    # ------------------------------------------------------------------ #
    def fetch_malwarebazaar_samples(
        self,
        query: str = "tag:exe",
        limit: int = 25,
    ) -> List[SampleMetadata]:
        """
        Fetch metadata for MalwareBazaar samples matching a query.
        """
        payload = {"query": "get_taginfo", "tag": query, "limit": limit}
        if not self.malwarebazaar_api_key:
            return self._load_demo_samples(limit)

        headers = {"API-KEY": self.malwarebazaar_api_key}

        logger.info("Fetching MalwareBazaar samples for query=%s (limit=%d)", query, limit)
        try:
            response = requests.post(MALWAREBAZAAR_API, data=payload, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status in (401, 403):
                logger.warning(
                    "MalwareBazaar returned %s. Falling back to demo dataset.", status
                )
                return self._load_demo_samples(limit)
            raise
        except requests.RequestException as exc:  # pragma: no cover - network dependent
            logger.error("Failed to reach MalwareBazaar API: %s", exc)
            return self._load_demo_samples(limit)

        result: List[SampleMetadata] = []
        for entry in data.get("data", []):
            result.append(
                SampleMetadata(
                    sha256=entry.get("sha256"),
                    file_name=entry.get("file_name"),
                    file_type=entry.get("file_type"),
                    signature=entry.get("signature"),
                    first_seen=entry.get("first_seen"),
                    malware_family=entry.get("malware_family"),
                )
            )
        logger.info("MalwareBazaar returned %d records", len(result))
        return result

    def download_malwarebazaar_sample(self, sha256: str, destination: Path) -> Path:
        """
        Download a MalwareBazaar sample archive and extract it to destination.
        """
        payload = {"query": "get_file", "sha256_hash": sha256}
        if not self.malwarebazaar_api_key:
            return self._create_demo_sample_file(sha256, destination)

        headers = {"API-KEY": self.malwarebazaar_api_key}

        logger.info("Downloading MalwareBazaar sample %s", sha256)
        try:
            response = requests.post(MALWAREBAZAAR_API, data=payload, headers=headers, timeout=60)
            response.raise_for_status()
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status in (401, 403):
                logger.warning(
                    "MalwareBazaar download rejected with %s. Returning demo payload.", status
                )
                return self._create_demo_sample_file(sha256, destination)
            raise
        except requests.RequestException as exc:  # pragma: no cover - network dependent
            logger.error("MalwareBazaar request failed: %s", exc)
            return self._create_demo_sample_file(sha256, destination)

        archive_path = destination / f"{sha256}.zip"
        archive_path.write_bytes(response.content)

        password = "infected"
        extracted_path = destination / sha256
        extracted_path.mkdir(parents=True, exist_ok=True)

        try:
            with ZipFile(archive_path) as zf:
                zf.extractall(path=extracted_path, pwd=password.encode("utf-8"))
        finally:
            archive_path.unlink(missing_ok=True)

        members = list(extracted_path.glob("**/*"))
        for item in members:
            if item.is_file():
                return item

        raise FileNotFoundError(f"Sample archive for {sha256} did not contain a file")

    def _load_demo_samples(self, limit: int) -> List[SampleMetadata]:
        """Return a deterministic offline dataset when the API cannot be used."""
        logger.info("Using MalwareBazaar demo dataset (limit=%s)", limit)
        try:
            limit_int = int(limit)
        except (TypeError, ValueError):
            limit_int = len(DEMO_MALWARE_SAMPLES)

        selected = DEMO_MALWARE_SAMPLES[:limit_int] if limit_int > 0 else DEMO_MALWARE_SAMPLES
        return [
            SampleMetadata(
                sha256=item.get("sha256", ""),
                file_name=item.get("file_name", ""),
                file_type=item.get("file_type", "unknown"),
                signature=item.get("signature"),
                first_seen=item.get("first_seen"),
                malware_family=item.get("malware_family"),
            )
            for item in selected
        ]

    def _create_demo_sample_file(self, sha256: str, destination: Path) -> Path:
        """Create a placeholder sample file for offline/demo usage."""
        logger.info("Creating demo sample for %s (offline mode)", sha256)
        demo_dir = destination / sha256
        demo_dir.mkdir(parents=True, exist_ok=True)
        sample_path = demo_dir / f"{sha256[:12]}_demo.bin"
        demo_content = (
            f"Demo sample placeholder for {sha256}. "
            "Replace with real malware sample when API access is available.\n"
        )
        sample_path.write_text(demo_content, encoding="utf-8")
        return sample_path

    # ------------------------------------------------------------------ #
    # Feature extraction                                                 #
    # ------------------------------------------------------------------ #
    def extract_features(
        self,
        file_path: os.PathLike[str] | str,
        *,
        run_dynamic: bool = False,
        dynamic_timeout: int = 10,
    ) -> Dict[str, Any]:
        """
        Build a feature dictionary for an individual sample.
        """
        file_path = Path(file_path)
        logger.info("Extracting features from %s", file_path)

        static_data = static_analysis(str(file_path))
        dynamic_data: Dict[str, Any] = {}
        if run_dynamic:
            dynamic_data = dynamic_analysis(str(file_path), timeout=dynamic_timeout)

        iocs = extract_iocs(static_data, dynamic_data)
        behavioral = analyze_behavior(dynamic_data.get("api_calls", []))
        risk = calculate_risk(
            static_data=static_data,
            dynamic_data=dynamic_data,
            ioc_data=iocs,
            behavioral_patterns=behavioral,
        )

        features = {
            "sha256": static_data.get("hashes", {}).get("sha256") if isinstance(static_data, dict) else "",
            "file_path": str(file_path),
            "label": "unknown",
            "static_features": static_data,
            "ioc_count": len(iocs),
            "behavioral_patterns": behavioral,
            "risk_score": risk.get("score"),
            "risk_level": risk.get("level"),
            "ml_probability": risk.get("ml_probability"),
        }
        return features

    # ------------------------------------------------------------------ #
    # Dataset orchestration                                              #
    # ------------------------------------------------------------------ #
    def build_dataset(
        self,
        malware_files: Iterable[Path],
        benign_files: Iterable[Path],
        *,
        run_dynamic: bool = False,
        output_csv: Optional[os.PathLike[str] | str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Build a balanced dataset from supplied malware and benign files.
        """
        malware_files = list(malware_files)
        benign_files = list(benign_files)
        balance = min(len(malware_files), len(benign_files))
        malware_files = malware_files[:balance]
        benign_files = benign_files[:balance]

        dataset: List[Dict[str, Any]] = []

        for label, files in (("malicious", malware_files), ("benign", benign_files)):
            for file_path in files:
                try:
                    features = self.extract_features(file_path, run_dynamic=run_dynamic)
                    features["label"] = label
                    dataset.append(features)
                except Exception as exc:
                    logger.error("Failed to extract features from %s: %s", file_path, exc)

        if output_csv:
            output_csv = Path(output_csv)
            output_csv.parent.mkdir(parents=True, exist_ok=True)
            with output_csv.open("w", encoding="utf-8", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["file_path", "label", "risk_score", "risk_level", "ioc_count", "ml_probability"])
                for record in dataset:
                    writer.writerow(
                        [
                            record.get("file_path"),
                            record.get("label"),
                            record.get("risk_score"),
                            record.get("risk_level"),
                            record.get("ioc_count"),
                            record.get("ml_probability"),
                        ]
                    )
            logger.info("Dataset CSV saved to %s", output_csv)

        return dataset


def _load_file_list(path: str) -> List[Path]:
    root = Path(path)
    if root.is_file():
        return [root]
    return [item for item in root.glob("**/*") if item.is_file()]


def cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="ThreatInquisitor dataset builder")
    parser.add_argument("--malware-dir", help="Directory with malware samples", required=True)
    parser.add_argument("--benign-dir", help="Directory with benign samples", required=True)
    parser.add_argument("--output", help="Path to dataset CSV", default="dataset.csv")
    parser.add_argument("--dynamic", action="store_true", help="Enable dynamic analysis (slower)")
    args = parser.parse_args()

    builder = DatasetBuilder()

    malware_files = _load_file_list(args.malware_dir)
    benign_files = _load_file_list(args.benign_dir)

    logger.info("Building dataset (malicious=%d, benign=%d)", len(malware_files), len(benign_files))
    builder.build_dataset(
        malware_files,
        benign_files,
        run_dynamic=args.dynamic,
        output_csv=args.output,
    )


if __name__ == "__main__":  # pragma: no cover
    cli()
