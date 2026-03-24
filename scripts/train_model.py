#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Training pipeline for ThreatInquisitor's malware probability model.

The script prefers labelled static/dynamic telemetry (JSON/CSV) when available
and only falls back to synthetic heuristics when no dataset can be located.
The resulting scikit-learn model (together with its scaler and training
metadata) is stored under `models/malware_model.pkl` and can be loaded
automatically by the scoring engine.
"""

from __future__ import annotations

import json
import pickle
import random
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

from analyzer.ml_detector import MalwareMLDetector

RANDOM_SEED = 4242
DEFAULT_SAMPLE_COUNT = 4000
MODEL_PATH = Path("models/malware_model.pkl")
METRICS_PATH = Path("models/malware_model_metrics.json")
DEFAULT_DATASET_CANDIDATES = [
    Path("datasets/labeled_samples.json"),
    Path("datasets/labeled_samples.jsonl"),
    Path("datasets/labeled_samples.ndjson"),
    Path("datasets/labeled_samples.csv"),
]
MIN_LABELLED_SAMPLES = 200


@dataclass
class SampleBundle:
    static: Dict[str, object]
    dynamic: Dict[str, object]
    iocs: List[Dict[str, object]]


def _normalise_label(value: object) -> Optional[int]:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        if value >= 1:
            return 1
        if value <= 0:
            return 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "malicious", "malware", "bad", "evil", "true", "yes", "positive"}:
            return 1
        if text in {"0", "benign", "clean", "good", "false", "no", "negative"}:
            return 0
    return None


def _load_json_records(path: Path) -> List[Dict[str, object]]:
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        records: List[Dict[str, object]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
        return records

    parsed = json.loads(content)
    if isinstance(parsed, dict) and "records" in parsed:
        parsed = parsed["records"]
    if not isinstance(parsed, list):
        raise ValueError(f"Unsupported JSON dataset format in {path}")
    return parsed  # type: ignore[return-value]


def _load_csv_records(path: Path) -> List[Dict[str, object]]:
    import csv

    records: List[Dict[str, object]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            record: Dict[str, object] = dict(row)
            records.append(record)
    return records


def _coerce_json(data: object, base_dir: Path) -> Optional[Dict[str, object]]:
    if isinstance(data, dict):
        return data
    if isinstance(data, str):
        text = data.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            candidate = Path(text)
            if not candidate.is_absolute():
                candidate = (base_dir / candidate).resolve()
            if candidate.exists():
                return json.loads(candidate.read_text(encoding="utf-8"))
    return None


def load_labelled_dataset(
    detector: MalwareMLDetector,
    dataset_path: Path,
) -> Tuple[np.ndarray, np.ndarray, Dict[str, int]]:
    dataset_path = dataset_path.resolve()
    if dataset_path.suffix.lower() in {".json", ".jsonl", ".ndjson"}:
        raw_records = _load_json_records(dataset_path)
    elif dataset_path.suffix.lower() == ".csv":
        raw_records = _load_csv_records(dataset_path)
    else:
        raise ValueError(f"Unsupported dataset format: {dataset_path.suffix}")

    features: List[List[float]] = []
    labels: List[int] = []
    stats = {"total": len(raw_records), "skipped": 0}
    base_dir = dataset_path.parent

    for record in raw_records:
        if not isinstance(record, dict):
            stats["skipped"] += 1
            continue

        label = _normalise_label(
            record.get("label")
            or record.get("target")
            or record.get("class")
            or record.get("malicious")
        )
        if label is None:
            stats["skipped"] += 1
            continue

        static_data = record.get("static") or record.get("static_data") or record.get("static_json")
        dynamic_data = record.get("dynamic") or record.get("dynamic_data") or record.get("dynamic_json")
        ioc_data = record.get("iocs") or record.get("ioc_data") or record.get("indicators")

        static_dict = _coerce_json(static_data, base_dir)
        dynamic_dict = _coerce_json(dynamic_data, base_dir) or {}
        if not isinstance(static_dict, dict):
            stats["skipped"] += 1
            continue
        if not isinstance(dynamic_dict, dict):
            dynamic_dict = {}
        if isinstance(ioc_data, str):
            ioc_dict = _coerce_json(ioc_data, base_dir)
            ioc_list = ioc_dict if isinstance(ioc_dict, list) else []
        elif isinstance(ioc_data, list):
            ioc_list = ioc_data  # type: ignore[assignment]
        else:
            ioc_list = []

        try:
            vector = detector.extract_features(static_dict, dynamic_dict, ioc_list)  # type: ignore[arg-type]
        except Exception:
            stats["skipped"] += 1
            continue

        features.append(vector)
        labels.append(label)

    return np.asarray(features, dtype=np.float32), np.asarray(labels, dtype=np.int64), stats


def discover_dataset_path(explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        candidate = Path(explicit).expanduser()
        if not candidate.is_absolute():
            candidate = (ROOT_DIR / candidate).resolve()
        if not candidate.exists():
            raise FileNotFoundError(f"Dataset path does not exist: {candidate}")
        return candidate

    for candidate in DEFAULT_DATASET_CANDIDATES:
        resolved = (ROOT_DIR / candidate).resolve()
        if resolved.exists():
            return resolved
    return None


def _random_entropy(malicious: bool) -> float:
    if malicious:
        return random.uniform(6.7, 7.9)
    return random.uniform(3.4, 6.2)


def _random_section_name() -> str:
    base = random.choice([".text", ".data", ".rdata", ".pdata", ".rsrc"])
    if random.random() < 0.2:
        return base + random.choice(["", "_sec", "1", "2"])
    return base


def _generate_static_profile(malicious: bool) -> Dict[str, object]:
    section_count = random.randint(4, 8)
    sections = []
    for _ in range(section_count):
        name = _random_section_name()
        sections.append({name: {"entropy": _random_entropy(malicious)}})

    suspicious_strings = [
        "http://c2-malware.com/path",
        "powershell -enc ...",
        "cmd.exe /c net user",
        "socket://evil",
        "ftp://dropzone",
    ]
    benign_strings = [
        "printf",
        "user32.dll",
        "document.ready",
        "updateChecker",
        "https://help.microsoft.com",
    ]

    imports: List[str] = []
    if malicious:
        imports.extend(
            random.sample(MalwareMLDetector.SUSPICIOUS_APIS, k=random.randint(2, 4))
        )
        imports.extend(random.sample(benign_strings, k=random.randint(1, 2)))
    else:
        imports.extend(random.sample(benign_strings, k=random.randint(2, 4)))
        if random.random() < 0.05:
            imports.append(random.choice(MalwareMLDetector.SUSPICIOUS_APIS))

    strings = random.sample(
        suspicious_strings if malicious else benign_strings,
        k=min(5, len(suspicious_strings if malicious else benign_strings)),
    )
    if not malicious and random.random() < 0.3:
        strings += ["Version 1.0.0", "License Agreement"]

    entropy_score = (
        sum(section[list(section.keys())[0]]["entropy"] for section in sections) / section_count
    )
    if malicious:
        entropy_score += random.uniform(0.1, 0.4)
    else:
        entropy_score -= random.uniform(0.1, 0.5)
    entropy_score = max(0.0, min(entropy_score, 8.0))

    static_data: Dict[str, object] = {
        "file_size": random.uniform(
            400_000 if malicious else 50_000,
            12_000_000 if malicious else 4_000_000,
        ),
        "is_packed": malicious and random.random() < 0.6,
        "analysis": {
            "sections": sections,
            "imports": imports,
            "strings": strings,
            "enhanced_checks": {"entropy_score": entropy_score},
        },
    }
    return static_data


def _generate_dynamic_profile(malicious: bool) -> Dict[str, object]:
    call_volume = random.randint(70, 220) if malicious else random.randint(5, 60)
    api_calls: List[Dict[str, object]] = []
    suspicious_apis = list(MalwareMLDetector.SUSPICIOUS_APIS)
    benign_apis = [
        "ReadFile",
        "WriteFile",
        "CreateFileW",
        "RegOpenKeyExW",
        "GetModuleHandleW",
        "Sleep",
        "GetVersionEx",
    ]
    for _ in range(call_volume):
        if malicious and random.random() < 0.35:
            api_name = random.choice(suspicious_apis)
        else:
            api_name = random.choice(benign_apis)
        api_calls.append({"api": api_name})

    if malicious:
        api_calls.extend({"api": "CreateProcessInternalW"} for _ in range(random.randint(2, 6)))
        api_calls.extend({"api": "NtWriteVirtualMemory"} for _ in range(random.randint(1, 4)))

    network: List[Dict[str, object]] = []
    if malicious:
        for _ in range(random.randint(1, 4)):
            network.append(
                {
                    "remote_ip": f"185.220.{random.randint(0, 255)}.{random.randint(1, 254)}",
                    "remote_port": random.choice([4444, 5555, 6667, 8080, 8443]),
                }
            )
    else:
        for _ in range(random.randint(0, 2)):
            network.append(
                {
                    "remote_ip": f"104.244.{random.randint(0, 255)}.{random.randint(1, 254)}",
                    "remote_port": random.choice([80, 443, 22, 53]),
                }
            )

    return {"api_calls": api_calls, "network": network}


def _generate_iocs(malicious: bool) -> List[Dict[str, object]]:
    if not malicious:
        return []
    count = random.randint(2, 6)
    types = ["ip", "domain", "url", "registry", "hash_md5"]
    iocs: List[Dict[str, object]] = []
    for _ in range(count):
        iocs.append(
            {
                "type": random.choice(types),
                "value": f"indicator-{random.randint(1000, 9999)}",
            }
        )
    return iocs


def generate_sample(malicious: bool) -> SampleBundle:
    return SampleBundle(
        static=_generate_static_profile(malicious),
        dynamic=_generate_dynamic_profile(malicious),
        iocs=_generate_iocs(malicious),
    )


def maybe_attach_real_sample(detector: MalwareMLDetector) -> Tuple[List[List[float]], List[int]]:
    """Augment dataset with the bundled analysis JSON (if available)."""
    static_path = Path("static_analysis.json")
    dynamic_path = Path("dynamic_analysis.json")
    if not static_path.exists() or not dynamic_path.exists():
        return [], []
    try:
        static_data = json.loads(static_path.read_text(encoding="utf-8"))
        dynamic_data = json.loads(dynamic_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return [], []

    analysis = static_data.get("analysis")
    if isinstance(analysis, dict):
        sections = analysis.get("sections")
        if isinstance(sections, list):
            converted_sections = []
            for section in sections:
                if isinstance(section, dict):
                    name = section.get("name")
                    entropy = section.get("entropy")
                    if name:
                        converted_sections.append({name: {"entropy": entropy or 0}})
            if converted_sections:
                analysis["sections"] = converted_sections

        imports = analysis.get("imports")
        if isinstance(imports, list):
            converted_imports = []
            for entry in imports:
                if isinstance(entry, dict):
                    dll = entry.get("dll") or ""
                    name = entry.get("name") or ""
                    if dll or name:
                        converted_imports.append(f"{dll}!{name}".strip("!"))
                else:
                    converted_imports.append(str(entry))
            if converted_imports:
                analysis["imports"] = converted_imports

    features = detector.extract_features(static_data, dynamic_data, ioc_data=[])
    return [features], [1]


def generate_synthetic_vectors(
    detector: MalwareMLDetector, count: int, *, malicious: Optional[bool] = None
) -> Tuple[List[List[float]], List[int]]:
    vectors: List[List[float]] = []
    labels: List[int] = []
    for idx in range(max(0, count)):
        label_bool = bool(malicious) if malicious is not None else (idx % 2 == 0)
        bundle = generate_sample(malicious=label_bool)
        vectors.append(detector.extract_features(bundle.static, bundle.dynamic, bundle.iocs))
        labels.append(1 if label_bool else 0)
    return vectors, labels


def build_synthetic_dataset(detector: MalwareMLDetector, sample_count: int) -> Tuple[np.ndarray, np.ndarray]:
    feature_rows, labels = generate_synthetic_vectors(detector, sample_count)
    real_features, real_labels = maybe_attach_real_sample(detector)
    feature_rows.extend(real_features)
    labels.extend(real_labels)
    return np.asarray(feature_rows, dtype=np.float32), np.asarray(labels, dtype=np.int64)


def train_model(
    sample_count: int = DEFAULT_SAMPLE_COUNT,
    dataset_path: Optional[str] = None,
) -> Dict[str, object]:
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    detector = MalwareMLDetector()
    resolved_dataset = discover_dataset_path(dataset_path)

    synthetic_added = 0
    labelled_used = 0
    dataset_stats: Optional[Dict[str, int]] = None
    data_source = "synthetic_only"

    X: Optional[np.ndarray] = None
    y: Optional[np.ndarray] = None

    if resolved_dataset:
        X_labelled, y_labelled, stats = load_labelled_dataset(detector, resolved_dataset)
        dataset_stats = stats
        labelled_used = int(y_labelled.shape[0])
        if labelled_used >= 1:
            X = X_labelled
            y = y_labelled
            data_source = f"labelled:{resolved_dataset.name}"

            if labelled_used < MIN_LABELLED_SAMPLES:
                top_up = MIN_LABELLED_SAMPLES - labelled_used
                vectors_extra, labels_extra = generate_synthetic_vectors(detector, top_up)
                if vectors_extra:
                    X = np.concatenate((X, np.asarray(vectors_extra, dtype=np.float32)), axis=0)
                    y = np.concatenate((y, np.asarray(labels_extra, dtype=np.int64)), axis=0)
                    synthetic_added += len(labels_extra)
                    data_source += f"+synthetic_topup({len(labels_extra)})"
        else:
            X = None
            y = None

    if X is None or y is None:
        X, y = build_synthetic_dataset(detector, sample_count)
        synthetic_added = int(y.shape[0])
        data_source = "synthetic_only"

    missing_classes = {0, 1} - set(int(v) for v in np.unique(y))
    if missing_classes:
        supplement_count = max(50, int(0.1 * y.shape[0]))
        vectors_extra: List[List[float]] = []
        labels_extra: List[int] = []
        for cls in missing_classes:
            v, l = generate_synthetic_vectors(detector, supplement_count, malicious=bool(cls))
            vectors_extra.extend(v)
            labels_extra.extend(l)
        if vectors_extra:
            X = np.concatenate((X, np.asarray(vectors_extra, dtype=np.float32)), axis=0)
            y = np.concatenate((y, np.asarray(labels_extra, dtype=np.int64)), axis=0)
            synthetic_added += len(labels_extra)
            data_source += "+synthetic_balance"

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_SEED
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        solver="lbfgs",
    )
    clf.fit(X_train_scaled, y_train)

    probas = clf.predict_proba(X_test_scaled)[:, 1]
    preds = (probas >= 0.5).astype(int)

    report = classification_report(y_test, preds, output_dict=True)
    auc = roc_auc_score(y_test, probas)
    matrix = confusion_matrix(y_test, preds).tolist()

    metadata = {
        "trained_at": datetime.utcnow().isoformat() + "Z",
        "sample_count": int(X.shape[0]),
        "train_size": int(X_train.shape[0]),
        "test_size": int(X_test.shape[0]),
        "random_seed": RANDOM_SEED,
        "auc": float(auc),
        "classification_report": report,
        "confusion_matrix": matrix,
        "feature_vector_length": int(detector.FEATURE_VECTOR_SIZE),
        "model_class": clf.__class__.__name__,
        "scaler_class": scaler.__class__.__name__,
        "data_source": data_source,
        "labelled_samples_used": labelled_used,
        "synthetic_samples_added": synthetic_added,
    }
    if dataset_stats:
        metadata["dataset_records_total"] = dataset_stats.get("total", 0)
        metadata["dataset_records_skipped"] = dataset_stats.get("skipped", 0)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with MODEL_PATH.open("wb") as handle:
        pickle.dump({"model": clf, "scaler": scaler, "metadata": metadata}, handle)

    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with METRICS_PATH.open("w", encoding="utf-8") as metrics_file:
        json.dump(metadata, metrics_file, indent=2, ensure_ascii=False)

    return metadata


def cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Train ThreatInquisitor ML malware detector.")
    parser.add_argument(
        "--dataset",
        help="Path to labelled telemetry dataset (JSON/JSONL/CSV). Defaults to the first file found in ./datasets/.",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=DEFAULT_SAMPLE_COUNT,
        help=f"Fallback synthetic sample count when no dataset is available (default: {DEFAULT_SAMPLE_COUNT}).",
    )
    args = parser.parse_args()

    metadata = train_model(sample_count=max(200, args.samples), dataset_path=args.dataset)

    print("Model trained successfully!")
    print(f"Stored at: {MODEL_PATH.resolve()}")
    print(f"AUC: {metadata['auc']:.3f}")
    print("Confusion matrix [tn, fp; fn, tp]:", metadata["confusion_matrix"])
    precision = metadata["classification_report"]["1"]["precision"]
    recall = metadata["classification_report"]["1"]["recall"]
    f1 = metadata["classification_report"]["1"]["f1-score"]
    print(f"Malicious precision={precision:.3f}, recall={recall:.3f}, f1={f1:.3f}")


if __name__ == "__main__":
    cli()
