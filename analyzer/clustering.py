#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Behaviour-based malware clustering utilities.

The implementation relies on DBSCAN to group samples with similar dynamic
behaviour (API usage, network patterns, etc.). The feature extraction logic
is intentionally lightweight so that it can operate on the existing analysis
results produced by ThreatInquisitor.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np

try:
    from sklearn.cluster import DBSCAN
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import MultiLabelBinarizer, StandardScaler
except Exception as exc:  # pragma: no cover - optional dependency
    DBSCAN = None  # type: ignore
    StandardScaler = None  # type: ignore
    TfidfVectorizer = None  # type: ignore
    MultiLabelBinarizer = None  # type: ignore
    SKLEARN_IMPORT_ERROR = exc
else:
    SKLEARN_IMPORT_ERROR = None


SUSPICIOUS_APIS = {
    "createremotethread",
    "writeprocessmemory",
    "virtualallocex",
    "setthreadcontext",
    "queueuserapc",
    "ntcreatethreadex",
    "createremotethreadex",
    "mapviewoffile",
    "createtoolhelp32snapshot",
    "process32first",
    "process32next",
    "loadlibrarya",
    "loadlibraryw",
    "getprocaddress",
    "regsetvalueexw",
    "regcreatekeyexw",
}


class MalwareClustering:
    """Cluster samples by behaviour and provide simple family identification."""

    def __init__(self, *, eps: float = 0.75, min_samples: int = 2) -> None:
        if (
            DBSCAN is None
            or StandardScaler is None
            or TfidfVectorizer is None
            or MultiLabelBinarizer is None
        ):
            raise RuntimeError(
                "scikit-learn is required for clustering "
                f"({SKLEARN_IMPORT_ERROR})"
            )
        self.eps = eps
        self.min_samples = min_samples

        self._scaler: Optional[StandardScaler] = None
        self._centroids: Dict[int, np.ndarray] = {}
        self._labels: List[int] = []
        self._samples_meta: List[Dict[str, Any]] = []
        self._feature_dim: int = 0
        self._feature_matrix: Optional[np.ndarray] = None
        self._quadrant_origin: Dict[str, float] = {"x": 0.0, "y": 0.0}
        self._family_quadrant_origin: Dict[str, float] = {"x": 0.0, "y": 0.0}

        self.api_vectorizer: Optional[TfidfVectorizer] = None
        self.ioc_binarizer: Optional[MultiLabelBinarizer] = None
        self.behavior_binarizer: Optional[MultiLabelBinarizer] = None
        self._family_profiles: Dict[str, Any] = {}
        self._family_scaler: Optional[StandardScaler] = None

    def cluster_by_behavior(
        self,
        samples: Iterable[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Cluster behaviour profiles using DBSCAN.

        Args:
            samples: iterable of analysis results. Each sample is expected to carry
                a subset of the following keys:
                - "id": unique identifier
                - "static": static analysis results
                - "dynamic": dynamic analysis results (API calls, network)
                - "risk": risk scoring outcome

        Returns:
            Dict with cluster labels, noise count, and centroid summaries.
        """
        matrix, meta, _families = self._prepare_dataset(
            samples,
            fit=True,
            require_family=False,
        )
        if matrix.size == 0:
            return {"labels": [], "clusters": {}, "noise": 0}

        self._scaler = StandardScaler()
        data = self._scaler.fit_transform(matrix)
        self._feature_matrix = data

        model = DBSCAN(eps=self.eps, min_samples=self.min_samples)
        self._labels = model.fit_predict(data).tolist()
        self._samples_meta = meta
        self._quadrant_origin = self._assign_behavioral_plane(self._samples_meta)

        self._centroids = self._compute_centroids(data, self._labels)

        cluster_mapping = defaultdict(list)
        for label, sample_meta in zip(self._labels, meta):
            cluster_mapping[label].append(sample_meta)

        summaries = self._summarize_clusters(cluster_mapping)

        clusters_payload: Dict[int, Dict[str, Any]] = {}
        for label, entries in cluster_mapping.items():
            if label == -1:
                continue
            clusters_payload[label] = {
                "size": len(entries),
                "sample_ids": [entry["id"] for entry in entries],
                "summary": summaries.get(label, {}),
                "samples": entries,
                "centroid": self._centroids.get(label).tolist() if label in self._centroids else None,
                "dominant_quadrant": summaries.get(label, {}).get("dominant_quadrant"),
            }

        summary = {
            "labels": self._labels,
            "clusters": clusters_payload,
            "noise": len(cluster_mapping.get(-1, [])),
            "noise_samples": [entry["id"] for entry in cluster_mapping.get(-1, [])],
        }
        return summary

    def identify_family(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """
        Approximate the family for a new sample by comparing it to existing centroids.
        """
        if self._scaler is None or self._feature_dim == 0 or self._feature_matrix is None or not self._samples_meta:
            raise RuntimeError("No clustering has been performed yet.")

        vector = self._transform_sample(sample)
        if vector is None or vector.shape[0] != self._feature_dim:
            return {"label": None, "similarity": None, "reason": "insufficient_features"}

        transformed = self._scaler.transform(vector.reshape(1, -1))[0]
        vector_norm = float(np.linalg.norm(transformed))
        if vector_norm == 0.0:
            return {"label": None, "similarity": None, "reason": "zero_vector"}
        sample_profile = self.describe_sample_projection(sample)

        if not self._centroids:
            return {
                "label": None,
                "similarity": None,
                "distance": None,
                "manhattan_distance": None,
                "nearest_samples": [item.get("id") for item in self.get_nearest_neighbors(sample, top_k=5)],
                "quadrant": sample_profile.get("quadrant"),
                "behavioral_plane": sample_profile,
                "reason": "no_clusters",
            }

        best_label: Optional[int] = None
        best_similarity: float = -1.0
        best_distance: float = math.inf
        best_manhattan: float = math.inf

        for label, centroid in self._centroids.items():
            centroid_norm = float(np.linalg.norm(centroid))
            if centroid_norm == 0.0:
                continue
            similarity = float(np.dot(transformed, centroid) / (vector_norm * centroid_norm))
            distance = float(np.linalg.norm(transformed - centroid))
            manhattan_distance = float(np.abs(transformed - centroid).sum())
            if similarity > best_similarity:
                best_similarity = similarity
                best_distance = distance
                best_manhattan = manhattan_distance
                best_label = label

        if best_label is None:
            return {"label": None, "similarity": None, "reason": "no_clusters"}

        nearest = [
            meta["id"]
            for lbl, meta in zip(self._labels, self._samples_meta)
            if lbl == best_label
        ][:10]

        return {
            "label": int(best_label),
            "similarity": best_similarity,
            "distance": best_distance,
            "manhattan_distance": best_manhattan,
            "nearest_samples": nearest,
            "quadrant": sample_profile.get("quadrant"),
            "behavioral_plane": sample_profile,
        }

    def build_family_profiles(
        self,
        samples: Iterable[Dict[str, Any]],
        *,
        family_key: str = "family",
    ) -> Dict[str, Any]:
        matrix, metadata, families = self._prepare_dataset(
            samples,
            fit=True,
            require_family=True,
            family_key=family_key,
        )
        if matrix.size == 0:
            self._family_profiles = {}
            self._family_scaler = None
            return {}

        self._family_scaler = StandardScaler()
        scaled = self._family_scaler.fit_transform(matrix)
        self._feature_dim = scaled.shape[1]

        family_vectors: Dict[str, List[np.ndarray]] = defaultdict(list)
        family_samples: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._family_quadrant_origin = self._assign_behavioral_plane(metadata)

        for family, vector, meta in zip(families, scaled, metadata):
            family_vectors[family].append(vector)
            family_samples[family].append(meta)

        profiles: Dict[str, Any] = {}
        for family, vectors in family_vectors.items():
            data = np.vstack(vectors)
            centroid = data.mean(axis=0)
            samples_meta = family_samples[family]
            profiles[family] = {
                "centroid": centroid.tolist(),
                "size": len(samples_meta),
                "samples": samples_meta,
                "summary": self._summarize_family(samples_meta),
                "plane_centroid": self._average_plane(samples_meta),
            }

        self._family_profiles = profiles
        return profiles

    def identify_family_from_profiles(
        self,
        sample: Dict[str, Any],
        profiles: Optional[Dict[str, Any]] = None,
        *,
        top_k: int = 3,
    ) -> Dict[str, Any]:
        profiles = profiles or getattr(self, "_family_profiles", None)
        if not profiles:
            return {"family": None, "candidates": [], "reason": "no_profiles"}
        if self._family_scaler is None:
            return {"family": None, "candidates": [], "reason": "family_scaler_not_available"}

        vector = self._transform_sample(sample)
        if vector is None or vector.shape[0] != self._feature_dim:
            return {"family": None, "candidates": [], "reason": "insufficient_features"}

        scaled = self._family_scaler.transform(vector.reshape(1, -1))[0]
        vec_norm = float(np.linalg.norm(scaled))
        if vec_norm == 0.0:
            return {"family": None, "candidates": [], "reason": "zero_vector"}
        sample_profile = self.describe_sample_projection(sample, use_family_origin=True)

        candidates: List[Dict[str, Any]] = []
        for family, profile in profiles.items():
            centroid = np.asarray(profile.get("centroid") or [], dtype=np.float32)
            if centroid.size != self._feature_dim:
                continue
            centroid_norm = float(np.linalg.norm(centroid))
            if centroid_norm == 0.0:
                continue
            similarity = float(np.dot(scaled, centroid) / (vec_norm * centroid_norm))
            distance = float(np.linalg.norm(scaled - centroid))
            manhattan_distance = float(np.abs(scaled - centroid).sum())
            candidates.append(
                {
                    "family": family,
                    "similarity": similarity,
                    "distance": distance,
                    "manhattan_distance": manhattan_distance,
                    "size": profile.get("size", 0),
                    "summary": profile.get("summary", {}),
                    "plane_centroid": profile.get("plane_centroid", {}),
                }
            )

        if not candidates:
            return {"family": None, "candidates": [], "reason": "no_candidates"}

        candidates.sort(key=lambda item: item["similarity"], reverse=True)
        best = candidates[0]
        return {
            "family": best["family"],
            "similarity": best["similarity"],
            "distance": best["distance"],
            "manhattan_distance": best["manhattan_distance"],
            "candidates": candidates[:max(1, top_k)],
            "quadrant": sample_profile.get("quadrant"),
            "behavioral_plane": sample_profile,
        }

    def cluster_samples(self, samples: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        """Backward-compatible alias for existing integrations."""
        return self.cluster_by_behavior(samples)

    def get_cluster_details(self) -> Dict[int, List[Dict[str, Any]]]:
        """Return raw sample metadata per cluster (requires prior clustering)."""
        clusters: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for label, meta in zip(self._labels, self._samples_meta):
            clusters[label].append(meta)
        return clusters

    def get_nearest_neighbors(self, sample: Dict[str, Any], *, top_k: int = 5) -> List[Dict[str, Any]]:
        """Return nearest neighbours using Manhattan distance in scaled feature space."""
        if self._feature_matrix is None or self._scaler is None or not self._samples_meta:
            raise RuntimeError("No clustering index is available yet.")

        vector = self._transform_sample(sample)
        if vector is None or vector.shape[0] != self._feature_dim:
            return []

        transformed = self._scaler.transform(vector.reshape(1, -1))[0]
        neighbours: List[Dict[str, Any]] = []
        for idx, stored_vector in enumerate(self._feature_matrix):
            meta = self._samples_meta[idx]
            neighbours.append(
                {
                    "id": meta.get("id"),
                    "family": meta.get("family"),
                    "quadrant": (meta.get("behavioral_plane") or {}).get("quadrant"),
                    "manhattan_distance": float(np.abs(stored_vector - transformed).sum()),
                    "euclidean_distance": float(np.linalg.norm(stored_vector - transformed)),
                    "risk_score": meta.get("risk_score", 0.0),
                    "ml_probability": meta.get("ml_probability", 0.0),
                }
            )
        neighbours.sort(key=lambda item: item["manhattan_distance"])
        return neighbours[: max(1, top_k)]

    def get_scaled_feature_vector(self, sample: Dict[str, Any]) -> Optional[List[float]]:
        """Return the scaled feature vector for a sample using the fitted clustering scaler."""
        if self._scaler is None:
            return None
        vector = self._transform_sample(sample)
        if vector is None or vector.shape[0] != self._feature_dim:
            return None
        transformed = self._scaler.transform(vector.reshape(1, -1))[0]
        return transformed.astype(float).tolist()

    def describe_sample_projection(
        self,
        sample: Dict[str, Any],
        *,
        use_family_origin: bool = False,
    ) -> Dict[str, Any]:
        """Project a sample onto the 2D behavioural plane and assign a quadrant."""
        components = self._extract_components(sample)
        profile = self._build_plane_profile(
            {
                "risk_score": components["risk_score"],
                "ml_probability": components["ml_probability"],
                "suspicious_ratio": components["suspicious_ratio"],
                "network_count": components["network_count"],
                "ioc_count": components["ioc_count"],
                "behavior_count": components["behavior_count"],
                "api_call_count": components["api_call_count"],
                "entropy": components["entropy"],
            },
            origin=self._family_quadrant_origin if use_family_origin else self._quadrant_origin,
        )
        return profile

    def export_similarity_profiles(self) -> List[Dict[str, Any]]:
        """Export fitted sample profiles so they can be persisted in an external store."""
        if self._feature_matrix is None:
            return []
        exported: List[Dict[str, Any]] = []
        for idx, meta in enumerate(self._samples_meta):
            plane = meta.get("behavioral_plane") or {}
            exported.append(
                {
                    "sample_id": str(meta.get("id")),
                    "family": meta.get("family"),
                    "cluster_label": self._labels[idx] if idx < len(self._labels) else None,
                    "quadrant": plane.get("quadrant"),
                    "axis_x": plane.get("x"),
                    "axis_y": plane.get("y"),
                    "risk_score": meta.get("risk_score", 0.0),
                    "ml_probability": meta.get("ml_probability", 0.0),
                    "suspicious_ratio": meta.get("suspicious_ratio", 0.0),
                    "network_count": meta.get("network_count", 0),
                    "feature_vector": self._feature_matrix[idx].astype(float).tolist(),
                    "metadata": meta,
                }
            )
        return exported

    def persist_similarity_profiles(self, store_path: Optional[str] = None) -> int:
        """Persist exported similarity profiles into the SQLite profile store."""
        from services.ml_profile_store import MLProfileStore

        profiles = self.export_similarity_profiles()
        if not profiles:
            return 0
        store = MLProfileStore(db_path=store_path)
        return store.upsert_profiles(profiles)

    def _prepare_dataset(
        self,
        samples: Iterable[Dict[str, Any]],
        *,
        fit: bool,
        require_family: bool,
        family_key: str = "family",
    ) -> Tuple[np.ndarray, List[Dict[str, Any]], List[str]]:
        api_docs: List[str] = []
        ioc_lists: List[List[str]] = []
        behavior_lists: List[List[str]] = []
        numeric_rows: List[List[float]] = []
        metadata: List[Dict[str, Any]] = []
        families: List[str] = []

        for idx, sample in enumerate(samples):
            components = self._extract_components(sample)
            numeric = components["numeric"]
            if not numeric:
                continue

            family_label = sample.get(family_key)
            if family_label is None:
                attributes = sample.get("attributes")
                if isinstance(attributes, dict):
                    family_label = attributes.get(family_key)
            if require_family and family_label is None:
                continue

            api_docs.append(components["api_doc"] or "<no_api>")
            ioc_lists.append(components["ioc_tokens"])
            behavior_lists.append(components["behavior_tokens"])
            numeric_rows.append(numeric)
            metadata.append(
                {
                    "id": sample.get("id", f"sample_{idx}"),
                    "attributes": sample.get("attributes", {}),
                    "family": family_label,
                    "api_tokens": components["api_tokens"][:50],
                    "ioc_tokens": components["ioc_tokens"][:50],
                    "behavior_tokens": components["behavior_tokens"][:50],
                    "risk_score": components["risk_score"],
                    "ml_probability": components["ml_probability"],
                    "suspicious_ratio": components["suspicious_ratio"],
                    "network_count": components["network_count"],
                    "ioc_count": components["ioc_count"],
                    "behavior_count": components["behavior_count"],
                    "api_call_count": components["api_call_count"],
                    "api_unique_count": components["api_unique_count"],
                    "entropy": components["entropy"],
                    "timestamp": sample.get("timestamp"),
                }
            )
            if require_family:
                families.append(str(family_label))

        if not metadata:
            return np.empty((0, 0), dtype=np.float32), [], []

        matrix = self._combine_features(
            api_docs,
            ioc_lists,
            behavior_lists,
            numeric_rows,
            fit=fit,
        )
        if fit and matrix.size:
            self._feature_dim = matrix.shape[1]
        return matrix, metadata, families

    def _extract_components(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        static = sample.get("static") or {}
        dynamic = sample.get("dynamic") or {}
        risk = sample.get("risk") or {}

        api_calls = dynamic.get("api_calls") or []
        api_tokens: List[str] = []
        suspicious_hits = 0
        if isinstance(api_calls, list):
            for call in api_calls:
                if isinstance(call, dict):
                    name = call.get("api") or call.get("function") or call.get("name")
                else:
                    name = call
                token = str(name or "").strip().lower()
                if not token:
                    continue
                api_tokens.append(token)
                if token in SUSPICIOUS_APIS:
                    suspicious_hits += 1
        if not api_tokens:
            api_tokens = ["<no_api>"]
        api_doc = " ".join(api_tokens)

        raw_iocs = sample.get("iocs")
        if not raw_iocs:
            raw_iocs = dynamic.get("iocs")
        ioc_tokens: List[str] = []
        if isinstance(raw_iocs, list):
            for entry in raw_iocs:
                if isinstance(entry, dict):
                    category = str(entry.get("type") or entry.get("category") or "").strip().lower()
                    value = str(entry.get("value") or entry.get("indicator") or entry.get("ioc") or "").strip().lower()
                    if category and value:
                        ioc_tokens.append(f"{category}:{value}")
                    elif value:
                        ioc_tokens.append(value)
                else:
                    token = str(entry or "").strip().lower()
                    if token:
                        ioc_tokens.append(token)
        if not ioc_tokens:
            network_entries = dynamic.get("network") or []
            if isinstance(network_entries, list):
                for entry in network_entries:
                    if isinstance(entry, dict):
                        host = entry.get("remote_ip") or entry.get("remote_host") or entry.get("domain")
                        if host:
                            ioc_tokens.append(f"network:{str(host).lower()}")
        ioc_tokens = sorted(set(ioc_tokens))

        behavior_entries = sample.get("behavioral_patterns") or dynamic.get("behavioral_patterns") or []
        behavior_tokens: List[str] = []
        if isinstance(behavior_entries, list):
            for entry in behavior_entries:
                if isinstance(entry, dict):
                    pattern = entry.get("pattern") or entry.get("name")
                else:
                    pattern = entry
                token = str(pattern or "").strip().lower()
                if token:
                    behavior_tokens.append(token)
        behavior_tokens = sorted(set(behavior_tokens))

        analysis = static.get("analysis") if isinstance(static.get("analysis"), dict) else {}
        enhanced = analysis.get("enhanced_checks") if isinstance(analysis, dict) else {}
        imports = analysis.get("imports")
        if isinstance(imports, dict):
            import_count = len(imports)
        elif isinstance(imports, list):
            import_count = len(imports)
        else:
            import_count = 0

        entropy = 0.0
        if isinstance(enhanced, dict) and enhanced.get("entropy_score") is not None:
            entropy = float(enhanced.get("entropy_score") or 0.0)
        elif isinstance(analysis, dict) and analysis.get("entropy") is not None:
            entropy = float(analysis.get("entropy") or 0.0)
        else:
            entropy = float(static.get("entropy") or 0.0)

        dns_queries = dynamic.get("dns_queries")
        if not isinstance(dns_queries, list):
            dns_queries = []
        file_ops = dynamic.get("file_operations")
        if not isinstance(file_ops, list):
            file_ops = []
        registry_ops = dynamic.get("registry_modifications") or dynamic.get("registry_operations")
        if not isinstance(registry_ops, list):
            registry_ops = []
        process_tree = dynamic.get("processes")
        if not isinstance(process_tree, list):
            process_tree = []
        network_entries = dynamic.get("network")
        if not isinstance(network_entries, list):
            network_entries = []

        numeric_features: List[float] = [
            float(len(api_calls) if isinstance(api_calls, list) else 0),
            float(len(set(api_tokens))),
            float(suspicious_hits / max(len(api_tokens), 1)),
            float(len(ioc_tokens)),
            float(len(behavior_tokens)),
            float(len(network_entries)),
            float(len(dns_queries)),
            float(len(file_ops)),
            float(len(registry_ops)),
            float(len(process_tree)),
            float(risk.get("score", 0) or 0),
            float(risk.get("ml_probability", 0) or 0),
            float(risk.get("confidence", 0) or 0),
            float(entropy),
            float(import_count),
        ]

        return {
            "api_doc": api_doc,
            "api_tokens": api_tokens,
            "ioc_tokens": ioc_tokens,
            "behavior_tokens": behavior_tokens,
            "numeric": numeric_features,
            "risk_score": float(risk.get("score", 0) or 0),
            "ml_probability": float(risk.get("ml_probability", 0) or 0),
            "suspicious_ratio": float(suspicious_hits / max(len(api_tokens), 1)),
            "network_count": len(network_entries),
            "ioc_count": len(ioc_tokens),
            "behavior_count": len(behavior_tokens),
            "api_call_count": len(api_calls) if isinstance(api_calls, list) else 0,
            "api_unique_count": len(set(api_tokens)),
            "entropy": entropy,
        }

    def _combine_features(
        self,
        api_docs: List[str],
        ioc_lists: List[List[str]],
        behavior_lists: List[List[str]],
        numeric_rows: List[List[float]],
        *,
        fit: bool,
    ) -> np.ndarray:
        blocks: List[np.ndarray] = []

        if fit:
            self.api_vectorizer = TfidfVectorizer(
                token_pattern=r"[^ ]+",
                lowercase=True,
                ngram_range=(1, 2),
                max_features=512,
            )
            api_matrix = self.api_vectorizer.fit_transform(api_docs).toarray().astype(np.float32)
        else:
            if self.api_vectorizer is None:
                api_matrix = np.zeros((len(api_docs), 0), dtype=np.float32)
            else:
                api_matrix = self.api_vectorizer.transform(api_docs).toarray().astype(np.float32)
        if api_matrix.size:
            blocks.append(api_matrix)

        if fit:
            self.ioc_binarizer = MultiLabelBinarizer(sparse_output=False)
            ioc_matrix = self.ioc_binarizer.fit_transform(ioc_lists).astype(np.float32)
        else:
            if self.ioc_binarizer is None:
                ioc_matrix = np.zeros((len(ioc_lists), 0), dtype=np.float32)
            else:
                known_iocs = set(self.ioc_binarizer.classes_.tolist())
                filtered_iocs = [[token for token in tokens if token in known_iocs] for tokens in ioc_lists]
                ioc_matrix = self.ioc_binarizer.transform(filtered_iocs).astype(np.float32)
        if ioc_matrix.size:
            blocks.append(ioc_matrix)

        if fit:
            self.behavior_binarizer = MultiLabelBinarizer(sparse_output=False)
            behavior_matrix = self.behavior_binarizer.fit_transform(behavior_lists).astype(np.float32)
        else:
            if self.behavior_binarizer is None:
                behavior_matrix = np.zeros((len(behavior_lists), 0), dtype=np.float32)
            else:
                known_behaviors = set(self.behavior_binarizer.classes_.tolist())
                filtered_behaviors = [
                    [token for token in tokens if token in known_behaviors]
                    for tokens in behavior_lists
                ]
                behavior_matrix = self.behavior_binarizer.transform(filtered_behaviors).astype(np.float32)
        if behavior_matrix.size:
            blocks.append(behavior_matrix)

        numeric_matrix = np.asarray(numeric_rows, dtype=np.float32)
        if numeric_matrix.size:
            blocks.append(numeric_matrix)

        if not blocks:
            return np.empty((len(api_docs), 0), dtype=np.float32)

        combined = np.hstack(blocks).astype(np.float32)
        if fit:
            self._feature_dim = combined.shape[1]
        return combined

    def _transform_sample(self, sample: Dict[str, Any]) -> Optional[np.ndarray]:
        if self._feature_dim == 0:
            return None

        components = self._extract_components(sample)
        numeric = components["numeric"]
        if not numeric:
            return None

        combined = self._combine_features(
            [components["api_doc"] or "<no_api>"],
            [components["ioc_tokens"]],
            [components["behavior_tokens"]],
            [numeric],
            fit=False,
        )
        if combined.size == 0:
            return None
        return combined[0]

    @staticmethod
    def _compute_centroids(data: np.ndarray, labels: List[int]) -> Dict[int, np.ndarray]:
        centroids: Dict[int, np.ndarray] = {}
        for label in set(labels):
            if label == -1:
                continue
            indices = [idx for idx, lbl in enumerate(labels) if lbl == label]
            if indices:
                centroids[label] = data[indices].mean(axis=0)
        return centroids

    @staticmethod
    def _summarize_tokens(entries: List[Dict[str, Any]], key: str, limit: int = 5) -> List[str]:
        counter: Dict[str, int] = defaultdict(int)
        for entry in entries:
            for token in entry.get(key) or []:
                counter[token] += 1
        if not counter:
            return []
        return [
            f"{token} ({count})"
            for token, count in sorted(counter.items(), key=lambda item: item[1], reverse=True)[:limit]
        ]

    def _summarize_clusters(self, clusters: Dict[int, List[Dict[str, Any]]]) -> Dict[int, Dict[str, Any]]:
        summaries: Dict[int, Dict[str, Any]] = {}
        for label, entries in clusters.items():
            if label == -1 or not entries:
                continue
            avg_risk = float(
                sum(entry.get("risk_score", 0.0) for entry in entries) / max(len(entries), 1)
            )
            avg_ml = float(
                sum(entry.get("ml_probability", 0.0) for entry in entries) / max(len(entries), 1)
            )
            avg_suspicious = float(
                sum(entry.get("suspicious_ratio", 0.0) for entry in entries) / max(len(entries), 1)
            )
            summaries[label] = {
                "avg_risk": avg_risk,
                "avg_ml_probability": avg_ml,
                "avg_suspicious_ratio": avg_suspicious,
                "top_apis": self._summarize_tokens(entries, "api_tokens"),
                "top_behaviors": self._summarize_tokens(entries, "behavior_tokens"),
                "top_iocs": self._summarize_tokens(entries, "ioc_tokens"),
                "dominant_quadrant": self._dominant_quadrant(entries),
                "quadrant_distribution": self._quadrant_distribution(entries),
            }
        return summaries

    def _summarize_family(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not entries:
            return {}
        return {
            "avg_risk": float(
                sum(entry.get("risk_score", 0.0) for entry in entries) / max(len(entries), 1)
            ),
            "avg_ml_probability": float(
                sum(entry.get("ml_probability", 0.0) for entry in entries) / max(len(entries), 1)
            ),
            "top_apis": self._summarize_tokens(entries, "api_tokens"),
            "top_behaviors": self._summarize_tokens(entries, "behavior_tokens"),
            "top_iocs": self._summarize_tokens(entries, "ioc_tokens"),
            "dominant_quadrant": self._dominant_quadrant(entries),
            "quadrant_distribution": self._quadrant_distribution(entries),
        }

    @staticmethod
    def _quadrant_label(quadrant: str) -> str:
        labels = {
            "Q1": "Execution & Propagation",
            "Q2": "Propagation-Dominant",
            "Q3": "Dormant / Low-Activity",
            "Q4": "Execution-Dominant",
        }
        return labels.get(quadrant, "Unknown")

    def _build_plane_profile(
        self,
        entry: Dict[str, Any],
        *,
        origin: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        risk_norm = min(max(float(entry.get("risk_score", 0.0) or 0.0) / 100.0, 0.0), 1.0)
        ml_norm = min(max(float(entry.get("ml_probability", 0.0) or 0.0), 0.0), 1.0)
        suspicious_norm = min(max(float(entry.get("suspicious_ratio", 0.0) or 0.0), 0.0), 1.0)
        network_norm = min(max(float(entry.get("network_count", 0.0) or 0.0) / 10.0, 0.0), 1.0)
        ioc_norm = min(max(float(entry.get("ioc_count", 0.0) or 0.0) / 10.0, 0.0), 1.0)
        behavior_norm = min(max(float(entry.get("behavior_count", 0.0) or 0.0) / 10.0, 0.0), 1.0)
        api_norm = min(max(float(entry.get("api_call_count", 0.0) or 0.0) / 200.0, 0.0), 1.0)
        entropy_norm = min(max(float(entry.get("entropy", 0.0) or 0.0) / 8.0, 0.0), 1.0)

        raw_x = suspicious_norm * 0.4 + ml_norm * 0.35 + risk_norm * 0.25
        raw_y = network_norm * 0.35 + ioc_norm * 0.25 + behavior_norm * 0.2 + api_norm * 0.1 + entropy_norm * 0.1

        origin = origin or {"x": 0.0, "y": 0.0}
        centered_x = float(raw_x - origin.get("x", 0.0))
        centered_y = float(raw_y - origin.get("y", 0.0))

        if centered_x >= 0 and centered_y >= 0:
            quadrant = "Q1"
        elif centered_x < 0 <= centered_y:
            quadrant = "Q2"
        elif centered_x < 0 and centered_y < 0:
            quadrant = "Q3"
        else:
            quadrant = "Q4"

        return {
            "raw_x": float(raw_x),
            "raw_y": float(raw_y),
            "x": centered_x,
            "y": centered_y,
            "quadrant": quadrant,
            "quadrant_label": self._quadrant_label(quadrant),
        }

    def _assign_behavioral_plane(self, entries: List[Dict[str, Any]]) -> Dict[str, float]:
        if not entries:
            return {"x": 0.0, "y": 0.0}
        provisional = [self._build_plane_profile(entry) for entry in entries]
        origin = {
            "x": float(np.median([profile["raw_x"] for profile in provisional])),
            "y": float(np.median([profile["raw_y"] for profile in provisional])),
        }
        for entry in entries:
            entry["behavioral_plane"] = self._build_plane_profile(entry, origin=origin)
        return origin

    @staticmethod
    def _average_plane(entries: List[Dict[str, Any]]) -> Dict[str, float]:
        if not entries:
            return {"x": 0.0, "y": 0.0}
        xs = [float((entry.get("behavioral_plane") or {}).get("x", 0.0)) for entry in entries]
        ys = [float((entry.get("behavioral_plane") or {}).get("y", 0.0)) for entry in entries]
        return {"x": float(sum(xs) / len(xs)), "y": float(sum(ys) / len(ys))}

    @staticmethod
    def _quadrant_distribution(entries: List[Dict[str, Any]]) -> Dict[str, int]:
        distribution: Dict[str, int] = defaultdict(int)
        for entry in entries:
            quadrant = (entry.get("behavioral_plane") or {}).get("quadrant")
            if quadrant:
                distribution[str(quadrant)] += 1
        return dict(distribution)

    def _dominant_quadrant(self, entries: List[Dict[str, Any]]) -> Optional[str]:
        distribution = self._quadrant_distribution(entries)
        if not distribution:
            return None
        dominant = max(distribution.items(), key=lambda item: item[1])[0]
        return f"{dominant} ({self._quadrant_label(dominant)})"


__all__ = ["MalwareClustering"]
