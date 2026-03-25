#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Optional Qdrant-backed store for behavioural ML profiles.

The store mirrors the SQLite profile persistence so the project can keep a
local fallback while also using a real vector database for similarity search.
Qdrant is only used when explicitly enabled and configured.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote

import requests

from core.config import config_manager

logger = logging.getLogger("services.qdrant_profile_store")


class QdrantProfileStore:
    """Persist and query behavioural ML profiles in Qdrant."""

    def __init__(
        self,
        *,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        collection: Optional[str] = None,
        timeout: Optional[int] = None,
        verify_ssl: Optional[bool] = None,
        enabled: Optional[bool] = None,
        distance: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        configured_endpoint = endpoint if endpoint is not None else config_manager.get("QDRANT_ENDPOINT", "")
        self.endpoint = str(configured_endpoint or "").strip().rstrip("/")
        self.api_key = str(api_key if api_key is not None else config_manager.get("QDRANT_API_KEY", "")).strip()
        self.collection = str(
            collection if collection is not None else config_manager.get("QDRANT_COLLECTION", "pied_piper_ml_profiles")
        ).strip()
        self.timeout = int(timeout if timeout is not None else config_manager.get("QDRANT_TIMEOUT", 15))
        if verify_ssl is None:
            verify_ssl = bool(config_manager.get("QDRANT_VERIFY_SSL", True))
        self.verify_ssl = bool(verify_ssl)
        if enabled is None:
            enabled = bool(config_manager.get("QDRANT_ENABLED", False))
        self.enabled = bool(enabled)
        self.distance = str(distance if distance is not None else config_manager.get("QDRANT_DISTANCE", "Manhattan"))
        self.session = session or requests.Session()

    def is_configured(self) -> bool:
        return self.enabled and bool(self.endpoint) and bool(self.collection)

    def describe(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "configured": self.is_configured(),
            "endpoint": self.endpoint,
            "collection": self.collection,
            "distance": self.distance,
            "timeout": self.timeout,
            "verify_ssl": self.verify_ssl,
        }

    def ensure_collection(self, vector_size: int) -> bool:
        if not self.is_configured():
            return False

        collection_path = f"collections/{quote(self.collection, safe='')}"
        status_code, response = self._request("GET", collection_path, expected_statuses=(200, 404))
        if status_code == 200:
            current_size = self._extract_vector_size(response)
            if current_size is not None and int(current_size) != int(vector_size):
                raise RuntimeError(
                    f"Qdrant collection '{self.collection}' already exists with vector size "
                    f"{current_size}, expected {vector_size}"
                )
            return True

        payload = {
            "vectors": {
                "size": int(vector_size),
                "distance": self.distance,
            }
        }
        self._request("PUT", collection_path, json_payload=payload, expected_statuses=(200, 201))
        logger.info("Created Qdrant collection %s with vector size %s", self.collection, vector_size)
        return True

    def upsert_profiles(self, profiles: Iterable[Dict[str, Any]]) -> int:
        rows = list(profiles)
        if not rows or not self.is_configured():
            return 0

        vector_size = len(rows[0].get("feature_vector") or [])
        if vector_size <= 0:
            return 0

        self.ensure_collection(vector_size)
        points: List[Dict[str, Any]] = []
        for row in rows:
            sample_id = str(row.get("sample_id") or uuid.uuid4().hex)
            feature_vector = [float(value) for value in (row.get("feature_vector") or [])]
            if len(feature_vector) != vector_size:
                continue
            points.append(
                {
                    "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"pied-piper:{sample_id}")),
                    "vector": feature_vector,
                    "payload": {
                        "sample_id": sample_id,
                        "family": row.get("family"),
                        "cluster_label": row.get("cluster_label"),
                        "quadrant": row.get("quadrant"),
                        "axis_x": row.get("axis_x"),
                        "axis_y": row.get("axis_y"),
                        "risk_score": row.get("risk_score"),
                        "ml_probability": row.get("ml_probability"),
                        "suspicious_ratio": row.get("suspicious_ratio"),
                        "network_count": row.get("network_count"),
                        "feature_vector": feature_vector,
                        "metadata": row.get("metadata") or {},
                    },
                }
            )

        if not points:
            return 0

        self._request(
            "PUT",
            f"collections/{quote(self.collection, safe='')}/points?wait=true",
            json_payload={"points": points},
            expected_statuses=(200, 201),
        )
        return len(points)

    def find_neighbors(
        self,
        feature_vector: Sequence[float],
        *,
        top_k: int = 5,
        family: Optional[str] = None,
        quadrant: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        target = [float(value) for value in feature_vector]
        if not target or not self.is_configured():
            return []

        self.ensure_collection(len(target))
        payload: Dict[str, Any] = {
            "vector": target,
            "limit": max(1, int(top_k)),
            "with_payload": True,
        }
        filters: List[Dict[str, Any]] = []
        if family:
            filters.append({"key": "family", "match": {"value": family}})
        if quadrant:
            filters.append({"key": "quadrant", "match": {"value": quadrant}})
        if filters:
            payload["filter"] = {"must": filters}

        try:
            _, response = self._request(
                "POST",
                f"collections/{quote(self.collection, safe='')}/points/search",
                json_payload=payload,
                expected_statuses=(200,),
            )
        except RuntimeError as exc:
            logger.debug("Qdrant /points/search failed, retrying with /points/query: %s", exc)
            query_payload = {
                "query": target,
                "limit": payload["limit"],
                "with_payload": True,
            }
            if "filter" in payload:
                query_payload["filter"] = payload["filter"]
            _, response = self._request(
                "POST",
                f"collections/{quote(self.collection, safe='')}/points/query",
                json_payload=query_payload,
                expected_statuses=(200,),
            )

        result_items = response.get("result") or []
        if isinstance(result_items, dict):
            result_items = result_items.get("points") or result_items.get("hits") or []

        neighbours: List[Dict[str, Any]] = []
        for entry in result_items:
            point_payload = entry.get("payload") or {}
            stored_vector = point_payload.get("feature_vector") or []
            neighbour = {
                "sample_id": point_payload.get("sample_id") or entry.get("id"),
                "family": point_payload.get("family"),
                "cluster_label": point_payload.get("cluster_label"),
                "quadrant": point_payload.get("quadrant"),
                "axis_x": point_payload.get("axis_x"),
                "axis_y": point_payload.get("axis_y"),
                "risk_score": point_payload.get("risk_score"),
                "ml_probability": point_payload.get("ml_probability"),
                "suspicious_ratio": point_payload.get("suspicious_ratio"),
                "network_count": point_payload.get("network_count"),
                "metadata": point_payload.get("metadata") or {},
                "qdrant_score": entry.get("score"),
            }
            if len(stored_vector) == len(target):
                neighbour["manhattan_distance"] = float(
                    sum(abs(float(left) - float(right)) for left, right in zip(target, stored_vector))
                )
            neighbours.append(neighbour)

        if neighbours and all("manhattan_distance" in item for item in neighbours):
            neighbours.sort(key=lambda item: item["manhattan_distance"])
        return neighbours

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_payload: Optional[Dict[str, Any]] = None,
        expected_statuses: Tuple[int, ...] = (200,),
    ) -> Tuple[int, Dict[str, Any]]:
        if not self.endpoint:
            raise RuntimeError("Qdrant endpoint is not configured")

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["api-key"] = self.api_key

        try:
            response = self.session.request(
                method=method,
                url=f"{self.endpoint}/{path.lstrip('/')}",
                headers=headers,
                json=json_payload,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except requests.RequestException as exc:
            raise RuntimeError(f"Qdrant request failed: {exc}") from exc

        parsed: Dict[str, Any] = {}
        if response.content:
            try:
                parsed = response.json()
            except ValueError:
                parsed = {}

        if response.status_code not in expected_statuses:
            message = parsed.get("status", {}).get("error") or parsed.get("message") or response.text[:300]
            raise RuntimeError(
                f"Qdrant request {method} {path} failed with HTTP {response.status_code}: {message}"
            )
        return response.status_code, parsed

    @staticmethod
    def _extract_vector_size(payload: Dict[str, Any]) -> Optional[int]:
        result = payload.get("result") or {}
        config = result.get("config") or {}
        params = config.get("params") or {}
        vectors = params.get("vectors")
        if isinstance(vectors, dict):
            size = vectors.get("size")
            if size is not None:
                return int(size)
        return None


__all__ = ["QdrantProfileStore"]
