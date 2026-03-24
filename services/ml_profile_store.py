#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQLite-backed store for ML similarity profiles.

Profiles contain a scaled feature vector, quadrant metadata and high-level
risk descriptors so that nearest-neighbour search can be performed later
without rerunning the full clustering pipeline.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from core.config import config_manager


class MLProfileStore:
    """Persist and query behavioural ML profiles."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        configured = db_path or config_manager.get("ML_PROFILE_STORE_PATH", "./data/ml_profiles.db")
        self.db_path = Path(configured).expanduser()
        if not self.db_path.is_absolute():
            self.db_path = (Path.cwd() / self.db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        return connection

    def _initialise(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ml_profiles (
                    sample_id TEXT PRIMARY KEY,
                    family TEXT,
                    cluster_label INTEGER,
                    quadrant TEXT,
                    axis_x REAL,
                    axis_y REAL,
                    risk_score REAL,
                    ml_probability REAL,
                    suspicious_ratio REAL,
                    network_count INTEGER,
                    feature_vector TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ml_profiles_quadrant ON ml_profiles(quadrant)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ml_profiles_family ON ml_profiles(family)"
            )
            conn.commit()

    def upsert_profiles(self, profiles: Iterable[Dict[str, Any]]) -> int:
        rows = list(profiles)
        if not rows:
            return 0
        timestamp = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            for row in rows:
                conn.execute(
                    """
                    INSERT INTO ml_profiles (
                        sample_id, family, cluster_label, quadrant, axis_x, axis_y,
                        risk_score, ml_probability, suspicious_ratio, network_count,
                        feature_vector, metadata_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sample_id) DO UPDATE SET
                        family = excluded.family,
                        cluster_label = excluded.cluster_label,
                        quadrant = excluded.quadrant,
                        axis_x = excluded.axis_x,
                        axis_y = excluded.axis_y,
                        risk_score = excluded.risk_score,
                        ml_probability = excluded.ml_probability,
                        suspicious_ratio = excluded.suspicious_ratio,
                        network_count = excluded.network_count,
                        feature_vector = excluded.feature_vector,
                        metadata_json = excluded.metadata_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        str(row.get("sample_id")),
                        row.get("family"),
                        row.get("cluster_label"),
                        row.get("quadrant"),
                        row.get("axis_x"),
                        row.get("axis_y"),
                        row.get("risk_score"),
                        row.get("ml_probability"),
                        row.get("suspicious_ratio"),
                        row.get("network_count"),
                        json.dumps(row.get("feature_vector") or []),
                        json.dumps(row.get("metadata") or {}, ensure_ascii=False),
                        timestamp,
                        timestamp,
                    ),
                )
            conn.commit()
        return len(rows)

    def fetch_profiles(
        self,
        *,
        quadrant: Optional[str] = None,
        family: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM ml_profiles WHERE 1=1"
        params: List[Any] = []
        if quadrant:
            query += " AND quadrant = ?"
            params.append(quadrant)
        if family:
            query += " AND family = ?"
            params.append(family)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, int(limit)))

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_profile(row) for row in rows]

    def find_neighbors(
        self,
        feature_vector: Sequence[float],
        *,
        top_k: int = 5,
        family: Optional[str] = None,
        quadrant: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        target = [float(value) for value in feature_vector]
        if not target:
            return []
        candidates = self.fetch_profiles(quadrant=quadrant, family=family, limit=5000)
        neighbours: List[Dict[str, Any]] = []
        for profile in candidates:
            vector = profile.get("feature_vector") or []
            if len(vector) != len(target):
                continue
            manhattan = sum(abs(float(left) - float(right)) for left, right in zip(target, vector))
            neighbour = dict(profile)
            neighbour["manhattan_distance"] = float(manhattan)
            neighbours.append(neighbour)
        neighbours.sort(key=lambda item: item["manhattan_distance"])
        return neighbours[: max(1, int(top_k))]

    @staticmethod
    def _row_to_profile(row: sqlite3.Row) -> Dict[str, Any]:
        profile = dict(row)
        profile["feature_vector"] = json.loads(profile.get("feature_vector") or "[]")
        profile["metadata"] = json.loads(profile.get("metadata_json") or "{}")
        profile.pop("metadata_json", None)
        return profile


__all__ = ["MLProfileStore"]
