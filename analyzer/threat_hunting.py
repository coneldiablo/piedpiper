#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Internal threat hunting query engine.

Supports a minimal SQL-like syntax for filtering analysis datasets, e.g.:

    SELECT * FROM api_calls
    WHERE api LIKE '%Remote%' AND args.pid != self.pid
"""

from __future__ import annotations

import operator
import re
from typing import Any, Callable, Dict, Iterable, List, Optional


class ThreatHuntingEngine:
    """Execute lightweight hunting queries against in-memory datasets."""

    OPERATORS: Dict[str, Callable[[Any, Any], bool]] = {
        "=": operator.eq,
        "==": operator.eq,
        "!=": operator.ne,
        ">": operator.gt,
        "<": operator.lt,
        ">=": operator.ge,
        "<=": operator.le,
    }

    def __init__(self, dataset: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> None:
        self.dataset = dataset or {}
        self.context = context or {}

    def execute_query(self, query: str) -> List[Dict[str, Any]]:
        query = (query or "").strip()
        if not query:
            raise ValueError("Query string is empty")

        match = re.match(r"SELECT\s+\*\s+FROM\s+([a-zA-Z0-9_]+)\s*(WHERE\s+(.+))?$", query, re.IGNORECASE)
        if not match:
            raise ValueError("Unsupported query syntax")

        collection_name = match.group(1)
        condition = match.group(3) or ""

        collection = self.dataset.get(collection_name)
        if not isinstance(collection, Iterable):
            raise ValueError(f"Collection '{collection_name}' not found in dataset")

        filters = self._parse_conditions(condition)
        results = []
        for record in collection:
            if not isinstance(record, dict):
                continue
            if all(self._evaluate_condition(record, comparator, field, value) for comparator, field, value in filters):
                results.append(record)
        return results

    def _parse_conditions(self, condition: str) -> List[tuple]:
        if not condition:
            return []
        parts = re.split(r"\s+AND\s+", condition, flags=re.IGNORECASE)
        filters = []
        for part in parts:
            part = part.strip()
            if not part:
                continue
            like_match = re.match(r"([a-zA-Z0-9_.]+)\s+LIKE\s+'(.+)'", part, re.IGNORECASE)
            if like_match:
                filters.append(("LIKE", like_match.group(1), like_match.group(2)))
                continue
            op_match = re.match(r"([a-zA-Z0-9_.]+)\s*(==|!=|>=|<=|>|<|=)\s*(.+)", part)
            if op_match:
                filters.append((op_match.group(2), op_match.group(1), op_match.group(3)))
                continue
            raise ValueError(f"Unsupported condition: {part}")
        return filters

    def _evaluate_condition(self, record: Dict[str, Any], comparator: str, field: str, raw_value: str) -> bool:
        left = self._resolve_field(record, field)
        right = self._resolve_value(raw_value)

        if comparator.upper() == "LIKE":
            pattern = "^" + re.escape(str(right)).replace("%", ".*").replace("_", ".") + "$"
            return bool(re.match(pattern, str(left), re.IGNORECASE))

        op = self.OPERATORS.get(comparator)
        if op is None:
            raise ValueError(f"Unsupported comparator: {comparator}")
        try:
            return op(left, right)
        except Exception:
            return False

    def _resolve_field(self, record: Dict[str, Any], path: str) -> Any:
        value: Any = record
        for part in path.split("."):
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value

    def _resolve_value(self, token: str) -> Any:
        token = token.strip()
        if token.lower() in {"true", "false"}:
            return token.lower() == "true"
        if token.lower() in {"null", "none"}:
            return None
        if token.startswith(("'", '"')) and token.endswith(("'", '"')):
            return token[1:-1]
        if token.startswith("self."):
            ctx_key = token.split(".", 1)[1]
            return self.context.get(ctx_key)
        try:
            if "." in token:
                return float(token)
            return int(token)
        except ValueError:
            return token


__all__ = ["ThreatHuntingEngine"]
