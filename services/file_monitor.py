#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
services/file_monitor.py

Filesystem monitoring service built on top of watchdog that feeds ThreatInquisitor
with continuous file events. It performs lightweight enrichment for every change,
optionally executes baseline scans, and exposes a summary that can be consumed by
CLI tools or the GUI.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.explorer import compute_file_hashes, is_suspicious_file, scan_directory

logger = logging.getLogger("services.file_monitor")

try:  # pragma: no cover - optional dependency
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer

    WATCHDOG_AVAILABLE = True
except Exception:  # pragma: no cover - watchdog missing
    FileSystemEvent = object  # type: ignore
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore
    WATCHDOG_AVAILABLE = False


def _normalize_extensions(exts: Optional[Iterable[str]]) -> Optional[Tuple[str, ...]]:
    if not exts:
        return None
    normalised = []
    for ext in exts:
        if not ext:
            continue
        ext = ext.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        normalised.append(ext)
    return tuple(sorted(set(normalised)))


def _normalize_paths(paths: Optional[Iterable[str]]) -> List[str]:
    if not paths:
        return []
    return sorted({os.path.abspath(os.path.expanduser(p.strip())) for p in paths if p})


@dataclass
class MonitorEvent:
    """Uniform representation of a filesystem event."""

    timestamp: float
    action: str
    path: str
    is_directory: bool
    size: Optional[int] = None
    hashes: Optional[Dict[str, str]] = None
    suspicious: Optional[bool] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "timestamp": self.timestamp,
            "action": self.action,
            "path": self.path,
            "is_directory": self.is_directory,
        }
        if self.size is not None:
            payload["size"] = self.size
        if self.hashes:
            payload["hashes"] = self.hashes
        if self.suspicious is not None:
            payload["suspicious"] = self.suspicious
        if self.extra:
            payload.update(self.extra)
        return payload


class _WatchdogHandler(FileSystemEventHandler):
    """Collect watchdog events and push them into the service queue."""

    def __init__(self, service: "FileMonitorService") -> None:
        super().__init__()
        self._service = service

    def on_created(self, event: FileSystemEvent):
        self._service.enqueue_event("created", event)

    def on_modified(self, event: FileSystemEvent):
        self._service.enqueue_event("modified", event)

    def on_deleted(self, event: FileSystemEvent):
        self._service.enqueue_event("deleted", event)

    def on_moved(self, event: FileSystemEvent):
        self._service.enqueue_event("moved", event)


class FileMonitorService:
    """High-level coordinator for filesystem monitoring."""

    def __init__(
        self,
        directories: Iterable[str],
        *,
        include_extensions: Optional[Iterable[str]] = None,
        exclude_paths: Optional[Iterable[str]] = None,
        recursive: bool = True,
        baseline_with_hashes: bool = True,
        event_queue: Optional["queue.Queue[Dict[str, Any]]"] = None,
        max_events: int = 1000,
        throttle_per_minute: Optional[int] = 60,
        hash_size_limit: int = 16 * 1024 * 1024,
    ) -> None:
        if not WATCHDOG_AVAILABLE:
            raise RuntimeError(
                "watchdog is not available. Install 'watchdog' dependency to enable monitoring."
            )

        self.directories = _normalize_paths(directories)
        if not self.directories:
            raise ValueError("At least one directory must be provided for monitoring.")

        self.include_extensions = _normalize_extensions(include_extensions)
        self.exclude_paths = _normalize_paths(exclude_paths)
        self.recursive = recursive
        self._hash_size_limit = max(hash_size_limit, 0)
        self._max_events = max_events if max_events and max_events > 0 else 1000
        self._baseline_with_hashes = baseline_with_hashes
        self._throttle_per_minute = throttle_per_minute if throttle_per_minute and throttle_per_minute > 0 else None

        self._observer: Observer = Observer()
        self._internal_queue: "queue.Queue[Tuple[str, FileSystemEvent]]" = queue.Queue()
        self._public_queue: "queue.Queue[Dict[str, Any]]" = (
            event_queue if event_queue is not None else queue.Queue()
        )
        self._events: List[MonitorEvent] = []
        self._baseline: List[Dict[str, Any]] = []

        self._stop_event = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._throttle_window: deque[float] = deque()

    @staticmethod
    def is_available() -> bool:
        return WATCHDOG_AVAILABLE

    def enqueue_event(self, action: str, event: FileSystemEvent) -> None:
        if self._stop_event.is_set():
            return
        try:
            self._internal_queue.put_nowait((action, event))
        except queue.Full:
            logger.debug("Internal monitor queue is full; dropping event %s", event)

    def start(self) -> None:
        if self._worker and self._worker.is_alive():
            logger.debug("FileMonitorService already running.")
            return

        for directory in self.directories:
            handler = _WatchdogHandler(self)
            try:
                self._observer.schedule(handler, directory, recursive=self.recursive)
                logger.info("Monitoring directory: %s", directory)
            except Exception as exc:  # pragma: no cover - watchdog edge case
                logger.warning("Failed to schedule directory %s: %s", directory, exc)

        self._observer.start()
        self._stop_event.clear()
        self._worker = threading.Thread(target=self._process_events, daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=5)
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=5)
        logger.info("FileMonitorService stopped.")

    def run_baseline(self) -> List[Dict[str, Any]]:
        baseline_results: List[Dict[str, Any]] = []
        for directory in self.directories:
            baseline_results.extend(
                scan_directory(
                    directory,
                    recursive=self.recursive,
                    with_hashes=self._baseline_with_hashes,
                    suspicious_rules=True,
                )
            )
        self._baseline = baseline_results[-self._max_events :]
        logger.info("Baseline scan completed: %d entries", len(self._baseline))
        return list(self._baseline)

    def smart_scan(self, target_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run a focused scan around a target path."""
        if target_path and os.path.isfile(target_path):
            directory = os.path.dirname(target_path)
        else:
            directory = target_path or (self.directories[0] if self.directories else ".")
        results = scan_directory(
            directory,
            recursive=False,
            with_hashes=True,
            suspicious_rules=True,
        )
        return results

    def get_summary(self) -> Dict[str, Any]:
        return {
            "monitored_paths": self.directories,
            "include_extensions": list(self.include_extensions) if self.include_extensions else None,
            "exclude_paths": self.exclude_paths or None,
            "event_count": len(self._events),
            "baseline_count": len(self._baseline),
            "recent_events": [event.to_dict() for event in self._events[-50:]],
        }

    def export_summary(self, output_file: str) -> None:
        payload = {
            "baseline": self._baseline,
            "events": [event.to_dict() for event in self._events],
            "generated_at": time.time(),
        }
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        logger.info("Monitoring summary exported to %s", output_file)

    def drain_public_queue(self) -> List[Dict[str, Any]]:
        drained: List[Dict[str, Any]] = []
        while True:
            try:
                drained.append(self._public_queue.get_nowait())
            except queue.Empty:
                break
        return drained

    # --------------------------------------------------------------------- #
    # Internal helpers
    # --------------------------------------------------------------------- #

    def _within_include(self, path: str) -> bool:
        if not self.include_extensions:
            return True
        ext = Path(path).suffix.lower()
        return ext in self.include_extensions

    def _within_exclude(self, path: str) -> bool:
        return any(path.startswith(excluded) for excluded in self.exclude_paths)

    def _process_events(self) -> None:
        while not self._stop_event.is_set():
            try:
                action, event = self._internal_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            payload = self._enrich_event(action, event)
            if not payload:
                continue

            self._events.append(payload)
            if len(self._events) > self._max_events:
                self._events = self._events[-self._max_events :]

            try:
                self._public_queue.put_nowait(payload.to_dict())
            except queue.Full:
                try:
                    self._public_queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self._public_queue.put_nowait(payload.to_dict())
                except queue.Full:
                    logger.debug("Public monitoring queue overflow; dropping event.")

    def _enrich_event(self, action: str, event: FileSystemEvent) -> Optional[MonitorEvent]:
        src_path = getattr(event, "src_path", None)
        dest_path = getattr(event, "dest_path", None)
        is_directory = getattr(event, "is_directory", False)
        timestamp = time.time()

        path = dest_path if action == "moved" and dest_path else src_path
        if not path:
            return None
        path = os.path.abspath(path)

        if is_directory:
            return MonitorEvent(timestamp=timestamp, action=action, path=path, is_directory=True)

        if self._within_exclude(path):
            return None
        if not self._within_include(path):
            return None

        if self._throttle_per_minute:
            self._enforce_throttle(timestamp)

        size: Optional[int] = None
        hashes: Optional[Dict[str, str]] = None
        suspicious: Optional[bool] = None

        try:
            stat = os.stat(path)
            size = stat.st_size
        except FileNotFoundError:
            size = None

        if action != "deleted" and size is not None and size <= self._hash_size_limit:
            hashes = compute_file_hashes(path, do_md5=True, do_sha256=True)

        if size is not None:
            file_info = {"filepath": path, "size": size, "modified_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(timestamp))}
            if hashes and "sha256" in hashes:
                file_info["sha256"] = hashes["sha256"]
            suspicious = is_suspicious_file(file_info)

        extra: Dict[str, Any] = {}
        if action == "moved" and dest_path:
            extra["src_path"] = src_path
            extra["dest_path"] = dest_path

        return MonitorEvent(
            timestamp=timestamp,
            action=action,
            path=path,
            is_directory=False,
            size=size,
            hashes=hashes,
            suspicious=suspicious,
            extra=extra,
        )

    def _enforce_throttle(self, timestamp: float) -> None:
        if not self._throttle_per_minute:
            return

        window = self._throttle_window
        window.append(timestamp)
        while window and timestamp - window[0] > 60.0:
            window.popleft()
        if len(window) > self._throttle_per_minute:
            time.sleep(0.5)


__all__ = ["FileMonitorService", "MonitorEvent"]
