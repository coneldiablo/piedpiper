#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor REST API service.

Provides asynchronous analysis jobs reachable via HTTP endpoints and
optional WebSocket broadcasts (if Flask-SocketIO is installed).
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, Future
from pathlib import Path
from functools import wraps
from datetime import timedelta
from typing import Any, Dict, Optional, Tuple

if __package__ in {None, ""}:
    project_root = Path(__file__).resolve().parent.parent
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from analyzer.ai_analyst import get_ai_analyst
from analyzer.clustering import MalwareClustering
from analyzer.threat_hunting import ThreatHuntingEngine
from analyzer.yara_generator import YARAGenerator
from core.config import config_manager
from reports.report_generator import generate_report
from api.collaboration import register_collaboration_handlers
from services.analysis_pipeline import run_canonical_pipeline
from services.ml_profile_store import MLProfileStore
from services.qdrant_profile_store import QdrantProfileStore
from services.retro_hunt import RetroHuntOrchestrator
from scripts.train_model import train_model

logger = logging.getLogger("api.server")
logging.basicConfig(level=logging.INFO)

PRODUCT_NAME = "Pied Piper"
PRODUCT_DESCRIPTION = (
    "Интегрированная система многоуровневого анализа вредоносных объектов "
    "с AI-ассистированной классификацией и автоматизацией threat intelligence"
)

socketio = None
try:
    from flask_socketio import SocketIO

    socketio = SocketIO(cors_allowed_origins="*")
except Exception:  # pragma: no cover - optional dependency
    socketio = None

limiter = Limiter(key_func=get_remote_address, default_limits=[], storage_uri="memory://")
jwt_manager = JWTManager()


class JobStatus:
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class JobStore:
    """Thread-safe job storage."""

    def __init__(self) -> None:
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create_job(self, payload: Dict[str, Any]) -> str:
        job_id = uuid.uuid4().hex
        with self._lock:
            self._jobs[job_id] = {
                "status": JobStatus.QUEUED,
                "progress": 0,
                "payload": payload,
                "result": None,
                "error": None,
                "report_paths": [],
                "report_errors": [],
            }
        return job_id

    def update_job(
        self,
        job_id: str,
        *,
        status: Optional[str] = None,
        progress: Optional[int] = None,
        result: Optional[Any] = None,
        error: Optional[str] = None,
        report_paths: Optional[list] = None,
        report_errors: Optional[list] = None,
    ) -> None:
        with self._lock:
            payload = self._jobs.get(job_id)
            if not payload:
                return
            if status:
                payload["status"] = status
            if progress is not None:
                payload["progress"] = progress
            if result is not None:
                payload["result"] = result
            if error is not None:
                payload["error"] = error
            if report_paths is not None:
                payload["report_paths"] = report_paths
            if report_errors is not None:
                payload["report_errors"] = report_errors

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._jobs.get(job_id)


job_store = JobStore()
executor = ThreadPoolExecutor(max_workers=max(os.cpu_count() or 2, 4))


def _emit_socket_event(event: str, payload: Dict[str, Any]) -> None:
    if socketio:
        try:  # pragma: no cover - network side-effect
            socketio.emit(event, payload)
        except Exception as exc:
            logger.debug("Socket emit error: %s", exc)


def _run_analysis_job(job_id: str, payload: Dict[str, Any]) -> None:
    try:
        job_store.update_job(job_id, status=JobStatus.RUNNING, progress=5)
        _emit_socket_event("job_status", {"job_id": job_id, "status": JobStatus.RUNNING})

        file_path = payload.get("file")
        if not file_path:
            raise ValueError("Field 'file' is required")
        file_path = os.path.abspath(file_path)
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File {file_path} does not exist")

        run_dynamic = bool(payload.get("dynamic", False))
        generate_reports = bool(payload.get("generate_report", True))
        requested_formats = payload.get("report_format") or ["pdf", "html"]
        report_dir = Path(payload.get("report_dir") or config_manager.get("REPORT_OUTPUT_DIR", "./reports_api"))
        report_dir.mkdir(parents=True, exist_ok=True)

        def _progress(progress: int, stage: str) -> None:
            job_store.update_job(job_id, progress=progress)
            _emit_socket_event("job_progress", {"job_id": job_id, "progress": progress, "stage": stage})

        timeout = int(payload.get("timeout", 20))
        logger.info("Job %s: running canonical pipeline for %s", job_id, file_path)
        report_payload = run_canonical_pipeline(
            file_path,
            run_dynamic=run_dynamic,
            timeout=timeout,
            enable_threat_intel=bool(payload.get("threat_intel", True)),
            enable_retrohunt=bool(payload.get("retro_hunt", True)),
            progress_callback=_progress,
        )

        report_paths: list = []
        report_errors: list = list(report_payload.get("report_errors") or [])
        if generate_reports:
            try:
                base_name = payload.get("report_basename") or f"TI_{job_id}"
                generated_files = generate_report(
                    static_data=report_payload.get("static") or {},
                    dynamic_data=report_payload.get("dynamic") or {},
                    ioc_data=report_payload.get("iocs") or [],
                    risk_data=report_payload.get("risk") or {},
                    output_dir=str(report_dir),
                    base_name=base_name,
                    formats=requested_formats,
                    behavioral_data=report_payload.get("behavioral") or [],
                    mitre_data=report_payload.get("mitre") or {},
                    d3fend_data=report_payload.get("d3fend") or {},
                    ti_enrichment=report_payload.get("ti_enrichment") or {},
                    fusion_data=report_payload.get("fusion") or {},
                    retro_hunt=report_payload.get("retro_hunt") or {},
                    report_errors=report_errors,
                )
                report_paths = [str(Path(path).resolve()) for path in generated_files.values()]
            except Exception as report_exc:  # pragma: no cover - heavy side-effect
                logger.error("Report generation failed for job %s: %s", job_id, report_exc)
                report_errors.append(
                    {
                        "stage": "report_generation",
                        "message": str(report_exc),
                    }
                )
        report_payload["report_errors"] = report_errors

        job_store.update_job(
            job_id,
            status=JobStatus.COMPLETED,
            progress=100,
            result=report_payload,
            report_paths=report_paths,
            report_errors=report_errors,
        )
        _emit_socket_event("job_status", {"job_id": job_id, "status": JobStatus.COMPLETED, "progress": 100})

    except Exception as exc:
        logger.exception("Job %s failed: %s", job_id, exc)
        job_store.update_job(
            job_id,
            status=JobStatus.FAILED,
            progress=100,
            error=str(exc),
        )
        _emit_socket_event("job_status", {"job_id": job_id, "status": JobStatus.FAILED, "error": str(exc)})


def create_app() -> Flask:
    app = Flask(__name__)

    cors_origins = config_manager.get("API_CORS_ORIGINS", ["*"])
    if isinstance(cors_origins, str):
        cors_origins = [item.strip() for item in cors_origins.split(",") if item.strip()]
    if not cors_origins:
        cors_origins = ["*"]

    CORS(app, resources={r"/api/*": {"origins": cors_origins}}, supports_credentials=True)

    jwt_secret = config_manager.get("API_JWT_SECRET", os.environ.get("TI_API_JWT_SECRET"))
    if not jwt_secret:
        jwt_secret = "change-me"
        logger.warning("API JWT secret not configured; falling back to insecure default.")
    app.config["JWT_SECRET_KEY"] = jwt_secret

    expires_minutes = config_manager.get("API_JWT_EXPIRES_MINUTES", 30)
    try:
        expires_minutes = int(expires_minutes)
    except (TypeError, ValueError):
        expires_minutes = 30
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=max(expires_minutes, 5))

    limiter.init_app(app)
    jwt_manager.init_app(app)

    analyze_rate_limit = config_manager.get("API_RATE_LIMIT_ANALYZE", "5 per minute")
    status_rate_limit = config_manager.get("API_RATE_LIMIT_STATUS", "30 per minute")
    report_rate_limit = config_manager.get("API_RATE_LIMIT_REPORT", "20 per minute")
    auth_rate_limit = config_manager.get("API_RATE_LIMIT_AUTH", "10 per hour")
    ping_rate_limit = config_manager.get("API_RATE_LIMIT_PING", "120 per minute")
    cluster_rate_limit = config_manager.get("API_RATE_LIMIT_CLUSTER", "3 per minute")
    hunt_rate_limit = config_manager.get("API_RATE_LIMIT_HUNT", "10 per minute")
    yara_rate_limit = config_manager.get("API_RATE_LIMIT_YARA", "5 per minute")
    ml_train_rate_limit = config_manager.get("API_RATE_LIMIT_ML_TRAIN", "2 per hour")
    ml_similarity_rate_limit = config_manager.get("API_RATE_LIMIT_ML_SIMILARITY", "10 per minute")

    auth_users_cfg = config_manager.get("API_AUTH_USERS", {})
    auth_users: Dict[str, str] = {}
    if isinstance(auth_users_cfg, dict):
        for username, password in auth_users_cfg.items():
            if username and password:
                auth_users[str(username)] = str(password)

    fallback_user = config_manager.get("API_AUTH_USERNAME") or os.environ.get("TI_API_USERNAME")
    fallback_pass = config_manager.get("API_AUTH_PASSWORD") or os.environ.get("TI_API_PASSWORD")
    if fallback_user and fallback_pass:
        auth_users[str(fallback_user)] = str(fallback_pass)

    tokens_cfg = config_manager.get("API_STATIC_TOKENS", [])
    if isinstance(tokens_cfg, str):
        tokens_cfg = [token.strip() for token in tokens_cfg.split(",") if token.strip()]
    static_tokens = {str(token) for token in tokens_cfg if token}

    auth_enabled = bool(auth_users or static_tokens)

    if socketio:
        socketio.init_app(app, cors_allowed_origins=cors_origins or "*")
        register_collaboration_handlers(socketio)

    def _get_identity() -> Optional[str]:
        if not auth_enabled:
            return None
        try:
            return get_jwt_identity()
        except Exception:
            return None

    def secure_route(fn):
        if not auth_enabled:
            return fn

        jwt_protected = jwt_required()(fn)

        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if static_tokens and auth_header.startswith("Bearer "):
                provided = auth_header.split(" ", 1)[1].strip()
                if provided in static_tokens:
                    return fn(*args, **kwargs)
            return jwt_protected(*args, **kwargs)

        return wrapper

    requires_auth = secure_route

    def _build_openapi_spec(base_url: str) -> Dict[str, Any]:
        protected_security = [{"BearerAuth": []}] if auth_enabled else []
        protected = {"security": protected_security} if protected_security else {}

        spec: Dict[str, Any] = {
            "openapi": "3.0.3",
            "info": {
                "title": f"{PRODUCT_NAME} API",
                "version": "1.1.0",
                "description": PRODUCT_DESCRIPTION,
            },
            "servers": [{"url": base_url}],
            "tags": [
                {"name": "Auth", "description": "Authentication and token issuance"},
                {"name": "Analysis", "description": "Asynchronous malware analysis pipeline"},
                {"name": "Utilities", "description": "Auxiliary API capabilities"},
                {"name": "ML", "description": "Supervised training and unsupervised similarity analysis"},
            ],
            "components": {
                "securitySchemes": {
                    "BearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT",
                    }
                },
                "schemas": {
                    "LoginRequest": {
                        "type": "object",
                        "required": ["username", "password"],
                        "properties": {
                            "username": {"type": "string", "example": "tester"},
                            "password": {"type": "string", "example": "secret"},
                        },
                    },
                    "AnalyzeRequest": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {
                            "file": {"type": "string", "example": "C:/samples/suspicious.exe"},
                            "dynamic": {"type": "boolean", "default": False},
                            "timeout": {"type": "integer", "default": 20},
                            "threat_intel": {"type": "boolean", "default": True},
                            "retro_hunt": {"type": "boolean", "default": True},
                            "generate_report": {"type": "boolean", "default": True},
                            "report_format": {
                                "type": "array",
                                "items": {"type": "string", "enum": ["pdf", "html", "json"]},
                            },
                            "report_dir": {"type": "string"},
                            "report_basename": {"type": "string"},
                        },
                    },
                    "QueuedResponse": {
                        "type": "object",
                        "properties": {
                            "job_id": {"type": "string"},
                            "status": {"type": "string", "example": "queued"},
                        },
                    },
                    "AnalysisResult": {
                        "type": "object",
                        "properties": {
                            "static": {"type": "object"},
                            "dynamic": {"type": "object"},
                            "iocs": {"type": "array", "items": {"type": "object"}},
                            "behavioral": {"type": "array", "items": {"type": "object"}},
                            "mitre": {"type": "object"},
                            "d3fend": {"type": "object"},
                            "ti_enrichment": {"type": "object"},
                            "retro_hunt": {"type": "object"},
                            "fusion": {"type": "object"},
                            "risk": {"type": "object"},
                            "system_status": {"type": "object"},
                            "report_errors": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                    "JobStatusResponse": {
                        "type": "object",
                        "properties": {
                            "job_id": {"type": "string"},
                            "status": {"type": "string"},
                            "progress": {"type": "integer"},
                            "error": {"type": "string", "nullable": True},
                            "report_errors": {"type": "array", "items": {"type": "object"}},
                            "result": {"$ref": "#/components/schemas/AnalysisResult"},
                            "report_paths": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                    "ReportResponse": {
                        "type": "object",
                        "properties": {
                            "job_id": {"type": "string"},
                            "result": {"$ref": "#/components/schemas/AnalysisResult"},
                            "report_paths": {"type": "array", "items": {"type": "string"}},
                            "report_errors": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                    "ClusterRequest": {
                        "type": "object",
                        "required": ["samples"],
                        "properties": {
                            "samples": {
                                "type": "array",
                                "items": {"type": "object"},
                            }
                        },
                    },
                    "ThreatHuntRequest": {
                        "type": "object",
                        "required": ["query", "dataset"],
                        "properties": {
                            "query": {"type": "string"},
                            "dataset": {"type": "object"},
                            "job_id": {"type": "string"},
                            "context": {"type": "object"},
                        },
                    },
                    "RetroHuntRequest": {
                        "type": "object",
                        "properties": {
                            "job_id": {"type": "string"},
                            "iocs": {"type": "array", "items": {"type": "object"}},
                            "context": {"type": "object"},
                        },
                    },
                    "RetroHuntResponse": {
                        "type": "object",
                        "properties": {
                            "status": {"type": "string"},
                            "results": {"type": "array", "items": {"type": "object"}},
                            "confidence_boost": {"type": "number"},
                            "total_hits": {"type": "integer"},
                        },
                    },
                    "YaraRequest": {
                        "type": "object",
                        "properties": {
                            "analysis_data": {"type": "object"},
                            "job_id": {"type": "string"},
                            "rule_name": {"type": "string"},
                        },
                    },
                    "YaraResponse": {
                        "type": "object",
                        "properties": {
                            "rule_name": {"type": "string"},
                            "rule": {"type": "string"},
                            "provider_status": {"type": "object"},
                        },
                    },
                    "MLTrainRequest": {
                        "type": "object",
                        "properties": {
                            "dataset_path": {"type": "string"},
                            "samples": {"type": "integer", "default": 1000},
                        },
                    },
                    "MLSimilarityRequest": {
                        "type": "object",
                        "required": ["dataset", "sample"],
                        "properties": {
                            "dataset": {
                                "type": "array",
                                "items": {"type": "object"},
                            },
                            "sample": {"type": "object"},
                            "family_key": {"type": "string", "default": "family"},
                            "top_k": {"type": "integer", "default": 5},
                            "eps": {"type": "number", "default": 0.9},
                            "min_samples": {"type": "integer", "default": 2},
                            "persist_store": {"type": "boolean", "default": False},
                            "store_path": {"type": "string"},
                        },
                    },
                    "ErrorResponse": {
                        "type": "object",
                        "properties": {
                            "error": {"type": "string"},
                            "details": {},
                        },
                    },
                },
            },
            "paths": {
                "/api/ping": {
                    "get": {
                        "tags": ["Utilities"],
                        "summary": "Health check",
                        "responses": {
                            "200": {
                                "description": "Service is reachable",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "status": {"type": "string", "example": "ok"}
                                            },
                                        }
                                    }
                                },
                            }
                        },
                    }
                },
                "/api/auth/login": {
                    "post": {
                        "tags": ["Auth"],
                        "summary": "Issue JWT access token",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/LoginRequest"}
                                }
                            },
                        },
                        "responses": {
                            "200": {"description": "Access token issued"},
                            "400": {"description": "Authentication disabled or bad payload"},
                            "401": {"description": "Invalid credentials"},
                        },
                    }
                },
                "/api/analyze": {
                    "post": {
                        "tags": ["Analysis"],
                        "summary": "Queue asynchronous malware analysis job",
                        **protected,
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/AnalyzeRequest"}
                                }
                            },
                        },
                        "responses": {
                            "202": {
                                "description": "Job queued",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/QueuedResponse"}
                                    }
                                },
                            },
                            "400": {"description": "Expected JSON payload"},
                            "401": {"description": "Unauthorized"},
                            "429": {"description": "Rate limit exceeded"},
                        },
                    }
                },
                "/api/status/{job_id}": {
                    "get": {
                        "tags": ["Analysis"],
                        "summary": "Get analysis job status",
                        **protected,
                        "parameters": [
                            {
                                "name": "job_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            },
                            {
                                "name": "details",
                                "in": "query",
                                "required": False,
                                "schema": {"type": "string", "enum": ["true", "false"]},
                            },
                        ],
                        "responses": {
                            "200": {
                                "description": "Status payload",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/JobStatusResponse"}
                                    }
                                },
                            },
                            "404": {"description": "Job not found"},
                            "401": {"description": "Unauthorized"},
                        },
                    }
                },
                "/api/report/{job_id}": {
                    "get": {
                        "tags": ["Analysis"],
                        "summary": "Fetch completed analysis result and report paths",
                        **protected,
                        "parameters": [
                            {
                                "name": "job_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Completed analysis payload",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/ReportResponse"}
                                    }
                                },
                            },
                            "404": {"description": "Job not found"},
                            "409": {"description": "Job not ready"},
                            "401": {"description": "Unauthorized"},
                        },
                    }
                },
                "/api/cluster": {
                    "post": {
                        "tags": ["Utilities"],
                        "summary": "Cluster samples by behavioral similarity",
                        **protected,
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ClusterRequest"}
                                }
                            },
                        },
                        "responses": {
                            "200": {"description": "Cluster summary"},
                            "400": {"description": "Bad request"},
                            "401": {"description": "Unauthorized"},
                            "503": {"description": "Clustering unavailable"},
                        },
                    }
                },
                "/api/hunt": {
                    "post": {
                        "tags": ["Utilities"],
                        "summary": "Run threat hunting query against analysis dataset",
                        **protected,
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ThreatHuntRequest"}
                                }
                            },
                        },
                        "responses": {
                            "200": {"description": "Threat hunting results"},
                            "400": {"description": "Bad request"},
                            "401": {"description": "Unauthorized"},
                        },
                    }
                },
                "/api/retro-hunt": {
                    "post": {
                        "tags": ["Utilities"],
                        "summary": "Replay extracted IoCs against external SIEM/EDR/sandbox connectors",
                        **protected,
                        "requestBody": {
                            "required": False,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/RetroHuntRequest"}
                                }
                            },
                        },
                        "responses": {
                            "200": {
                                "description": "External retro-hunt results",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/RetroHuntResponse"}
                                    }
                                },
                            },
                            "400": {"description": "Bad request"},
                            "401": {"description": "Unauthorized"},
                        },
                    }
                },
                "/api/yara": {
                    "post": {
                        "tags": ["Utilities"],
                        "summary": "Generate YARA rule from analysis data",
                        **protected,
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/YaraRequest"}
                                }
                            },
                        },
                        "responses": {
                            "200": {
                                "description": "Generated YARA rule",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/YaraResponse"}
                                    }
                                },
                            },
                            "400": {"description": "Bad request"},
                            "401": {"description": "Unauthorized"},
                        },
                    }
                },
                "/api/ml/train": {
                    "post": {
                        "tags": ["ML"],
                        "summary": "Train the supervised malware classifier",
                        **protected,
                        "requestBody": {
                            "required": False,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/MLTrainRequest"}
                                }
                            },
                        },
                        "responses": {
                            "200": {"description": "Training metrics"},
                            "400": {"description": "Bad request"},
                            "401": {"description": "Unauthorized"},
                        },
                    }
                },
                "/api/ml/similarity": {
                    "post": {
                        "tags": ["ML"],
                        "summary": "Build unsupervised similarity view with quadrants and Manhattan distance",
                        **protected,
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/MLSimilarityRequest"}
                                }
                            },
                        },
                        "responses": {
                            "200": {"description": "Similarity analysis payload"},
                            "400": {"description": "Bad request"},
                            "401": {"description": "Unauthorized"},
                        },
                    }
                },
            },
        }

        if not auth_enabled:
            spec["components"]["securitySchemes"] = {}

        return spec

    @app.route("/api/openapi.json", methods=["GET"])
    def openapi_spec() -> Any:
        return jsonify(_build_openapi_spec(request.url_root.rstrip("/")))

    @app.route("/api/docs", methods=["GET"])
    def swagger_ui() -> Tuple[str, int, Dict[str, str]]:
        html = """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Pied Piper API Docs</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
      body { margin: 0; background: #fafafa; }
      .topbar { display: none; }
      .swagger-ui .info { margin: 24px 0; }
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.onload = function() {
        const specUrl = new URL('/api/openapi.json', window.location.origin).toString();
        SwaggerUIBundle({
          url: specUrl,
          dom_id: '#swagger-ui',
          deepLinking: true,
          displayRequestDuration: true,
          persistAuthorization: true
        });
      };
    </script>
  </body>
</html>"""
        return html, 200, {"Content-Type": "text/html; charset=utf-8"}

    @app.route("/api/auth/login", methods=["POST"])
    @limiter.limit(auth_rate_limit)
    def login() -> Tuple[Any, int]:
        if not auth_enabled or not auth_users:
            return jsonify({"error": "Password-based authentication is disabled"}), 400
        if not request.is_json:
            return jsonify({"error": "Expected JSON payload"}), 400

        data = request.get_json() or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()

        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        expected = auth_users.get(username)
        if expected != password:
            logger.warning("Authentication failed for user %s", username)
            return jsonify({"error": "Invalid credentials"}), 401

        token = create_access_token(identity=username)
        logger.info("Access token issued for user %s", username)
        return jsonify({"access_token": token, "token_type": "Bearer"}), 200

    @app.route("/api/analyze", methods=["POST"])
    @limiter.limit(analyze_rate_limit)
    @requires_auth
    def enqueue_analysis() -> Tuple[Any, int]:
        if not request.is_json:
            return jsonify({"error": "Expected JSON payload"}), 400

        payload = request.get_json() or {}
        job_id = job_store.create_job(payload)
        executor.submit(_run_analysis_job, job_id, payload)

        requester = _get_identity() or "anonymous"
        logger.info("Job %s queued by %s", job_id, requester)
        return jsonify({"job_id": job_id, "status": JobStatus.QUEUED}), 202

    @app.route("/api/status/<job_id>", methods=["GET"])
    @limiter.limit(status_rate_limit)
    @requires_auth
    def job_status(job_id: str) -> Tuple[Any, int]:
        job = job_store.get_job(job_id)
        if not job:
            return jsonify({"error": f"Job {job_id} not found"}), 404

        response = {
            "job_id": job_id,
            "status": job["status"],
            "progress": job.get("progress", 0),
            "error": job.get("error"),
            "report_errors": job.get("report_errors", []),
        }
        if request.args.get("details") == "true" and job.get("result") is not None:
            response["result"] = job["result"]
            response["report_paths"] = job.get("report_paths", [])
        return jsonify(response)

    @app.route("/api/report/<job_id>", methods=["GET"])
    @limiter.limit(report_rate_limit)
    @requires_auth
    def job_report(job_id: str) -> Tuple[Any, int]:
        job = job_store.get_job(job_id)
        if not job:
            return jsonify({"error": f"Job {job_id} not found"}), 404
        if job["status"] != JobStatus.COMPLETED:
            return jsonify({"error": f"Job {job_id} is not ready", "status": job['status']}), 409
        return jsonify(
            {
                "job_id": job_id,
                "result": job.get("result"),
                "report_paths": job.get("report_paths", []),
                "report_errors": job.get("report_errors", []),
            }
        )

    @app.route("/api/cluster", methods=["POST"])
    @limiter.limit(cluster_rate_limit)
    @requires_auth
    def cluster_samples() -> Tuple[Any, int]:
        if not request.is_json:
            return jsonify({"error": "Expected JSON payload"}), 400

        payload = request.get_json() or {}
        samples = payload.get("samples")
        if not isinstance(samples, list) or not samples:
            return jsonify({"error": "Field 'samples' must be a non-empty list"}), 400

        try:
            clustering = MalwareClustering()
            result = clustering.cluster_by_behavior(samples)
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 503
        except Exception as exc:  # pragma: no cover - safety
            logger.exception("Clustering failed: %s", exc)
            return jsonify({"error": "clustering_failed", "details": str(exc)}), 500

        response_payload = dict(result)
        clusters = result.get("clusters", {})
        if isinstance(clusters, dict):
            normalized_clusters = []
            for label in sorted(
                clusters.keys(),
                key=lambda value: int(value) if str(value).lstrip("-").isdigit() else str(value),
            ):
                cluster_payload = clusters[label]
                if isinstance(cluster_payload, dict):
                    enriched_payload = dict(cluster_payload)
                    enriched_payload.setdefault(
                        "label",
                        int(label) if str(label).lstrip("-").isdigit() else label,
                    )
                    normalized_clusters.append(enriched_payload)
            response_payload["clusters"] = normalized_clusters

        return jsonify(response_payload), 200

    @app.route("/api/hunt", methods=["POST"])
    @limiter.limit(hunt_rate_limit)
    @requires_auth
    def hunt() -> Tuple[Any, int]:
        if not request.is_json:
            return jsonify({"error": "Expected JSON payload"}), 400

        payload = request.get_json() or {}
        query = payload.get("query")
        if not query:
            return jsonify({"error": "Field 'query' is required"}), 400

        dataset = payload.get("dataset")
        job_id = payload.get("job_id")
        if dataset is None and job_id:
            job = job_store.get_job(str(job_id))
            if job and job.get("result"):
                dataset = job["result"]

        if not isinstance(dataset, dict):
            return jsonify({"error": "Field 'dataset' must be an object"}), 400

        context = payload.get("context")
        if not isinstance(context, dict):
            context = {}
        if job_id and "job_id" not in context:
            context["job_id"] = job_id

        try:
            engine = ThreatHuntingEngine(dataset, context)
            results = engine.execute_query(str(query))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:  # pragma: no cover - safety
            logger.exception("Threat hunting failed: %s", exc)
            return jsonify({"error": "threat_hunting_failed", "details": str(exc)}), 500

        return jsonify({"results": results}), 200

    @app.route("/api/retro-hunt", methods=["POST"])
    @limiter.limit(hunt_rate_limit)
    @requires_auth
    def retro_hunt() -> Tuple[Any, int]:
        payload = request.get_json() or {} if request.is_json else {}
        iocs = payload.get("iocs")
        job_id = payload.get("job_id")
        if iocs is None and job_id:
            job = job_store.get_job(str(job_id))
            if job and job.get("result"):
                iocs = (job["result"] or {}).get("iocs")
        if not isinstance(iocs, list):
            return jsonify({"error": "Field 'iocs' must be a list or provided via job_id"}), 400

        context = payload.get("context")
        if not isinstance(context, dict):
            context = {}
        if job_id:
            context.setdefault("job_id", job_id)

        try:
            result = RetroHuntOrchestrator().run(iocs, context=context)
        except Exception as exc:  # pragma: no cover - runtime dependent
            logger.exception("Retro-hunt failed: %s", exc)
            return jsonify({"error": "retro_hunt_failed", "details": str(exc)}), 500

        return jsonify(result), 200

    @app.route("/api/yara", methods=["POST"])
    @limiter.limit(yara_rate_limit)
    @requires_auth
    def yara_generation() -> Tuple[Any, int]:
        if not request.is_json:
            return jsonify({"error": "Expected JSON payload"}), 400

        payload = request.get_json() or {}
        analysis_data = payload.get("analysis_data")
        job_id = payload.get("job_id")

        if analysis_data is None and job_id:
            job = job_store.get_job(str(job_id))
            if job and job.get("result"):
                analysis_data = job["result"]

        if not isinstance(analysis_data, dict):
            return jsonify({"error": "Field 'analysis_data' must be an object"}), 400

        rule_name = str(payload.get("rule_name") or f"TI_{uuid.uuid4().hex[:8]}")
        try:
            analyst = get_ai_analyst()
            rule = analyst.generate_yara_rule(analysis_data, rule_name)
        except Exception as exc:  # pragma: no cover - safety
            logger.exception("YARA generation failed: %s", exc)
            return jsonify({"error": "yara_generation_failed", "details": str(exc)}), 500

        return jsonify({"rule_name": rule_name, "rule": rule, "provider_status": get_ai_analyst().get_provider_status()}), 200

    @app.route("/api/ml/train", methods=["POST"])
    @limiter.limit(ml_train_rate_limit)
    @requires_auth
    def ml_train() -> Tuple[Any, int]:
        payload = {}
        if request.is_json:
            payload = request.get_json() or {}
        elif request.data:
            return jsonify({"error": "Expected JSON payload"}), 400

        dataset_path = payload.get("dataset_path")
        try:
            samples = int(payload.get("samples", 1000))
        except (TypeError, ValueError):
            return jsonify({"error": "Field 'samples' must be an integer"}), 400

        try:
            metadata = train_model(sample_count=max(200, samples), dataset_path=dataset_path)
        except Exception as exc:
            logger.exception("ML training failed: %s", exc)
            return jsonify({"error": "ml_training_failed", "details": str(exc)}), 500

        return jsonify(metadata), 200

    @app.route("/api/ml/similarity", methods=["POST"])
    @limiter.limit(ml_similarity_rate_limit)
    @requires_auth
    def ml_similarity() -> Tuple[Any, int]:
        if not request.is_json:
            return jsonify({"error": "Expected JSON payload"}), 400

        payload = request.get_json() or {}
        dataset = payload.get("dataset")
        sample = payload.get("sample")
        if not isinstance(dataset, list) or not dataset:
            return jsonify({"error": "Field 'dataset' must be a non-empty list"}), 400
        if not isinstance(sample, dict):
            return jsonify({"error": "Field 'sample' must be an object"}), 400

        try:
            top_k = max(1, int(payload.get("top_k", 5)))
            eps = float(payload.get("eps", 0.9))
            min_samples = max(1, int(payload.get("min_samples", 2)))
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid numeric parameters"}), 400

        family_key = str(payload.get("family_key") or "family")
        persist_store = bool(payload.get("persist_store", False))
        store_path = payload.get("store_path")

        try:
            clusterer = MalwareClustering(eps=eps, min_samples=min_samples)
            cluster_summary = clusterer.cluster_by_behavior(dataset)
            cluster_match = clusterer.identify_family(sample)
            nearest_neighbors = clusterer.get_nearest_neighbors(sample, top_k=top_k)
            sample_projection = clusterer.describe_sample_projection(sample)

            family_profiles: Dict[str, Any] = {}
            family_match: Dict[str, Any] = {"family": None, "reason": "family_labels_missing"}
            if any(
                isinstance(entry, dict)
                and (
                    entry.get(family_key) is not None
                    or (
                        isinstance(entry.get("attributes"), dict)
                        and entry["attributes"].get(family_key) is not None
                    )
                )
                for entry in dataset
            ):
                family_profiles = clusterer.build_family_profiles(dataset, family_key=family_key)
                if family_profiles:
                    family_match = clusterer.identify_family_from_profiles(
                        sample,
                        profiles=family_profiles,
                        top_k=top_k,
                    )

            persisted_profiles = 0
            store_neighbors: List[Dict[str, Any]] = []
            vector_store = {
                "backend": "not_persisted",
                "status": {
                    "profiles": 0,
                    "sqlite": {"enabled": True, "stored": 0},
                    "qdrant": {"enabled": False, "configured": False, "stored": 0},
                },
            }
            if persist_store:
                persisted_profiles = clusterer.persist_similarity_profiles(store_path)
                vector_store["status"] = clusterer.get_persistence_status()
                scaled_vector = clusterer.get_scaled_feature_vector(sample)
                if scaled_vector:
                    qdrant_store = QdrantProfileStore()
                    if qdrant_store.is_configured():
                        try:
                            store_neighbors = qdrant_store.find_neighbors(scaled_vector, top_k=top_k)
                            if store_neighbors:
                                vector_store["backend"] = "qdrant"
                        except Exception as exc:
                            logger.warning("Qdrant similarity lookup failed, falling back to SQLite: %s", exc)
                            vector_store["status"].setdefault("qdrant", {})["search_error"] = str(exc)

                    if not store_neighbors:
                        store = MLProfileStore(db_path=store_path)
                        store_neighbors = store.find_neighbors(scaled_vector, top_k=top_k)
                        vector_store["backend"] = "sqlite"

            response_payload = {
                "sample_projection": sample_projection,
                "quadrant_origin": getattr(clusterer, "_quadrant_origin", {"x": 0.0, "y": 0.0}),
                "cluster_summary": cluster_summary,
                "cluster_match": cluster_match,
                "nearest_neighbors": nearest_neighbors,
                "family_profiles_count": len(family_profiles),
                "family_match": family_match,
                "persisted_profiles": persisted_profiles,
                "store_neighbors": store_neighbors,
                "vector_store": vector_store,
            }
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 503
        except Exception as exc:
            logger.exception("ML similarity analysis failed: %s", exc)
            return jsonify({"error": "ml_similarity_failed", "details": str(exc)}), 500

        return jsonify(response_payload), 200

    @app.route("/api/ping", methods=["GET"])
    @limiter.limit(ping_rate_limit)
    def ping() -> Tuple[Any, int]:
        return jsonify({"status": "ok"}), 200

    return app


if __name__ == "__main__":  # pragma: no cover
    flask_app = create_app()
    host = os.environ.get("TI_API_HOST", "0.0.0.0")
    port = int(os.environ.get("TI_API_PORT", 8080))
    if socketio:
        socketio.run(flask_app, host=host, port=port, allow_unsafe_werkzeug=True)
    else:
        flask_app.run(host=host, port=port, debug=False)
