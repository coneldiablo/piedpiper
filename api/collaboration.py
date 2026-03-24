#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Socket.IO handlers for real-time collaboration features.

These handlers allow multiple analysts to join the same analysis room,
exchange live updates, and broadcast comments/status changes.
"""

from __future__ import annotations

from typing import Any, Dict

from flask import request
from flask_socketio import emit, join_room, leave_room

ROOM_NAMESPACE = "/analysis"


def _normalise_payload(data: Any) -> Dict[str, Any]:
    return data if isinstance(data, dict) else {}


def register_collaboration_handlers(socketio) -> None:
    """Register collaboration events with the provided SocketIO instance."""
    if socketio is None:
        return

    @socketio.on("join_analysis", namespace=ROOM_NAMESPACE)
    def join_analysis_session(data):
        payload = _normalise_payload(data)
        job_id = str(payload.get("job_id") or "").strip()
        username = str(payload.get("username") or "anonymous").strip()
        if not job_id:
            emit(
                "collab_error",
                {"error": "job_id is required"},
                room=request.sid,
                namespace=ROOM_NAMESPACE,
            )
            return

        room_name = f"job:{job_id}"
        join_room(room_name)
        emit(
            "collab_joined",
            {"job_id": job_id, "username": username},
            room=room_name,
            namespace=ROOM_NAMESPACE,
        )

    @socketio.on("leave_analysis", namespace=ROOM_NAMESPACE)
    def leave_analysis_session(data):
        payload = _normalise_payload(data)
        job_id = str(payload.get("job_id") or "").strip()
        username = str(payload.get("username") or "anonymous").strip()
        if not job_id:
            return
        room_name = f"job:{job_id}"
        leave_room(room_name)
        emit(
            "collab_left",
            {"job_id": job_id, "username": username},
            room=room_name,
            namespace=ROOM_NAMESPACE,
        )

    @socketio.on("analysis_update", namespace=ROOM_NAMESPACE)
    def relay_analysis_update(data):
        payload = _normalise_payload(data)
        job_id = str(payload.get("job_id") or "").strip()
        if not job_id:
            emit(
                "collab_error",
                {"error": "job_id is required for updates"},
                room=request.sid,
                namespace=ROOM_NAMESPACE,
            )
            return

        room_name = f"job:{job_id}"
        update = {
            "job_id": job_id,
            "username": payload.get("username", "system"),
            "message": payload.get("message"),
            "progress": payload.get("progress"),
            "timestamp": payload.get("timestamp"),
        }
        emit("analysis_update", update, room=room_name, namespace=ROOM_NAMESPACE)

    @socketio.on("typing", namespace=ROOM_NAMESPACE)
    def relay_typing_event(data):
        payload = _normalise_payload(data)
        job_id = str(payload.get("job_id") or "").strip()
        if not job_id:
            return
        emit(
            "typing",
            {
                "job_id": job_id,
                "username": payload.get("username", "anonymous"),
                "is_typing": bool(payload.get("is_typing", True)),
            },
            room=f"job:{job_id}",
            namespace=ROOM_NAMESPACE,
        )


__all__ = ["register_collaboration_handlers", "ROOM_NAMESPACE"]

