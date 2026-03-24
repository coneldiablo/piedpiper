"""
ThreatInquisitor REST API package.

This module exposes the Flask application factory for the public API.
"""

from .server import create_app, socketio  # noqa: F401

