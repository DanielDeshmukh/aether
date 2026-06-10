"""Compatibility entrypoint for legacy tooling that imports ``backend.main``."""

from app.api.main import app, persist_scan_state, scan_storage
