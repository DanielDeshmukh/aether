# Progress Tracker

## Current Phase

- Completed: Hardened MVP with implemented quota, SSRF, verification, persistence, dashboard, and finalized orchestrator/engine foundations.

## Current Goal

- Finalized Aether core with Attack Surface Orchestrator and Heuristic Engine.

## Completed

- React SPA routes for landing, auth, home, dashboard, and scan debrief flows are in place.
- Supabase authentication is wired on the frontend and bearer-token auth is enforced for backend scan APIs.
- Scan creation flow enforces consent confirmation before the hunt starts.
- Backend persistence exists for scans, sessions, vulnerabilities, profiles, and consent logs.
- Dashboard list and scan detail debrief views are implemented.
- PDF report download flow is implemented.
- Quota guard for the MVP three-scan limit is implemented and covered by tests.
- SSRF/private-network blocking is implemented and covered by tests.
- Domain verification service is implemented and used before active validation.
- Validation lanes exist for bounded XSS and injection confirmation on verified/allowlisted targets.
- Remediation generation flow exists through the remediation WebSocket path.
- Resolved backend merge markers in `backend/main.py` and `backend/app/api/deps.py`.
- Implemented `AETHER-Shield` middleware for safety handshake and token validation.
- Implemented `Intent-Router` for deterministic schema-based routing of scan intents.
- Formalized `HeuristicEngine` with deep sensitive file and CORS checks.
- Refactored `AttackOrchestrator` into a full Attack Surface Orchestrator.
- Integrated `create_pull_request` in the remediation WebSocket handler.

## In Progress

- Documentation alignment so the context pack reflects the live repository instead of templates.
- Frontend wiring for Git pull-request remediation actions.

## Next Up

- Audit dashboard and debrief responsiveness on smaller breakpoints per project definition of done.

## Open Questions

- Should `AetherStorage` and `aether_routes.py` remain supported, or should the project standardize entirely on `ScanStorage` plus `backend/main.py`?
- Is the NVIDIA orchestration path intended to be the default production path or a guarded experimental mode?
