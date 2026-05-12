# Progress Tracker

## Current Phase

- ✅ **COMPLETED**: Target Registration with Upsert (Get-or-Create) Pattern
  - Implemented `get_or_create_target()` method in `ScanStorage` class
  - Enforces database schema compliance with NOT NULL `user_id` field
  - Integrated into `create_scan` endpoint with proper error handling
  - Full unit test coverage with 5 tests (all passing)
  - API endpoint tests updated and passing

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
- **Target Registration with Upsert Pattern**: Get-or-create targets with user_id tracking (NEW)

## In Progress

- Documentation alignment so the context pack reflects the live repository instead of templates.
- Frontend wiring for Git pull-request remediation actions.

## Next Up

- **Phase 15: Dashboard and Debrief Responsiveness** — Audit dashboard and debrief responsiveness on smaller breakpoints (mobile/tablet) per project definition of done.
  - Test dashboard on mobile breakpoints (320px, 768px, 1024px)
  - Test debrief view on smaller screens
  - Optimize layout and component sizing
  - Ensure all scan data is readable and functional on mobile devices

## Open Questions

- Should `AetherStorage` and `aether_routes.py` remain supported, or should the project standardize entirely on `ScanStorage` plus `backend/main.py`?
- Is the NVIDIA orchestration path intended to be the default production path or a guarded experimental mode?
- Should the target registration trigger any initial domain verification automatically, or remain a manual flow?
