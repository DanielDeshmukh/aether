# Progress Tracker

## Current Phase

- In progress: Hardened MVP with implemented quota, SSRF, verification, persistence, dashboard, and remediation foundations.

## Current Goal

- Stabilize the active architecture around the authenticated scan loop, persisted debrief experience, and defensive validation controls while cleaning remaining integration mismatches.

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

## In Progress

- Backend cleanup between the modern `ScanStorage` path and older `AetherStorage` or `aether_routes.py` path.
- Merge-conflict resolution in `backend/main.py` and `backend/app/api/deps.py`.
- End-to-end Git remediation PR flow. Frontend exposes the action, but the current remediation WebSocket handler does not yet process `create_pull_request`.
- Documentation alignment so the context pack reflects the live repository instead of templates.

## Next Up

- Resolve the backend merge markers and choose one canonical auth/storage path.
- Finish wiring Git pull-request remediation or remove the exposed frontend action until supported.
- Audit dashboard and debrief responsiveness on smaller breakpoints per project definition of done.
- Confirm whether AETHER-Shield middleware and Hector-style Intent-Router conventions need to be introduced as code or remain protocol-only guidance.

## Open Questions

- Should `AetherStorage` and `aether_routes.py` remain supported, or should the project standardize entirely on `ScanStorage` plus `backend/main.py`?
- Is the NVIDIA orchestration path intended to be the default production path or a guarded experimental mode?
- Should the frontend continue reading some records directly from Supabase while other actions go through FastAPI, or should all authenticated data access move behind the backend?
- How should the AGENTS protocol requirements for AETHER-Shield and Intent-Router map onto the current implementation?

## Architecture Decisions

- The main persisted source of truth is `public.scans`, with supporting relational tables for sessions, vulnerabilities, profiles, and consent logs.
- Scan execution is streamed over WebSockets so the operator can watch reasoning and react to plan-hold states without waiting for a blocking HTTP response.
- Domain verification is enforced before active browser-based validation to reduce misuse risk.
- The frontend keeps a dark luxury-console visual language built from custom React components and Tailwind, not a third-party component kit.

## Session Notes

- `MISSION_GOALS.md` describes the intended hardened-MVP direction and is broadly reflected in the current codebase.
- The repo currently contains visible implementation mismatches, so future sessions should verify whether they are intended branches-in-progress or accidental unresolved conflicts before making backend changes.
- Context docs were refreshed from current source code and should now be treated as status documentation, not blank templates.
