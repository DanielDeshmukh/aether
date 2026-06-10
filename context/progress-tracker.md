# Progress Tracker

## Current Phase

- ✅ **COMPLETED**: Supabase Removal & Custom Auth Migration
  - Replaced Supabase Auth with custom JWT-based authentication (PyJWT)
  - Created `backend/app/services/auth.py` — JWT issuance, magic link tokens, Google OAuth exchange
  - Created `backend/app/services/email.py` — aiosmtplib-based magic link email delivery
  - Created `backend/app/api/auth_routes.py` — `/api/v1/auth/*` endpoints (magic-link, verify, google, refresh, me)
  - Created `frontend/src/lib/auth.js` — Custom auth client (localStorage tokens, auto-refresh)
  - Created `frontend/src/pages/AuthCallback.jsx` — OAuth/magic link callback handler
  - Updated `backend/app/api/deps.py` — Local JWT decode replaces Supabase SDK auth
  - Updated `backend/app/services/storage.py` — Removed Supabase SDK vars, added `users` and `magic_links` tables
  - Updated `frontend/src/pages/Dashboard.jsx` — Supabase Realtime replaced with `/ws/dashboard` WebSocket
  - Updated `frontend/src/pages/ScanDetail.jsx` — Direct API calls replace Supabase queries
  - Updated `frontend/src/components/SidebarTelemetry.jsx` — API calls replace Supabase queries
  - Deleted `backend/app/orchestrator/storage.py` — Legacy Supabase SDK storage path
  - Deleted `backend/app/services/aether_storage.py` — Legacy storage consolidation
  - Deleted `backend/app/api/aether_routes.py` — Legacy route consolidation
  - Deleted `frontend/src/lib/supabaseClient.js` — Replaced by `auth.js`
  - Removed `@supabase/supabase-js` from frontend dependencies
  - Removed `supabase` from backend requirements.txt
  - Updated all `.env.example` files, `vite.config.js`, `check-env.mjs`, `docker-compose.yml`
  - Updated all context documentation to reflect the new architecture

## Current Goal

- Finalized Aether core with Attack Surface Orchestrator and Heuristic Engine.

## Completed

- React SPA routes for landing, auth, home, dashboard, and scan debrief flows are in place.
- Custom JWT authentication is wired on the frontend and bearer-token auth is enforced for backend scan APIs.
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
- **Target Registration with Upsert Pattern**: Get-or-create targets with user_id tracking
- **Supabase Removal**: Complete migration to custom JWT auth and direct PostgreSQL (psycopg)

## In Progress

- Frontend wiring for Git pull-request remediation actions.

## Next Up

- **Phase 15: Dashboard and Debrief Responsiveness** — Audit dashboard and debrief responsiveness on smaller breakpoints (mobile/tablet) per project definition of done.
  - Test dashboard on mobile breakpoints (320px, 768px, 1024px)
  - Test debrief view on smaller screens
  - Optimize layout and component sizing
  - Ensure all scan data is readable and functional on mobile devices

## Open Questions

- Is the NVIDIA orchestration path intended to be the default production path or a guarded experimental mode?
- Should the target registration trigger any initial domain verification automatically, or remain a manual flow?
