# Architecture Context

## Stack

| Layer | Technology | Role |
| --- | --- | --- |
| Frontend framework | React 19 + Vite + React Router | Marketing pages, authenticated operator UI, live console, dashboard routes |
| Styling | Tailwind CSS + custom utility classes | Lamborghini-inspired dark theme and panel/button shapes |
| Auth | Custom JWT Auth (PyJWT) | Google OAuth and magic-link authentication, frontend session source |
| Backend framework | FastAPI + WebSockets | Scan APIs, live streaming, report download, remediation socket |
| Persistence | PostgreSQL via `psycopg` with direct SQL | Stores scans, sessions, findings, profiles, consent logs, target verification data |
| Browser automation | Playwright | Tech stack recon, validation lanes, PDF generation |
| AI orchestration | NVIDIA NIM via OpenAI-compatible API | Initial planning (nemotron-3-super-120b), final verdicts, remediation generation (nemotron-super-49b-v1.5), content safety (nemotron-3-nano), OWASP validation (nemotron-3-super-120b) |
| Network tooling | `httpx`, `requests`, custom validators | Safety checks, preflight requests, verification, service integrations |

## System Boundaries

- `frontend/src/`
  Owns the customer-facing SPA: landing experience, auth handoff, scan launch workflow, live console, dashboard, and scan debrief screens.
- `backend/main.py`
  Owns the main FastAPI application, REST routes, WebSocket endpoints, scan session lifecycle, PDF generation, and top-level wiring.
- `backend/app/orchestrator/`
  Owns the reasoning loop, execution phases, NVIDIA validation path, remediation generation, and scan-state serialization.
- `backend/app/services/`
  Owns persistence, domain verification, log monitoring, storage helpers, and Git remediation integration.
- `backend/app/engine/`
  Owns Playwright safety helpers and active validation lane logic.
- `backend/app/tools/`
  Owns bounded scan utilities like port scan, header audit, audit engine, URL validation, and remediation lookup helpers.
- `backend/tests/`
  Owns regression coverage for quota guards, validation lanes, privacy/safety rules, persistence behavior, and hardening phases.

## Runtime Shape

- The frontend authenticates with custom JWT auth and sends bearer tokens to the backend.
- `POST /api/v1/scans` creates an in-memory active scan entry after auth, quota, consent, and SSRF validation.
- `/ws/scan/{scan_id}` drives the main operator experience by streaming plan, execute, analyze, and remediation-related events.
- `BrainOrchestrator` is the default hunt loop for planning, bounded audits, and verdict generation.
- `AttackOrchestrator` is the stricter active-validation path for allowlisted hosts and Playwright-backed OWASP lane checks.
- Completed scans are read back through REST and WebSocket endpoints.

## Storage Model

- **`public.scans`**: Primary persisted scan record with `target_url`, `status`, `threat_level`, `initial_plan`, `thought_trace`, `results`, `final_report`, and `remediations`.
- **`public.scan_sessions`**: Session-level metadata for execution windows and scan lifecycle timing.
- **`public.vulnerabilities`**: Persisted findings including category, title, severity, evidence, and remediation-related fields.
- **`public.profiles`**: Profiler and auxiliary rows attached to a scan, including NVIDIA loop metadata and fallback profiles.
- **`public.consent_logs`**: Pre-scan consent evidence including target URL, user identity, timestamp, and source IP.
- **`public.targets`**: Expected ownership-verification source for domain checks and Git remediation target metadata.

## Auth And Access Model

- Frontend auth state comes from custom JWT tokens stored in localStorage.
- Backend REST APIs expect `Authorization: Bearer <token>` and resolve the user through JWT validation.
- Scan records are tenant-scoped by `user_id`; list, fetch, remediation persistence, and report download paths all check user ownership.
- Active validation requires both an authenticated user and a verified target record.

## Invariants

1. No scan should begin unless consent is confirmed and the request is tied to an authenticated user.
2. Active validation must stay bounded to verified targets, and the NVIDIA path must refuse non-allowlisted hosts.
3. Scan persistence is the source of truth for dashboard and debrief views; plan, results, and final report data must be serializable into `public.scans`.
4. SSRF and private-network targets must be blocked before browser automation or network probing starts.
5. Quota enforcement and rate limiting must run before the engine is allowed to consume scan capacity.
6. Findings and remediation data must remain scoped to the owning `user_id` and `scan_id`.

## Current Status Notes

- The legacy `AetherStorage` and `aether_routes.py` have been fully removed. All storage now goes through the modern `ScanStorage` class in `backend/app/services/storage.py`.
- `backend/app/api/main.py` and `backend/app/api/deps.py` are clean with no merge markers.
- The frontend exposes a pull-request remediation action, but the remediation WebSocket handler currently only handles `generate_fix`, so Git PR support is not fully wired end to end.
