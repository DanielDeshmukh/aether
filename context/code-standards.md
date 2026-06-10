# Code Standards

## General

- Keep the scan pipeline explicit: auth, consent, safety validation, orchestration, persistence, and reporting should stay readable as separate responsibilities.
- Prefer defensive defaults. If a target, token, schema, or external AI dependency is missing, fail closed or degrade to a bounded fallback.
- Fix the real boundary, not the symptom. Security checks belong at request and orchestration boundaries, not only in UI copy.
- Preserve tenant isolation for every persisted scan artifact.

## Python And FastAPI

- Validate request bodies with Pydantic models before running scan logic.
- Keep route handlers thin; orchestration belongs in `app/orchestrator`, persistence in `app/services`, and low-level utilities in `app/tools` or `app/engine`.
- Raise structured `HTTPException` values for user-facing failures and log the underlying cause on the server.
- Long-running or staged scan work should stream over WebSockets instead of blocking a single synchronous request.
- Security-sensitive helpers such as URL validation, quota checks, and verification checks should remain reusable and testable in isolation.

## React

- Pages own route composition; reusable UI and workflow primitives belong in `frontend/src/components`.
- Network access that depends on JWT auth should go through shared helpers like `apiRequest` or `buildWsUrl`.
- State should stay local to the active workflow unless multiple screens truly share it.
- Keep the authenticated UI aligned with the existing dark operator-console design system rather than introducing generic component-library patterns.

## Styling

- Reuse the existing root color tokens in `frontend/src/index.css` where possible.
- Prefer the established `chamfer-panel`, `chamfer-button`, and `chamfer-badge` shapes for core operator surfaces.
- Treat Lamborghini-style gold as the primary CTA accent, with green for live/success and red for hard failures.
- Dashboard and debrief views must remain mobile-safe.

## API And WebSocket Contracts

- Authenticated REST routes should expect JWT bearer tokens and resolve the owning user before touching persisted resources.
- Scan creation must enforce quota, consent confirmation, and SSRF safety before allocating engine work.
- WebSocket payloads should keep predictable keys such as `type`, `phase`, `msg`, and `brain` so the console UI stays stable.
- Persisted scan data must remain serializable to JSON because the frontend reads `initial_plan`, `results`, `final_report`, and `remediations` directly.

## Data And Storage

- `public.scans` is the canonical scan record used by dashboard and debrief screens.
- `public.vulnerabilities`, `public.profiles`, `public.scan_sessions`, and `public.consent_logs` are supporting tables and should remain relationally consistent with the parent scan.
- Use UUID normalization consistently when mapping frontend scan ids to database records.
- Do not bypass ownership checks when fetching scans, findings, profiles, or remediation payloads.

## Testing

- Backend changes should extend the existing `backend/tests` suite around quota guards, safety gates, persistence, verification, and orchestration behavior.
- Per repository protocol, every new backend function should be considered for unit coverage under `tests`.
- High-risk areas are quota enforcement, SSRF validation, domain verification, persistence relations, and WebSocket failure handling.

## File Organization

- `frontend/src/pages/` contains route-level screens.
- `frontend/src/components/` contains reusable UI and workflow components.
- `frontend/src/lib/` contains frontend integration helpers such as API, WebSocket, and auth client setup.
- `backend/app/orchestrator/` contains reasoning, execution, remediation, and agent loop logic.
- `backend/app/services/` contains persistence, verification, monitoring, and integration services.
- `backend/app/tools/` and `backend/app/engine/` contain lower-level scan and validation helpers.

## Implemented Conventions

- AETHER-Shield middleware and Intent-Router conventions are implemented in `backend/app/api/shield.py` and `backend/app/orchestrator/intent_router.py`.
- The active persistence path follows the `ScanStorage` and `persist_full_pipeline` patterns in `backend/main.py`.

## Current Gaps To Respect

- There are parallel storage/auth paths in the backend; when documenting or extending behavior, treat `backend/main.py` plus `ScanStorage` as the main active path and call out legacy pieces explicitly.
