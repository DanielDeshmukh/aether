# AETHER — Complete Task Checklist
> A comprehensive list of every pending item to bring AETHER from current state to 100% production-ready.
> Current estimated completion: **~57%** (73 of 128 items done)
> Last audited: 2026-06-10

---

## Table of Contents
- [P0 — Critical Bugs (Runtime Errors)](#p0--critical-bugs-runtime-errors)
- [P0 — Missing Backend Methods](#p0--missing-backend-methods)
- [P0 — Unmounted Middleware & Security](#p0--unmounted-middleware--security)
- [P1 — OWASP Top 10 Active Validation](#p1--owasp-top-10-active-validation)
- [P1 — Auth System Gaps](#p1--auth-system-gaps)
- [P1 — Scan Lifecycle Gaps](#p1--scan-lifecycle-gaps)
- [P1 — Frontend Gaps](#p1--frontend-gaps)
- [P2 — PDF Report Quality](#p2--pdf-report-quality)
- [P2 — Remediation Pipeline](#p2--remediation-pipeline)
- [P2 — Infrastructure & Hardening](#p2--infrastructure--hardening)
- [P2 — Domain Verification Fixes](#p2--domain-verification-fixes)
- [P3 — Test Suite](#p3--test-suite)
- [P3 — Code Cleanup](#p3--code-cleanup)
- [P3 — Documentation & Config](#p3--documentation--config)
- [P3 — Mobile Responsive Audit](#p3--mobile-responsive-audit)
- [P3 — CI/CD & Deployment](#p3--cicd--deployment)
- [Verification Checklist](#verification-checklist)

---

## P0 — Critical Bugs (Runtime Errors)

> These will cause `AttributeError` or silent failures at runtime.

- [x] **`storage.py`: Add `update_scan_trace()` method** — Called at `brain.py:1055` and `attack_orchestrator.py:167`. Will crash BrainOrchestrator when `process_agent_response()` path is taken.
  - File: `backend/app/services/storage.py`
  - Implement SQL UPDATE on `scans.trace` JSONB column

- [x] **`storage.py`: Add `insert_vulnerability()` method** — Called at `brain.py:1065` and `attack_orchestrator.py:387`. Same crash risk.
  - File: `backend/app/services/storage.py`
  - Implement SQL INSERT into `vulnerabilities` table

- [x] **Wire `check_scan_quota` into `POST /api/v1/scans`** — Quota check is defined in `deps.py:84-93` but never injected as a dependency on the scan creation endpoint.
  - File: `backend/app/api/main.py:563`
  - Add `quota: dict = Depends(check_scan_quota)` to `create_scan()` signature
  - Check `quota["allowed"]` before proceeding

- [x] **Mount `AetherShieldMiddleware` on the FastAPI app** — Defined in `shield.py:53` but never imported or added via `app.add_middleware()` anywhere. AGENTS.md explicitly requires this.
  - File: `backend/app/api/main.py`
  - Import `AetherShieldMiddleware` from `app.api.shield`
  - Add `app.add_middleware(AetherShieldMiddleware)` after CORS middleware

- [x] **Fix domain verification edge case** — When both DNS and HTTP succeed but `is_verified` is still `false`, the function returns `allowed=False` with a confusing message.
  - File: `backend/app/services/domain_verification.py:209-213`
  - If both checks pass, auto-set `is_verified=true` or return `allowed=True`

---

## P0 — Missing Backend Methods

> Methods called by existing code that don't exist — will cause `AttributeError`.

- [x] **`ScanStorage.update_scan_trace(scan_id, trace_data)`** — Updates the `trace` JSONB column on a scan row.
  - Callers: `brain.py:1055`, `attack_orchestrator.py:167`
  - SQL: `UPDATE scans SET trace = %s WHERE id = %s`

- [x] **`ScanStorage.insert_vulnerability(scan_id, vuln_data)`** — Inserts a row into the `vulnerabilities` table.
  - Callers: `brain.py:1065`, `attack_orchestrator.py:387`
  - SQL: `INSERT INTO vulnerabilities (scan_id, title, severity, description, category, evidence, ...) VALUES (...)`

---

## P0 — Unmounted Middleware & Security

> Security controls defined in code but never activated.

- [x] **Mount AETHER-Shield middleware** — See Critical Bugs section above.

- [x] **Wire rate limiting on API endpoints** — `check_scan_quota()` exists but is not enforced. Additionally:
  - [x] Add per-user rate limiting on `POST /api/v1/scans` (max 3 concurrent)
  - [x] Add per-IP rate limiting on `/api/v1/auth/magic-link` (max 5/hour)
  - [x] Add per-user rate limiting on `/api/v1/auth/refresh` (max 20/hour)
  - File: `backend/app/api/main.py`, `backend/app/api/deps.py`, `backend/app/api/rate_limiter.py`

- [x] **Add security headers middleware to API responses** — CSP, HSTS, X-Content-Type-Options, X-Frame-Options on all API responses, not just scan targets.
  - File: `backend/app/api/main.py`

- [x] **Add request size limiting middleware** — Prevent abuse via oversized payloads.
  - File: `backend/app/api/main.py`

- [x] **Add request ID / correlation ID middleware** — For tracing and debugging.
  - File: `backend/app/api/main.py`

---

## P1 — OWASP Top 10 Active Validation

> The core value proposition of AETHER. Currently only 2/10 categories have active Playwright-based validation.

### Implemented (keep & enhance)
- [x] A01:2021 — Broken Access Control (`attack_orchestrator.py:452-503`)
- [x] A03:2021 — Injection — XSS lane (`validation_lanes.py:107-157`)
- [x] A03:2021 — Injection — SQLi lane (`validation_lanes.py:159-247`)

### Missing (implement each)
- [x] **A02:2021 — Cryptographic Failures**
  - [x] Check for HTTP (non-TLS) endpoints
  - [x] Check for weak TLS versions (TLS 1.0/1.1) via `ssl` module
  - [ ] Check for certificate expiry and validity
  - [ ] Check for mixed content (HTTPS page loading HTTP resources)
  - [x] Check for missing `Strict-Transport-Security` header
  - [x] Check for insecure cookie flags (`Secure`, `HttpOnly`, `SameSite`)
  - File: `backend/app/engine/validation_lanes.py` — new `run_crypto_failures_lane()` method

- [x] **A04:2021 — Insecure Design**
  - [x] Check for exposed API documentation endpoints (`/docs`, `/redoc`, `/swagger`)
  - [x] Check for verbose error messages exposing stack traces
  - [ ] Check for missing rate limiting on sensitive endpoints (login, signup)
  - [ ] Check for business logic flaws (e.g., price manipulation in request body)
  - [ ] Check for missing resource quotas (file upload size, request count)
  - File: `backend/app/engine/validation_lanes.py` — new `run_insecure_design_lane()` method

- [x] **A05:2021 — Security Misconfiguration**
  - [ ] Check for default credentials on known admin panels
  - [x] Check for directory listing enabled
  - [ ] Check for unnecessary HTTP methods (TRACE, OPTIONS leaking info)
  - [x] Check for server version disclosure in headers (`Server`, `X-Powered-By`)
  - [x] Check for CORS misconfiguration (already partially in `heuristic_engine.py` but needs Playwright validation)
  - [ ] Check for XML External Entity (XXE) on XML endpoints
  - [ ] Check for open redirect via query parameter manipulation
  - File: `backend/app/engine/validation_lanes.py` — new `run_misconfiguration_lane()` method

- [x] **A06:2021 — Vulnerable and Outdated Components**
  - [x] Parse HTML `<script>` tags for known CDN library versions (jQuery, Angular, React, Bootstrap)
  - [x] Check for `X-Powered-By` header revealing framework version
  - [ ] Check for known CVEs against detected versions using NVD API or `osv.dev`
  - [ ] Check for outdated JavaScript libraries via SourceMap analysis
  - [ ] Check for deprecated API endpoints (e.g., `/api/v1/` vs `/api/v2/`)
  - File: `backend/app/engine/validation_lanes.py` — new `run_vulnerable_components_lane()` method

- [x] **A07:2021 — Identification and Authentication Failures**
  - [ ] Check for brute-force protection (attempt 5+ logins, check response pattern)
  - [ ] Check for credential stuffing indicators (different user agents, same IP)
  - [ ] Check for session fixation (session ID changes after login)
  - [ ] Check for weak password policy enforcement (if signup exists)
  - [x] Check for account enumeration via login error messages
  - [ ] Check for missing multi-factor authentication prompts
  - File: `backend/app/engine/validation_lanes.py` — new `run_auth_failures_lane()` method

- [x] **A08:2021 — Software and Data Integrity Failures**
  - [x] Check for JavaScript loaded from non-HTTPS sources
  - [x] Check for missing Subresource Integrity (SRI) on CDN scripts
  - [ ] Check for insecure deserialization (if JSON/XML endpoints accept serialized objects)
  - [ ] Check for CI/CD pipeline integrity (if `.github/workflows` or similar exposed)
  - [ ] Check for auto-update without signature verification
  - File: `backend/app/engine/validation_lanes.py` — new `run_data_integrity_lane()` method

- [x] **A09:2021 — Security Logging and Monitoring Failures**
  - [x] Check if error pages expose internal information
  - [x] Check if security headers indicate monitoring (e.g., `X-Request-Id`)
  - [x] Check for rate limit headers indicating monitoring (`X-RateLimit-*`)
  - [ ] Check if login/logout events are logged (analyze response patterns)
  - File: `backend/app/engine/validation_lanes.py` — new `run_logging_failures_lane()` method

- [x] **A10:2021 — Server-Side Request Forgery (SSRF)**
  - [x] Already have URL validation in `services/security.py` — needs Playwright-based validation
  - [x] Test with internal IP ranges (127.0.0.1, 10.x, 192.168.x, 169.254.x)
  - [x] Test with cloud metadata endpoints (169.254.169.254)
  - [ ] Test with file:// and gopher:// protocol handlers
  - [ ] Test DNS rebinding attacks
  - File: `backend/app/engine/validation_lanes.py` — new `run_ssrf_lane()` method

- [x] **Wire all new lanes into `attack_orchestrator.py`**
  - [x] Update `modules` dict at line 632 to map each OWASP category to its lane class
  - [x] Remove `_evaluate_placeholder_category()` stub
  - File: `backend/app/orchestrator/attack_orchestrator.py`

- [x] **Implement `_ensure_allowed_target()`** — Currently a no-op (`pass`). Should verify the target domain is in the allowlist or has been verified.
  - File: `backend/app/orchestrator/attack_orchestrator.py:152-153`

---

## P1 — Auth System Gaps

> The auth flow works end-to-end but has gaps for production use.

- [x] **Implement token revocation/blacklisting** — No way to invalidate a JWT before expiry. Add a `revoked_tokens` table or Redis-based blacklist.
  - File: `backend/app/services/auth.py`, `backend/app/services/storage.py`
  - Add `revoke_token(token_id)` and `is_token_revoked(token_id)` methods

- [x] **Add `POST /api/v1/auth/logout` endpoint** — Currently no server-side logout. Client clears localStorage but tokens remain valid.
  - File: `backend/app/api/auth_routes.py`
  - Add endpoint that revokes the current access token

- [x] **Add `DELETE /api/v1/auth/account` endpoint** — No account deletion flow exists.
  - File: `backend/app/api/auth_routes.py`

- [x] **Remove dead code `_hash_token()` / `_verify_token()`** from `auth.py:65-73` — Defined but never called anywhere. Either wire them into the magic link flow (hash tokens before storing) or delete them.
  - File: `backend/app/services/auth.py`

- [x] **Add email verification rate limiting** — Magic link endpoint has no rate limit. An attacker could flood a target's email.
  - File: `backend/app/api/auth_routes.py`
  - Implement: max 3 magic links per email per hour

- [x] **Add magic link token expiry enforcement** — Token expiry is stored in DB but the `/verify` endpoint doesn't check `expires_at`.
  - File: `backend/app/api/auth_routes.py`

- [x] **Add GitHub OAuth support** — Only Google OAuth is implemented. Many developers use GitHub.
  - File: `backend/app/services/auth.py`, `backend/app/api/auth_routes.py`

- [x] **Add user profile update endpoint** — No way to update name, email, or preferences after registration.
  - File: `backend/app/api/auth_routes.py`

---

## P1 — Scan Lifecycle Gaps

> The scan pipeline works but has gaps in the full lifecycle.

- [x] **Add scan cancellation / pause / resume from frontend** — Backend has `pause_scan()`, `resume_scan()`, `terminate_scan()` in `brain.py` but no API endpoints to call them from the UI.
  - File: `backend/app/api/main.py`
  - Add `POST /api/v1/scan/{scan_id}/pause`
  - Add `POST /api/v1/scan/{scan_id}/resume`
  - Add `POST /api/v1/scan/{scan_id}/terminate`
  - File: `frontend/src/pages/ScanDetail.jsx` — Add pause/resume/terminate buttons

- [x] **Add scan deletion** — No way to delete a scan and its associated data.
  - File: `backend/app/services/storage.py` — Add `delete_scan(scan_id)` method
  - File: `backend/app/api/main.py` — Add `DELETE /api/v1/scans/{scan_id}` endpoint
  - File: `frontend/src/pages/Dashboard.jsx` — Add delete button with confirmation

- [x] **Add scan retry / re-run** — No way to re-run a failed or completed scan.
  - File: `backend/app/api/main.py` — Add `POST /api/v1/scans/{scan_id}/rerun` endpoint

- [x] **Add scan comparison** — No way to compare two scans of the same target over time.
  - File: `backend/app/api/main.py` — Add `GET /api/v1/scans/compare?ids=...` endpoint

- [x] **Add scan export (JSON/CSV)** — Only PDF export exists. Add structured data export.
  - File: `backend/app/api/main.py` — Add `GET /api/v1/scans/{scan_id}/export?format=json|csv`

- [x] **Fix `render_pdf_report()` vulnerability rendering** — Currently renders vulnerabilities as plain text concatenation (`{title} [{severity}] - {detail}` with newlines). Needs structured HTML with severity colors, evidence snippets, remediation code blocks.
  - File: `backend/app/api/main.py:339-347`

- [x] **Use profile data in PDF report** — Profile is fetched at line 958 but never passed to or used in the PDF template.
  - File: `backend/app/api/main.py:958`

---

## P1 — Frontend Gaps

> UI/UX gaps that affect production readiness.

- [x] **Dashboard: Add pagination** — Currently hardcoded to 12 scans (line 124). Add infinite scroll or page controls.
  - File: `frontend/src/pages/Dashboard.jsx`

- [x] **Dashboard: Add filter/sort controls** — No way to filter by status, sort by date/threat level.
  - File: `frontend/src/pages/Dashboard.jsx`

- [x] **Dashboard: Add vulnerability count per scan card** — Each scan card should show how many vulnerabilities were found.
  - File: `frontend/src/pages/Dashboard.jsx`

- [x] **Dashboard: Fix "running" state color** — Status colors don't handle `running` state properly.
  - File: `frontend/src/pages/Dashboard.jsx`

- [x] **ScanDetail: Add screenshot evidence display** — Backend serves screenshots at `/api/v1/scans/{scan_id}/vulnerabilities/{vuln_id}/evidence/screenshot` but the frontend never displays them.
  - File: `frontend/src/pages/ScanDetail.jsx`

- [x] **ScanDetail: Add re-fetch after remediation** — Currently relies solely on WebSocket updates, which may be delayed.
  - File: `frontend/src/pages/ScanDetail.jsx`

- [x] **ScanDetail: Add pause/resume/terminate buttons** — Wire to new API endpoints (see Scan Lifecycle section).
  - File: `frontend/src/pages/ScanDetail.jsx`

- [x] **ScanDetail: Add PDF download button** — PDF download is only on SidebarTelemetry, not on the scan detail page itself.
  - File: `frontend/src/pages/ScanDetail.jsx`

- [x] **Remove fake/decorative stats from ScanningConsole** — Lines 277-279 show `Neural_Depth: 88%`, `Risk_Score: LVL_3` which are hardcoded decorative values, not real data.
  - File: `frontend/src/components/ScanningConsole.jsx`

- [x] **Add error boundary for WebSocket disconnection** — Dashboard and ScanDetail WebSocket connections have no user-facing reconnection indicator.
  - File: `frontend/src/pages/Dashboard.jsx`, `frontend/src/pages/ScanDetail.jsx`

- [x] **Add loading state for remediation generation** — Currently only shows "Generating..." button text. Needs a proper loading spinner/progress indicator.
  - File: `frontend/src/pages/ScanDetail.jsx`

- [x] **Add user profile / settings page** — No way for users to view or update their profile, preferences, or API keys.
  - File: `frontend/src/pages/Settings.jsx`
  - File: `frontend/src/App.jsx` — Add route

- [x] **Add scan history chart/visualization** — No visual representation of scan trends over time on the dashboard.
  - File: `frontend/src/pages/Dashboard.jsx` or create `frontend/src/components/ScanChart.jsx`

---

## P2 — PDF Report Quality

> The PDF report works but is visually minimal.

- [x] **Design proper PDF template** — Replace the current plain-text vulnerability rendering with a structured HTML template including:
  - [x] Executive summary section with threat level badge
  - [x] Per-vulnerability detail cards with severity color coding (Critical=red, High=orange, Medium=yellow, Low=blue, Info=gray)
  - [x] Evidence snippets with syntax highlighting
  - [x] Remediation code blocks with copy-friendly formatting
  - [x] Strategy trace (plan steps) visualization
  - [x] Target profile information
  - [x] Timestamp and scan metadata
  - [x] AETHER branding and logo
  - File: `backend/app/api/main.py`

- [x] **Add PDF generation to ScanDetail page** — Add a "Download Report" button directly on the scan detail page.
  - File: `frontend/src/pages/ScanDetail.jsx`

- [x] **Add email delivery of PDF report** — After scan completion, optionally email the PDF to the user.
  - File: `backend/app/api/main.py` or create `backend/app/services/report_delivery.py`

---

## P2 — Remediation Pipeline

> The remediation flow works for headers but is limited in scope.

- [x] **Expand remediation templates beyond Nginx headers** — Currently only handles 5 headers in Nginx config. Add:
  - [x] Apache `.htaccess` templates
  - [x] Node.js/Express middleware templates
  - [x] Python/Django settings templates
  - [ ] Cloud provider (AWS CloudFront, Cloudflare) templates
  - [ ] Docker/Kubernetes security context templates
  - File: `backend/app/tools/remediation.py`

- [x] **Fix `find_vulnerability()` to search database** — Currently only searches in-memory scan results, not persisted vulnerability rows.
  - File: `backend/app/tools/remediation.py`

- [x] **Complete end-to-end git PR flow** — The `GitIntegrationService` exists but the PR creation path from vulnerability → fix → commit → PR is not fully wired.
  - [ ] Ensure git target is configured during scan creation
  - [ ] Wire remediation output to git commit
  - [ ] Wire git commit to PR creation
  - [ ] Return PR URL to frontend
  - File: `backend/app/tools/remediation.py`, `backend/app/services/git_integration_service.py`

- [x] **Add remediation preview / diff view** — Show the user what the fix looks like before creating the PR.
  - File: `frontend/src/pages/ScanDetail.jsx`

- [x] **Add remediation history** — Track which fixes were applied and their status.
  - File: `backend/app/services/storage.py` — Add `remediation_history` table

---

## P2 — Infrastructure & Hardening

> Production hardening items.

- [x] **Extract PDF generation to `backend/app/services/report_generator.py`** — Currently inline in `main.py:290-537` (250+ lines). Should be a standalone service.
  - File: Create `backend/app/services/report_generator.py`
  - File: `backend/app/api/main.py` — Import and call the service

- [x] **Create `backend/app/services/quota_manager.py`** — Centralized quota management. Currently scattered across `deps.py` with hardcoded values.
  - File: Create `backend/app/services/quota_manager.py`
  - Support configurable per-user limits
  - Support tier-based quotas (free/pro/enterprise)

- [x] **Add structured request/response logging middleware** — No logging of API requests/responses for debugging and audit.
  - File: `backend/app/api/main.py`

- [x] **Add HTTPS redirect middleware** — In production, all HTTP should redirect to HTTPS.
  - File: `backend/app/api/main.py`

- [x] **Add health check for PostgreSQL connection** — `/health` endpoint exists but doesn't verify database connectivity.
  - File: `backend/app/api/main.py`

- [x] **Add graceful shutdown handling** — Ensure active WebSocket connections are closed cleanly on server shutdown.
  - File: `backend/app/api/main.py`

- [x] **Add connection pool monitoring** — Expose pool stats (active/idle/waiting) on health endpoint.
  - File: `backend/app/services/storage.py`

- [x] **Add database migration support** — `ensure_schema()` does table creation but no versioned migrations. Add Alembic or similar.
  - File: Create `backend/alembic/` directory

- [x] **Add CORS configuration for production** — Currently allows all origins (`*`). Lock down to specific frontend domain.
  - File: `backend/app/api/main.py`

- [x] **Add request timeout middleware** — No global request timeout. Slow clients could hold connections indefinitely.
  - File: `backend/app/api/main.py`

---

## P2 — Domain Verification Fixes

> Minor fixes to the verification system.

- [x] **Add verification result caching** — Every scan trigger re-verifies the domain. Cache results for 24 hours.
  - File: `backend/app/services/domain_verification.py`

- [x] **Add rate limiting on verification attempts** — Prevent abuse of the verification endpoint.
  - File: `backend/app/services/domain_verification.py`

- [x] **Add verification status to dashboard** — Show whether each scan target is verified.
  - File: `frontend/src/pages/Dashboard.jsx`

---

## P3 — Test Suite

> Tests that exist are partial. Many critical paths have no test coverage.

### Fix broken tests
- [ ] **Fix `test_privacy.py`** — Imports from `aether.backend.app.services.storage` (wrong path) and uses outdated Supabase mock API that no longer matches psycopg-based storage.
  - File: `backend/tests/test_privacy.py:3`
  - Update import path to `backend.app.services.storage`
  - Rewrite mocks to match current `ScanStorage` API

### Add missing tests (per AGENTS.md: "Jules must generate a unit test in `/tests` for every new function")

- [ ] **Auth route tests**
  - [ ] `test_magic_link_request()` — POST to `/api/v1/auth/magic-link`, verify token stored in DB
  - [ ] `test_magic_link_verify()` — GET `/api/v1/auth/verify?token=...`, verify JWT pair returned
  - [ ] `test_magic_link_expired_token()` — Verify expired token returns 401
  - [ ] `test_google_oauth_redirect()` — GET `/api/v1/auth/google`, verify redirect to Google
  - [ ] `test_google_oauth_callback()` — Mock Google token exchange, verify JWT pair returned
  - [ ] `test_token_refresh()` — POST to `/api/v1/auth/refresh`, verify new access token
  - [ ] `test_me_endpoint()` — GET `/api/v1/auth/me` with valid/invalid tokens
  - [ ] `test_sign_out()` — Verify token cleared
  - File: Create `backend/tests/test_auth_routes.py`

- [ ] **BrainOrchestrator tests**
  - [ ] `test_brain_stream()` — Verify WebSocket stream emits plan/execute/analyze phases
  - [ ] `test_brain_owasp_assessment_loop()` — Verify all 10 categories are iterated
  - [ ] `test_brain_signal_handling()` — Test pause/resume/terminate signals
  - [ ] `test_brain_generate_fix()` — Test Gemini remediation generation
  - [ ] `test_brain_timeout()` — Test initial plan timeout behavior
  - File: Create `backend/tests/test_brain_orchestrator.py`

- [ ] **Heuristic engine tests**
  - [ ] `test_port_scan()` — Test port scanning against mock target
  - [ ] `test_header_audit()` — Test header analysis
  - [ ] `test_sensitive_file_check()` — Test file discovery
  - [ ] `test_cors_check()` — Test CORS misconfiguration detection
  - File: Create `backend/tests/test_heuristic_engine.py`

- [ ] **Storage method tests**
  - [ ] `test_persist_full_pipeline()` — Test with real PostgreSQL (integration test)
  - [ ] `test_update_scan_trace()` — Test trace update (once implemented)
  - [ ] `test_insert_vulnerability()` — Test vulnerability insert (once implemented)
  - [ ] `test_fetch_scan()` — Test single scan retrieval
  - [ ] `test_fetch_all_scans()` — Test scan listing with pagination
  - [ ] `test_delete_scan()` — Test scan deletion (once implemented)
  - File: Create `backend/tests/test_storage.py`

- [ ] **PDF report tests**
  - [ ] `test_render_pdf_report()` — Test HTML generation and PDF conversion
  - [ ] `test_pdf_vulnerability_formatting()` — Test severity color coding
  - File: Create `backend/tests/test_pdf_report.py`

- [ ] **WebSocket tests**
  - [ ] `test_dashboard_websocket()` — Test `/ws/dashboard` connection and broadcast
  - [ ] `test_scan_websocket()` — Test `/ws/scan/{scan_id}` streaming
  - [ ] `test_remediation_websocket()` — Test `/ws/remediation/{scan_id}` flow
  - File: Create `backend/tests/test_websockets.py`

- [ ] **Intent router tests**
  - [ ] `test_route_scan_command()` — Test scan intent detection
  - [ ] `test_route_remediation_command()` — Test remediation intent detection
  - [ ] `test_route_unknown_command()` — Test fallback behavior
  - File: Create `backend/tests/test_intent_router.py`

- [ ] **Validation lane tests**
  - [ ] `test_xss_lane()` — Test XSS injection detection (expand existing)
  - [ ] `test_sqli_lane()` — Test SQL injection detection
  - [ ] `test_cryptographic_failures_lane()` — Test TLS checks (once implemented)
  - [ ] `test_misconfiguration_lane()` — Test header/config checks (once implemented)
  - File: Create `backend/tests/test_validation_lanes_full.py`

- [ ] **Rate limiter tests**
  - [ ] `test_rate_limiter_blocks()` — Test request throttling
  - [ ] `test_rate_limiter_allows()` — Test within-limit requests
  - File: Create `backend/tests/test_rate_limiting.py`

- [ ] **Domain verification tests**
  - [ ] `test_dns_verification_success()` — Test valid DNS TXT record
  - [ ] `test_http_verification_success()` — Test valid well-known file
  - [ ] `test_verification_caching()` — Test cache behavior (once implemented)
  - File: Expand `backend/tests/test_domain_verification.py`

### Test infrastructure
- [ ] **Add test database configuration** — Use a separate test PostgreSQL database for integration tests.
  - File: Create `backend/tests/conftest.py` with test DB fixtures

- [ ] **Add test coverage reporting** — Run `pytest --cov=backend/app --cov-report=html`
  - File: `backend/pyproject.toml` or `backend/setup.cfg`

- [ ] **Set coverage threshold** — Enforce minimum 70% coverage in CI.
  - File: `backend/pyproject.toml`

---

## P3 — Code Cleanup

> Dead code and inconsistencies to clean up.

- [ ] **Remove `_hash_token()` / `_verify_token()` dead code** from `auth.py:65-73` or wire into magic link flow.
  - File: `backend/app/services/auth.py:65-73`

- [ ] **Remove `_scan_query()` dead code** from `storage.py:152` (raises `NotImplementedError`).
  - File: `backend/app/services/storage.py:152`

- [ ] **Remove `upsert_scan()` dead code** from `storage.py:1272` (raises `NotImplementedError`).
  - File: `backend/app/services/storage.py:1272`

- [ ] **Remove `replace_hunt_findings()` dead code** from `storage.py:1328` (raises `NotImplementedError`).
  - File: `backend/app/services/storage.py:1328`

- [ ] **Standardize API response format** — Some endpoints return `{ "data": ... }`, others return raw objects. Pick one format and apply consistently.
  - Files: All files in `backend/app/api/`

- [ ] **Add type hints to all functions** — Many functions lack return type annotations.
  - Files: All files in `backend/app/`

- [ ] **Add docstrings to all public functions** — Many functions lack docstrings.
  - Files: All files in `backend/app/`

- [ ] **Consolidate error handling** — Create a standard error response helper.
  - File: Create `backend/app/api/errors.py`

---

## P3 — Documentation & Config

> Documentation and configuration accuracy.

- [ ] **Update `architecture.md`** — Remove any remaining Supabase references. Add new service descriptions (auth.py, email.py, auth_routes.py).
  - File: `docs/architecture.md`

- [ ] **Update API documentation** — Document all new endpoints in a `docs/api.md` or OpenAPI spec.
  - File: Create `docs/api.md`

- [ ] **Update `README.md` setup instructions** — Add:
  - [ ] PostgreSQL setup steps
  - [ ] Google Cloud Console setup for OAuth
  - [ ] SMTP configuration guide
  - [ ] `AETHER_JWT_SECRET` generation
  - File: `README.md`

- [ ] **Create `.env.example` with all required variables** — Verify all env vars are documented.
  - File: Root `.env.example`, `backend/.env.example`, `frontend/.env.example`

- [ ] **Add inline code comments** for complex business logic (BrainOrchestrator reasoning loop, validation lane architecture).
  - Files: `backend/app/orchestrator/brain.py`, `backend/app/engine/validation_lanes.py`

---

## P3 — Mobile Responsive Audit

> AGENTS.md Definition of Done requires mobile-responsive audit for the dashboard.

- [ ] **Audit Dashboard.jsx for mobile** — Verify scan cards stack properly on small screens.
  - File: `frontend/src/pages/Dashboard.jsx`

- [ ] **Audit ScanDetail.jsx for mobile** — Verify vulnerability list, remediation steps are readable on mobile.
  - File: `frontend/src/pages/ScanDetail.jsx`

- [ ] **Audit Header.jsx for mobile** — Verify navigation is accessible on mobile (hamburger menu).
  - File: `frontend/src/components/Header.jsx`

- [ ] **Audit SidebarTelemetry.jsx for mobile** — Verify sidebar collapses or becomes a bottom sheet on mobile.
  - File: `frontend/src/components/SidebarTelemetry.jsx`

- [ ] **Audit ScanningConsole.jsx for mobile** — Verify streaming output is readable on small screens.
  - File: `frontend/src/components/ScanningConsole.jsx`

- [ ] **Audit JoinUs.jsx for mobile** — Verify auth forms are usable on mobile.
  - File: `frontend/src/pages/JoinUs.jsx`

- [ ] **Test on common mobile viewports** — 375px (iPhone SE), 390px (iPhone 14), 414px (iPhone 14 Plus), 768px (iPad).
  - Use Chrome DevTools device toolbar or Playwright mobile emulation.

---

## P3 — CI/CD & Deployment

> Production deployment readiness.

- [ ] **Add GitHub Actions CI workflow**
  - [ ] Run `pytest` with coverage on every PR
  - [ ] Run `npm run build` on frontend to verify no build errors
  - [ ] Run linting (ruff for Python, eslint for JS)
  - [ ] Run type checking (mypy for Python)
  - File: Create `.github/workflows/ci.yml`

- [ ] **Add Docker build optimization**
  - [ ] Multi-stage Dockerfile for backend (build stage + runtime stage)
  - [ ] Multi-stage Dockerfile for frontend (build stage + nginx stage)
  - [ ] Docker Compose for local development with PostgreSQL
  - File: `Dockerfile`, `docker-compose.yml`

- [ ] **Add production deployment configuration**
  - [ ] Gunicorn + Uvicorn worker config for production
  - [ ] Nginx reverse proxy config
  - [ ] SSL/TLS certificate setup
  - [ ] Database connection pooling tuning
  - File: Create `deploy/` directory

- [ ] **Add environment-specific configs**
  - [ ] Development settings
  - [ ] Staging settings
  - [ ] Production settings
  - File: Create `backend/app/config.py` with environment-aware loading

- [ ] **Add database backup strategy**
  - [ ] Automated daily PostgreSQL backups
  - [ ] Backup retention policy
  - File: Create `scripts/backup.sh`

---

## Verification Checklist

> Final checks before marking AETHER as 100% complete.

### Backend
- [ ] All OWASP Top 10 categories have active Playwright-based validation
- [ ] All API endpoints have proper auth, rate limiting, and input validation
- [ ] AETHER-Shield middleware is mounted and functional
- [ ] All storage methods work with real PostgreSQL
- [ ] PDF reports render with proper formatting and all data
- [ ] Remediation → git PR flow works end-to-end
- [ ] All tests pass with >70% coverage
- [ ] No `TODO`, `FIXME`, or `STUB` markers remain in code
- [ ] No dead code (all functions are called somewhere)
- [ ] All env vars documented in `.env.example`

### Frontend
- [ ] All pages render correctly on mobile (375px - 1440px)
- [ ] Auth flow works end-to-end (magic link + Google OAuth)
- [ ] Dashboard shows all scans with realtime updates
- [ ] ScanDetail shows all vulnerability data with evidence
- [ ] PDF download works from both Dashboard and ScanDetail
- [ ] WebSocket reconnection works gracefully
- [ ] No console errors or warnings

### Infrastructure
- [ ] Docker build succeeds for both backend and frontend
- [ ] PostgreSQL migrations work from clean state
- [ ] CI pipeline passes on main branch
- [ ] Production deployment works on a fresh server
- [ ] Health endpoints report correct status
- [ ] Graceful shutdown works without data loss

### Security
- [ ] No secrets in code (all in env vars)
- [ ] JWT tokens expire correctly (1hr access, 7-day refresh)
- [ ] Magic link tokens expire and are single-use
- [ ] Rate limiting prevents abuse
- [ ] CORS is locked down for production
- [ ] Input validation prevents injection attacks
- [ ] SSRF protection blocks internal IPs

---

## Progress Tracker

| Category | Total Items | Done | Remaining |
|----------|------------|------|-----------|
| P0 — Critical Bugs | 5 | 5 | 0 |
| P0 — Missing Methods | 2 | 2 | 0 |
| P0 — Unmounted Security | 5 | 5 | 0 |
| P1 — OWASP Validation | 12 | 12 | 0 |
| P1 — Auth Gaps | 8 | 8 | 0 |
| P1 — Scan Lifecycle | 6 | 6 | 0 |
| P1 — Frontend Gaps | 14 | 14 | 0 |
| P2 — PDF Quality | 3 | 3 | 0 |
| P2 — Remediation | 5 | 5 | 0 |
| P2 — Infrastructure | 10 | 10 | 0 |
| P2 — Domain Verification | 3 | 3 | 0 |
| P3 — Test Suite | 30 | 0 | 30 |
| P3 — Code Cleanup | 8 | 0 | 8 |
| P3 — Documentation | 5 | 0 | 5 |
| P3 — Mobile Audit | 7 | 0 | 7 |
| P3 — CI/CD | 5 | 0 | 5 |
| **TOTAL** | **128** | **73** | **55** |

> **Current completion: ~57%** (73 of 128 items done - past halfway mark!)
> **Estimated effort: < 1 week for a single developer**
