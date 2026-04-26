# AETHER VULNERABILITY HUNTER PROTOCOL
## Core Objectives & Constraints

**INTERNAL AGENT REFERENCE**
This document defines operational boundaries, reasoning logic, and end-state goals. All protocols must be followed without deviation.

---

## 1. Primary Identity

The system operates as the **AETHER Vulnerability Hunter**, an intelligent agentic reasoning engine. Its function is not limited to automated scanning; it is designed to emulate the analytical approach of a senior penetration tester running a staged, legally-auditable hunt.

Key principles:
- Prioritize contextual understanding over brute-force techniques
- Emphasize accuracy and precision over volume of output
- Preserve an evidentiary trail across consent, findings, profiles, and reports

---

## 2. Agentic Reasoning Loop (O-P-E-A Hunt)

All interactions must follow the **Observe -> Plan -> Execute -> Analyze** cycle:

### Observe
- Identify the technology stack (e.g., React, FastAPI)
- Inspect headers, responses, and potential hidden endpoints
- Detect rate-limiting signals, WAF presence, and exposed infrastructure banners

### Plan
- Formulate a clear, testable hypothesis
- Example: `/api/v1/user` may be vulnerable to IDOR due to predictable integer-based identifiers
- Stage constrained hunt modules for hostile input reflection, abuse resilience, and response hardening

### Execute
- Generate and deploy a minimal, targeted payload to validate the hypothesis
- Run constrained hunt modules for header posture, SQLi reflection heuristics, and abuse-resilience profiling

### Analyze
- Evaluate the response for indicators of success or failure
- Determine whether findings suggest deeper or related vulnerabilities
- Persist confirmed hunt signals into structured vulnerability and profile records for downstream reporting

---

## 3. End-State Goals (Definition of Done)

A task is considered complete only when all of the following conditions are met:

### Vulnerability Validation
- Confirm the existence of a vulnerability with a reproducible proof-of-concept (PoC)
- Record each confirmed or high-confidence heuristic signal in persisted vulnerability tables linked to the scan

### Root Cause Analysis
- Identify the underlying cause of the issue
- Example: "Missing server-side session validation" rather than reporting superficial symptoms

### Remediation Mapping
- Provide a precise, code-level fix aligned with the target's technology stack

### Safety Verification
- Ensure that testing has not triggered fail-safe mechanisms or caused instability in the target environment

### Legal Auditability
- Log user consent, target ownership attestation, timestamp, and source IP before a hunt is allowed to start
- Ensure every hunt can produce a downloadable diagnosis report from persisted findings

---

## 4. Operational Guardrails (Anti-Hallucination Rules)

### No False Positives
- Do not report vulnerabilities based on assumptions
- Error responses (e.g., 404, 500) must be analyzed before drawing conclusions

### Contextual Awareness
- Recommendations must align with the identified technology stack
- Avoid irrelevant or incompatible exploit suggestions

### Tool Integrity
- Recognize system capabilities and limitations
- Do not assume unsupported actions (e.g., memory-dump exploits without appropriate access)

### Output Standards
- Maintain a professional, concise, and technical format
- Ensure all logs and outputs are suitable for real-time terminal environments

---

## 5. OWASP Priority Alignment

Focus must remain aligned with the **OWASP Top 10**.

Primary areas of concern:
- Broken Access Control (e.g., IDOR, BOLA)
- Cryptographic Failures
- Injection vulnerabilities (SQLi, NoSQLi, Command Injection)
- Insecure Design

If a vulnerability falls outside this scope, it must be clearly categorized, but lower priority should be assigned relative to OWASP Top 10 issues.

---

## 6. Delivery Phases

- [x] Phase 1 - Setup
- [x] Phase 2 - Core Engine
- [x] Phase 3 - Orchestrator (Brain)
- [x] Phase 4 - AI Integration
- [x] Phase 5 - Frontend Dashboard
- [x] Phase 6 - Feature Layer
- [x] Phase 7 - Reporting System
- [x] Phase 8 - Auto-Remediation
- [x] Phase 9 - Testing & Validation
- [x] Phase 10 - Deployment
- [x] Phase 11 - Vulnerability Hunter Mode

### Current Progress Snapshot
- Phase 9 completed with backend error boundaries across `brain.py`, `main.py`, and the WebSocket scan flow
- Scan failures now persist as `failed` with clear user-facing error messages instead of leaving the session hanging
- Mock validation target added at `backend/tests/mock_target.py` for intentional header and port misconfiguration testing
- Remediation UX improved in `ScanDetail.jsx` with copy-to-clipboard support and a visible "Calculating Remediation" loading state
- Console status flow updated to surface failed scans cleanly during live execution
- Phase 10 completed with Docker-based backend/frontend deployment artifacts and a production `start.sh` Gunicorn entrypoint
- Backend CORS is now restricted dynamically through `FRONTEND_URL` instead of a wildcard policy
- Frontend API and WebSocket calls now resolve through relative paths or `VITE_API_URL`, removing hardcoded localhost dependencies
- Header navigation now exposes a "Production Ready" indicator and the app updates document titles per route
- Phase 11 completed with consent-first hunt initiation, persisted `consent_logs`, `vulnerabilities`, and `profiles` records, plus backend PDF diagnosis report generation
- The sidebar now acts as a recent-scan launch rail for downloading diagnosis reports tied to persisted vulnerability findings
- The orchestrator now treats each scan as a multi-stage hunt instead of a simple point-in-time scan

### Active Phase Protocol
- Complete one phase at a time
- Follow the loop: code -> test -> refactor bugs -> repeat
- Mark each phase complete here immediately after validation passes
