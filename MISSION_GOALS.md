# AETHER VULNERABILITY HUNTER PROTOCOL
## Core Objectives & Constraints (Hardened MVP Edition)

**INTERNAL AGENT REFERENCE** **Identity:** AETHER Vulnerability Hunter  
**Primary Directive:** Secure the Target, Harden the Hunter.

---

## 1. Primary Identity
AETHER is an agentic reasoning engine designed for senior penetration testing emulation. It operates with a **"Security-First"** mindset, ensuring both the target environment and the AETHER infrastructure remain resilient throughout the engagement.

---

## 2. Agentic Reasoning Loop (O-P-E-A Hunt)
The engine executes a continuous, stateful loop to ensure precision:
* **Observe:** Passive stack detection, WAF discovery, and rate-limit signaling.
* **Plan:** Hypothesis-driven testing strategy (focusing on IDOR, SQLi, and Logic flaws).
* **Execute:** Targeted, non-destructive payload deployment based on the staged plan.
* **Analyze:** Signal correlation, false-positive filtering, and persistent evidence logging.

---

## 3. MVP Operational Guardrails (3-Scan Limit)

### Anti-Abuse Logic (Anti-Sybil)
* **Scan Quota:** Hard limit of **3 scans** per unique Google Account.
* **Identity Multi-Factor:** Quotas strictly tracked via `email` (verified Google OAuth) and `origin_ip` fingerprinting.
* **Sybil Defense:** Automatic flagging of accounts sharing the same IP if they exceed 3 unique emails per 24h window.

### Self-Preservation (Security Hardening)
* **Injection Defense:** Mandatory parameterized queries for all DB interactions; strict Pydantic schema validation.
* **SSRF Prevention:** Validation of `target_url` against internal/private IP ranges (e.g., `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`).
* **DDoS Mitigation:** Global API throttling via `SlowAPI` to prevent engine exhaustion and resource denial.

---

## 4. Delivery Phases

- [x] **Phase 1–11: Foundations**
    - Core Engine, UI, Reporting System, and Hunter Mode integration.
- [x] **Phase 12 - Hardening: Quota & Identity Guard**
    - Implement `check_scan_quota` middleware for the 3-scan limit.
    - Integrate `origin_ip` logging into `consent_logs` for forensics.
- [x] **Phase 13 - Hardening: Attack Surface Reduction**
    - Implement `SlowAPI` for granular rate limiting.
    - Deploy SSRF URL Sanitizer for all target input vectors.
- [x] **Phase 14 - Final Audit & Launch**
    - End-to-end "Cheater Test" (quota bypass attempts).
    - AETHER self-pentest (automated and manual security audit).

### Next Phase

- [ ] **Phase 15 - Stability & Polish**
    - Update documentation to reflect completed phases.
    - Fix any remaining TODO comments in critical paths.
    - Add integration tests for full scan flow.
    - Polish error messages and user feedback.
    - Validate Git PR remediation end-to-end flow.

### Active Phase Protocol
1.  **Complete one phase at a time.**
2.  **Follow the loop:** `Code` -> `Test` -> `Refactor Bugs` -> `Repeat`.
3.  **Validation:** Mark each phase complete here immediately after validation passes.

---

## 5. End-State Goals (Definition of Done)

### Vulnerability Validation
* Every finding must include a reproducible Proof-of-Concept (PoC).
* Root cause analysis must be provided for every high-confidence signal.

### Safety & Integrity
* AETHER must be immune to the very vulnerabilities it hunts (Injection, Broken Access Control).
* Identity verification via Google OAuth must be the **sole** entry point for all operations.