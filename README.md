# AETHER (Automated Ethical Testing & Heuristic Evaluation Routine)

## Welcome
Welcome to the AETHER repository. This project is an advanced, autonomous penetration testing platform designed to simulate the reasoning of a human security expert. By moving beyond static rulesets, AETHER identifies, executes, and validates **OWASP Top 10** exploits against target URLs with high precision and professional rigor.

---

## Overview
Traditional security scanners rely on predefined payloads, often resulting in high false positives. AETHER introduces an **Agentic Reasoning Loop**, enabling it to analyze and execute security tests in a context-aware, targeted manner.

Instead of blindly scanning, AETHER:
*   **Observes:** Analyzes application behavior and tech stacks (React, FastAPI, PHP, etc.).
*   **Identifies:** Maps the attack surface for vulnerabilities (SQLi, XSS, SSRF, etc.).
*   **Executes:** Deploys context-aware exploits based on validated consent and ownership.
*   **Validates:** Confirms successful breaches to eliminate false positives.
*   **Remediates:** Provides professional code refactors and snippets to patch the flaw.

---

## Objectives
*   **Autonomous OWASP Top 10 Execution**  
    Full automation of the OWASP Top 10. If an attack is possible, AETHER executes it to prove the flaw's existence.
*   **Mandatory Consent & Ownership**  
    Rigid safety protocols ensuring scans only proceed after user-verified ownership and breach consent.
*   **Intelligent Remediation**  
    Moving beyond "finding" bugs to "fixing" them by providing actionable code snippets and root-cause explanations.
*   **Scalable Security-as-a-Service**  
    A multi-tenant architecture built for continuous, scalable security audits.

---

## System Architecture
AETHER is structured as a modular SaaS platform designed for high-concurrency testing:

| Layer | Technology Stack | Purpose |
| :--- | :--- | :--- |
| **Frontend** | React.js (Dark Mode) | Real-time visualization of attacks, telemetry, and vulnerability dashboards. |
| **Orchestrator** | LangGraph / Python | The "Brain." Manages the stateful reasoning loop and attack planning. |
| **Engine** | FastAPI + Playwright + Safety & Rate Limiting | The execution layer. Interacts with the DOM, delivers payloads, and enforces operational safety gates with request throttling and scan-identification headers. |
| **Intelligence** | Gemini 2.0 Flash / Claude | Interprets HTTP responses and generates adaptive bypass payloads. |
| **Backend** | PostgreSQL (psycopg) + Custom JWT Auth | Manages auth, scan persistence, and the "Flaw & Remediation" database. |

---

## Core Features
*   **The Threat Feed**  
    A live stream of terminal-style logs showing active payload delivery and server responses.
*   **OWASP Attack Modules**  
    Specialized routines for Injection, Broken Access Control, Cryptographic Failures, and more.
*   **Professional Remediation Engine**  
    For every confirmed flaw, AETHER generates a technical report including "Current Vulnerable Code" vs. "Proposed Secure Refactor."
*   **Kill Switch & Safety Gate**  
    Immediate termination of all active sessions and automated rollback if target instability is detected or User's concern arise.

---

## Development Roadmap

### Completed

| Milestone | Notes |
| :--- | :--- |
| **Setup** | Repository init, PostgreSQL schema foundation, and custom JWT auth wiring. |
| **Database Persistence Resilience** | Stabilized the transactional `persist_full_pipeline` path and hardened scan/session/profile persistence. |
| **Dynamic Profile Normalization** | Normalized profile payload generation so automated and user-linked profiles persist safely even with nullable identity fields. |
| **NVIDIA Agentic Reasoning Loop Integration** | Bridged Nemotron-guided orchestration into the live WebSocket stream with tenant-safe persistence handoff. |
| **Remediation Logic** | Added a typed remediation engine that turns validated findings into root-cause analysis and secure refactor packages. |

### In Progress

| Milestone | Notes |
| :--- | :--- |
| **Core Engine** | Continuing development of the FastAPI + Playwright interaction layer and bounded validation modules. |
| **Headless Playwright Validation Lanes** | Refining the proof-of-concept exploit lanes into broader, repeatable validation coverage. |

### Upcoming

| Milestone | Notes |
| :--- | :--- |
| **Auto-Remediation** | Automated Pull Request generation for GitHub/GitLab repair workflows. |
| **Deployment** | Hardened CI/CD pipelines and production-ready environment controls. |
| **Hard-RAG Clinical Protocol (Project Ella)** | High-assurance retrieval and protocol orchestration for the clinical reasoning track. |
| **Automated Ethical Auditing** | Continuous auditing of guardrails, consent flows, and operator safety boundaries. |

---


> **Disclaimer:** AETHER is designed for ethical security testing. Use of this tool requires explicit, written consent from the target system owner. Unauthorized use is strictly prohibited.

## Delivery Phases

- [x] **Phase 12 - Hardening: Quota & Identity Guard**
- [x] **Phase 13 - Hardening: Attack Surface Reduction**
- [x] **Phase 14 - Final Audit & Launch**

## Post-Launch Reliability

- [x] Replaced legacy scan persistence path with transactional `persist_full_pipeline`.
- [x] Hardened orchestration timeout handling for upstream AI overload scenarios.

