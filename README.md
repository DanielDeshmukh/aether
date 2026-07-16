<div align="center">

![AETHER Logo](/images/logo.png)

# AETHER

### Automated Ethical Testing & Heuristic Evaluation Routine

**An autonomous penetration testing platform that reasons like a human security expert.**

[![Tests](https://img.shields.io/badge/tests-231%20passed-brightgreen?style=flat-square)](https://github.com/DanielDeshmukh/aether)
[![Stars](https://img.shields.io/github/stars/DanielDeshmukh/aether?style=flat-square&color=yellow)](https://github.com/DanielDeshmukh/aether/stargazers)
[![NVIDIA NIM](https://img.shields.io/badge/AI-NVIDIA%20NIM-76B900?style=flat-square&logo=nvidia)](https://build.nvidia.com)
[![Live](https://img.shields.io/badge/Live-Deployed-00D4FF?style=flat-square)](https://aether-pentesting.netlify.app)
[![License](https://img.shields.io/badge/License-Proprietary-FF4444?style=flat-square)](#license)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)

---

AETHER doesn't just scan. It **thinks**, **plans**, **executes**, and **validates** exploits against live targets using AI-powered reasoning, then generates production-ready remediation patches.

</div>

---

## What It Does

AETHER is a **Security-as-a-Service** platform that autonomously discovers, validates, and remediates web application vulnerabilities. It replaces static rule-based scanners with an agentic reasoning loop that mimics how a senior penetration tester approaches a target.

```
Target URL  -->  Recon  -->  AI Planning  -->  Exploit Execution  -->  Validation  -->  Remediation
                  |              |                    |                    |                |
            Tech stack    Nemotron 3 Super     OWASP Top 10         Confirms        Generates
            fingerprint   generates attack    attack lanes with     breach with     copy-paste
            + passive     plan with THOUGHT   Playwright-backed     evidence        security
            recon         / OBSERVE / PLAN    active testing        + screenshots   patches
```

---

## Core Capabilities

### Autonomous Exploit Execution

AETHER executes **all 10 OWASP Top 10** categories autonomously once consent is verified:

| Category | What AETHER Tests |
|----------|-------------------|
| **A01: Broken Access Control** | Privilege escalation, IDOR, CORS misconfig |
| **A02: Cryptographic Failures** | Weak TLS, mixed content, certificate validation |
| **A03: Injection** | SQL injection, XSS, command injection |
| **A04: Insecure Design** | Business logic flaws, missing rate limiting |
| **A05: Security Misconfiguration** | Default creds, verbose errors, debug endpoints |
| **A06: Vulnerable Components** | Outdated libraries, known CVEs |
| **A07: Auth Failures** | Session management, brute force, token weaknesses |
| **A08: Data Integrity** | Insecure deserialization, supply chain |
| **A09: Logging Failures** | Insufficient logging, missing audit trails |
| **A10: SSRF** | Server-side request forgery, internal network probing |

### AI-Powered Reasoning

AETHER uses a **multi-model NVIDIA NIM pipeline** for different stages of the assessment:

| Model | Role | Why |
|-------|------|-----|
| **Nemotron 3 Super 120B** | Scan planning + final verdicts | 1M context window, reasoning with transparent thought chains |
| **Llama 3.3 Nemotron Super 49B** | Remediation code generation | 91.3% MBPP score, optimized for security patch generation |
| **Nemotron 3 Nano 30B** | Content safety filtering | Sub-second response for real-time safety gating |
| **DeepSeek V4 Flash** | Fast fallback analysis | 284B MoE, ~120 tok/s for high-throughput scenarios |
| **MiniMax M2.7** | Heavy reasoning fallback | 230B MoE, highest intelligence for complex verdicts |

### Professional Remediation

Every confirmed vulnerability generates a **production-ready security patch**:

```python
# BEFORE: Vulnerable Code
cursor.execute(f"SELECT * FROM users WHERE email = '{user_email}'")

# AFTER: Secure Refactor
cursor.execute("SELECT * FROM users WHERE email = %s", (user_email,))
```

Remediations include Nginx, Apache, Node.js, Python, Docker, and Kubernetes configurations.

### Real-Time Telemetry

- **Live WebSocket stream** of the entire attack lifecycle
- **Terminal-style console** showing payload delivery and server responses
- **PDF report generation** with executive summary and technical findings
- **Email delivery** of reports directly from the platform

---

## Safety Architecture

AETHER is built with **safety-first principles**:

| Control | Implementation |
|---------|---------------|
| **Mandatory Consent** | Scans require explicit ownership verification and breach consent before execution |
| **AETHER-Shield** | HMAC-based safety middleware that validates every request with cryptographic tokens |
| **Target Verification** | Domain ownership must be proven via DNS TXT records or HTTP tokens |
| **SSRF Protection** | Private IPs, loopback, and internal networks are blocked before any request |
| **Kill Switch** | Immediate termination of all active sessions with automated rollback |
| **Rate Limiting** | Per-IP rate limits on scan creation (10/hr), report downloads (30/hr), and emails (5/hr) |
| **Quota Enforcement** | Per-user scan quotas with tier-based limits (Free/Pro/Enterprise) |
| **Non-Root Container** | Production Docker images run as unprivileged user |
| **Token Rotation** | Refresh tokens are rotated on every use; all tokens include revocable JTIs |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 19, Vite, React Router, Tailwind CSS |
| **Backend** | FastAPI, Python 3.12, WebSockets |
| **AI Orchestration** | NVIDIA NIM (OpenAI-compatible API) |
| **Browser Automation** | Playwright with headless Chromium |
| **Database** | PostgreSQL 15 with psycopg3 connection pooling |
| **Auth** | Custom JWT with magic link + OAuth (Google/GitHub) |
| **PDF Generation** | fpdf2 with Playwright-rendered evidence screenshots |
| **Deployment** | Fly.io (backend), Netlify (frontend), Docker multi-stage build |

---

## Security Features

- **Magic Link Authentication** — Passwordless login via email
- **OAuth 2.0** — Google and GitHub social login
- **JWT with Rotation** — Access tokens (60min) + rotating refresh tokens (7 days)
- **Token Revocation** — All tokens include JTIs; revoked on logout, compromise, or account deletion
- **Tenant Isolation** — All data scoped to `user_id`; scan records, findings, and remediations are isolated
- **Input Validation** — SSRF protection, URL normalization, Pydantic validation on all endpoints
- **Security Headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Structured Logging** — Request/response logging with method, path, status, and timing

---

## Project Structure

```
aether/
├── backend/
│   ├── app/
│   │   ├── api/            # FastAPI routes, auth, WebSocket endpoints
│   │   ├── orchestrator/   # BrainOrchestrator, AttackOrchestrator, remediation
│   │   ├── engine/         # Playwright validation lanes, heuristic engine
│   │   ├── tools/          # Port scanner, header audit, remediation generation
│   │   ├── services/       # Storage, auth, email, domain verification
│   │   └── config.py       # Pydantic-based configuration
│   ├── tests/              # 231 unit + integration tests
│   ├── alembic/            # Database migrations
│   ├── Dockerfile          # Multi-stage production build
│   └── start.sh            # Gunicorn entrypoint
├── frontend/
│   ├── src/
│   │   ├── components/     # UI components (Navbar, ErrorBoundary, etc.)
│   │   ├── pages/          # Dashboard, ScanDetail, Settings, Landing
│   │   ├── lib/            # Auth, API client, utilities
│   │   └── App.jsx         # Route definitions
│   └── package.json
├── context/                # Architecture docs, coding standards
└── scripts/                # Deployment validation, utilities
```

---

## Testing

```bash
# Run full test suite
cd backend && python -m pytest tests/ -v

# Results: 231 passed, 0 failed
```

**Test Coverage:**
- Auth routes and JWT lifecycle
- Storage CRUD and privacy isolation
- Rate limiting and quota enforcement
- WebSocket connection handling
- Validation lanes (OWASP attack modules)
- Remediation flow (AI + fallback paths)
- PDF report generation
- Email delivery
- Domain verification

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scans` | POST | Create a new scan |
| `/api/v1/scans` | GET | List all scans for authenticated user |
| `/api/v1/scans/{id}` | GET | Get scan details |
| `/api/v1/scans/{id}/report` | GET | Download PDF report |
| `/api/v1/scans/{id}/report/email` | POST | Email PDF report |
| `/ws/scan/{id}` | WS | Real-time scan telemetry |
| `/ws/remediation/{id}` | WS | Remediation generation stream |
| `/ws/dashboard` | WS | Dashboard live updates |
| `/api/v1/auth/magic-link` | POST | Request magic link |
| `/api/v1/auth/refresh` | POST | Refresh access token |
| `/api/v1/health` | GET | Health check |

---

## License

This project is proprietary software. All rights reserved by the author.

Unauthorized reproduction, distribution, or modification is strictly prohibited.

---

<div align="center">

**Built with precision. Deployed with confidence.**

[AETHER Live Demo](https://aether-pentesting.netlify.app) · [Report Issues](https://github.com/DanielDeshmukh/aether/issues)

</div>
