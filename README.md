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

---

## Setup Instructions

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 14+
- Docker (optional)

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/aether.git
cd aether
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

pip install -r requirements.txt
```

### 3. Database Setup

```bash
# Create PostgreSQL database
createdb aether

# Set DATABASE_URL in .env
echo "DATABASE_URL=postgresql://user:password@localhost:5432/aether" >> .env

# Run migrations
alembic upgrade head
```

### 4. Google Cloud Console Setup (OAuth)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Go to Credentials > Create Credentials > OAuth 2.0 Client ID
5. Set authorized redirect URIs to `http://localhost:8080/api/v1/auth/google/callback`
6. Copy Client ID and Client Secret to `.env`

### 5. SMTP Configuration (Email)

```bash
# Required for magic links and report delivery
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=AETHER <noreply@aether.local>
```

### 6. JWT Secret Generation

```bash
# Generate a secure random secret
python -c "import secrets; print(secrets.token_urlsafe(64))"

# Add to .env
echo "AETHER_JWT_SECRET=your-generated-secret" >> .env
```

### 7. Frontend Setup

```bash
cd frontend
npm install
```

### 8. Environment Variables

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
```

See `.env.example` for all required variables.

### 9. Running Development Servers

```bash
# Terminal 1 - Backend
cd backend
uvicorn main:app --reload --port 8000

# Terminal 2 - Frontend
cd frontend
npm run dev
```

### 10. Docker Setup (Optional)

```bash
docker-compose up -d
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `AETHER_JWT_SECRET` | Yes | JWT signing secret |
| `GEMINI_API_KEY` | No | Google Gemini API key for AI analysis |
| `GOOGLE_CLIENT_ID` | No | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | Google OAuth client secret |
| `SMTP_HOST` | No | SMTP server host |
| `SMTP_PORT` | No | SMTP server port |
| `SMTP_USER` | No | SMTP username |
| `SMTP_PASSWORD` | No | SMTP password |
| `FRONTEND_URL` | Yes | Frontend URL for CORS |
| `ENVIRONMENT` | No | `development` or `production` |

---

## API Documentation

See [docs/api.md](docs/api.md) for complete API documentation.

---

## Architecture

See [docs/architecture.md](docs/architecture.md) for system architecture details.

