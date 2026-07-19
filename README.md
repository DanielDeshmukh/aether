<div align="center">

![AETHER Banner](banner.png)

---

[![CI](https://github.com/DanielDeshmukh/aether/actions/workflows/ci.yml/badge.svg)](https://github.com/DanielDeshmukh/aether/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-99%20passed-brightgreen?style=flat-square)](https://github.com/DanielDeshmukh/aether)
[![Stars](https://img.shields.io/github/stars/DanielDeshmukh/aether?style=flat-square&color=yellow)](https://github.com/DanielDeshmukh/aether/stargazers)
[![NVIDIA NIM](https://img.shields.io/badge/AI-NVIDIA%20NIM-76B900?style=flat-square&logo=nvidia)](https://build.nvidia.com)
[![License](https://img.shields.io/badge/License-Proprietary-FF4444?style=flat-square)](#license)
[![Next.js](https://img.shields.io/badge/Next.js-15-000000?style=flat-square&logo=next.js)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript)](https://typescriptlang.org)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python)](https://python.org)

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

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | Next.js 15, React 19, TypeScript, Tailwind CSS |
| **Backend** | Python 3.12, Playwright, NVIDIA NIM (OpenAI-compatible API) |
| **Database** | PostgreSQL 17, Prisma ORM |
| **Auth** | Custom JWT with magic link authentication |
| **AI Orchestration** | Nemotron 3 Super, Llama 3.3 Nemotron, DeepSeek V4 Flash |
| **Browser Automation** | Playwright with headless Chromium |

---

## Project Structure

```
aether/
├── src/app/            # Next.js App Router (pages + API routes)
├── src/lib/            # Auth, DB, email, API utilities
├── prisma/             # Database schema (10 tables)
├── public/             # Static assets
└── backend/            # Python scanning engine (subprocess)
    └── app/
        ├── orchestrator/   # Brain, attack orchestrator
        ├── engine/         # Heuristic, Playwright, validation lanes
        ├── tools/          # Audit, headers, scanner, validators
        └── services/       # Storage, domain verification
```

---

## Getting Started

### Prerequisites
- Node.js 18+
- Python 3.12+
- PostgreSQL 17+

### Setup

```bash
# Clone
git clone https://github.com/DanielDeshmukh/aether.git
cd aether

# Install dependencies
cd aether && npm install
cd ../aether/backend && pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env with your DATABASE_URL, NVIDIA_API_KEY, AETHER_JWT_SECRET

# Sync database schema
cd ../aether
npx prisma db push

# Start development
cd ../aether && npm run dev
```

Open http://localhost:3000

### Docker (Full Stack)

```bash
docker compose up --build
```

This starts PostgreSQL + the Next.js app with the Python scanning engine.

---

## Deployment

### Option 1: Railway / Fly.io (Full Functionality)

The scan engine requires a Python subprocess, so **full functionality needs a server environment**.

```bash
# Railway
railway init
railway add --database postgres
railway variables set NVIDIA_API_KEY=... AETHER_JWT_SECRET=... AETHER_USE_NVIDIA_ORCHESTRATOR=true
railway up
```

### Option 2: Vercel (UI Only)

The Next.js app deploys to Vercel. Scans won't execute (serverless can't spawn Python), but the UI, auth, and dashboard work.

```bash
vercel deploy
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

| Model | Role | Why |
|-------|------|-----|
| **Nemotron 3 Super 120B** | Scan planning + final verdicts | 1M context window, reasoning with transparent thought chains |
| **Llama 3.3 Nemotron Super 49B** | Remediation code generation | 91.3% MBPP score, optimized for security patch generation |
| **Nemotron 3 Nano 30B** | Content safety filtering | Sub-second response for real-time safety gating |
| **DeepSeek V4 Flash** | Fast fallback analysis | 284B MoE, ~120 tok/s for high-throughput scenarios |

---

## Safety Architecture

| Control | Implementation |
|---------|---------------|
| **Mandatory Consent** | Scans require explicit ownership verification before execution |
| **SSRF Protection** | Private IPs, loopback, and internal networks are blocked |
| **Rate Limiting** | Per-IP rate limits on scan creation and API endpoints |
| **Quota Enforcement** | Per-user scan quotas with tier-based limits |
| **Token Rotation** | Refresh tokens rotated on every use; all tokens include revocable JTIs |

---

## License

This project is proprietary software. All rights reserved by the author.

---

<div align="center">

**Built with precision. Deployed with confidence.**

[Report Issues](https://github.com/DanielDeshmukh/aether/issues)

</div>
