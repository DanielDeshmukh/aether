<div align="center">

![AETHER Banner](banner.png)

---

[![CI](https://github.com/DanielDeshmukh/aether/actions/workflows/ci.yml/badge.svg)](https://github.com/DanielDeshmukh/aether/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-99%20passed-brightgreen?style=flat-square)](https://github.com/DanielDeshmukh/aether)
[![Stars](https://img.shields.io/github/stars/DanielDeshmukh/aether?style=flat-square&color=yellow)](https://github.com/DanielDeshmukh/aether/stargazers)
[![NVIDIA NIM](https://img.shields.io/badge/AI-NVIDIA%20NIM-76B900?style=flat-square&logo=nvidia)](https://build.nvidia.com)
[![License](https://img.shields.io/badge/License-Proprietary-FF4444?style=flat-square)](#license)
[![Next.js](https://img.shields.io/badge/Next.js-16-000000?style=flat-square&logo=next.js)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript)](https://typescriptlang.org)

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
| **Frontend** | Next.js 16, React 19, TypeScript, Tailwind CSS |
| **Backend** | Next.js API Routes, TypeScript |
| **Database** | PostgreSQL 17, Prisma ORM |
| **Auth** | Custom JWT with magic link authentication |
| **AI Orchestration** | NVIDIA NIM (Nemotron 3 Super, Llama 3.3 Nemotron, DeepSeek V4 Flash) |
| **Browser Automation** | Playwright with headless Chromium |

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
