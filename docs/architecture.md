# AETHER Architecture

## Overview

AETHER is a security scanning and vulnerability assessment platform that uses AI-powered analysis to identify and remediate security issues in web applications.

## System Architecture

### Backend (FastAPI)

The backend is built with FastAPI and provides:

- **REST API** for scan management, authentication, and reporting
- **WebSocket endpoints** for real-time scan updates and remediation
- **Background processing** for scan execution and analysis

#### Key Components

1. **API Layer** (`backend/app/api/`)
   - `main.py` - FastAPI application and endpoints
   - `auth_routes.py` - Authentication endpoints (magic link, OAuth)
   - `shield.py` - AETHER-Shield middleware for token validation
   - `rate_limiter.py` - Rate limiting for API endpoints
   - `deps.py` - Dependency injection for authentication

2. **Services** (`backend/app/services/`)
   - `storage.py` - PostgreSQL database operations
   - `auth.py` - JWT token creation and validation
   - `email.py` - Email sending (magic links, reports)
   - `domain_verification.py` - Domain ownership verification
   - `report_generator.py` - PDF report generation
   - `quota_manager.py` - User quota management

3. **Orchestrator** (`backend/app/orchestrator/`)
   - `brain.py` - BrainOrchestrator for scan reasoning
   - `attack_orchestrator.py` - Attack execution and validation
   - `intent_router.py` - Intent detection and routing

4. **Engine** (`backend/app/engine/`)
   - `validation_lanes.py` - OWASP Top 10 validation
   - `heuristic_engine.py` - Heuristic analysis

5. **Tools** (`backend/app/tools/`)
   - `remediation.py` - Remediation generation
   - `audit_engine.py` - Security auditing

### Frontend (React + Vite)

The frontend is built with React and Vite:

- **Pages** (`frontend/src/pages/`)
  - `Dashboard.jsx` - Scan listing and management
  - `ScanDetail.jsx` - Scan results and remediation
  - `JoinUs.jsx` - Authentication page

- **Components** (`frontend/src/components/`)
  - `Header.jsx` - Navigation with mobile menu
  - `ScanningConsole.jsx` - Real-time scan output
  - `SidebarTelemetry.jsx` - Quick scan access
  - `ScanChart.jsx` - Scan history visualization

### Database (PostgreSQL)

The database stores:

- **scans** - Scan records and results
- **vulnerabilities** - Vulnerability findings
- **users** - User accounts
- **targets** - Domain verification records
- **magic_links** - Authentication tokens
- **revoked_tokens** - Token blacklist
- **consent_logs** - Scan consent records

## Security Features

1. **AETHER-Shield Middleware** - Validates JWT tokens on all API requests
2. **Rate Limiting** - Prevents abuse on sensitive endpoints
3. **Domain Verification** - Ensures users own scanned domains
4. **Input Validation** - Prevents injection attacks
5. **SSRF Protection** - Blocks internal IP scanning

## Deployment

- **Docker** - Containerized deployment
- **Alembic** - Database migrations
- **Nginx** - Reverse proxy (production)
- **Gunicorn** - WSGI server (production)