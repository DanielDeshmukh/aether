# AETHER Project Overview

## Overview

AETHER is a security scanning platform with a React frontend and FastAPI backend that lets an authenticated operator launch bounded vulnerability hunts against verified targets, stream the engine's reasoning over WebSockets, persist scan artifacts in Postgres/Supabase-backed storage, and review scan debriefs plus generated remediation guidance in the dashboard.

## Goals

1. Let a signed-in operator start a scan only after explicit consent confirmation and authenticated identity checks.
2. Run a deterministic scan loop that captures plan, execution telemetry, findings, and final risk summaries for each target.
3. Persist every scan so the dashboard, PDF export flow, and remediation workflow can reopen past hunts.
4. Keep the engine defensive by enforcing quota limits, SSRF safeguards, domain ownership verification, and rate limiting.

## Core User Flow

1. User authenticates from `/join-us` with Google OAuth or email magic link through Supabase.
2. User opens `/home`, enters a target URL, and confirms ownership or written authorization.
3. Frontend calls `POST /api/v1/scans` with the Supabase access token and consent flag.
4. Backend validates auth, quota, consent, and target safety, then creates an in-memory scan session.
5. Frontend connects to `/ws/scan/{scan_id}` and receives staged reasoning, execution logs, findings, and final report data.
6. Backend persists scan state, results, findings, profiles, and consent logs into the database.
7. User reviews completed scans in `/dashboard` and opens `/dashboard/:scanId` for a full debrief.
8. User can download a PDF report and request remediation guidance for individual findings.

## Features

### Hunt Execution

- Authenticated scan creation with consent logging
- WebSocket-driven live reasoning and telemetry stream
- Playwright-assisted reconnaissance and validation lanes
- Port scan, header audit, and bounded audit engine execution
- Optional NVIDIA/Nemotron orchestration path for allowlisted targets

### Safety Controls

- Three-scan MVP quota per authenticated user
- SSRF and private-network blocking before scan execution
- Domain ownership verification through `public.targets`
- Global and per-endpoint rate limiting
- Kill switch support during active scans

### Persistence And Reporting

- Postgres persistence for scans, sessions, findings, profiles, and consent logs
- Dashboard list view with Supabase realtime updates
- Scan debrief detail screen with persisted plan and verdict
- PDF report generation through Playwright
- Remediation package generation for findings

### Frontend Experience

- Lamborghini-inspired dark visual system with gold accent styling
- Marketing landing page plus authenticated operator workspace
- Home page split between target input, live console, and recent telemetry
- Dashboard cards for recent scans and deep-link into debriefs

## Scope

### In Scope

- Supabase-authenticated scan initiation
- FastAPI APIs and WebSocket orchestration for scan execution
- Persistence to the `scans`, `scan_sessions`, `vulnerabilities`, `profiles`, and `consent_logs` tables
- Domain verification checks before active validation
- Frontend flows for authentication, launching scans, viewing scans, downloading reports, and generating remediations

### Out Of Scope

- Unauthenticated public scanning
- Destructive or unrestricted offensive testing against arbitrary internet hosts
- Full mobile redesign beyond keeping current dashboard layouts responsive
- Fully implemented Git pull-request remediation flow end to end

## Success Criteria

1. An authenticated user can start a scan only after consent confirmation, and the backend persists the consent log plus scan record.
2. A running scan streams reasoning and execution events to the frontend, then stores a final report retrievable from the dashboard.
3. A completed scan can be reopened later, exported as PDF, and used to request remediation guidance for persisted findings.
4. Unsafe targets, over-quota users, and unverified domains are blocked before active validation begins.
