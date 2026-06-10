# AETHER API Documentation

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

All endpoints require authentication via Bearer token unless noted otherwise.

### Get Access Token

```http
POST /auth/magic-link
Content-Type: application/json

{
  "email": "user@example.com"
}
```

### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "..."
}
```

## Scan Endpoints

### Create Scan

```http
POST /scans
Content-Type: application/json

{
  "target_url": "https://example.com",
  "consent_confirmed": true
}
```

### List Scans

```http
GET /scans
```

### Get Scan

```http
GET /scans/{scan_id}
```

### Delete Scan

```http
DELETE /scans/{scan_id}
```

### Re-run Scan

```http
POST /scans/{scan_id}/rerun
```

### Compare Scans

```http
GET /scans/compare?ids=scan1,scan2
```

### Export Scan

```http
GET /scans/{scan_id}/export?format=json
```

## Scan Control

### Pause Scan

```http
POST /scan/{scan_id}/pause
```

### Resume Scan

```http
POST /scan/{scan_id}/resume
```

### Terminate Scan

```http
POST /scan/{scan_id}/terminate
```

## Reports

### Download PDF Report

```http
GET /scans/{scan_id}/report
```

### Email PDF Report

```http
POST /scans/{scan_id}/report/email
Content-Type: application/json

{
  "email": "user@example.com"
}
```

### Get Remediation History

```http
GET /scans/{scan_id}/remediation-history
```

## Vulnerabilities

### Get Vulnerability Screenshot

```http
GET /scans/{scan_id}/vulnerabilities/{vuln_id}/evidence/screenshot
```

## Domain Verification

### Get Verification Status

```http
GET /verification/status?domain=example.com
```

## WebSocket Endpoints

### Dashboard Updates

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/dashboard?token=...');
```

### Scan Streaming

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/scan/{scan_id}');
```

### Remediation

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/remediation/{scan_id}?user_id=...');
```

#### Actions

```json
{
  "action": "generate_fix",
  "vuln_id": "..."
}
```

```json
{
  "action": "create_pull_request",
  "vuln_id": "...",
  "target_id": "..."
}
```

## Health Endpoints

### Basic Health Check

```http
GET /health
```

### API Health Check

```http
GET /api/v1/health
```

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/auth/magic-link` | 5 requests | 1 hour |
| `/auth/refresh` | 20 requests | 1 hour |
| `/scans` | 3 concurrent | - |