# AETHER Engineering Protocols

## Project Structure
```
aether/                 # Full-stack Next.js app
├── src/app/            # App Router pages and API routes
├── src/lib/            # Shared utilities (auth, DB, email)
├── prisma/             # Database schema (10 tables)
├── public/             # Static assets
└── backend/            # Python scanning engine (spawned as subprocess)
    └── app/
        ├── api/headless_runner.py
        ├── orchestrator/   # Brain, attack orchestrator, remediation
        ├── engine/         # Heuristic, Playwright, validation lanes
        ├── tools/          # Audit, headers, scanner, validators
        └── services/       # Storage, domain verification
```

## Architectural Standards
- **Pattern:** Multi-agent autonomous loops with deterministic state validation.
- **Frontend:** Next.js App Router with TypeScript, Tailwind CSS, Prisma ORM.
- **Backend Bridge:** Next.js API spawns Python subprocess for scan execution.
- **Security:** Every request validated via JWT middleware.

## Definition of Done
- All code must pass `npx next build` without errors.
- All code must pass a mobile-responsive audit for the dashboard.
