# AI Workflow Rules

## Approach

Treat the `context/` folder as the project brief for AETHER's current implementation, not as greenfield product design. The source of truth lives in `MISSION_GOALS.md`, `frontend/src`, `backend/main.py`, and `backend/app`. Update these context files whenever the live system meaningfully changes so future work starts from what the repository actually does today.

## Scoping Rules

- Work one boundary at a time: frontend workflow, API contract, orchestration behavior, persistence, or verification.
- Prefer changes that are easy to verify against the existing routes and components.
- Keep marketing-site work separate from authenticated operator-console work.
- Keep passive scan/reporting work separate from active validation lane work.

## When To Split Work

Split an implementation step if it combines:

- React route/UI work and FastAPI/WebSocket contract changes
- Storage schema changes and orchestration changes
- Legacy `AetherStorage` path cleanup and modern `ScanStorage` path changes
- Marketing-page styling and dashboard/debrief functionality
- Product behavior that is not already grounded in `MISSION_GOALS.md` or the existing code

If a change cannot be traced from request -> backend -> persistence -> frontend presentation, the scope is probably too broad.

## Handling Missing Requirements

- Do not invent security-product behavior that is not described in code or `MISSION_GOALS.md`.
- If the AGENTS protocol names a required concept that is missing in code, document that gap instead of pretending it already exists.
- Record unresolved implementation mismatches in `progress-tracker.md` before building on top of them.
- When current code and template docs disagree, update the docs to the code and flag obvious defects separately.

## Protected Files

Do not modify the following unless the task explicitly calls for it:

- `frontend/dist/*`
- `frontend/node_modules/*`
- `backend/venv/*`
- generated or vendored third-party dependency files

Use extra caution with:

- `backend/main.py` and `backend/app/api/deps.py` because the current repo state shows unresolved merge markers
- persistence and verification code because these define cross-tenant and legal-safety boundaries

## Keeping Docs In Sync

Update the relevant context file whenever any of the following change:

- Scan lifecycle or route structure
- Persistence tables or ownership model
- Domain verification, quota, SSRF, or rate-limit rules
- Frontend route/component responsibilities
- Visual tokens, layout patterns, or dashboard/debrief UX expectations

## Before Moving To The Next Unit

1. The changed boundary is consistent with the current architecture docs.
2. Any new or changed security invariant is reflected in `architecture.md` or `code-standards.md`.
3. `progress-tracker.md` records what changed, what is still in progress, and any known repo mismatch.
4. Relevant verification has been run or the inability to verify is explicitly recorded.
