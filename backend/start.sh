#!/bin/sh
set -eu

PORT="${PORT:-8000}"
WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}"

# Run database migrations
echo "Running Alembic migrations..."
alembic upgrade head 2>/dev/null || echo "Alembic migration skipped (no migrations or DB not ready)"

# Set Playwright browser path for headless Chromium
export PLAYWRIGHT_BROWSERS_PATH=/usr/lib/chromium
export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

exec gunicorn app.api.main:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers "${WEB_CONCURRENCY}" \
  --bind "0.0.0.0:${PORT}" \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
