#!/bin/sh
set -eu

PORT="${PORT:-8000}"
WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}"
ENVIRONMENT="${ENVIRONMENT:-development}"

# Run database migrations
echo "Running Alembic migrations..."
if [ "$ENVIRONMENT" = "production" ]; then
  alembic upgrade head
else
  alembic upgrade head 2>/dev/null || echo "Alembic migration skipped (no migrations or DB not ready)"
fi

# Set Playwright browser path for headless Chromium
export PLAYWRIGHT_BROWSERS_PATH=/usr/lib/chromium
export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

exec gunicorn app.api.main:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers "${WEB_CONCURRENCY}" \
  --bind "0.0.0.0:${PORT}" \
  --timeout 120 \
  --max-requests 1000 \
  --max-requests-jitter 50 \
  --access-logfile - \
  --error-logfile -
