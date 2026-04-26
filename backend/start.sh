#!/bin/sh
set -eu

PORT="${PORT:-8000}"
WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}"

exec gunicorn app.api.main:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers "${WEB_CONCURRENCY}" \
  --bind "0.0.0.0:${PORT}" \
  --access-logfile - \
  --error-logfile -
