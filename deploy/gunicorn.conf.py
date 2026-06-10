"""Gunicorn configuration for AETHER production deployment."""

import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
backlog = 2048

# Worker processes
workers = int(os.getenv("WEB_CONCURRENCY", multiprocessing.cpu_count() * 2 + 1))
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
timeout = 120
keepalive = 5

# Restart workers after this many requests (to prevent memory leaks)
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "aether"

# Server mechanics
preload_app = True
daemon = False
tmp_upload_dir = None

# SSL (uncomment for production)
# certfile = "/etc/nginx/ssl/cert.pem"
# keyfile = "/etc/nginx/ssl/key.pem"

# Security
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# Memory management
worker_tmp_dir = "/dev/shm"
