# Build stage
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt

# Runtime stage
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install Playwright/Chromium system dependencies for PDF generation
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        chromium \
        fontconfig \
        libnss3 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        libgbm1 \
        libpango-1.0-0 \
        libcairo2 \
        libasound2 \
        libxshmfence1 \
        libx11-xcb1 \
        libxcb-dri3-0 \
        libxext6 \
        libxfixes3 \
        libxi6 \
        libxtst6 \
        libx11-6 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY app ./app
COPY main.py ./main.py
COPY start.sh ./start.sh
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic
COPY .env.example ./.env.example

# Install Playwright browsers (Chromium only)
RUN playwright install chromium

RUN chmod +x /app/start.sh

EXPOSE 8000

CMD ["/app/start.sh"]
