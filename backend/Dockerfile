FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY backend/main.py ./main.py
COPY backend/start.sh ./start.sh
COPY backend/tests ./tests
COPY backend/.env.example ./.env.example

RUN chmod +x /app/start.sh

EXPOSE 8000

CMD ["/app/start.sh"]
