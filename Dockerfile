FROM node:20-slim AS frontend
WORKDIR /app/aether
COPY aether/package*.json ./
RUN npm ci
COPY aether/prisma ./prisma
COPY aether/prisma.config.ts ./
COPY aether/src ./src
COPY aether/public ./public
COPY aether/next.config.ts ./
COPY aether/postcss.config.mjs ./
COPY aether/tsconfig.json ./
COPY aether/eslint.config.mjs ./
RUN npx prisma generate
RUN npx next build

FROM python:3.12-slim AS backend
WORKDIR /app/aether/backend
COPY aether/backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY aether/backend/app ./app

FROM node:20-slim AS runtime
RUN apt-get update && apt-get install -y python3 python3-pip && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=frontend /app/aether/.next ./.next
COPY --from=frontend /app/aether/node_modules ./node_modules
COPY --from=frontend /app/aether/package.json ./
COPY --from=frontend /app/aether/prisma ./.prisma
COPY --from=backend /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=backend /usr/local/bin/python3 /usr/local/bin/python3
COPY --from=backend /app/aether/backend ./backend
COPY aether/src ./src
COPY aether/public ./public
COPY aether/next.config.ts ./
COPY aether/postcss.config.mjs ./
COPY aether/tsconfig.json ./
COPY aether/eslint.config.mjs ./
EXPOSE 3000
ENV NODE_ENV=production
CMD ["node_modules/.bin/next", "start"]
