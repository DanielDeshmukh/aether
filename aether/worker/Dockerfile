FROM mcr.microsoft.com/playwright:v1.52.0-noble

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --production=false

COPY prisma ./prisma
RUN npx prisma generate

COPY worker/src ./worker/src
COPY src ./src
COPY tsconfig.json ./

WORKDIR /app/worker
RUN npx tsc --noEmit || true

CMD ["npx", "tsx", "src/index.ts"]
