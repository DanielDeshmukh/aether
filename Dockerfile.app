FROM node:20-alpine AS builder

WORKDIR /app

COPY aether/package.json aether/package-lock.json* ./
RUN npm install

COPY aether/prisma ./prisma
RUN npx prisma generate

COPY aether/src ./src
COPY aether/public ./public
COPY aether/next.config.* ./
COPY aether/tsconfig.json ./
COPY aether/.env .env

RUN npm run build

FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

EXPOSE 3000
CMD ["node", "server.js"]
