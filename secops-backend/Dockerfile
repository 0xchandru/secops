# ---------- Stage 1: Build ----------
FROM node:22-alpine AS builder

WORKDIR /app

# Copy manifests first for layer caching
COPY package.json ./

# Install all deps (incl. dev for build)
RUN npm install

# Copy source and build config
COPY tsconfig.json build.mjs drizzle.config.ts ./
COPY src/ src/
COPY scripts/ scripts/

# Build
RUN node build.mjs

# ---------- Stage 2: Production ----------
FROM node:22-alpine AS runner

ENV NODE_ENV=production
WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

# Copy built output and scripts
COPY --from=builder /app/dist/ dist/
COPY --from=builder /app/scripts/ scripts/
COPY --from=builder /app/drizzle.config.ts ./

EXPOSE 8080

CMD ["node", "--enable-source-maps", "dist/index.mjs"]
