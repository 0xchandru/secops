# ---------- Stage 1: Build ----------
FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json ./

RUN npm install

COPY tsconfig.json vite.config.ts index.html components.json ./
COPY src/ src/
COPY public/ public/

# Build frontend
RUN npm run build

# ---------- Stage 2: Serve with nginx ----------
FROM nginx:alpine AS runner

COPY --from=builder /app/dist/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
