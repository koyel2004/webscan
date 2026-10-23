# ==============================================================================
# SentinelScan Frontend Dockerfile
# Multi-stage: Build with Node 20 -> Serve with hardened Nginx Alpine
# ==============================================================================

# Stage 1: Build static assets
FROM node:20-alpine AS build

WORKDIR /app

# Copy package manifests
COPY package*.json ./

# Install dependencies (recharts peer deps compatibility)
RUN npm install --legacy-peer-deps

# Copy frontend source
COPY . .

# Build production bundle
RUN npm run build

# Stage 2: Production Nginx runtime
FROM nginx:1.25-alpine AS production

# Install curl for container health check
RUN apk add --no-cache curl

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy compiled SPA assets from build stage
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
