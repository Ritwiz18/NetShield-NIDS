# ==================================================
# NetShield-NIDS — Multi-Stage React Frontend Dockerfile
# ==================================================

# Stage 1: Node.js Builder
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY package.json package-lock.json ./

# Install frontend dependencies
RUN npm ci || npm install

# Copy application source code
COPY . .

# Build production static bundle
RUN npm run build

# Stage 2: Production Nginx Server
FROM nginx:alpine

# Clean default Nginx html assets
RUN rm -rf /usr/share/nginx/html/*

# Copy compiled static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration with API reverse proxy
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose container HTTP port
EXPOSE 80

# Healthcheck
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1

# Start Nginx in foreground
CMD ["nginx", "-g", "daemon off;"]
