FROM node:20-alpine AS build

WORKDIR /app

# Build context is the monorepo root (see docker-compose.yml) so the
# @sec-toolkit/common workspace resolves via npm workspaces.
COPY package.json package-lock.json ./
COPY packages/sec-common/frontend/package.json ./packages/sec-common/frontend/
COPY packages/osint-toolkit/frontend/package.json ./packages/osint-toolkit/frontend/
# soc-toolkit is referenced by the workspace root but not needed for the
# osint build - install it anyway because npm workspaces resolves all
# siblings, and the alternative is a fragile workspace-filter flag.
COPY packages/soc-toolkit/frontend/package.json ./packages/soc-toolkit/frontend/

RUN npm ci

COPY packages/sec-common/frontend/ ./packages/sec-common/frontend/
COPY packages/osint-toolkit/frontend/ ./packages/osint-toolkit/frontend/

RUN npm -w osint-toolkit-frontend run build

# nginx-unprivileged runs as UID 101 and listens on :8080 by default.
# Port 80 requires CAP_NET_BIND_SERVICE which we avoid giving the
# container - compose publishes 3001 on the host, internal port is 8080.
FROM nginxinc/nginx-unprivileged:alpine
COPY --from=build /app/packages/osint-toolkit/frontend/dist /usr/share/nginx/html
COPY packages/osint-toolkit/frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
