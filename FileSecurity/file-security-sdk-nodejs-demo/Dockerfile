FROM node:24.11.1-slim

LABEL org.opencontainers.image.title="fs-demoapp-node"
WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-fund --no-audit

COPY . .

# OpenShift: UID 1001, GID 0 con permisos de grupo (igual que la demo Python)
RUN mkdir -p uploads && chown -R 1001:0 /app && chmod -R g=u /app
USER 1001

EXPOSE 8080
CMD ["node", "app.js"]
