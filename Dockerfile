# syntax=docker/dockerfile:1

# better-sqlite3's install script is `prebuild-install || node-gyp rebuild`.
# Current versions do ship musl prebuilds, but when one is missing for a given
# version/arch the fallback compile needs a toolchain. Keep that toolchain in
# the builder so the image still builds either way and stays free of it.
FROM node:22-alpine AS builder
WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production PORT=3000 DATA_DIR=/app/data
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
COPY src/ src/
COPY public/ public/
RUN mkdir -p /app/data
EXPOSE 3000
VOLUME /app/data
CMD ["node", "src/server.js"]
