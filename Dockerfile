FROM node:22-slim AS deps

WORKDIR /app

# better-sqlite3 needs Python + a C++ toolchain to compile its native addon
# via node-gyp. These are only needed here in the builder stage; the final
# stage below does not carry them, so the runtime image stays slim. This is
# native-module compilation, not the TypeScript build step the plan
# deliberately avoids.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
# better-sqlite3 bundles a prebuilt linux-arm64 binary that's linked against
# a newer glibc than this Debian bookworm base ships, and its build script
# always prefers that bundled prebuild over compiling, regardless of ABI/
# glibc compatibility. Install with scripts skipped (so the incompatible
# prebuild is never loaded/used), delete it, then force a real node-gyp
# compile with the toolchain installed above.
RUN npm ci --omit=dev --ignore-scripts \
    && rm -f node_modules/better-sqlite3/prebuilds/*.node \
    && npm rebuild better-sqlite3 --build-from-source

# The SPA is built in its own stage rather than in `deps`, because the two
# stages need opposite dependency sets: `deps` installs --omit=dev to keep the
# runtime node_modules slim, while Vite/React live in devDependencies and are
# needed only to produce static files. Nothing from this stage reaches the
# runtime image except web/dist.
#
# --ignore-scripts here skips better-sqlite3's native compile entirely: this
# stage never loads the addon, it only runs Vite, so paying for a node-gyp
# build (and carrying python3/make/g++) would be pure build time for nothing.
FROM node:22-slim AS webbuild

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY web ./web
RUN npm run build:web

FROM node:22-slim

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY src ./src
COPY demo ./demo
COPY tsconfig.json ./
# Fastify serves this at / with an SPA history fallback (src/api/server.ts
# resolves it as ../../web/dist relative to src/api/). The image is broken
# without it -- every non-API route would 404 -- so it is copied, never
# mounted.
COPY --from=webbuild /app/web/dist ./web/dist

ENV NODE_ENV=production
# config.ts defaults HOST to 127.0.0.1, which is the right default for `npm run
# dev` (don't put a dev server on the LAN) but wrong inside a container: the
# process would bind the container's loopback only, so EXPOSE/-p publishes a
# port that resets every connection. The container's network namespace is the
# isolation boundary here, not the bind address. docker-compose.yml already
# sets this explicitly; setting it in the image too means a plain
# `docker run -p` works instead of appearing to start and then refusing traffic.
ENV HOST=0.0.0.0
EXPOSE 3000

# The app writes its DB and keys under /data (see docker-compose.yml's volume
# mount) as the non-root `node` user below -- create it and hand over
# ownership before dropping root, so that user can actually write there.
# Also chown /app (the WORKDIR itself, not recursively -- existing files
# under it stay root-owned and world-readable, which is all the app needs to
# read its own source/node_modules): DB_PATH/KEY_DIR default to relative
# paths under the CWD when unset, so a container run without those two env
# vars explicitly set (e.g. a quick smoke test outside docker-compose's
# managed /data volume) still needs to create human-attest.db and keys/
# directly under /app as this non-root user.
RUN mkdir -p /data && chown -R node:node /data && chown node:node /app
USER node

# No curl in this slim image -- use Node's own http client instead.
# /healthz is exempt from rate limiting (src/api/routes.health.ts), so this
# probe never risks tripping the same limit real traffic shares.
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node -e "require('http').get('http://localhost:3000/healthz', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

# Run the local tsx binary directly -- no npx/npm wrapper -- so this Node
# process is PID 1 and receives SIGTERM/SIGINT directly instead of an
# npm-exec/sh -c wrapper chain swallowing them (Finding 3, 2026-07-29 final
# review: `docker kill --signal=TERM` never reached main.ts's SIGTERM
# handler under the old `npx tsx` CMD).
CMD ["node_modules/.bin/tsx", "src/main.ts"]
