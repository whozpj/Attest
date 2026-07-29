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

FROM node:22-slim

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY src ./src
COPY demo ./demo
COPY tsconfig.json ./

ENV NODE_ENV=production
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
