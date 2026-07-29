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

CMD ["npx", "tsx", "src/main.ts"]
