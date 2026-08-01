import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // No asset may be inlined as a data: URI or an inline <script>. The
    // server's Content-Security-Policy is scriptSrc 'self' with no
    // 'unsafe-inline', so an inlined asset would be silently blocked in the
    // browser while building and testing just fine.
    assetsInlineLimit: 0,
  },
  server: { proxy: { "/v1": "http://localhost:3000", "/web": "http://localhost:3000" } },
});
