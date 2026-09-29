import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    /* Pinned. `localhost` makes Node bind IPv6 ::1 only on Windows, which an
     * IPv4 readiness check (run.ps1) cannot see; and a busy port must fail
     * loudly rather than move the dashboard to 5174 in the middle of a demo. */
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    /* Proxy the API through the dev server so the dashboard is same-origin in
     * development as well as in production, where FastAPI serves the built
     * assets itself. Without this the client would need an absolute URL, which
     * reintroduces CORS and breaks on any host mismatch - including localhost
     * versus 127.0.0.1, which are the same server but different origins. */
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
});
