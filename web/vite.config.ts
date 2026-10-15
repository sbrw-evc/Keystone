import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': 'http://localhost:8080', '/oauth2': 'http://localhost:8080', '/.well-known': 'http://localhost:8080' },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: (id: string) => (/node_modules\/(react|react-dom|scheduler|react-router|react-router-dom)\//.test(id) ? 'vendor' : undefined),
      },
    },
  },
  test: { environment: 'jsdom' },
} as never);
