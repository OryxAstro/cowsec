import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// `npm run dev` proxies the API to a CowSec server (e.g. an SSH tunnel to 127.0.0.1:8090).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { port: 5173, proxy: { '/api': { target: 'http://127.0.0.1:8090', changeOrigin: true } } },
});
