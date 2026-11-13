import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    target: 'chrome116',
    rollupOptions: {
      input: { sidepanel: resolve(import.meta.dirname, 'sidepanel.html'), background: resolve(import.meta.dirname, 'src/background.ts') },
      output: { entryFileNames: '[name].js', chunkFileNames: 'assets/[name]-[hash].js' },
    },
  },
});
