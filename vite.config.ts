import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { xtermWebglFontFix } from './scripts/xterm-webgl-font.ts';

export default defineConfig({
  base: './',
  plugins: [xtermWebglFontFix(), react(), tailwindcss()],
  optimizeDeps: {
    rolldownOptions: { plugins: [xtermWebglFontFix()] },
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    // public/Assets is copied first. On macOS/Windows it would absorb Vite's default
    // assets directory with the wrong casing, which ASAR then preserves case-sensitively.
    assetsDir: 'renderer-assets',
    emptyOutDir: true,
    sourcemap: false,
    rolldownOptions: {
      output: {
        codeSplitting: {
          minSize: 20_000,
          maxSize: 400_000,
          groups: [
            {
              name: 'react-vendor',
              test: /node_modules[\\/](?:react|react-dom)[\\/]/,
              priority: 30,
            },
            {
              name: 'ui-vendor',
              test: /node_modules[\\/](?:@base-ui|@radix-ui|radix-ui|lucide-react)[\\/]/,
              priority: 20,
            },
            {
              name: 'vendor',
              test: /node_modules[\\/]/,
              priority: 10,
            },
          ],
        },
      },
    },
  },
});
