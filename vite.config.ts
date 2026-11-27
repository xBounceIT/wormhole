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
      input: {
        main: fileURLToPath(new URL('./index.html', import.meta.url)),
        vaultCreate: fileURLToPath(new URL('./vault-create.html', import.meta.url)),
        vaultReauthentication: fileURLToPath(new URL('./vault-reauth.html', import.meta.url)),
        vaultShared: fileURLToPath(new URL('./vault-shared.html', import.meta.url)),
        vaultSharedSetup: fileURLToPath(new URL('./vault-shared-setup.html', import.meta.url)),
        vaultCredentials: fileURLToPath(new URL('./vault-credentials.html', import.meta.url)),
        vaultNotes: fileURLToPath(new URL('./vault-notes.html', import.meta.url)),
        vaultVncPassword: fileURLToPath(new URL('./vault-vnc-password.html', import.meta.url)),
        vaultBitwardenCliUnlock: fileURLToPath(
          new URL('./vault-bitwarden-cli-unlock.html', import.meta.url),
        ),
        vaultTunnelAuthentication: fileURLToPath(
          new URL('./vault-tunnel-authentication.html', import.meta.url),
        ),
        vaultSshCredentials: fileURLToPath(
          new URL('./vault-ssh-credentials.html', import.meta.url),
        ),
        vaultRdpCredentials: fileURLToPath(
          new URL('./vault-rdp-credentials.html', import.meta.url),
        ),
        vaultTunnel: fileURLToPath(new URL('./vault-tunnel.html', import.meta.url)),
      },
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
