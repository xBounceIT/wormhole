import { build } from 'vite';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
export async function buildVaultBitwardenBridge(outputDirectory = join(repoRoot, 'dist-electron')) {
  const result = await build({
    configFile: false,
    root: repoRoot,
    logLevel: 'warn',
    resolve: {
      alias: [
        {
          find: /^(?:node:)?crypto$/,
          replacement: join(repoRoot, 'src/vault-bitwarden-extension-crypto.ts'),
        },
      ],
    },
    build: {
      outDir: outputDirectory,
      emptyOutDir: false,
      sourcemap: false,
      target: 'es2022',
      lib: {
        entry: join(repoRoot, 'src/vault-bitwarden-extension-entry.ts'),
        formats: ['iife'],
        name: 'WormholeVaultBitwarden',
        fileName: () => 'vault-bitwarden-extension.js',
      },
    },
  });
  const chunks = (Array.isArray(result) ? result : [result])
    .flatMap((r) => r.output)
    .filter((r) => r.type === 'chunk');
  // Rolldown records an inlined lazy module as a self-reference, not a file load.
  if (
    chunks.length !== 1 ||
    chunks[0].imports.length ||
    chunks[0].dynamicImports.some((name) => name !== chunks[0].fileName)
  )
    throw Error('Bitwarden bridge must be one standalone browser asset.');
  return join(outputDirectory, 'vault-bitwarden-extension.js');
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await buildVaultBitwardenBridge();
