import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'win32') {
  console.info(`[Wormhole] Skipping Windows Go backend on ${process.platform}.`);
  process.exit(0);
}

const architecture = process.arch === 'arm64' ? 'arm64' : 'x64';
const scriptDirectory = fileURLToPath(new URL('.', import.meta.url));
const buildScripts = ['Build-ElectronBackend.ps1', 'Build-CredentialReader.ps1'];

for (const scriptName of buildScripts) {
  const scriptPath = `${scriptDirectory}${scriptName}`;
  const result = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, '-Arch', architecture],
    { stdio: 'inherit' },
  );
  if (result.error) {
    console.error(`[Wormhole] Failed to start ${scriptName}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
