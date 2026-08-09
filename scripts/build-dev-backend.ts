import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createDevRuntimeBuildPlan } from './dev-runtime-plan.ts';

const scriptDirectory = fileURLToPath(new URL('.', import.meta.url));
const buildPlan = createDevRuntimeBuildPlan({
  platform: process.platform,
  architecture: process.arch,
  scriptDirectory,
  nodeExecutable: process.execPath,
});

console.info(`[Wormhole] Preparing development runtime for ${process.platform}/${process.arch}.`);

for (const step of buildPlan) {
  const result = spawnSync(step.command, step.args, { stdio: 'inherit', windowsHide: true });
  if (result.error) {
    console.error(`[Wormhole] Failed to start ${step.name}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
