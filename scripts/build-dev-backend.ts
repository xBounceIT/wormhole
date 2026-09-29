import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createDevRuntimeBuildPlan, devRuntimeToolchainCommands } from './dev-runtime-plan.ts';
import {
  devRuntimeCacheAllowed,
  devRuntimeEnvironment,
  devRuntimeGoEnvironment,
  devRuntimeGoModuleDirectories,
  runCachedDevRuntimeBuild,
} from './dev-runtime-cache.ts';

const scriptDirectory = fileURLToPath(new URL('.', import.meta.url));
const root = fileURLToPath(new URL('..', import.meta.url));
const buildPlan = createDevRuntimeBuildPlan({
  platform: process.platform,
  architecture: process.arch,
  scriptDirectory,
  nodeExecutable: process.execPath,
});

console.info(`[Wormhole] Preparing development runtime for ${process.platform}/${process.arch}.`);

const environment = devRuntimeEnvironment(process.env, process.platform);
const toolchains = devRuntimeToolchainCommands(process.arch).map((command) => {
  const result = spawnSync(command, [command === 'go' ? 'version' : '--version'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  return [command, result.status, result.stdout, result.error?.message];
});

// Fetch-OvpnProxy hydrates these values from the registry. Include them in the
// cache key too, so installing/replacing a native toolchain invalidates reuse.
const registryEnvironment =
  process.platform === 'win32'
    ? spawnSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-Command',
          "@('User', 'Machine') | ForEach-Object { [Environment]::GetEnvironmentVariable('PATH', $_); [Environment]::GetEnvironmentVariable('VCPKG_ROOT', $_) }",
        ],
        { encoding: 'utf8', windowsHide: true },
      ).stdout
    : '';
const goEnvironments = devRuntimeGoModuleDirectories(root, buildPlan).map((cwd) =>
  devRuntimeGoEnvironment(
    spawnSync('go', ['env', '-json'], { cwd, encoding: 'utf8', windowsHide: true }).stdout,
  ),
);

runCachedDevRuntimeBuild({
  root,
  plan: buildPlan,
  context: {
    platform: process.platform,
    architecture: process.arch,
    environment,
    toolchains,
    registryEnvironment,
    goEnvironments,
  },
  force:
    process.argv.includes('--force') ||
    goEnvironments.some((environment) => !devRuntimeCacheAllowed(environment)),
  execute(step) {
    const result = spawnSync(step.command, step.args, { stdio: 'inherit', windowsHide: true });
    if (result.error) {
      throw new Error(`Failed to start ${step.name}: ${result.error.message}`);
    }
    if (result.status !== 0) {
      throw new Error(`${step.name} exited with status ${result.status ?? 'unknown'}.`);
    }
  },
});
