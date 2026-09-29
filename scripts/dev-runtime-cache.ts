import { createHash } from 'node:crypto';
import {
  accessSync,
  constants,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import type { DevRuntimeBuildStep } from './dev-runtime-plan.ts';

// Exclude generated trees, including CMake/vcpkg outputs and .NET intermediates.
// Hash file contents so edits, deletions and branch switches invalidate the cache even
// when a checkout restores old timestamps. Only build hashes are persisted here.
const metadataDirectories = new Set(['.git', 'node_modules']);

export function devRuntimeEnvironment(
  environment: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
): Record<string, string | undefined> {
  return Object.fromEntries(
    Object.entries(environment)
      .filter(([name]) =>
        /^(PATH|GO.*|CGO.*|CC|CXX|CFLAGS|CPPFLAGS|CXXFLAGS|LDFLAGS|SDKROOT|MACOSX_DEPLOYMENT_TARGET|VCPKG.*|WORMHOLE_OVPN.*|DOTNET.*)$/i.test(
          name,
        ),
      )
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, value]) => {
        if (name.toUpperCase() !== 'PATH' || !value) return [name, value];
        // Nested npm scripts prepend the same .bin directories repeatedly. Keep
        // resolution order while normalizing duplicates, so direct builds and
        // npm run dev share their native cache.
        const separator = platform === 'win32' ? ';' : ':';
        const seen = new Set<string>();
        const paths = value.split(separator).filter((entry) => {
          const key = platform === 'win32' ? entry.toLowerCase() : entry;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
        return [name.toUpperCase(), paths.join(separator)];
      }),
  );
}

export function devRuntimeGoEnvironment(contents: string): string {
  try {
    const environment = JSON.parse(contents);
    if (!environment || typeof environment !== 'object' || Array.isArray(environment)) return '';
    // go env derives GOGCCFLAGS using a fresh temporary work directory on each
    // query. Its stable inputs (architecture, CC and CGO_*FLAGS) remain in the key.
    delete environment.GOGCCFLAGS;
    return JSON.stringify(environment);
  } catch {
    return '';
  }
}

export function devRuntimeCacheAllowed(goEnvironment: string): boolean {
  try {
    const { GOWORK, GOFLAGS } = JSON.parse(goEnvironment);
    // Workspaces and these flags can introduce build inputs outside the repository.
    // Keep those workflows fresh rather than pretending their paths are content hashes.
    return (
      typeof GOWORK === 'string' &&
      (GOWORK === '' || GOWORK === 'off') &&
      typeof GOFLAGS === 'string' &&
      !/(?:^|[\s'"])-{1,2}(?:overlay|modfile|toolexec|pkgdir|a)(?:=|[\s'"]|$)/.test(GOFLAGS) &&
      // auto selects default.pgo inside the already hashed main-package directory;
      // off uses no profile. Every other PGO value can refer to an external file.
      !/(?:^|[\s'"])-{1,2}pgo(?:=(?!(?:auto|off)(?:[\s'"]|$))|(?=[\s'"]|$))/.test(GOFLAGS)
    );
  } catch {
    return false;
  }
}

export function devRuntimeGoModuleDirectories(root: string, plan: DevRuntimeBuildStep[]): string[] {
  return [...new Set(plan.flatMap((step) => step.inputs))]
    .map((input) => path.join(root, input))
    .filter((directory) => existsSync(path.join(directory, 'go.mod')));
}

function fingerprint(root: string, inputs: string[], excludedInputs: string[] = []): string {
  const hash = createHash('sha256');
  const normalize = (input: string) => {
    const normalized = path.normalize(input);
    return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
  };
  const excluded = new Set(excludedInputs.map(normalize));
  function visit(relative: string): void {
    if (excluded.has(normalize(relative))) return;
    const absolute = path.join(root, relative);
    hash.update(JSON.stringify(relative));
    let stats;
    try {
      stats = statSync(absolute);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      hash.update('missing');
      return;
    }
    if (stats.isDirectory()) {
      for (const entry of readdirSync(absolute, { withFileTypes: true }).sort((a, b) =>
        a.name.localeCompare(b.name),
      )) {
        if (metadataDirectories.has(normalize(entry.name))) continue;
        visit(path.join(relative, entry.name));
      }
    } else {
      hash.update(createHash('sha256').update(readFileSync(absolute)).digest());
    }
  }
  for (const input of inputs) visit(input);
  return hash.digest('hex');
}

function outputFingerprint(root: string, outputs: string[]): string {
  for (const output of outputs) {
    const stats = statSync(path.join(root, output));
    if (!stats.isFile() || stats.size === 0) {
      throw new Error(`Development build did not produce ${output}.`);
    }
    if (process.platform !== 'win32') accessSync(path.join(root, output), constants.X_OK);
  }
  return fingerprint(root, outputs);
}

export function runCachedDevRuntimeBuild({
  root,
  plan,
  context,
  execute,
  force = false,
  log = console.info,
}: {
  root: string;
  plan: DevRuntimeBuildStep[];
  context: unknown;
  execute: (step: DevRuntimeBuildStep) => void;
  force?: boolean;
  log?: (message: string) => void;
}): void {
  const cacheDirectory = path.join(root, 'obj', 'dev-runtime');
  mkdirSync(cacheDirectory, { recursive: true });
  for (const step of plan) {
    const started = performance.now();
    if (
      step.bootstrap &&
      step.bootstrap.outputs.some((output) => !existsSync(path.join(root, output)))
    ) {
      log(`[Wormhole] Prepare ${step.name} sources.`);
      execute({ ...step.bootstrap, name: `${step.name} sources`, inputs: [] });
      for (const output of step.bootstrap.outputs) {
        if (!existsSync(path.join(root, output)))
          throw new Error(`Development bootstrap did not produce ${output}.`);
      }
    }
    const key = createHash('sha256').update(JSON.stringify({ step, context })).digest('hex');
    const stampPath = path.join(cacheDirectory, `${key}.json`);
    const sourcePaths = [
      'scripts/build-dev-backend.ts',
      'scripts/dev-runtime-plan.ts',
      'scripts/dev-runtime-cache.ts',
      ...step.inputs,
    ];
    const inputs = fingerprint(root, sourcePaths, step.excludedInputs);
    if (!force) {
      try {
        const stamp = JSON.parse(readFileSync(stampPath, 'utf8'));
        if (stamp.inputs === inputs && stamp.outputs === outputFingerprint(root, step.outputs)) {
          log(
            `[Wormhole] Reuse ${step.name} (${((performance.now() - started) / 1000).toFixed(2)}s).`,
          );
          continue;
        }
      } catch {
        // Missing/corrupt stamps or outputs always rebuild; a failed build never gets a stamp.
      }
    }
    rmSync(stampPath, { force: true });
    log(`[Wormhole] Build ${step.name}.`);
    execute(step);
    const outputs = outputFingerprint(root, step.outputs);
    const currentInputs = fingerprint(root, sourcePaths, step.excludedInputs);
    if (currentInputs === inputs) {
      writeFileSync(stampPath, JSON.stringify({ inputs, outputs }));
    }
    log(`[Wormhole] Ready ${step.name} (${((performance.now() - started) / 1000).toFixed(2)}s).`);
  }
}
