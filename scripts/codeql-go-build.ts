import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface GoBuild {
  cwd: string;
  goos: string;
}

export function codeqlGoBuildPlan(repositoryRoot: string): GoBuild[] {
  const modules: string[] = [];
  function visit(directory: string): void {
    const entries = readdirSync(directory, { withFileTypes: true });
    if (entries.some((entry) => entry.isFile() && entry.name === 'go.mod')) {
      modules.push(directory);
    }
    for (const entry of entries) {
      if (entry.isDirectory() && !['vendor', 'node_modules', '.git'].includes(entry.name)) {
        visit(join(directory, entry.name));
      }
    }
  }
  visit(join(repositoryRoot, 'tools'));
  if (modules.length === 0) {
    throw new Error('No Go modules found for CodeQL analysis.');
  }
  const credentialReader = join(repositoryRoot, 'tools', 'wormhole-credential-reader');
  return ['linux', 'windows', 'darwin'].flatMap((goos) =>
    modules
      .sort()
      .filter((cwd) => goos === 'windows' || cwd !== credentialReader)
      .map((cwd) => ({ cwd, goos })),
  );
}

type BuildRunner = (
  command: string,
  args: string[],
  options: {
    cwd: string;
    env: NodeJS.ProcessEnv;
    stdio: 'inherit';
    windowsHide: boolean;
  },
) => { status: number | null; error?: Error };

export function buildCodeqlGo(repositoryRoot: string, run: BuildRunner = spawnSync): void {
  const plan = codeqlGoBuildPlan(repositoryRoot);
  // Go recognizes its host's null device for both libraries and executables.
  const output = process.platform === 'win32' ? 'NUL' : '/dev/null';
  for (const { cwd, goos } of plan) {
    console.log(`CodeQL Go build: ${cwd} (${goos}/amd64)`);
    const result = run('go', ['build', '-a', '-o', output, './...'], {
      cwd,
      env: { ...process.env, GOOS: goos, GOARCH: 'amd64', CGO_ENABLED: '0' },
      stdio: 'inherit',
      windowsHide: true,
    });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(`CodeQL Go build failed for ${cwd} (${goos}): ${result.status ?? 'unknown'}`);
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildCodeqlGo(dirname(dirname(fileURLToPath(import.meta.url))));
}
