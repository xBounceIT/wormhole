import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

export const coverageThreshold = 80;

export interface GoCoverage {
  covered: number;
  total: number;
}

const ignoredDiscoveryDirectories = new Set([
  '.git',
  'bin',
  'dist',
  'dist-electron',
  'node_modules',
  'obj',
  'vendor',
]);

function discoverFiles(directory: string, matches: (name: string) => boolean): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
    left.name.localeCompare(right.name),
  )) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (!ignoredDiscoveryDirectories.has(entry.name)) {
        files.push(...discoverFiles(path, matches));
      }
    } else if (entry.isFile() && matches(entry.name)) {
      files.push(path);
    }
  }
  return files;
}

export function discoverTypeScriptTests(repositoryRoot: string): string[] {
  return discoverFiles(join(repositoryRoot, 'tests'), (name) => /\.test\.(?:mjs|ts)$/.test(name));
}

export function discoverGoModules(repositoryRoot: string): string[] {
  return discoverFiles(join(repositoryRoot, 'tools'), (name) => name === 'go.mod').map(dirname);
}

function run(command: string, args: string[], cwd: string): void {
  const result = spawnSync(command, args, { cwd, stdio: 'inherit' });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${basename(command)} exited with status ${result.status ?? 'unknown'}`);
  }
}

function runTypeScriptCoverage(repositoryRoot: string): void {
  const testFiles = discoverTypeScriptTests(repositoryRoot);
  if (testFiles.length === 0) {
    throw new Error('No TypeScript or JavaScript test files were found.');
  }

  // Node's native coverage can measure only modules loaded by node:test. React TSX surfaces and
  // process entrypoints remain protected by the repository's integration and source-contract
  // tests, but they are intentionally not represented by this unit-module percentage.
  console.log(`\nTypeScript loaded-module coverage (minimum ${coverageThreshold}%):`);
  run(
    process.execPath,
    [
      '--experimental-strip-types',
      '--experimental-test-coverage',
      `--test-coverage-lines=${coverageThreshold}`,
      `--test-coverage-branches=${coverageThreshold}`,
      `--test-coverage-functions=${coverageThreshold}`,
      '--test-coverage-include=src/**/*.ts',
      '--test-coverage-include=electron/**/*.ts',
      '--test-coverage-include=scripts/**/*.ts',
      '--test-coverage-include=scripts/**/*.mjs',
      '--test',
      ...testFiles,
    ],
    repositoryRoot,
  );
}

export function parseGoCoverage(contents: string): GoCoverage {
  const lines = contents.split(/\r?\n/);
  if (!/^mode: (?:atomic|count|set)$/.test(lines[0] ?? '')) {
    throw new Error('Go coverage profile has an invalid header.');
  }

  let covered = 0;
  let total = 0;
  for (const line of lines.slice(1)) {
    if (line.trim() === '') {
      continue;
    }
    const match = /^.+:\d+\.\d+,\d+\.\d+\s+(\d+)\s+(\d+)$/.exec(line);
    if (!match) {
      throw new Error(`Go coverage profile contains an invalid block: ${line}`);
    }

    const statements = Number(match[1]);
    const executions = Number(match[2]);
    if (!Number.isSafeInteger(statements) || !Number.isSafeInteger(executions)) {
      throw new Error(`Go coverage profile contains invalid counters: ${line}`);
    }
    total += statements;
    if (!Number.isSafeInteger(total)) {
      throw new Error('Go coverage statement total exceeds the safe integer range.');
    }
    if (executions > 0) {
      covered += statements;
    }
  }

  if (total === 0) {
    throw new Error('Go coverage profile contains no statements.');
  }
  return { covered, total };
}

export function meetsCoverageThreshold(coverage: GoCoverage, threshold: number): boolean {
  if (
    !Number.isSafeInteger(coverage.covered) ||
    !Number.isSafeInteger(coverage.total) ||
    coverage.covered < 0 ||
    coverage.total <= 0 ||
    coverage.covered > coverage.total ||
    !Number.isFinite(threshold) ||
    threshold < 0 ||
    threshold > 100
  ) {
    throw new Error('Coverage totals and threshold must be valid.');
  }
  return coverage.covered * 100 >= coverage.total * threshold;
}

function runGoCoverage(repositoryRoot: string): void {
  const goModules = discoverGoModules(repositoryRoot);
  if (goModules.length === 0) {
    throw new Error('No Go modules were found.');
  }

  const temporaryDirectory = mkdtempSync(join(tmpdir(), 'wormhole-coverage-'));
  let covered = 0;
  let total = 0;

  console.log(`\nGo coverage (aggregate minimum ${coverageThreshold}%):`);
  try {
    for (const [index, modulePath] of goModules.entries()) {
      const profilePath = join(temporaryDirectory, `module-${index}.out`);
      run('go', ['test', '-timeout=180s', './...', `-coverprofile=${profilePath}`], modulePath);

      const moduleCoverage = parseGoCoverage(readFileSync(profilePath, 'utf8'));
      covered += moduleCoverage.covered;
      total += moduleCoverage.total;
      console.log(
        `  ${basename(modulePath)}: ${((100 * moduleCoverage.covered) / moduleCoverage.total).toFixed(2)}% ` +
          `(${moduleCoverage.covered}/${moduleCoverage.total})`,
      );
    }
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }

  const aggregate = { covered, total };
  console.log(`  aggregate: ${((100 * covered) / total).toFixed(2)}% (${covered}/${total})`);
  if (!meetsCoverageThreshold(aggregate, coverageThreshold)) {
    throw new Error(`Go statement coverage must be at least ${coverageThreshold}%.`);
  }
}

export function main(repositoryRoot = resolve(import.meta.dirname, '..')): void {
  runTypeScriptCoverage(repositoryRoot);
  runGoCoverage(repositoryRoot);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Coverage verification failed.');
    process.exitCode = 1;
  }
}
