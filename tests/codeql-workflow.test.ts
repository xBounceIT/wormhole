import assert from 'node:assert/strict';
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { parse } from 'yaml';

import { buildCodeqlGo, codeqlGoBuildPlan } from '../scripts/codeql-go-build.ts';

const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));
const workflow = parse(
  readFileSync(new URL('../.github/workflows/codeql.yml', import.meta.url), 'utf8'),
);

function fixture(t: test.TestContext): string {
  const root = mkdtempSync(join(tmpdir(), 'wormhole-codeql-é spaces-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, 'tools'));
  return root;
}

function addModule(root: string, name: string): string {
  const directory = join(root, 'tools', name);
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, 'go.mod'), 'module example.com/test\n\ngo 1.25.0\n');
  return directory;
}

test('CodeQL discovers nested modules and includes the Windows-only credential reader', (t) => {
  const root = fixture(t);
  const backend = addModule(root, 'backend');
  const shared = addModule(root, 'internal/shared');
  const reader = addModule(root, 'wormhole-credential-reader');
  addModule(root, 'vendor/ignored');
  addModule(root, 'node_modules/ignored');
  addModule(root, '.git/ignored');
  writeFileSync(join(root, 'tools', 'not-a-module.txt'), '');

  assert.deepEqual(codeqlGoBuildPlan(root), [
    { cwd: backend, goos: 'linux' },
    { cwd: shared, goos: 'linux' },
    { cwd: backend, goos: 'windows' },
    { cwd: shared, goos: 'windows' },
    { cwd: reader, goos: 'windows' },
    { cwd: backend, goos: 'darwin' },
    { cwd: shared, goos: 'darwin' },
  ]);
});

test('CodeQL refuses an empty module tree or missing tools directory', (t) => {
  const root = fixture(t);
  assert.throws(() => codeqlGoBuildPlan(root), /No Go modules/);
  assert.throws(() => codeqlGoBuildPlan(join(root, 'missing')), /ENOENT/);
});

test('CodeQL builds every planned module with uncached compilation and platform selection', (t) => {
  const root = fixture(t);
  addModule(root, 'backend');
  addModule(root, 'wormhole-credential-reader');
  const calls: { cwd: string; goos: string }[] = [];
  buildCodeqlGo(root, (command, args, options) => {
    assert.equal(command, 'go');
    assert.deepEqual(args.slice(0, 3), ['build', '-a', '-o']);
    assert.equal(args[4], './...');
    assert.equal(args[3], process.platform === 'win32' ? 'NUL' : '/dev/null');
    assert.equal(options.env.CGO_ENABLED, '0');
    assert.equal(options.env.GOARCH, 'amd64');
    const pathKey = Object.keys(process.env).find((key) => key.toLowerCase() === 'path')!;
    assert.equal(options.env[pathKey], process.env[pathKey]);
    assert.equal(options.stdio, 'inherit');
    assert.equal(options.windowsHide, true);
    calls.push({ cwd: options.cwd, goos: options.env.GOOS! });
    return { status: 0 };
  });
  assert.deepEqual(calls, codeqlGoBuildPlan(root));
});

test('CodeQL stops immediately when Go cannot start or a build fails', (t) => {
  const root = fixture(t);
  addModule(root, 'backend');
  const error = new Error('go not available');
  assert.throws(
    () => buildCodeqlGo(root, () => ({ status: null, error })),
    (caught) => caught === error,
  );
  for (const status of [1, null]) {
    let calls = 0;
    assert.throws(
      () =>
        buildCodeqlGo(root, () => {
          calls++;
          return { status };
        }),
      /CodeQL Go build failed.*\(linux\): (1|unknown)/,
    );
    assert.equal(calls, 1);
  }
});

test('CodeQL entrypoint builds real modules from its own root without output artifacts', (t) => {
  const root = fixture(t);
  const library = addModule(root, 'internal/shared');
  const reader = addModule(root, 'wormhole-credential-reader');
  writeFileSync(join(library, 'shared.go'), 'package shared\nfunc Value() int { return 1 }\n');
  writeFileSync(
    join(reader, 'main_windows.go'),
    '//go:build windows\n\npackage main\nfunc main() {}\n',
  );
  const scripts = join(root, 'scripts');
  mkdirSync(scripts);
  const script = join(scripts, 'codeql-go-build.ts');
  copyFileSync(new URL('../scripts/codeql-go-build.ts', import.meta.url), script);
  writeFileSync(join(root, 'package.json'), '{"type":"module"}');
  const result = spawnSync(process.execPath, ['--experimental-strip-types', script], {
    cwd: tmpdir(),
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.match(/CodeQL Go build:/g)?.length, 4);
  assert.ok(result.stdout.includes(`${reader} (windows/amd64)`));
  assert.ok(!result.stdout.includes(`${reader} (linux/amd64)`));
  assert.ok(!result.stdout.includes(`${reader} (darwin/amd64)`));
  assert.deepEqual(readdirSync(library).sort(), ['go.mod', 'shared.go']);
  assert.deepEqual(readdirSync(reader).sort(), ['go.mod', 'main_windows.go']);
});

test('CodeQL covers all seven repository modules and all portable backend platforms', () => {
  const plan = codeqlGoBuildPlan(repositoryRoot);
  const windows = plan.filter(({ goos }) => goos === 'windows');
  assert.equal(windows.length, 7);
  assert.ok(windows.some(({ cwd }) => cwd.endsWith('wormhole-credential-reader')));
  assert.ok(windows.some(({ cwd }) => cwd.endsWith(join('internal', 'sockstun'))));
  for (const goos of ['linux', 'windows', 'darwin']) {
    assert.ok(plan.some((build) => build.goos === goos && build.cwd.endsWith('wormhole-backend')));
  }
});

test('CodeQL preserves all languages, triggers, and read-only repository permissions', () => {
  assert.deepEqual(workflow.on.push.branches, ['main']);
  assert.deepEqual(workflow.on.pull_request.branches, ['main']);
  assert.ok(workflow.on.schedule[0].cron);
  assert.ok(Object.hasOwn(workflow.on, 'workflow_dispatch'));
  assert.deepEqual(workflow.permissions, { contents: 'read' });
  const job = workflow.jobs.analyze;
  assert.equal(job.permissions['security-events'], 'write');
  assert.equal(job.strategy['fail-fast'], false);
  assert.deepEqual(
    job.strategy.matrix.include,
    ['actions', 'c-cpp', 'csharp', 'javascript-typescript', 'go'].map((language) => ({
      language,
      'build-mode': language === 'go' ? 'manual' : 'none',
    })),
  );
  for (const step of job.steps.filter((step: { uses?: string }) => step.uses)) {
    assert.match(step.uses, /@[a-f0-9]{40}$/);
  }
});

test('CodeQL initializes tracing before Go builds and analyzes afterwards', () => {
  const steps = workflow.jobs.analyze.steps;
  const init = steps.findIndex((step: { name?: string }) => step.name === 'Initialize CodeQL');
  const build = steps.findIndex((step: { run?: string }) =>
    step.run?.includes('codeql-go-build.ts'),
  );
  const analyze = steps.findIndex((step: { name?: string }) => step.name === 'Analyze');
  assert.ok(init >= 0 && build > init && analyze > build);
  assert.deepEqual(steps[init].with, {
    languages: '${{ matrix.language }}',
    'build-mode': '${{ matrix.build-mode }}',
  });
  assert.equal(steps[build].if, "matrix.language == 'go'");
  assert.equal(steps[build].run, 'node --experimental-strip-types scripts/codeql-go-build.ts');
  const setup = steps.find((step: { name?: string }) => step.name === 'Setup Go');
  assert.ok(steps.indexOf(setup) < init);
  assert.equal(setup.with['go-version-file'], 'tools/wormhole-backend/go.mod');
  assert.equal(setup.with.cache, false);
  assert.equal(steps[analyze].with.category, '/language:${{ matrix.language }}');
});
