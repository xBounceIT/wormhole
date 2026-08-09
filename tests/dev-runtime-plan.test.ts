import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createDevRuntimeBuildPlan } from '../scripts/dev-runtime-plan.ts';

const planOptions = {
  architecture: 'x64' as const,
  scriptDirectory: path.join('repo', 'scripts'),
  nodeExecutable: 'node',
};

test('non-Windows development builds only the portable runtime', () => {
  for (const platform of ['linux', 'darwin'] as const) {
    const plan = createDevRuntimeBuildPlan({ ...planOptions, platform });

    assert.deepEqual(
      plan.map((step) => step.name),
      ['Go backend'],
    );
    assert.equal(path.basename(plan[0].args[0]), 'Build-ElectronBackend.mjs');
  }
});

test('Windows development builds all native runtime components', () => {
  const plan = createDevRuntimeBuildPlan({ ...planOptions, platform: 'win32' });

  assert.deepEqual(
    plan.map((step) => step.name),
    ['Windows VPN sidecars', 'Go backend', 'Windows credential reader', 'Windows RDP host'],
  );
  assert.equal(path.basename(plan[0].args[4]), 'Build-ElectronVpnSidecars.ps1');
  assert.equal(path.basename(plan[1].args[0]), 'Build-ElectronBackend.mjs');
  assert.deepEqual(
    plan.slice(2).map((step) => path.basename(step.args[4])),
    ['Build-CredentialReader.ps1', 'Build-RdpHost.ps1'],
  );
  assert.ok(plan[0].args.includes('-RequireRealOvpn'));
  assert.ok(plan.slice(1).every((step) => !step.args.includes('-RequireRealOvpn')));
  assert.ok(plan.every((step) => step.args.at(-1) === 'x64'));
});

test('development runtime uses the current ARM64 architecture', () => {
  const plan = createDevRuntimeBuildPlan({
    ...planOptions,
    platform: 'win32',
    architecture: 'arm64',
  });

  assert.ok(plan.every((step) => step.args.at(-1) === 'arm64'));
});

test('unsupported development architectures fail instead of building the wrong binaries', () => {
  assert.throws(
    () =>
      createDevRuntimeBuildPlan({
        ...planOptions,
        platform: 'linux',
        architecture: 'ia32',
      }),
    /Unsupported development architecture 'ia32'/,
  );
});
