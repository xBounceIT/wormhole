import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MRemoteImportDialog } from '../../src/components/MRemoteImportDialog';

declare const assert: typeof import('node:assert/strict');

export async function runMRemoteDialogTests() {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const root = createRoot(document.getElementById('root')!);
  const requests: Array<{ phase: string; options: unknown }> = [];
  let failAnalysis = false;
  let failCommit = false;
  let failRefresh = false;
  let encrypted = false;
  let fullFileEncrypted = false;
  let closed = 0;
  let refreshed = 0;
  const inspection = { fileName: 'connections.xml', fileSize: 1024, confVersion: '2.7' };
  const plan: WormholeMRemoteImportPlan = {
    planToken: 'a'.repeat(64),
    folders: 1,
    connections: 11,
    credentials: 5,
    credentialsReused: 2,
    sharedCredentials: 3,
    sharedCredentialConnections: 11,
    skippedUnsupported: 0,
    skippedUnsupportedSamples: [],
    warnings: [],
    droppedWarnings: 0,
    preview: [
      { name: 'Linux', kind: 'folder', depth: 1 },
      { name: 'server', kind: 'connection', protocol: 'ssh', depth: 2 },
    ],
    previewTruncated: false,
  };
  const result: WormholeMRemoteImportResult = {
    foldersCreated: 1,
    connectionsCreated: 11,
    credentialsCreated: 5,
    credentialsReused: 2,
    skippedUnsupported: 0,
    warnings: [],
    droppedWarnings: 0,
  };
  window.wormhole = {
    onOperationProgress: () => () => {},
    clearMRemoteImport: () => {},
    cancelMRemoteImportAnalysis: () => {},
    selectMRemoteImport: async () => ({
      ...inspection,
      passwordRequired: encrypted,
      fullFileEncrypted,
    }),
    analyzeMRemoteImport: async (options) => {
      requests.push({ phase: 'analyze', options });
      if (failAnalysis) throw new Error('analysis unavailable');
      return plan;
    },
    commitMRemoteImport: async (options) => {
      requests.push({ phase: 'commit', options });
      if (failCommit) throw new Error('workspace changed; analyze again');
      return result;
    },
  } as unknown as Window['wormhole'];
  const render = async () =>
    act(async () =>
      root.render(
        <MRemoteImportDialog
          open
          onOpenChange={() => closed++}
          onImported={async () => {
            refreshed++;
            if (failRefresh) throw new Error('refresh failed');
          }}
        />,
      ),
    );
  const button = (text: string) =>
    [...document.querySelectorAll<HTMLButtonElement>('button')].find(
      (item) => item.textContent?.trim() === text,
    )!;
  const click = async (text: string) => {
    assert.ok(button(text), `Missing button: ${text}`);
    await act(async () => button(text).click());
  };
  const reuseCheckbox = () =>
    [...document.querySelectorAll<HTMLElement>('label')]
      .find((item) => item.textContent === 'Reuse matching saved credentials')!
      .querySelector<HTMLButtonElement>('[role=checkbox]')!;
  await render();
  await click('Choose file…');
  assert.equal(reuseCheckbox().getAttribute('aria-checked'), 'true');
  await click('Analyze file');
  assert.deepEqual(requests.at(-1), {
    phase: 'analyze',
    options: { password: '', structureOnly: false, reuseExisting: true },
  });
  assert.match(
    document.body.textContent!,
    /Credentials: 5 new \(3 shared by 11 connections\), 2 reused/,
  );
  assert.ok(button('Import plan'));
  await act(async () => reuseCheckbox().click());
  assert.equal(button('Import plan'), undefined);
  assert.ok(button('Analyze file'));
  await click('Analyze file');
  assert.deepEqual(requests.at(-1), {
    phase: 'analyze',
    options: { password: '', structureOnly: false, reuseExisting: false },
  });
  failCommit = true;
  await click('Import plan');
  assert.match(document.body.textContent!, /workspace changed; analyze again/);
  assert.ok(button('Analyze file'));
  failCommit = false;
  await click('Analyze file');
  await click('Import plan');
  assert.deepEqual(requests.at(-1), {
    phase: 'commit',
    options: { password: '', structureOnly: false, reuseExisting: false },
  });
  assert.match(document.body.textContent!, /Reused 2 saved credentials/);
  assert.equal(refreshed, 1);
  await click('Close');
  assert.equal(closed, 1);
  await render();
  encrypted = true;
  await click('Choose file…');
  assert.equal(reuseCheckbox().getAttribute('aria-checked'), 'true');
  assert.equal(button('Analyze file').disabled, true);
  const password = document.querySelector<HTMLInputElement>('#mremote-import-password')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(
      password,
      'master-password',
    );
    password.dispatchEvent(new Event('input', { bubbles: true }));
  });
  failAnalysis = true;
  await click('Analyze file');
  assert.match(document.body.textContent!, /analysis unavailable/);
  failAnalysis = false;
  const structure = [...document.querySelectorAll<HTMLElement>('label')]
    .find((item) => item.textContent?.includes('Import structure only'))!
    .querySelector<HTMLButtonElement>('[role=checkbox]')!;
  await act(async () => structure.click());
  assert.equal(password.value, '');
  assert.equal(reuseCheckbox().disabled, true);
  plan.warnings = ['Passwords skipped'];
  plan.droppedWarnings = 2;
  plan.skippedUnsupportedSamples = ['legacy: Telnet'];
  plan.previewTruncated = true;
  await click('Analyze file');
  assert.deepEqual(requests.at(-1), {
    phase: 'analyze',
    options: { password: '', structureOnly: true, reuseExisting: true },
  });
  assert.match(document.body.textContent!, /Passwords skipped/);
  assert.match(document.body.textContent!, /Preview truncated/);
  failRefresh = true;
  result.warnings = ['One', 'Two', 'Three', 'Four'];
  result.droppedWarnings = 1;
  await click('Import plan');
  assert.match(document.body.textContent!, /Import completed, but the workspace could not refresh/);
  assert.match(document.body.textContent!, /2 additional warnings/);
  await click('Close');
  fullFileEncrypted = true;
  await click('Choose file…');
  assert.equal(button('Analyze file').disabled, true);
  assert.match(document.body.textContent!, /full-file encryption/);
  await click('Cancel');
  await act(async () => root.unmount());
}
