import * as React from 'react';
import { createRoot } from 'react-dom/client';
import App, { CredentialsPage } from '../../src/App';
import { TooltipProvider } from '../../src/components/ui/tooltip';
import { ContextMenuOverlayProvider } from '../../src/components/ui/context-menu';
import '../../src/index.css';

declare global {
  interface Window {
    certificateAssert: typeof import('node:assert/strict');
    runCertificateTests(): Promise<void>;
  }
}

window.runCertificateTests = async () => {
  const assert = window.certificateAssert;
  const root = createRoot(document.getElementById('root')!);
  const tick = () => React.act(async () => new Promise((resolve) => setTimeout(resolve, 25)));
  const dialog = () => [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].at(-1)!;
  const button = (label: string, scope: ParentNode = dialog()) => {
    const result = [...scope.querySelectorAll<HTMLButtonElement>('button')].find(
      (element) => element.textContent?.trim() === label,
    );
    assert.ok(result, `Missing button: ${label}`);
    return result;
  };
  const click = async (element: HTMLElement) => {
    await React.act(async () => element.click());
    await tick();
  };
  const input = async (id: string, value: string) => {
    const element = document.getElementById(id) as HTMLInputElement;
    assert.ok(element, `Missing input ${id}`);
    await React.act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(
        element,
        value,
      );
      element.dispatchEvent(new Event('input', { bubbles: true }));
    });
  };
  const certificateRow = () =>
    document.querySelector<HTMLElement>('[aria-label="SSH certificate"]')!;
  const submit = async () => {
    await React.act(async () =>
      dialog()
        .querySelector('form')!
        .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })),
    );
    await tick();
  };
  const key = { selectionId: '11111111-1111-4111-8111-111111111111', fileName: 'id_ed25519' };
  const certificate = {
    selectionId: '22222222-2222-4222-8222-222222222222',
    fileName: 'id_ed25519-cert.pub',
  };
  const saved: WormholeWorkspaceCredential = {
    id: '33333333-3333-4333-8333-333333333333',
    name: 'CA login',
    protocol: 'ssh',
    kind: 'sshKey',
    username: 'operator',
    provider: 'Local',
    canEdit: true,
    canDelete: true,
    privateKeyFileName: key.fileName,
    hasCertificate: true,
    certificateFileName: certificate.fileName,
    certificate: {
      keyId: 'vault-key',
      principals: ['operator'],
      validBefore: '2000-01-01T00:00:00Z',
      signingCaFingerprint: 'SHA256:test',
    },
  };
  const requests: any[] = [];
  const discarded: string[] = [];
  let keySelection: any = { ...key, suggestedCertificate: certificate };
  let keyPickerError: unknown;
  let pendingKey: Promise<any> | undefined;
  let certificateSelection: any = certificate;
  let pickerError: unknown;
  let saveError = false;
  let pendingCertificate: Promise<any> | undefined;
  const bridge = {
    selectSshPrivateKey: async () => {
      if (keyPickerError) throw keyPickerError;
      return pendingKey ?? keySelection;
    },
    selectSshCertificate: async () => {
      if (pickerError) throw pickerError;
      return pendingCertificate ?? certificateSelection;
    },
    discardSshPrivateKeySelection: async ({ selectionId }: { selectionId: string }) => {
      discarded.push(selectionId);
      return { discarded: true };
    },
    discardSshCertificateSelection: async ({ selectionId }: { selectionId: string }) => {
      discarded.push(selectionId);
      return { discarded: true };
    },
  } as unknown as NonNullable<Window['wormhole']>;
  let mountID = 0;
  const mountEditor = async (credential?: WormholeWorkspaceCredential, authorized = true) => {
    window.wormhole = bridge;
    await React.act(async () =>
      root.render(
        <TooltipProvider>
          <CredentialsPage
            key={++mountID}
            editorOnly
            initialCredentials={credential ? [credential] : []}
            initialEditor={{ credential, username: 'operator' }}
            isAuthorized={authorized}
            onCreate={async (request) => {
              requests.push(request);
              if (saveError) throw new Error('certificate does not match');
            }}
            onUpdate={async (id, request) => {
              requests.push({ ...request, id });
              if (saveError) throw new Error('certificate does not match');
            }}
            onDelete={async () => {}}
          />
        </TooltipProvider>,
      ),
    );
    await tick();
  };

  await mountEditor();
  assert.match(certificateRow().textContent!, /No certificate attached/);
  await input('credential-name', 'Imported SSH');
  await click(
    button(
      'Select…',
      dialog().querySelector('[aria-label="SSH certificate"]')!.previousElementSibling!,
    ),
  );
  assert.match(certificateRow().textContent!, /id_ed25519-cert.pub/);
  await click(button('Remove', certificateRow()));
  assert.match(certificateRow().textContent!, /No certificate attached/);
  await click(button('Select…', certificateRow()));
  assert.match(certificateRow().textContent!, /validated when saving/);
  certificateSelection = null;
  await click(button('Replace…', certificateRow()));
  assert.match(certificateRow().textContent!, /id_ed25519-cert.pub/);
  pickerError = new Error('bad certificate file');
  await click(button('Replace…', certificateRow()));
  assert.match(dialog().textContent!, /bad certificate file/);
  pickerError = 'unexpected picker failure';
  await click(button('Replace…', certificateRow()));
  assert.match(dialog().textContent!, /Could not select the SSH certificate/);
  pickerError = undefined;
  certificateSelection = certificate;
  await input('credential-key-passphrase', 'one-shot-pass');
  saveError = true;
  await submit();
  assert.equal(
    (document.getElementById('credential-key-passphrase') as HTMLInputElement).value,
    '',
  );
  assert.equal(requests.at(-1).certificateSelectionId, certificate.selectionId);
  assert.equal(requests.at(-1).passphrase, 'one-shot-pass');
  saveError = false;
  await click(button('Cancel'));

  await mountEditor(saved);
  assert.match(certificateRow().textContent!, /Expired/);
  assert.match(certificateRow().textContent!, /vault-key/);
  await click(button('Replace…', certificateRow()));
  await submit();
  assert.equal(requests.at(-1).privateKeySelectionId, '');
  assert.equal(requests.at(-1).certificateSelectionId, certificate.selectionId);
  assert.equal(requests.at(-1).clearCertificate, false);

  await mountEditor({
    ...saved,
    certificate: {
      ...saved.certificate!,
      validBefore: new Date(Date.now() + 7 * 3600000).toISOString(),
    },
  });
  assert.match(certificateRow().textContent!, /Expires in 7 h/);
  await click(button('Remove', certificateRow()));
  await submit();
  assert.equal(requests.at(-1).clearCertificate, true);
  assert.equal(requests.at(-1).certificateSelectionId, '');

  await mountEditor({ ...saved, certificate: { ...saved.certificate!, validBefore: undefined } });
  assert.match(certificateRow().textContent!, /No expiry/);
  await click(button('Cancel'));
  await mountEditor({
    ...saved,
    kind: 'password',
    protocol: 'rdp',
    username: 'No username',
    domain: 'CORP',
    provider: 'Bitwarden',
    privateKeyFileName: undefined,
    certificateFileName: undefined,
    hasCertificate: false,
    certificate: undefined,
    bitwardenItemId: 'vault-item',
    bitwardenItemName: 'Vault login',
  });
  assert.equal((document.getElementById('credential-username') as HTMLInputElement).value, '');
  await click(button('Cancel'));
  await mountEditor();
  window.wormhole = undefined;
  await click(button('Select…', certificateRow()));
  await click(button('Select…', certificateRow().previousElementSibling!));
  window.wormhole = bridge;
  keySelection = key;
  await click(button('Select…', certificateRow().previousElementSibling!));
  assert.match(certificateRow().textContent!, /No certificate attached/);
  keySelection = null;
  await click(button('Select…', certificateRow().previousElementSibling!));
  assert.match(dialog().textContent!, /id_ed25519/);
  keyPickerError = new Error('Private key picker failed');
  await click(button('Select…', certificateRow().previousElementSibling!));
  assert.match(dialog().textContent!, /Private key picker failed/);
  keyPickerError = 'unexpected';
  await click(button('Select…', certificateRow().previousElementSibling!));
  assert.match(dialog().textContent!, /Could not select the SSH key/);
  keyPickerError = undefined;
  let resolvePicker: (value: any) => void = () => {};
  pendingCertificate = new Promise((resolve) => {
    resolvePicker = resolve;
  });
  await click(button('Select…', certificateRow()));
  await click(button('Cancel'));
  await React.act(async () => resolvePicker(certificate));
  await tick();
  assert.ok(discarded.includes(certificate.selectionId));
  pendingCertificate = undefined;
  await mountEditor();
  let resolveKey: (value: any) => void = () => {};
  pendingKey = new Promise((resolve) => {
    resolveKey = resolve;
  });
  await click(button('Select…', certificateRow().previousElementSibling!));
  await click(button('Cancel'));
  await React.act(async () => resolveKey({ ...key, suggestedCertificate: certificate }));
  await tick();
  assert.ok(discarded.includes(key.selectionId));
  pendingKey = undefined;
  await mountEditor(saved, false);
  assert.equal(document.querySelector('[role="dialog"]'), null);

  // Locking resets the editor while its authorized mutation may still finish.
  // That completion must not close or put errors into a newly opened draft.
  const regularKey = ++mountID;
  for (const rejectSave of [false, true]) {
    let finishSave: () => void = () => {};
    let failSave: (error: Error) => void = () => {};
    const pendingSave = new Promise<void>((resolve, reject) => {
      finishSave = resolve;
      failSave = reject;
    });
    const regular = async (isAuthorized: boolean) => {
      await React.act(async () =>
        root.render(
          <TooltipProvider>
            <CredentialsPage
              key={regularKey + Number(rejectSave)}
              initialCredentials={[saved]}
              isAuthorized={isAuthorized}
              onCreate={async () => {}}
              onUpdate={() => pendingSave}
              onDelete={async () => {}}
            />
          </TooltipProvider>,
        ),
      );
      await tick();
    };
    await regular(true);
    const edit = document.querySelector<HTMLElement>('[aria-label="Edit CA login"]');
    assert.ok(edit);
    await click(edit);
    await submit();
    await regular(false);
    await regular(true);
    await click(button('Add credential', document));
    await input('credential-name', 'Keep this draft');
    await React.act(async () => {
      if (rejectSave) failSave(new Error('old operation failed'));
      else finishSave();
    });
    await tick();
    assert.ok(dialog(), 'the old operation closed a new editor');
    assert.equal(
      dialog().hasAttribute('data-closed'),
      false,
      'the old operation dismissed a new editor',
    );
    assert.equal(
      (document.getElementById('credential-name') as HTMLInputElement).value,
      'Keep this draft',
    );
    assert.doesNotMatch(dialog().textContent!, /old operation failed/);
    await click(button('Cancel'));
  }
  await React.act(async () => root.unmount());

  // Mount the real connection editor: creation must leave the connection open,
  // select the newly saved credential and preserve the user's target fields.
  const appRoot = createRoot(document.getElementById('root')!);
  window.wormhole = undefined;
  await React.act(async () =>
    appRoot.render(
      <ContextMenuOverlayProvider>
        <App
          initialAuthState={{
            mode: 'disabled',
            fallback: 'pin',
            idleTimeoutMinutes: null,
            hasPin: false,
            hasPassword: false,
            isCorrupted: false,
            configured: false,
            windowsHello: { available: false, message: '' },
          }}
          initialWorkspace={{
            tree: [],
            credentials: [],
            credentialOptions: { ssh: [], rdp: [], vnc: [] },
            tunnels: [],
          }}
          initialSettings={{
            theme: 'dark',
            promptBeforeTunnelConnect: true,
            autoCopyOnSelect: false,
            confirmOnTabClose: true,
            confirmOnWindowClose: true,
            sidebarWidth: 320,
            sidebarPinned: true,
            connectionTreeExpansion: null,
            autoCheckForUpdates: false,
            lastUpdateCheck: null,
            skippedUpdateVersion: null,
          }}
        />
      </ContextMenuOverlayProvider>,
    ),
  );
  await tick();
  await click(button('Quick Connect', document));
  await input('connection-host', 'server.example.test');
  await click(button('Use an SSH key or certificate…'));
  window.wormhole = {
    ...bridge,
    createCredential: async (request) => {
      requests.push(request);
      return saved;
    },
    getWorkspace: async () => ({
      tree: [],
      credentials: [saved],
      credentialOptions: { ssh: [saved], rdp: [], vnc: [] },
      tunnels: [],
    }),
    openSshSession: async () => {
      throw new Error('SSH certificate expired on 2026-10-24 14:00 UTC; replace the certificate');
    },
    reportActiveSessionCount: async () => {},
  } as unknown as NonNullable<Window['wormhole']>;
  keySelection = { ...key, suggestedCertificate: certificate };
  await input('credential-name', 'Shortcut key');
  await input('credential-username', 'operator');
  await click(button('Select…', certificateRow().previousElementSibling!));
  await submit();
  assert.match(dialog().textContent!, /Quick Connect/);
  assert.equal(
    (document.getElementById('connection-host') as HTMLInputElement).value,
    'server.example.test',
  );
  assert.match(document.getElementById('connection-credential')!.textContent!, /CA login/);
  assert.equal(requests.at(-1).kind, 'sshKey');
  assert.equal(requests.at(-1).certificateSelectionId, certificate.selectionId);
  await click(button('Connect'));
  for (
    let attempt = 0;
    attempt < 50 && !document.body.textContent?.includes('SSH certificate expired');
    attempt++
  )
    await tick();
  assert.ok(
    document.body.textContent?.includes('SSH certificate expired'),
    document.body.innerText.slice(-4000),
  );
  await click(button('Replace certificate…', document));
  assert.match(dialog().textContent!, /Edit credential/);
  assert.match(certificateRow().textContent!, /vault-key/);
  window.wormhole = undefined;
  await React.act(async () => appRoot.unmount());
};
