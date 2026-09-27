declare function CredentialsSearchHarness(props: {
  isAuthorized?: boolean;
}): import('react').ReactElement;

// eslint-disable-next-line no-unused-vars -- Called by auth-prompt.tsx after the fixtures are combined.
async function runBitwardenDemandTests() {
  const root = createRoot(document.getElementById('root'));
  let searches = 0,
    reads = 0,
    unlocked = false;
  const queries: string[] = [];
  let search = async () => {
    if (!unlocked) throw new Error('Bitwarden vault is locked.');
    return { items: [{ id: 'router', name: 'Router', username: 'admin' }] };
  };
  window.wormhole = {
    searchBitwardenItems: async (query) => {
      queries.push(query);
      searches++;
      return search();
    },
    readBitwardenStartupState: async () => {
      reads++;
      return {
        serverRegion: 'Europe',
        status: { status: 'Locked', serverUrl: null, hasSessionKey: false },
      };
    },
    unlockBitwardenCli: async () => {
      unlocked = true;
    },
  } as unknown as typeof window.wormhole;
  let key = 0;
  const mount = async () =>
    React.act(async () => root.render(<CredentialsSearchHarness key={++key} />));
  const click = async (id: string) => React.act(async () => document.getElementById(id).click());
  const dialog = () => document.querySelector('[role="dialog"]');
  await mount();
  assert.equal(reads, 0, 'opening the credentials editor must not authenticate Bitwarden');
  await click('vault-search');
  assert.equal(searches, 1);
  assert.equal(reads, 1);
  assert.match(dialog().textContent, /Unlock Bitwarden/);
  await React.act(async () => {
    const field = document.getElementById('runtime-bitwarden-password');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(
      field,
      'test-only-secret',
    );
    field.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await React.act(async () => dialog().querySelector('form').requestSubmit());
  assert.equal(searches, 2, 'successful authentication resumes the original search');
  assert.deepEqual(queries, ['router', 'router']);
  assert.equal(dialog(), null);
  assert.equal(document.getElementById('vault-selected').textContent, 'router');
  assert.equal(document.getElementById('vault-item-count').textContent, '1');

  for (const items of [[], [{ id: 'a' }, { id: 'b' }]]) {
    search = async () => ({ items });
    await mount();
    await click('vault-search');
    assert.equal(document.getElementById('vault-item-count').textContent, String(items.length));
    assert.equal(dialog(), null);
  }
  search = async () => {
    throw new Error('Network unavailable');
  };
  await click('vault-search');
  assert.match(document.getElementById('vault-search-status').textContent, /Network unavailable/);
  assert.equal(dialog(), null, 'transport errors must not request a password');

  for (const outcome of ['resolve', 'reject']) {
    let resolve, reject;
    search = () =>
      new Promise((done, fail) => {
        resolve = done;
        reject = fail;
      });
    await mount();
    await click('vault-search');
    const before = searches;
    await click('vault-search');
    assert.equal(searches, before, 'an in-flight search must not be duplicated');
    await click('vault-editor-close');
    await React.act(async () => {
      if (outcome === 'resolve') resolve({ items: [{ id: 'late' }] });
      else reject(new Error('Bitwarden vault is locked'));
    });
    assert.equal(dialog(), null, 'late results cannot reopen a closed editor');
    assert.equal(document.getElementById('vault-item-count').textContent, '0');
  }
  // Successful login hides the modal before synchronization completes. Editing
  // the search during that wait must not revive the old query on completion.
  unlocked = false;
  search = async () => {
    if (!unlocked) throw new Error('You are not logged in.');
    return { items: [] };
  };
  window.wormhole.readBitwardenStartupState = async () => ({
    serverRegion: 'Europe',
    status: { status: 'Unauthenticated', serverUrl: null, hasSessionKey: false },
  });
  window.wormhole.loginBitwardenCli = async () => {
    unlocked = true;
    return { loggedIn: true };
  };
  let finishSync: () => void;
  window.wormhole.syncBitwardenCli = () =>
    new Promise<void>((resolve) => {
      finishSync = resolve;
    }) as never;
  await mount();
  await click('vault-search');
  assert.match(dialog().textContent, /Log in to Bitwarden/);
  const type = async (id: string, value: string) =>
    React.act(async () => {
      const field = document.getElementById(id);
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(field, value);
      field.dispatchEvent(new Event('input', { bubbles: true }));
    });
  await type('bw-login-email', 'operator@example.test');
  await type('bw-login-password', 'test-only-secret');
  await React.act(async () => dialog().querySelector('form').requestSubmit());
  assert.equal(dialog(), null);
  await type('vault-query', 'updated-router');
  await React.act(async () => finishSync());
  assert.equal(queries.at(-1), 'updated-router', 'authentication must resume the current query');

  window.wormhole = undefined;
  await click('vault-search');
  await React.act(async () => root.unmount());
}
