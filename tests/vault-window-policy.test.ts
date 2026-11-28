import assert from 'node:assert/strict';
import test from 'node:test';
import type { BrowserWindowConstructorOptions } from 'electron';
import { VaultWindowPolicy, protectSecretWindow } from '../electron/vault-window-policy.ts';

class FakeWindow {
  protected = false;
  destroyed = false;
  protectionAvailable = true;
  events: string[] = [];

  isContentProtected() {
    return this.protected;
  }
  setContentProtection(enabled: boolean) {
    this.events.push(`protect:${enabled}`);
    if (this.protectionAvailable) this.protected = enabled;
  }
  show() {
    this.events.push('show');
  }
  destroy() {
    this.destroyed = true;
    this.events.push('destroy');
  }
  isDestroyed() {
    return this.destroyed;
  }
}

function fixture(platform: NodeJS.Platform = 'win32') {
  const windows: FakeWindow[] = [];
  const requests: BrowserWindowConstructorOptions[] = [];
  let available = true;
  const policy = new VaultWindowPolicy({
    platform,
    getWindows: () => windows,
    createWindow: (options) => {
      requests.push(options);
      const window = new FakeWindow();
      window.protectionAvailable = available;
      windows.push(window);
      return window;
    },
  });
  return { policy, requests, windows, available: (value: boolean) => (available = value) };
}

test('application windows share secure preferences with their own preload and partition', () => {
  const { policy, requests } = fixture('linux');
  policy.apply('default');
  const window = policy.createWindow({
    show: true,
    webPreferences: { partition: 'scoped', preload: 'owner.cjs', devTools: true, sandbox: false },
  });
  assert.deepEqual(requests[0], {
    show: true,
    webPreferences: {
      partition: 'scoped',
      preload: 'owner.cjs',
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      devTools: false,
    },
  });
  policy.apply('standard');
  assert.deepEqual(window.events, []);
  assert.throws(() => policy.apply('paranoid'), /Content protection unavailable/);
  assert.equal(window.isContentProtected(), false);
});

test('strong profiles protect existing windows and enforce protection before new windows show', () => {
  for (const platform of ['win32', 'darwin'] as const) {
    const { policy, requests } = fixture(platform);
    const existing = policy.createWindow({});
    const destroyed = policy.createWindow({});
    destroyed.destroy();
    assert.equal(policy.requiresContentProtection, false);
    policy.apply('hardened');
    assert.equal(policy.requiresContentProtection, true);
    assert.deepEqual(existing.events, ['protect:true']);
    assert.deepEqual(destroyed.events, ['destroy']);

    const hidden = policy.createWindow({ show: false });
    const visible = policy.createWindow({});
    assert.deepEqual(hidden.events, ['protect:true']);
    assert.deepEqual(visible.events, ['protect:true', 'show']);
    assert.equal(requests.at(-1)?.show, false);
    policy.apply('paranoid');
    assert.deepEqual(existing.events, ['protect:true']);
  }
});

test('a weaker authenticated profile releases only protection owned by the all-window policy', () => {
  const { policy } = fixture();
  const prior = policy.createWindow({});
  protectSecretWindow(prior);
  const native = policy.createWindow({});
  native.setContentProtection(true);
  const ordinary = policy.createWindow({});
  policy.apply('paranoid');
  const during = policy.createWindow({ show: false });
  protectSecretWindow(during);
  policy.apply('standard');
  assert.equal(policy.requiresContentProtection, false);
  assert.deepEqual(ordinary.events, ['protect:true', 'protect:false']);
  for (const window of [prior, native, during]) assert.equal(window.isContentProtected(), true);
  assert.deepEqual(policy.createWindow({}).events, []);
});

test('a failed requirement denies activation and destroys new windows before showing them', () => {
  const { policy, available, requests, windows } = fixture();
  available(false);
  const existing = policy.createWindow({});
  assert.throws(() => policy.apply('hardened'), /Content protection unavailable/);
  assert.throws(() => policy.createWindow({}), /Content protection unavailable/);
  assert.equal(requests.at(-1)?.show, false);
  assert.deepEqual(windows.at(-1)?.events, ['protect:true', 'destroy']);
  assert.deepEqual(existing.events, ['protect:true']);
  // The failed activation keeps new windows subject to the strict requirement.
  available(true);
  assert.deepEqual(policy.createWindow({}).events, ['protect:true', 'show']);
});
