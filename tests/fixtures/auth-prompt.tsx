// Executed with real React and Chromium by auth-prompt.test.ts. Only the preload
// bridge and presentational UI wrappers are replaced; hooks and dialog are real.
declare const React: typeof import('react');
declare const createRoot: typeof import('react-dom/client').createRoot;
declare const assert: typeof import('node:assert/strict');
declare function AuthPrompt(props: Record<string, unknown>): import('react').ReactElement;
declare function AppCloseHarness(props: Record<string, unknown>): import('react').ReactElement;
declare function Dialog(props: Record<string, unknown>): import('react').ReactElement;
declare function DialogContent(props: Record<string, unknown>): import('react').ReactElement;
declare function DialogTitle(props: Record<string, unknown>): import('react').ReactElement;
declare function showUnlock(startup: Record<string, unknown>): void;

async function runAuthPromptTests() {
  let root = createRoot(document.getElementById('root'));
  const remoteMessage =
    "Windows Hello isn't available in Remote Desktop. Use your Wormhole PIN or password.";
  const results: boolean[] = [];
  let checks = 0;
  let verifications = 0;
  let check = async () => ({ available: false, message: remoteMessage });
  let verifyHello = async () => ({ succeeded: false, message: 'Windows Hello was canceled.' });
  let verifySecret = async () => ({ succeeded: false, message: '' });
  window.wormhole = {
    checkWindowsHello: () => {
      checks += 1;
      return check();
    },
    verifyWindowsHello: () => {
      verifications += 1;
      return verifyHello();
    },
    verifyAuth: () => verifySecret(),
  };
  const state = {
    mode: 'windowsHello',
    fallback: 'pin',
    configured: true,
    windowsHello: { available: false, message: remoteMessage },
  };
  const request = { kind: 'lock', reason: 'Locked after inactivity.', autoWindowsHello: true };
  let key = 0;
  const mount = async (stateOverrides = {}, requestOverrides = {}) => {
    await React.act(async () => {
      root.render(
        <React.StrictMode>
          <AuthPrompt
            key={++key}
            state={{ ...state, ...stateOverrides }}
            request={{ ...request, ...requestOverrides }}
            onResult={(value: boolean) => results.push(value)}
          />
        </React.StrictMode>,
      );
    });
  };
  const text = () => document.getElementById('root').textContent;
  const helloButton = () =>
    [...document.querySelectorAll('button')].find((button) =>
      /Windows Hello/.test(button.textContent),
    );
  const clickHello = async () => {
    await React.act(async () => {
      helloButton().click();
    });
  };
  const assertNeutral = (message: string) => {
    assert.equal(text().split(message).length - 1, 1);
    assert.equal(document.querySelector('[role="alert"]'), null);
    assert.equal(document.querySelector('[role="status"]').textContent, message);
    assert.match(document.querySelector('[role="status"]').className, /text-muted-foreground/);
  };
  const deferred = () => {
    let resolve;
    const promise = new Promise((done) => {
      resolve = done;
    });
    return { promise, resolve };
  };
  const enterSecret = async () => {
    await React.act(async () => {
      const input = document.getElementById('auth-secret');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(
        input,
        'test-only-secret',
      );
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await React.act(async () => {
      document.querySelector('form').requestSubmit();
    });
  };

  await mount();
  assertNeutral(remoteMessage);
  assert.ok(!helloButton(), 'unavailable Hello must not offer a login button');
  assert.equal(checks, 1, 'StrictMode must not launch Hello twice');
  assert.equal(verifications, 0, 'unavailable Hello must not open verification');
  assert.equal(document.activeElement.id, 'auth-secret');
  assert.doesNotMatch(text(), /will open now/);

  const initialCheck = deferred();
  check = () => initialCheck.promise;
  await mount({ windowsHello: { available: true, message: 'Previously available.' } });
  assert.ok(!helloButton(), 'Hello must stay hidden until the current check succeeds');
  await React.act(async () => {
    initialCheck.resolve({ available: true, message: 'Windows Hello is ready.' });
  });
  assert.ok(helloButton());
  assertNeutral('Windows Hello was canceled.');

  // The live region must exist before asynchronous progress changes, so assistive
  // technology can announce waiting and the resulting neutral fallback message.
  const pending = deferred();
  check = () => pending.promise;
  const liveRegion = document.querySelector('[role="status"]');
  await clickHello();
  assert.equal(document.querySelector('[role="status"]'), liveRegion);
  assert.equal(liveRegion.textContent, 'Waiting for Windows Hello…');
  assert.equal(text().split('Waiting for Windows Hello…').length - 1, 1);
  assert.equal(helloButton().disabled, true);
  const checksWhilePending = checks;
  await clickHello();
  assert.equal(checks, checksWhilePending);

  await enterSecret();
  assert.equal(document.querySelector('[role="alert"]').textContent, 'Invalid PIN.');
  await React.act(async () => {
    pending.resolve({ available: false, message: remoteMessage });
  });
  assert.equal(document.querySelector('[role="alert"]').textContent, 'Invalid PIN.');
  assert.equal(liveRegion.textContent, remoteMessage);
  assert.ok(!helloButton(), 'Hello must disappear when a retry finds it unavailable');
  assert.equal(document.activeElement.id, 'auth-secret');

  for (const fallback of ['pin', 'password']) {
    const name = fallback === 'pin' ? 'Wormhole PIN' : 'Wormhole password';
    check = async () => ({ available: false, message: '' });
    await mount({ fallback });
    assertNeutral(`Windows Hello is unavailable. Use your ${name}.`);
    assert.ok(!helloButton());

    check = async () => {
      throw new Error('native availability failed');
    };
    await mount({ fallback });
    assertNeutral(`Windows Hello isn't available right now. Use your ${name}.`);
    assert.ok(!helloButton());

    check = async () => ({ available: true, message: 'Windows Hello is ready.' });
    verifyHello = async () => ({ succeeded: false, message: 'Windows Hello was canceled.' });
    await mount({ fallback });
    assertNeutral('Windows Hello was canceled.');
    assert.ok(helloButton(), 'canceled verification must still allow a retry');
    verifyHello = async () => ({ succeeded: false, message: '' });
    await clickHello();
    assertNeutral(`Windows Hello didn't recognize you. Use your ${name}.`);
    assert.ok(helloButton());
    verifyHello = async () => {
      throw new Error('native verification failed');
    };
    await clickHello();
    assertNeutral(`Windows Hello couldn't verify you. Try again or use your ${name}.`);
    assert.ok(helloButton(), 'a transient verification error must not hide available Hello');

    verifyHello = async () => {
      check = async () => ({ available: false, message: remoteMessage });
      return { succeeded: false, message: 'No Windows Hello device was found.' };
    };
    await clickHello();
    assert.ok(!helloButton(), 'Hello must disappear if availability changes during verification');
    assertNeutral(remoteMessage);

    check = async () => ({ available: true, message: 'Windows Hello is ready.' });
    verifyHello = async () => {
      check = async () => {
        throw new Error('availability refresh failed');
      };
      return { succeeded: false, message: 'Windows Hello was canceled.' };
    };
    await mount({ fallback });
    assert.ok(!helloButton(), 'a failed availability refresh must clear the previous ready state');
    assertNeutral(`Windows Hello isn't available right now. Use your ${name}.`);

    await enterSecret();
    assert.equal(
      document.querySelector('[role="alert"]').textContent,
      fallback === 'pin' ? 'Invalid PIN.' : 'Invalid password.',
    );
    verifySecret = async () => {
      throw new Error('secret verification failed');
    };
    await enterSecret();
    assert.equal(
      document.querySelector('[role="alert"]').textContent,
      `Wormhole couldn't check your ${fallback === 'pin' ? 'PIN' : 'password'}. Try again.`,
    );
    verifySecret = async () => ({ succeeded: false, message: '' });
  }

  check = async () => ({ available: true, message: 'Windows Hello is ready.' });
  verifyHello = async () => ({ succeeded: true, message: 'Verified.' });
  const beforeManualPrompt = verifications;
  await mount({}, { kind: 'confirmation', autoWindowsHello: false });
  assert.equal(verifications, beforeManualPrompt, 'manual prompts must only check availability');
  assert.ok(helloButton());
  const beforeRetry = results.length;
  await clickHello();
  assert.equal(results.length, beforeRetry + 1);
  assert.equal(results.at(-1), true);

  // Completing Hello must not move focus away from a control the user selected.
  const canceled = deferred();
  verifyHello = () => canceled.promise;
  await mount({}, { kind: 'confirmation' });
  const cancel = [...document.querySelectorAll('button')].find(
    (button) => button.textContent === 'Cancel',
  );
  cancel.focus();
  await React.act(async () => {
    canceled.resolve({ succeeded: false, message: 'Windows Hello was canceled.' });
  });
  assert.equal(document.activeElement, cancel);
  await React.act(async () => {
    cancel.click();
  });
  assert.equal(results.at(-1), false);

  const literalMessage = '<img src=x onerror=alert(1)> — Windows Hello';
  check = async () => ({ available: false, message: literalMessage });
  await mount();
  assertNeutral(literalMessage);
  assert.ok(!helloButton());
  assert.equal(document.querySelector('img'), null);

  for (const mode of ['pin', 'password']) {
    const checksBeforeMount = checks;
    await mount({ mode });
    assert.ok(!helloButton());
    assert.equal(checks, checksBeforeMount);
    assert.doesNotMatch(text(), /Windows Hello/);
    assert.equal(document.activeElement.id, 'auth-secret');
    const waiting = deferred();
    verifySecret = () => waiting.promise;
    const beforeSecret = results.length;
    await enterSecret();
    assert.equal(results.length, beforeSecret);
    assert.equal(document.querySelector('[role="status"]').textContent, 'Checking…');
    assert.equal(document.querySelector('[role="alert"]'), null);
    await React.act(async () => {
      waiting.resolve({ succeeded: true, message: 'Verified.' });
    });
    assert.equal(results.length, beforeSecret + 1);
    assert.equal(results.at(-1), true);
  }

  const stale = deferred();
  check = () => stale.promise;
  await mount();
  const beforeUnmount = results.length;
  await React.act(async () => {
    root.unmount();
  });
  const verifiesBeforeUnmount = verifications;
  await React.act(async () => {
    stale.resolve({ available: true, message: 'Ready.' });
  });
  assert.equal(results.length, beforeUnmount);
  assert.equal(verifications, verifiesBeforeUnmount);

  root = createRoot(document.getElementById('root'));
  const handoff = deferred();
  check = () => handoff.promise;
  await mount();
  const verifiesBeforeHandoff = verifications;
  await React.act(async () => {
    handoff.resolve({ available: true, message: 'Ready.' });
    // Closing the prompt can run after the status query settles but before its
    // continuation opens native verification.
    await Promise.resolve();
    root.unmount();
  });
  assert.equal(
    verifications,
    verifiesBeforeHandoff,
    'an unmounted prompt must not open verification after availability settles',
  );

  for (const succeeded of [true, false]) {
    root = createRoot(document.getElementById('root'));
    check = async () => ({ available: true, message: 'Ready.' });
    const lateVerification = deferred();
    verifyHello = () => lateVerification.promise;
    await mount();
    const checksBeforeClose = checks;
    const resultsBeforeClose = results.length;
    await React.act(async () => {
      root.unmount();
      lateVerification.resolve({ succeeded, message: '' });
    });
    assert.equal(checks, checksBeforeClose, 'closed prompts must not refresh availability');
    assert.equal(
      results.length,
      resultsBeforeClose,
      'closed prompts must ignore verification results',
    );
  }
}

async function runWindowCloseTests() {
  const root = createRoot(document.getElementById('root'));
  let closeListener;
  let authResults = 0;
  window.wormhole = {
    onWindowCloseConfirmationRequested: (listener) => {
      closeListener = listener;
      return () => {
        closeListener = undefined;
      };
    },
  };
  let key = 0;
  const mount = async (locked: boolean, remount = true) => {
    if (remount) key += 1;
    await React.act(async () => {
      root.render(
        <React.StrictMode>
          <AppCloseHarness key={key} locked={locked} onResult={() => authResults++} />
        </React.StrictMode>,
      );
    });
  };
  const button = (label: string) =>
    [...document.querySelectorAll<HTMLButtonElement>('[role="alertdialog"] button')].find(
      (element) => element.textContent === label,
    );
  const assertReachable = (element: HTMLElement) => {
    assert.ok(element);
    const rect = element.getBoundingClientRect();
    assert.ok(rect.width > 0 && rect.height > 0);
    const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
    assert.ok(element.contains(hit), `${element.textContent} is covered or inert`);
    element.focus();
    assert.ok(document.activeElement === element, `${element.textContent} cannot receive focus`);
  };
  const assertLocked = (phase: string) => {
    assert.ok(document.querySelector('dialog:modal'), `Lock dialog must remain modal: ${phase}`);
    assert.equal(document.querySelector('#workspace-action').parentElement.inert, true);
    document.querySelector<HTMLElement>('#workspace-action').focus();
    assert.notEqual(document.activeElement.id, 'workspace-action');
    assert.equal(authResults, 0, 'closing or cancelling must never authenticate');
  };
  const requestClose = async (action = 'window', activeSessionCount = 2) => {
    let settled = false;
    let result;
    await React.act(async () => {
      result = closeListener({ action, activeSessionCount });
      result.then(() => {
        settled = true;
      });
    });
    assert.equal(settled, false, 'sessions must wait for explicit close confirmation');
    return { result };
  };
  const finishAnimations = async () => {
    await React.act(async () => {
      await Promise.all(
        document
          .getAnimations()
          .filter((animation) => animation.effect.getComputedTiming().iterations !== Infinity)
          .map((animation) => animation.finished.catch(() => undefined)),
      );
    });
    // Radix restores focus in a timer after the exit animation unmounts its focus scope.
    await new Promise((resolve) => setTimeout(resolve, 0));
  };
  const click = async (label: string) => {
    const target = button(label);
    assertReachable(target);
    await React.act(async () => {
      target.click();
    });
    await finishAnimations();
  };
  const escape = async () => {
    await React.act(async () => {
      await require('electron').ipcRenderer.invoke('test:escape');
    });
    await finishAnimations();
  };

  await mount(true);
  assertLocked('initial lock');
  let pending = await requestClose();
  assert.equal(
    document.activeElement?.textContent,
    'Cancel',
    'close confirmation must receive focus',
  );
  assertReachable(button('Cancel'));
  assertReachable(button('Close and terminate sessions'));
  assertLocked('confirmation is open');
  assert.equal(await closeListener({ action: 'window', activeSessionCount: 2 }), false);
  await click('Cancel');
  assert.equal(await pending.result, false);
  assert.equal(
    document.activeElement?.id,
    'auth-secret',
    'cancelling close must restore keyboard focus to authentication',
  );
  assertLocked('Cancel closes confirmation');
  assertReachable(document.querySelector('#auth-secret'));

  pending = await requestClose();
  await escape();
  assert.equal(await pending.result, false);
  assert.equal(
    document.activeElement?.id,
    'auth-secret',
    'Escape must restore authentication focus',
  );
  assertLocked('Escape closes confirmation');
  for (let repeat = 0; repeat < 3; repeat++) {
    await escape();
    assertLocked('Escape while locked');
  }

  for (const action of ['window', 'quit']) {
    await mount(true);
    pending = await requestClose(action, 1);
    assert.match(
      document.querySelector('[role="alertdialog"]').textContent,
      action === 'quit' ? /Quit Wormhole\?/ : /Close Wormhole\?/,
    );
    await click('Close and terminate sessions');
    assert.equal(await pending.result, true);
    assertLocked(`${action} confirmed`);
    assert.equal(button('Terminating sessions…').disabled, true);
    assert.equal(button('Cancel').disabled, true);
    await escape();
    assert.ok(document.querySelector('[role="alertdialog"]'));
  }

  // A timeout can arrive while an ordinary close confirmation is already open.
  await mount(false);
  pending = await requestClose();
  assertReachable(button('Cancel'));
  await mount(true, false);
  assert.equal(
    document.activeElement?.textContent,
    'Cancel',
    'locking must keep confirmation focus',
  );
  assertLocked('timeout while confirmation is open');
  await click('Cancel');
  assert.equal(await pending.result, false);
  assertLocked('Cancel after timeout');

  // Finishing authentication while closing must preserve the pending decision.
  pending = await requestClose();
  await mount(false, false);
  assert.equal(
    document.activeElement?.textContent,
    'Cancel',
    'unlocking must keep confirmation focus',
  );
  assert.equal(document.querySelector('dialog:modal'), null);
  await click('Cancel');
  assert.equal(await pending.result, false);

  await mount(false);
  pending = await requestClose();
  await click('Close and terminate sessions');
  assert.equal(await pending.result, true);

  // Existing callers without a container must retain the ordinary body portal
  // and its default close control.
  await React.act(async () => {
    root.render(
      <Dialog defaultOpen>
        <DialogContent aria-describedby={undefined}>
          <DialogTitle>Ordinary dialog</DialogTitle>
          <button type="button">Ordinary action</button>
        </DialogContent>
      </Dialog>,
    );
  });
  assert.equal(closeListener, undefined);
  assert.ok(document.querySelector('body > [data-slot="dialog-content"]'));
  const defaultClose = document.querySelector<HTMLButtonElement>('[data-slot="dialog-close"]');
  defaultClose.focus();
  assert.ok(document.activeElement === defaultClose, 'the default close control must accept focus');
  await React.act(async () => {
    defaultClose.click();
  });
  await finishAnimations();
  assert.equal(document.querySelector('[data-slot="dialog-content"]'), null);
  await React.act(async () => {
    root.unmount();
  });
  assert.equal(closeListener, undefined);
  assert.equal(document.querySelector('dialog:modal'), null);
}

async function runStartupUnlockTests() {
  const root = document.getElementById('root');
  const remoteMessage = "Windows Hello isn't available in Remote Desktop.";
  const ready = { available: true, message: 'Windows Hello is ready.' };
  let checks = 0;
  let verifications = 0;
  let check = async () => ({ available: false, message: remoteMessage });
  let verifyHello = async () => ({ succeeded: false, message: 'Windows Hello was canceled.' });
  let loadWorkspace = async () => ({ connections: [] });
  const secrets: { method: string; secret: string }[] = [];
  const mounts: unknown[] = [];
  window.wormhole = {
    markStartupReady: () => {},
    checkWindowsHello: () => {
      checks += 1;
      return check();
    },
    verifyWindowsHello: () => {
      verifications += 1;
      return verifyHello();
    },
    unlockStartup: async (request) => {
      secrets.push(request);
      return { succeeded: false, message: '' };
    },
    loadWorkspace: () => loadWorkspace(),
  };
  globalThis.mountWorkspace = async (startup, workspace) => {
    mounts.push({ startup, workspace });
  };
  const settle = () => new Promise((resolve) => window.setTimeout(resolve, 0));
  const mount = (auth = {}) => {
    showUnlock({
      auth: {
        mode: 'windowsHello',
        fallback: 'pin',
        windowsHello: { available: false, message: 'Not checked yet.' },
        ...auth,
      },
    });
  };
  const helloButton = () =>
    [...root.querySelectorAll('button')].find(
      (button) => button.textContent === 'Use Windows Hello',
    );
  const assertFallback = async (fallback: string) => {
    const input = document.getElementById('startup-secret') as HTMLInputElement;
    assert.equal(input.disabled, false);
    assert.equal(document.activeElement, input);
    input.value = 'test-only-secret';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    assert.equal(root.querySelector<HTMLButtonElement>('button[type="submit"]').disabled, false);
    root.querySelector('form').requestSubmit();
    await settle();
    assert.deepEqual(secrets.at(-1), { method: fallback, secret: 'test-only-secret' });
    assert.equal(
      root.querySelector('.startup-status').textContent,
      fallback === 'pin' ? 'Invalid PIN.' : 'Invalid password.',
    );
  };

  for (const fallback of ['pin', 'password']) {
    check = async () => ({ available: false, message: remoteMessage });
    mount({ fallback });
    assert.ok(!helloButton(), 'startup must not briefly show unchecked Hello');
    const beforeUnavailable = verifications;
    await settle();
    assert.ok(!helloButton());
    assert.equal(verifications, beforeUnavailable);
    assert.match(root.querySelector('.startup-status').textContent, /Remote Desktop/);
    await assertFallback(fallback);

    check = async () => {
      throw new Error('native availability failed');
    };
    mount({ fallback });
    await settle();
    assert.ok(!helloButton());
    await assertFallback(fallback);
  }

  let resolveCheck;
  check = () =>
    new Promise((resolve) => {
      resolveCheck = resolve;
    });
  mount({ windowsHello: ready });
  assert.ok(!helloButton(), 'a previous availability snapshot must be rechecked');
  resolveCheck(ready);
  check = async () => ready;
  await settle();
  assert.ok(helloButton(), 'available Hello must remain usable after cancellation');
  assert.equal(root.querySelector('.startup-status').textContent, 'Windows Hello was canceled.');

  check = async () => ({ available: false, message: remoteMessage });
  const beforeUnavailableRetry = verifications;
  helloButton().click();
  await settle();
  assert.ok(!helloButton(), 'startup must remove Hello if it becomes unavailable');
  assert.equal(verifications, beforeUnavailableRetry);
  await assertFallback('pin');

  check = async () => ready;
  mount();
  await settle();
  check = async () => {
    throw new Error('native availability failed');
  };
  helloButton().click();
  await settle();
  assert.ok(!helloButton(), 'startup must remove Hello if a retry cannot check availability');
  await assertFallback('pin');

  check = async () => ready;
  verifyHello = async () => {
    throw new Error('native verification failed');
  };
  mount();
  await settle();
  assert.ok(
    helloButton(),
    'startup must keep available Hello after a transient verification error',
  );
  document.getElementById('startup-secret').focus();
  await assertFallback('pin');

  verifyHello = async () => {
    check = async () => ({ available: false, message: remoteMessage });
    return { succeeded: false, message: 'No Windows Hello device was found.' };
  };
  helloButton().click();
  await settle();
  assert.ok(!helloButton(), 'startup must refresh availability after failed verification');
  assert.match(root.querySelector('.startup-status').textContent, /Remote Desktop/);
  await assertFallback('pin');

  check = async () => ready;
  verifyHello = async () => {
    check = async () => {
      throw new Error('availability refresh failed');
    };
    return { succeeded: false, message: 'Windows Hello was canceled.' };
  };
  mount();
  await settle();
  assert.ok(!helloButton(), 'startup must clear readiness if its availability refresh fails');
  await assertFallback('pin');

  check = async () => ready;
  verifyHello = async () => ({ succeeded: false, message: '' });
  mount();
  await settle();
  assert.ok(helloButton(), 'failed recognition must still allow a retry');
  assert.equal(
    root.querySelector('.startup-status').textContent,
    "Windows Hello didn't recognize you.",
  );
  verifyHello = async () => ({ succeeded: true, message: 'Verified.' });
  loadWorkspace = async () => {
    throw new Error('workspace load failed');
  };
  helloButton().click();
  await settle();
  assert.ok(helloButton(), 'workspace-load failures must not remove an available login method');
  assert.equal(
    root.querySelector('.startup-status').textContent,
    "Wormhole couldn't load the workspace. Try again.",
  );
  assert.equal(mounts.length, 0);
  loadWorkspace = async () => ({ connections: [] });
  helloButton().click();
  await settle();
  assert.equal(mounts.length, 1);

  for (const mode of ['pin', 'password']) {
    const checksBeforeMount = checks;
    mount({ mode });
    await settle();
    assert.ok(!helloButton());
    assert.equal(checks, checksBeforeMount);
    await assertFallback(mode);
  }
}

runAuthPromptTests().then(runWindowCloseTests).then(runStartupUnlockTests);
