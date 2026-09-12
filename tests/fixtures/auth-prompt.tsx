// Executed with real React and Chromium by auth-prompt.test.ts. Only the preload
// bridge and presentational UI wrappers are replaced; hooks and dialog are real.
declare const React: typeof import('react');
declare const createRoot: typeof import('react-dom/client').createRoot;
declare const assert: typeof import('node:assert/strict');
declare function AuthPrompt(props: Record<string, unknown>): import('react').ReactElement;
declare function AppCloseHarness(props: Record<string, unknown>): import('react').ReactElement;

async function runAuthPromptTests() {
  const root = createRoot(document.getElementById('root'));
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
  assert.equal(checks, 1, 'StrictMode must not launch Hello twice');
  assert.equal(verifications, 0, 'unavailable Hello must not open verification');
  assert.equal(document.activeElement.id, 'auth-secret');
  assert.doesNotMatch(text(), /will open now/);

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
  assert.equal(helloButton().disabled, false);
  assert.equal(document.activeElement.id, 'auth-secret');

  for (const fallback of ['pin', 'password']) {
    const name = fallback === 'pin' ? 'Wormhole PIN' : 'Wormhole password';
    check = async () => ({ available: false, message: '' });
    await mount({ fallback });
    assertNeutral(`Windows Hello is unavailable. Use your ${name}.`);

    check = async () => {
      throw new Error('native availability failed');
    };
    await clickHello();
    assertNeutral(`Windows Hello isn't available right now. Use your ${name}.`);

    check = async () => ({ available: true, message: 'Windows Hello is ready.' });
    verifyHello = async () => ({ succeeded: false, message: 'Windows Hello was canceled.' });
    await clickHello();
    assertNeutral('Windows Hello was canceled.');
    verifyHello = async () => ({ succeeded: false, message: '' });
    await clickHello();
    assertNeutral(`Windows Hello didn't recognize you. Use your ${name}.`);
    verifyHello = async () => {
      throw new Error('native verification failed');
    };
    await clickHello();
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
  await mount({}, { kind: 'confirmation', autoWindowsHello: false });
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
  assert.equal(document.querySelector('img'), null);

  for (const mode of ['pin', 'password']) {
    await mount({ mode });
    assert.equal(helloButton(), undefined);
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
  await React.act(async () => {
    root.unmount();
  });
  assert.equal(closeListener, undefined);
  assert.equal(document.querySelector('dialog:modal'), null);
}

runAuthPromptTests().then(runWindowCloseTests);
