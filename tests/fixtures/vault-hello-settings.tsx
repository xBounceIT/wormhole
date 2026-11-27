import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { VaultPresenceSettings } from '../../src/VaultPresenceSettings';
import { VaultSecurityProfile } from '../../src/VaultSecurityProfile';
import type { VaultProfileStatus } from '../../electron/vault-security';
import type {
  VaultPresenceAction,
  VaultPresenceChange,
  VaultPresenceStatus,
} from '../../electron/vault-hello';

export async function exercise() {
  Object.assign(window, { IS_REACT_ACT_ENVIRONMENT: true });
  const card = document.createElement('div');
  document.body.append(card);
  const button = () => card.querySelector('button');
  const check = (condition: unknown, message: string) => {
    if (!condition) throw Error(message);
  };
  let root = createRoot(card);
  const draw = (disabled = false) =>
    act(async () => root.render(<VaultPresenceSettings disabled={disabled} />));
  const mount = async (
    status: VaultPresenceStatus | null,
    options?: { platform?: string; fail?: boolean },
  ) => {
    await act(async () => root.unmount());
    root = createRoot(card);
    Object.defineProperty(window, 'wormhole', {
      configurable: true,
      value: {
        platform: options?.platform ?? 'win32',
        vaultPresenceStatus: async () => {
          statusReads++;
          if (options?.fail) throw Error('private availability diagnostic');
          return status;
        },
        configureVaultPresence: (action: VaultPresenceAction) => {
          actions.push(action);
          if (!reply) throw Error('missing response');
          return reply;
        },
      },
    });
    await draw();
  };
  let statusReads = 0;
  const actions: VaultPresenceAction[] = [];
  let reply: Promise<VaultPresenceChange> | undefined;
  const update = async (result: VaultPresenceChange) => {
    reply = Promise.resolve(result);
    await act(async () => button()?.click());
  };
  const statusText = () => card.querySelector('[role=status]')?.textContent ?? '';
  try {
    await mount(null, { platform: 'linux' });
    check(statusReads === 0 && !button(), 'unsupported platform probed the provider');
    await mount(null);
    check(!button(), 'control offered for out-of-scope vault');
    await mount(null, { fail: true });
    check(!button() && !card.textContent, 'provider diagnostic reached the Settings page');
    await mount({ enrolled: false, availability: 'remote-desktop' });
    check(!button(), 'unsupported device can start enrollment');
    await mount({ enrolled: false, availability: 'ready' });
    check(button()?.textContent?.includes('Set up'), 'setup missing');
    await draw(true);
    await act(async () => button()?.click());
    check(button()?.disabled && actions.length === 0, 'disabled settings accepted action');
    await draw();
    const pending = Promise.withResolvers<VaultPresenceChange>();
    reply = pending.promise;
    await act(async () => button()?.click());
    check(button()?.disabled && actions.at(-1) === 'enroll', 'enrollment is not single-flight');
    await act(async () => pending.reject(Error('private dialog diagnostic')));
    check(
      !button()?.disabled && !statusText().includes('private'),
      'enrollment failure did not re-enable settings',
    );
    for (const value of ['unavailable', 'remote-desktop', 'canceled', 'not-repeatable'] as const) {
      await update({ status: value });
      check(
        statusText().length > 0 && button()?.textContent?.includes('Set up'),
        'native failure changed enrollment state',
      );
    }
    await update({ enrolled: true });
    check(
      button()?.textContent?.includes('Remove') && statusText().includes('ready'),
      'enrollment result was not reflected',
    );
    await update({ removed: true, keyDeleted: true });
    check(
      actions.at(-1) === 'remove' &&
        button()?.textContent?.includes('Set up') &&
        statusText().includes('removed'),
      'removal did not update settings',
    );
    await mount({ enrolled: true, availability: 'unavailable' });
    check(button()?.textContent?.includes('Remove'), 'unavailable provider blocked slot removal');
    await update({ removed: true, keyDeleted: false });
    check(
      !button() && statusText().includes('could still be present'),
      'failed native cleanup claimed deletion',
    );
    await mount({ enrolled: false, availability: 'ready' }, { platform: 'darwin' });
    check(button()?.textContent === 'Set up Touch ID…', 'macOS setup labels the wrong provider');
    await update({ status: 'canceled' });
    check(statusText().includes('Touch ID setup was canceled.'), 'macOS cancellation text missing');
    await update({ enrolled: true });
    check(button()?.textContent === 'Remove Touch ID…', 'macOS enrollment did not update settings');
    await update({ removed: true, keyDeleted: true });
    check(statusText().includes('Touch ID was removed'), 'macOS removal did not update settings');
    let policy: VaultProfileStatus = {
      effective: 'default',
      source: 'workspace',
      retainedUntilLock: false,
    };
    let changed!: () => void;
    const profileAPI = {
      getVaultSecurityProfile: async () => policy,
      onVaultSecurityProfileChanged: (callback: () => void) => {
        changed = callback;
        return () => {};
      },
    };
    let attempts = 0;
    let choice = Promise.withResolvers<void>();
    const tighten = () => {
      attempts++;
      return choice.promise;
    };
    const drawProfile = (disabled = false, shared = false) =>
      act(async () =>
        root.render(
          <VaultSecurityProfile
            api={profileAPI}
            tighten={tighten}
            disabled={disabled}
            shared={shared}
          />,
        ),
      );
    await drawProfile();
    check(
      statusText().includes('Default') &&
        statusText().includes('Workspace policy') &&
        !card.querySelector('svg') &&
        !button(),
      'personal workspace shown as organization-managed',
    );
    policy = { ...policy, canTightenToStandard: true };
    await act(async () => changed());
    await drawProfile(false, true);
    check(
      button()?.textContent?.includes('on this device'),
      'shared profile choice omitted the device scope',
    );
    await drawProfile(true);
    await act(async () => button()?.click());
    check(attempts === 0 && button()?.disabled, 'busy settings accepted a profile change');
    await drawProfile();
    check(button()?.textContent?.includes('lock vault'), 'missing lock confirmation');
    await act(async () => {
      button()?.click();
      button()?.click();
    });
    check(attempts === 1 && button()?.disabled, 'duplicate confirmation requested');
    await act(async () => choice.reject(Error('private native diagnostic')));
    check(
      !button()?.disabled &&
        card.textContent?.includes('could not be confirmed') &&
        !card.textContent?.includes('private'),
      'failed confirmation was not retryable',
    );
    choice = Promise.withResolvers<void>();
    await act(async () => button()?.click());
    await act(async () => choice.resolve());
    policy = { effective: 'standard', source: 'user', retainedUntilLock: false };
    await act(async () => changed());
    check(
      attempts === 2 && !button() && statusText().includes('Your preference'),
      'confirmed personal floor not displayed',
    );
    policy = { effective: 'standard', source: 'os', retainedUntilLock: false };
    await act(async () => changed());
    check(
      statusText().includes('Set by your organization') &&
        statusText().includes('Device policy') &&
        card.querySelector('svg'),
      'local managed floor not indicated',
    );
  } finally {
    await act(async () => root.unmount());
    card.remove();
  }
}
