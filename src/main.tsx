import startupLogo from '../Assets/wormhole-logo-transparent.png';
import { applyTheme, getInitialTheme } from './theme';

// Resolve the stored/system theme before React renders so the very first painted
// frame already has the correct background. Deferring this to a post-mount effect
// leaves a light-theme frame visible until the `.dark` class lands — the startup
// flash.
applyTheme(getInitialTheme());

const rootElement = document.getElementById('root');
if (!rootElement) throw new Error('Wormhole startup root is missing.');
const root: HTMLElement = rootElement;

let workspaceModulePromise: Promise<typeof import('./WorkspaceRoot')> | undefined;
let startupRequest: Promise<WormholeStartupSnapshot> | undefined;

function loadWorkspaceModule() {
  workspaceModulePromise ??= import('./WorkspaceRoot').catch((error) => {
    workspaceModulePromise = undefined;
    throw error;
  });
  return workspaceModulePromise;
}

function renderLoading() {
  root.innerHTML = `
    <main class="startup-shell startup-loading-shell">
      <div class="startup-loading" role="status" aria-label="Wormhole is loading">
        <div class="startup-logo-stage" aria-label="Wormhole">
          <img class="startup-logo startup-logo-base" src="${startupLogo}" alt="" />
          <img class="startup-logo startup-logo-shine" src="${startupLogo}" alt="" aria-hidden="true" />
        </div>
      </div>
    </main>`;
}

function renderCard(title: string, detail: string): HTMLElement {
  root.innerHTML = `
    <main class="startup-shell">
      <section class="startup-card">
        <div class="startup-heading">
          <span class="startup-mark-box">
            <svg aria-hidden="true" class="startup-mark" viewBox="0 0 24 24">
              <path d="M12 3a5 5 0 0 0-3.54 8.54L5 15v4h4v-2h2v-2h1.17A5 5 0 1 0 12 3Zm0 2a3 3 0 1 1 0 6 3 3 0 0 1 0-6Z"></path>
            </svg>
          </span>
          <span>
            <strong></strong>
            <small></small>
          </span>
        </div>
      </section>
    </main>`;
  root.querySelector('strong')!.textContent = title;
  root.querySelector('small')!.textContent = detail;
  return root.querySelector('.startup-card')!;
}

function showError(message: string) {
  window.wormhole?.markStartupReady();
  const card = renderCard("Wormhole couldn't open", message);
  const retry = document.createElement('button');
  retry.className = 'startup-button';
  retry.type = 'button';
  retry.textContent = 'Try again';
  retry.addEventListener('click', () => {
    startupRequest = undefined;
    renderLoading();
    void bootstrap();
  });
  card.append(retry);
}

async function mountWorkspace(
  startup: WormholeStartupSnapshot,
  workspace: WormholeWorkspaceSnapshot,
) {
  renderLoading();
  try {
    const { mountWorkspaceApp } = await loadWorkspaceModule();
    mountWorkspaceApp(root, {
      initialAuthState: startup.auth,
      initialSettings: startup.settings,
      initialWorkspace: workspace,
    });
  } catch (error) {
    showError(error instanceof Error ? error.message : "Wormhole couldn't load the workspace.");
  }
}

function showUnlock(startup: WormholeStartupSnapshot) {
  const { auth } = startup;
  const method: WormholeAuthFallback =
    auth.mode === 'password' || (auth.mode === 'windowsHello' && auth.fallback === 'password')
      ? 'password'
      : 'pin';
  const isHelloMode = auth.mode === 'windowsHello';
  const fallbackName = method === 'pin' ? 'Wormhole PIN' : 'Wormhole password';
  const card = renderCard('Wormhole is locked', 'Unlock to load your connections.');
  window.wormhole?.markStartupReady();
  let busy = false;

  const form = document.createElement('form');
  form.className = 'startup-form';
  const label = document.createElement('label');
  label.htmlFor = 'startup-secret';
  label.textContent = fallbackName;
  const input = document.createElement('input');
  input.autocomplete = 'current-password';
  input.id = 'startup-secret';
  input.placeholder = `Enter your ${method === 'pin' ? 'Wormhole PIN' : 'password'}`;
  input.type = 'password';
  if (method === 'pin') input.inputMode = 'numeric';
  const status = document.createElement('p');
  status.className = 'startup-status';
  const submit = document.createElement('button');
  submit.className = 'startup-button';
  submit.disabled = true;
  submit.type = 'submit';
  submit.textContent = 'Unlock';
  input.addEventListener('input', () => {
    submit.disabled = busy || input.value.length === 0;
  });
  form.append(label, input, status, submit);

  async function tryWindowsHello() {
    if (busy || !window.wormhole) return;
    busy = true;
    input.disabled = true;
    submit.disabled = true;
    status.textContent = 'Waiting for Windows Hello…';
    try {
      const availability = await window.wormhole.checkWindowsHello();
      if (!availability.available) {
        status.textContent = `${availability.message} You can use your ${fallbackName} instead.`;
        return;
      }
      const result = await window.wormhole.verifyWindowsHello();
      if (!result.succeeded) {
        status.textContent = result.message || `Windows Hello didn't recognize you.`;
        return;
      }
      const workspace = await window.wormhole.loadWorkspace();
      await mountWorkspace(startup, workspace);
    } catch {
      status.textContent = `Windows Hello isn't available right now. Use your ${fallbackName}.`;
    } finally {
      busy = false;
      input.disabled = false;
      submit.disabled = input.value.length === 0;
    }
  }

  if (isHelloMode) {
    const hello = document.createElement('button');
    hello.className = 'startup-button startup-button-secondary';
    hello.type = 'button';
    hello.textContent = 'Use Windows Hello';
    hello.addEventListener('click', () => void tryWindowsHello());
    card.append(hello);
  }
  card.append(form);
  if (!isHelloMode) input.focus();

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    if (busy || !input.value || !window.wormhole) return;
    busy = true;
    input.disabled = true;
    submit.disabled = true;
    submit.textContent = 'Checking…';
    status.textContent = 'Checking…';
    void window.wormhole
      .unlockStartup({ method, secret: input.value })
      .then(async (result) => {
        if (!result.succeeded || !result.workspace) {
          input.value = '';
          status.textContent =
            result.message || (method === 'pin' ? 'Invalid PIN.' : 'Invalid password.');
          return;
        }
        input.value = '';
        await mountWorkspace(startup, result.workspace);
      })
      .catch(() => {
        status.textContent = "Wormhole couldn't unlock. Try again.";
      })
      .finally(() => {
        busy = false;
        input.disabled = false;
        submit.disabled = input.value.length === 0;
        submit.textContent = 'Unlock';
        input.focus();
      });
  });

  if (isHelloMode) void tryWindowsHello();
}

async function bootstrap() {
  // The full React workspace is fetched only after the static frame can paint. Its parsing then
  // overlaps the single native bootstrap process instead of extending the blank-window phase.
  window.setTimeout(() => void loadWorkspaceModule().catch(() => undefined), 0);
  if (!window.wormhole) {
    showError('The native bridge did not load.');
    return;
  }
  try {
    startupRequest ??= window.wormhole.loadStartup();
    const startup = await startupRequest;
    if (startup.auth.configured) {
      showUnlock(startup);
      return;
    }
    if (!startup.workspace) throw new Error('The native bootstrap returned no workspace.');
    await mountWorkspace(startup, startup.workspace);
  } catch (error) {
    startupRequest = undefined;
    showError(error instanceof Error ? error.message : "Wormhole couldn't start.");
  }
}

void bootstrap();
