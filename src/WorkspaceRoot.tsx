import { StrictMode } from 'react';
import { flushSync } from 'react-dom';
import { createRoot } from 'react-dom/client';
import App from './App';

type WorkspaceAppProps = {
  initialAuthState: WormholeAuthState;
  initialWorkspace: WormholeWorkspaceSnapshot;
  initialSettings: WormholeAppSettings;
};

export function mountWorkspaceApp(container: HTMLElement, props: WorkspaceAppProps) {
  const workspaceRoot = createRoot(container);
  flushSync(() => {
    workspaceRoot.render(
      <StrictMode>
        <App {...props} />
      </StrictMode>,
    );
  });

  window.wormhole?.markStartupReady();
}
