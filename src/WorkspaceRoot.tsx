import { StrictMode, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { ContextMenuOverlayProvider } from './components/ui/context-menu';
import { WorkspaceErrorBoundary } from './WorkspaceErrorBoundary';

type WorkspaceAppProps = {
  initialAuthState: WormholeAuthState;
  initialWorkspace: WormholeWorkspaceSnapshot;
  initialSettings: WormholeAppSettings;
};

function WorkspaceApp(props: WorkspaceAppProps) {
  useEffect(() => {
    window.wormhole?.markStartupReady();
  }, []);
  return <App {...props} />;
}

export function mountWorkspaceApp(container: HTMLElement, props: WorkspaceAppProps) {
  const workspaceRoot = createRoot(container);
  workspaceRoot.render(
    <StrictMode>
      <WorkspaceErrorBoundary
        onFailure={() => window.wormhole?.markWorkspaceFailed()}
        onRetry={() => window.location.reload()}
      >
        <ContextMenuOverlayProvider>
          <WorkspaceApp {...props} />
        </ContextMenuOverlayProvider>
      </WorkspaceErrorBoundary>
    </StrictMode>,
  );
}
