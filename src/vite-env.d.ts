/// <reference types="vite/client" />

type WormholeProtocol = 'ssh' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';

interface WormholeWorkspaceNode {
  id: string;
  name: string;
  kind: 'folder' | 'connection';
  protocol?: WormholeProtocol;
  host?: string;
  children?: WormholeWorkspaceNode[];
}

interface WormholeWorkspaceCredential {
  id: string;
  name: string;
  protocol: WormholeProtocol;
  username: string;
  domain?: string;
  provider: 'Local' | 'Bitwarden';
  readOnly?: boolean;
}

interface WormholeWorkspaceTunnel {
  id: string;
  name: string;
  kind: string;
}

interface WormholeWorkspaceSnapshot {
  tree: WormholeWorkspaceNode[];
  credentials: WormholeWorkspaceCredential[];
  tunnels: WormholeWorkspaceTunnel[];
}

interface WormholeSshConnected {
  sessionId: string;
  host: string;
  port: number;
  username: string;
  fingerprint: string;
}

type WormholeSshEvent =
  | ({ type: 'connected' } & WormholeSshConnected)
  | { type: 'data'; sessionId: string; data: string }
  | { type: 'closed'; sessionId: string }
  | { type: 'error'; sessionId: string; error: string };

interface Window {
  wormhole?: {
    loadWorkspace(): Promise<WormholeWorkspaceSnapshot>;
    openSshSession(request: {
      sessionId: string;
      nodeId: string;
      columns: number;
      rows: number;
    }): Promise<WormholeSshConnected>;
    sendSshInput(sessionId: string, data: string): Promise<void>;
    resizeSshSession(sessionId: string, columns: number, rows: number): Promise<void>;
    closeSshSession(sessionId: string): Promise<void>;
    onSshEvent(listener: (event: WormholeSshEvent) => void): () => void;
  };
}
