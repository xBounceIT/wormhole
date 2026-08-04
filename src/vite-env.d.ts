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

interface Window {
  wormhole?: {
    loadWorkspace(): Promise<WormholeWorkspaceSnapshot>;
  };
}
