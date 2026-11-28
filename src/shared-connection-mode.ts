import type { SharedCatalogNode } from '../electron/vault-shared-catalog.ts';

export type SharedConnectionMode = 'terminal' | 'serial' | 'sftp' | 'vnc' | 'rdp' | 'web';

export function sharedConnectionMode(node: SharedCatalogNode): SharedConnectionMode | undefined {
  return node.kind === 1 && node.canUse ? modeForProtocol(node.protocol) : undefined;
}

export function modeForProtocol(protocol: number | null): SharedConnectionMode | undefined {
  switch (protocol) {
    case 0:
      return 'terminal';
    case 7:
      return 'sftp';
    case 1:
      return 'rdp';
    case 6:
      return 'vnc';
    case 3:
    case 4:
      return 'web';
    case 5:
      return 'serial';
  }
}
