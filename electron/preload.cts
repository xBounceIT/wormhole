import { contextBridge, ipcRenderer } from 'electron';
import type { RdpBackendEvent, RdpCommandRequest, RdpStartRequest } from './rdp-contract.js';

contextBridge.exposeInMainWorld('wormhole', {
  loadWorkspace: () => ipcRenderer.invoke('workspace:load'),
  openSshSession: (request: { sessionId: string; nodeId: string; columns: number; rows: number }) =>
    ipcRenderer.invoke('ssh:open', request),
  trustSshHostKey: (request: { nodeId: string; expected: string; received: string }) =>
    ipcRenderer.invoke('ssh:trust-host-key', request),
  sendSshInput: (sessionId: string, data: string) =>
    ipcRenderer.invoke('ssh:input', sessionId, data),
  resizeSshSession: (sessionId: string, columns: number, rows: number) =>
    ipcRenderer.invoke('ssh:resize', sessionId, columns, rows),
  closeSshSession: (sessionId: string) => ipcRenderer.invoke('ssh:close', sessionId),
  openSerialSession: (request: {
    sessionId: string;
    nodeId?: string;
    portName?: string;
    settings?: {
      baudRate: number;
      dataBits: number;
      stopBits: number;
      parity: number;
      flowControl: number;
    };
    columns: number;
    rows: number;
  }) => ipcRenderer.invoke('serial:open', request),
  sendSerialInput: (sessionId: string, data: string) =>
    ipcRenderer.invoke('serial:input', sessionId, data),
  resizeSerialSession: (sessionId: string, columns: number, rows: number) =>
    ipcRenderer.invoke('serial:resize', sessionId, columns, rows),
  closeSerialSession: (sessionId: string) => ipcRenderer.invoke('serial:close', sessionId),
  onSerialEvent: (
    listener: (event: {
      type: 'connected' | 'screen' | 'closed' | 'error';
      sessionId: string;
      portName?: string;
      baudRate?: number;
      dataBits?: number;
      stopBits?: number;
      parity?: number;
      flowControl?: number;
      frame?: {
        columns: number;
        rows: number;
        full: boolean;
        cells?: Array<{
          character: string;
          foreground: number;
          background: number;
        }>;
        changes?: Array<{
          index: number;
          character: string;
          foreground: number;
          background: number;
        }>;
        scrollbackReset?: boolean;
        viewportReset?: boolean;
        scrollback?: Array<{
          runs: Array<{
            text: string;
            cells: number;
            foreground: number;
            background: number;
          }>;
        }>;
        cursorX: number;
        cursorY: number;
        cursorVisible: boolean;
        applicationCursor: boolean;
        title?: string;
        sequence: number;
      };
      error?: string;
    }) => void,
  ) => {
    const handler = (_event: Electron.IpcRendererEvent, value: unknown) => {
      listener(value as Parameters<typeof listener>[0]);
    };
    ipcRenderer.on('serial:event', handler);
    return () => ipcRenderer.removeListener('serial:event', handler);
  },
  onSshEvent: (
    listener: (event: {
      type: 'connected' | 'screen' | 'closed' | 'error';
      sessionId: string;
      host?: string;
      port?: number;
      username?: string;
      fingerprint?: string;
      hostKeyExpected?: string;
      hostKeyReceived?: string;
      frame?: {
        columns: number;
        rows: number;
        full: boolean;
        cells?: Array<{
          character: string;
          foreground: number;
          background: number;
        }>;
        changes?: Array<{
          index: number;
          character: string;
          foreground: number;
          background: number;
        }>;
        scrollbackReset?: boolean;
        viewportReset?: boolean;
        scrollback?: Array<{
          runs: Array<{
            text: string;
            cells: number;
            foreground: number;
            background: number;
          }>;
        }>;
        cursorX: number;
        cursorY: number;
        cursorVisible: boolean;
        applicationCursor: boolean;
        title?: string;
        sequence: number;
      };
      error?: string;
    }) => void,
  ) => {
    const handler = (_event: Electron.IpcRendererEvent, value: unknown) => {
      listener(value as Parameters<typeof listener>[0]);
    };
    ipcRenderer.on('ssh:event', handler);
    return () => ipcRenderer.removeListener('ssh:event', handler);
  },
  getAuthState: () => ipcRenderer.invoke('auth:status'),
  verifyAuth: (request: unknown) => ipcRenderer.invoke('auth:verify', request),
  setAuthSecret: (request: unknown) => ipcRenderer.invoke('auth:set-secret', request),
  updateAuthSettings: (request: unknown) => ipcRenderer.invoke('auth:update-settings', request),
  lockAuthentication: () => ipcRenderer.invoke('auth:lock'),
  checkWindowsHello: () => ipcRenderer.invoke('auth:hello-status'),
  verifyWindowsHello: () => ipcRenderer.invoke('auth:hello-verify'),
  getSystemIdleSeconds: () => ipcRenderer.invoke('auth:system-idle'),
  sendVncCommand: (command: unknown) => ipcRenderer.invoke('vnc:command', command),
  onBackendEvent: (listener: (event: unknown) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, payload: unknown) => listener(payload);
    ipcRenderer.on('backend:event', handler);
    return () => ipcRenderer.removeListener('backend:event', handler);
  },
  startRdpSession: (request: RdpStartRequest) => ipcRenderer.invoke('rdp:start', request),
  resizeRdpSession: (request: RdpCommandRequest) => ipcRenderer.invoke('rdp:resize', request),
  commandRdpSession: (
    request: RdpCommandRequest & { operation: 'show' | 'hide' | 'focus' | 'disconnect' },
  ) => ipcRenderer.invoke('rdp:command', request),
  onRdpEvent: (listener: (event: RdpBackendEvent) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, value: RdpBackendEvent) => listener(value);
    ipcRenderer.on('rdp:event', handler);
    return () => ipcRenderer.removeListener('rdp:event', handler);
  },
});
