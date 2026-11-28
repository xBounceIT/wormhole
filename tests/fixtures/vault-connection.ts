import type { VaultConnectionInput } from '../../electron/vault-connection.ts';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';

export function appRdpDefaults(): NonNullable<VaultConnectionInput['metadata']['rdp']> {
  const source = readFileSync(new URL('../../src/App.tsx', import.meta.url), 'utf8');
  const declaration = source.match(/const defaultRdpSettings:[\s\S]*?\n};/)![0];
  return runInNewContext(stripTypeScriptTypes(declaration + '\ndefaultRdpSettings;'));
}
export const connectionNodeId = '11111111-1111-4111-8111-111111111111';
export function connectionInput(): VaultConnectionInput {
  return {
    rowVersion: '0',
    notesAction: 'set',
    password: new TextEncoder().encode('password-fixture'),
    notes: new TextEncoder().encode('notes-fixture'),
    metadata: {
      id: '',
      parentId: '',
      name: 'Connection',
      protocol: 'ssh',
      host: 'host.example',
      port: 22,
      username: 'alice',
      inlinePasswordAction: 'set',
      sshAutoSudo: null,
      httpIgnoreCertErrors: null,
      tunnelEnabled: null,
      tunnelConfigId: '',
      credentialMode: 1,
      credentialId: '',
      serialBaudRate: 115200,
      serialDataBits: 8,
      serialStopBits: 1,
      serialParity: 0,
      serialFlowControl: 0,
      rdp: null,
    },
  };
}
