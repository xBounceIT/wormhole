export type TunnelMode = 'inherit' | 'off' | 'on' | string;

export const inheritTunnelConfigPrefix = 'inherit-config:';

export function tunnelModeFor(node: {
  tunnelEnabled?: boolean | null;
  tunnelConfigId?: string;
}): TunnelMode {
  if (node.tunnelEnabled === false) return 'off';
  if (node.tunnelEnabled === true && node.tunnelConfigId) return node.tunnelConfigId;
  if (node.tunnelEnabled === true) return 'on';
  if (node.tunnelConfigId) return `${inheritTunnelConfigPrefix}${node.tunnelConfigId}`;
  return 'inherit';
}

export function tunnelValueFor(mode: TunnelMode): {
  tunnelEnabled: boolean | null;
  tunnelConfigId: string;
} {
  if (mode === 'inherit') return { tunnelEnabled: null, tunnelConfigId: '' };
  if (mode === 'off') return { tunnelEnabled: false, tunnelConfigId: '' };
  if (mode === 'on') return { tunnelEnabled: true, tunnelConfigId: '' };
  if (mode.startsWith(inheritTunnelConfigPrefix)) {
    return {
      tunnelEnabled: null,
      tunnelConfigId: mode.slice(inheritTunnelConfigPrefix.length),
    };
  }
  return { tunnelEnabled: true, tunnelConfigId: mode };
}

export function normalizeTunnelEditorSettings(
  kind: number,
  input: Record<string, unknown>,
): Record<string, unknown> {
  const settings = { ...input };
  for (const key of ['AllowedIps', 'Dns']) {
    if (typeof settings[key] === 'string') {
      settings[key] = settings[key]
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
    }
  }
  if (kind === 5 && typeof settings.Servers === 'string') {
    settings.Servers = settings.Servers.split(',')
      .map((item) => item.trim())
      .filter(Boolean);
  }
  for (const key of ['Port', 'Mtu', 'PersistentKeepaliveSeconds', 'SamlRedirectPort']) {
    if (typeof settings[key] !== 'string') continue;
    const value = settings[key].trim();
    if (!value) {
      delete settings[key];
      continue;
    }
    const parsed = Number(value);
    if (Number.isInteger(parsed)) settings[key] = parsed;
  }
  if (kind === 4 && settings.Mode === undefined) {
    settings.Mode = typeof settings.ProfileOvpn === 'string' && settings.ProfileOvpn.trim() ? 1 : 0;
  }
  const trimCrlf = (key: string) => {
    if (typeof settings[key] === 'string') {
      settings[key] = (settings[key] as string).replace(/[\r\n]+$/, '');
    }
  };
  const stripAll = (key: string) => {
    if (typeof settings[key] === 'string') {
      const value = (settings[key] as string).replace(/\s+/g, '');
      if (value) settings[key] = value;
      else delete settings[key];
    }
  };
  const deleteIfBlank = (key: string) => {
    if (typeof settings[key] === 'string' && !(settings[key] as string).trim()) {
      delete settings[key];
    }
  };

  if (kind === 0) {
    deleteIfBlank('PeerPresharedKey');
  } else if (kind === 1) {
    deleteIfBlank('Username');
    deleteIfBlank('Password');
  } else if (kind === 2) {
    const useSso = settings.UseSingleSignOn === true;
    const useExternalBrowser = useSso && settings.UseExternalBrowser === true;
    if (useSso) {
      delete settings.Username;
      delete settings.Password;
      delete settings.TotpSecret;
    } else {
      trimCrlf('Password');
    }
    if (useSso && useExternalBrowser) delete settings.Realm;
    else deleteIfBlank('Realm');
    stripAll('TotpSecret');
    stripAll('ServerCertSha256Pin');
  } else if (kind === 3) {
    trimCrlf('Password');
    deleteIfBlank('Domain');
    if (!(settings.VerifyX509Name as string | undefined)?.trim()) {
      settings.VerifyX509Name = '/O=WatchGuard_Technologies/OU=Fireware/CN=Fireware_SSLVPN_Server';
    }
  } else if (kind === 4) {
    trimCrlf('Password');
    if (!(settings.AppToken as string | undefined)?.trim()) settings.AppToken = 'sslclient';
  } else if (kind === 5) {
    deleteIfBlank('ApplicationId');
    deleteIfBlank('Issuer');
    deleteIfBlank('CaPem');
    stripAll('ServerSecretHex');
  } else if (kind === 6) {
    trimCrlf('Password');
    trimCrlf('SecondaryPassword');
    deleteIfBlank('Group');
    if (!(settings.SecondaryPassword as string | undefined)?.trim()) {
      delete settings.SecondaryPassword;
    }
    stripAll('TotpSecret');
    stripAll('ServerCertSha256Pin');
  }
  return settings;
}

export function missingTunnelFields(value: {
  name: string;
  kind: number;
  settings: Record<string, unknown>;
}): string[] {
  const settings = value.settings;
  const blank = (key: string) => {
    const current = settings[key];
    return typeof current !== 'string' || current.trim().length === 0;
  };
  const validPort = (key: string) => {
    const current = settings[key];
    return (
      (typeof current === 'number' &&
        Number.isInteger(current) &&
        current >= 1 &&
        current <= 65535) ||
      (typeof current === 'string' &&
        /^\d+$/.test(current.trim()) &&
        Number(current) >= 1 &&
        Number(current) <= 65535)
    );
  };
  const missing: string[] = [];
  if (!value.name.trim()) missing.push('Name');
  switch (value.kind) {
    case 0:
      if (blank('InterfacePrivateKey')) missing.push('Interface private key');
      if (blank('InterfaceAddress')) missing.push('Interface address');
      if (blank('PeerPublicKey')) missing.push('Peer public key');
      if (blank('PeerEndpoint')) missing.push('Peer endpoint');
      break;
    case 1:
      if (blank('ProfileOvpn')) missing.push('OpenVPN profile');
      break;
    case 2: {
      if (blank('Host')) missing.push('Host');
      if (!validPort('Port')) missing.push('Port (1-65535)');
      if (settings.UseSingleSignOn === true) {
        if (settings.UseExternalBrowser === true) {
          if (!validPort('SamlRedirectPort')) missing.push('SAML callback port (1-65535)');
          if (!blank('Realm')) missing.push('an empty realm for external-browser SSO');
        } else if (!blank('ServerCertSha256Pin')) {
          missing.push('external-browser SSO or an empty server certificate pin');
        }
      } else {
        if (blank('Username')) missing.push('Username');
        if (blank('Password')) missing.push('Password');
      }
      break;
    }
    case 3:
      if (blank('Server')) missing.push('Server');
      if (!validPort('Port')) missing.push('Port (1-65535)');
      if (settings.AuthMode === 1) {
        if (blank('Username')) missing.push('Username');
        if (blank('Password')) missing.push('Password');
      }
      break;
    case 4:
      if (settings.Mode === 1) {
        if (blank('ProfileOvpn')) missing.push('OpenVPN profile');
      } else {
        if (blank('Server')) missing.push('Server');
        if (!validPort('Port')) missing.push('Port (1-65535)');
        if (settings.UseSingleSignOn !== true) {
          if (blank('Username')) missing.push('Username');
          if (blank('Password')) missing.push('Password');
        }
      }
      break;
    case 5: {
      const servers = Array.isArray(settings.Servers)
        ? settings.Servers
        : typeof settings.Servers === 'string'
          ? settings.Servers.split(',')
              .map((item) => item.trim())
              .filter(Boolean)
          : [];
      if (servers.length === 0) missing.push('Server FQDN');
      if (blank('TenantId')) missing.push('Tenant ID');
      if (blank('Audience')) missing.push('Audience');
      const secret =
        typeof settings.ServerSecretHex === 'string'
          ? settings.ServerSecretHex.replace(/\s+/g, '')
          : '';
      if (secret && !/^[0-9a-fA-F]{512}$/.test(secret)) {
        missing.push('Server secret (512 hex chars, or blank)');
      }
      break;
    }
    case 6:
      if (blank('Host')) missing.push('Host');
      if (!validPort('Port')) missing.push('Port (1-65535)');
      if (blank('Username')) missing.push('Username');
      if (blank('Password')) missing.push('Password');
      break;
  }
  return missing;
}

// Electron wraps renderer-side IPC rejections as "Error invoking remote method '<channel>':
// Error: <original>". Users should see only the original, already user-friendly message.
export function userFacingTunnelError(error: unknown): string {
  let message = error instanceof Error ? error.message : String(error ?? 'Unknown error');
  message = message.replace(/^Error invoking remote method '[^']+':\s*/i, '');
  message = message.replace(/^Error:\s*/i, '');
  return message.trim();
}

// Only treat a test as voluntarily cancelled when the backend says an interactive step was
// cancelled. A broad /cancell/i match would mislabel gateway errors that mention "cancel".
export function isTunnelTestCancellation(message: string): boolean {
  return /(authentication|prompt|operation|establishment).{0,48}cancell/i.test(message);
}
