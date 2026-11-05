export const fortinetIPsecDefaults = { Port: 500, SamlPort: 1001 };

export const fortinetIPsecFields: {
  key: string;
  label: string;
  section: string;
  type?: 'number' | 'password' | 'switch';
  hint?: string;
  placeholder?: string;
  fullWidth?: boolean;
}[] = [
  { key: 'Host', label: 'Host', section: 'Gateway', placeholder: 'vpn.example.com' },
  { key: 'Port', label: 'IKE port (UDP)', section: 'Gateway', type: 'number' },
  { key: 'SamlPort', label: 'SAML port (HTTPS)', section: 'Gateway', type: 'number' },
  {
    key: 'PreSharedKey',
    label: 'Gateway pre-shared key (PSK)',
    section: 'Authentication',
    type: 'password',
    fullWidth: true,
  },
  {
    key: 'LocalId',
    label: 'Local IKE identity (optional)',
    section: 'Advanced',
    hint: 'Defaults to the temporary SAML identity.',
  },
  {
    key: 'RemoteId',
    label: 'Remote IKE identity (optional)',
    section: 'Advanced',
    hint: 'Must match the gateway identity when specified.',
  },
  {
    key: 'TrustServerCertificate',
    label: 'Trust SAML server certificate (skip verification)',
    section: 'Advanced',
    type: 'switch',
    fullWidth: true,
  },
];

export function normalizeFortinetIPsecSettings(
  input: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const { key } of fortinetIPsecFields) {
    let value = input[key];
    if (value === undefined || value === '') continue;
    if (key === 'Port' || key === 'SamlPort') {
      if (typeof value === 'string' && /^\d+$/.test(value.trim())) value = Number(value);
    } else if (typeof value === 'string' && key !== 'PreSharedKey') value = value.trim();
    result[key] = value;
  }
  return result;
}

export function missingFortinetIPsecFields(settings: Record<string, unknown>): string[] {
  const missing: string[] = [];
  for (const [key, label] of [
    ['Host', 'Host'],
    ['PreSharedKey', 'Gateway pre-shared key (PSK)'],
  ]) {
    if (typeof settings[key] !== 'string' || !settings[key].trim()) missing.push(label);
  }
  for (const key of ['Port', 'SamlPort']) {
    const value = settings[key];
    if (
      (typeof value !== 'string' && typeof value !== 'number') ||
      !/^\d+$/.test(String(value).trim()) ||
      Number(value) < 1 ||
      Number(value) > 65535
    ) {
      missing.push(`${key === 'Port' ? 'IKE' : 'SAML'} port (1-65535)`);
    }
  }
  return missing;
}
