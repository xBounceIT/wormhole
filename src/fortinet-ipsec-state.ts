export const fortinetIPsecDefaults = {
  Port: 500,
  SamlPort: 1001,
  AuthMethod: 0,
  UserAuth: 0,
  IkeVersion: 2,
  ExchangeMode: 0,
  AddressAssignment: 0,
  Phase1Encryption: 2,
  Phase1Authentication: 2,
  Phase1Encryption2: 2,
  Phase1Authentication2: 2,
  DhGroups: '14, 19, 20',
  Phase1Lifetime: 14400,
  DeadPeerDetection: true,
  NatTraversal: true,
  EnableLocalLan: false,
  Phase2Encryption: 2,
  Phase2Authentication: 2,
  Phase2Encryption2: 2,
  Phase2Authentication2: 2,
  Phase2TimeLifetime: true,
  Phase2Lifetime: 3600,
  Phase2ByteLifetime: false,
  Phase2LifetimeKb: 5120,
  ReplayDetection: true,
  Pfs: false,
  PfsGroup: 14,
};

export const fortinetIPsecFields: {
  key: string;
  label: string;
  section: string;
  type?: 'number' | 'switch' | 'select';
  options?: { value: number; label: string }[];
  hint?: string;
  placeholder?: string;
  fullWidth?: boolean;
}[] = [
  {
    key: 'AutoProposals',
    label: 'Automatic IKEv2 proposals',
    section: 'Phase 1',
    type: 'switch',
    fullWidth: true,
    hint: 'Use the built-in IKEv2 proposals, or disable to configure each proposal explicitly.',
  },
  { key: 'Host', label: 'Remote gateway', section: 'Gateway', placeholder: 'vpn.example.com' },
  { key: 'Port', label: 'IKE port (UDP)', section: 'Gateway', type: 'number' },
  {
    key: 'RemoteGateways',
    label: 'Additional gateways (in order)',
    section: 'Gateway',
    fullWidth: true,
    hint: 'Comma-separated host names or IP addresses.',
  },
  { key: 'Description', label: 'Description (optional)', section: 'Gateway', fullWidth: true },
  {
    key: 'AuthMethod',
    label: 'Authentication method',
    section: 'Authentication',
    type: 'select',
    options: [
      { value: 0, label: 'Pre-shared key (PSK)' },
      { value: 1, label: 'Client certificate' },
    ],
  },
  {
    key: 'UserAuth',
    label: 'User authentication (XAuth / EAP)',
    section: 'Authentication',
    type: 'select',
    options: [
      { value: 0, label: 'Disabled' },
      { value: 1, label: 'Prompt on login' },
      { value: 2, label: 'Save login' },
      { value: 3, label: 'SAML single sign-on' },
    ],
  },
  { key: 'Username', label: 'Username', section: 'Authentication' },
  { key: 'SamlPort', label: 'SAML port (HTTPS)', section: 'Authentication', type: 'number' },
  {
    key: 'IkeVersion',
    label: 'IKE version',
    section: 'VPN settings',
    type: 'select',
    options: [
      { value: 1, label: 'Version 1' },
      { value: 2, label: 'Version 2' },
    ],
  },
  {
    key: 'ExchangeMode',
    label: 'IKEv1 mode',
    section: 'VPN settings',
    type: 'select',
    options: [
      { value: 0, label: 'Main' },
      { value: 1, label: 'Aggressive' },
    ],
  },
  {
    key: 'AddressAssignment',
    label: 'Address assignment',
    section: 'VPN settings',
    type: 'select',
    options: [
      { value: 0, label: 'Mode Config' },
      { value: 1, label: 'Manually set' },
      { value: 2, label: 'DHCP over IPsec' },
    ],
  },
  {
    key: 'ManualAddress',
    label: 'Client IPv4 address',
    section: 'VPN settings',
    placeholder: '10.10.10.2',
  },
  {
    key: 'ManualDns',
    label: 'DNS servers',
    section: 'VPN settings',
    hint: 'Comma-separated IP addresses; queries travel inside the tunnel.',
  },
  ...([1, 2] as const).flatMap((phase) =>
    [1, 2].flatMap((proposal) => [
      {
        key: `Phase${phase}Encryption${proposal === 1 ? '' : '2'}`,
        label: `Proposal ${proposal} · Encryption`,
        section: `Phase ${phase}`,
        type: 'select' as const,
        options: [
          { value: 0, label: 'AES-128' },
          { value: 1, label: 'AES-192' },
          { value: 2, label: 'AES-256' },
          { value: 3, label: '3DES' },
        ],
      },
      {
        key: `Phase${phase}Authentication${proposal === 1 ? '' : '2'}`,
        label: `Proposal ${proposal} · Authentication`,
        section: `Phase ${phase}`,
        type: 'select' as const,
        options: [
          { value: 0, label: 'MD5' },
          { value: 1, label: 'SHA-1' },
          { value: 2, label: 'SHA-256' },
          { value: 3, label: 'SHA-384' },
          { value: 4, label: 'SHA-512' },
        ],
      },
    ]),
  ),
  {
    key: 'DhGroups',
    label: 'DH groups (in preference order)',
    section: 'Phase 1',
    fullWidth: true,
    hint: '1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21',
  },
  { key: 'Phase1Lifetime', label: 'Key life (seconds)', section: 'Phase 1', type: 'number' },
  {
    key: 'LocalId',
    label: 'Local IKE identity (optional)',
    section: 'Phase 1',
  },
  {
    key: 'RemoteId',
    label: 'Remote IKE identity (optional)',
    section: 'Phase 1',
    hint: 'Must match the gateway identity when specified.',
  },
  {
    key: 'TrustServerCertificate',
    label: 'Trust SAML server certificate (skip verification)',
    section: 'Authentication',
    type: 'switch',
    fullWidth: true,
  },
  {
    key: 'DeadPeerDetection',
    label: 'Dead peer detection',
    section: 'Phase 1',
    type: 'switch',
    fullWidth: true,
  },
  {
    key: 'NatTraversal',
    label: 'NAT traversal',
    section: 'Phase 1',
    type: 'switch',
    fullWidth: true,
  },
  {
    key: 'EnableLocalLan',
    label: 'Enable local LAN',
    section: 'Phase 1',
    type: 'switch',
    fullWidth: true,
  },
  {
    key: 'Phase2TimeLifetime',
    label: 'Time-based key life',
    section: 'Phase 2',
    type: 'switch',
    fullWidth: true,
  },
  { key: 'Phase2Lifetime', label: 'Key life (seconds)', section: 'Phase 2', type: 'number' },
  {
    key: 'Phase2ByteLifetime',
    label: 'Volume-based key life',
    section: 'Phase 2',
    type: 'switch',
    fullWidth: true,
  },
  { key: 'Phase2LifetimeKb', label: 'Key life (KB)', section: 'Phase 2', type: 'number' },
  {
    key: 'ReplayDetection',
    label: 'Replay detection',
    section: 'Phase 2',
    type: 'switch',
    fullWidth: true,
  },
  {
    key: 'Pfs',
    label: 'Perfect forward secrecy (PFS)',
    section: 'Phase 2',
    type: 'switch',
    fullWidth: true,
  },
  {
    key: 'PfsGroup',
    label: 'PFS DH group',
    section: 'Phase 2',
    type: 'select',
    options: [1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21].map((value) => ({
      value,
      label: String(value),
    })),
  },
];

export const fortinetIPsecSecrets = [
  'PreSharedKey',
  'Password',
  'ClientCert',
  'ClientKey',
  'CaCert',
] as const;

export function fortinetIPsecEditorSettings(
  input: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...fortinetIPsecDefaults,
    ...input,
    UserAuth: input.UserAuth ?? 3,
    AutoProposals: input.AutoProposals ?? input.UserAuth === undefined,
  };
}

export function fortinetIPsecFieldVisible(key: string, settings: Record<string, unknown>): boolean {
  if (key === 'AutoProposals') return settings.IkeVersion === 2;
  if (
    settings.IkeVersion === 2 &&
    settings.AutoProposals === true &&
    (/^Phase[12](Encryption|Authentication)/.test(key) || key === 'DhGroups')
  )
    return false;
  if (key === 'Username') return settings.UserAuth === 1 || settings.UserAuth === 2;
  if (key === 'SamlPort' || key === 'TrustServerCertificate') return settings.UserAuth === 3;
  if (key === 'ExchangeMode') return settings.IkeVersion === 1;
  if (key === 'ManualAddress' || key === 'ManualDns') return settings.AddressAssignment === 1;
  if (key === 'Phase2Lifetime') return settings.Phase2TimeLifetime !== false;
  if (key === 'Phase2LifetimeKb') return settings.Phase2ByteLifetime === true;
  if (key === 'PfsGroup') return settings.Pfs === true;
  return true;
}

export function normalizeFortinetIPsecSettings(
  input: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const key of [
    ...fortinetIPsecFields.map((field) => field.key),
    ...fortinetIPsecSecrets.flatMap((key) => [`Has${key}`, `Replace${key}`]),
  ]) {
    let value = input[key];
    if (value === undefined || value === '') continue;
    const field = fortinetIPsecFields.find((field) => field.key === key);
    if (field?.type === 'number' || field?.type === 'select') {
      if (typeof value === 'string' && /^\d+$/.test(value.trim())) value = Number(value);
    } else if (typeof value === 'string') value = value.trim();
    result[key] = value;
  }
  return result;
}

export function missingFortinetIPsecFields(settings: Record<string, unknown>): string[] {
  const missing: string[] = [];
  if (typeof settings.Host !== 'string' || !settings.Host.trim()) missing.push('Host');
  for (const key of [
    'Port',
    ...(settings.UserAuth === 3 || settings.UserAuth === undefined ? ['SamlPort'] : []),
  ]) {
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
  for (const field of fortinetIPsecFields) {
    if (!fortinetIPsecFieldVisible(field.key, settings)) continue;
    const value = settings[field.key];
    if (
      field.type === 'select' &&
      value !== undefined &&
      !field.options?.some((option) => option.value === value)
    )
      missing.push(field.label);
    if (
      field.type === 'number' &&
      !['Port', 'SamlPort'].includes(field.key) &&
      value !== undefined &&
      (!/^\d+$/.test(String(value)) || Number(value) < 1 || Number(value) > 2147483647)
    )
      missing.push(field.label);
  }
  if (
    settings.UserAuth === 2 &&
    (typeof settings.Username !== 'string' || !settings.Username.trim())
  )
    missing.push('Username');
  if (
    settings.AddressAssignment === 1 &&
    (typeof settings.ManualAddress !== 'string' || !settings.ManualAddress.trim())
  )
    missing.push('Client IPv4 address');
  if (settings.UserAuth === 3 && settings.IkeVersion === 1) missing.push('SAML requires IKEv2');
  if (settings.UserAuth === 3 && settings.AuthMethod === 1) missing.push('SAML requires PSK');
  return missing;
}
