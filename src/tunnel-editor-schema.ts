import { fortinetIPsecFields, fortinetIPsecDefaults } from './fortinet-ipsec-state.ts';

export const tunnelKinds = [
  { value: 0, label: 'WireGuard' },
  { value: 1, label: 'OpenVPN' },
  { value: 2, label: 'Fortinet' },
  { value: 9, label: 'Fortinet IPsec' },
  { value: 3, label: 'WatchGuard' },
  { value: 4, label: 'Stormshield' },
  { value: 5, label: 'Azure VPN' },
  { value: 6, label: 'Cisco Secure Client' },
  { value: 7, label: 'Forcepoint' },
  { value: 8, label: 'SSH tunnel (jump host)' },
] as const;

export type TunnelField = {
  key: string;
  label: string;
  section?: string;
  type?: 'password' | 'textarea' | 'number' | 'checkbox' | 'switch' | 'select';
  options?: { value: number; label: string }[];
  placeholder?: string;
  hint?: string;
  fullWidth?: boolean;
};

export function tunnelKindLabel(kind: number) {
  return tunnelKinds.find((item) => item.value === kind)?.label ?? 'Unknown';
}

export function tunnelEditorFields(kind: number): TunnelField[] {
  if (kind === 9) return fortinetIPsecFields;
  switch (kind) {
    case 0:
      return [
        {
          key: 'InterfacePrivateKey',
          label: 'Private key (base64)',
          section: 'Interface',
          type: 'password',
        },
        {
          key: 'InterfaceAddress',
          label: 'Address (e.g. 10.0.0.2/32)',
          section: 'Interface',
          placeholder: '10.0.0.2/32',
        },
        {
          key: 'Mtu',
          label: 'MTU (optional)',
          section: 'Interface',
          type: 'number',
        },
        {
          key: 'Dns',
          label: 'DNS (comma-separated, optional)',
          section: 'Interface',
          placeholder: '1.1.1.1, 2606:4700:4700::1111',
        },
        { key: 'PeerPublicKey', label: 'Public key (base64)', section: 'Peer' },
        {
          key: 'PeerPresharedKey',
          label: 'Preshared key (base64, optional)',
          section: 'Peer',
          type: 'password',
        },
        {
          key: 'PeerEndpoint',
          label: 'Endpoint (host:port)',
          section: 'Peer',
          placeholder: 'vpn.example.com:51820',
        },
        {
          key: 'AllowedIps',
          label: 'Allowed IPs (comma-separated)',
          section: 'Peer',
          placeholder: 'leave blank to route all traffic (0.0.0.0/0, ::/0)',
        },
        {
          key: 'PersistentKeepaliveSeconds',
          label: 'Persistent keepalive seconds (optional)',
          section: 'Peer',
          type: 'number',
        },
      ];
    case 1:
      return [
        {
          key: 'ProfileOvpn',
          label: 'OpenVPN profile (.ovpn contents)',
          section: 'Profile',
          type: 'textarea',
          placeholder: 'client\nproto udp\nremote vpn.example.com 1194\n...',
          hint: 'Paste the full .ovpn profile.',
        },
        {
          key: 'Username',
          label: 'Username',
          section: 'Authentication',
          placeholder: 'leave blank for certificate-only auth',
        },
        {
          key: 'Password',
          label: 'Password',
          section: 'Authentication',
          type: 'password',
        },
      ];
    case 2:
      return [
        {
          key: 'Host',
          label: 'Host',
          section: 'Gateway',
          placeholder: 'vpn.example.com',
        },
        {
          key: 'Port',
          label: 'Port',
          section: 'Gateway',
          type: 'number',
          placeholder: '443',
        },
        { key: 'Username', label: 'Username', section: 'Credentials' },
        {
          key: 'Password',
          label: 'Password',
          section: 'Credentials',
          type: 'password',
        },
        { key: 'Realm', label: 'Realm (optional)', section: 'Credentials' },
        {
          key: 'UseSingleSignOn',
          label: 'Enable single sign-on (SSO) for the VPN tunnel',
          section: 'Single sign-on',
          type: 'switch',
        },
        {
          key: 'UseSamlCallback',
          label: 'Use FortiGate SAML callback',
          section: 'Single sign-on',
          type: 'switch',
          fullWidth: true,
        },
        {
          key: 'TotpSecret',
          label: 'TOTP shared secret (Base32, optional)',
          section: 'Advanced',
          type: 'password',
          hint: 'used by username/password authentication',
          fullWidth: true,
        },
        {
          key: 'TrustServerCertificate',
          label: 'Trust server certificate (skip verification)',
          section: 'Advanced',
          type: 'switch',
          fullWidth: true,
        },
        {
          key: 'ServerCertSha256Pin',
          label: 'Server certificate SHA-256 pin (hex, optional)',
          section: 'Advanced',
          fullWidth: true,
        },
      ];
    case 3:
      return [
        {
          key: 'Server',
          label: 'Server',
          section: 'Gateway',
          placeholder: 'firebox.example.com',
        },
        {
          key: 'Port',
          label: 'Port',
          section: 'Gateway',
          type: 'number',
          placeholder: '443',
        },
        {
          key: 'TrustServerCertificate',
          label: 'Ignore certificate errors',
          section: 'Gateway',
          type: 'switch',
          fullWidth: true,
          hint: 'Skip certificate validation for the WatchGuard portal and embedded SAML sign-in. Use only for a gateway you trust.',
        },
        {
          key: 'AuthMode',
          label: 'Authentication mode',
          section: 'Authentication',
          type: 'select',
          options: [
            { value: 1, label: 'Username and password' },
            { value: 2, label: 'SAML' },
          ],
          fullWidth: true,
        },
        { key: 'Username', label: 'Username', section: 'Authentication' },
        {
          key: 'Password',
          label: 'Password',
          section: 'Authentication',
          type: 'password',
        },
        {
          key: 'Domain',
          label: 'Authentication domain override',
          section: 'Advanced',
          placeholder: 'auto-detect',
        },
        {
          key: 'CaPem',
          label: 'CA certificate (PEM)',
          section: 'Advanced',
          type: 'textarea',
        },
        {
          key: 'ClientCertPem',
          label: 'Client certificate (PEM)',
          section: 'Advanced',
          type: 'textarea',
        },
        {
          key: 'ClientKeyPem',
          label: 'Client private key (PEM)',
          section: 'Advanced',
          type: 'textarea',
        },
        {
          key: 'ProfileOvpn',
          label: 'Imported .ovpn fallback (optional)',
          section: 'Advanced',
          type: 'textarea',
        },
        {
          key: 'VerifyX509Name',
          label: 'verify-x509-name subject (advanced)',
          section: 'Advanced',
          placeholder: 'leave default unless the Firebox uses a custom server cert',
          fullWidth: true,
        },
      ];
    case 4:
      return [
        {
          key: 'Mode',
          label: 'Connection mode',
          section: 'Connection mode',
          type: 'select',
          options: [
            { value: 0, label: 'Automatic — authenticate & fetch config' },
            { value: 1, label: 'Import — paste a downloaded .ovpn' },
          ],
        },
        {
          key: 'Server',
          label: 'Server',
          section: 'Gateway',
          placeholder: 'rpv.example.com',
        },
        {
          key: 'Port',
          label: 'Port',
          section: 'Gateway',
          type: 'number',
          placeholder: '443',
        },
        {
          key: 'Description',
          label: 'Description (optional)',
          section: 'Gateway',
        },
        {
          key: 'UseOtp',
          label: 'Use an OTP',
          section: 'Authentication',
          type: 'checkbox',
          fullWidth: true,
        },
        { key: 'Username', label: 'Username', section: 'Authentication' },
        {
          key: 'Password',
          label: 'Password',
          section: 'Authentication',
          type: 'password',
        },
        {
          key: 'ProfileOvpn',
          label: 'OpenVPN profile (.ovpn contents)',
          section: 'Profile',
          type: 'textarea',
          placeholder: 'client\ndev tun\nremote rpv.example.com 443 tcp\n...',
        },
        {
          key: 'CaPem',
          label: 'Firewall CA certificate (PEM, for automatic mode)',
          section: 'Advanced',
          type: 'textarea',
          placeholder: 'paste the SNS portal CA so its TLS cert validates (CN = appliance serial)',
        },
        {
          key: 'TrustServerCertificate',
          label: 'Trust server certificate (skip ALL TLS checks)',
          section: 'Advanced',
          type: 'checkbox',
        },
        {
          key: 'OpenVpnTransportOverride',
          label: 'OpenVPN transport override',
          section: 'Advanced',
          type: 'select',
          options: [
            { value: 0, label: 'Auto — use profile order' },
            { value: 1, label: 'Force TCP' },
            { value: 2, label: 'Force UDP' },
          ],
        },
        {
          key: 'OpenVpnCompressionFramingOverride',
          label: 'OpenVPN compression/framing',
          section: 'Advanced',
          type: 'select',
          options: [
            { value: 0, label: 'Preserve profile compression/framing' },
            { value: 1, label: 'Add legacy no-compression stub' },
          ],
        },
        {
          key: 'AppToken',
          label: 'Portal app token (advanced)',
          section: 'Advanced',
          placeholder: 'sslclient',
        },
      ];
    case 5:
      return [
        {
          key: 'Servers',
          label: 'Server FQDN(s) (comma-separated)',
          section: 'Gateway',
          placeholder: 'gateway.vpn.azure.com, backup.vpn.azure.com',
        },
        {
          key: 'Protocol',
          label: 'Transport',
          section: 'Gateway',
          type: 'select',
          options: [
            { value: 0, label: 'TCP (default)' },
            { value: 1, label: 'UDP' },
          ],
        },
        { key: 'TenantId', label: 'Tenant ID', section: 'Microsoft Entra ID' },
        { key: 'Audience', label: 'Audience', section: 'Microsoft Entra ID' },
        {
          key: 'ApplicationId',
          label: 'Application (client) ID override',
          section: 'Advanced',
          placeholder: 'leave blank to use the audience as the client id',
        },
        {
          key: 'Issuer',
          label: 'Issuer',
          section: 'Advanced',
          placeholder: 'https://sts.windows.net/{tenant}/',
        },
        {
          key: 'CaPem',
          label: 'CA certificate override (PEM, optional)',
          section: 'Advanced',
          type: 'textarea',
          placeholder: 'leave blank to validate against DigiCert Global Root G2',
        },
      ];
    case 6:
      return [
        {
          key: 'Host',
          label: 'Host',
          section: 'Gateway',
          placeholder: 'vpn.example.com',
        },
        {
          key: 'Port',
          label: 'Port',
          section: 'Gateway',
          type: 'number',
          placeholder: '443',
        },
        {
          key: 'Group',
          label: 'Group / connection profile (optional)',
          section: 'Gateway',
          placeholder: 'leave blank for the gateway default',
        },
        { key: 'Username', label: 'Username', section: 'Credentials' },
        {
          key: 'Password',
          label: 'Password',
          section: 'Credentials',
          type: 'password',
        },
        {
          key: 'TotpSecret',
          label: 'TOTP shared secret (Base32, optional)',
          section: 'Two-factor & advanced',
          type: 'password',
        },
        {
          key: 'SecondaryPassword',
          label: 'Secondary password (optional)',
          section: 'Two-factor & advanced',
          type: 'password',
        },
        {
          key: 'TrustServerCertificate',
          label: 'Trust server certificate (skip verification)',
          section: 'Two-factor & advanced',
          type: 'checkbox',
        },
        {
          key: 'ServerCertSha256Pin',
          label: 'Server certificate SHA-256 pin (hex, optional)',
          section: 'Two-factor & advanced',
        },
      ];
    case 7:
      return [
        {
          key: 'Host',
          label: 'Host',
          section: 'Gateway',
          placeholder: 'vpn.example.com',
          hint: 'SSL VPN with username and password.',
        },
        { key: 'Port', label: 'SSL port', section: 'Gateway', type: 'number', placeholder: '443' },
        { key: 'Username', label: 'Username', section: 'Credentials' },
        { key: 'Password', label: 'Password', section: 'Credentials', type: 'password' },
        {
          key: 'ServerCertSha256Pin',
          label: 'Server certificate SHA-256 pin (optional)',
          section: 'Certificates & advanced',
          hint: 'Leave blank to verify the gateway certificate on first connection, or enter a fingerprint verified with your administrator or trusted client.',
        },
        {
          key: 'Mtu',
          label: 'MTU',
          section: 'Certificates & advanced',
          type: 'number',
          placeholder: '1390',
        },
      ];
    default:
      return [];
  }
}

export function tunnelDefaultSettings(
  kind: number,
): Record<string, string | number | boolean | string[] | null> {
  switch (kind) {
    case 9:
      return { ...fortinetIPsecDefaults };
    case 2:
      return { Port: 443 };
    case 3:
      return {
        Port: 443,
        AuthMode: 1,
        VerifyX509Name: '/O=WatchGuard_Technologies/OU=Fireware/CN=Fireware_SSLVPN_Server',
      };
    case 4:
      return {
        Port: 443,
        Mode: 0,
        OpenVpnTransportOverride: 0,
        OpenVpnCompressionFramingOverride: 0,
        AppToken: 'sslclient',
      };
    case 5:
      return { Protocol: 0 };
    case 6:
      return { Port: 443 };
    case 7:
      return { Port: 443, Mtu: 1390 };
    case 8:
      return { Mode: 'connection', KeepaliveSeconds: 30 };
    default:
      return {};
  }
}
