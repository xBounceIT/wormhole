import {
  Eye,
  LockKeyhole,
  Network,
  Shield,
  ShieldCheck,
  Terminal,
  Waypoints,
  createLucideIcon,
  type LucideIcon,
} from 'lucide-react';
import { createElement } from 'react';

const AzureVpn = createLucideIcon('AzureVpn', [
  ['path', { d: 'M8 3h5l-6 18H2L8 3Z', fill: 'currentColor', stroke: 'none', key: 'left' }],
  ['path', { d: 'M13 3h3l6 18h-8l-6-5h8L12 5', strokeWidth: 1.5, key: 'right' }],
]);

const Fortinet = createLucideIcon('Fortinet', [
  [
    'path',
    {
      d: 'M5 5h3v4H2V8a3 3 0 0 1 3-3Zm5 0h4v4h-4Zm6 0h3a3 3 0 0 1 3 3v1h-6ZM2 11h6v2H2Zm14 0h6v2h-6ZM2 15h6v4H5a3 3 0 0 1-3-3Zm8 0h4v4h-4Zm6 0h6v1a3 3 0 0 1-3 3h-3Z',
      fill: 'currentColor',
      stroke: 'none',
      key: 'mark',
    },
  ],
]);

const Cisco = createLucideIcon('Cisco', [
  ['path', { d: 'M2 11v2m3-4v6m4-9v12m3-8v4m3-8v12m4-9v6m3-4v2', key: 'bridge' }],
]);

const providerIcons = new Map<string, LucideIcon>([
  ['WireGuard', Waypoints],
  ['OpenVPN', LockKeyhole],
  ['Fortinet', Fortinet],
  ['Fortinet IPsec', Fortinet],
  ['WatchGuard', Eye],
  ['Stormshield', Shield],
  ['Azure VPN', AzureVpn],
  ['Cisco Secure Client', Cisco],
  ['Forcepoint', ShieldCheck],
  ['SSH tunnel (jump host)', Terminal],
]);

export function TunnelProviderIcon({ kind, className }: { kind: string; className?: string }) {
  return createElement(providerIcons.get(kind) ?? Network, { 'aria-hidden': true, className });
}
