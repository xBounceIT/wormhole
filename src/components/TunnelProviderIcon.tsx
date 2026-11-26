import { Network, Terminal } from 'lucide-react';
import azureVpn from '../../Assets/TunnelProviders/azure-vpn.svg';
import ciscoSecureClient from '../../Assets/TunnelProviders/cisco-secure-client.svg';
import forcepoint from '../../Assets/TunnelProviders/forcepoint.svg';
import fortinet from '../../Assets/TunnelProviders/fortinet.svg';
import openVpnLight from '../../Assets/TunnelProviders/openvpn-on-light.svg';
import stormshield from '../../Assets/TunnelProviders/stormshield.svg';
import watchguard from '../../Assets/TunnelProviders/watchguard.svg';
import wireGuard from '../../Assets/TunnelProviders/wireguard.svg';
import { cn } from '@/lib/utils';

const providerLogos = new Map([
  ['Azure VPN', azureVpn],
  ['Cisco Secure Client', ciscoSecureClient],
  ['Forcepoint', forcepoint],
  ['Fortinet', fortinet],
  ['Fortinet IPsec', fortinet],
  ['OpenVPN', openVpnLight],
  ['Stormshield', stormshield],
  ['WatchGuard', watchguard],
  ['WireGuard', wireGuard],
]);

export function TunnelProviderIcon({
  kind,
  size = 'filter',
}: {
  kind: string;
  size?: 'filter' | 'card';
}) {
  const logo = providerLogos.get(kind);
  const Fallback = kind === 'SSH tunnel (jump host)' ? Terminal : Network;
  const markSize = size === 'card' ? 'size-5' : 'size-3.5';

  return (
    <span
      aria-hidden="true"
      className={cn(
        'grid shrink-0 place-items-center border border-black/10 bg-white text-neutral-900',
        size === 'card' ? 'size-8 rounded-lg' : 'size-5 rounded-full',
      )}
    >
      {logo ? (
        <img alt="" aria-hidden="true" className={cn(markSize, 'object-contain')} src={logo} />
      ) : (
        <Fallback className={markSize} />
      )}
    </span>
  );
}
