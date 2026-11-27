import { useEffect, useState } from 'react';

export function useTunnelCapabilities(open: boolean): { openVpn: boolean } | null {
  const [capabilities, setCapabilities] = useState<{ openVpn: boolean } | null>(null);
  useEffect(() => {
    let active = true;
    const api = window.wormhole;
    if (!open) return;
    if (!api?.getTunnelCapabilities) {
      setCapabilities({ openVpn: false });
      return;
    }
    setCapabilities(null);
    api.getTunnelCapabilities().then(
      (result) => {
        if (active) setCapabilities(result);
      },
      () => {
        if (active) setCapabilities({ openVpn: false });
      },
    );
    return () => {
      active = false;
    };
  }, [open]);
  return capabilities;
}
