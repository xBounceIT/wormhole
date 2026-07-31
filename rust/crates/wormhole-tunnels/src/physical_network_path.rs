//! Physical network path / split-routing heuristics (Fake / LabOnly).
//!
//! Mirrors the spirit of C# `WindowsPhysicalNetworkPathService` without live
//! `dnsapi` / `iphlpapi` P/Invoke. Stormshield and other ovpn-backed providers
//! pin outer transport to physical adapters (`TransportAdapterIds`); this module
//! supplies adapter preflight plus per-host split-route classification
//! ([`PhysicalNetworkRoute`]) for unit tests and lab orchestration.
//!
//! **No live OS probes:** adapter lists come from [`FakePhysicalNetworkPath`]
//! scripts; host classification uses pure string/IP heuristics unless a Fake
//! override is installed.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::TunnelError;

/// Maximum physical adapters retained in a preflight path (C# `MaxAdapters`).
pub const MAX_PHYSICAL_ADAPTERS: usize = 8;

/// Split-routing heuristic for a destination host.
///
/// Conservative defaults: without live adapter/DNS probes, public names resolve to
/// [`Unknown`] rather than guessing VPN capture behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalNetworkRoute {
    /// Loopback / link-local / hosts that do not require physical uplink pinning.
    Direct,
    /// Prefer a physical adapter (LAN, mDNS, private ranges) to bypass VPN capture.
    Physical,
    /// Cannot classify without live `dnsapi` / route-table probes.
    Unknown,
}

/// Stable Windows adapter identity for transport pinning (C# `WindowsPhysicalNetworkAdapter`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalNetworkAdapter {
    pub id: String,
    pub name: String,
    pub is_active: bool,
    pub ipv4_interface_index: Option<u32>,
    pub ipv6_interface_index: Option<u32>,
}

impl PhysicalNetworkAdapter {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        is_active: bool,
        ipv4_interface_index: Option<u32>,
        ipv6_interface_index: Option<u32>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            is_active,
            ipv4_interface_index,
            ipv6_interface_index,
        }
    }

    fn has_usable_interface_index(&self) -> bool {
        self.ipv4_interface_index.is_some_and(|i| i > 0)
            || self.ipv6_interface_index.is_some_and(|i| i > 0)
    }
}

/// Ordered physical adapters for tunnel transport preflight (C# `WindowsPhysicalNetworkPath`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PhysicalNetworkPath {
    pub adapters: Vec<PhysicalNetworkAdapter>,
}

impl PhysicalNetworkPath {
    pub fn new(adapters: Vec<PhysicalNetworkAdapter>) -> Self {
        Self { adapters }
    }

    /// True when at least one adapter is active with a non-blank id and a positive index.
    pub fn has_any_interface(&self) -> bool {
        self.adapters.iter().any(|adapter| {
            adapter.is_active
                && !adapter.id.trim().is_empty()
                && adapter.has_usable_interface_index()
        })
    }

    /// Distinct stable adapter ids (case-insensitive), blank ids omitted.
    pub fn adapter_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for adapter in &self.adapters {
            let id = adapter.id.trim();
            if id.is_empty() {
                continue;
            }
            if ids
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(id))
            {
                continue;
            }
            ids.push(id.to_string());
        }
        ids
    }
}

/// Lab adapter kind for ordering heuristics (maps to C# `NetworkInterfaceType` scoring).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalAdapterKind {
    Ethernet,
    Wireless,
    Wwan,
    Tunnel,
    Ppp,
    Other,
}

/// Input row for Fake adapter enumeration.
#[derive(Debug, Clone)]
pub struct PhysicalAdapterRecord {
    pub id: String,
    pub name: String,
    pub description: String,
    pub kind: PhysicalAdapterKind,
    pub is_active: bool,
    pub ipv4_metric: u32,
    pub ipv6_metric: u32,
    pub ipv4_interface_index: Option<u32>,
    pub ipv6_interface_index: Option<u32>,
    pub speed: u64,
}

impl PhysicalAdapterRecord {
    pub fn ethernet(
        id: impl Into<String>,
        name: impl Into<String>,
        ipv4_index: u32,
        ipv6_index: u32,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            kind: PhysicalAdapterKind::Ethernet,
            is_active: true,
            ipv4_metric: 10,
            ipv6_metric: 10,
            ipv4_interface_index: Some(ipv4_index),
            ipv6_interface_index: Some(ipv6_index),
            speed: 1_000_000_000,
        }
    }
}

/// Probe surface for physical-path preflight and per-host split routing.
pub trait PhysicalNetworkPathProbe: Send + Sync {
    /// Enumerate physical adapters for transport pinning.
    ///
    /// Destination hosts are accepted for API parity with C# but are **not**
    /// resolved — preflight must not reintroduce VPN-captured DNS.
    fn get_best_path(&self, destination_hosts: &[&str]) -> Result<PhysicalNetworkPath, TunnelError>;

    /// Classify how a destination should be reached (Direct / Physical / Unknown).
    fn classify_host(&self, host: &str) -> Result<PhysicalNetworkRoute, TunnelError>;
}

/// Pure per-host split-route heuristic (no adapter list, no OS calls).
///
/// Fail-closed on empty/whitespace host. Loopback and link-local → [`Direct`];
/// RFC1918 literals and `.local` names → [`Physical`]; everything else → [`Unknown`].
pub fn classify_split_route(host: &str) -> Result<PhysicalNetworkRoute, TunnelError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(TunnelError::InvalidHost {
            host: host.to_string(),
            reason: "destination host required".into(),
        });
    }

    if is_loopback_host(trimmed) {
        return Ok(PhysicalNetworkRoute::Direct);
    }

    if is_private_or_lan_host(trimmed) {
        return Ok(PhysicalNetworkRoute::Physical);
    }

    Ok(PhysicalNetworkRoute::Unknown)
}

/// C# `WindowsPhysicalNetworkPathService.IsVpnLikeAdapter` name/description heuristic.
pub fn is_vpn_like_adapter(name: &str, description: &str) -> bool {
    let kind_tunnel = name.contains("tunnel") || description.contains("tunnel");
    if kind_tunnel {
        return true;
    }

    let text = format!("{name} {description}").to_lowercase();
    const MARKERS: &[&str] = &[
        "vpn",
        "stormshield",
        "openvpn",
        "nordlynx",
        "wintun",
        "tap",
        "anyconnect",
        "fortinet",
        "globalprotect",
        "palo alto",
        "check point",
        "checkpoint",
        "sonicwall",
        "juniper",
        "tailscale",
        "zerotier",
        "hamachi",
        "zscaler",
        "pulse secure",
    ];
    MARKERS.iter().any(|marker| text.contains(marker))
}

/// Score used to order physical adapters (C# `PhysicalAdapterScore`).
pub fn physical_adapter_score(kind: PhysicalAdapterKind) -> i32 {
    match kind {
        PhysicalAdapterKind::Ethernet => 40,
        PhysicalAdapterKind::Wireless => 30,
        PhysicalAdapterKind::Wwan => 20,
        PhysicalAdapterKind::Tunnel | PhysicalAdapterKind::Ppp | PhysicalAdapterKind::Other => 0,
    }
}

/// Build a preflight path from in-memory adapter rows (Fake / tests).
pub fn build_physical_network_path(adapters: &[PhysicalAdapterRecord]) -> PhysicalNetworkPath {
    let mut rows: Vec<_> = adapters
        .iter()
        .filter(|adapter| {
            !is_vpn_like_adapter(&adapter.name, &adapter.description)
                && adapter.has_usable_interface_index()
                && physical_adapter_score(adapter.kind) > 0
        })
        .collect();

    rows.sort_by(|left, right| {
        right
            .is_active
            .cmp(&left.is_active)
            .then_with(|| {
                left.ipv4_metric
                    .min(left.ipv6_metric)
                    .cmp(&right.ipv4_metric.min(right.ipv6_metric))
            })
            .then_with(|| {
                physical_adapter_score(right.kind).cmp(&physical_adapter_score(left.kind))
            })
            .then_with(|| right.speed.cmp(&left.speed))
            .then_with(|| left.id.cmp(&right.id))
    });

    let mapped = rows
        .into_iter()
        .take(MAX_PHYSICAL_ADAPTERS)
        .map(|adapter| {
            PhysicalNetworkAdapter::new(
                adapter.id.clone(),
                adapter.name.clone(),
                adapter.is_active,
                adapter.ipv4_interface_index,
                adapter.ipv6_interface_index,
            )
        })
        .collect();

    PhysicalNetworkPath::new(mapped)
}

impl PhysicalAdapterRecord {
    fn has_usable_interface_index(&self) -> bool {
        self.ipv4_interface_index.is_some_and(|i| i > 0)
            || self.ipv6_interface_index.is_some_and(|i| i > 0)
    }
}

struct FakePhysicalNetworkPathState {
    adapters: Vec<PhysicalAdapterRecord>,
    host_overrides: HashMap<String, PhysicalNetworkRoute>,
    default_route: Option<PhysicalNetworkRoute>,
}

/// Scriptable Fake probe for unit tests (no `dnsapi` / `iphlpapi`).
pub struct FakePhysicalNetworkPath {
    state: Mutex<FakePhysicalNetworkPathState>,
}

impl FakePhysicalNetworkPath {
    pub fn new(adapters: Vec<PhysicalAdapterRecord>) -> Self {
        Self {
            state: Mutex::new(FakePhysicalNetworkPathState {
                adapters,
                host_overrides: HashMap::new(),
                default_route: None,
            }),
        }
    }

    pub fn with_host_route(
        self,
        host: impl Into<String>,
        route: PhysicalNetworkRoute,
    ) -> Self {
        if let Ok(mut state) = self.state.lock() {
            state
                .host_overrides
                .insert(host.into().to_ascii_lowercase(), route);
        }
        self
    }

    pub fn with_default_route(self, route: PhysicalNetworkRoute) -> Self {
        if let Ok(mut state) = self.state.lock() {
            state.default_route = Some(route);
        }
        self
    }

    fn classify_with_overrides(&self, host: &str) -> Result<PhysicalNetworkRoute, TunnelError> {
        let trimmed = host.trim();
        if trimmed.is_empty() {
            return Err(TunnelError::InvalidHost {
                host: host.to_string(),
                reason: "destination host required".into(),
            });
        }

        let state = self
            .state
            .lock()
            .map_err(|_| TunnelError::Establish("FakePhysicalNetworkPath poisoned".into()))?;

        if let Some(route) = state.host_overrides.get(&trimmed.to_ascii_lowercase()) {
            return Ok(*route);
        }
        if let Some(route) = state.default_route {
            return Ok(route);
        }
        drop(state);

        classify_split_route(trimmed)
    }
}

impl fmt::Debug for FakePhysicalNetworkPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().ok();
        f.debug_struct("FakePhysicalNetworkPath")
            .field(
                "adapter_count",
                &state.as_ref().map(|s| s.adapters.len()),
            )
            .field(
                "override_count",
                &state.as_ref().map(|s| s.host_overrides.len()),
            )
            .field(
                "has_default_route",
                &state.as_ref().map(|s| s.default_route.is_some()),
            )
            .finish()
    }
}

impl PhysicalNetworkPathProbe for FakePhysicalNetworkPath {
    fn get_best_path(&self, _destination_hosts: &[&str]) -> Result<PhysicalNetworkPath, TunnelError> {
        let state = self
            .state
            .lock()
            .map_err(|_| TunnelError::Establish("FakePhysicalNetworkPath poisoned".into()))?;
        Ok(build_physical_network_path(&state.adapters))
    }

    fn classify_host(&self, host: &str) -> Result<PhysicalNetworkRoute, TunnelError> {
        self.classify_with_overrides(host)
    }
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    let literal = strip_brackets(host);
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return ip.is_loopback() || is_link_local(ip);
    }

    false
}

fn is_private_or_lan_host(host: &str) -> bool {
    if host.to_ascii_lowercase().ends_with(".local") {
        return true;
    }

    let literal = strip_brackets(host);
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return is_private_ipv4(ip) || is_unique_local_ipv6(ip);
    }

    false
}

fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    }
}

fn is_private_ipv4(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(_) => false,
    }
}

fn is_unique_local_ipv6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.is_unique_local())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wifi() -> PhysicalAdapterRecord {
        PhysicalAdapterRecord {
            id: "wifi".into(),
            name: "Wi-Fi".into(),
            description: String::new(),
            kind: PhysicalAdapterKind::Wireless,
            is_active: true,
            ipv4_metric: 25,
            ipv6_metric: 30,
            ipv4_interface_index: Some(13),
            ipv6_interface_index: Some(14),
            speed: 300_000_000,
        }
    }

    fn ethernet_down() -> PhysicalAdapterRecord {
        PhysicalAdapterRecord {
            id: "ethernet".into(),
            name: "Ethernet".into(),
            description: String::new(),
            kind: PhysicalAdapterKind::Ethernet,
            is_active: false,
            ipv4_metric: 5,
            ipv6_metric: 8,
            ipv4_interface_index: Some(21),
            ipv6_interface_index: Some(22),
            speed: 1_000_000_000,
        }
    }

    fn vpn_tunnel() -> PhysicalAdapterRecord {
        PhysicalAdapterRecord {
            id: "vpn".into(),
            name: "Stormshield VPN".into(),
            description: "Tunnel".into(),
            kind: PhysicalAdapterKind::Tunnel,
            is_active: true,
            ipv4_metric: 1,
            ipv6_metric: 1,
            ipv4_interface_index: Some(7),
            ipv6_interface_index: Some(8),
            speed: 100_000_000,
        }
    }

    #[test]
    fn empty_host_fail_closed() {
        assert!(matches!(
            classify_split_route(""),
            Err(TunnelError::InvalidHost { .. })
        ));
        assert!(matches!(
            classify_split_route("   "),
            Err(TunnelError::InvalidHost { .. })
        ));

        let fake = FakePhysicalNetworkPath::new(vec![]);
        assert!(matches!(
            fake.classify_host(""),
            Err(TunnelError::InvalidHost { .. })
        ));
    }

    #[test]
    fn classify_loopback_is_direct() {
        for host in ["127.0.0.1", "localhost", "::1", "[::1]"] {
            assert_eq!(
                classify_split_route(host).unwrap(),
                PhysicalNetworkRoute::Direct,
                "{host}"
            );
        }
    }

    #[test]
    fn classify_private_and_local_is_physical() {
        for host in ["10.0.0.5", "192.168.1.1", "appliance.local"] {
            assert_eq!(
                classify_split_route(host).unwrap(),
                PhysicalNetworkRoute::Physical,
                "{host}"
            );
        }
    }

    #[test]
    fn classify_public_is_unknown() {
        assert_eq!(
            classify_split_route("vpn.example.test").unwrap(),
            PhysicalNetworkRoute::Unknown
        );
        assert_eq!(
            classify_split_route("8.8.8.8").unwrap(),
            PhysicalNetworkRoute::Unknown
        );
    }

    #[test]
    fn get_best_path_excludes_vpn_and_keeps_fallbacks() {
        let fake = FakePhysicalNetworkPath::new(vec![
            PhysicalAdapterRecord {
                id: "filter".into(),
                name: "WFP filter".into(),
                description: String::new(),
                kind: PhysicalAdapterKind::Other,
                is_active: true,
                ipv4_metric: 1,
                ipv6_metric: 1,
                ipv4_interface_index: Some(1),
                ipv6_interface_index: Some(1),
                speed: 1,
            },
            vpn_tunnel(),
            wifi(),
            ethernet_down(),
        ]);

        let path = fake.get_best_path(&["vpn.example.test"]).unwrap();
        assert!(path.has_any_interface());
        assert_eq!(path.adapter_ids(), vec!["wifi", "ethernet"]);
        assert_eq!(path.adapters[0].id, "wifi");
        assert!(path.adapters[0].is_active);
        assert_eq!(path.adapters[1].id, "ethernet");
        assert!(!path.adapters[1].is_active);
    }

    #[test]
    fn blank_adapter_id_is_unavailable() {
        let path = PhysicalNetworkPath::new(vec![PhysicalNetworkAdapter::new(
            "",
            "Ethernet",
            true,
            Some(11),
            Some(12),
        )]);
        assert!(!path.has_any_interface());
        assert!(path.adapter_ids().is_empty());
    }

    #[test]
    fn is_vpn_like_adapter_rejects_markers() {
        assert!(is_vpn_like_adapter("NordLynx", "NordLynx Tunnel"));
        assert!(is_vpn_like_adapter(
            "Corporate adapter",
            "Palo Alto Networks Virtual Ethernet Adapter"
        ));
        assert!(!is_vpn_like_adapter("Ethernet", "Intel(R) Ethernet Connection"));
    }

    #[test]
    fn fake_host_override_wins() {
        let fake = FakePhysicalNetworkPath::new(vec![]).with_host_route(
            "corp.example",
            PhysicalNetworkRoute::Physical,
        );
        assert_eq!(
            fake.classify_host("corp.example").unwrap(),
            PhysicalNetworkRoute::Physical
        );
        assert_eq!(
            fake.classify_host("other.example").unwrap(),
            PhysicalNetworkRoute::Unknown
        );
    }

    #[test]
    fn fake_default_route_applies_when_no_override() {
        let fake =
            FakePhysicalNetworkPath::new(vec![]).with_default_route(PhysicalNetworkRoute::Direct);
        assert_eq!(
            fake.classify_host("public.example").unwrap(),
            PhysicalNetworkRoute::Direct
        );
    }

    #[test]
    fn fake_debug_omits_host_overrides() {
        let fake = FakePhysicalNetworkPath::new(vec![wifi()])
            .with_host_route("secret.gateway", PhysicalNetworkRoute::Physical);
        let debug = format!("{fake:?}");
        assert!(!debug.contains("secret.gateway"));
        assert!(debug.contains("adapter_count"));
    }

    #[test]
    fn classify_link_local_is_direct() {
        for host in ["169.254.1.1", "fe80::1"] {
            assert_eq!(
                classify_split_route(host).unwrap(),
                PhysicalNetworkRoute::Direct,
                "{host}"
            );
        }
    }

    #[test]
    fn fake_host_override_is_case_insensitive() {
        let fake = FakePhysicalNetworkPath::new(vec![]).with_host_route(
            "CORP.EXAMPLE",
            PhysicalNetworkRoute::Physical,
        );
        assert_eq!(
            fake.classify_host("corp.example").unwrap(),
            PhysicalNetworkRoute::Physical
        );
    }

    #[test]
    fn nbsp_only_host_fail_closed() {
        assert!(matches!(
            classify_split_route("\u{00a0}"),
            Err(TunnelError::InvalidHost { .. })
        ));
    }

    #[test]
    fn get_best_path_rejects_unknown_interface_types() {
        let fake = FakePhysicalNetworkPath::new(vec![PhysicalAdapterRecord {
            id: "opaque".into(),
            name: "Opaque adapter".into(),
            description: String::new(),
            kind: PhysicalAdapterKind::Other,
            is_active: true,
            ipv4_metric: 1,
            ipv6_metric: 1,
            ipv4_interface_index: Some(41),
            ipv6_interface_index: Some(42),
            speed: 1,
        }]);
        let path = fake.get_best_path(&[]).unwrap();
        assert!(path.adapters.is_empty());
        assert!(!path.has_any_interface());
    }

    #[test]
    fn get_best_path_does_not_require_destination_hosts() {
        let fake = FakePhysicalNetworkPath::new(vec![wifi()]);
        let path = fake.get_best_path(&[]).unwrap();
        assert!(path.has_any_interface());
    }
}
