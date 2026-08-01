//! Live Windows physical-network-path client (iphlpapi) — Lab unit.
//!
//! C# parity: `Services/Tunneling/WindowsPhysicalNetworkPathService.cs` enumerates
//! adapters via `GetAdaptersAddresses` (walking the `IP_ADAPTER_ADDRESSES_LH` linked
//! list, capturing the adapter GUID id / friendly name / operational status / ipv4 +
//! ipv6 interface indexes) and resolves a per-destination best interface via
//! `GetBestInterfaceEx`. Adapter identity is `{adapter GUID id, name, is_active,
//! ipv4/ipv6 interface index}`; `IsVpnLikeAdapter` filters VPN adapters by name /
//! description. The pure ordering + split-route heuristics already live in
//! [`crate::physical_network_path`] ([`build_physical_network_path`] /
//! [`classify_split_route`] / [`is_vpn_like_adapter`] / [`physical_adapter_score`]);
//! this module adds the injectable [`WindowsAdapterSource`] seam and a real probe
//! ([`Win32PhysicalNetworkPathProbe`]) that composes it with those heuristics.
//!
//! The [`Win32AdapterSource`] mirrors the Win32-call style of
//! `wormhole-secrets-win/src/os_idle.rs` (struct sizing / fail-closed `Err` mapping /
//! presence-only tests / `#[cfg(not(windows))]` → unsupported). **Never** resolves DNS
//! in preflight — a hostname has no determinable best interface without resolving, so
//! [`WindowsAdapterSource::best_interface_index`] returns `Ok(None)` for non-IP-literal
//! hosts (a VPN-captured resolver must never be consulted during preflight).
//!
//! Fail-closed matrix:
//!
//! | Condition | [`WindowsAdapterSource::get_adapters`] | [`WindowsAdapterSource::best_interface_index`] |
//! |---|---|
//! | `GetAdaptersAddresses` sizing pass: unexpected status (incl. with zero size) | `Err` | — |
//! | `GetAdaptersAddresses` sizing pass: `ERROR_BUFFER_OVERFLOW` with zero size | `Ok(empty)` — no adapters enumerated | — |
//! | `GetAdaptersAddresses` sizing pass: buffer larger than [`MAX_ADAPTER_BUFFER_BYTES`] | `Err` — never allocate unbounded memory | — |
//! | `GetAdaptersAddresses` fill pass: non-zero status | `Err` | — |
//! | `GetBestInterfaceEx` non-zero return | — | `Err` (fail closed) |
//! | best-route index `0` or beyond `i32::MAX` (C# `is > 0 and <= int.MaxValue`) | — | `Ok(None)` (no usable best route) |
//! | host is not an IP literal | — | `Ok(None)` — no DNS during preflight |
//! | not running on Windows | `Err` | `Err` |
//!
//! | Condition | real probe `get_best_path` | real probe `classify_host` |
//! |---|---|---|
//! | adapter enumeration failed | `Err` | — |
//! | no active / usable adapters | `Ok(empty path)` — **not** an error | — |
//! | empty / whitespace host | — | `Err(InvalidHost)` |
//! | loopback / link-local / RFC1918 / `.local` | — | `Direct` / `Physical` (pure, no OS calls) |
//! | public host, best interface owned by an active non-VPN adapter | — | `Physical` |
//! | public host, best interface VPN / missing / best-route error | — | `Unknown` / `Err` (fail closed) |
//!
//! **Tests never call the real API** — behavior flows through [`FakeAdapterSource`];
//! [`Win32AdapterSource`] gets a compile-time presence check only (os_idle style).
//! [`Debug`] prints adapter ids / names / indexes / counters only.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::physical_network_path::{
    build_physical_network_path, classify_split_route, is_vpn_like_adapter, PhysicalAdapterKind,
    PhysicalAdapterRecord, PhysicalNetworkPath, PhysicalNetworkPathProbe, PhysicalNetworkRoute,
};
use crate::TunnelError;

/// Failure enumerating / probing Windows network adapters (Win32 call style).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterSourceError {
    /// `GetAdaptersAddresses` / `GetBestInterfaceEx` returned a non-zero status.
    Win32 {
        /// API or operation name.
        op: &'static str,
        /// Windows error code (the function return value).
        code: u32,
    },
    /// The sizing pass reported an implausibly large adapter table
    /// (fail closed instead of allocating unbounded memory).
    AdapterBufferTooLarge {
        /// The [`MAX_ADAPTER_BUFFER_BYTES`] cap that was exceeded.
        max_bytes: u32,
    },
    /// Not running on Windows.
    UnsupportedPlatform,
}

impl fmt::Display for AdapterSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Win32 { op, code } => write!(f, "{op} failed with Win32 error {code}"),
            Self::AdapterBufferTooLarge { max_bytes } => write!(
                f,
                "GetAdaptersAddresses reported an adapter table larger than {max_bytes} bytes"
            ),
            Self::UnsupportedPlatform => write!(f, "Windows adapter enumeration requires Windows"),
        }
    }
}

impl std::error::Error for AdapterSourceError {}

impl From<AdapterSourceError> for TunnelError {
    fn from(error: AdapterSourceError) -> Self {
        TunnelError::Establish(error.to_string())
    }
}

/// Injectable adapter source mirroring `IWindowsNetworkAdapterSource` (the
/// `GetAdapters` + `GetBestRouteInterfaceIndex` halves C# uses).
///
/// Implementations must never log credentials (there are none on this surface).
pub trait WindowsAdapterSource: Send + Sync {
    /// Enumerate physical adapters (`GetAdaptersAddresses` in the real impl).
    ///
    /// Fail-closed: API errors → `Err`; an empty adapter list is a valid enumeration
    /// (`Ok(empty)`).
    fn get_adapters(&self) -> Result<Vec<PhysicalAdapterRecord>, TunnelError>;

    /// Best route interface index for a destination host (`GetBestInterfaceEx`).
    ///
    /// Fail-closed: API errors → `Err`. `Ok(None)` when there is no usable best route
    /// **or** when `host` is not an IP literal (preflight never resolves DNS).
    fn best_interface_index(&self, host: &str) -> Result<Option<u32>, TunnelError>;
}

/// Production adapter source: `GetAdaptersAddresses` + `GetBestInterfaceEx` (iphlpapi).
///
/// `[Debug]` is an empty unit struct — no adapter payload is held.
#[derive(Debug, Default, Clone, Copy)]
pub struct Win32AdapterSource;

#[cfg(windows)]
impl WindowsAdapterSource for Win32AdapterSource {
    fn get_adapters(&self) -> Result<Vec<PhysicalAdapterRecord>, TunnelError> {
        enumerate_adapters().map_err(TunnelError::from)
    }

    fn best_interface_index(&self, host: &str) -> Result<Option<u32>, TunnelError> {
        best_interface_index_win32(host).map_err(TunnelError::from)
    }
}

#[cfg(not(windows))]
impl WindowsAdapterSource for Win32AdapterSource {
    fn get_adapters(&self) -> Result<Vec<PhysicalAdapterRecord>, TunnelError> {
        Err(AdapterSourceError::UnsupportedPlatform.into())
    }

    fn best_interface_index(&self, _host: &str) -> Result<Option<u32>, TunnelError> {
        Err(AdapterSourceError::UnsupportedPlatform.into())
    }
}

/// Real-style probe composing a [`WindowsAdapterSource`] with the existing
/// [`build_physical_network_path`] / [`classify_split_route`] / [`is_vpn_like_adapter`]
/// heuristics (C# `WindowsPhysicalNetworkPathService.GetBestPathAsync` + the split-route
/// classification the Stormshield / WatchGuard portal glue relies on).
///
/// Fail-closed: an enumeration error → `Err`; **no active adapters** → a valid empty
/// path (never an error here — the portal glue decides whether an empty path aborts).
pub struct Win32PhysicalNetworkPathProbe<S> {
    source: S,
}

impl<S> Win32PhysicalNetworkPathProbe<S> {
    pub fn new(source: S) -> Self {
        Self { source }
    }
}

impl<S: WindowsAdapterSource> Win32PhysicalNetworkPathProbe<S> {
    /// Destination hosts are accepted for C# parity but never resolved (see the
    /// module header — preflight must not reintroduce VPN-captured DNS).
    fn classify_unknown_with_best_route(&self, host: &str) -> Result<PhysicalNetworkRoute, TunnelError> {
        let Some(index) = self.source.best_interface_index(host)? else {
            return Ok(PhysicalNetworkRoute::Unknown);
        };
        let adapters = self.source.get_adapters()?;
        let owner = adapters.iter().find(|adapter| {
            adapter.ipv4_interface_index == Some(index)
                || adapter.ipv6_interface_index == Some(index)
        });
        match owner {
            // C# `IsVpnLikeAdapter` parity: Tunnel / Ppp interface kinds are VPN-like
            // unconditionally (regardless of the name/description markers), so a
            // tunnel-kind adapter must never qualify as the physical owner.
            Some(adapter)
                if adapter.is_active
                    && !matches!(
                        adapter.kind,
                        PhysicalAdapterKind::Tunnel | PhysicalAdapterKind::Ppp
                    )
                    && !is_vpn_like_adapter(&adapter.name, &adapter.description) =>
            {
                Ok(PhysicalNetworkRoute::Physical)
            }
            _ => Ok(PhysicalNetworkRoute::Unknown),
        }
    }
}

impl<S: WindowsAdapterSource + fmt::Debug> fmt::Debug for Win32PhysicalNetworkPathProbe<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Win32PhysicalNetworkPathProbe")
            .field("source", &self.source)
            .finish()
    }
}

impl<S: WindowsAdapterSource> PhysicalNetworkPathProbe for Win32PhysicalNetworkPathProbe<S> {
    fn get_best_path(&self, _destination_hosts: &[&str]) -> Result<PhysicalNetworkPath, TunnelError> {
        let adapters = self.source.get_adapters()?;
        Ok(build_physical_network_path(&adapters))
    }

    fn classify_host(&self, host: &str) -> Result<PhysicalNetworkRoute, TunnelError> {
        let trimmed = host.trim();
        if trimmed.is_empty() {
            return Err(TunnelError::InvalidHost {
                host: host.to_string(),
                reason: "destination host required".into(),
            });
        }

        match classify_split_route(trimmed) {
            Ok(route @ (PhysicalNetworkRoute::Direct | PhysicalNetworkRoute::Physical)) => {
                Ok(route)
            }
            Ok(PhysicalNetworkRoute::Unknown) => self.classify_unknown_with_best_route(trimmed),
            Err(error) => Err(error),
        }
    }
}

/// Deterministic adapter source for unit tests (never touches iphlpapi).
///
/// [`Debug`] prints adapter ids / counters only — never scripted route hosts.
pub struct FakeAdapterSource {
    state: Mutex<FakeAdapterSourceState>,
}

#[derive(Default)]
struct FakeAdapterSourceState {
    adapters: Vec<PhysicalAdapterRecord>,
    /// Host (lowercased) → best interface index (`None` = no best route).
    best_routes: HashMap<String, Option<u32>>,
    adapters_error: Option<String>,
    best_interface_error: Option<String>,
}

impl FakeAdapterSource {
    pub fn new(adapters: Vec<PhysicalAdapterRecord>) -> Self {
        Self {
            state: Mutex::new(FakeAdapterSourceState {
                adapters,
                ..Default::default()
            }),
        }
    }

    /// Script the best-route interface index for a host (case-insensitive; leading /
    /// trailing whitespace is ignored, matching the [`best_interface_index`] lookup).
    pub fn with_best_route(self, host: impl Into<String>, index: Option<u32>) -> Self {
        if let Ok(mut state) = self.state.lock() {
            state
                .best_routes
                .insert(host.into().trim().to_ascii_lowercase(), index);
        }
        self
    }

    /// Script `get_adapters` to fail (fail-closed paths).
    pub fn with_adapters_error(self, message: impl Into<String>) -> Self {
        if let Ok(mut state) = self.state.lock() {
            state.adapters_error = Some(message.into());
        }
        self
    }

    /// Script `best_interface_index` to fail (fail-closed paths).
    pub fn with_best_interface_error(self, message: impl Into<String>) -> Self {
        if let Ok(mut state) = self.state.lock() {
            state.best_interface_error = Some(message.into());
        }
        self
    }

    /// Current scripted adapter rows (test assertions only).
    pub fn adapters(&self) -> Vec<PhysicalAdapterRecord> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .adapters
            .clone()
    }

    /// Scripted best-route for a host (test assertions only; case-insensitive,
    /// surrounding whitespace ignored).
    pub fn best_route(&self, host: &str) -> Option<Option<u32>> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .best_routes
            .get(&host.trim().to_ascii_lowercase())
            .copied()
    }
}

impl fmt::Debug for FakeAdapterSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().ok();
        let ids: Vec<&str> = state
            .as_ref()
            .map(|s| {
                s.adapters
                    .iter()
                    .map(|adapter| adapter.id.as_str())
                    .collect()
            })
            .unwrap_or_default();
        f.debug_struct("FakeAdapterSource")
            .field("adapter_ids", &ids)
            .field(
                "route_count",
                &state.as_ref().map(|s| s.best_routes.len()),
            )
            .field(
                "has_adapters_error",
                &state.as_ref().map(|s| s.adapters_error.is_some()),
            )
            .field(
                "has_best_interface_error",
                &state.as_ref().map(|s| s.best_interface_error.is_some()),
            )
            .finish()
    }
}

impl WindowsAdapterSource for FakeAdapterSource {
    fn get_adapters(&self) -> Result<Vec<PhysicalAdapterRecord>, TunnelError> {
        let state = self
            .state
            .lock()
            .map_err(|_| TunnelError::Establish("FakeAdapterSource poisoned".into()))?;
        if let Some(message) = &state.adapters_error {
            return Err(TunnelError::Establish(message.clone()));
        }
        Ok(state.adapters.clone())
    }

    fn best_interface_index(&self, host: &str) -> Result<Option<u32>, TunnelError> {
        let state = self
            .state
            .lock()
            .map_err(|_| TunnelError::Establish("FakeAdapterSource poisoned".into()))?;
        if let Some(message) = &state.best_interface_error {
            return Err(TunnelError::Establish(message.clone()));
        }
        Ok(state
            .best_routes
            .get(&host.trim().to_ascii_lowercase())
            .copied()
            .flatten())
    }
}

/// Map a Windows `IF_TYPE` (`IfType`) onto the lab [`PhysicalAdapterKind`] scoring
/// (C# `PhysicalAdapterScore(NetworkInterfaceType)` parity).
fn kind_from_if_type(if_type: u32) -> PhysicalAdapterKind {
    match if_type {
        6 | 26 | 62 | 69 | 117 => PhysicalAdapterKind::Ethernet,
        71 => PhysicalAdapterKind::Wireless,
        243 | 244 => PhysicalAdapterKind::Wwan,
        23 => PhysicalAdapterKind::Ppp,
        131 => PhysicalAdapterKind::Tunnel,
        _ => PhysicalAdapterKind::Other,
    }
}

/// Extract the `{GUID}` adapter id from `AdapterName` (C# `NetworkInterface.Id` is the
/// braced GUID; `AdapterName` is `\DEVICE\TCPIP_{GUID}`). Falls back to the last path
/// segment, then the raw string — an adapter with a blank id is unusable for pinning.
fn adapter_guid(adapter_name: &str) -> String {
    if let Some(open) = adapter_name.find('{') {
        if let Some(close) = adapter_name.rfind('}') {
            if close > open {
                return adapter_name[open..=close].to_string();
            }
        }
    }
    adapter_name
        .rsplit('\\')
        .next()
        .unwrap_or(adapter_name)
        .trim()
        .to_string()
}

/// Safety cap for the adapter table reported by the `GetAdaptersAddresses` sizing
/// pass. Each entry is ~1 KB; 16 MiB covers thousands of adapters while ensuring a
/// hostile / corrupt size can never drive an unbounded allocation (which would abort
/// the process on OOM instead of failing closed).
const MAX_ADAPTER_BUFFER_BYTES: u32 = 16 * 1024 * 1024;

/// Pure sizing-pass decision for `GetAdaptersAddresses` (unit-testable without the
/// live API). `Ok(true)` → proceed with the reported size; `Ok(false)` → no adapters
/// (valid empty list); `Err` → fail closed.
///
/// Fail-closed matrix (see the module header): `NO_ERROR` → empty (degenerate
/// success with a null buffer); `ERROR_BUFFER_OVERFLOW` with zero size → empty; any
/// **other** status → `Err` (even when `size` is zero — an error is never reported
/// as "no adapters"); a size beyond [`MAX_ADAPTER_BUFFER_BYTES`] → `Err`.
fn sizing_pass(code: u32, size: u32) -> Result<bool, AdapterSourceError> {
    const NO_ERROR: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    if code == NO_ERROR {
        return Ok(false);
    }
    if code != ERROR_BUFFER_OVERFLOW {
        return Err(AdapterSourceError::Win32 {
            op: "GetAdaptersAddresses",
            code,
        });
    }
    if size == 0 {
        return Ok(false);
    }
    if size > MAX_ADAPTER_BUFFER_BYTES {
        return Err(AdapterSourceError::AdapterBufferTooLarge {
            max_bytes: MAX_ADAPTER_BUFFER_BYTES,
        });
    }
    Ok(true)
}

#[cfg(windows)]
fn enumerate_adapters() -> Result<Vec<PhysicalAdapterRecord>, AdapterSourceError> {
    use std::mem::MaybeUninit;

    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

    const AF_UNSPEC: u32 = 0;
    let flags = GET_ADAPTERS_ADDRESSES_FLAGS(0);

    // Sizing pass: a null buffer returns ERROR_BUFFER_OVERFLOW + the required byte size.
    let mut size: u32 = 0;
    let code = unsafe { GetAdaptersAddresses(AF_UNSPEC, flags, None, None, &mut size) };
    if !sizing_pass(code, size)? {
        // No adapters enumerated — an empty list is a valid result.
        return Ok(Vec::new());
    }

    // Allocate through `IP_ADAPTER_ADDRESSES_LH` elements so the buffer carries the
    // struct's alignment (a byte vec is only 1-aligned and would be UB to cast).
    let element_size = std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32;
    let capacity = size.div_ceil(element_size) as usize + 1;
    let mut buffer: Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>> = Vec::with_capacity(capacity);
    // SAFETY: the elements are `MaybeUninit`; the OS fills them before any read.
    unsafe { buffer.set_len(capacity) };
    let base = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    let mut buffer_bytes = (capacity as u32).saturating_mul(element_size);

    let code =
        unsafe { GetAdaptersAddresses(AF_UNSPEC, flags, None, Some(base), &mut buffer_bytes) };
    if code != NO_ERROR.0 {
        return Err(AdapterSourceError::Win32 {
            op: "GetAdaptersAddresses",
            code,
        });
    }

    let mut records = Vec::new();
    let mut current = base;
    while !current.is_null() {
        // SAFETY: `current` stays inside the `buffer` the OS just filled; every entry
        // is a valid `IP_ADAPTER_ADDRESSES_LH` with `Next`/`AdapterName`/string
        // pointers set by GetAdaptersAddresses. A zero `Length` marks a bogus tail
        // entry — stop walking rather than dereference garbage.
        unsafe {
            if (*current).Anonymous1.Anonymous.Length == 0 {
                break;
            }
            let node = &*current;
            let adapter_name = if node.AdapterName.is_null() {
                String::new()
            } else {
                node.AdapterName.to_string().unwrap_or_default()
            };
            let name = if node.FriendlyName.is_null() {
                String::new()
            } else {
                node.FriendlyName.to_string().unwrap_or_default()
            };
            let description = if node.Description.is_null() {
                String::new()
            } else {
                node.Description.to_string().unwrap_or_default()
            };
            let if_index = (*current).Anonymous1.Anonymous.IfIndex;
            let ipv6_index = node.Ipv6IfIndex;
            let if_type = node.IfType;
            let is_active = node.OperStatus == IfOperStatusUp;
            records.push(PhysicalAdapterRecord {
                id: adapter_guid(&adapter_name),
                name,
                description,
                kind: kind_from_if_type(if_type),
                is_active,
                ipv4_metric: node.Ipv4Metric,
                ipv6_metric: node.Ipv6Metric,
                ipv4_interface_index: (if_index > 0).then_some(if_index),
                ipv6_interface_index: (ipv6_index > 0).then_some(ipv6_index),
                speed: node.TransmitLinkSpeed,
            });
            current = node.Next;
        }
    }
    Ok(records)
}

#[cfg(windows)]
fn best_interface_index_win32(host: &str) -> Result<Option<u32>, AdapterSourceError> {
    use windows::Win32::NetworkManagement::IpHelper::GetBestInterfaceEx;
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR, SOCKADDR_IN,
        SOCKADDR_IN6,
    };

    // Preflight never resolves DNS (VPN-captured resolver): only IP literals have a
    // determinable best interface. Bracketed literals are stripped (C# DnsEndPoint parity).
    let trimmed = host.trim();
    let literal = trimmed
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(trimmed);
    let Ok(ip) = literal.parse::<IpAddr>() else {
        return Ok(None);
    };

    let mut index: u32 = 0;
    let code = match ip {
        IpAddr::V4(v4) => {
            let addr = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                },
                sin_zero: [0; 8],
            };
            // SAFETY: SOCKADDR_IN is repr(C), 16 bytes, and shares the SOCKADDR
            // family-first layout; GetBestInterfaceEx only reads the family + address.
            unsafe { GetBestInterfaceEx(&addr as *const SOCKADDR_IN as *const SOCKADDR, &mut index) }
        }
        IpAddr::V6(v6) => {
            use windows::Win32::Networking::WinSock::SOCKADDR_IN6_0;
            let addr = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: v6.octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            };
            // SAFETY: SOCKADDR_IN6 is repr(C), 28 bytes (larger than the 16-byte
            // SOCKADDR view the callee reads); family-first layout preserved.
            unsafe { GetBestInterfaceEx(&addr as *const SOCKADDR_IN6 as *const SOCKADDR, &mut index) }
        }
    };
    if code != 0 {
        return Err(AdapterSourceError::Win32 {
            op: "GetBestInterfaceEx",
            code,
        });
    }
    // C# parity: `interfaceIndex is > 0 and <= int.MaxValue`, else no usable route.
    if index == 0 || index > i32::MAX as u32 {
        return Ok(None);
    }
    Ok(Some(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet() -> PhysicalAdapterRecord {
        PhysicalAdapterRecord::ethernet("eth0", "Ethernet", 11, 12)
    }

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
    fn sizing_pass_matches_fail_closed_matrix() {
        const OVERFLOW: u32 = 111;

        // NO_ERROR (degenerate success with a null buffer) → empty.
        assert!(!sizing_pass(0, 0).unwrap());
        assert!(!sizing_pass(0, 4096).unwrap());

        // ERROR_BUFFER_OVERFLOW with zero size → empty (no adapters enumerated).
        assert!(!sizing_pass(OVERFLOW, 0).unwrap());

        // ERROR_BUFFER_OVERFLOW with a sane size → proceed.
        assert!(sizing_pass(OVERFLOW, 4096).unwrap());

        // Any *other* status → Err, even when size is zero (an error must never
        // be reported as "no adapters" — fail closed).
        assert!(matches!(
            sizing_pass(5, 0),
            Err(AdapterSourceError::Win32 { code: 5, .. })
        ));
        assert!(matches!(
            sizing_pass(5, 1024),
            Err(AdapterSourceError::Win32 { code: 5, .. })
        ));
        assert!(matches!(
            sizing_pass(87, 0),
            Err(AdapterSourceError::Win32 { code: 87, .. })
        ));

        // A size beyond the cap → Err (never allocate unbounded memory).
        assert!(matches!(
            sizing_pass(OVERFLOW, MAX_ADAPTER_BUFFER_BYTES + 1),
            Err(AdapterSourceError::AdapterBufferTooLarge { .. })
        ));
        assert!(sizing_pass(OVERFLOW, MAX_ADAPTER_BUFFER_BYTES).unwrap());
    }

    #[test]
    fn adapter_source_error_display_covers_all_variants_without_payload() {
        assert_eq!(
            AdapterSourceError::Win32 {
                op: "GetAdaptersAddresses",
                code: 111,
            }
            .to_string(),
            "GetAdaptersAddresses failed with Win32 error 111"
        );
        assert_eq!(
            AdapterSourceError::AdapterBufferTooLarge {
                max_bytes: MAX_ADAPTER_BUFFER_BYTES,
            }
            .to_string(),
            "GetAdaptersAddresses reported an adapter table larger than 16777216 bytes"
        );
        assert_eq!(
            AdapterSourceError::UnsupportedPlatform.to_string(),
            "Windows adapter enumeration requires Windows"
        );
        let mapped: TunnelError = AdapterSourceError::Win32 {
            op: "GetBestInterfaceEx",
            code: 5,
        }
        .into();
        assert!(!format!("{mapped}").contains("hunter2"));
    }

    #[test]
    fn kind_from_if_type_matches_csharp_scoring_types() {
        assert_eq!(kind_from_if_type(6), PhysicalAdapterKind::Ethernet);
        assert_eq!(kind_from_if_type(26), PhysicalAdapterKind::Ethernet);
        assert_eq!(kind_from_if_type(62), PhysicalAdapterKind::Ethernet);
        assert_eq!(kind_from_if_type(69), PhysicalAdapterKind::Ethernet);
        assert_eq!(kind_from_if_type(117), PhysicalAdapterKind::Ethernet);
        assert_eq!(kind_from_if_type(71), PhysicalAdapterKind::Wireless);
        assert_eq!(kind_from_if_type(243), PhysicalAdapterKind::Wwan);
        assert_eq!(kind_from_if_type(244), PhysicalAdapterKind::Wwan);
        assert_eq!(kind_from_if_type(23), PhysicalAdapterKind::Ppp);
        assert_eq!(kind_from_if_type(131), PhysicalAdapterKind::Tunnel);
        assert_eq!(kind_from_if_type(0), PhysicalAdapterKind::Other);
        assert_eq!(kind_from_if_type(999), PhysicalAdapterKind::Other);
    }

    #[test]
    fn adapter_guid_extracts_braced_guid_with_fallback() {
        assert_eq!(
            adapter_guid(r"\DEVICE\TCPIP_{5B2A9E12-1B3F-4C2D-9E8F-0A1B2C3D4E5F}"),
            "{5B2A9E12-1B3F-4C2D-9E8F-0A1B2C3D4E5F}"
        );
        assert_eq!(adapter_guid(r"\DEVICE\something"), "something");
        assert_eq!(adapter_guid("  raw-id  "), "raw-id");
    }

    #[test]
    fn fake_get_adapters_returns_scripted_records() {
        let source = FakeAdapterSource::new(vec![ethernet(), wifi()]);
        let adapters = source.get_adapters().unwrap();
        assert_eq!(adapters.len(), 2);
        assert_eq!(adapters[0].id, "eth0");
        assert_eq!(adapters[1].id, "wifi");
        assert_eq!(source.adapters().len(), 2);
        let dbg = format!("{source:?}");
        assert!(dbg.contains("eth0"), "{dbg}");
    }

    #[test]
    fn fake_get_adapters_error_fails_closed() {
        let source = FakeAdapterSource::new(vec![ethernet()])
            .with_adapters_error("simulated enumeration failure");
        assert!(source.get_adapters().is_err());
    }

    #[test]
    fn fake_best_interface_route_lookup_is_case_insensitive() {
        let source = FakeAdapterSource::new(vec![]).with_best_route("vpn.example", Some(11));
        assert_eq!(source.best_interface_index("vpn.example").unwrap(), Some(11));
        assert_eq!(source.best_interface_index("VPN.EXAMPLE").unwrap(), Some(11));
        assert_eq!(source.best_interface_index("other.example").unwrap(), None);
        assert_eq!(source.best_route("vpn.example"), Some(Some(11)));

        // Script keys with surrounding whitespace normalize the same way the lookup
        // trims — no silent no-match traps for test authors.
        let padded = FakeAdapterSource::new(vec![]).with_best_route("  fw.example  ", Some(12));
        assert_eq!(
            padded.best_interface_index("fw.example").unwrap(),
            Some(12),
            "scripted key whitespace must be ignored like the lookup"
        );
        assert_eq!(padded.best_route(" fw.example "), Some(Some(12)));
    }

    #[test]
    fn fake_best_interface_none_route_is_no_best_route() {
        let source = FakeAdapterSource::new(vec![]).with_best_route("fw.example", None);
        assert_eq!(source.best_interface_index("fw.example").unwrap(), None);
    }

    #[test]
    fn fake_best_interface_error_fails_closed() {
        let source =
            FakeAdapterSource::new(vec![]).with_best_interface_error("simulated route failure");
        assert!(source.best_interface_index("fw.example").is_err());
    }

    #[test]
    fn probe_get_best_path_orders_and_filters() {
        let source = FakeAdapterSource::new(vec![
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
            ethernet(),
        ]);
        let probe = Win32PhysicalNetworkPathProbe::new(source);
        let path = probe.get_best_path(&["vpn.example"]).unwrap();
        assert!(path.has_any_interface());
        assert_eq!(path.adapter_ids(), vec!["eth0", "wifi"]);
        assert_eq!(path.adapters[0].id, "eth0");
        assert!(path.adapters[0].is_active);
        assert_eq!(path.adapters[1].id, "wifi");
        assert!(path.adapters[1].is_active);
    }

    #[test]
    fn probe_get_best_path_empty_adapters_is_valid_empty_path() {
        let probe = Win32PhysicalNetworkPathProbe::new(FakeAdapterSource::new(vec![]));
        let path = probe.get_best_path(&[]).unwrap();
        assert!(path.adapters.is_empty());
        assert!(!path.has_any_interface());
    }

    #[test]
    fn probe_get_best_path_enumeration_error_propagates() {
        let source = FakeAdapterSource::new(vec![]).with_adapters_error("boom");
        let probe = Win32PhysicalNetworkPathProbe::new(source);
        assert!(matches!(
            probe.get_best_path(&[]),
            Err(TunnelError::Establish(_))
        ));
    }

    #[test]
    fn probe_classify_unknown_uses_best_route_on_physical_adapter() {
        // Public host: pure heuristics say Unknown, the live source says interface 11
        // (eth0, active, non-VPN) → Physical.
        let source = FakeAdapterSource::new(vec![ethernet()]).with_best_route("vpn.example", Some(11));
        let probe = Win32PhysicalNetworkPathProbe::new(source);
        assert_eq!(
            probe.classify_host("vpn.example").unwrap(),
            PhysicalNetworkRoute::Physical
        );
    }

    #[test]
    fn probe_classify_unknown_best_route_on_vpn_is_unknown() {
        let source = FakeAdapterSource::new(vec![vpn_tunnel()]).with_best_route("corp.example", Some(7));
        let probe = Win32PhysicalNetworkPathProbe::new(source);
        assert_eq!(
            probe.classify_host("corp.example").unwrap(),
            PhysicalNetworkRoute::Unknown
        );
    }

    #[test]
    fn probe_classify_unknown_tunnel_kind_owner_never_physical() {
        // C# `IsVpnLikeAdapter` excludes Ppp/Tunnel interface kinds unconditionally —
        // a Tunnel-kind adapter with a benign name/description must not qualify as the
        // physical owner even when it owns the best route (fail closed).
        let source = FakeAdapterSource::new(vec![PhysicalAdapterRecord {
            id: "loopback-tunnel".into(),
            name: "Loopback Adapter".into(),
            description: "Microsoft Loopback Adapter".into(),
            kind: PhysicalAdapterKind::Tunnel,
            is_active: true,
            ipv4_metric: 1,
            ipv6_metric: 1,
            ipv4_interface_index: Some(99),
            ipv6_interface_index: Some(99),
            speed: 1,
        }])
        .with_best_route("vpn.example", Some(99));
        let probe = Win32PhysicalNetworkPathProbe::new(source);
        assert_eq!(
            probe.classify_host("vpn.example").unwrap(),
            PhysicalNetworkRoute::Unknown,
            "Tunnel-kind adapters never qualify as the physical owner"
        );
    }

    #[test]
    fn probe_classify_unknown_inactive_or_missing_owner_is_unknown() {
        // Best route owned by a disconnected adapter or by no adapter at all → Unknown.
        let source = FakeAdapterSource::new(vec![PhysicalAdapterRecord {
            id: "eth-down".into(),
            name: "Ethernet".into(),
            description: String::new(),
            kind: PhysicalAdapterKind::Ethernet,
            is_active: false,
            ipv4_metric: 1,
            ipv6_metric: 1,
            ipv4_interface_index: Some(11),
            ipv6_interface_index: Some(12),
            speed: 1_000_000_000,
        }])
        .with_best_route("vpn.example", Some(11));
        let probe = Win32PhysicalNetworkPathProbe::new(source);
        assert_eq!(
            probe.classify_host("vpn.example").unwrap(),
            PhysicalNetworkRoute::Unknown,
            "an inactive owner must not classify as Physical"
        );

        let source = FakeAdapterSource::new(vec![ethernet()]).with_best_route("vpn.example", Some(555));
        let probe = Win32PhysicalNetworkPathProbe::new(source);
        assert_eq!(
            probe.classify_host("vpn.example").unwrap(),
            PhysicalNetworkRoute::Unknown,
            "an unowned best-route index must not classify as Physical"
        );
    }

    #[test]
    fn probe_classify_unknown_no_best_route_is_unknown() {
        let probe =
            Win32PhysicalNetworkPathProbe::new(FakeAdapterSource::new(vec![ethernet()]));
        assert_eq!(
            probe.classify_host("vpn.example").unwrap(),
            PhysicalNetworkRoute::Unknown
        );
    }

    #[test]
    fn probe_classify_best_interface_error_fails_closed() {
        let source =
            FakeAdapterSource::new(vec![ethernet()]).with_best_interface_error("probe boom");
        let probe = Win32PhysicalNetworkPathProbe::new(source);
        assert!(matches!(
            probe.classify_host("vpn.example"),
            Err(TunnelError::Establish(_))
        ));
    }

    #[test]
    fn probe_classify_empty_host_fails_closed() {
        let probe = Win32PhysicalNetworkPathProbe::new(FakeAdapterSource::new(vec![ethernet()]));
        assert!(matches!(
            probe.classify_host("   "),
            Err(TunnelError::InvalidHost { .. })
        ));
    }

    #[test]
    fn probe_classify_direct_and_physical_never_query_source() {
        // Loopback / RFC1918 short-circuit in the pure heuristic — the source's
        // best-route script for these hosts must never be consulted.
        let source = FakeAdapterSource::new(vec![]).with_best_route("10.0.0.5", Some(99));
        assert_eq!(source.best_route("10.0.0.5"), Some(Some(99)));
        let probe = Win32PhysicalNetworkPathProbe::new(source);
        assert_eq!(
            probe.classify_host("127.0.0.1").unwrap(),
            PhysicalNetworkRoute::Direct
        );
        assert_eq!(
            probe.classify_host("10.0.0.5").unwrap(),
            PhysicalNetworkRoute::Physical
        );
    }

    #[test]
    fn fake_debug_omits_scripted_route_hosts() {
        let source = FakeAdapterSource::new(vec![ethernet(), wifi()])
            .with_best_route("secret.gateway", Some(11))
            .with_adapters_error("x");
        let debug = format!("{source:?}");
        assert!(debug.contains("eth0"), "{debug}");
        assert!(debug.contains("route_count"), "{debug}");
        assert!(!debug.contains("secret.gateway"), "{debug}");
        assert!(!debug.contains("x"), "{debug}");
    }

    #[cfg(windows)]
    #[test]
    fn win32_source_presence_check_does_not_panic() {
        // Compile-time presence of the real iphlpapi client. Never asserts a value
        // (CI determinism) — it must merely construct and return Ok or Err.
        let source = Win32AdapterSource;
        if let Ok(adapters) = source.get_adapters() {
            let _ = format!("{adapters:?}");
        }
        let _ = source.best_interface_index("127.0.0.1");
        let _ = source.best_interface_index("vpn.example");
        let probe = Win32PhysicalNetworkPathProbe::new(Win32AdapterSource);
        if let Ok(path) = probe.get_best_path(&["127.0.0.1"]) {
            let _ = format!("{path:?}");
        }
        let _ = format!("{source:?} / {probe:?}");
    }

    #[cfg(not(windows))]
    #[test]
    fn win32_source_unsupported_off_windows() {
        let source = Win32AdapterSource;
        assert!(source.get_adapters().is_err());
        assert!(source.best_interface_index("8.8.8.8").is_err());
        let probe = Win32PhysicalNetworkPathProbe::new(source);
        assert!(probe.get_best_path(&[]).is_err());
        assert!(probe.classify_host("vpn.example").is_err());
    }
}
