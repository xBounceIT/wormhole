//! DPAPI optional-entropy constants mirroring the C# protectors.
//!
//! | Blob | Entropy |
//! |---|---|
//! | `keys\*.dpapi` / `tunnels\*.dpapi` | **none** (`optionalEntropy: null`) |
//! | `app-auth.dpapi` | UTF-8 `Wormhole.AppAuthentication.v1` |
//! | `bitwarden-browser-storage.dpapi` | UTF-8 `Wormhole.BitwardenBrowser.SharedStorage.v1` |
//! | Azure / WatchGuard / Stormshield caches | `Guid.ToByteArray()` (mixed-endian) |

use uuid::Uuid;

/// Entropy for [`crate::paths::app_authentication_path`] —
/// `DpapiAppAuthenticationDataProtector`.
pub const APP_AUTHENTICATION_V1: &[u8] = b"Wormhole.AppAuthentication.v1";

/// Entropy for [`crate::paths::bitwarden_browser_shared_storage_path`] —
/// `BitwardenBrowserSharedStorage`.
pub const BITWARDEN_BROWSER_SHARED_STORAGE_V1: &[u8] =
    b"Wormhole.BitwardenBrowser.SharedStorage.v1";

/// Returns [`APP_AUTHENTICATION_V1`].
#[inline]
pub fn app_authentication_v1() -> &'static [u8] {
    APP_AUTHENTICATION_V1
}

/// Returns [`BITWARDEN_BROWSER_SHARED_STORAGE_V1`].
#[inline]
pub fn bitwarden_browser_shared_storage_v1() -> &'static [u8] {
    BITWARDEN_BROWSER_SHARED_STORAGE_V1
}

/// `.NET Guid.ToByteArray()` layout (mixed-endian), used as DPAPI optionalEntropy
/// for Azure VPN / WatchGuard / Stormshield per-tunnel caches.
///
/// This matches `uuid::Uuid::to_bytes_le()` (Microsoft GUID byte order), **not**
/// RFC 4122 network order (`as_bytes()`).
#[inline]
pub fn guid_to_dotnet_bytes(id: &Uuid) -> [u8; 16] {
    id.to_bytes_le()
}

/// Per-tunnel DPAPI entropy: `tunnelConfigId.ToByteArray()` in C#.
#[inline]
pub fn tunnel_id_entropy(tunnel_config_id: &Uuid) -> [u8; 16] {
    guid_to_dotnet_bytes(tunnel_config_id)
}
