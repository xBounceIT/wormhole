//! Azure AD / external-client routing Fake glue (no live WAM / AAD / `Process::Command`).
//!
//! Mirrors C# `AzureAdCredentialDetector` + `RdpSessionViewModel.ShouldUseExternalClientAsync`:
//! resolve `PreferExternalMstsc` vs `EmbeddedOcx` from scripted profile + credential-catalog
//! signals, then compose with [`super::external_mstsc_glue::RdpExternalMstscGlue`] for the
//! tunnel + external reject policy. Does **not** rewrite CredSSP / display / performance glues.

use std::collections::HashMap;
use std::fmt;

use uuid::Uuid;
use wormhole_domain::{ConnectionProfile, ProtocolType};

use super::external_mstsc_glue::{
    ExternalMstscGlueError, ExternalMstscPolicyInputs, RdpExternalMstscGlue,
};

/// Microsoft-documented AAD domain for mstsc credential prompts (case-insensitive).
pub const AZURE_AD_DOMAIN: &str = "AzureAD";
/// UPN-style AAD username prefix (`AzureAD\user@tenant`).
pub const AZURE_AD_USERNAME_PREFIX: &str = "AzureAD\\";

/// Embedded mstscax vs external `mstsc.exe` routing (C# `ShouldUseExternalClientAsync` outcome).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpClientRouting {
    /// Route through external `mstsc.exe` (AAD-safe; host network).
    PreferExternalMstsc,
    /// Embedded owned-overlay OCX path.
    EmbeddedOcx,
}

impl RdpClientRouting {
    /// True when external hand-off is preferred.
    pub fn prefers_external_mstsc(self) -> bool {
        matches!(self, Self::PreferExternalMstsc)
    }

    /// True when the embedded OCX path is selected.
    pub fn prefers_embedded_ocx(self) -> bool {
        matches!(self, Self::EmbeddedOcx)
    }
}

/// Which signal tripped external routing (diagnostics only — never secrets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpAadSignal {
    /// Per-profile `RdpUseExternalClient` opt-in.
    OptInFlag,
    /// Node `RdpDomain` equals AzureAD.
    NodeDomain,
    /// Node `Username` carries the `AzureAD\` prefix.
    NodeUsername,
    /// Linked credential `Domain` equals AzureAD.
    CredentialDomain,
    /// Linked credential `Username` carries the `AzureAD\` prefix.
    CredentialUsername,
    /// Credential catalog lookup failed — fail-safe to external (C# catch branch).
    CredentialLookupFailSafe,
}

/// True when a Domain field equals `AzureAD` (case-insensitive, trim surrounding whitespace).
pub fn has_azure_ad_domain(domain: Option<&str>) -> bool {
    domain
        .map(|value| value.trim().eq_ignore_ascii_case(AZURE_AD_DOMAIN))
        .unwrap_or(false)
}

/// True when a Username field starts with `AzureAD\` (case-insensitive, trim leading whitespace).
pub fn has_azure_ad_prefix(username: Option<&str>) -> bool {
    let Some(username) = username else {
        return false;
    };
    let trimmed = username.trim_start();
    trimmed
        .get(..AZURE_AD_USERNAME_PREFIX.len())
        .map(|head| head.eq_ignore_ascii_case(AZURE_AD_USERNAME_PREFIX))
        .unwrap_or(false)
}

/// Credential-only Azure AD check (C# `AzureAdCredentialDetector.IsAzureAd(CredentialProfile?)`).
pub fn is_azure_ad_credential(domain: Option<&str>, username: Option<&str>) -> bool {
    has_azure_ad_domain(domain) || has_azure_ad_prefix(username)
}

/// Profile + optional credential Azure AD check (C# `IsAzureAd(profile, credential)`).
pub fn is_azure_ad_profile(
    profile: &ConnectionProfile,
    credential_domain: Option<&str>,
    credential_username: Option<&str>,
) -> bool {
    is_azure_ad_credential(credential_domain, credential_username)
        || has_azure_ad_domain(profile.rdp_domain.as_deref())
        || has_azure_ad_prefix(profile.username.as_deref())
}

/// Scripted credential row for Fake catalog lookups (metadata only — no password body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptedRdpCredential {
    /// Credential `Domain` column (may be `AzureAD`).
    pub domain: Option<String>,
    /// Credential `Username` column (may carry `AzureAD\` prefix).
    pub username: Option<String>,
    /// Saved credential protocol — only `Rdp` rows participate in AAD routing.
    pub protocol: ProtocolType,
}

impl ScriptedRdpCredential {
    /// Convenience builder for RDP credential rows in tests / lab scripts.
    pub fn rdp(domain: Option<&str>, username: Option<&str>) -> Self {
        Self {
            domain: domain.map(str::to_owned),
            username: username.map(str::to_owned),
            protocol: ProtocolType::Rdp,
        }
    }
}

/// Outcome of a Fake credential-catalog lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeCredentialLookup {
    /// Row found (may still be non-AAD / non-RDP).
    Ok(ScriptedRdpCredential),
    /// Id not present in the scripted catalog.
    Missing,
    /// Scripted repository failure — routes external fail-safe.
    Error,
}

/// In-memory credential catalog for unit tests / lab (no SQLite / CredMgr).
#[derive(Default, Clone)]
pub struct FakeRdpCredentialCatalog {
    rows: HashMap<Uuid, ScriptedRdpCredential>,
    script_lookup_error: bool,
    lookup_count: usize,
}

impl FakeRdpCredentialCatalog {
    /// Empty scripted catalog.
    pub fn new() -> Self {
        Self {
            rows: HashMap::new(),
            script_lookup_error: false,
            lookup_count: 0,
        }
    }

    /// Insert or replace a scripted credential row.
    pub fn insert(&mut self, id: Uuid, credential: ScriptedRdpCredential) -> &mut Self {
        self.rows.insert(id, credential);
        self
    }

    /// Script the next lookup to fail (C# repository exception path).
    pub fn script_lookup_error(&mut self) -> &mut Self {
        self.script_lookup_error = true;
        self
    }

    /// How many lookups ran.
    pub fn lookup_count(&self) -> usize {
        self.lookup_count
    }

    /// Scripted lookup by id (increments `lookup_count`).
    pub fn lookup(&mut self, id: Uuid) -> FakeCredentialLookup {
        self.lookup_count += 1;
        if self.script_lookup_error {
            return FakeCredentialLookup::Error;
        }
        self.rows
            .get(&id)
            .cloned()
            .map(FakeCredentialLookup::Ok)
            .unwrap_or(FakeCredentialLookup::Missing)
    }
}

/// Resolution of external vs embedded routing (C# `ShouldUseExternalClientAsync`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdpRoutingResolution {
    /// Selected client path.
    pub routing: RdpClientRouting,
    /// Why external routing was chosen (`None` when embedded).
    pub signal: Option<RdpAadSignal>,
}

impl RdpRoutingResolution {
    /// Effective `use_external_client` bool for tunnel policy helpers.
    pub fn effective_use_external_client(self) -> bool {
        self.routing.prefers_external_mstsc()
    }
}

/// Decide external vs embedded from effective bool.
pub fn decide_rdp_client_routing(use_external_client: bool) -> RdpClientRouting {
    if use_external_client {
        RdpClientRouting::PreferExternalMstsc
    } else {
        RdpClientRouting::EmbeddedOcx
    }
}

/// C# `ShouldUseExternalClientAsync` parity using a scripted credential catalog.
pub fn resolve_rdp_routing(
    profile: &ConnectionProfile,
    catalog: &mut FakeRdpCredentialCatalog,
) -> RdpRoutingResolution {
    let (use_external, signal) = should_use_external_client(profile, catalog);
    RdpRoutingResolution {
        routing: decide_rdp_client_routing(use_external),
        signal,
    }
}

fn should_use_external_client(
    profile: &ConnectionProfile,
    catalog: &mut FakeRdpCredentialCatalog,
) -> (bool, Option<RdpAadSignal>) {
    if profile.rdp_use_external_client {
        return (true, Some(RdpAadSignal::OptInFlag));
    }
    if has_azure_ad_domain(profile.rdp_domain.as_deref()) {
        return (true, Some(RdpAadSignal::NodeDomain));
    }
    if has_azure_ad_prefix(profile.username.as_deref()) {
        return (true, Some(RdpAadSignal::NodeUsername));
    }

    let Some(cred_id) = profile.credential_id else {
        return (false, None);
    };

    match catalog.lookup(cred_id) {
        FakeCredentialLookup::Error => (true, Some(RdpAadSignal::CredentialLookupFailSafe)),
        FakeCredentialLookup::Missing => (false, None),
        FakeCredentialLookup::Ok(credential) => {
            if credential.protocol != ProtocolType::Rdp {
                return (false, None);
            }
            if has_azure_ad_domain(credential.domain.as_deref()) {
                (true, Some(RdpAadSignal::CredentialDomain))
            } else if has_azure_ad_prefix(credential.username.as_deref()) {
                (true, Some(RdpAadSignal::CredentialUsername))
            } else {
                (false, None)
            }
        }
    }
}

/// Outcome after AAD routing + optional external mstsc tunnel policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdpConnectRouteOutcome {
    /// Selected client path.
    pub routing: RdpClientRouting,
    /// Why external routing was chosen (`None` when embedded).
    pub signal: Option<RdpAadSignal>,
}

/// Stand-in surface — counts only; never spawns `mstsc.exe`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FakeAadRoutingSurface {
    resolve_count: usize,
    external_route_count: usize,
    embedded_route_count: usize,
    last_resolution: Option<RdpRoutingResolution>,
}

impl FakeAadRoutingSurface {
    /// Empty Fake (no resolutions yet).
    pub const fn new() -> Self {
        Self {
            resolve_count: 0,
            external_route_count: 0,
            embedded_route_count: 0,
            last_resolution: None,
        }
    }

    /// How many routing resolutions ran.
    pub fn resolve_count(&self) -> usize {
        self.resolve_count
    }

    /// External routing decisions recorded.
    pub fn external_route_count(&self) -> usize {
        self.external_route_count
    }

    /// Embedded routing decisions recorded.
    pub fn embedded_route_count(&self) -> usize {
        self.embedded_route_count
    }

    /// Last resolution from the most recent evaluation.
    pub fn last_resolution(&self) -> Option<RdpRoutingResolution> {
        self.last_resolution
    }

    pub(crate) fn record_resolution(&mut self, resolution: RdpRoutingResolution) {
        self.resolve_count += 1;
        self.last_resolution = Some(resolution);
        if resolution.routing.prefers_external_mstsc() {
            self.external_route_count += 1;
        } else {
            self.embedded_route_count += 1;
        }
    }
}

/// Fake glue: AAD routing resolution composed with [`RdpExternalMstscGlue`].
#[derive(Debug, Default)]
pub struct RdpAadExternalClientGlue {
    aad_fake: FakeAadRoutingSurface,
    external: RdpExternalMstscGlue,
}

impl RdpAadExternalClientGlue {
    /// Glue backed by in-memory Fake surfaces.
    pub fn with_fake() -> Self {
        Self::default()
    }

    /// Inspect AAD Fake counters / last resolution.
    pub fn aad_fake(&self) -> &FakeAadRoutingSurface {
        &self.aad_fake
    }

    /// Borrow composed external mstsc tunnel glue (read-only).
    pub fn external_glue(&self) -> &RdpExternalMstscGlue {
        &self.external
    }

    /// Borrow composed external mstsc tunnel glue (mutable).
    pub fn external_glue_mut(&mut self) -> &mut RdpExternalMstscGlue {
        &mut self.external
    }

    /// Resolve routing only (no tunnel policy).
    pub fn resolve_routing(
        &mut self,
        profile: &ConnectionProfile,
        catalog: &mut FakeRdpCredentialCatalog,
    ) -> RdpRoutingResolution {
        let resolution = resolve_rdp_routing(profile, catalog);
        self.aad_fake.record_resolution(resolution);
        resolution
    }

    /// C# connect guard chain: AAD routing → external mstsc tunnel policy when external.
    pub fn evaluate_connect_route(
        &mut self,
        profile: &ConnectionProfile,
        tunnel_enabled: bool,
        catalog: &mut FakeRdpCredentialCatalog,
    ) -> Result<RdpConnectRouteOutcome, ExternalMstscGlueError> {
        let resolution = self.resolve_routing(profile, catalog);
        if resolution.routing.prefers_external_mstsc() {
            self.external.evaluate_external_route(ExternalMstscPolicyInputs {
                tunnel_enabled,
                use_external_client: true,
            })?;
        }
        Ok(RdpConnectRouteOutcome {
            routing: resolution.routing,
            signal: resolution.signal,
        })
    }
}

impl fmt::Debug for FakeRdpCredentialCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeRdpCredentialCatalog")
            .field("row_count", &self.rows.len())
            .field("script_lookup_error", &self.script_lookup_error)
            .field("lookup_count", &self.lookup_count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_domain::ConnectionProfile;

    fn base_profile() -> ConnectionProfile {
        ConnectionProfile {
            protocol: ProtocolType::Rdp,
            host: "host".into(),
            port: 3389,
            ..Default::default()
        }
    }

    #[test]
    fn has_azure_ad_domain_matches_csharp_matrix() {
        assert!(has_azure_ad_domain(Some("AzureAD")));
        assert!(has_azure_ad_domain(Some("azuread")));
        assert!(has_azure_ad_domain(Some("  AzureAD  ")));
        assert!(!has_azure_ad_domain(Some("AzureADish")));
        assert!(!has_azure_ad_domain(Some("")));
        assert!(!has_azure_ad_domain(None));
    }

    #[test]
    fn has_azure_ad_prefix_matches_csharp_matrix() {
        assert!(has_azure_ad_prefix(Some("AzureAD\\alice")));
        assert!(has_azure_ad_prefix(Some("  AzureAD\\alice")));
        assert!(has_azure_ad_prefix(Some("azuread\\bob")));
        assert!(!has_azure_ad_prefix(Some("MYCORP\\alice")));
        assert!(!has_azure_ad_prefix(Some("AzureAD")));
        assert!(!has_azure_ad_prefix(Some("")));
        assert!(!has_azure_ad_prefix(None));
    }

    #[test]
    fn onmicrosoft_upn_without_prefix_is_not_azure_ad() {
        assert!(!is_azure_ad_credential(
            Some("CONTOSO"),
            Some("user@contoso.onmicrosoft.com")
        ));
    }

    #[test]
    fn opt_in_flag_always_external() {
        let profile = base_profile();
        let profile = ConnectionProfile {
            rdp_use_external_client: true,
            ..profile
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::PreferExternalMstsc);
        assert_eq!(resolution.signal, Some(RdpAadSignal::OptInFlag));
        assert_eq!(catalog.lookup_count(), 0);
    }

    #[test]
    fn node_rdp_domain_azuread_routes_external_without_credential() {
        let profile = ConnectionProfile {
            rdp_domain: Some("AzureAD".into()),
            credential_id: None,
            ..base_profile()
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::PreferExternalMstsc);
        assert_eq!(resolution.signal, Some(RdpAadSignal::NodeDomain));
        assert_eq!(catalog.lookup_count(), 0);
    }

    #[test]
    fn node_username_azuread_prefix_routes_external() {
        let profile = ConnectionProfile {
            username: Some("AzureAD\\alice@tenant.com".into()),
            credential_id: None,
            ..base_profile()
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::PreferExternalMstsc);
        assert_eq!(resolution.signal, Some(RdpAadSignal::NodeUsername));
    }

    #[test]
    fn saved_credential_azuread_domain_routes_external() {
        let cred_id = Uuid::new_v4();
        let profile = ConnectionProfile {
            credential_id: Some(cred_id),
            ..base_profile()
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        catalog.insert(cred_id, ScriptedRdpCredential::rdp(Some("AzureAD"), None));
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::PreferExternalMstsc);
        assert_eq!(resolution.signal, Some(RdpAadSignal::CredentialDomain));
        assert_eq!(catalog.lookup_count(), 1);
    }

    #[test]
    fn no_aad_signals_stays_embedded() {
        let cred_id = Uuid::new_v4();
        let profile = ConnectionProfile {
            credential_id: Some(cred_id),
            rdp_domain: Some("CORP".into()),
            username: Some("alice".into()),
            ..base_profile()
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        catalog.insert(
            cred_id,
            ScriptedRdpCredential::rdp(Some("CORP"), Some("alice")),
        );
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::EmbeddedOcx);
        assert_eq!(resolution.signal, None);
    }

    #[test]
    fn credential_lookup_error_fails_safe_to_external() {
        let cred_id = Uuid::new_v4();
        let profile = ConnectionProfile {
            credential_id: Some(cred_id),
            ..base_profile()
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        catalog.script_lookup_error();
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::PreferExternalMstsc);
        assert_eq!(
            resolution.signal,
            Some(RdpAadSignal::CredentialLookupFailSafe)
        );
    }

    #[test]
    fn unchecked_flag_with_aad_domain_override_ignored() {
        let profile = ConnectionProfile {
            rdp_use_external_client: false,
            rdp_domain: Some("AzureAD".into()),
            ..base_profile()
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::PreferExternalMstsc);
        assert_eq!(resolution.signal, Some(RdpAadSignal::NodeDomain));
    }

    #[test]
    fn non_rdp_credential_does_not_force_external() {
        let cred_id = Uuid::new_v4();
        let profile = ConnectionProfile {
            credential_id: Some(cred_id),
            ..base_profile()
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        catalog.insert(
            cred_id,
            ScriptedRdpCredential {
                domain: Some("AzureAD".into()),
                username: None,
                protocol: ProtocolType::Ssh,
            },
        );
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::EmbeddedOcx);
    }

    #[test]
    fn saved_credential_azuread_username_prefix_routes_external() {
        let cred_id = Uuid::new_v4();
        let profile = ConnectionProfile {
            credential_id: Some(cred_id),
            ..base_profile()
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        catalog.insert(
            cred_id,
            ScriptedRdpCredential::rdp(None, Some("AzureAD\\bob@tenant.com")),
        );
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::PreferExternalMstsc);
        assert_eq!(resolution.signal, Some(RdpAadSignal::CredentialUsername));
    }

    #[test]
    fn missing_credential_row_stays_embedded() {
        let cred_id = Uuid::new_v4();
        let profile = ConnectionProfile {
            credential_id: Some(cred_id),
            ..base_profile()
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::EmbeddedOcx);
        assert_eq!(catalog.lookup_count(), 1);
    }

    #[test]
    fn node_domain_short_circuits_before_catalog_lookup() {
        let cred_id = Uuid::new_v4();
        let profile = ConnectionProfile {
            rdp_domain: Some("AzureAD".into()),
            credential_id: Some(cred_id),
            ..base_profile()
        };
        let mut catalog = FakeRdpCredentialCatalog::new();
        catalog.insert(cred_id, ScriptedRdpCredential::rdp(Some("CORP"), Some("alice")));
        let resolution = resolve_rdp_routing(&profile, &mut catalog);
        assert_eq!(resolution.routing, RdpClientRouting::PreferExternalMstsc);
        assert_eq!(resolution.signal, Some(RdpAadSignal::NodeDomain));
        assert_eq!(catalog.lookup_count(), 0);
    }

    #[test]
    fn is_azure_ad_profile_checks_node_and_credential() {
        let profile = ConnectionProfile {
            rdp_domain: Some("CORP".into()),
            ..base_profile()
        };
        assert!(is_azure_ad_profile(&profile, Some("AzureAD"), None));
        let node_aad = ConnectionProfile {
            username: Some("AzureAD\\x".into()),
            ..base_profile()
        };
        assert!(is_azure_ad_profile(&node_aad, None, None));
        assert!(!is_azure_ad_profile(&profile, Some("CORP"), Some("alice")));
    }

    #[test]
    fn glue_compose_tunnel_reject_when_external_and_tunnel_on() {
        let profile = ConnectionProfile {
            rdp_domain: Some("AzureAD".into()),
            tunnel_enabled: true,
            ..base_profile()
        };
        let mut glue = RdpAadExternalClientGlue::with_fake();
        let mut catalog = FakeRdpCredentialCatalog::new();
        let err = glue
            .evaluate_connect_route(&profile, true, &mut catalog)
            .expect_err("tunnel reject");
        assert!(err.message().contains("mstsc.exe"));
        assert_eq!(glue.aad_fake().external_route_count(), 1);
        assert_eq!(glue.external_glue().fake().reject_count(), 1);
        assert_eq!(glue.external_glue().fake().launch_eligible_count(), 0);
    }

    #[test]
    fn glue_compose_allow_external_when_tunnel_off() {
        let profile = ConnectionProfile {
            rdp_domain: Some("AzureAD".into()),
            ..base_profile()
        };
        let mut glue = RdpAadExternalClientGlue::with_fake();
        let mut catalog = FakeRdpCredentialCatalog::new();
        let outcome = glue
            .evaluate_connect_route(&profile, false, &mut catalog)
            .expect("allow");
        assert_eq!(outcome.routing, RdpClientRouting::PreferExternalMstsc);
        assert_eq!(glue.external_glue().fake().launch_eligible_count(), 1);
    }

    #[test]
    fn glue_embedded_skips_external_tunnel_evaluate() {
        let profile = base_profile();
        let mut glue = RdpAadExternalClientGlue::with_fake();
        let mut catalog = FakeRdpCredentialCatalog::new();
        let outcome = glue
            .evaluate_connect_route(&profile, true, &mut catalog)
            .expect("embedded ok");
        assert_eq!(outcome.routing, RdpClientRouting::EmbeddedOcx);
        assert_eq!(glue.external_glue().fake().evaluate_count(), 0);
        assert_eq!(glue.aad_fake().embedded_route_count(), 1);
    }

    #[test]
    fn debug_catalog_omits_credential_bodies() {
        let cred_id = Uuid::new_v4();
        let mut catalog = FakeRdpCredentialCatalog::new();
        catalog.insert(
            cred_id,
            ScriptedRdpCredential::rdp(Some("AzureAD"), Some("secret-shaped-user")),
        );
        let dbg = format!("{catalog:?}");
        assert!(!dbg.to_lowercase().contains("password"));
    }
}
