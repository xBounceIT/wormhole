//! Cisco Secure Client (AnyConnect) provider + aggregate-auth typing stub +
//! establish-path glue.
//!
//! Sidecar establish (`wormhole-ciscoproxy`) is unchanged. Aggregate-auth
//! group / second-factor types live in [`aggregate_auth`] — no HTTPS login,
//! STF framing, or CSTP tunnel in this crate. **SAML SSO**, client
//! certificates, and **CSD / HostScan** are unsupported (v1).
//!
//! Establish glue ([`establish_cisco`] / [`establish_cisco_from_auth`]) loads
//! TunnelConfigs metadata (+ secret or auth stub) then calls
//! [`TunnelProvider::establish`](crate::TunnelProvider::establish) — separate
//! from WireGuard / OpenVPN / Fortinet glue. Unit tests use
//! [`crate::FakeTunnelProvider`] (no live ASA / local Cisco client).

pub mod aggregate_auth;
mod establish;
mod provider;

pub use aggregate_auth::{
    answer_aggregate_auth_form, is_second_factor_field_name, prepare_cisco_sidecar_config,
    reject_unsupported_cisco_auth, AggregateAuthAnswer, AggregateAuthFieldType,
    AggregateAuthFormKind, AggregateAuthInput, CiscoAuthError, CiscoAuthOptions,
    CiscoSecondFactor, CiscoSecureClientSidecarConfig, CiscoUnsupportedAuth,
    DEFAULT_CISCO_PORT,
};
pub use establish::{
    establish_cisco, establish_cisco_from_auth, reject_cisco_unsupported_auth,
    FAKE_CISCO_SIDECAR_JSON,
};
pub use provider::CiscoSecureClientProvider;
