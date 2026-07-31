//! Optional `russh-sftp` compile marker.
//!
//! `russh-sftp` `=2.3.0` has **no** hard dependency on `russh` and resolves cleanly
//! alongside workspace `russh =0.62.4`. Live `Channel` → SFTP client wiring is deferred
//! until `wormhole-ssh` exposes a reusable authenticated session.

/// Presence handle proving the optional `russh-sftp` feature linked.
#[derive(Debug, Clone, Copy, Default)]
pub struct RusshSftpMarker;

#[cfg(feature = "russh")]
impl RusshSftpMarker {
    pub fn crate_name(self) -> &'static str {
        "russh-sftp"
    }

    pub fn linked(self) -> bool {
        // Touch the dependency so `--features russh` fails loudly if the pin breaks.
        let _ = std::any::type_name::<russh_sftp::client::SftpSession>();
        true
    }
}

#[cfg(feature = "russh")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russh_sftp_feature_links() {
        assert!(RusshSftpMarker.linked());
        assert_eq!(RusshSftpMarker.crate_name(), "russh-sftp");
    }
}
