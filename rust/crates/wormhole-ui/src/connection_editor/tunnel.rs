//! Tunnel tri-state UI values (`TunnelPickerViewModel` concepts).

use uuid::Uuid;

/// Single-picker selection encoding inherit / off / concrete config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelUiSelection {
    /// `TunnelEnabled = null`, no config id — walk parent folders.
    Inherit,
    /// Explicit override off.
    NoTunnel,
    /// Explicitly on with a concrete `TunnelConfigId`.
    Config(Uuid),
    /// Force-on without a bound config id (rare; no picker sentinel in C#).
    EnabledNoConfig,
}

/// Backing fields for the tunnel picker (atomic pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelUiState {
    /// Whether "(Inherit from folder)" is offered (false for Quick Connect).
    pub allow_inheritance: bool,
    /// Tri-state: `None` inherit, `Some(false)` off, `Some(true)` on.
    pub enabled: Option<bool>,
    pub config_id: Option<Uuid>,
}

impl Default for TunnelUiState {
    fn default() -> Self {
        Self {
            allow_inheritance: true,
            enabled: None,
            config_id: None,
        }
    }
}

impl TunnelUiState {
    pub fn selection(&self) -> TunnelUiSelection {
        if self.enabled == Some(false) {
            return TunnelUiSelection::NoTunnel;
        }
        if let Some(id) = self.config_id {
            return TunnelUiSelection::Config(id);
        }
        if self.enabled.is_none() {
            return TunnelUiSelection::Inherit;
        }
        TunnelUiSelection::EnabledNoConfig
    }

    /// Atomic two-field write from a picker selection.
    pub fn set_selection(&mut self, selection: TunnelUiSelection) {
        match selection {
            TunnelUiSelection::Inherit => {
                self.enabled = if self.allow_inheritance {
                    None
                } else {
                    Some(false)
                };
                self.config_id = None;
            }
            TunnelUiSelection::NoTunnel => {
                self.enabled = Some(false);
                self.config_id = None;
            }
            TunnelUiSelection::Config(id) => {
                self.enabled = Some(true);
                self.config_id = Some(id);
            }
            TunnelUiSelection::EnabledNoConfig => {
                self.enabled = Some(true);
                self.config_id = None;
            }
        }
    }

    pub fn load_from_node(
        &mut self,
        tunnel_enabled: Option<bool>,
        tunnel_config_id: Option<Uuid>,
    ) {
        self.enabled = if self.allow_inheritance {
            tunnel_enabled
        } else if tunnel_enabled == Some(false) {
            Some(false)
        } else if tunnel_enabled == Some(true) || tunnel_config_id.is_some() {
            Some(true)
        } else {
            Some(false)
        };
        self.config_id = if tunnel_enabled == Some(false) {
            None
        } else {
            tunnel_config_id
        };
    }

    /// Values to persist on a connection node (non-serial).
    ///
    /// Explicit off (`Some(false)`) clears any vestigial config id (same as
    /// [`Self::load_from_node`] / NoTunnel selection). Inherit (`None`) may still
    /// carry an override config id — that is a deliberate domain shape.
    pub fn to_node_fields(&self) -> (Option<bool>, Option<Uuid>) {
        let enabled = if self.allow_inheritance {
            self.enabled
        } else {
            Some(self.enabled.unwrap_or(false))
        };
        let config_id = if enabled == Some(false) {
            None
        } else {
            self.config_id
        };
        (enabled, config_id)
    }
}
