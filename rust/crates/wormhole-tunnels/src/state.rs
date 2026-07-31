//! Mirrors `Wormhole.Models.TunnelState`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelState {
    Idle,
    Establishing,
    Up,
    Failed,
    Closed,
}
