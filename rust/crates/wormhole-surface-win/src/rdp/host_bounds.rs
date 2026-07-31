//! Screen-physical bounds for the owned RDP overlay (mirrors C# `HostBounds`).

/// Window-screen physical-pixel rectangle for the owned RDP overlay.
///
/// Coordinates are **screen** physical pixels (not relative to the owner client).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostBounds {
    /// Left edge in screen physical pixels.
    pub x: i32,
    /// Top edge in screen physical pixels.
    pub y: i32,
    /// Width in physical pixels.
    pub width: i32,
    /// Height in physical pixels.
    pub height: i32,
}

impl HostBounds {
    /// Empty / unset bounds `(0,0,0,0)`.
    pub const EMPTY: Self = Self {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    };

    /// 1×1 activation seed used before real layout arrives.
    pub const SEED: Self = Self {
        x: 0,
        y: 0,
        width: 1,
        height: 1,
    };

    /// Create bounds from screen physical pixels.
    pub const fn new(x: i32, y: i32, width: i32, height: i32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// True when width or height is below `min_dim` (C# default layout skip is 8).
    pub fn is_degenerate(self, min_dim: i32) -> bool {
        self.width < min_dim || self.height < min_dim
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_and_empty() {
        assert!(HostBounds::EMPTY.is_degenerate(1));
        assert!(!HostBounds::SEED.is_degenerate(1));
        assert!(HostBounds::SEED.is_degenerate(8));
    }

    #[test]
    fn degenerate_edges() {
        assert!(HostBounds::new(0, 0, 7, 100).is_degenerate(8));
        assert!(HostBounds::new(0, 0, 100, 7).is_degenerate(8));
        assert!(!HostBounds::new(0, 0, 8, 8).is_degenerate(8));
        assert!(HostBounds::new(0, 0, -1, 100).is_degenerate(1));
        assert!(HostBounds::new(0, 0, 100, 0).is_degenerate(1));
        assert!(!HostBounds::new(-10, -20, 64, 48).is_degenerate(8));
    }
}
