//! DPI / logical→physical helpers shared by chrome layout.

use crate::layout_sink::PanePhysicalBounds;

const SPLIT_MIN: f32 = 0.15;
const SPLIT_MAX: f32 = 0.85;

/// Sanitize a window scale factor before DPI / physical conversion.
pub fn sanitize_scale_factor(scale_factor: f32) -> f32 {
    if scale_factor.is_finite() && scale_factor > 0.0 {
        scale_factor
    } else {
        1.0
    }
}

/// Clamp a pane split ratio into the live drag range (rejects NaN/Inf → 0.5).
pub fn clamp_split_ratio(ratio: f32) -> f32 {
    if ratio.is_finite() {
        ratio.clamp(SPLIT_MIN, SPLIT_MAX)
    } else {
        0.5
    }
}

/// Split a total axis length into (near, far) segments around a centered gap.
pub fn split_axis_sizes(total: f32, ratio: f32, gap: f32) -> (f32, f32) {
    let ratio = clamp_split_ratio(ratio);
    let near = (total * ratio - gap / 2.).max(0.);
    let far = (total * (1. - ratio) - gap / 2.).max(0.);
    (near, far)
}

/// Convert scale factor to approximate Windows DPI.
pub fn scale_factor_to_dpi(scale_factor: f32) -> u32 {
    let scale = sanitize_scale_factor(scale_factor);
    (96.0 * scale).round().max(1.0) as u32
}

/// Convert GPUI logical bounds + scale into [`PanePhysicalBounds`].
pub fn logical_bounds_to_physical(
    origin_x: f32,
    origin_y: f32,
    width: f32,
    height: f32,
    scale_factor: f32,
) -> PanePhysicalBounds {
    let scale = sanitize_scale_factor(scale_factor);
    let dpi = scale_factor_to_dpi(scale);
    PanePhysicalBounds {
        x: (origin_x * scale).round() as i32,
        y: (origin_y * scale).round() as i32,
        width: (width * scale).round().max(0.0) as u32,
        height: (height * scale).round().max(0.0) as u32,
        dpi,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_to_physical_scales() {
        let at_100 = logical_bounds_to_physical(10., 20., 100., 50., 1.0);
        assert_eq!(at_100.dpi, 96);
        assert_eq!((at_100.x, at_100.y, at_100.width, at_100.height), (10, 20, 100, 50));

        let at_150 = logical_bounds_to_physical(10., 20., 100., 50., 1.5);
        assert_eq!(at_150.dpi, 144);
        assert_eq!((at_150.x, at_150.y, at_150.width, at_150.height), (15, 30, 150, 75));

        let bad = logical_bounds_to_physical(1., 2., 3., 4., f32::NAN);
        assert_eq!(bad.dpi, 96);
        assert_eq!((bad.x, bad.y, bad.width, bad.height), (1, 2, 3, 4));
    }

    #[test]
    fn split_ratio_clamps() {
        assert_eq!(clamp_split_ratio(0.0), SPLIT_MIN);
        assert_eq!(clamp_split_ratio(1.0), SPLIT_MAX);
        assert_eq!(clamp_split_ratio(f32::NAN), 0.5);
        let (l, r) = split_axis_sizes(400.0, 0.5, 6.0);
        assert!((l + r + 6.0 - 400.0).abs() < 0.01);
    }
}
