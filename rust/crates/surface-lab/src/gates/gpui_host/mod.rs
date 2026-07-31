//! Optional GPUI boot hooks (`--features gpui`).
//!
//! - [`try_boot`] — gates 1–2 (`lab.rs`: custom title bar, theme, Mica, 2×2 panes).
//! - [`try_boot_a11y`] — gate 8 AccessKit / keyboard Tab spike (`a11y.rs`).

mod a11y;
mod lab;

pub use a11y::try_boot_a11y;
pub use lab::try_boot;

/// DPI / physical-bounds helpers from the gate 1–2 lab path.
#[doc(inline)]
pub use lab::{
    clamp_split_ratio, logical_bounds_to_physical, pane_order_is_permutation, sanitize_scale_factor,
    split_axis_sizes, DPI_HARDWARE_CHECKLIST,
};

// Touch re-exports so `cargo check` does not warn when no other crate imports them yet.
const _: fn() = || {
    let _ = DPI_HARDWARE_CHECKLIST;
    let _ = logical_bounds_to_physical as fn(gpui::Bounds<gpui::Pixels>, f32) -> wormhole_surface_win::PhysicalBounds;
    let _ = sanitize_scale_factor as fn(f32) -> f32;
    let _ = clamp_split_ratio as fn(f32) -> f32;
    let _ = split_axis_sizes as fn(f32, f32, f32) -> (f32, f32);
    let _ = pane_order_is_permutation as fn(&[u8; 4]) -> bool;
};
