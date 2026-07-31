//! Feature-gated GPUI chrome for the Wormhole shell.
//!
//! Boot with [`try_boot_shell`] (see `examples/wormhole-ui-lab.rs`). Patterns follow
//! `surface-lab` gates 1–2: `gpui_platform::application()`, custom title bar,
//! `WindowBackgroundAppearance::MicaBackdrop`.

mod chrome;
mod dpi;

pub use chrome::{try_boot_shell, try_boot_shell_with_sink, LogicalRect, ShellChrome};
pub use dpi::{
    clamp_split_ratio, logical_bounds_to_physical, sanitize_scale_factor, scale_factor_to_dpi,
    split_axis_sizes,
};

/// Linked when `--features gpui` is on — composition root can hold an `Arc` of this.
#[derive(Debug, Clone, Copy, Default)]
pub struct GpuiShellMarker;

impl GpuiShellMarker {
    pub fn gpui_linked() -> bool {
        let _ = std::any::type_name::<gpui::App>();
        true
    }
}

// Touch re-exports so `cargo check` does not warn when no other crate imports them yet.
const _: fn() = || {
    let _ = clamp_split_ratio as fn(f32) -> f32;
    let _ = sanitize_scale_factor as fn(f32) -> f32;
    let _ = scale_factor_to_dpi as fn(f32) -> u32;
    let _ = split_axis_sizes as fn(f32, f32, f32) -> (f32, f32);
    let _ = logical_bounds_to_physical as fn(f32, f32, f32, f32, f32) -> crate::PanePhysicalBounds;
};
