//! Gates 1–2 GPUI lab window.
//!
//! Gate 1: custom client-area title bar, light/dark toggle, DPI helpers, Mica via
//! [`gpui::WindowBackgroundAppearance::MicaBackdrop`] (Win32 `DwmSetWindowAttribute` /
//! `DWMWA_SYSTEMBACKDROP_TYPE` inside `gpui_windows`).
//!
//! Gate 2: 2×2 resizable split panes with drag splitters; optional tab DnD stub.
//!
//! NOTE: Keep this file as the gates 1–2 host. Gate 8 lives in `a11y.rs`.

use gpui::{
    App, Bounds, Context, CursorStyle, IntoElement, MouseButton, MouseMoveEvent, ParentElement,
    Pixels, Point, SharedString, StatefulInteractiveElement, Styled, TitlebarOptions, Window,
    WindowAppearance, WindowBackgroundAppearance, WindowBounds, WindowControlArea, WindowOptions,
    div, point, prelude::*, px, rgb, rgba, size,
};
use wormhole_surface_win::PhysicalBounds;

const TITLE_BAR_HEIGHT: f32 = 36.0;
/// Fixed status strip under the title bar — must match `content_bounds` chrome inset.
const STATUS_BAR_HEIGHT: f32 = 22.0;
const SPLITTER_THICKNESS: f32 = 6.0;
const SPLIT_MIN: f32 = 0.15;
const SPLIT_MAX: f32 = 0.85;

/// Theme preference for the lab chrome (independent of macOS-only `App::set_window_appearance`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThemePref {
    /// Follow [`Window::appearance`] / system.
    System,
    Light,
    Dark,
}

impl ThemePref {
    fn cycle(self) -> Self {
        match self {
            Self::System => Self::Light,
            Self::Light => Self::Dark,
            Self::Dark => Self::System,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::System => "Theme: System",
            Self::Light => "Theme: Light",
            Self::Dark => "Theme: Dark",
        }
    }

    fn resolves_dark(self, system: WindowAppearance) -> bool {
        match self {
            Self::System => matches!(
                system,
                WindowAppearance::Dark | WindowAppearance::VibrantDark
            ),
            Self::Light => false,
            Self::Dark => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SplitterAxis {
    Horizontal,
    Vertical,
}

struct LabPalette {
    window_bg: gpui::Rgba,
    title_bg: gpui::Rgba,
    pane_bg: [gpui::Rgba; 4],
    text: gpui::Rgba,
    muted: gpui::Rgba,
    border: gpui::Rgba,
    splitter: gpui::Rgba,
    button_bg: gpui::Rgba,
}

impl LabPalette {
    fn for_dark(dark: bool) -> Self {
        if dark {
            Self {
                window_bg: rgba(0x1e1e1ecc),
                title_bg: rgba(0x2d2d2de6),
                pane_bg: [
                    rgba(0x252526e6),
                    rgba(0x2a2a2ce6),
                    rgba(0x2e2e30e6),
                    rgba(0x323234e6),
                ],
                text: rgb(0xe0e0e0),
                muted: rgb(0xa0a0a0),
                border: rgb(0x3e3e42),
                splitter: rgb(0x007acc),
                button_bg: rgb(0x3c3c3c),
            }
        } else {
            Self {
                window_bg: rgba(0xf3f3f3cc),
                title_bg: rgba(0xffffffe6),
                pane_bg: [
                    rgba(0xf8f8f8e6),
                    rgba(0xf0f0f0e6),
                    rgba(0xe8e8e8e6),
                    rgba(0xe0e0e0e6),
                ],
                text: rgb(0x1e1e1e),
                muted: rgb(0x606060),
                border: rgb(0xc8c8c8),
                splitter: rgb(0x0078d4),
                button_bg: rgb(0xe5e5e5),
            }
        }
    }
}

/// Sanitize a window scale factor before DPI / physical conversion.
///
/// Non-finite or non-positive values fall back to 1.0 (96 DPI).
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

/// True when `order` is a permutation of `{0,1,2,3}` (4-pane identity invariant).
pub fn pane_order_is_permutation(order: &[u8; 4]) -> bool {
    let mut seen = [false; 4];
    for &id in order {
        let Some(slot) = seen.get_mut(id as usize) else {
            return false;
        };
        if *slot {
            return false;
        }
        *slot = true;
    }
    seen.iter().all(|&v| v)
}

/// Split a total axis length into (near, far) segments around a centered gap.
pub fn split_axis_sizes(total: f32, ratio: f32, gap: f32) -> (f32, f32) {
    let ratio = clamp_split_ratio(ratio);
    let near = (total * ratio - gap / 2.).max(0.);
    let far = (total * (1. - ratio) - gap / 2.).max(0.);
    (near, far)
}

/// Convert a GPUI logical bounds + scale factor into broker [`PhysicalBounds`].
pub fn logical_bounds_to_physical(bounds: Bounds<Pixels>, scale_factor: f32) -> PhysicalBounds {
    let scale = sanitize_scale_factor(scale_factor);
    let device = bounds.to_device_pixels(scale);
    PhysicalBounds {
        x: i32::from(device.origin.x),
        y: i32::from(device.origin.y),
        width: i32::from(device.size.width).max(0) as u32,
        height: i32::from(device.size.height).max(0) as u32,
        dpi: scale_factor_to_dpi(scale),
    }
}

fn scale_factor_to_dpi(scale_factor: f32) -> u32 {
    let scale = sanitize_scale_factor(scale_factor);
    (96.0 * scale).round().max(1.0) as u32
}

/// Hardware checklist for gate-checklist.md (do **not** auto-pass).
pub const DPI_HARDWARE_CHECKLIST: &str = "\
DPI hardware checklist (gate 1 — manual, gate-checklist.md):\n\
  [ ] 100% (96 DPI): title bar + 2x2 panes layout; splitter drag; theme toggle\n\
  [ ] 150% (144 DPI): same; PhysicalBounds dpi field reports ~144\n\
  [ ] 200% (192 DPI): same; no clipped caption buttons / splitters\n\
  [ ] light + dark (system + in-app toggle) at each scale\n\
  [ ] Win11: Mica visible through translucent chrome (Win10: backdrop API no-op / opaque)\n";

struct LabRoot {
    title: SharedString,
    theme: ThemePref,
    h_split: f32,
    v_split: f32,
    dragging: Option<SplitterAxis>,
    pane_order: [u8; 4],
    pane_bounds: [Option<PhysicalBounds>; 4],
}

impl LabRoot {
    fn new() -> Self {
        Self {
            title: "Wormhole surface-lab".into(),
            theme: ThemePref::System,
            h_split: 0.5,
            v_split: 0.5,
            dragging: None,
            pane_order: [0, 1, 2, 3],
            pane_bounds: [None; 4],
        }
    }

    fn effective_dark(&self, window: &Window) -> bool {
        self.theme.resolves_dark(window.appearance())
    }

    fn apply_splitter_drag(
        &mut self,
        axis: SplitterAxis,
        event: &MouseMoveEvent,
        content: Bounds<Pixels>,
    ) {
        match axis {
            SplitterAxis::Horizontal => {
                let width = f32::from(content.size.width);
                if !width.is_finite() || width <= 0.0 {
                    return;
                }
                let local = f32::from(event.position.x - content.origin.x);
                self.h_split = clamp_split_ratio(local / width);
            }
            SplitterAxis::Vertical => {
                let height = f32::from(content.size.height);
                if !height.is_finite() || height <= 0.0 {
                    return;
                }
                let local = f32::from(event.position.y - content.origin.y);
                self.v_split = clamp_split_ratio(local / height);
            }
        }
    }

    fn swap_panes(&mut self, a: usize, b: usize) {
        if a < 4 && b < 4 && a != b {
            self.pane_order.swap(a, b);
            debug_assert!(
                pane_order_is_permutation(&self.pane_order),
                "pane_order must remain a permutation of 0..4"
            );
        }
    }

    fn content_bounds(window: &Window) -> Bounds<Pixels> {
        let viewport = window.viewport_size();
        let top = px(TITLE_BAR_HEIGHT + STATUS_BAR_HEIGHT);
        Bounds {
            origin: point(px(0.), top),
            size: size(viewport.width, (viewport.height - top).max(px(0.))),
        }
    }

    fn compute_pane_logical(
        content: Bounds<Pixels>,
        slot: usize,
        h: f32,
        v: f32,
    ) -> Bounds<Pixels> {
        let gap = px(SPLITTER_THICKNESS);
        let (left_w, right_w) =
            split_axis_sizes(f32::from(content.size.width), h, SPLITTER_THICKNESS);
        let (top_h, bottom_h) =
            split_axis_sizes(f32::from(content.size.height), v, SPLITTER_THICKNESS);
        let h = clamp_split_ratio(h);
        let v = clamp_split_ratio(v);
        let mid_x = content.origin.x + content.size.width * h + gap / 2.;
        let mid_y = content.origin.y + content.size.height * v + gap / 2.;

        match slot {
            0 => Bounds {
                origin: content.origin,
                size: size(px(left_w), px(top_h)),
            },
            1 => Bounds {
                origin: point(mid_x, content.origin.y),
                size: size(px(right_w), px(top_h)),
            },
            2 => Bounds {
                origin: point(content.origin.x, mid_y),
                size: size(px(left_w), px(bottom_h)),
            },
            _ => Bounds {
                origin: point(mid_x, mid_y),
                size: size(px(right_w), px(bottom_h)),
            },
        }
    }

    fn refresh_pane_bounds(&mut self, window: &Window) {
        let scale = window.scale_factor();
        let content = Self::content_bounds(window);
        for slot in 0..4 {
            let logical = Self::compute_pane_logical(content, slot, self.h_split, self.v_split);
            self.pane_bounds[slot] = Some(logical_bounds_to_physical(logical, scale));
        }
    }

    fn title_bar(&self, palette: &LabPalette, cx: &mut Context<Self>) -> impl IntoElement {
        let theme_label = self.theme.label();
        div()
            .id("lab-titlebar")
            .h(px(TITLE_BAR_HEIGHT))
            .w_full()
            .flex()
            .flex_row()
            .items_center()
            .px_3()
            .gap_2()
            .bg(palette.title_bg)
            .border_b_1()
            .border_color(palette.border)
            .window_control_area(WindowControlArea::Drag)
            .child(
                div()
                    .flex_1()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(palette.text)
                    .child(self.title.clone()),
            )
            .child(chrome_button(
                "theme-toggle",
                theme_label,
                palette,
                cx.listener(|this, _, window, cx| {
                    this.theme = this.theme.cycle();
                    window.set_background_appearance(WindowBackgroundAppearance::MicaBackdrop);
                    cx.notify();
                }),
            ))
            .child(chrome_button(
                "dpi-log",
                "Log DPI",
                palette,
                cx.listener(|this, _, window, cx| {
                    this.refresh_pane_bounds(window);
                    let dpi = scale_factor_to_dpi(window.scale_factor());
                    eprintln!(
                        "[gate1] scale_factor={:.3} dpi≈{dpi} viewport={:?} panes={:?}",
                        window.scale_factor(),
                        window.viewport_size(),
                        this.pane_bounds
                    );
                    eprintln!("{DPI_HARDWARE_CHECKLIST}");
                    cx.notify();
                }),
            ))
            .child(caption_button(
                "min",
                "—",
                WindowControlArea::Min,
                palette,
                |window, _| window.minimize_window(),
            ))
            .child(caption_button(
                "max",
                "□",
                WindowControlArea::Max,
                palette,
                |window, _| window.zoom_window(),
            ))
            .child(caption_button(
                "close",
                "×",
                WindowControlArea::Close,
                palette,
                |window, _| window.remove_window(),
            ))
    }

    fn pane_tile(
        &self,
        slot: usize,
        palette: &LabPalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let pane_id = self.pane_order[slot] as usize;
        let label = format!("Pane {}", pane_id + 1);
        let bounds_txt = self.pane_bounds[slot]
            .map(|b| {
                format!(
                    "phys {}×{} @{},{}, dpi={}",
                    b.width, b.height, b.x, b.y, b.dpi
                )
            })
            .unwrap_or_else(|| "phys (pending layout)".into());
        let bg = palette.pane_bg[pane_id % 4];

        #[derive(Clone)]
        struct PaneDrag {
            from_slot: usize,
            pane_id: u8,
        }

        div()
            .id(("pane", slot))
            .size_full()
            .min_w(px(40.))
            .min_h(px(40.))
            .flex()
            .flex_col()
            .p_3()
            .gap_1()
            .bg(bg)
            .border_1()
            .border_color(palette.border)
            .text_color(palette.text)
            .child(
                div()
                    .id(("pane-tab", slot))
                    .flex()
                    .items_center()
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .bg(palette.button_bg)
                    .text_sm()
                    .cursor(CursorStyle::ClosedHand)
                    .child(format!("{label} (drag stub)"))
                    .on_drag(
                        PaneDrag {
                            from_slot: slot,
                            pane_id: self.pane_order[slot],
                        },
                        |drag, position, _, cx| {
                            cx.new(|_| DragGhost {
                                pane_id: drag.pane_id,
                                position,
                            })
                        },
                    ),
            )
            .child(div().text_xs().text_color(palette.muted).child(bounds_txt))
            .child(
                div()
                    .text_xs()
                    .text_color(palette.muted)
                    .child("Drop another pane tab here to swap (stub)"),
            )
            .on_drop(cx.listener(move |this, drag: &PaneDrag, _, cx| {
                this.swap_panes(drag.from_slot, slot);
                cx.notify();
            }))
    }

    fn splitter(
        &self,
        axis: SplitterAxis,
        id_tag: u32,
        palette: &LabPalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let (id, cursor) = match axis {
            SplitterAxis::Horizontal => (("split-h", id_tag), CursorStyle::ResizeLeftRight),
            SplitterAxis::Vertical => (("split-v", id_tag), CursorStyle::ResizeUpDown),
        };
        let active = self.dragging == Some(axis);
        let base = match axis {
            SplitterAxis::Horizontal => div().w(px(SPLITTER_THICKNESS)).h_full(),
            SplitterAxis::Vertical => div().h(px(SPLITTER_THICKNESS)).w_full(),
        };

        base.id(id)
            .flex_none()
            .cursor(cursor)
            .bg(if active {
                palette.splitter
            } else {
                palette.border
            })
            .hover(|s| s.bg(palette.splitter))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    this.dragging = Some(axis);
                    cx.notify();
                }),
            )
    }

    fn panes_body(
        &self,
        palette: &LabPalette,
        content: Bounds<Pixels>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let (left_w, right_w) =
            split_axis_sizes(f32::from(content.size.width), self.h_split, SPLITTER_THICKNESS);
        let (top_h, bottom_h) =
            split_axis_sizes(f32::from(content.size.height), self.v_split, SPLITTER_THICKNESS);

        div()
            .id("lab-panes")
            .flex_1()
            .w_full()
            .flex()
            .flex_col()
            .child(
                div()
                    .h(px(top_h))
                    .w_full()
                    .flex()
                    .flex_row()
                    .flex_none()
                    .child(
                        div()
                            .w(px(left_w))
                            .h_full()
                            .flex_none()
                            .child(self.pane_tile(0, palette, cx)),
                    )
                    .child(self.splitter(SplitterAxis::Horizontal, 0, palette, cx))
                    .child(
                        div()
                            .w(px(right_w))
                            .h_full()
                            .flex_none()
                            .child(self.pane_tile(1, palette, cx)),
                    ),
            )
            .child(self.splitter(SplitterAxis::Vertical, 0, palette, cx))
            .child(
                div()
                    .h(px(bottom_h))
                    .w_full()
                    .flex()
                    .flex_row()
                    .flex_none()
                    .child(
                        div()
                            .w(px(left_w))
                            .h_full()
                            .flex_none()
                            .child(self.pane_tile(2, palette, cx)),
                    )
                    .child(self.splitter(SplitterAxis::Horizontal, 1, palette, cx))
                    .child(
                        div()
                            .w(px(right_w))
                            .h_full()
                            .flex_none()
                            .child(self.pane_tile(3, palette, cx)),
                    ),
            )
    }
}

struct DragGhost {
    pane_id: u8,
    position: Point<Pixels>,
}

impl Render for DragGhost {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .absolute()
            .left(self.position.x)
            .top(self.position.y)
            .px_2()
            .py_1()
            .rounded_sm()
            .bg(rgba(0x007acccc))
            .text_color(rgb(0xffffff))
            .text_xs()
            .child(format!("Pane {}", self.pane_id as usize + 1))
    }
}

fn chrome_button(
    id: &'static str,
    label: impl Into<SharedString>,
    palette: &LabPalette,
    on_click: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id)
        .px_2()
        .py_1()
        .rounded_sm()
        .bg(palette.button_bg)
        .text_xs()
        .text_color(palette.text)
        .cursor_pointer()
        .occlude()
        .hover(|s| s.opacity(0.85))
        .child(label.into())
        .on_click(on_click)
}

fn caption_button(
    id: &'static str,
    glyph: &'static str,
    area: WindowControlArea,
    palette: &LabPalette,
    on_click: impl Fn(&mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id)
        .w(px(40.))
        .h_full()
        .flex()
        .items_center()
        .justify_center()
        .text_sm()
        .text_color(palette.text)
        .window_control_area(area)
        .occlude()
        .hover(|s| s.bg(palette.button_bg))
        .cursor_pointer()
        .child(glyph)
        .on_click(move |_, window, cx| on_click(window, cx))
}

impl Render for LabRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.refresh_pane_bounds(window);
        let dark = self.effective_dark(window);
        let palette = LabPalette::for_dark(dark);
        let content = Self::content_bounds(window);
        let dpi = scale_factor_to_dpi(window.scale_factor());
        let status = format!(
            "gate1+2 · scale {:.2} (dpi≈{dpi}) · h={:.0}% v={:.0}% · {}",
            window.scale_factor(),
            self.h_split * 100.0,
            self.v_split * 100.0,
            if dark { "dark" } else { "light" }
        );

        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(palette.window_bg)
            .text_color(palette.text)
            .on_mouse_move(cx.listener(|this, event: &MouseMoveEvent, window, cx| {
                if let Some(axis) = this.dragging {
                    if event.dragging() {
                        // Recompute from the live window — do not reuse render-time bounds.
                        let content = LabRoot::content_bounds(window);
                        this.apply_splitter_drag(axis, event, content);
                        this.refresh_pane_bounds(window);
                        cx.notify();
                    } else {
                        this.dragging = None;
                        cx.notify();
                    }
                }
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    if this.dragging.take().is_some() {
                        cx.notify();
                    }
                }),
            )
            .child(self.title_bar(&palette, cx))
            .child(
                div()
                    .id("lab-status")
                    .w_full()
                    .h(px(STATUS_BAR_HEIGHT))
                    .px_3()
                    .flex()
                    .items_center()
                    .text_xs()
                    .text_color(palette.muted)
                    .bg(palette.title_bg)
                    .child(status),
            )
            .child(self.panes_body(&palette, content, cx))
    }
}

/// Boot the gate 1–2 GPUI window. Blocks on the UI event loop.
pub fn try_boot() -> Result<&'static str, &'static str> {
    eprintln!("[gpui] surface-lab gates 1–2");
    eprintln!(
        "[gpui] Mica: WindowBackgroundAppearance::MicaBackdrop → \
         DwmSetWindowAttribute(DWMWA_SYSTEMBACKDROP_TYPE, DWMSBT_MAINWINDOW) via gpui_windows"
    );
    eprintln!("[gpui] {DPI_HARDWARE_CHECKLIST}");

    // Zed pin: standalone apps use `gpui_platform::application()`, not `Application::new()`.
    gpui_platform::application().run(|cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(1100.), px(720.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("Wormhole surface-lab".into()),
                    appears_transparent: true,
                    traffic_light_position: None,
                }),
                window_background: WindowBackgroundAppearance::MicaBackdrop,
                window_min_size: Some(size(px(640.), px(480.))),
                ..Default::default()
            },
            |window, cx| {
                window.set_background_appearance(WindowBackgroundAppearance::MicaBackdrop);
                let entity = cx.new(|_cx| LabRoot::new());
                entity.update(cx, |root, cx| {
                    root.refresh_pane_bounds(window);
                    cx.observe_window_appearance(window, |this, window, cx| {
                        if this.theme == ThemePref::System {
                            this.refresh_pane_bounds(window);
                            cx.notify();
                        }
                    })
                    .detach();
                });
                entity
            },
        )
        .expect("open surface-lab window");
        cx.activate(true);
    });
    Ok("GPUI event loop exited")
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::{Bounds, point, px, size};

    #[test]
    fn logical_to_physical_at_100_150_200_percent() {
        let logical = Bounds {
            origin: point(px(10.), px(20.)),
            size: size(px(100.), px(50.)),
        };

        let at_100 = logical_bounds_to_physical(logical, 1.0);
        assert_eq!(at_100.dpi, 96);
        assert_eq!((at_100.x, at_100.y, at_100.width, at_100.height), (10, 20, 100, 50));

        let at_150 = logical_bounds_to_physical(logical, 1.5);
        assert_eq!(at_150.dpi, 144);
        assert_eq!((at_150.x, at_150.y, at_150.width, at_150.height), (15, 30, 150, 75));

        let at_200 = logical_bounds_to_physical(logical, 2.0);
        assert_eq!(at_200.dpi, 192);
        assert_eq!((at_200.x, at_200.y, at_200.width, at_200.height), (20, 40, 200, 100));
    }

    #[test]
    fn logical_to_physical_degenerate_and_bad_scale() {
        let empty = Bounds {
            origin: point(px(0.), px(0.)),
            size: size(px(0.), px(40.)),
        };
        let phys = logical_bounds_to_physical(empty, 1.5);
        assert!(phys.is_degenerate());
        assert_eq!(phys.width, 0);
        assert_eq!(phys.height, 60);
        assert_eq!(phys.dpi, 144);

        let fallback = logical_bounds_to_physical(
            Bounds {
                origin: point(px(1.), px(2.)),
                size: size(px(3.), px(4.)),
            },
            f32::NAN,
        );
        assert_eq!(fallback.dpi, 96);
        assert_eq!((fallback.x, fallback.y, fallback.width, fallback.height), (1, 2, 3, 4));

        assert_eq!(sanitize_scale_factor(0.0), 1.0);
        assert_eq!(sanitize_scale_factor(-2.0), 1.0);
        assert_eq!(sanitize_scale_factor(f32::INFINITY), 1.0);
        assert_eq!(scale_factor_to_dpi(1.0), 96);
        assert_eq!(scale_factor_to_dpi(f32::NAN), 96);
    }

    #[test]
    fn theme_cycle_and_resolve() {
        assert_eq!(ThemePref::System.cycle(), ThemePref::Light);
        assert_eq!(ThemePref::Light.cycle(), ThemePref::Dark);
        assert_eq!(ThemePref::Dark.cycle(), ThemePref::System);

        assert!(ThemePref::Dark.resolves_dark(WindowAppearance::Light));
        assert!(!ThemePref::Light.resolves_dark(WindowAppearance::Dark));
        assert!(ThemePref::System.resolves_dark(WindowAppearance::Dark));
        assert!(ThemePref::System.resolves_dark(WindowAppearance::VibrantDark));
        assert!(!ThemePref::System.resolves_dark(WindowAppearance::Light));
        assert!(!ThemePref::System.resolves_dark(WindowAppearance::VibrantLight));
    }

    #[test]
    fn split_ratio_clamps_and_rejects_non_finite() {
        assert_eq!(clamp_split_ratio(0.0), SPLIT_MIN);
        assert_eq!(clamp_split_ratio(1.0), SPLIT_MAX);
        assert_eq!(clamp_split_ratio(0.5), 0.5);
        assert_eq!(clamp_split_ratio(f32::NAN), 0.5);
        assert_eq!(clamp_split_ratio(f32::INFINITY), 0.5);
        assert_eq!(clamp_split_ratio(f32::NEG_INFINITY), 0.5);
    }

    #[test]
    fn apply_splitter_drag_ignores_degenerate_content() {
        let mut root = LabRoot::new();
        let event = MouseMoveEvent {
            position: point(px(999.), px(999.)),
            pressed_button: Some(MouseButton::Left),
            ..Default::default()
        };
        let empty = Bounds {
            origin: point(px(0.), px(0.)),
            size: size(px(0.), px(0.)),
        };
        root.apply_splitter_drag(SplitterAxis::Horizontal, &event, empty);
        root.apply_splitter_drag(SplitterAxis::Vertical, &event, empty);
        assert_eq!(root.h_split, 0.5);
        assert_eq!(root.v_split, 0.5);
    }

    #[test]
    fn apply_splitter_drag_clamps_to_min_max() {
        let mut root = LabRoot::new();
        let content = Bounds {
            origin: point(px(10.), px(20.)),
            size: size(px(200.), px(100.)),
        };
        let far_left = MouseMoveEvent {
            position: point(px(0.), px(50.)),
            pressed_button: Some(MouseButton::Left),
            ..Default::default()
        };
        root.apply_splitter_drag(SplitterAxis::Horizontal, &far_left, content);
        assert_eq!(root.h_split, SPLIT_MIN);

        let far_right = MouseMoveEvent {
            position: point(px(400.), px(50.)),
            pressed_button: Some(MouseButton::Left),
            ..Default::default()
        };
        root.apply_splitter_drag(SplitterAxis::Horizontal, &far_right, content);
        assert_eq!(root.h_split, SPLIT_MAX);

        let far_top = MouseMoveEvent {
            position: point(px(100.), px(0.)),
            pressed_button: Some(MouseButton::Left),
            ..Default::default()
        };
        root.apply_splitter_drag(SplitterAxis::Vertical, &far_top, content);
        assert_eq!(root.v_split, SPLIT_MIN);
    }

    #[test]
    fn compute_pane_logical_four_slots_and_clamps_ratios() {
        let content = Bounds {
            origin: point(px(0.), px(0.)),
            size: size(px(400.), px(200.)),
        };
        let tl = LabRoot::compute_pane_logical(content, 0, 0.5, 0.5);
        let tr = LabRoot::compute_pane_logical(content, 1, 0.5, 0.5);
        let bl = LabRoot::compute_pane_logical(content, 2, 0.5, 0.5);
        let br = LabRoot::compute_pane_logical(content, 3, 0.5, 0.5);

        assert!(f32::from(tl.size.width) > 0.0 && f32::from(tl.size.height) > 0.0);
        assert!(f32::from(tr.size.width) > 0.0 && f32::from(tr.size.height) > 0.0);
        assert!(f32::from(bl.size.width) > 0.0 && f32::from(bl.size.height) > 0.0);
        assert!(f32::from(br.size.width) > 0.0 && f32::from(br.size.height) > 0.0);
        assert!(f32::from(tr.origin.x) > f32::from(tl.origin.x));
        assert!(f32::from(bl.origin.y) > f32::from(tl.origin.y));

        // Out-of-range / NaN ratios must not explode layout.
        let poisoned = LabRoot::compute_pane_logical(content, 0, f32::NAN, 99.0);
        assert!(f32::from(poisoned.size.width).is_finite());
        assert!(f32::from(poisoned.size.height).is_finite());
        assert!(f32::from(poisoned.size.width) > 0.0);
    }

    #[test]
    fn visual_split_sizes_match_compute_pane_logical() {
        let content = Bounds {
            origin: point(px(0.), px(0.)),
            size: size(px(400.), px(200.)),
        };
        let h = 0.05; // below SPLIT_MIN → clamped
        let v = 0.75;
        let (left_w, right_w) = split_axis_sizes(400.0, h, SPLITTER_THICKNESS);
        let (top_h, bottom_h) = split_axis_sizes(200.0, v, SPLITTER_THICKNESS);
        assert_eq!(left_w, split_axis_sizes(400.0, SPLIT_MIN, SPLITTER_THICKNESS).0);

        let tl = LabRoot::compute_pane_logical(content, 0, h, v);
        let tr = LabRoot::compute_pane_logical(content, 1, h, v);
        let bl = LabRoot::compute_pane_logical(content, 2, h, v);
        let br = LabRoot::compute_pane_logical(content, 3, h, v);
        assert_eq!(f32::from(tl.size.width), left_w);
        assert_eq!(f32::from(tl.size.height), top_h);
        assert_eq!(f32::from(tr.size.width), right_w);
        assert_eq!(f32::from(tr.size.height), top_h);
        assert_eq!(f32::from(bl.size.width), left_w);
        assert_eq!(f32::from(bl.size.height), bottom_h);
        assert_eq!(f32::from(br.size.width), right_w);
        assert_eq!(f32::from(br.size.height), bottom_h);

        // Unclamped mid split keeps near+far+gap ≈ total.
        let (l, r) = split_axis_sizes(400.0, 0.5, SPLITTER_THICKNESS);
        assert!((l + r + SPLITTER_THICKNESS - 400.0).abs() < 0.01);
    }

    #[test]
    fn content_chrome_inset_matches_status_bar_constant() {
        assert_eq!(TITLE_BAR_HEIGHT + STATUS_BAR_HEIGHT, 58.0);
        // Splitter drag / PhysicalBounds use this inset; keep the status strip fixed-height.
        assert!(STATUS_BAR_HEIGHT > 0.0);
    }

    #[test]
    fn swap_panes_preserves_four_pane_permutation() {
        let mut root = LabRoot::new();
        assert!(pane_order_is_permutation(&root.pane_order));
        root.swap_panes(0, 3);
        assert_eq!(root.pane_order, [3, 1, 2, 0]);
        assert!(pane_order_is_permutation(&root.pane_order));

        // Same slot / OOB are no-ops.
        root.swap_panes(1, 1);
        root.swap_panes(0, 99);
        root.swap_panes(99, 0);
        assert_eq!(root.pane_order, [3, 1, 2, 0]);
        assert!(pane_order_is_permutation(&root.pane_order));

        assert!(!pane_order_is_permutation(&[0, 0, 1, 2]));
        assert!(!pane_order_is_permutation(&[0, 1, 2, 4]));
    }
}
