//! Shell chrome: title/quick-connect strip, sidebar, tab strip, ≤4 panes.
//!
//! Layout (plan ASCII):
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │ Wormhole          Quick Connect (stub)         [—][□][×] │
//! ├────────────┬─────────────────────────────────────────────┤
//! │ Connections│ [tab] [tab*] …                              │
//! │ Credentials├─────────────────────────────────────────────┤
//! │ Sessions   │  pane slots (1..=4 from ShellState)         │
//! │ Tunnels    │                                             │
//! │ Settings   │                                             │
//! └────────────┴─────────────────────────────────────────────┘
//! ```

use std::sync::{Arc, Mutex};

use gpui::{
    div, prelude::*, px, rgb, size, App, Bounds, Context, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled, TitlebarOptions, Window, WindowBackgroundAppearance,
    WindowBounds, WindowControlArea, WindowOptions,
};

use crate::layout_sink::{NopPaneLayoutSink, PaneLayoutSink, PaneLayoutUpdate};
use crate::shell::{ShellState, SidebarRegion};
use crate::theme::ThemeTokens;
use crate::workspace::{PaneId, WorkspaceState, MAX_PANES};

use super::dpi::{
    clamp_split_ratio, logical_bounds_to_physical, sanitize_scale_factor, scale_factor_to_dpi,
    split_axis_sizes,
};

/// Stable ElementId key for a session tab (index-based ids collide after close/reorder).
pub(crate) fn tab_element_key(tab_id: uuid::Uuid) -> SharedString {
    SharedString::from(format!("tab-{tab_id}"))
}

/// Stable ElementId key for a workspace pane tile.
pub(crate) fn pane_element_key(pane: PaneId) -> (&'static str, u32) {
    ("pane", pane.0 as u32)
}

const TITLE_BAR_HEIGHT: f32 = 40.0;
const TAB_STRIP_HEIGHT: f32 = 32.0;
const STATUS_BAR_HEIGHT: f32 = 20.0;
const SIDEBAR_WIDTH: f32 = 180.0;
const SPLITTER_THICKNESS: f32 = 4.0;

struct ChromePalette {
    window_bg: u32,
    title_bg: u32,
    sidebar_bg: u32,
    pane_bg: u32,
    pane_focused_border: u32,
    text: u32,
    muted: u32,
    border: u32,
    accent: u32,
    button_bg: u32,
}

impl ChromePalette {
    fn from_theme(theme: ThemeTokens) -> Self {
        Self {
            window_bg: theme.terminal_bg,
            title_bg: 0x16_16_16,
            sidebar_bg: 0x12_12_12,
            pane_bg: theme.terminal_bg,
            pane_focused_border: theme.link,
            text: theme.foreground,
            muted: 0xA0_A0_A0,
            border: 0x2A_2A_2A,
            accent: theme.link,
            button_bg: 0x2A_2A_2A,
        }
    }
}

/// GPUI entity owning [`ShellState`] and optional layout sink.
pub struct ShellChrome {
    shell: ShellState,
    layout_sink: Arc<Mutex<dyn PaneLayoutSink>>,
    last_pane_bounds: Vec<PaneLayoutUpdate>,
    /// Horizontal split ratio for 2/4-pane layouts.
    h_split: f32,
    /// Vertical split ratio for 3/4-pane layouts.
    v_split: f32,
    quick_connect_stub: SharedString,
}

impl ShellChrome {
    pub fn new(shell: ShellState, layout_sink: Arc<Mutex<dyn PaneLayoutSink>>) -> Self {
        Self {
            shell,
            layout_sink,
            last_pane_bounds: Vec::new(),
            h_split: 0.5,
            v_split: 0.5,
            quick_connect_stub: "Quick Connect (stub)".into(),
        }
    }

    pub fn shell(&self) -> &ShellState {
        &self.shell
    }

    pub fn last_pane_bounds(&self) -> &[PaneLayoutUpdate] {
        &self.last_pane_bounds
    }

    /// UI action: split workspace. Returns `true` when a pane was added (≤ [`MAX_PANES`]).
    pub fn action_split_pane(&mut self) -> bool {
        self.shell.split_pane().is_ok()
    }

    /// UI action: close the focused pane (no-op when it is the last pane).
    pub fn action_close_focused_pane(&mut self) -> bool {
        let id = self.shell.workspace.focused();
        self.shell.close_pane(id).is_ok()
    }

    /// UI action: open a demo tab and assign it to the focused pane.
    pub fn action_open_demo_tab(&mut self) -> uuid::Uuid {
        let n = self.shell.tabs.len() + 1;
        let tab = self.shell.tabs.open(format!("Session {n}"));
        let pane = self.shell.workspace.focused();
        let _ = self.shell.assign_tab_pane(tab, pane);
        tab
    }

    /// Drive layout → [`PaneLayoutSink`] without a live window (unit tests / headless).
    pub fn apply_layout(&mut self, content: LogicalRect, scale_factor: f32) {
        let updates = compute_pane_updates(
            &self.shell.workspace,
            content,
            self.h_split,
            self.v_split,
            scale_factor,
        );
        self.notify_layout_sink(updates);
    }

    fn workspace_origin_offset() -> (f32, f32) {
        (SIDEBAR_WIDTH, TITLE_BAR_HEIGHT + TAB_STRIP_HEIGHT)
    }

    fn notify_layout_sink(&mut self, updates: Vec<PaneLayoutUpdate>) {
        // Skip identical ticks so a future NativeSurfaceBroker is not spammed every frame.
        if self.last_pane_bounds == updates {
            return;
        }
        self.last_pane_bounds = updates;
        if let Ok(mut sink) = self.layout_sink.lock() {
            sink.on_pane_layout(&self.last_pane_bounds);
        }
    }

    fn refresh_pane_bounds(&mut self, window: &Window) {
        let scale = window.scale_factor();
        let viewport = window.viewport_size();
        let (ox, oy) = Self::workspace_origin_offset();
        let work_w = (f32::from(viewport.width) - SIDEBAR_WIDTH).max(0.0);
        let work_h = (f32::from(viewport.height)
            - TITLE_BAR_HEIGHT
            - TAB_STRIP_HEIGHT
            - STATUS_BAR_HEIGHT)
            .max(0.0);
        let content = LogicalRect {
            x: ox,
            y: oy,
            w: work_w,
            h: work_h,
        };
        self.apply_layout(content, scale);
    }

    fn title_quick_connect_strip(&self, palette: &ChromePalette) -> impl IntoElement {
        div()
            .id("shell-titlebar")
            .h(px(TITLE_BAR_HEIGHT))
            .w_full()
            .flex()
            .flex_row()
            .items_center()
            .px_3()
            .gap_3()
            .bg(rgb(palette.title_bg))
            .border_b_1()
            .border_color(rgb(palette.border))
            .window_control_area(WindowControlArea::Drag)
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(rgb(palette.text))
                    .child("Wormhole"),
            )
            .child(
                div()
                    .flex_1()
                    .flex()
                    .justify_center()
                    .child(
                        div()
                            .id("quick-connect-stub")
                            .px_3()
                            .py_1()
                            .rounded_sm()
                            .bg(rgb(palette.button_bg))
                            .text_xs()
                            .text_color(rgb(palette.muted))
                            .occlude()
                            .child(self.quick_connect_stub.clone()),
                    ),
            )
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

    fn sidebar(&self, palette: &ChromePalette, cx: &mut Context<Self>) -> impl IntoElement {
        let selected = self.shell.sidebar;
        let mut items = div()
            .id("shell-sidebar")
            .w(px(SIDEBAR_WIDTH))
            .h_full()
            .flex()
            .flex_col()
            .gap_1()
            .p_2()
            .bg(rgb(palette.sidebar_bg))
            .border_r_1()
            .border_color(rgb(palette.border));

        for region in SidebarRegion::ALL {
            let active = region == selected;
            let label = region.as_str();
            items = items.child(
                div()
                    .id(("sidebar-item", region as u32))
                    .w_full()
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(if active {
                        rgb(palette.button_bg)
                    } else {
                        rgb(palette.sidebar_bg)
                    })
                    .text_sm()
                    .text_color(if active {
                        rgb(palette.accent)
                    } else {
                        rgb(palette.text)
                    })
                    .hover(|s| s.opacity(0.9))
                    .child(label)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.shell.select_sidebar(region);
                        cx.notify();
                    })),
            );
        }

        items.child(
            div()
                .flex_1()
                .min_h(px(8.))
                .child(
                    div()
                        .mt_2()
                        .text_xs()
                        .text_color(rgb(palette.muted))
                        .child(format!("Region: {}", selected.as_str())),
                ),
        )
    }

    fn tab_strip(&self, palette: &ChromePalette, cx: &mut Context<Self>) -> impl IntoElement {
        let active = self.shell.tabs.active_id();
        let mut row = div()
            .id("shell-tabs")
            .h(px(TAB_STRIP_HEIGHT))
            .w_full()
            .flex()
            .flex_row()
            .items_center()
            .gap_1()
            .px_2()
            .bg(rgb(palette.title_bg))
            .border_b_1()
            .border_color(rgb(palette.border));

        for tab in self.shell.tabs.tabs().iter() {
            let id = tab.id;
            let is_active = active == Some(id);
            let title = tab.title.clone();
            row = row.child(
                div()
                    .id(tab_element_key(id))
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(if is_active {
                        rgb(palette.button_bg)
                    } else {
                        rgb(palette.title_bg)
                    })
                    .text_xs()
                    .text_color(if is_active {
                        rgb(palette.text)
                    } else {
                        rgb(palette.muted)
                    })
                    .child(title)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let _ = this.shell.tabs.activate(id);
                        cx.notify();
                    })),
            );
        }

        row.child(self.toolbar_button("tab-open-demo", "+", palette, cx, |this, window, cx| {
            this.action_open_demo_tab();
            this.refresh_pane_bounds(window);
            cx.notify();
        }))
        .child(self.toolbar_button("pane-split-demo", "Split", palette, cx, |this, window, cx| {
            this.action_split_pane();
            this.refresh_pane_bounds(window);
            cx.notify();
        }))
        .child(self.toolbar_button(
            "pane-close-demo",
            "Close pane",
            palette,
            cx,
            |this, window, cx| {
                this.action_close_focused_pane();
                this.refresh_pane_bounds(window);
                cx.notify();
            },
        ))
    }

    fn toolbar_button(
        &self,
        id: &'static str,
        label: &'static str,
        palette: &ChromePalette,
        cx: &mut Context<Self>,
        on_click: impl Fn(&mut Self, &mut Window, &mut Context<Self>) + 'static,
    ) -> impl IntoElement {
        div()
            .id(id)
            .px_2()
            .py_1()
            .rounded_sm()
            .bg(rgb(palette.button_bg))
            .text_xs()
            .text_color(rgb(palette.muted))
            .cursor_pointer()
            .child(label)
            .on_click(cx.listener(move |this, _, window, cx| on_click(this, window, cx)))
    }

    fn workspace_panes(
        &self,
        palette: &ChromePalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let panes = self.shell.workspace.panes();
        let focused = self.shell.workspace.focused();
        let count = panes.len().min(MAX_PANES);

        let body = div()
            .id("shell-workspace")
            .flex_1()
            .w_full()
            .h_full()
            .bg(rgb(palette.window_bg));

        match count {
            0 => body.child(
                div()
                    .id("workspace-empty")
                    .size_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_xs()
                    .text_color(rgb(palette.muted))
                    .child("No panes"),
            ),
            1 => {
                let pane = panes[0];
                body.child(self.pane_tile(pane, focused, palette, cx))
            }
            2 => {
                let left = panes[0];
                let right = panes[1];
                body.flex().flex_row().child(self.horizontal_pane_pair(
                    left, right, focused, palette, cx,
                ))
            }
            3 => {
                let a = panes[0];
                let b = panes[1];
                let c = panes[2];
                body.flex().flex_col().child(
                    div()
                        .flex()
                        .flex_col()
                        .size_full()
                        .child(
                            div()
                                .w_full()
                                .flex_1()
                                .child(self.horizontal_pane_pair(a, b, focused, palette, cx)),
                        )
                        .child(div().h(px(SPLITTER_THICKNESS)).w_full().bg(rgb(palette.border)))
                        .child(
                            div()
                                .w_full()
                                .flex_1()
                                .child(self.pane_tile(c, focused, palette, cx)),
                        ),
                )
            }
            _ => {
                // Quad — only real open panes (never invent ids).
                let slots = [panes[0], panes[1], panes[2], panes[3]];
                body.flex().flex_col().child(
                    div()
                        .flex()
                        .flex_col()
                        .size_full()
                        .child(
                            div().w_full().flex_1().child(self.horizontal_pane_pair(
                                slots[0], slots[1], focused, palette, cx,
                            )),
                        )
                        .child(div().h(px(SPLITTER_THICKNESS)).w_full().bg(rgb(palette.border)))
                        .child(
                            div().w_full().flex_1().child(self.horizontal_pane_pair(
                                slots[2], slots[3], focused, palette, cx,
                            )),
                        ),
                )
            }
        }
    }

    fn horizontal_pane_pair(
        &self,
        left: PaneId,
        right: PaneId,
        focused: PaneId,
        palette: &ChromePalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .flex()
            .flex_row()
            .size_full()
            .child(
                div()
                    .h_full()
                    .flex_1()
                    .child(self.pane_tile(left, focused, palette, cx)),
            )
            .child(div().w(px(SPLITTER_THICKNESS)).h_full().bg(rgb(palette.border)))
            .child(
                div()
                    .h_full()
                    .flex_1()
                    .child(self.pane_tile(right, focused, palette, cx)),
            )
    }

    fn pane_tile(
        &self,
        pane: PaneId,
        focused: PaneId,
        palette: &ChromePalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let is_focused = pane == focused;
        let bounds_txt = self
            .last_pane_bounds
            .iter()
            .find(|u| u.pane == pane)
            .map(|u| {
                format!(
                    "phys {}×{} @{},{} dpi={}",
                    u.bounds.width, u.bounds.height, u.bounds.x, u.bounds.y, u.bounds.dpi
                )
            })
            .unwrap_or_else(|| "phys (pending)".into());

        let tab_title = self
            .shell
            .tabs
            .tabs()
            .iter()
            .find(|t| t.pane == Some(pane))
            .map(|t| t.title.as_str())
            .unwrap_or("(empty)");

        div()
            .id(pane_element_key(pane))
            .size_full()
            .min_w(px(40.))
            .min_h(px(40.))
            .flex()
            .flex_col()
            .p_2()
            .gap_1()
            .bg(rgb(palette.pane_bg))
            .border_1()
            .border_color(rgb(if is_focused {
                palette.pane_focused_border
            } else {
                palette.border
            }))
            .text_color(rgb(palette.text))
            .cursor_pointer()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::MEDIUM)
                    .child(format!("Pane {}", pane.0)),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(palette.muted))
                    .child(tab_title.to_string()),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(palette.muted))
                    .child(bounds_txt),
            )
            .on_click(cx.listener(move |this, _, window, cx| {
                let _ = this.shell.workspace.focus(pane);
                this.refresh_pane_bounds(window);
                cx.notify();
            }))
    }
}

impl Render for ShellChrome {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.refresh_pane_bounds(window);
        let palette = ChromePalette::from_theme(self.shell.theme);
        let dpi = scale_factor_to_dpi(window.scale_factor());
        let status = format!(
            "wormhole-ui · panes {} · layout {:?} · scale {:.2} (dpi≈{dpi})",
            self.shell.workspace.pane_count(),
            self.shell.workspace.arrangement(),
            window.scale_factor(),
        );

        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(palette.window_bg))
            .text_color(rgb(palette.text))
            .child(self.title_quick_connect_strip(&palette))
            .child(
                div()
                    .id("shell-body")
                    .flex_1()
                    .w_full()
                    .flex()
                    .flex_row()
                    .child(self.sidebar(&palette, cx))
                    .child(
                        div()
                            .flex_1()
                            .h_full()
                            .flex()
                            .flex_col()
                            .child(self.tab_strip(&palette, cx))
                            .child(self.workspace_panes(&palette, cx))
                            .child(
                                div()
                                    .id("shell-status")
                                    .w_full()
                                    .h(px(STATUS_BAR_HEIGHT))
                                    .px_2()
                                    .flex()
                                    .items_center()
                                    .text_xs()
                                    .text_color(rgb(palette.muted))
                                    .bg(rgb(palette.title_bg))
                                    .border_t_1()
                                    .border_color(rgb(palette.border))
                                    .child(status),
                            ),
                    ),
            )
    }
}

fn caption_button(
    id: &'static str,
    glyph: &'static str,
    area: WindowControlArea,
    palette: &ChromePalette,
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
        .text_color(rgb(palette.text))
        .window_control_area(area)
        .occlude()
        .hover(|s| s.bg(rgb(palette.button_bg)))
        .cursor_pointer()
        .child(glyph)
        .on_click(move |_, window, cx| on_click(window, cx))
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LogicalRect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

fn sanitize_extent(v: f32) -> f32 {
    if v.is_finite() && v >= 0.0 {
        v
    } else {
        0.0
    }
}

fn sanitize_origin(v: f32) -> f32 {
    if v.is_finite() {
        v
    } else {
        0.0
    }
}

/// Compute physical pane updates from workspace state + content rect.
pub(crate) fn compute_pane_updates(
    workspace: &WorkspaceState,
    content: LogicalRect,
    h_split: f32,
    v_split: f32,
    scale_factor: f32,
) -> Vec<PaneLayoutUpdate> {
    let content = LogicalRect {
        x: sanitize_origin(content.x),
        y: sanitize_origin(content.y),
        w: sanitize_extent(content.w),
        h: sanitize_extent(content.h),
    };
    let panes = workspace.panes();
    let h = clamp_split_ratio(h_split);
    let v = clamp_split_ratio(v_split);
    let gap = SPLITTER_THICKNESS;
    let scale = sanitize_scale_factor(scale_factor);

    let rects: Vec<(PaneId, LogicalRect)> = match panes.len() {
        0 => Vec::new(),
        1 => vec![(panes[0], content)],
        2 => {
            let (lw, rw) = split_axis_sizes(content.w, h, gap);
            vec![
                (
                    panes[0],
                    LogicalRect {
                        x: content.x,
                        y: content.y,
                        w: lw,
                        h: content.h,
                    },
                ),
                (
                    panes[1],
                    LogicalRect {
                        x: content.x + lw + gap,
                        y: content.y,
                        w: rw,
                        h: content.h,
                    },
                ),
            ]
        }
        3 => {
            let (lw, rw) = split_axis_sizes(content.w, h, gap);
            let (th, bh) = split_axis_sizes(content.h, v, gap);
            vec![
                (
                    panes[0],
                    LogicalRect {
                        x: content.x,
                        y: content.y,
                        w: lw,
                        h: th,
                    },
                ),
                (
                    panes[1],
                    LogicalRect {
                        x: content.x + lw + gap,
                        y: content.y,
                        w: rw,
                        h: th,
                    },
                ),
                (
                    panes[2],
                    LogicalRect {
                        x: content.x,
                        y: content.y + th + gap,
                        w: content.w,
                        h: bh,
                    },
                ),
            ]
        }
        _ => {
            // Cap at MAX_PANES — only emit updates for real open panes (never invent ids).
            debug_assert!(panes.len() >= 4 && panes.len() <= MAX_PANES);
            let (lw, rw) = split_axis_sizes(content.w, h, gap);
            let (th, bh) = split_axis_sizes(content.h, v, gap);
            let slots = [panes[0], panes[1], panes[2], panes[3]];
            vec![
                (
                    slots[0],
                    LogicalRect {
                        x: content.x,
                        y: content.y,
                        w: lw,
                        h: th,
                    },
                ),
                (
                    slots[1],
                    LogicalRect {
                        x: content.x + lw + gap,
                        y: content.y,
                        w: rw,
                        h: th,
                    },
                ),
                (
                    slots[2],
                    LogicalRect {
                        x: content.x,
                        y: content.y + th + gap,
                        w: lw,
                        h: bh,
                    },
                ),
                (
                    slots[3],
                    LogicalRect {
                        x: content.x + lw + gap,
                        y: content.y + th + gap,
                        w: rw,
                        h: bh,
                    },
                ),
            ]
        }
    };

    rects
        .into_iter()
        .map(|(pane, r)| PaneLayoutUpdate {
            pane,
            bounds: logical_bounds_to_physical(r.x, r.y, r.w, r.h, scale),
        })
        .collect()
}

/// Boot shell chrome with a no-op layout sink. Blocks on the UI event loop.
pub fn try_boot_shell() -> Result<&'static str, &'static str> {
    let sink: Arc<Mutex<dyn PaneLayoutSink>> = Arc::new(Mutex::new(NopPaneLayoutSink));
    try_boot_shell_with_sink(sink)
}

/// Boot shell chrome, forwarding pane bounds to `layout_sink`.
pub fn try_boot_shell_with_sink(
    layout_sink: Arc<Mutex<dyn PaneLayoutSink>>,
) -> Result<&'static str, &'static str> {
    eprintln!("[wormhole-ui] GPUI shell chrome (feature gpui)");
    eprintln!(
        "[wormhole-ui] layout ASCII: title/quick-connect | sidebar | tabs | panes≤4 → PaneLayoutSink"
    );

    let mut shell = ShellState::new();
    let _ = shell.tabs.open("Welcome");
    let _ = shell.assign_tab_pane(shell.tabs.active_id().unwrap(), PaneId(0));

    gpui_platform::application().run(move |cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(1200.), px(760.)), cx);
        let sink = layout_sink.clone();
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("Wormhole UI".into()),
                    appears_transparent: true,
                    traffic_light_position: None,
                }),
                window_background: WindowBackgroundAppearance::MicaBackdrop,
                window_min_size: Some(size(px(800.), px(520.))),
                ..Default::default()
            },
            move |window, cx| {
                window.set_background_appearance(WindowBackgroundAppearance::MicaBackdrop);
                let entity = cx.new(|_cx| ShellChrome::new(shell.clone(), sink.clone()));
                entity.update(cx, |root, cx| {
                    root.refresh_pane_bounds(window);
                    cx.observe_window_appearance(window, |this, window, cx| {
                        this.refresh_pane_bounds(window);
                        cx.notify();
                    })
                    .detach();
                });
                entity
            },
        )
        .expect("open wormhole-ui shell window");
        cx.activate(true);
    });
    Ok("GPUI shell event loop exited")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout_sink::RecordingPaneLayoutSink;
    use crate::theme::THEME;
    use crate::pane_layout::PaneArrangement;
    use std::collections::HashSet;

    fn lab_content() -> LogicalRect {
        LogicalRect {
            x: 180.,
            y: 72.,
            w: 400.,
            h: 200.,
        }
    }

    #[test]
    fn compute_updates_single_and_quad() {
        let ws = WorkspaceState::single_pane();
        let content = lab_content();
        let one = compute_pane_updates(&ws, content, 0.5, 0.5, 1.0);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].pane, PaneId(0));
        assert_eq!(one[0].bounds.width, 400);
        assert_eq!(one[0].bounds.height, 200);
        assert_eq!(one[0].bounds.x, 180);
        assert_eq!(one[0].bounds.y, 72);

        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        ws.split().unwrap();
        ws.split().unwrap();
        assert_eq!(ws.arrangement(), PaneArrangement::Quad);
        let four = compute_pane_updates(&ws, content, 0.5, 0.5, 1.0);
        assert_eq!(four.len(), 4);
        assert!(four.iter().all(|u| !u.bounds.is_degenerate()));
        let ids: HashSet<_> = four.iter().map(|u| u.pane).collect();
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn compute_empty_workspace_is_empty_no_panic() {
        let ws = WorkspaceState::empty();
        let updates = compute_pane_updates(&ws, lab_content(), 0.5, 0.5, 1.0);
        assert!(updates.is_empty());
    }

    #[test]
    fn compute_two_and_three_pane_layouts() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        let two = compute_pane_updates(&ws, lab_content(), 0.5, 0.5, 1.0);
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].pane, PaneId(0));
        assert_eq!(two[1].pane, PaneId(1));
        assert!(two.iter().all(|u| !u.bounds.is_degenerate()));

        ws.split().unwrap();
        let three = compute_pane_updates(&ws, lab_content(), 0.5, 0.5, 1.0);
        assert_eq!(three.len(), 3);
        let ids: HashSet<_> = three.iter().map(|u| u.pane).collect();
        assert_eq!(ids.len(), 3);
        assert!(three.iter().all(|u| !u.bounds.is_degenerate()));
    }

    #[test]
    fn compute_zero_content_emits_degenerate_not_panic() {
        let ws = WorkspaceState::single_pane();
        let updates = compute_pane_updates(
            &ws,
            LogicalRect {
                x: 10.,
                y: 10.,
                w: 0.,
                h: 0.,
            },
            0.5,
            0.5,
            1.0,
        );
        assert_eq!(updates.len(), 1);
        assert!(updates[0].bounds.is_degenerate());
    }

    #[test]
    fn apply_layout_sanitizes_nan_extents() {
        let sink = Arc::new(Mutex::new(RecordingPaneLayoutSink::default()));
        let mut chrome = ShellChrome::new(ShellState::new(), sink.clone());
        chrome.apply_layout(
            LogicalRect {
                x: f32::NAN,
                y: f32::NEG_INFINITY,
                w: -10.,
                h: f32::NAN,
            },
            f32::NAN,
        );
        let tick = sink.lock().unwrap().ticks.last().unwrap().clone();
        assert_eq!(tick.len(), 1);
        assert_eq!(tick[0].pane, PaneId(0));
        assert!(tick[0].bounds.is_degenerate());
        assert_eq!(tick[0].bounds.dpi, 96);
    }

    #[test]
    fn ui_actions_respect_pane_limit_and_coordinate_tabs() {
        let sink = Arc::new(Mutex::new(RecordingPaneLayoutSink::default()));
        let mut chrome = ShellChrome::new(ShellState::new(), sink.clone());

        assert!(chrome.action_split_pane());
        assert!(chrome.action_split_pane());
        assert!(chrome.action_split_pane());
        assert_eq!(chrome.shell().workspace.pane_count(), MAX_PANES);
        assert!(!chrome.action_split_pane());
        assert_eq!(chrome.shell().workspace.pane_count(), MAX_PANES);

        let focused = chrome.shell().workspace.focused();
        let tab = chrome.action_open_demo_tab();
        assert_eq!(
            chrome.shell().tabs.tabs().iter().find(|t| t.id == tab).unwrap().pane,
            Some(focused)
        );

        chrome.apply_layout(lab_content(), 1.0);
        let ticks_before_close = sink.lock().unwrap().ticks.len();
        assert!(ticks_before_close >= 1);
        let last = sink.lock().unwrap().ticks.last().unwrap().clone();
        assert_eq!(last.len(), MAX_PANES);
        assert!(last.iter().all(|u| u.bounds.width > 0 && u.bounds.height > 0));
        assert!(last.iter().all(|u| chrome.shell().workspace.contains(u.pane)));

        assert!(chrome.action_close_focused_pane());
        assert_eq!(chrome.shell().workspace.pane_count(), 3);
        assert_eq!(
            chrome.shell().tabs.tabs().iter().find(|t| t.id == tab).unwrap().pane,
            None
        );

        chrome.apply_layout(lab_content(), 1.0);
        let after = sink.lock().unwrap().ticks.last().unwrap().clone();
        assert_eq!(after.len(), 3);
        assert!(!after.iter().any(|u| u.pane == focused));

        // Identical layout tick must not spam the sink.
        let n = sink.lock().unwrap().ticks.len();
        chrome.apply_layout(lab_content(), 1.0);
        assert_eq!(sink.lock().unwrap().ticks.len(), n);

        while chrome.action_close_focused_pane() {}
        assert_eq!(chrome.shell().workspace.pane_count(), 1);
        assert!(!chrome.action_close_focused_pane());
    }

    #[test]
    fn element_keys_unique_for_tabs_and_panes() {
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        assert_ne!(tab_element_key(a).as_ref(), tab_element_key(b).as_ref());
        assert!(tab_element_key(a).as_ref().contains(&a.to_string()));

        let keys: HashSet<_> = (0..MAX_PANES as u8)
            .map(|i| pane_element_key(PaneId(i)))
            .collect();
        assert_eq!(keys.len(), MAX_PANES);
    }

    #[test]
    fn palette_tracks_theme_plan_tokens() {
        let palette = ChromePalette::from_theme(THEME);
        assert_eq!(palette.window_bg, THEME.terminal_bg);
        assert_eq!(palette.pane_bg, THEME.terminal_bg);
        assert_eq!(palette.text, THEME.foreground);
        assert_eq!(palette.accent, THEME.link);
        assert_eq!(palette.pane_focused_border, THEME.link);
    }

    #[test]
    fn gpui_marker_reports_linked() {
        assert!(crate::GpuiShellMarker::gpui_linked());
    }
}
