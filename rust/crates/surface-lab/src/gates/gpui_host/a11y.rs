//! Gate 8 AccessKit / keyboard navigation spike for GPUI chrome.
//!
//! HWND overlays (WebView2 / RDP) are **outside** this AccessKit tree — see
//! `docs/migration/08-focus-a11y.md`.

use gpui::{
    actions, div, prelude::*, px, rgb, size, text, AccessibleAction, App, Bounds, Context,
    FocusHandle, KeyBinding, Role, SharedString, Window, WindowBounds, WindowOptions,
};

actions!(surface_lab_a11y, [Tab, TabPrev]);

/// Gate 8 AccessKit spike: Application role, tab stops, Tab / Shift-Tab.
///
/// Blocks on the UI event loop. Enable via `SURFACE_LAB_A11Y=1` or `--gate08-a11y`.
pub fn try_boot_a11y() -> Result<&'static str, &'static str> {
    gpui_platform::application().run(|cx: &mut App| {
        cx.bind_keys([
            KeyBinding::new("tab", Tab, None),
            KeyBinding::new("shift-tab", TabPrev, None),
        ]);

        let bounds = Bounds::centered(None, size(px(560.), px(420.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(gpui::TitlebarOptions {
                    title: Some("Wormhole surface-lab a11y".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |window, cx| cx.new(|cx| A11yLab::new(window, cx)),
        )
        .expect("open a11y lab window");

        cx.activate(true);
    });
    Ok("GPUI AccessKit a11y event loop exited")
}

struct A11yLab {
    focus_handle: FocusHandle,
    count: i32,
}

impl A11yLab {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus_handle = cx.focus_handle();
        window.focus(&focus_handle, cx);
        Self {
            focus_handle,
            count: 0,
        }
    }
}

impl Render for A11yLab {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("a11y-root")
            .role(Role::Application)
            .aria_label("Wormhole surface-lab accessibility spike")
            .track_focus(&self.focus_handle)
            .on_action(cx.listener(|_, _: &Tab, window, cx| window.focus_next(cx)))
            .on_action(cx.listener(|_, _: &TabPrev, window, cx| window.focus_prev(cx)))
            .size_full()
            .flex()
            .flex_col()
            .gap_4()
            .p_4()
            .bg(rgb(0x1e1e1e))
            .text_color(rgb(0xe0e0e0))
            .child(
                div()
                    .id("heading")
                    .role(Role::Heading)
                    .aria_level(1)
                    .aria_label("Focus and accessibility")
                    .child(text!("Focus and accessibility")),
            )
            .child(
                div()
                    .id("counter")
                    .focusable()
                    .tab_stop(true)
                    .role(Role::SpinButton)
                    .aria_label(SharedString::from(format!("Counter: {}", self.count)))
                    .aria_numeric_value(self.count as f64)
                    .aria_min_numeric_value(0.0)
                    .on_a11y_action(AccessibleAction::Increment, {
                        let this = cx.entity().downgrade();
                        move |_, _, cx| {
                            this.update(cx, |this, cx| {
                                this.count += 1;
                                cx.notify();
                            })
                            .ok();
                        }
                    })
                    .on_a11y_action(AccessibleAction::Decrement, {
                        let this = cx.entity().downgrade();
                        move |_, _, cx| {
                            this.update(cx, |this, cx| {
                                this.count = (this.count - 1).max(0);
                                cx.notify();
                            })
                            .ok();
                        }
                    })
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.count += 1;
                        cx.notify();
                    }))
                    .child(text!(format!("Counter: {}", self.count))),
            )
            .child(
                div()
                    .id("reset")
                    .focusable()
                    .tab_stop(true)
                    .role(Role::Button)
                    .aria_label("Reset counter")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.count = 0;
                        cx.notify();
                    }))
                    .child(text!("Reset counter")),
            )
            .child(
                div()
                    .id("note")
                    .role(Role::Note)
                    .aria_label("HWND overlay gap")
                    .child(text!(
                        "WebView2 and RDP HWNDs are outside this AccessKit tree — see 08-focus-a11y.md"
                    )),
            )
    }
}
