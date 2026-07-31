//! Surface kinds the broker knows how to host (later: create + position).

/// Registered native surface kinds for Phase-1 gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SurfaceKind {
    /// Embedded WebView2 (SSH/serial xterm.js, HTTP/HTTPS appliance UI).
    WebView2,
    /// RDP ActiveX `MsRdpClient9NotSafeForScripting` as an owned top-level overlay HWND.
    RdpActiveX,
}

impl SurfaceKind {
    /// Human-readable label for logs / lab output.
    pub fn label(self) -> &'static str {
        match self {
            Self::WebView2 => "WebView2",
            Self::RdpActiveX => "RdpActiveX",
        }
    }
}
