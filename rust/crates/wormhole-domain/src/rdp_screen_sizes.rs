/// Shared RDP screen-size constants (`Wormhole.Helpers.RdpScreenSizes`).
pub struct RdpScreenSizes;

impl RdpScreenSizes {
    /// Canonical editor value: size remote desktop to the embedded content area.
    pub const FULL_CONNECTION_CONTENT: &'static str = "Full connection content";

    /// Legacy value from older Wormhole builds.
    pub const LEGACY_FULL_SCREEN_SENTINEL: &'static str = "Full screen";

    /// Legacy mRemoteNG import sentinel.
    pub const M_REMOTE_NG_FIT_TO_WINDOW_SENTINEL: &'static str = "FitToWindow";

    pub const PRESETS: &'static [&'static str] = &[
        Self::FULL_CONNECTION_CONTENT,
        "640x480",
        "800x600",
        "1024x768",
        "1280x800",
        "1280x1024",
        "1366x768",
        "1440x900",
        "1600x900",
        "1680x1050",
        "1920x1080",
    ];

    pub fn is_full_connection_content(screen_size: Option<&str>) -> bool {
        match screen_size {
            None => true,
            Some(s) if s.trim().is_empty() => true,
            Some(s) => {
                eq_ignore_ascii_case(s, Self::FULL_CONNECTION_CONTENT)
                    || eq_ignore_ascii_case(s, Self::LEGACY_FULL_SCREEN_SENTINEL)
                    || eq_ignore_ascii_case(s, Self::M_REMOTE_NG_FIT_TO_WINDOW_SENTINEL)
            }
        }
    }

    pub fn normalize_for_picker(screen_size: Option<&str>) -> Option<String> {
        match screen_size {
            None => None,
            Some(s) if s.trim().is_empty() => None,
            Some(s) if Self::is_full_connection_content(Some(s)) => {
                Some(Self::FULL_CONNECTION_CONTENT.to_string())
            }
            Some(s) => Some(s.to_string()),
        }
    }
}

fn eq_ignore_ascii_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
