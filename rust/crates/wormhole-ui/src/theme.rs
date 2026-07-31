//! Theme tokens from the migration plan (terminal-first chrome).

/// Fixed color tokens shared by GPUI chrome and native overlays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThemeTokens {
    /// Terminal / content background (`#0C0C0C`).
    pub terminal_bg: u32,
    /// Primary foreground (`#E0E0E0`).
    pub foreground: u32,
    /// Error / danger (`#FF6B6B`).
    pub error: u32,
    /// Success (`#6BCB77`).
    pub success: u32,
    /// Link / accent (`#175DDC`).
    pub link: u32,
}

impl ThemeTokens {
    pub const fn wormhole_default() -> Self {
        Self {
            terminal_bg: 0x0C_0C_0C,
            foreground: 0xE0_E0_E0,
            error: 0xFF_6B_6B,
            success: 0x6B_CB_77,
            link: 0x17_5D_DC,
        }
    }

    /// `#RRGGBB` for CSS / WebView2 bridge strings, derived from the token field.
    pub fn to_css(rgb: u32) -> String {
        format!("#{:06X}", rgb & 0x00FF_FFFF)
    }

    pub fn terminal_bg_css(self) -> String {
        Self::to_css(self.terminal_bg)
    }

    pub fn foreground_css(self) -> String {
        Self::to_css(self.foreground)
    }

    pub fn error_css(self) -> String {
        Self::to_css(self.error)
    }

    pub fn success_css(self) -> String {
        Self::to_css(self.success)
    }

    pub fn link_css(self) -> String {
        Self::to_css(self.link)
    }
}

/// Process-wide default tokens.
pub const THEME: ThemeTokens = ThemeTokens::wormhole_default();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tokens_match_plan_hex() {
        assert_eq!(THEME.terminal_bg, 0x0C0C0C);
        assert_eq!(THEME.foreground, 0xE0E0E0);
        assert_eq!(THEME.error, 0xFF6B6B);
        assert_eq!(THEME.success, 0x6BCB77);
        assert_eq!(THEME.link, 0x175DDC);
        assert_eq!(THEME.terminal_bg_css(), "#0C0C0C");
        assert_eq!(THEME.foreground_css(), "#E0E0E0");
        assert_eq!(THEME.error_css(), "#FF6B6B");
        assert_eq!(THEME.success_css(), "#6BCB77");
        assert_eq!(THEME.link_css(), "#175DDC");
    }

    #[test]
    fn css_tracks_custom_token_fields() {
        let custom = ThemeTokens {
            terminal_bg: 0x11_22_33,
            foreground: 0xAA_BB_CC,
            error: 0x01_02_03,
            success: 0x04_05_06,
            link: 0x07_08_09,
        };
        assert_eq!(custom.terminal_bg_css(), "#112233");
        assert_eq!(custom.link_css(), "#070809");
    }
}
