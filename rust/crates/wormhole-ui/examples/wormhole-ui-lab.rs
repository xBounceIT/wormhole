//! Optional lab window for `wormhole-ui` GPUI chrome.
//!
//! ```powershell
//! $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
//! cd rust
//! cargo run -p wormhole-ui --example wormhole-ui-lab --features gpui
//! ```
//!
//! Does **not** claim hardware gate pass — visual smoke only.

fn main() {
    match wormhole_ui::try_boot_shell() {
        Ok(msg) => eprintln!("[wormhole-ui-lab] {msg}"),
        Err(err) => {
            eprintln!("[wormhole-ui-lab] boot failed: {err}");
            std::process::exit(1);
        }
    }
}
