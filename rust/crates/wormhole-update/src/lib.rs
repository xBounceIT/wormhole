//! GitHub release update check / download stubs for the Wormhole Rust migration.
//!
//! Mirrors the pure helpers and result shape of `Services/UpdateService.cs` and
//! `Models/UpdateCheckResult.cs`. **Does not** implement installer UX, silent launch,
//! Mark-of-the-Web strip, or live HTTP — see `docs/migration/13-update-logging.md`.
//!
//! Inject [`UpdateChecker`] implementations: production [`NetworkStubUpdateChecker`]
//! (fail-closed) or test [`FakeUpdateChecker`]. Wire UI notify via [`check_now`] /
//! [`UpdateNotifyStatus`]. **Never** log API tokens ([`UpdateApiToken`]).

mod channel;
mod changelog;
mod check;
mod download;
mod error;
mod github;
mod notify;
mod version;

pub use channel::{
    check_for_update_network_stub, FakeSeenRequest, FakeUpdateChecker, FakeUpdateOutcome,
    NetworkStubUpdateChecker, SharedUpdateChecker, UpdateApiToken, UpdateCheckRequest,
    UpdateChecker, UPDATE_CHECK_NETWORK_GAP,
};
pub use notify::{
    check_now, notify_status_from_result, UpdateNotifyKind, UpdateNotifyStatus,
    UPDATE_NOTIFY_ERROR_TEXT, UPDATE_NOTIFY_UP_TO_DATE_TEXT,
};
pub use changelog::{fetch_changelog_live_stub, ChangelogDocument};
pub use check::{
    check_for_update_live_stub, check_for_update_with_manifest, evaluate_release, UpdateCheckResult,
};
pub use download::{
    download_bytes_to_temp, download_bytes_to_temp_limited, download_installer_live_stub,
    is_safe_installer_file_name, sha256_hex, update_cache_dir, verify_sha256,
    verify_sha256_sidecar, MAX_INSTALLER_BYTES,
};
pub use error::{Result, UpdateError};
pub use github::{
    find_installer_asset, is_allowed_http_url, normalize_sha256_token, parse_repo_url,
    parse_sha_sidecar, target_architecture, try_parse_repo_url, try_validate_http_url,
    ReleaseAsset, ReleaseManifest,
};
pub use version::{
    compare_versions, is_newer, parse_tag_version, try_parse_tag_version, AppVersion,
};
