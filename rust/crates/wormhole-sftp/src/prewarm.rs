//! SFTP client prewarm / tunnel-borrow Fake glue (pure Rust; no live SFTP).
//!
//! Thin Lab stub mirroring C# `SshSessionViewModel` prewarm cache:
//! - SSH **Connected** + captured credentials → start background Fake prewarm
//! - Any other status → cancel in-flight + dispose cached pair (fail closed;
//!   Connected flag and slot clear share one lock so a racing connect cannot
//!   observe Connected with an empty wiped slot)
//! - [`SftpPrewarmGlue::try_consume`] transfers ownership; re-warms while Connected
//! - Stale (`!is_connected`) cache → dispose corpse + `None` (on-demand fallback)
//! - Tunnel is a **non-owning** [`BorrowedShellTunnel`]: Drop / dispose never
//!   closes the shell-owned [`FakeShellTunnel`] (OTP-interactive VPN must not
//!   re-establish / burn a second code)
//!
//! [`FakePrewarmConnectMode::ImmediateSuccess`] completes Fake connect
//! synchronously (eager Fake). Use [`FakePrewarmConnectMode::Deferred`] to pin
//! C#-style empty-cache-while-in-flight timing after consume / before finish.
//!
//! No credentials on this surface — callers only set a credentials-present flag
//! (C# silent no-op without `_capturedCredentials`). Live russh dial deferred.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Opaque in-flight prewarm identity (C# `CancellationTokenSource` reference).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrewarmToken(u64);

impl PrewarmToken {
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Shell-owned tunnel recording handle (SSH session is the real owner).
///
/// Only [`Self::close`] increments [`Self::close_count`]. Borrowers must use
/// [`BorrowedShellTunnel`], whose Drop never calls [`Self::close`].
pub struct FakeShellTunnel {
    close_count: AtomicUsize,
    closed: AtomicBool,
}

impl FakeShellTunnel {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            close_count: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        })
    }

    /// Real owner tear-down (SSH disconnect). Idempotent.
    pub fn close(&self) {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.close_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn close_count(&self) -> usize {
        self.close_count.load(Ordering::SeqCst)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Non-owning borrow for SFTP prewarm / on-demand path.
    pub fn borrow(self: &Arc<Self>) -> BorrowedShellTunnel {
        BorrowedShellTunnel::new(Arc::clone(self))
    }
}

impl fmt::Debug for FakeShellTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeShellTunnel")
            .field("close_count", &self.close_count())
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// Non-owning view over [`FakeShellTunnel`] (C# `BorrowedTunnelInstance` without `onDispose`).
///
/// Drop / [`Self::dispose`] never closes the shell tunnel. Dispose is idempotent.
pub struct BorrowedShellTunnel {
    shell: Arc<FakeShellTunnel>,
    disposed: AtomicBool,
    dispose_count: AtomicUsize,
}

impl BorrowedShellTunnel {
    fn new(shell: Arc<FakeShellTunnel>) -> Self {
        Self {
            shell,
            disposed: AtomicBool::new(false),
            dispose_count: AtomicUsize::new(0),
        }
    }

    pub fn shell(&self) -> &Arc<FakeShellTunnel> {
        &self.shell
    }

    /// Detach the borrow handle only — shell stays alive. Idempotent.
    pub fn dispose(&self) {
        if self
            .disposed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.dispose_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn borrow_dispose_count(&self) -> usize {
        self.dispose_count.load(Ordering::SeqCst)
    }

    pub fn is_disposed(&self) -> bool {
        self.disposed.load(Ordering::SeqCst)
    }
}

impl Drop for BorrowedShellTunnel {
    fn drop(&mut self) {
        // Non-owning: never call FakeShellTunnel::close.
        self.dispose();
    }
}

impl fmt::Debug for BorrowedShellTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BorrowedShellTunnel")
            .field("shell_closed", &self.shell.is_closed())
            .field("shell_close_count", &self.shell.close_count())
            .field("borrow_dispose_count", &self.borrow_dispose_count())
            .field("disposed", &self.is_disposed())
            .finish()
    }
}

/// Fake prewarmed SFTP session handle (no network / no russh).
pub struct FakePrewarmedSftp {
    id: u64,
    connected: AtomicBool,
    dispose_count: AtomicUsize,
}

impl FakePrewarmedSftp {
    pub fn new() -> Arc<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Arc::new(Self {
            id: NEXT.fetch_add(1, Ordering::SeqCst),
            connected: AtomicBool::new(true),
            dispose_count: AtomicUsize::new(0),
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Test hook — mark transport idle / dead (C# `FakeSftpSession.IsConnected = false`).
    pub fn set_connected(&self, connected: bool) {
        self.connected.store(connected, Ordering::SeqCst);
    }

    /// Dispose the SFTP handle (not the shell tunnel). Counts every call (C# DisposeCount).
    pub fn dispose(&self) {
        self.connected.store(false, Ordering::SeqCst);
        self.dispose_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn dispose_count(&self) -> usize {
        self.dispose_count.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for FakePrewarmedSftp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakePrewarmedSftp")
            .field("id", &self.id)
            .field("connected", &self.is_connected())
            .field("dispose_count", &self.dispose_count())
            .finish()
    }
}

/// Ownership-transfer result from [`SftpPrewarmGlue::try_consume`].
pub struct PrewarmedSftpPair {
    pub session: Arc<FakePrewarmedSftp>,
    pub tunnel: Option<BorrowedShellTunnel>,
}

impl fmt::Debug for PrewarmedSftpPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrewarmedSftpPair")
            .field("session", &self.session)
            .field("tunnel", &self.tunnel)
            .finish()
    }
}

/// How Fake connect completes when a prewarm slot is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakePrewarmConnectMode {
    /// `begin_prewarm` immediately stashes a fresh connected Fake handle.
    ImmediateSuccess,
    /// Leave in-flight until the test calls [`SftpPrewarmGlue::finish_prewarm`].
    Deferred,
    /// Fail immediately — cache stays empty, in-flight cleared (on-demand fallback).
    ImmediateFail,
}

#[derive(Debug)]
struct CachedSlot {
    session: Arc<FakePrewarmedSftp>,
    tunnel: Option<BorrowedShellTunnel>,
}

struct Inner {
    ssh_connected: bool,
    /// C# `_capturedCredentials is not null` — no secret material stored here.
    credentials_present: bool,
    shell_tunnel: Option<Arc<FakeShellTunnel>>,
    connect_mode: FakePrewarmConnectMode,
    next_token: u64,
    in_flight: Option<PrewarmToken>,
    cached: Option<CachedSlot>,
}

/// SSH-tab SFTP prewarm cache (Fake).
///
/// Tied to one logical SSH session: status transitions start / cancel prewarm;
/// [`Self::try_consume`] hands the warm pair to the file-transfer dialog.
pub struct SftpPrewarmGlue {
    inner: Mutex<Inner>,
}

impl Default for SftpPrewarmGlue {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpPrewarmGlue {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                ssh_connected: false,
                credentials_present: false,
                shell_tunnel: None,
                connect_mode: FakePrewarmConnectMode::ImmediateSuccess,
                next_token: 1,
                in_flight: None,
                cached: None,
            }),
        }
    }

    /// C# `PrimeCredentialsForTesting` — flags that connect captured creds (no secret bytes).
    pub fn prime_credentials(&self) {
        self.inner.lock().expect("prewarm lock").credentials_present = true;
    }

    pub fn clear_credentials(&self) {
        self.inner.lock().expect("prewarm lock").credentials_present = false;
    }

    pub fn set_connect_mode(&self, mode: FakePrewarmConnectMode) {
        self.inner.lock().expect("prewarm lock").connect_mode = mode;
    }

    /// Attach / replace the shell-owned tunnel (or `None` for direct).
    pub fn set_shell_tunnel(&self, tunnel: Option<Arc<FakeShellTunnel>>) {
        self.inner.lock().expect("prewarm lock").shell_tunnel = tunnel;
    }

    /// Non-owning borrow for SFTP (C# `BorrowTunnelForSftp`). `None` when direct.
    pub fn borrow_tunnel_for_sftp(&self) -> Option<BorrowedShellTunnel> {
        let g = self.inner.lock().expect("prewarm lock");
        g.shell_tunnel.as_ref().map(|t| t.borrow())
    }

    /// Status transition (C# `HandlePrewarmStatusTransition`).
    ///
    /// Connected → start Fake prewarm (idempotent). Else → cancel + dispose.
    ///
    /// Disconnect clears `ssh_connected` **and** in-flight/cache under the same
    /// lock so a concurrent `on_ssh_status(true)` cannot observe Connected with a
    /// wiped slot (empty cache, no in-flight) after a racing cancel.
    pub fn on_ssh_status(&self, connected: bool) {
        if connected {
            {
                let mut g = self.inner.lock().expect("prewarm lock");
                g.ssh_connected = true;
            }
            let _ = self.begin_prewarm();
        } else {
            let cached = {
                let mut g = self.inner.lock().expect("prewarm lock");
                g.ssh_connected = false;
                take_inflight_and_cache(&mut g).1
            };
            if let Some(slot) = cached {
                dispose_pair(slot.session, slot.tunnel);
            }
        }
    }

    /// Open an in-flight slot (and optionally complete immediately per connect mode).
    ///
    /// Returns `None` when not Connected, credentials missing, already in-flight,
    /// or cache already warm (C# `StartPrewarm` early returns).
    pub fn begin_prewarm(&self) -> Option<PrewarmToken> {
        let (token, mode, shell) = {
            let mut g = self.inner.lock().expect("prewarm lock");
            if !g.ssh_connected || !g.credentials_present {
                return None;
            }
            if g.in_flight.is_some() || g.cached.is_some() {
                return None;
            }
            let token = PrewarmToken(g.next_token);
            g.next_token = g.next_token.wrapping_add(1);
            if g.next_token == 0 {
                g.next_token = 1;
            }
            g.in_flight = Some(token);
            let mode = g.connect_mode;
            // Borrow only for ImmediateSuccess (C# borrows at PrewarmAsync start).
            // Deferred / Fail leave the tunnel to finish_prewarm / nowhere — avoid a
            // throwaway BorrowedShellTunnel Drop on those paths.
            let shell = if matches!(mode, FakePrewarmConnectMode::ImmediateSuccess) {
                g.shell_tunnel.clone()
            } else {
                None
            };
            (token, mode, shell)
        };

        match mode {
            FakePrewarmConnectMode::Deferred => Some(token),
            FakePrewarmConnectMode::ImmediateFail => {
                let _ = self.finish_prewarm(token, Err(()));
                None
            }
            FakePrewarmConnectMode::ImmediateSuccess => {
                let session = FakePrewarmedSftp::new();
                let tunnel = shell.as_ref().map(|t| t.borrow());
                // May return false when disconnect clears the token between begin and
                // finish; finish_prewarm disposes the pair in that case.
                let _ = self.finish_prewarm(
                    token,
                    Ok(PrewarmedSftpPair {
                        session,
                        tunnel,
                    }),
                );
                None // slot no longer in-flight (ready in cache, or disposed on race)
            }
        }
    }

    /// Complete a Deferred (or race) prewarm. Stashes only when `token` is still current.
    ///
    /// On mismatch / cancel / disconnect: disposes the pair (session + borrow) and
    /// returns `false`. Borrow dispose never closes the shell tunnel.
    pub fn finish_prewarm(
        &self,
        token: PrewarmToken,
        result: Result<PrewarmedSftpPair, ()>,
    ) -> bool {
        let mut g = self.inner.lock().expect("prewarm lock");
        let stash = g.in_flight == Some(token);
        if stash {
            g.in_flight = None;
        }

        match result {
            Ok(pair) if stash && g.ssh_connected && g.cached.is_none() => {
                g.cached = Some(CachedSlot {
                    session: pair.session,
                    tunnel: pair.tunnel,
                });
                true
            }
            Ok(pair) => {
                drop(g);
                dispose_pair(pair.session, pair.tunnel);
                false
            }
            Err(()) => false,
        }
    }

    /// Atomically transfer a warm pair to the caller (C# `TryConsumePrewarmedSftp`).
    ///
    /// Stale / disconnected sessions are disposed and yield `None`. Successful
    /// consume re-starts prewarm while SSH remains Connected (status re-read
    /// after the cache take, matching C# `Status == Connected` checks).
    pub fn try_consume(&self) -> Option<PrewarmedSftpPair> {
        let slot = {
            let mut g = self.inner.lock().expect("prewarm lock");
            g.cached.take()
        };

        let Some(slot) = slot else {
            return None;
        };

        if !slot.session.is_connected() {
            dispose_pair(slot.session, slot.tunnel);
            if self.is_ssh_connected() {
                let _ = self.begin_prewarm();
            }
            return None;
        }

        if self.is_ssh_connected() {
            let _ = self.begin_prewarm();
        }

        Some(PrewarmedSftpPair {
            session: slot.session,
            tunnel: slot.tunnel,
        })
    }

    /// Cancel in-flight + dispose cached pair (C# `CancelAndDisposePrewarm`).
    pub fn cancel_and_dispose(&self) {
        let cached = {
            let mut g = self.inner.lock().expect("prewarm lock");
            // Token identity cleared — late finish_prewarm will not stash.
            take_inflight_and_cache(&mut g).1
        };
        if let Some(slot) = cached {
            dispose_pair(slot.session, slot.tunnel);
        }
    }

    pub fn has_prewarmed(&self) -> bool {
        self.inner.lock().expect("prewarm lock").cached.is_some()
    }

    pub fn has_in_flight(&self) -> bool {
        self.inner.lock().expect("prewarm lock").in_flight.is_some()
    }

    pub fn is_ssh_connected(&self) -> bool {
        self.inner.lock().expect("prewarm lock").ssh_connected
    }

    /// Peek current in-flight token (tests).
    pub fn in_flight_token(&self) -> Option<PrewarmToken> {
        self.inner.lock().expect("prewarm lock").in_flight
    }
}

impl fmt::Debug for SftpPrewarmGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let g = self.inner.lock().expect("prewarm lock");
        f.debug_struct("SftpPrewarmGlue")
            .field("ssh_connected", &g.ssh_connected)
            .field("credentials_present", &g.credentials_present)
            .field("connect_mode", &g.connect_mode)
            .field("has_shell_tunnel", &g.shell_tunnel.is_some())
            .field("in_flight", &g.in_flight)
            .field("has_prewarmed", &g.cached.is_some())
            .finish()
    }
}

fn take_inflight_and_cache(g: &mut Inner) -> (Option<PrewarmToken>, Option<CachedSlot>) {
    (g.in_flight.take(), g.cached.take())
}

fn dispose_pair(session: Arc<FakePrewarmedSftp>, tunnel: Option<BorrowedShellTunnel>) {
    session.dispose();
    // BorrowedShellTunnel::Drop detaches only — never FakeShellTunnel::close.
    drop(tunnel);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warm_ready(glue: &SftpPrewarmGlue) {
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::ImmediateSuccess);
        glue.on_ssh_status(true);
        assert!(glue.has_prewarmed());
        assert!(!glue.has_in_flight());
    }

    #[test]
    fn borrow_drop_does_not_close_shell_tunnel() {
        let shell = FakeShellTunnel::new();
        let borrowed = shell.borrow();
        drop(borrowed);
        assert_eq!(shell.close_count(), 0);
        assert!(!shell.is_closed());

        let borrowed = shell.borrow();
        borrowed.dispose();
        drop(borrowed);
        assert_eq!(shell.close_count(), 0);

        shell.close();
        assert_eq!(shell.close_count(), 1);
        shell.close();
        assert_eq!(shell.close_count(), 1);
    }

    #[test]
    fn prewarm_borrows_shell_tunnel_without_closing_it() {
        let glue = SftpPrewarmGlue::new();
        let shell = FakeShellTunnel::new();
        glue.set_shell_tunnel(Some(Arc::clone(&shell)));
        glue.prime_credentials();
        glue.on_ssh_status(true);

        let pair = glue.try_consume().expect("warm");
        assert!(pair.tunnel.is_some());
        drop(pair.tunnel);
        assert_eq!(shell.close_count(), 0);

        // Session dispose is independent of the shell.
        pair.session.dispose();
        assert_eq!(shell.close_count(), 0);
    }

    #[test]
    fn cancel_on_disconnect_clears_cache_and_in_flight() {
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::Deferred);
        glue.on_ssh_status(true);
        assert!(glue.has_in_flight());

        glue.on_ssh_status(false);
        assert!(!glue.has_in_flight());
        assert!(!glue.has_prewarmed());
        assert!(!glue.is_ssh_connected());
    }

    #[test]
    fn cancel_disposes_cached_session_not_shell() {
        let glue = SftpPrewarmGlue::new();
        let shell = FakeShellTunnel::new();
        glue.set_shell_tunnel(Some(Arc::clone(&shell)));
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::Deferred);
        glue.on_ssh_status(true);
        let token = glue.in_flight_token().expect("flight");
        let session = FakePrewarmedSftp::new();
        assert!(glue.finish_prewarm(
            token,
            Ok(PrewarmedSftpPair {
                session: Arc::clone(&session),
                tunnel: glue.borrow_tunnel_for_sftp(),
            }),
        ));
        assert!(glue.has_prewarmed());

        glue.cancel_and_dispose();
        assert!(session.dispose_count() >= 1);
        assert!(!glue.has_prewarmed());
        assert_eq!(shell.close_count(), 0);
    }

    #[test]
    fn try_consume_none_before_ready() {
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::Deferred);
        glue.on_ssh_status(true);
        assert!(glue.has_in_flight());
        assert!(glue.try_consume().is_none());
    }

    #[test]
    fn try_consume_returns_once_and_rewarms() {
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::Deferred);
        glue.on_ssh_status(true);
        let t1 = glue.in_flight_token().expect("in flight");
        let first = FakePrewarmedSftp::new();
        let first_id = first.id();
        assert!(glue.finish_prewarm(
            t1,
            Ok(PrewarmedSftpPair {
                session: Arc::clone(&first),
                tunnel: None,
            }),
        ));
        assert!(glue.has_prewarmed());

        let consumed = glue.try_consume().expect("first");
        assert_eq!(consumed.session.id(), first_id);
        assert!(!glue.has_prewarmed());
        // Re-warm kicked off (Deferred → in flight).
        assert!(glue.has_in_flight());
        assert!(glue.try_consume().is_none());

        let t2 = glue.in_flight_token().expect("second flight");
        let second = FakePrewarmedSftp::new();
        let second_id = second.id();
        assert!(glue.finish_prewarm(
            t2,
            Ok(PrewarmedSftpPair {
                session: Arc::clone(&second),
                tunnel: None,
            }),
        ));
        let again = glue.try_consume().expect("second");
        assert_eq!(again.session.id(), second_id);
        assert_ne!(first_id, second_id);
    }

    #[test]
    fn prewarm_failure_leaves_cache_empty() {
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::ImmediateFail);
        glue.on_ssh_status(true);
        assert!(!glue.has_in_flight());
        assert!(!glue.has_prewarmed());
        assert!(glue.try_consume().is_none());
    }

    #[test]
    fn try_consume_drops_stale_session() {
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::Deferred);
        glue.on_ssh_status(true);
        let token = glue.in_flight_token().expect("flight");
        let stale = FakePrewarmedSftp::new();
        stale.set_connected(false);
        assert!(glue.finish_prewarm(
            token,
            Ok(PrewarmedSftpPair {
                session: Arc::clone(&stale),
                tunnel: None,
            }),
        ));
        // Cached even if disconnected — liveness checked at consume.
        assert!(glue.has_prewarmed());
        assert!(glue.try_consume().is_none());
        assert!(stale.dispose_count() >= 1);
        // Deferred re-warm: in-flight until finish (C# cache empty while connecting).
        assert!(glue.has_in_flight());
        assert!(!glue.has_prewarmed());
    }

    #[test]
    fn retry_after_immediate_fail_can_warm() {
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::ImmediateFail);
        glue.on_ssh_status(true);
        assert!(!glue.has_prewarmed());

        glue.set_connect_mode(FakePrewarmConnectMode::ImmediateSuccess);
        assert!(glue.begin_prewarm().is_none()); // completed into cache
        assert!(glue.has_prewarmed());
        assert!(glue.try_consume().is_some());
    }

    #[test]
    fn borrow_dispose_is_idempotent() {
        let shell = FakeShellTunnel::new();
        let borrowed = shell.borrow();
        borrowed.dispose();
        borrowed.dispose();
        assert_eq!(borrowed.borrow_dispose_count(), 1);
        drop(borrowed);
        assert_eq!(shell.close_count(), 0);
    }

    #[test]
    fn no_prewarm_without_credentials() {
        let glue = SftpPrewarmGlue::new();
        glue.set_connect_mode(FakePrewarmConnectMode::ImmediateSuccess);
        glue.on_ssh_status(true);
        assert!(!glue.has_in_flight());
        assert!(!glue.has_prewarmed());
        assert!(glue.begin_prewarm().is_none());
    }

    #[test]
    fn finish_after_cancel_does_not_stash() {
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::Deferred);
        glue.on_ssh_status(true);
        let token = glue.in_flight_token().expect("flight");
        glue.cancel_and_dispose();
        assert!(!glue.has_in_flight());

        let session = FakePrewarmedSftp::new();
        let stashed = glue.finish_prewarm(
            token,
            Ok(PrewarmedSftpPair {
                session: Arc::clone(&session),
                tunnel: None,
            }),
        );
        assert!(!stashed);
        assert!(!glue.has_prewarmed());
        assert!(session.dispose_count() >= 1);
    }

    #[test]
    fn finish_foreign_token_does_not_stash() {
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::Deferred);
        glue.on_ssh_status(true);
        let real = glue.in_flight_token().expect("flight");
        let foreign = PrewarmToken(real.get().wrapping_add(99));
        let session = FakePrewarmedSftp::new();
        assert!(!glue.finish_prewarm(
            foreign,
            Ok(PrewarmedSftpPair {
                session: Arc::clone(&session),
                tunnel: None,
            }),
        ));
        assert!(glue.has_in_flight());
        assert!(!glue.has_prewarmed());
        assert!(session.dispose_count() >= 1);
    }

    #[test]
    fn debug_omits_secret_shaped_fields() {
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        let shell = FakeShellTunnel::new();
        glue.set_shell_tunnel(Some(shell));
        glue.on_ssh_status(true);
        let text = format!("{glue:?}");
        assert!(!text.to_ascii_lowercase().contains("password"));
        assert!(!text.to_ascii_lowercase().contains("secret"));
        assert!(!text.contains("hunter2"));
        assert!(text.contains("credentials_present"));
    }

    #[test]
    fn begin_idempotent_while_warm_or_in_flight() {
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::Deferred);
        glue.on_ssh_status(true);
        assert!(glue.begin_prewarm().is_none()); // already in flight

        let token = glue.in_flight_token().unwrap();
        assert!(glue.finish_prewarm(
            token,
            Ok(PrewarmedSftpPair {
                session: FakePrewarmedSftp::new(),
                tunnel: None,
            }),
        ));
        assert!(glue.begin_prewarm().is_none()); // already warm
    }

    #[test]
    fn dispose_pair_on_cancel_does_not_close_shell() {
        let glue = SftpPrewarmGlue::new();
        let shell = FakeShellTunnel::new();
        glue.set_shell_tunnel(Some(Arc::clone(&shell)));
        warm_ready(&glue);
        glue.cancel_and_dispose();
        assert_eq!(shell.close_count(), 0);
        assert!(!glue.has_prewarmed());
    }

    #[test]
    fn reconnect_after_disconnect_rewarms() {
        let glue = SftpPrewarmGlue::new();
        warm_ready(&glue);
        let first = glue.try_consume().expect("first warm");
        let first_id = first.session.id();

        glue.on_ssh_status(false);
        assert!(!glue.is_ssh_connected());
        assert!(!glue.has_prewarmed());
        assert!(!glue.has_in_flight());

        glue.on_ssh_status(true);
        assert!(glue.is_ssh_connected());
        assert!(glue.has_prewarmed());
        let second = glue.try_consume().expect("rewarm after reconnect");
        assert_ne!(second.session.id(), first_id);
    }

    #[test]
    fn disconnect_is_atomic_with_cache_clear() {
        // Invariant: after on_ssh_status(false), Connected is false and the
        // prewarm slot is empty (same lock — no window for a racing connect to
        // leave Connected + empty after a late cancel).
        let glue = SftpPrewarmGlue::new();
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::Deferred);
        glue.on_ssh_status(true);
        assert!(glue.has_in_flight());

        glue.on_ssh_status(false);
        assert!(!glue.is_ssh_connected());
        assert!(!glue.has_in_flight());
        assert!(!glue.has_prewarmed());
    }

    #[test]
    fn concurrent_status_flips_settle_consistently() {
        use std::thread;

        let glue = Arc::new(SftpPrewarmGlue::new());
        glue.prime_credentials();
        glue.set_connect_mode(FakePrewarmConnectMode::ImmediateSuccess);
        let shell = FakeShellTunnel::new();
        glue.set_shell_tunnel(Some(Arc::clone(&shell)));

        let mut handles = Vec::new();
        for i in 0..8 {
            let g = Arc::clone(&glue);
            handles.push(thread::spawn(move || {
                for round in 0..200 {
                    g.on_ssh_status((i + round) % 2 == 0);
                }
            }));
        }
        for h in handles {
            h.join().expect("status flip thread");
        }

        // Final transition settles the machine; shell must never have been closed
        // by borrow dispose during the chaos.
        glue.on_ssh_status(true);
        assert!(glue.is_ssh_connected());
        assert!(
            glue.has_prewarmed() || glue.has_in_flight(),
            "Connected+creds must not stick in empty/no-flight after status chaos"
        );
        assert_eq!(shell.close_count(), 0);
    }

    #[test]
    fn try_consume_immediate_success_rewarm_is_eager() {
        let glue = SftpPrewarmGlue::new();
        warm_ready(&glue);
        let first = glue.try_consume().expect("first");
        // ImmediateSuccess rewarm completes synchronously into cache.
        assert!(glue.has_prewarmed());
        assert!(!glue.has_in_flight());
        let second = glue.try_consume().expect("eager rewarm");
        assert_ne!(first.session.id(), second.session.id());
    }
}
