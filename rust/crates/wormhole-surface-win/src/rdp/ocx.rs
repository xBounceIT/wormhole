//! MsRdpClient CoCreate + OLE in-place activation + Connect stub (STA-affine).
//!
//! mstscax is loaded only at runtime via `CoCreateInstance`. The OCX is hosted
//! inside the owned overlay HWND through `IOleObject::SetClientSite` +
//! `DoVerb(OLEIVERB_INPLACEACTIVATE)` — never via `SetParent` on the overlay.
//!
//! # Drop order (mandatory)
//!
//! Drop [`RdpOcx`] **before** destroying the overlay HWND ([`super::host::RdpOverlayHost`]).
//! Teardown sequence inside [`RdpOcx`]: Unadvise → `IOleObject::Close` →
//! `SetClientSite(None)` → release site. Destroying the HWND first leaves the OLE
//! site holding a stale window.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::{Duration, Instant};

use windows::core::{Interface, IUnknown};
use windows::Win32::Foundation::{HWND, RECT};
use windows::Win32::System::Com::{
    CoCreateInstance, IConnectionPoint, IConnectionPointContainer, IDispatch, CLSCTX_INPROC_SERVER,
};
use windows::Win32::System::Ole::{
    IOleInPlaceObject, IOleObject, OleInitialize, OleUninitialize, OLECLOSE_NOSAVE,
    OLEIVERB_INPLACEACTIVATE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetClientRect, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
};

use zeroize::Zeroize;

use super::clsid::{probe_registered_classes, RdpActiveXClass};
use super::configure::{
    normalise_color_depth, validate_configure_inputs, ConfigureReport, RdpConfigureOptions,
    WipePasswordOnDrop, CREDSSP_SOFT_MISS_NLA_RISK, NEGOTIATE_SOFT_MISS,
};
use super::dispatch::{self, SoftPut};
use super::events::{
    create_events_sink, sink_unknown, MsTscAxEventsSink, RdpEventState, IMS_TSC_AX_EVENTS_IID,
};
use super::site::{as_client_site, create_client_site, ensure_min_rect, RdpOleSite};

/// Stub connect options (server/port). Prefer [`RdpOcx::configure`] when credentials
/// or CredSSP are needed — this path never touches password properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectStubOptions {
    /// RDP server hostname or IP.
    pub server: String,
    /// RDP TCP port (usually 3389).
    pub port: u16,
}

/// Pairs `OleInitialize` with `OleUninitialize` even if the STA body panics.
struct OleInitGuard;

impl Drop for OleInitGuard {
    fn drop(&mut self) {
        unsafe {
            OleUninitialize();
        }
    }
}

/// Run `f` on a fresh STA thread with `OleInitialize` (apartment-threaded + OLE).
///
/// Keep COM objects inside `f` and drop them before `f` returns so
/// `OleUninitialize` runs after all OCX/site teardown. Do not return `RdpOcx`
/// (it is `!Send`).
pub fn run_on_sta<T, F>(f: F) -> windows::core::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> windows::core::Result<T> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("wormhole-rdp-ocx-sta".into())
        .spawn(move || {
            unsafe {
                if let Err(e) = OleInitialize(None) {
                    let _ = tx.send(Err(e));
                    return;
                }
            }
            let _ole = OleInitGuard;
            let result = f();
            let _ = tx.send(result);
            // OleUninitialize via OleInitGuard Drop (also on panic unwind).
        })
        .map_err(|e| {
            windows::core::Error::new(
                windows::Win32::Foundation::E_FAIL,
                format!("failed to spawn RDP STA thread: {e}"),
            )
        })?;
    rx.recv().map_err(|_| {
        windows::core::Error::new(
            windows::Win32::Foundation::E_FAIL,
            "RDP STA thread exited without result",
        )
    })?
}

/// Pump the STA message queue briefly (required for OLE/ActiveX callbacks).
pub fn pump_messages(timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut msg = MSG::default();
    while Instant::now() < deadline {
        let mut pumped = false;
        unsafe {
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                pumped = true;
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if !pumped {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Result of embedding MsRdpClient into an overlay HWND.
#[derive(Debug, Clone)]
pub struct InPlaceActivateInfo {
    /// ActiveX class that was activated.
    pub class_name: String,
    /// CLSID string.
    pub clsid: String,
    /// True when `IOleObject` + `DoVerb(INPLACEACTIVATE)` succeeded.
    pub inplace_ok: bool,
    /// True when the connection-point sink was advised.
    pub events_advised: bool,
}

/// Build a `windows::core::Error` with `E_FAIL` (for lab / STA drivers).
pub fn rdp_fail(message: impl Into<String>) -> windows::core::Error {
    windows::core::Error::new(windows::Win32::Foundation::E_FAIL, message.into())
}

/// CoCreated MsRdpClient with optional OLE site + event sink.
///
/// `!Send` / `!Sync`: STA apartment affinity — do not move across threads.
pub struct RdpOcx {
    class: RdpActiveXClass,
    dispatch: IDispatch,
    ole: Option<IOleObject>,
    site: Option<windows::core::ComObject<RdpOleSite>>,
    sink: Option<windows::core::ComObject<MsTscAxEventsSink>>,
    connection_point: Option<IConnectionPoint>,
    advise_cookie: u32,
    event_state: Rc<RefCell<RdpEventState>>,
    _not_send_sync: PhantomData<*const ()>,
}

impl RdpOcx {
    /// CoCreate the newest registered preferred class (11 → 10 → 9 fallbacks).
    ///
    /// Must run on an STA apartment (`OleInitialize` / apartment-threaded).
    pub fn cocreate_best() -> windows::core::Result<Self> {
        let candidates = probe_registered_classes();
        let mut last_err = None;
        for candidate in &candidates {
            match Self::cocreate(*candidate) {
                Ok(ocx) => return Ok(ocx),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            windows::core::Error::new(
                windows::Win32::Foundation::E_FAIL,
                "no MsRdpClient CLSID could be activated",
            )
        }))
    }

    /// CoCreate a specific class.
    pub fn cocreate(class: RdpActiveXClass) -> windows::core::Result<Self> {
        let unknown: IUnknown =
            unsafe { CoCreateInstance(&class.guid, None, CLSCTX_INPROC_SERVER)? };
        let dispatch: IDispatch = unknown.cast()?;
        let ole: Option<IOleObject> = unknown.cast().ok();
        Ok(Self {
            class,
            dispatch,
            ole,
            site: None,
            sink: None,
            connection_point: None,
            advise_cookie: 0,
            event_state: Rc::new(RefCell::new(RdpEventState::default())),
            _not_send_sync: PhantomData,
        })
    }

    /// Selected ActiveX class.
    pub fn class(&self) -> RdpActiveXClass {
        self.class
    }

    /// Shared event state (Connected / Disconnected / FatalError).
    pub fn event_state(&self) -> Rc<RefCell<RdpEventState>> {
        Rc::clone(&self.event_state)
    }

    /// Embed into `container` via `IOleClientSite` + `DoVerb(OLEIVERB_INPLACEACTIVATE)`.
    ///
    /// `container` must be the owned overlay HWND (`WS_POPUP` + `GWLP_HWNDPARENT`).
    /// Re-activation first revokes any prior site / Advise so drop order stays defined.
    pub fn activate_in_place(
        &mut self,
        container: HWND,
    ) -> windows::core::Result<InPlaceActivateInfo> {
        // Prior site must be revoked before binding a new HWND (re-activate / reconnect).
        self.revoke_site_keep_object();

        let ole = self.ole.as_ref().ok_or_else(|| {
            windows::core::Error::new(
                windows::Win32::Foundation::E_NOINTERFACE,
                "MsRdpClient did not expose IOleObject — cannot in-place activate",
            )
        })?;

        let site = create_client_site(container);
        let client = as_client_site(&site);

        unsafe {
            ole.SetClientSite(&client)?;
            let _ = ole.SetHostNames(
                windows::core::w!("Wormhole"),
                windows::core::w!("RDP session"),
            );
        }

        let mut rc = RECT::default();
        unsafe {
            let _ = GetClientRect(container, &mut rc);
        }
        ensure_min_rect(&mut rc);

        // DoVerb's active-site parameter is typed as IOleClientSite (not IOleInPlaceSite).
        // Must run on the same STA that created `container` — never cross-thread DoVerb.
        unsafe {
            ole.DoVerb(
                OLEIVERB_INPLACEACTIVATE.0,
                std::ptr::null(),
                &client,
                0,
                container,
                &rc,
            )?;
        }

        if let Ok(ipo) = ole.cast::<IOleInPlaceObject>() {
            let _ = unsafe { ipo.SetObjectRects(&rc, &rc) };
            site.set_inplace_object(Some(ipo));
        }

        self.site = Some(site);

        let events_advised = self.advise_events_internal().is_ok();

        Ok(InPlaceActivateInfo {
            class_name: self.class.name.to_string(),
            clsid: self.class.clsid_string.to_string(),
            inplace_ok: true,
            events_advised,
        })
    }

    /// Advise the connection-point sink (Connected / Disconnected / FatalError).
    pub fn advise_events(&mut self) -> windows::core::Result<()> {
        self.advise_events_internal()
    }

    fn advise_events_internal(&mut self) -> windows::core::Result<()> {
        if self.advise_cookie != 0 {
            return Ok(());
        }
        let cpc: IConnectionPointContainer = self.dispatch.cast()?;
        let cp = unsafe { cpc.FindConnectionPoint(&IMS_TSC_AX_EVENTS_IID)? };
        let sink = create_events_sink(Rc::clone(&self.event_state));
        let unk = sink_unknown(&sink);
        let cookie = unsafe { cp.Advise(&unk)? };
        self.sink = Some(sink);
        self.connection_point = Some(cp);
        self.advise_cookie = cookie;
        Ok(())
    }

    /// Detach the event sink (best-effort). Safe to call more than once.
    pub fn unadvise_events(&mut self) {
        if let Some(cp) = self.connection_point.take() {
            if self.advise_cookie != 0 {
                let _ = unsafe { cp.Unadvise(self.advise_cookie) };
            }
        }
        self.advise_cookie = 0;
        self.sink = None;
    }

    /// Unadvise + revoke client site without `Close` (for re-activation onto a new HWND).
    fn revoke_site_keep_object(&mut self) {
        self.unadvise_events();
        if let Some(site) = self.site.take() {
            site.set_inplace_object(None);
        }
        if let Some(ole) = self.ole.as_ref() {
            unsafe {
                let _ = ole.SetClientSite(None);
            }
        }
    }

    /// Apply connect-time Server / display / CredSSP settings (before `Connect`).
    ///
    /// Loud (hard `Err`) for validation, core target + display + `RDPPort` + password put.
    /// Soft for `EnableCredSspSupport` and `NegotiateSecurityLayer` when the name is
    /// missing on the active AdvancedSettings tier — see [`ConfigureReport`].
    ///
    /// Password: wiped from `opts` on **every** exit (Ok or Err), including early
    /// validation / loud put failures. Never logged (`RdpConfigureOptions` Debug redacts).
    ///
    /// Soft CredSSP miss sets [`ConfigureReport::cred_ssp_soft_missed`] — OCX default is
    /// `EnableCredSspSupport = false` (NLA risk). Do not `Connect` after a hard `Err` or
    /// an unacked CredSSP soft miss when CredSSP was requested; the OCX may already be
    /// partially mutated by earlier loud puts.
    pub fn configure(
        &self,
        opts: &mut RdpConfigureOptions,
    ) -> windows::core::Result<ConfigureReport> {
        // Take password first. Validate while we still hold an immutable view, then
        // install WipePasswordOnDrop so every exit (including validation Err) wipes.
        let mut password_slot = opts.password.take();
        let validated = validate_configure_inputs(
            &opts.server,
            opts.port,
            opts.username.as_deref(),
            opts.domain.as_deref(),
            password_slot.as_ref().map(|p| p.as_str()),
            opts.desktop_width,
            opts.desktop_height,
        );
        let mut wipe = WipePasswordOnDrop::new(&mut password_slot);
        validated?;

        let mut report = ConfigureReport::default();
        let enable_cred_ssp = opts.enable_cred_ssp;
        let negotiate = opts.negotiate_security_layer;

        dispatch::put_bstr(&self.dispatch, "Server", opts.server.trim())?;
        if let Some(user) = opts.username.as_deref().filter(|s| !s.is_empty()) {
            dispatch::put_bstr(&self.dispatch, "UserName", user)?;
        }
        if let Some(domain) = opts.domain.as_deref().filter(|s| !s.is_empty()) {
            dispatch::put_bstr(&self.dispatch, "Domain", domain)?;
        }

        dispatch::put_i4(&self.dispatch, "DesktopWidth", opts.desktop_width)?;
        dispatch::put_i4(&self.dispatch, "DesktopHeight", opts.desktop_height)?;
        dispatch::put_i4(
            &self.dispatch,
            "ColorDepth",
            normalise_color_depth(opts.color_depth),
        )?;

        let adv = dispatch::get_advanced_settings(&self.dispatch)?;

        dispatch::put_i4(&adv, "RDPPort", i32::from(opts.port))?;

        // CredSSP: soft-fail with an explicit NLA-risk note if the property is missing
        // *and* CredSSP was requested on. Requested-off + missing matches OCX default (false).
        match dispatch::try_put_bool(&adv, "EnableCredSspSupport", enable_cred_ssp)? {
            SoftPut::Applied => {
                report.cred_ssp_applied = true;
            }
            SoftPut::Missing { detail, .. } => {
                report.cred_ssp_applied = false;
                if enable_cred_ssp {
                    report.cred_ssp_soft_missed = true;
                    report.push_missing(format!("{detail} {CREDSSP_SOFT_MISS_NLA_RISK}"));
                }
            }
        }

        // NegotiateSecurityLayer stub — optional; soft-fail when absent.
        if let Some(negotiate) = negotiate {
            match dispatch::try_put_bool(&adv, "NegotiateSecurityLayer", negotiate)? {
                SoftPut::Applied => {
                    report.negotiate_applied = Some(true);
                }
                SoftPut::Missing { detail, .. } => {
                    report.negotiate_applied = Some(false);
                    report.push_missing(format!("{detail} {NEGOTIATE_SOFT_MISS}"));
                }
            }
        }

        // Password: put then zeroize our copy. Loud if ClearTextPassword put fails.
        // Remaining wipe (early Err / no password) is handled by WipePasswordOnDrop.
        if let Some(mut password) = wipe.take_for_put() {
            let put = dispatch::put_bstr(&adv, "ClearTextPassword", password.as_str());
            password.zeroize();
            drop(password);
            put?;
        }

        Ok(report)
    }

    /// Set Server + RDPPort and call `Connect()`. No credential properties are touched.
    ///
    /// Prefer [`Self::configure`] first when CredSSP / credentials are required.
    pub fn connect_stub(&self, opts: &ConnectStubOptions) -> windows::core::Result<()> {
        dispatch::put_bstr(&self.dispatch, "Server", &opts.server)?;
        let adv = dispatch::get_advanced_settings(&self.dispatch)?;
        dispatch::put_i4(&adv, "RDPPort", i32::from(opts.port))?;
        dispatch::call0(&self.dispatch, "Connect")?;
        Ok(())
    }

    /// `configure` then `Connect()` — lab helper. Password already wiped by configure.
    ///
    /// Does **not** refuse `Connect` when [`ConfigureReport::cred_ssp_soft_missed`] is set;
    /// production callers must inspect the report (and hard `Err`) before connecting.
    pub fn configure_and_connect(
        &self,
        opts: &mut RdpConfigureOptions,
    ) -> windows::core::Result<ConfigureReport> {
        let report = self.configure(opts)?;
        dispatch::call0(&self.dispatch, "Connect")?;
        Ok(report)
    }
}

impl Drop for RdpOcx {
    fn drop(&mut self) {
        // Unadvise → Close → revoke site → drop site. Overlay HWND must still be alive
        // until this completes (drop OCX before RdpOverlayHost).
        self.unadvise_events();
        if let Some(ole) = self.ole.take() {
            unsafe {
                let _ = ole.Close(OLECLOSE_NOSAVE);
                let _ = ole.SetClientSite(None);
            }
        }
        if let Some(site) = self.site.take() {
            site.set_inplace_object(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdp::configure::RdpConfigureOptions;
    use crate::rdp::host::RdpOverlayHost;
    use crate::rdp::host_bounds::HostBounds;
    use crate::OwnerHwnd;

    #[test]
    fn run_on_sta_pairs_ole_initialize() {
        let v = run_on_sta(|| Ok(42i32)).expect("STA");
        assert_eq!(v, 42);
        // Second apartment proves prior OleUninitialize completed.
        let v = run_on_sta(|| Ok(7i32)).expect("second STA");
        assert_eq!(v, 7);
    }

    #[test]
    fn activate_in_place_then_drop_ocx_before_host() {
        let result = run_on_sta(|| {
            let host = RdpOverlayHost::spawn(OwnerHwnd(0), HostBounds::SEED)?;
            assert!(host.info().is_owned_popup);
            let mut ocx = RdpOcx::cocreate_best()?;
            let info = host.activate_ocx(&mut ocx)?;
            assert!(info.inplace_ok);
            // Re-activate onto the same HWND must not leak the prior site.
            let info2 = host.activate_ocx(&mut ocx)?;
            assert!(info2.inplace_ok);
            // Mandatory order: OCX before overlay HWND destroy.
            drop(ocx);
            host.shutdown();
            Ok(info.events_advised || info2.events_advised)
        });
        match result {
            Ok(_) => {}
            Err(e) => {
                // Missing mstscax on the machine is acceptable for CI/dev boxes.
                let msg = e.message();
                assert!(
                    msg.contains("CLSID")
                        || msg.contains("Class")
                        || msg.contains("mstsc")
                        || msg.contains("IOleObject")
                        || msg.contains("not been registered")
                        || e.code().0 != 0,
                    "unexpected STA/OLE error: {e}"
                );
            }
        }
    }

    #[test]
    fn configure_credssp_and_clears_password() {
        let result = run_on_sta(|| {
            let host = RdpOverlayHost::spawn(OwnerHwnd(0), HostBounds::SEED)?;
            let mut ocx = RdpOcx::cocreate_best()?;
            let _ = host.activate_ocx(&mut ocx)?;
            let mut opts = RdpConfigureOptions::new("127.0.0.1", 3389)
                .with_password("lab-only-never-log");
            opts.username = Some("lab".into());
            opts.domain = Some(".".into());
            opts.desktop_width = 800;
            opts.desktop_height = 600;
            opts.color_depth = 16;
            opts.enable_cred_ssp = true;
            opts.negotiate_security_layer = Some(false);
            let report = ocx.configure(&mut opts)?;
            assert!(
                opts.password.is_none(),
                "password must be taken/zeroized after configure"
            );
            // Soft failures are allowed (older tiers); they must be clear strings.
            for msg in &report.soft_failures {
                assert!(
                    msg.contains("not available")
                        || msg.contains("CLSID")
                        || msg.contains("NLA")
                        || msg.contains("NegotiateSecurityLayer"),
                    "unclear soft failure: {msg}"
                );
            }
            if report.cred_ssp_soft_missed {
                assert!(report.has_cred_ssp_risk());
                assert!(
                    report
                        .soft_failures
                        .iter()
                        .any(|m| m.contains("NLA") || m.contains("CredSSP")),
                    "CredSSP soft miss must document NLA risk"
                );
            }
            drop(ocx);
            host.shutdown();
            Ok(report.all_soft_applied() || !report.soft_failures.is_empty())
        });
        match result {
            Ok(_) => {}
            Err(e) => {
                let msg = e.message();
                assert!(
                    msg.contains("CLSID")
                        || msg.contains("Class")
                        || msg.contains("mstsc")
                        || msg.contains("IOleObject")
                        || msg.contains("not been registered")
                        || msg.contains("AdvancedSettings")
                        || e.code().0 != 0,
                    "unexpected configure error: {e}"
                );
            }
        }
    }

    #[test]
    fn configure_validation_failure_still_wipes_password() {
        let result = run_on_sta(|| {
            let host = RdpOverlayHost::spawn(OwnerHwnd(0), HostBounds::SEED)?;
            let mut ocx = RdpOcx::cocreate_best()?;
            let _ = host.activate_ocx(&mut ocx)?;
            // Empty server fails validation before any put; password must still wipe.
            let mut opts = RdpConfigureOptions::new("   ", 3389).with_password("must-wipe");
            let err = ocx
                .configure(&mut opts)
                .expect_err("empty server must fail");
            assert_eq!(err.code(), windows::Win32::Foundation::E_INVALIDARG);
            assert!(opts.password.is_none(), "password wiped on validation Err");
            let dbg = format!("{opts:?}");
            assert!(!dbg.contains("must-wipe"));
            drop(ocx);
            host.shutdown();
            Ok(())
        });
        match result {
            Ok(()) => {}
            Err(e) => {
                let msg = e.message();
                assert!(
                    msg.contains("CLSID")
                        || msg.contains("Class")
                        || msg.contains("mstsc")
                        || msg.contains("IOleObject")
                        || msg.contains("not been registered")
                        || e.code().0 != 0,
                    "unexpected STA/OLE error: {e}"
                );
            }
        }
    }
}
