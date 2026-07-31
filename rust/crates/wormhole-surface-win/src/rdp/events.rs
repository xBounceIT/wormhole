//! `IMsTscAxEvents` connection-point sink for Connected / Disconnected / FatalError.
//!
//! IID matches C# `IMsTscAxEvents` / mstscax: `336D5562-EFA8-482E-8CB3-C5C0FC7A7DB6`.
//!
//! The sink vtable mirrors `IDispatch` (IUnknown + four methods) under the events IID so
//! `IConnectionPoint::Advise` QI succeeds and `Invoke` reaches our DISPID handlers.
//!
//! Crash-sentinel Clear belongs on **Connected**, **Disconnected**, and **FatalError**
//! (C# `RdpSessionViewModel` clears once the session leaves the in-flight danger window).

#![allow(non_snake_case)] // COM method names match IDispatch / typelib.

use std::cell::RefCell;
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

use windows::core::{implement, interface, IUnknown, IUnknown_Vtbl, GUID, HRESULT, PCWSTR};
use windows::Win32::Foundation::{E_NOTIMPL, S_OK};
use windows::Win32::System::Com::{DISPPARAMS, DISPATCH_FLAGS, EXCEPINFO};
use windows::Win32::System::Variant::{VARIANT, VT_I4};

/// IMsTscAxEvents dispinterface IID (same as C# `MsTscAxEventsSink`).
pub const IMS_TSC_AX_EVENTS_IID: GUID =
    GUID::from_u128(0x336D_5562_EFA8_482E_8CB3_C5C0_FC7A_7DB6);

/// Dispinterface sink: IDispatch-shaped vtable under the mstscax events IID.
#[interface("336D5562-EFA8-482E-8CB3-C5C0FC7A7DB6")]
pub unsafe trait IMsTscAxEvents: IUnknown {
    fn GetTypeInfoCount(&self, pctinfo: *mut u32) -> HRESULT;
    fn GetTypeInfo(&self, itinfo: u32, lcid: u32, pptinfo: *mut *mut c_void) -> HRESULT;
    fn GetIDsOfNames(
        &self,
        riid: *const GUID,
        rgsznames: *const PCWSTR,
        cnames: u32,
        lcid: u32,
        rgdispid: *mut i32,
    ) -> HRESULT;
    fn Invoke(
        &self,
        dispidmember: i32,
        riid: *const GUID,
        lcid: u32,
        wflags: DISPATCH_FLAGS,
        pdispparams: *const DISPPARAMS,
        pvarresult: *mut VARIANT,
        pexcepinfo: *mut EXCEPINFO,
        puargerr: *mut u32,
    ) -> HRESULT;
}

/// DISPID_OnConnected
pub(crate) const DISPID_CONNECTED: i32 = 2;
/// DISPID_OnDisconnected(int)
pub(crate) const DISPID_DISCONNECTED: i32 = 4;
/// DISPID_OnFatalError(int)
pub(crate) const DISPID_FATAL_ERROR: i32 = 10;

/// Shared STA-only event flags + lifecycle hooks (crash-sentinel Clear).
#[derive(Default)]
pub struct RdpEventState {
    /// `OnConnected` fired.
    pub connected: bool,
    /// `OnDisconnected` reason (if any).
    pub disconnected_reason: Option<i32>,
    /// `OnFatalError` code (if any).
    pub fatal_error: Option<i32>,
    /// Invoked when Connected fires (e.g. crash-sentinel Clear).
    on_connected: Option<Box<dyn FnMut()>>,
    /// Invoked when Disconnected fires (reason code).
    on_disconnected: Option<Box<dyn FnMut(i32)>>,
    /// Invoked when FatalError fires (error code).
    on_fatal_error: Option<Box<dyn FnMut(i32)>>,
}

impl RdpEventState {
    /// Install a Connected hook (replaced if called again).
    pub fn set_on_connected<F: FnMut() + 'static>(&mut self, f: F) {
        self.on_connected = Some(Box::new(f));
    }

    /// Install a Disconnected hook (replaced if called again).
    pub fn set_on_disconnected<F: FnMut(i32) + 'static>(&mut self, f: F) {
        self.on_disconnected = Some(Box::new(f));
    }

    /// Install a FatalError hook (replaced if called again).
    pub fn set_on_fatal_error<F: FnMut(i32) + 'static>(&mut self, f: F) {
        self.on_fatal_error = Some(Box::new(f));
    }

    /// Install the same Clear-style callback for Connected / Disconnected / FatalError.
    ///
    /// Matches C# clearing once the embedded session leaves the Mark danger window.
    pub fn set_on_sentinel_clear<F: FnMut() + 'static>(&mut self, f: F) {
        let shared = Rc::new(RefCell::new(f));
        let c1 = Rc::clone(&shared);
        let c2 = Rc::clone(&shared);
        let c3 = Rc::clone(&shared);
        self.on_connected = Some(Box::new(move || c1.borrow_mut()()));
        self.on_disconnected = Some(Box::new(move |_| c2.borrow_mut()()));
        self.on_fatal_error = Some(Box::new(move |_| c3.borrow_mut()()));
    }
}

/// Concrete COM sink advised on the MsRdpClient connection point.
#[implement(IMsTscAxEvents)]
pub struct MsTscAxEventsSink {
    state: Rc<RefCell<RdpEventState>>,
}

impl MsTscAxEventsSink {
    /// Create a sink sharing `state` with the STA driver.
    pub fn new(state: Rc<RefCell<RdpEventState>>) -> Self {
        Self { state }
    }
}

impl IMsTscAxEvents_Impl for MsTscAxEventsSink_Impl {
    unsafe fn GetTypeInfoCount(&self, pctinfo: *mut u32) -> HRESULT {
        if !pctinfo.is_null() {
            unsafe { *pctinfo = 0 };
        }
        S_OK
    }

    unsafe fn GetTypeInfo(
        &self,
        _itinfo: u32,
        _lcid: u32,
        pptinfo: *mut *mut c_void,
    ) -> HRESULT {
        if !pptinfo.is_null() {
            unsafe { *pptinfo = std::ptr::null_mut() };
        }
        E_NOTIMPL
    }

    unsafe fn GetIDsOfNames(
        &self,
        _riid: *const GUID,
        _rgsznames: *const PCWSTR,
        _cnames: u32,
        _lcid: u32,
        _rgdispid: *mut i32,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe fn Invoke(
        &self,
        dispidmember: i32,
        _riid: *const GUID,
        _lcid: u32,
        _wflags: DISPATCH_FLAGS,
        pdispparams: *const DISPPARAMS,
        _pvarresult: *mut VARIANT,
        _pexcepinfo: *mut EXCEPINFO,
        _puargerr: *mut u32,
    ) -> HRESULT {
        // Take hooks out before calling so user code can re-enter `RdpEventState`.
        // Mirror C# `MsTscAxEventsSink.Safe`: never let a Rust panic escape a COM callback.
        match dispidmember {
            DISPID_CONNECTED => {
                take_call_restore(
                    &self.state,
                    |st| {
                        st.connected = true;
                        st.on_connected.take()
                    },
                    |st, h| st.on_connected = Some(h),
                    |h| h(),
                );
            }
            DISPID_DISCONNECTED => {
                let reason = read_i4_arg(pdispparams, 0);
                take_call_restore(
                    &self.state,
                    |st| {
                        st.disconnected_reason = Some(reason);
                        st.on_disconnected.take()
                    },
                    |st, h| st.on_disconnected = Some(h),
                    |h| h(reason),
                );
            }
            DISPID_FATAL_ERROR => {
                let code = read_i4_arg(pdispparams, 0);
                take_call_restore(
                    &self.state,
                    |st| {
                        st.fatal_error = Some(code);
                        st.on_fatal_error.take()
                    },
                    |st, h| st.on_fatal_error = Some(h),
                    |h| h(code),
                );
            }
            _ => {}
        }
        S_OK
    }
}

/// Update state, take a hook, call it without holding `RefCell`, restore afterward.
fn take_call_restore<H>(
    state: &Rc<RefCell<RdpEventState>>,
    take: impl FnOnce(&mut RdpEventState) -> Option<H>,
    restore: impl FnOnce(&mut RdpEventState, H),
    call: impl FnOnce(&mut H),
) {
    let mut hook = {
        let mut st = state.borrow_mut();
        take(&mut st)
    };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(ref mut h) = hook {
            call(h);
        }
    }));
    if let Some(h) = hook {
        restore(&mut state.borrow_mut(), h);
    }
}

/// Build a counted sink.
pub fn create_events_sink(
    state: Rc<RefCell<RdpEventState>>,
) -> windows::core::ComObject<MsTscAxEventsSink> {
    windows::core::ComObject::new(MsTscAxEventsSink::new(state))
}

/// Sink as `IUnknown` for `IConnectionPoint::Advise`.
pub fn sink_unknown(sink: &windows::core::ComObject<MsTscAxEventsSink>) -> IUnknown {
    sink.to_interface()
}

fn read_i4_arg(params: *const DISPPARAMS, index: usize) -> i32 {
    if params.is_null() {
        return 0;
    }
    let params = unsafe { &*params };
    if params.rgvarg.is_null() || (params.cArgs as usize) <= index {
        return 0;
    }
    // DISPPARAMS args are in reverse order; index 0 is the last formal parameter.
    let v = unsafe { &*params.rgvarg.add(index) };
    unsafe {
        if (*v.Anonymous.Anonymous).vt == VT_I4 {
            (*v.Anonymous.Anonymous).Anonymous.lVal
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Variant::VariantInit;

    fn invoke_dispid(sink: &windows::core::ComObject<MsTscAxEventsSink>, dispid: i32, arg: Option<i32>) {
        let iface: IMsTscAxEvents = sink.to_interface();
        let mut storage;
        let params = if let Some(code) = arg {
            storage = unsafe { VariantInit() };
            unsafe {
                (*storage.Anonymous.Anonymous).vt = VT_I4;
                (*storage.Anonymous.Anonymous).Anonymous.lVal = code;
            }
            DISPPARAMS {
                rgvarg: &mut storage,
                rgdispidNamedArgs: std::ptr::null_mut(),
                cArgs: 1,
                cNamedArgs: 0,
            }
        } else {
            DISPPARAMS::default()
        };
        let hr = unsafe {
            iface.Invoke(
                dispid,
                &GUID::zeroed(),
                0,
                DISPATCH_FLAGS(0),
                &params,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(hr, S_OK);
    }

    #[test]
    fn connected_disconnected_fatal_update_state_and_hooks() {
        let state = Rc::new(RefCell::new(RdpEventState::default()));
        let connected_n = Rc::new(RefCell::new(0u32));
        let disc_codes = Rc::new(RefCell::new(Vec::new()));
        let fatal_codes = Rc::new(RefCell::new(Vec::new()));
        {
            let mut st = state.borrow_mut();
            let c = Rc::clone(&connected_n);
            st.set_on_connected(move || *c.borrow_mut() += 1);
            let d = Rc::clone(&disc_codes);
            st.set_on_disconnected(move |r| d.borrow_mut().push(r));
            let f = Rc::clone(&fatal_codes);
            st.set_on_fatal_error(move |c| f.borrow_mut().push(c));
        }

        let sink = create_events_sink(Rc::clone(&state));
        invoke_dispid(&sink, DISPID_CONNECTED, None);
        invoke_dispid(&sink, DISPID_DISCONNECTED, Some(2825));
        invoke_dispid(&sink, DISPID_FATAL_ERROR, Some(517));

        let st = state.borrow();
        assert!(st.connected);
        assert_eq!(st.disconnected_reason, Some(2825));
        assert_eq!(st.fatal_error, Some(517));
        assert_eq!(*connected_n.borrow(), 1);
        assert_eq!(*disc_codes.borrow(), vec![2825]);
        assert_eq!(*fatal_codes.borrow(), vec![517]);
    }

    #[test]
    fn sentinel_clear_hook_fires_on_all_three_lifecycle_events() {
        let state = Rc::new(RefCell::new(RdpEventState::default()));
        let clears = Rc::new(RefCell::new(0u32));
        {
            let c = Rc::clone(&clears);
            state
                .borrow_mut()
                .set_on_sentinel_clear(move || *c.borrow_mut() += 1);
        }
        let sink = create_events_sink(Rc::clone(&state));
        invoke_dispid(&sink, DISPID_CONNECTED, None);
        invoke_dispid(&sink, DISPID_DISCONNECTED, Some(1));
        invoke_dispid(&sink, DISPID_FATAL_ERROR, Some(2));
        assert_eq!(*clears.borrow(), 3);
    }

    #[test]
    fn hook_panic_is_swallowed_and_state_still_updates() {
        let state = Rc::new(RefCell::new(RdpEventState::default()));
        state.borrow_mut().set_on_connected(|| panic!("hook boom"));
        let sink = create_events_sink(Rc::clone(&state));
        invoke_dispid(&sink, DISPID_CONNECTED, None);
        assert!(state.borrow().connected);
        // Hook must be restored after panic so a later Connected can fire again.
        let fired = Rc::new(RefCell::new(false));
        {
            let f = Rc::clone(&fired);
            state.borrow_mut().set_on_connected(move || *f.borrow_mut() = true);
        }
        invoke_dispid(&sink, DISPID_CONNECTED, None);
        assert!(*fired.borrow());
    }

    #[test]
    fn hook_may_reenter_event_state() {
        let state = Rc::new(RefCell::new(RdpEventState::default()));
        let saw = Rc::new(RefCell::new(false));
        {
            let st_ref = Rc::clone(&state);
            let saw = Rc::clone(&saw);
            state.borrow_mut().set_on_connected(move || {
                // Re-enter while the Connected handler runs.
                assert!(st_ref.borrow().connected);
                *saw.borrow_mut() = true;
            });
        }
        let sink = create_events_sink(Rc::clone(&state));
        invoke_dispid(&sink, DISPID_CONNECTED, None);
        assert!(*saw.borrow());
    }

    #[test]
    fn missing_or_null_params_default_i4_to_zero() {
        let state = Rc::new(RefCell::new(RdpEventState::default()));
        let sink = create_events_sink(Rc::clone(&state));
        invoke_dispid(&sink, DISPID_DISCONNECTED, None);
        assert_eq!(state.borrow().disconnected_reason, Some(0));
        assert_eq!(read_i4_arg(std::ptr::null(), 0), 0);
    }
}
