//! Minimal IDispatch helpers for MsRdpClient property / method access (windows 0.61).

use std::mem::ManuallyDrop;

use windows::core::{BSTR, HRESULT, PCWSTR};
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{
    IDispatch, DISPATCH_FLAGS, DISPATCH_METHOD, DISPATCH_PROPERTYGET, DISPATCH_PROPERTYPUT,
    DISPPARAMS, EXCEPINFO,
};
use windows::Win32::System::Variant::{
    VariantClear, VariantInit, VARIANT, VT_BOOL, VT_BSTR, VT_DISPATCH, VT_EMPTY, VT_I4,
};

/// `DISP_E_UNKNOWNNAME` — property/method not on this IDispatch tier.
const DISP_E_UNKNOWNNAME: HRESULT = HRESULT(0x80020006u32 as i32);
/// `DISP_E_MEMBERNOTFOUND`.
const DISP_E_MEMBERNOTFOUND: HRESULT = HRESULT(0x80020003u32 as i32);

/// Outcome of a soft property put (CredSSP / NegotiateSecurityLayer stubs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SoftPut {
    /// Property was set.
    Applied,
    /// Name missing on this CLSID / AdvancedSettings tier — caller may continue.
    Missing { property: String, detail: String },
}

pub(crate) fn put_bstr(disp: &IDispatch, name: &str, value: &str) -> windows::core::Result<()> {
    let mut args = [bstr_variant(value)];
    let result = invoke(disp, name, DISPATCH_PROPERTYPUT, &mut args, None);
    clear_variant(&mut args[0]);
    result
}

pub(crate) fn put_i4(disp: &IDispatch, name: &str, value: i32) -> windows::core::Result<()> {
    let mut args = [i4_variant(value)];
    let result = invoke(disp, name, DISPATCH_PROPERTYPUT, &mut args, None);
    clear_variant(&mut args[0]);
    result
}

#[allow(dead_code)] // loud bool put kept for parity with soft path
pub(crate) fn put_bool(disp: &IDispatch, name: &str, value: bool) -> windows::core::Result<()> {
    let mut args = [bool_variant(value)];
    let result = invoke(disp, name, DISPATCH_PROPERTYPUT, &mut args, None);
    clear_variant(&mut args[0]);
    result
}

/// Soft put: missing property name → [`SoftPut::Missing`] with a clear message; other errors
/// propagate as hard `Err`.
pub(crate) fn try_put_bool(
    disp: &IDispatch,
    name: &str,
    value: bool,
) -> windows::core::Result<SoftPut> {
    let mut args = [bool_variant(value)];
    let result = invoke(disp, name, DISPATCH_PROPERTYPUT, &mut args, None);
    clear_variant(&mut args[0]);
    map_soft(name, result)
}

pub(crate) fn get_dispatch(disp: &IDispatch, name: &str) -> windows::core::Result<IDispatch> {
    let mut result = unsafe { VariantInit() };
    let invoke_result = invoke(
        disp,
        name,
        DISPATCH_PROPERTYGET,
        &mut [],
        Some(&mut result),
    );
    if let Err(e) = invoke_result {
        clear_variant(&mut result);
        return Err(e);
    }
    let out = unsafe {
        if (*result.Anonymous.Anonymous).vt != VT_DISPATCH {
            clear_variant(&mut result);
            return Err(windows::core::Error::from(HRESULT(0x80020005u32 as i32)));
        }
        let opt = &mut (*result.Anonymous.Anonymous).Anonymous.pdispVal;
        let ptr = opt.take();
        (*result.Anonymous.Anonymous).vt = VT_EMPTY;
        match ptr {
            Some(d) => d,
            None => {
                clear_variant(&mut result);
                return Err(windows::core::Error::from(HRESULT(0x80004003u32 as i32)));
            }
        }
    };
    clear_variant(&mut result);
    Ok(out)
}

/// Prefer `AdvancedSettings9`, fall back to `AdvancedSettings2` (C# parity).
pub(crate) fn get_advanced_settings(disp: &IDispatch) -> windows::core::Result<IDispatch> {
    get_dispatch(disp, "AdvancedSettings9").or_else(|_| get_dispatch(disp, "AdvancedSettings2"))
}

pub(crate) fn call0(disp: &IDispatch, name: &str) -> windows::core::Result<()> {
    invoke(disp, name, DISPATCH_METHOD, &mut [], None)?;
    Ok(())
}

fn map_soft(property: &str, result: windows::core::Result<()>) -> windows::core::Result<SoftPut> {
    match result {
        Ok(()) => Ok(SoftPut::Applied),
        Err(e) if is_missing_member(e.code()) => Ok(SoftPut::Missing {
            property: property.to_string(),
            detail: format!(
                "IDispatch property '{property}' is not available on this MsRdpClient CLSID tier \
                 (GetIDsOfNames/Invoke: {e}). Falling back to the OCX default."
            ),
        }),
        Err(e) => Err(e),
    }
}

fn is_missing_member(code: HRESULT) -> bool {
    code == DISP_E_UNKNOWNNAME || code == DISP_E_MEMBERNOTFOUND
}

fn invoke(
    disp: &IDispatch,
    name: &str,
    flags: DISPATCH_FLAGS,
    args: &mut [VARIANT],
    result: Option<&mut VARIANT>,
) -> windows::core::Result<()> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut dispid = 0i32;
    unsafe {
        disp.GetIDsOfNames(
            &windows::core::GUID::zeroed(),
            &PCWSTR(wide.as_ptr()),
            1,
            0,
            &mut dispid,
        )?;
    }

    let mut excep = EXCEPINFO::default();
    let mut arg_err = 0u32;
    let mut params = DISPPARAMS::default();
    let mut named_put: i32 = -3; // DISPID_PROPERTYPUT
    if !args.is_empty() {
        args.reverse();
        params.rgvarg = args.as_mut_ptr();
        params.cArgs = args.len() as u32;
        if flags == DISPATCH_PROPERTYPUT {
            params.rgdispidNamedArgs = &mut named_put;
            params.cNamedArgs = 1;
        }
    }

    let hr = unsafe {
        disp.Invoke(
            dispid,
            &windows::core::GUID::zeroed(),
            0,
            flags,
            &params,
            result.map(|r| r as *mut VARIANT),
            Some(&mut excep),
            Some(&mut arg_err),
        )
    };
    if !args.is_empty() {
        args.reverse();
    }
    hr
}

fn bstr_variant(value: &str) -> VARIANT {
    let mut v = unsafe { VariantInit() };
    let bstr = BSTR::from(value);
    unsafe {
        (*v.Anonymous.Anonymous).vt = VT_BSTR;
        (*v.Anonymous.Anonymous).Anonymous.bstrVal = ManuallyDrop::new(bstr);
    }
    v
}

fn i4_variant(value: i32) -> VARIANT {
    let mut v = unsafe { VariantInit() };
    unsafe {
        (*v.Anonymous.Anonymous).vt = VT_I4;
        (*v.Anonymous.Anonymous).Anonymous.lVal = value;
    }
    v
}

fn bool_variant(value: bool) -> VARIANT {
    let mut v = unsafe { VariantInit() };
    unsafe {
        (*v.Anonymous.Anonymous).vt = VT_BOOL;
        (*v.Anonymous.Anonymous).Anonymous.boolVal = VARIANT_BOOL(if value { -1 } else { 0 });
    }
    v
}

fn clear_variant(v: &mut VARIANT) {
    unsafe {
        let _ = VariantClear(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_member_hresults() {
        assert!(is_missing_member(DISP_E_UNKNOWNNAME));
        assert!(is_missing_member(DISP_E_MEMBERNOTFOUND));
        assert!(!is_missing_member(HRESULT(0x80004005u32 as i32)));
    }

    #[test]
    fn map_soft_missing_vs_hard() {
        let soft = map_soft(
            "EnableCredSspSupport",
            Err(windows::core::Error::from(DISP_E_UNKNOWNNAME)),
        )
        .expect("soft");
        match soft {
            SoftPut::Missing { property, detail } => {
                assert_eq!(property, "EnableCredSspSupport");
                assert!(detail.contains("not available"));
                assert!(detail.contains("CLSID"));
            }
            SoftPut::Applied => panic!("expected Missing"),
        }

        let hard = map_soft(
            "Server",
            Err(windows::core::Error::from(HRESULT(0x80004005u32 as i32))),
        );
        assert!(hard.is_err());
    }
}
