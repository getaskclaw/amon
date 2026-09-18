//! Real-time process creation via WMI (`Win32_ProcessStartTrace`).
//!
//! Why this exists: a Toolhelp snapshot every second is fine, but a process that starts
//! and exits inside one tick is invisible to it. WMI pushes the event at creation time,
//! so nothing is missed. This restores the one capability the Rust rewrite had given up
//! relative to the PowerShell version, which used
//! `Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStartTrace"`.
//!
//! Implementation notes:
//! - `IWbemObjectSink_Impl` does not exist in windows-rs 0.58, so `#[implement]` is not
//!   available; the vtable is written out by hand.
//! - `IWbemServices::ExecNotificationQueryAsync` takes a `Param<IWbemObjectSink>`. There
//!   is no way to hand it a hand-rolled object through the safe wrapper, so the raw
//!   vtable entry is called directly with our pointer. WMI's only contract here is the
//!   vtable layout, which we match exactly.
//! - COM is per-thread, so everything lives on its own thread.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use windows::core::{GUID, HRESULT};
use windows::Win32::System::Wmi::{IWbemClassObject, IWbemServices};

use crate::event::{Event, Source};

const IID_IWBEMOBJECTSINK: GUID = GUID::from_u128(0x7c857801_7381_11cf_884d_00aa004b2e24);

/// Layout of `IWbemObjectSink`'s vtable, matching `IWbemObjectSink_Vtbl` in windows-rs.
/// `SetStatus`'s parameters are passed by value per the COM ABI, so anything the callee
/// does not read can be a raw pointer of the right size.
#[repr(C)]
struct SinkVtbl {
    query_interface: unsafe extern "system" fn(
        *mut std::ffi::c_void,
        *const GUID,
        *mut *mut std::ffi::c_void,
    ) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    indicate: unsafe extern "system" fn(
        *mut std::ffi::c_void,
        i32,
        *const *mut std::ffi::c_void,
    ) -> HRESULT,
    set_status: unsafe extern "system" fn(
        *mut std::ffi::c_void,
        i32,
        HRESULT,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
    ) -> HRESULT,
}

#[repr(C)]
struct ProcSink {
    vtbl: *const SinkVtbl,
    refs: AtomicU32,
    tx: Sender<Event>,
}

static SINK_VTBL: SinkVtbl = SinkVtbl {
    query_interface: sink_qi,
    add_ref: sink_add_ref,
    release: sink_release,
    indicate: sink_indicate,
    set_status: sink_set_status,
};

unsafe extern "system" fn sink_qi(
    this: *mut std::ffi::c_void,
    riid: *const GUID,
    ppv: *mut *mut std::ffi::c_void,
) -> HRESULT {
    if riid.is_null() || ppv.is_null() {
        return HRESULT(0x80004003u32 as i32); // E_POINTER
    }
    let iid = *riid;
    // IID_IUnknown
    if iid == GUID::from_u128(0x00000000_0000_0000_c000_000000000046) || iid == IID_IWBEMOBJECTSINK
    {
        *ppv = this;
        sink_add_ref(this);
        return HRESULT(0); // S_OK
    }
    *ppv = std::ptr::null_mut();
    HRESULT(0x80004002u32 as i32) // E_NOINTERFACE
}

unsafe extern "system" fn sink_add_ref(this: *mut std::ffi::c_void) -> u32 {
    let sink = &*(this as *const ProcSink);
    sink.refs.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn sink_release(this: *mut std::ffi::c_void) -> u32 {
    let sink = &*(this as *const ProcSink);
    let prev = sink.refs.fetch_sub(1, Ordering::SeqCst);
    if prev == 1 {
        drop(Box::from_raw(this as *mut ProcSink));
        0
    } else {
        prev - 1
    }
}

unsafe extern "system" fn sink_set_status(
    _this: *mut std::ffi::c_void,
    _flags: i32,
    _hr: HRESULT,
    _str: *mut std::ffi::c_void,
    _obj: *mut std::ffi::c_void,
) -> HRESULT {
    HRESULT(0)
}

/// WMI hands us an array of `IWbemClassObject`, one per event.
unsafe extern "system" fn sink_indicate(
    this: *mut std::ffi::c_void,
    count: i32,
    objects: *const *mut std::ffi::c_void,
) -> HRESULT {
    if this.is_null() || objects.is_null() || count <= 0 {
        return HRESULT(0);
    }
    let sink = &*(this as *const ProcSink);

    for i in 0..count as isize {
        let raw_ptr = *objects.offset(i);
        if raw_ptr.is_null() {
            continue;
        }
        // Borrow only: WMI keeps ownership of these objects.
        let Some(obj) = windows::core::from_raw_borrowed::<IWbemClassObject>(&raw_ptr) else {
            continue;
        };
        let name = get_string(obj, "ProcessName").unwrap_or_else(|| "?".to_string());
        let pid = get_u32(obj, "ProcessID").unwrap_or(0);
        let ppid = get_u32(obj, "ParentProcessID").unwrap_or(0);

        let _ = sink.tx.send(
            Event::new(Source::Proc, "started", name)
                .with_detail(serde_json::json!({ "pid": pid, "ppid": ppid, "via": "wmi" })),
        );
    }
    HRESULT(0)
}

fn get_string(obj: &IWbemClassObject, name: &str) -> Option<String> {
    /// VT_BSTR as the raw u16 stored in the internal variant layout.
    const VT_BSTR_RAW: u16 = 8;

    let mut var = windows::core::VARIANT::new();
    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        obj.Get(
            windows::core::PCWSTR(wname.as_ptr()),
            0,
            &mut var,
            None,
            None,
        )
        .ok()?;
        // VARIANT is opaque in windows-core 0.58. `as_raw()` exposes the C layout,
        // where vt is a plain u16 and the BSTR is a raw pointer.
        let raw = var.as_raw();
        if raw.Anonymous.Anonymous.vt != VT_BSTR_RAW {
            return None;
        }
        let ptr = raw.Anonymous.Anonymous.Anonymous.bstrVal;
        if ptr.is_null() {
            return None;
        }
        // Copy the string out, then forget the wrapper: the BSTR belongs to the
        // VARIANT (and thus to WMI), so it must not be freed here.
        let s = windows::core::BSTR::from_raw(ptr);
        let out = s.to_string();
        std::mem::forget(s);
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

fn get_u32(obj: &IWbemClassObject, name: &str) -> Option<u32> {
    const VT_I4_RAW: u16 = 3;
    const VT_UI4_RAW: u16 = 19;

    let mut var = windows::core::VARIANT::new();
    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        obj.Get(
            windows::core::PCWSTR(wname.as_ptr()),
            0,
            &mut var,
            None,
            None,
        )
        .ok()?;
        let raw = var.as_raw();
        match raw.Anonymous.Anonymous.vt {
            VT_I4_RAW => Some(raw.Anonymous.Anonymous.Anonymous.lVal as u32),
            VT_UI4_RAW => Some(raw.Anonymous.Anonymous.Anonymous.ulVal),
            _ => None,
        }
    }
}

/// Subscribe to `Win32_ProcessStartTrace` on a dedicated thread.
///
/// Emits `meta/proc_trace_ok` on success, or `meta/proc_trace_unavailable` with the
/// HRESULT and the failing call, so a dead subscription can never be mistaken for a
/// quiet system.
pub fn spawn_wmi_proc_watcher(
    tx: Sender<Event>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use windows::core::BSTR;
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket,
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
        };
        use windows::Win32::System::Wmi::{IWbemLocator, WbemLocator};

        let fail = |call: &str, hr: i64| {
            let _ = tx.send(
                Event::new(Source::Meta, "proc_trace_unavailable", call).with_detail(
                    serde_json::json!({ "hresult": format!("{hr:#x}"), "call": call }),
                ),
            );
        };

        unsafe {
            let init = CoInitializeEx(None, COINIT_MULTITHREADED);
            // RPC_E_CHANGED_MODE: COM already initialised on this thread; still usable.
            if init.is_err() && init.0 != 0x80010106u32 as i32 {
                fail("CoInitializeEx", init.0 as i64);
                return;
            }

            // Process-wide security; ignore "already set" (0x80010119).
            let sec = CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            );
            if let Err(e) = &sec {
                // 0x80010119 = RPC_E_TOO_LATE: security already set, which is fine.
                if e.code().0 as u32 != 0x80010119 {
                    fail("CoInitializeSecurity", e.code().0 as i64);
                    return;
                }
            }

            let locator: IWbemLocator =
                match CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) {
                    Ok(l) => l,
                    Err(e) => {
                        fail("CoCreateInstance(WbemLocator)", e.code().0 as i64);
                        return;
                    }
                };

            // The raw IWbemLocator wants the namespace as the network resource.
            let services: IWbemServices = match locator.ConnectServer(
                &BSTR::from("ROOT\\CIMV2"),
                &BSTR::from(""),
                &BSTR::from(""),
                &BSTR::from(""),
                0,
                &BSTR::from(""),
                None,
            ) {
                Ok(s) => s,
                Err(e) => {
                    fail("ConnectServer(ROOT\\CIMV2)", e.code().0 as i64);
                    return;
                }
            };

            // Without this the callback is rejected and the subscription stays silent.
            // Use explicit values rather than the "default" placeholders, which RPC
            // rejects with "the authentication level is unknown" (0x800706d4).
            // RPC_C_AUTHN_WINNT = 10, RPC_C_AUTHZ_NONE = 0.
            if let Err(e) = CoSetProxyBlanket(
                &services,
                10, // dwAuthnSvc = RPC_C_AUTHN_WINNT
                0,  // dwAuthzSvc = RPC_C_AUTHZ_NONE
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            ) {
                fail("CoSetProxyBlanket", e.code().0 as i64);
                return;
            }

            let sink = Box::new(ProcSink {
                vtbl: &SINK_VTBL,
                refs: AtomicU32::new(1),
                tx: tx.clone(),
            });
            let sink_ptr = Box::into_raw(sink) as *mut std::ffi::c_void;

            let lang = BSTR::from("WQL");
            let query = BSTR::from("SELECT * FROM Win32_ProcessStartTrace");

            // Call the raw vtable entry: the safe wrapper demands a real
            // IWbemObjectSink, and WMI only cares that the vtable matches.
            let vtbl = windows::core::Interface::vtable(&services);
            let hr = (vtbl.ExecNotificationQueryAsync)(
                windows::core::Interface::as_raw(&services),
                std::mem::transmute_copy(&lang),
                std::mem::transmute_copy(&query),
                windows::Win32::System::Wmi::WBEM_GENERIC_FLAG_TYPE(0), // lFlags
                std::ptr::null_mut(),
                sink_ptr,
            );

            if hr.is_err() {
                fail("ExecNotificationQueryAsync", hr.0 as i64);
                sink_release(sink_ptr);
                return;
            }

            let _ = tx.send(
                Event::new(Source::Meta, "proc_trace_ok", "Win32_ProcessStartTrace")
                    .with_detail(serde_json::json!({ "via": "wmi-async", "query": "SELECT * FROM Win32_ProcessStartTrace" })),
            );

            // Keep the subscription and our sink alive until shutdown.
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            sink_release(sink_ptr);
        }
    })
}
