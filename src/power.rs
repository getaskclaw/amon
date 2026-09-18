//! Suspend / resume tracking.
//!
//! Why this exists: amon only sees what happens while Windows is awake. A laptop
//! that sleeps every night has a blind window whose size nobody can see afterwards
//! — file and registry changes are recoverable by diffing state, but process
//! creations during the gap are gone forever.
//!
//! Measured on the first deployment target: 22 sleeps in 7 days totalling 64.9 h
//! (38.6% of wall time), i.e. real coverage was 61.4% while the process still
//! reported itself healthy. The monitor cannot claim "nothing happened" for a
//! period it was not running, so it now records the gap explicitly.
//!
//! Mechanism: `PowerRegisterSuspendResumeNotification` with
//! `DEVICE_NOTIFY_CALLBACK`. Windows calls the routine with `PBT_APMSUSPEND` just
//! before sleeping and `PBT_APMRESUMEAUTOMATIC` on wake. No window, no message
//! pump, no polling.

use std::sync::mpsc::Sender;

use crate::event::{Event, Source};
use crate::hostname;

// Power event codes (winuser.h). windows-rs 0.58 does not export these as
// constants in the Power module, so they are spelled out here.
const PBT_APMSUSPEND: u32 = 0x0004;
const PBT_APMRESUMESUSPEND: u32 = 0x0007;
const PBT_APMRESUMEAUTOMATIC: u32 = 0x0012;
const PBT_APMRESUMECRITICAL: u32 = 0x0006;

/// Context handed to the C callback. Boxed and leaked on purpose: the
/// registration outlives this function and Windows may call back at any time,
/// including during shutdown.
struct Ctx {
    tx: Sender<Event>,
}

/// Register for suspend/resume. Returns `false` if registration failed, and
/// emits `power_watch_unavailable` so the heartbeat can report the gap.
#[cfg(windows)]
pub fn spawn_power_watcher(tx: Sender<Event>) -> bool {
    use windows::Win32::System::Power::{
        PowerRegisterSuspendResumeNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS,
    };
    use windows::Win32::UI::WindowsAndMessaging::DEVICE_NOTIFY_CALLBACK;

    let ctx = Box::into_raw(Box::new(Ctx { tx: tx.clone() }));

    let params = DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
        Callback: Some(power_callback),
        Context: ctx as *mut core::ffi::c_void,
    };

    let mut reg: *mut core::ffi::c_void = std::ptr::null_mut();
    let rc = unsafe {
        PowerRegisterSuspendResumeNotification(
            DEVICE_NOTIFY_CALLBACK,
            windows::Win32::Foundation::HANDLE(&params as *const _ as *mut core::ffi::c_void),
            &mut reg,
        )
    };

    if rc.0 != 0 {
        let _ = tx.send(
            Event::new(Source::Meta, "power_watch_unavailable", hostname()).with_detail(
                serde_json::json!({ "error": format!("PowerRegisterSuspendResumeNotification rc={}", rc.0) }),
            ),
        );
        // Reclaim the box we just leaked; the callback will never fire.
        unsafe { drop(Box::from_raw(ctx)) };
        return false;
    }

    let _ = tx.send(
        Event::new(Source::Meta, "power_watch_ok", hostname())
            .with_detail(serde_json::json!({ "via": "PowerRegisterSuspendResumeNotification" })),
    );
    true
}

#[cfg(windows)]
unsafe extern "system" fn power_callback(
    context: *const core::ffi::c_void,
    r#type: u32,
    _setting: *const core::ffi::c_void,
) -> u32 {
    if context.is_null() {
        return 0;
    }
    let ctx = &*(context as *const Ctx);

    let (action, human) = match r#type {
        PBT_APMSUSPEND => ("suspended", "机器进入睡眠/挂起"),
        PBT_APMRESUMEAUTOMATIC => ("resumed", "机器自动唤醒"),
        PBT_APMRESUMESUSPEND => ("resumed", "机器被用户唤醒"),
        PBT_APMRESUMECRITICAL => ("resumed", "机器从严重状态唤醒"),
        _ => return 0,
    };

    // The sleep event must reach the log *before* the machine actually stops, so
    // this write is deliberately synchronous rather than queued-and-forgotten:
    // the channel send below hands it to the main loop, which flushes
    // immediately. Nothing here may block — Windows is waiting on us.
    let mut ev = Event::new(Source::Power, action, hostname());
    ev = ev.with_detail(serde_json::json!({
        "powerEvent": r#type,
        "note": human,
        // Recorded so a later patrol can say "状态类变化可靠，进程类不可靠" for
        // exactly the window this marks the start of.
        "gapRisk": if action == "suspended" { "suspend_begin" } else { "suspend_end" },
    }));
    let _ = ctx.tx.send(ev);

    0
}

#[cfg(not(windows))]
pub fn spawn_power_watcher(_tx: Sender<Event>) -> bool {
    false
}
