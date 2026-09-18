//! Filesystem + registry + device change notifications.
//!
//! This is the part that makes a native build worth it: instead of polling the
//! watched directory every few seconds, the kernel tells us. `ReadDirectoryChangesW`
//! covers the install dir, `RegNotifyChangeKeyValue` covers the autostart keys, and
//! `CM_Register_Notification` covers USB volume arrival — the capability the scripted
//! version simply did not have.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

use crate::event::{Event, Source};

// ---------------------------------------------------------------- directory

#[cfg(windows)]
pub fn spawn_dir_watcher(
    dir: PathBuf,
    tx: Sender<Event>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY,
            FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_CREATION,
            FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
            FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };

        let wide: Vec<u16> = dir
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            // dwDesiredAccess is a plain u32 in this binding set.
            let h = match CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_LIST_DIRECTORY.0, // 0x0001
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            ) {
                Ok(h) if h != INVALID_HANDLE_VALUE => h,
                _ => {
                    let _ = tx.send(
                        Event::new(Source::Meta, "dir_watch_unavailable", dir.to_string_lossy())
                            .with_detail(serde_json::json!({
                                "reason": "CreateFileW on directory failed (permissions?)",
                                "path": dir.to_string_lossy(),
                            })),
                    );
                    return;
                }
            };

            let mut buf = vec![0u8; 64 * 1024];
            let filter = FILE_NOTIFY_CHANGE_FILE_NAME
                | FILE_NOTIFY_CHANGE_DIR_NAME
                | FILE_NOTIFY_CHANGE_LAST_WRITE
                | FILE_NOTIFY_CHANGE_SIZE
                | FILE_NOTIFY_CHANGE_CREATION
                | FILE_NOTIFY_CHANGE_ATTRIBUTES;

            // Report the successful open, so the heartbeat distinguishes "watching"
            // from "silently failed to open". (dir=false on a healthy system was a
            // false alarm caused by staying silent here.)
            let _ = tx.send(
                Event::new(Source::Meta, "dir_watch_ok", dir.to_string_lossy())
                    .with_detail(serde_json::json!({ "recursive": true })),
            );

            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let mut returned = 0u32;
                let ok = ReadDirectoryChangesW(
                    h,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    true, // recursive
                    filter,
                    Some(&mut returned),
                    None,
                    None,
                )
                .is_ok();

                if !ok {
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                if returned > 0 {
                    let names = parse_notify_buffer(&buf[..returned as usize]);
                    let _ = tx.send(
                        Event::new(Source::File, "dir_changed", dir.to_string_lossy())
                            .with_detail(serde_json::json!({ "paths": names })),
                    );
                }
            }
            let _ = CloseHandle(h);
        }
    })
}

/// `FILE_NOTIFY_INFORMATION` is a self-relative linked list of UTF-16 names.
#[cfg(windows)]
fn parse_notify_buffer(buf: &[u8]) -> Vec<String> {
    use windows::Win32::Storage::FileSystem::FILE_NOTIFY_INFORMATION;
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        if offset + std::mem::size_of::<FILE_NOTIFY_INFORMATION>() > buf.len() {
            break;
        }
        let info = unsafe { &*(buf.as_ptr().add(offset) as *const FILE_NOTIFY_INFORMATION) };
        let name_bytes = info.FileNameLength as usize;
        // struct is (u32 NextEntryOffset, u32 Action, u32 FileNameLength, WCHAR[1])
        let name_start = offset + 12;
        if name_start + name_bytes > buf.len() {
            break;
        }
        let words: Vec<u16> = buf[name_start..name_start + name_bytes]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(String::from_utf16_lossy(&words));
        if info.NextEntryOffset == 0 {
            break;
        }
        offset += info.NextEntryOffset as usize;
    }
    out.truncate(50);
    out
}

// ---------------------------------------------------------------- registry

#[cfg(windows)]
pub fn spawn_reg_watcher(
    subkey: &'static str,
    label: &'static str,
    use_user_hive: bool,
    tx: Sender<Event>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
            HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_NOTIFY, KEY_READ, REG_NOTIFY_CHANGE_LAST_SET,
        };

        // Mirror the snapshot logic: when the user keys are being watched from a SYSTEM
        // process, HKEY_CURRENT_USER is SYSTEM's hive and the watch would sit on the
        // wrong key (or fail to open). Use HKEY_USERS\<sid> instead.
        let (hive, full_sub): (HKEY, String) = if use_user_hive {
            match crate::snapshot::current_user_sid() {
                Some(sid) => (HKEY_USERS, format!("{sid}\\{subkey}")),
                None => (HKEY_CURRENT_USER, subkey.to_string()),
            }
        } else {
            (HKEY_LOCAL_MACHINE, subkey.to_string())
        };

        let wide: Vec<u16> = full_sub.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey = HKEY::default();
            if RegOpenKeyExW(
                hive,
                PCWSTR(wide.as_ptr()),
                0,
                KEY_NOTIFY | KEY_READ,
                &mut hkey,
            )
            .is_err()
            {
                let _ = tx.send(
                    Event::new(
                        Source::Meta,
                        "reg_watch_unavailable",
                        format!("{label}: {full_sub}"),
                    )
                    .with_detail(serde_json::json!({
                        "hive": if use_user_hive { "HKEY_USERS" } else { "HKLM" },
                        "subkey": full_sub,
                        "sid_resolved": crate::snapshot::current_user_sid(),
                    })),
                );
                return;
            }

            // Report success explicitly: an open that works must be distinguishable from
            // one that silently failed, or a dark channel looks like a quiet system.
            let _ = tx.send(
                Event::new(Source::Meta, "reg_watch_ok", label)
                    .with_detail(serde_json::json!({ "subkey": full_sub })),
            );

            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                // Blocks until the key changes.
                let rc =
                    RegNotifyChangeKeyValue(hkey, true, REG_NOTIFY_CHANGE_LAST_SET, None, false);
                if rc.is_err() {
                    std::thread::sleep(Duration::from_secs(3));
                    continue;
                }
                let _ = tx.send(
                    Event::new(Source::Reg, "key_changed", label)
                        .with_detail(serde_json::json!({ "subkey": subkey })),
                );
            }
            let _ = RegCloseKey(hkey);
        }
    })
}

// ---------------------------------------------------------------- devices

/// USB / volume arrival notifications.
///
/// The signature in windows 0.58 is
/// `PCM_NOTIFY_CALLBACK = Option<unsafe extern "system" fn(HCMNOTIFICATION, *const c_void, CM_NOTIFY_ACTION, *const CM_NOTIFY_EVENT_DATA, u32) -> u32>`
/// and the return type is `CONFIGRET`, not a plain integer.
#[cfg(windows)]
pub fn spawn_device_watcher(
    tx: Sender<Event>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Register_Notification, CM_NOTIFY_FILTER, CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
        CONFIGRET,
    };

    /// GUID_DEVINTERFACE_VOLUME, written out so we need no GUID dependency.
    const GUID_DEVINTERFACE_VOLUME: windows::core::GUID =
        windows::core::GUID::from_u128(0x53f5630d_b6bf_11d0_94f6_00a0c91efb8b);

    std::thread::spawn(move || {
        unsafe extern "system" fn cb(
            _notify: windows::Win32::Devices::DeviceAndDriverInstallation::HCMNOTIFICATION,
            context: *const std::ffi::c_void,
            action: windows::Win32::Devices::DeviceAndDriverInstallation::CM_NOTIFY_ACTION,
            _event: *const windows::Win32::Devices::DeviceAndDriverInstallation::CM_NOTIFY_EVENT_DATA,
            _size: u32,
        ) -> u32 {
            if context.is_null() {
                return 0;
            }
            let ctx = &*(context as *const Sender<Event>);
            let _ = ctx.send(
                Event::new(Source::Device, "volume_event", "device").with_detail(
                    serde_json::json!({
                        "action_id": action.0,
                        "note": "volume interface notification received",
                    }),
                ),
            );
            0
        }

        unsafe {
            let mut filter = CM_NOTIFY_FILTER {
                cbSize: std::mem::size_of::<CM_NOTIFY_FILTER>() as u32,
                Flags: 0,
                FilterType: CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
                Reserved: 0,
                u: std::mem::zeroed(),
            };
            filter.u.DeviceInterface.ClassGuid = GUID_DEVINTERFACE_VOLUME;

            let boxed = Box::new(tx.clone());
            let ctx_ptr = Box::into_raw(boxed) as *const std::ffi::c_void;

            let mut handle = std::mem::zeroed();
            let rc: CONFIGRET =
                CM_Register_Notification(&filter, Some(ctx_ptr), Some(cb), &mut handle);
            if rc != CONFIGRET(0) {
                let _ = tx.send(
                    Event::new(
                        Source::Meta,
                        "device_watch_unavailable",
                        "CM_Register_Notification",
                    )
                    .with_detail(serde_json::json!({ "configret": rc.0 })),
                );
                // Reclaim the box we leaked above.
                drop(Box::from_raw(ctx_ptr as *mut Sender<Event>));
                return;
            }
            let _ = tx.send(Event::new(
                Source::Meta,
                "device_watch_ok",
                "GUID_DEVINTERFACE_VOLUME",
            ));

            // Keep this thread alive: the callback context lives in it.
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
            }
            // The notification is unregistered when the process exits.
        }
    })
}

// ---------------------------------------------------------------- non-windows stubs

#[cfg(not(windows))]
pub fn spawn_dir_watcher(
    _dir: PathBuf,
    _tx: Sender<Event>,
    _stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(|| {})
}

#[cfg(not(windows))]
pub fn spawn_reg_watcher(
    _subkey: &'static str,
    _label: &'static str,
    _use_user_hive: bool,
    _tx: Sender<Event>,
    _stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(|| {})
}

#[cfg(not(windows))]
pub fn spawn_device_watcher(
    _tx: Sender<Event>,
    _stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(|| {})
}

/// Does this path look interesting enough to log loudly?
pub fn is_interesting_path(p: &Path) -> bool {
    p.to_string_lossy().to_ascii_lowercase().contains("cursor")
}
