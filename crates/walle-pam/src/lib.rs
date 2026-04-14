#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;

use walle_daemon::runtime_lock_is_active;
use walle_daemon::ssh_overlay::{
    ExposedAuthInfoRecord, persist_exposed_auth_info, resolve_trap_identity_by_username,
};
use walle_policy::{SshJailPolicy, WalleConfig};

type PamHandle = c_void;

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;

const PAM_SERVICE: c_int = 1;
const PAM_RHOST: c_int = 4;
const PAM_AUTHTOK: c_int = 6;

const WALLE_TRAP_MARKER_ENV_NAME: &str = "WALLE_TRAP_IDENTITY";
const WALLE_TRAP_MARKER_ENV_VALUE: &str = "1";

#[cfg(not(test))]
mod ffi {
    use super::{PamHandle, c_char, c_int, c_void};

    unsafe extern "C" {
        fn pam_get_user(
            pamh: *mut PamHandle,
            user: *mut *const c_char,
            prompt: *const c_char,
        ) -> c_int;
        fn pam_get_item(
            pamh: *const PamHandle,
            item_type: c_int,
            item: *mut *const c_void,
        ) -> c_int;
        fn pam_putenv(pamh: *mut PamHandle, name_value: *const c_char) -> c_int;
        fn pam_getenv(pamh: *mut PamHandle, name: *const c_char) -> *const c_char;
    }

    pub(super) unsafe fn get_user(
        pamh: *mut PamHandle,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int {
        unsafe { pam_get_user(pamh, user, prompt) }
    }

    pub(super) unsafe fn get_item(
        pamh: *const PamHandle,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int {
        unsafe { pam_get_item(pamh, item_type, item) }
    }

    pub(super) unsafe fn putenv(pamh: *mut PamHandle, name_value: *const c_char) -> c_int {
        unsafe { pam_putenv(pamh, name_value) }
    }

    pub(super) unsafe fn getenv(pamh: *mut PamHandle, name: *const c_char) -> *const c_char {
        unsafe { pam_getenv(pamh, name) }
    }
}

#[cfg(test)]
mod ffi {
    use std::collections::BTreeMap;
    use std::ffi::{CStr, CString, c_char, c_int, c_void};
    use std::ptr;

    use super::{PAM_SUCCESS, PamHandle};

    const PAM_ABORT: c_int = 26;

    #[derive(Default)]
    pub(super) struct FakePamHandle {
        pub(super) user: Option<CString>,
        pub(super) items: BTreeMap<c_int, CString>,
        pub(super) env: BTreeMap<String, CString>,
    }

    impl FakePamHandle {
        pub(super) fn set_user(&mut self, value: &str) {
            self.user = CString::new(value).ok();
        }

        pub(super) fn set_item(&mut self, item_type: c_int, value: &str) {
            if let Ok(value) = CString::new(value) {
                self.items.insert(item_type, value);
            }
        }

        pub(super) fn env_value(&self, name: &str) -> Option<String> {
            self.env
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        }
    }

    pub(super) fn boxed_handle() -> Box<FakePamHandle> {
        Box::default()
    }

    fn fake_handle_mut<'a>(pamh: *mut PamHandle) -> Option<&'a mut FakePamHandle> {
        if pamh.is_null() {
            None
        } else {
            Some(unsafe { &mut *(pamh.cast::<FakePamHandle>()) })
        }
    }

    pub(super) unsafe fn get_user(
        pamh: *mut PamHandle,
        user: *mut *const c_char,
        _prompt: *const c_char,
    ) -> c_int {
        let Some(handle) = fake_handle_mut(pamh) else {
            return PAM_ABORT;
        };
        let Some(value) = handle.user.as_ref() else {
            return PAM_ABORT;
        };
        if user.is_null() {
            return PAM_ABORT;
        }
        unsafe {
            *user = value.as_ptr();
        }
        PAM_SUCCESS
    }

    pub(super) unsafe fn get_item(
        pamh: *const PamHandle,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int {
        if pamh.is_null() || item.is_null() {
            return PAM_ABORT;
        }
        let handle = unsafe { &*(pamh.cast::<FakePamHandle>()) };
        let Some(value) = handle.items.get(&item_type) else {
            return PAM_ABORT;
        };
        unsafe {
            *item = value.as_ptr().cast::<c_void>();
        }
        PAM_SUCCESS
    }

    pub(super) unsafe fn putenv(pamh: *mut PamHandle, name_value: *const c_char) -> c_int {
        let Some(handle) = fake_handle_mut(pamh) else {
            return PAM_ABORT;
        };
        if name_value.is_null() {
            return PAM_ABORT;
        }

        let Ok(assignment) = unsafe { CStr::from_ptr(name_value) }.to_str() else {
            return PAM_ABORT;
        };
        let Some((name, value)) = assignment.split_once('=') else {
            return PAM_ABORT;
        };
        let Ok(c_value) = CString::new(value) else {
            return PAM_ABORT;
        };
        handle.env.insert(name.to_string(), c_value);
        PAM_SUCCESS
    }

    pub(super) unsafe fn getenv(pamh: *mut PamHandle, name: *const c_char) -> *const c_char {
        let Some(handle) = fake_handle_mut(pamh) else {
            return ptr::null();
        };
        if name.is_null() {
            return ptr::null();
        }
        let Ok(name) = unsafe { CStr::from_ptr(name) }.to_str() else {
            return ptr::null();
        };
        handle
            .env
            .get(name)
            .map(|value| value.as_ptr())
            .unwrap_or(ptr::null())
    }
}

fn load_policy() -> Option<SshJailPolicy> {
    let config = WalleConfig::load_default().ok()?;
    Some(config.ssh_policy().gp.sshjail.clone())
}

fn pam_string_item(pamh: *mut PamHandle, item_type: c_int) -> Option<String> {
    let mut item: *const c_void = ptr::null();
    let status = unsafe { ffi::get_item(pamh.cast_const(), item_type, &mut item) };
    if status != PAM_SUCCESS || item.is_null() {
        return None;
    }

    let value = unsafe { CStr::from_ptr(item.cast()) }.to_str().ok()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn pam_username(pamh: *mut PamHandle) -> Option<String> {
    let mut user: *const c_char = ptr::null();
    let status = unsafe { ffi::get_user(pamh, &mut user, ptr::null()) };
    if status != PAM_SUCCESS || user.is_null() {
        return None;
    }

    let value = unsafe { CStr::from_ptr(user) }.to_str().ok()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn pam_env_value(pamh: *mut PamHandle, name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    let value = unsafe { ffi::getenv(pamh, name.as_ptr()) };
    if value.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(value) }.to_str().ok()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn put_pam_env(pamh: *mut PamHandle, name: &str, value: &str) -> bool {
    let assignment = match pam_env_assignment(name, value) {
        Some(assignment) => assignment,
        None => return false,
    };
    // Keep the backing buffer alive after pam_putenv in case the PAM
    // implementation retains the pointer instead of copying immediately.
    let raw = assignment.into_raw();
    unsafe { ffi::putenv(pamh, raw.cast_const()) == PAM_SUCCESS }
}

fn pam_env_assignment(name: &str, value: &str) -> Option<CString> {
    CString::new(format!("{}={}", name.trim(), value)).ok()
}

fn trap_policy_and_username(pamh: *mut PamHandle) -> Option<(SshJailPolicy, String)> {
    if !runtime_lock_is_active() {
        return None;
    }
    let policy = load_policy()?;
    let username = pam_username(pamh)?;
    Some((policy, username))
}

fn is_trap_identity(pamh: *mut PamHandle) -> Option<SshJailPolicy> {
    let (policy, username) = trap_policy_and_username(pamh)?;
    resolve_trap_identity_by_username(&policy, username.as_str())
        .ok()
        .flatten()
        .map(|_| policy)
}

fn persist_password_evidence(pamh: *mut PamHandle, policy: &SshJailPolicy) {
    let Some(username) = pam_username(pamh) else {
        return;
    };
    let record = ExposedAuthInfoRecord {
        service: pam_string_item(pamh, PAM_SERVICE).unwrap_or_else(|| "sshd".to_string()),
        username,
        auth_type: "password".to_string(),
        password: pam_string_item(pamh, PAM_AUTHTOK),
        rhost: pam_string_item(pamh, PAM_RHOST),
    };

    let Ok(path) = persist_exposed_auth_info(policy, &record) else {
        return;
    };

    let _ = put_pam_env(pamh, "SSH_USER_AUTH", path.display().to_string().as_str());
}

fn ensure_trap_marker_env(pamh: *mut PamHandle) {
    let _ = put_pam_env(
        pamh,
        WALLE_TRAP_MARKER_ENV_NAME,
        WALLE_TRAP_MARKER_ENV_VALUE,
    );
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let Some(policy) = is_trap_identity(pamh) else {
        return PAM_IGNORE;
    };

    ensure_trap_marker_env(pamh);
    persist_password_evidence(pamh, &policy);
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    if is_trap_identity(pamh).is_some() {
        PAM_SUCCESS
    } else {
        PAM_IGNORE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    if is_trap_identity(pamh).is_some() {
        PAM_SUCCESS
    } else {
        PAM_IGNORE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let Some(_policy) = is_trap_identity(pamh) else {
        return PAM_IGNORE;
    };

    if pam_env_value(pamh, WALLE_TRAP_MARKER_ENV_NAME).is_none() {
        ensure_trap_marker_env(pamh);
    }
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    if is_trap_identity(pamh).is_some() {
        PAM_SUCCESS
    } else {
        PAM_IGNORE
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PAM_AUTHTOK, PAM_RHOST, PAM_SERVICE, WALLE_TRAP_MARKER_ENV_NAME,
        WALLE_TRAP_MARKER_ENV_VALUE, ensure_trap_marker_env, ffi, pam_env_assignment,
        pam_env_value, pam_string_item, pam_username,
    };

    #[test]
    fn pam_env_assignment_renders_name_value_pairs() {
        let rendered = pam_env_assignment("SSH_USER_AUTH", "/tmp/test.auth")
            .unwrap()
            .into_string()
            .unwrap();
        assert_eq!(rendered, "SSH_USER_AUTH=/tmp/test.auth");
    }

    #[test]
    fn trap_marker_env_constants_are_stable() {
        assert_eq!(WALLE_TRAP_MARKER_ENV_NAME, "WALLE_TRAP_IDENTITY");
        assert_eq!(WALLE_TRAP_MARKER_ENV_VALUE, "1");
    }

    #[test]
    fn test_ffi_supports_string_items_and_env() {
        let mut pamh = ffi::boxed_handle();
        pamh.set_user("tomcat");
        pamh.set_item(PAM_SERVICE, "sshd");
        pamh.set_item(PAM_RHOST, "203.0.113.9");
        pamh.set_item(PAM_AUTHTOK, "hunter2");
        let raw = (&mut *pamh as *mut ffi::FakePamHandle).cast();

        assert_eq!(pam_username(raw), Some("tomcat".to_string()));
        assert_eq!(pam_string_item(raw, PAM_SERVICE), Some("sshd".to_string()));
        assert_eq!(
            pam_string_item(raw, PAM_RHOST),
            Some("203.0.113.9".to_string())
        );
        assert_eq!(
            pam_string_item(raw, PAM_AUTHTOK),
            Some("hunter2".to_string())
        );

        ensure_trap_marker_env(raw);
        assert_eq!(
            pam_env_value(raw, WALLE_TRAP_MARKER_ENV_NAME),
            Some(WALLE_TRAP_MARKER_ENV_VALUE.to_string())
        );
        assert_eq!(
            pamh.env_value(WALLE_TRAP_MARKER_ENV_NAME),
            Some(WALLE_TRAP_MARKER_ENV_VALUE.to_string())
        );
    }
}
