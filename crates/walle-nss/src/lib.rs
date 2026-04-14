#![cfg(target_os = "linux")]

use std::ffi::c_char;
use std::mem::{align_of, size_of};
use std::ptr;

use libc::{c_int, gid_t, size_t, uid_t};
use walle_daemon::runtime_lock_is_active;
use walle_daemon::ssh_overlay::{
    TrapIdentityRecord, resolve_trap_identity_by_uid, resolve_trap_identity_by_username,
};
use walle_policy::WalleConfig;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NssStatus {
    TryAgain = -2,
    Unavail = -1,
    NotFound = 0,
    Success = 1,
}

struct BufferWriter {
    base: *mut u8,
    len: usize,
    offset: usize,
}

impl BufferWriter {
    unsafe fn new(buffer: *mut c_char, buflen: usize) -> Self {
        Self {
            base: buffer.cast(),
            len: buflen,
            offset: 0,
        }
    }

    unsafe fn write_c_string(&mut self, value: &str) -> Option<*mut c_char> {
        let bytes = value.as_bytes();
        let required = bytes.len().saturating_add(1);
        if self.offset.saturating_add(required) > self.len {
            return None;
        }
        let ptr = unsafe { self.base.add(self.offset) };
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            *ptr.add(bytes.len()) = 0;
        }
        self.offset += required;
        Some(ptr.cast())
    }

    unsafe fn alloc<T>(&mut self, count: usize) -> Option<*mut T> {
        let align_mask = align_of::<T>().saturating_sub(1);
        let aligned = (self.offset + align_mask) & !align_mask;
        let required = size_of::<T>().checked_mul(count)?;
        if aligned.saturating_add(required) > self.len {
            return None;
        }
        let ptr = unsafe { self.base.add(aligned) };
        self.offset = aligned + required;
        Some(ptr.cast())
    }
}

fn load_policy() -> Option<walle_policy::SshJailPolicy> {
    let config = WalleConfig::load_default().ok()?;
    Some(config.ssh_policy().gp.sshjail.clone())
}

fn lookup_identity_by_name(name: &str) -> Result<Option<TrapIdentityRecord>, NssStatus> {
    if !runtime_lock_is_active() {
        return Ok(None);
    }
    let Some(policy) = load_policy() else {
        return Err(NssStatus::Unavail);
    };
    resolve_trap_identity_by_username(&policy, name).map_err(|_| NssStatus::Unavail)
}

fn lookup_identity_by_uid(uid: uid_t) -> Result<Option<TrapIdentityRecord>, NssStatus> {
    if !runtime_lock_is_active() {
        return Ok(None);
    }
    let Some(policy) = load_policy() else {
        return Err(NssStatus::Unavail);
    };
    resolve_trap_identity_by_uid(&policy, uid).map_err(|_| NssStatus::Unavail)
}

unsafe fn fill_passwd(
    identity: &TrapIdentityRecord,
    result: *mut libc::passwd,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
) -> NssStatus {
    let mut writer = unsafe { BufferWriter::new(buffer, buflen) };
    let Some(name) = (unsafe { writer.write_c_string(identity.username.as_str()) }) else {
        return set_erange(errnop);
    };
    let Some(passwd) = (unsafe { writer.write_c_string("x") }) else {
        return set_erange(errnop);
    };
    let Some(gecos) = (unsafe { writer.write_c_string(identity.gecos.as_str()) }) else {
        return set_erange(errnop);
    };
    let Some(home) = (unsafe { writer.write_c_string(identity.home.as_str()) }) else {
        return set_erange(errnop);
    };
    let Some(shell) = (unsafe { writer.write_c_string(identity.shell.as_str()) }) else {
        return set_erange(errnop);
    };

    unsafe {
        (*result).pw_name = name;
        (*result).pw_passwd = passwd;
        (*result).pw_uid = identity.uid;
        (*result).pw_gid = identity.gid;
        (*result).pw_gecos = gecos;
        (*result).pw_dir = home;
        (*result).pw_shell = shell;
    }
    NssStatus::Success
}

unsafe fn fill_group(
    identity: &TrapIdentityRecord,
    result: *mut libc::group,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
) -> NssStatus {
    let mut writer = unsafe { BufferWriter::new(buffer, buflen) };
    let Some(name) = (unsafe { writer.write_c_string(identity.username.as_str()) }) else {
        return set_erange(errnop);
    };
    let Some(passwd) = (unsafe { writer.write_c_string("x") }) else {
        return set_erange(errnop);
    };
    let Some(members) = (unsafe { writer.alloc::<*mut c_char>(1) }) else {
        return set_erange(errnop);
    };
    unsafe {
        *members = ptr::null_mut();
    }

    unsafe {
        (*result).gr_name = name;
        (*result).gr_passwd = passwd;
        (*result).gr_gid = identity.gid;
        (*result).gr_mem = members;
    }
    NssStatus::Success
}

unsafe fn fill_shadow(
    identity: &TrapIdentityRecord,
    result: *mut libc::spwd,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
) -> NssStatus {
    let mut writer = unsafe { BufferWriter::new(buffer, buflen) };
    let Some(name) = (unsafe { writer.write_c_string(identity.username.as_str()) }) else {
        return set_erange(errnop);
    };
    let Some(passwd) = (unsafe { writer.write_c_string("!") }) else {
        return set_erange(errnop);
    };

    unsafe {
        (*result).sp_namp = name;
        (*result).sp_pwdp = passwd;
        (*result).sp_lstchg = 0;
        (*result).sp_min = -1;
        (*result).sp_max = -1;
        (*result).sp_warn = -1;
        (*result).sp_inact = -1;
        (*result).sp_expire = -1;
        (*result).sp_flag = 0;
    }
    NssStatus::Success
}

unsafe fn append_primary_group(
    identity: &TrapIdentityRecord,
    start: *mut libc::c_long,
    size: *mut libc::c_long,
    groupsp: *mut *mut gid_t,
    limit: libc::c_long,
    errnop: *mut c_int,
) -> NssStatus {
    let current = unsafe { (*start).max(0) as usize };
    let required = current.saturating_add(1);
    let limit = if limit < 0 {
        usize::MAX
    } else {
        limit as usize
    };
    if required > limit {
        return set_erange(errnop);
    }

    let current_size = unsafe { (*size).max(0) as usize };
    if required > current_size {
        let next_size = required.max(current_size.max(1) * 2);
        let bytes = next_size
            .checked_mul(size_of::<gid_t>())
            .unwrap_or(usize::MAX);
        let new_ptr = if unsafe { (*groupsp).is_null() } {
            unsafe { libc::malloc(bytes) }
        } else {
            unsafe { libc::realloc((*groupsp).cast(), bytes) }
        };
        if new_ptr.is_null() {
            set_errno(errnop, libc::ENOMEM);
            return NssStatus::TryAgain;
        }
        unsafe {
            *groupsp = new_ptr.cast();
            *size = next_size as libc::c_long;
        }
    }

    unsafe {
        *(*groupsp).add(current) = identity.gid;
        *start = required as libc::c_long;
    }
    NssStatus::Success
}

fn set_errno(errnop: *mut c_int, value: c_int) {
    if !errnop.is_null() {
        unsafe {
            *errnop = value;
        }
    }
}

fn set_erange(errnop: *mut c_int) -> NssStatus {
    set_errno(errnop, libc::ERANGE);
    NssStatus::TryAgain
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_walle_getpwnam_r(
    name: *const c_char,
    result: *mut libc::passwd,
    buffer: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let name = match c_str_to_string(name) {
        Some(name) => name,
        None => return NssStatus::NotFound,
    };
    match lookup_identity_by_name(name.as_str()) {
        Ok(Some(identity)) => unsafe { fill_passwd(&identity, result, buffer, buflen, errnop) },
        Ok(None) => NssStatus::NotFound,
        Err(status) => status,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_walle_getpwuid_r(
    uid: uid_t,
    result: *mut libc::passwd,
    buffer: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    match lookup_identity_by_uid(uid) {
        Ok(Some(identity)) => unsafe { fill_passwd(&identity, result, buffer, buflen, errnop) },
        Ok(None) => NssStatus::NotFound,
        Err(status) => status,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_walle_getgrnam_r(
    name: *const c_char,
    result: *mut libc::group,
    buffer: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let name = match c_str_to_string(name) {
        Some(name) => name,
        None => return NssStatus::NotFound,
    };
    match lookup_identity_by_name(name.as_str()) {
        Ok(Some(identity)) => unsafe { fill_group(&identity, result, buffer, buflen, errnop) },
        Ok(None) => NssStatus::NotFound,
        Err(status) => status,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_walle_getgrgid_r(
    gid: gid_t,
    result: *mut libc::group,
    buffer: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    match lookup_identity_by_uid(gid) {
        Ok(Some(identity)) => unsafe { fill_group(&identity, result, buffer, buflen, errnop) },
        Ok(None) => NssStatus::NotFound,
        Err(status) => status,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_walle_getspnam_r(
    name: *const c_char,
    result: *mut libc::spwd,
    buffer: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let name = match c_str_to_string(name) {
        Some(name) => name,
        None => return NssStatus::NotFound,
    };
    match lookup_identity_by_name(name.as_str()) {
        Ok(Some(identity)) => unsafe { fill_shadow(&identity, result, buffer, buflen, errnop) },
        Ok(None) => NssStatus::NotFound,
        Err(status) => status,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_walle_initgroups_dyn(
    name: *const c_char,
    group: gid_t,
    start: *mut libc::c_long,
    size: *mut libc::c_long,
    groupsp: *mut *mut gid_t,
    limit: libc::c_long,
    errnop: *mut c_int,
) -> NssStatus {
    let name = match c_str_to_string(name) {
        Some(name) => name,
        None => return NssStatus::NotFound,
    };
    match lookup_identity_by_name(name.as_str()) {
        Ok(Some(identity)) => {
            if identity.gid == group {
                NssStatus::Success
            } else {
                unsafe { append_primary_group(&identity, start, size, groupsp, limit, errnop) }
            }
        }
        Ok(None) => NssStatus::NotFound,
        Err(status) => status,
    }
}

fn c_str_to_string(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(value) };
    cstr.to_str().ok().map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::{BufferWriter, NssStatus, fill_group, fill_passwd, fill_shadow};
    use walle_daemon::ssh_overlay::TrapIdentityRecord;

    fn identity() -> TrapIdentityRecord {
        TrapIdentityRecord {
            username: "tomcat".to_string(),
            uid: 62042,
            gid: 62042,
            home: "/tmp/walle/gp/ssh/trap-home/tomcat".to_string(),
            shell: "/usr/local/lib/walle/walle-ssh-overlay-shell".to_string(),
            gecos: "Walle SSH trap identity".to_string(),
        }
    }

    #[test]
    fn buffer_writer_stores_strings_and_alignment() {
        let mut storage = vec![0u8; 128];
        let mut writer = unsafe { BufferWriter::new(storage.as_mut_ptr().cast(), storage.len()) };
        let first = unsafe { writer.write_c_string("abc") }.unwrap();
        let ptrs = unsafe { writer.alloc::<*mut libc::c_char>(2) }.unwrap();
        unsafe {
            *ptrs = first;
            *ptrs.add(1) = std::ptr::null_mut();
        }
        assert!(!first.is_null());
        assert!(!ptrs.is_null());
    }

    #[test]
    fn passwd_fill_writes_expected_fields() {
        let identity = identity();
        let mut storage = vec![0u8; 256];
        let mut passwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut errno = 0;
        let status = unsafe {
            fill_passwd(
                &identity,
                &mut passwd,
                storage.as_mut_ptr().cast(),
                storage.len(),
                &mut errno,
            )
        };
        assert_eq!(status, NssStatus::Success);
        assert_eq!(errno, 0);
        let name = unsafe { std::ffi::CStr::from_ptr(passwd.pw_name) }
            .to_str()
            .unwrap();
        assert_eq!(name, "tomcat");
        assert_eq!(passwd.pw_uid, 62042);
        assert_eq!(passwd.pw_gid, 62042);
    }

    #[test]
    fn group_fill_writes_expected_fields() {
        let identity = identity();
        let mut storage = vec![0u8; 256];
        let mut group = unsafe { std::mem::zeroed::<libc::group>() };
        let mut errno = 0;
        let status = unsafe {
            fill_group(
                &identity,
                &mut group,
                storage.as_mut_ptr().cast(),
                storage.len(),
                &mut errno,
            )
        };
        assert_eq!(status, NssStatus::Success);
        assert_eq!(group.gr_gid, 62042);
        assert!(unsafe { (*group.gr_mem).is_null() });
    }

    #[test]
    fn shadow_fill_uses_locked_password_marker() {
        let identity = identity();
        let mut storage = vec![0u8; 128];
        let mut shadow = unsafe { std::mem::zeroed::<libc::spwd>() };
        let mut errno = 0;
        let status = unsafe {
            fill_shadow(
                &identity,
                &mut shadow,
                storage.as_mut_ptr().cast(),
                storage.len(),
                &mut errno,
            )
        };
        assert_eq!(status, NssStatus::Success);
        let passwd = unsafe { std::ffi::CStr::from_ptr(shadow.sp_pwdp) }
            .to_str()
            .unwrap();
        assert_eq!(passwd, "!");
    }
}
