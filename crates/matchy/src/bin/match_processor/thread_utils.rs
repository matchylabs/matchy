/// Set thread name for debugging/profiling (cross-platform)
#[cfg(target_os = "macos")]
pub fn set_thread_name(name: &str) {
    use std::ffi::CString;
    if let Ok(cname) = CString::new(name) {
        unsafe {
            libc::pthread_setname_np(cname.as_ptr());
        }
    }
}

#[cfg(target_os = "linux")]
pub fn set_thread_name(name: &str) {
    use std::ffi::CString;
    if let Ok(cname) = CString::new(name) {
        unsafe {
            // Linux takes current thread (NULL) + name
            libc::pthread_setname_np(libc::pthread_self(), cname.as_ptr());
        }
    }
}

#[cfg(target_os = "windows")]
pub fn set_thread_name(_name: &str) {
    // Windows 10+ supports SetThreadDescription but requires additional dependencies
    // Thread naming is debug-only, so we skip it for simplicity
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn set_thread_name(_name: &str) {
    // No-op on other platforms
}
