//! MaxMind DB Compatibility Layer
//!
//! This module provides libmaxminddb-compatible C API functions that wrap
//! matchy's native API. This allows applications using libmaxminddb to
//! switch to matchy with minimal code changes.

use super::matchy::{
    matchy_aget_value, matchy_close, matchy_entry_data_list_t, matchy_entry_data_t, matchy_entry_s,
    matchy_get_entry_data_list, matchy_open, matchy_query, matchy_t, MATCHY_SUCCESS,
};
use std::ffi::{CStr, CString};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

// ============================================================================
// TYPE DEFINITIONS (matching maxminddb.h)
// ============================================================================

/// MaxMind DB handle (compatibility wrapper)
#[repr(C)]
pub struct MMDB_s {
    /// Internal matchy handle
    _matchy_db: *mut matchy_t,
    /// Flags passed to open
    pub flags: u32,
    /// Filename (owned, needs to be freed)
    pub filename: *const c_char,
    /// File size (not used but provided for compatibility)
    pub file_size: isize,
}

/// MaxMind DB entry (compatibility wrapper)
#[repr(C)]
pub struct MMDB_entry_s {
    /// Database handle
    pub mmdb: *const MMDB_s,
    /// Internal matchy entry
    pub _matchy_entry: matchy_entry_s,
}

/// MaxMind DB lookup result
#[repr(C)]
pub struct MMDB_lookup_result_s {
    /// Whether entry was found
    pub found_entry: bool,
    /// Entry data
    pub entry: MMDB_entry_s,
    /// Network prefix length
    pub netmask: u16,
}

/// Entry data (aliases matchy_entry_data_t)
#[allow(non_camel_case_types)]
pub type MMDB_entry_data_s = matchy_entry_data_t;

/// Entry data list node
#[repr(C)]
pub struct MMDB_entry_data_list_s {
    /// The entry data for this node
    pub entry_data: MMDB_entry_data_s,
    /// Pointer to the next node in the list (NULL if last)
    pub next: *mut MMDB_entry_data_list_s,
    /// Memory pool pointer (not used in this implementation)
    pub pool: *mut c_void,
}

// ============================================================================
// ERROR CODE MAPPING
// ============================================================================

const MMDB_SUCCESS: c_int = 0;
const MMDB_FILE_OPEN_ERROR: c_int = 1;
const MMDB_IO_ERROR: c_int = 4;
const MMDB_OUT_OF_MEMORY_ERROR: c_int = 5;
const MMDB_INVALID_DATA_ERROR: c_int = 7;
const MMDB_INVALID_LOOKUP_PATH_ERROR: c_int = 8;
const MMDB_INVALID_NODE_NUMBER_ERROR: c_int = 10;

/// Map matchy error codes to MMDB error codes
fn map_matchy_error(matchy_error: i32) -> c_int {
    match matchy_error {
        MATCHY_SUCCESS => MMDB_SUCCESS,
        super::matchy::MATCHY_ERROR_FILE_NOT_FOUND => MMDB_FILE_OPEN_ERROR,
        super::matchy::MATCHY_ERROR_IO => MMDB_IO_ERROR,
        super::matchy::MATCHY_ERROR_OUT_OF_MEMORY => MMDB_OUT_OF_MEMORY_ERROR,
        super::matchy::MATCHY_ERROR_LOOKUP_PATH_INVALID => MMDB_INVALID_LOOKUP_PATH_ERROR,
        super::matchy::MATCHY_ERROR_NO_DATA => MMDB_INVALID_DATA_ERROR,
        super::matchy::MATCHY_ERROR_DATA_PARSE => MMDB_INVALID_DATA_ERROR,
        _ => MMDB_INVALID_DATA_ERROR,
    }
}

// ============================================================================
// CORE API FUNCTIONS
// ============================================================================

/// Open a MaxMind DB file
///
/// # Safety
/// - `filename` must be a valid null-terminated C string
/// - `mmdb` must be a valid pointer to MMDB_s struct
#[no_mangle]
pub unsafe extern "C" fn MMDB_open(
    filename: *const c_char,
    flags: u32,
    mmdb: *mut MMDB_s,
) -> c_int {
    if filename.is_null() || mmdb.is_null() {
        return MMDB_FILE_OPEN_ERROR;
    }

    // Zero the struct first (for safety)
    ptr::write_bytes(mmdb, 0, 1);

    // Convert filename to Rust string
    let filename_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return MMDB_FILE_OPEN_ERROR,
    };

    // Open database using matchy
    let db = matchy_open(filename_str.as_ptr() as *const c_char);
    if db.is_null() {
        return MMDB_FILE_OPEN_ERROR;
    }

    // Duplicate filename for storage
    let filename_copy = match CString::new(filename_str) {
        Ok(s) => s.into_raw(),
        Err(_) => {
            matchy_close(db);
            return MMDB_OUT_OF_MEMORY_ERROR;
        }
    };

    // Initialize MMDB_s
    (*mmdb)._matchy_db = db;
    (*mmdb).flags = flags;
    (*mmdb).filename = filename_copy;
    (*mmdb).file_size = 0; // Could query file size if needed

    MMDB_SUCCESS
}

/// Lookup an IP address from string
///
/// # Safety
/// - `mmdb` must be a valid opened database
/// - `ipstr` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn MMDB_lookup_string(
    mmdb: *const MMDB_s,
    ipstr: *const c_char,
    gai_error: *mut c_int,
    mmdb_error: *mut c_int,
) -> MMDB_lookup_result_s {
    // Helper to set errors and return empty result
    let set_error = |gai: c_int, mmdb_err: c_int| {
        if !gai_error.is_null() {
            *gai_error = gai;
        }
        if !mmdb_error.is_null() {
            *mmdb_error = mmdb_err;
        }
        MMDB_lookup_result_s {
            found_entry: false,
            entry: MMDB_entry_s {
                mmdb: ptr::null(),
                _matchy_entry: mem::zeroed(),
            },
            netmask: 0,
        }
    };

    if mmdb.is_null() || ipstr.is_null() {
        return set_error(0, MMDB_INVALID_DATA_ERROR);
    }

    let db = (*mmdb)._matchy_db;
    if db.is_null() {
        return set_error(0, MMDB_INVALID_DATA_ERROR);
    }

    // Query using matchy
    let result = matchy_query(db, ipstr);

    if !result.found {
        return set_error(0, MMDB_SUCCESS);
    }

    // Box the result to keep it alive - matchy_aget_value expects
    // data_ptr to point to a matchy_result_t, not directly to the DataValue.
    // This is a deliberate memory leak that matches libmaxminddb behavior
    // (data persists until db is closed).
    let result_box = Box::new(result);
    let result_ptr = Box::into_raw(result_box);

    let mmdb_entry = MMDB_entry_s {
        mmdb,
        _matchy_entry: matchy_entry_s {
            db,
            data_ptr: result_ptr as *const (),
        },
    };

    let lookup_result = MMDB_lookup_result_s {
        found_entry: true,
        entry: mmdb_entry,
        netmask: (*result_ptr).prefix_len as u16,
    };

    // Set success
    if !gai_error.is_null() {
        *gai_error = 0;
    }
    if !mmdb_error.is_null() {
        *mmdb_error = MMDB_SUCCESS;
    }

    lookup_result
}

/// Lookup an IP address from sockaddr
///
/// # Safety
/// - `mmdb` must be a valid opened database
/// - `sockaddr` must be a valid socket address
///
/// # Platform Support
/// This function works on Unix-like and Windows platforms.
/// - On Unix (Linux, macOS, FreeBSD, etc.): Uses libc's sockaddr types
/// - On Windows: Uses Windows socket types (winsock2)
#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn MMDB_lookup_sockaddr(
    mmdb: *const MMDB_s,
    sockaddr: *const libc::sockaddr,
    mmdb_error: *mut c_int,
) -> MMDB_lookup_result_s {
    let set_error = |err: c_int| {
        if !mmdb_error.is_null() {
            *mmdb_error = err;
        }
        MMDB_lookup_result_s {
            found_entry: false,
            entry: MMDB_entry_s {
                mmdb: ptr::null(),
                _matchy_entry: mem::zeroed(),
            },
            netmask: 0,
        }
    };

    if mmdb.is_null() || sockaddr.is_null() {
        return set_error(MMDB_INVALID_DATA_ERROR);
    }

    // Convert sockaddr to IP string
    let ip_addr = match (*sockaddr).sa_family as i32 {
        libc::AF_INET => {
            let sa = sockaddr as *const libc::sockaddr_in;
            let addr = u32::from_be((*sa).sin_addr.s_addr);
            IpAddr::V4(Ipv4Addr::from(addr))
        }
        libc::AF_INET6 => {
            let sa = sockaddr as *const libc::sockaddr_in6;
            let addr = (*sa).sin6_addr.s6_addr;
            IpAddr::V6(Ipv6Addr::from(addr))
        }
        _ => return set_error(MMDB_INVALID_DATA_ERROR),
    };

    let ip_str = ip_addr.to_string();
    let ip_cstr = match CString::new(ip_str) {
        Ok(s) => s,
        Err(_) => return set_error(MMDB_OUT_OF_MEMORY_ERROR),
    };

    // Use MMDB_lookup_string
    let mut gai_error = 0;
    MMDB_lookup_string(mmdb, ip_cstr.as_ptr(), &mut gai_error, mmdb_error)
}

/// Lookup an IP address from sockaddr (Windows implementation)
///
/// # Safety
/// - `mmdb` must be a valid opened database
/// - `sockaddr` must be a valid Windows SOCKADDR structure
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn MMDB_lookup_sockaddr(
    mmdb: *const MMDB_s,
    sockaddr: *const winapi::shared::ws2def::SOCKADDR,
    mmdb_error: *mut c_int,
) -> MMDB_lookup_result_s {
    let set_error = |err: c_int| {
        if !mmdb_error.is_null() {
            *mmdb_error = err;
        }
        MMDB_lookup_result_s {
            found_entry: false,
            entry: MMDB_entry_s {
                mmdb: ptr::null(),
                _matchy_entry: mem::zeroed(),
            },
            netmask: 0,
        }
    };

    if mmdb.is_null() || sockaddr.is_null() {
        return set_error(MMDB_INVALID_DATA_ERROR);
    }

    use winapi::shared::ws2def::{AF_INET, AF_INET6, SOCKADDR_IN};
    use winapi::shared::ws2ipdef::SOCKADDR_IN6_LH;

    // Convert sockaddr to IP string
    let ip_addr = match (*sockaddr).sa_family as i32 {
        AF_INET => {
            let sa = sockaddr as *const SOCKADDR_IN;
            let addr = u32::from_be(*(*sa).sin_addr.S_un.S_addr());
            IpAddr::V4(Ipv4Addr::from(addr))
        }
        AF_INET6 => {
            let sa = sockaddr as *const SOCKADDR_IN6_LH;
            let addr = *(*sa).sin6_addr.u.Byte();
            IpAddr::V6(Ipv6Addr::from(addr))
        }
        _ => return set_error(MMDB_INVALID_DATA_ERROR),
    };

    let ip_str = ip_addr.to_string();
    let ip_cstr = match CString::new(ip_str) {
        Ok(s) => s,
        Err(_) => return set_error(MMDB_OUT_OF_MEMORY_ERROR),
    };

    // Use MMDB_lookup_string
    let mut gai_error = 0;
    MMDB_lookup_string(mmdb, ip_cstr.as_ptr(), &mut gai_error, mmdb_error)
}

/// Get value from entry using array path
///
/// # Safety
/// - `start` must be a valid entry
/// - `entry_data` must be a valid pointer
/// - `path` must be NULL-terminated array of valid C strings
#[no_mangle]
pub unsafe extern "C" fn MMDB_aget_value(
    start: *mut MMDB_entry_s,
    entry_data: *mut MMDB_entry_data_s,
    path: *const *const c_char,
) -> c_int {
    if start.is_null() || entry_data.is_null() || path.is_null() {
        return MMDB_INVALID_DATA_ERROR;
    }

    // Call matchy's aget_value directly
    let matchy_entry = &(*start)._matchy_entry as *const _;
    let status = matchy_aget_value(matchy_entry, entry_data, path);

    map_matchy_error(status)
}

/// Get entry data list (tree traversal)
///
/// # Safety
/// - `start` must be a valid entry
/// - `entry_data_list` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn MMDB_get_entry_data_list(
    start: *mut MMDB_entry_s,
    entry_data_list: *mut *mut MMDB_entry_data_list_s,
) -> c_int {
    if start.is_null() || entry_data_list.is_null() {
        return MMDB_INVALID_DATA_ERROR;
    }

    // Call matchy's get_entry_data_list
    let matchy_entry = &(*start)._matchy_entry as *const _;
    let matchy_list_ptr = entry_data_list as *mut *mut matchy_entry_data_list_t;
    let status = matchy_get_entry_data_list(matchy_entry, matchy_list_ptr);

    map_matchy_error(status)
}

/// Free entry data list
///
/// # Safety
/// - `entry_data_list` must be from MMDB_get_entry_data_list or NULL
#[no_mangle]
pub unsafe extern "C" fn MMDB_free_entry_data_list(entry_data_list: *mut MMDB_entry_data_list_s) {
    if entry_data_list.is_null() {
        return;
    }

    let mut current = entry_data_list;
    while !current.is_null() {
        let next = (*current).next;
        let _ = Box::from_raw(current);
        current = next;
    }
}

/// Close database
///
/// # Safety
/// - `mmdb` must be a valid opened database or NULL
#[no_mangle]
pub unsafe extern "C" fn MMDB_close(mmdb: *mut MMDB_s) {
    if mmdb.is_null() {
        return;
    }

    // Close matchy database
    if !(*mmdb)._matchy_db.is_null() {
        matchy_close((*mmdb)._matchy_db);
        (*mmdb)._matchy_db = ptr::null_mut();
    }

    // Free filename
    if !(*mmdb).filename.is_null() {
        let _ = CString::from_raw((*mmdb).filename as *mut c_char);
        (*mmdb).filename = ptr::null();
    }
}

/// Get library version
#[no_mangle]
pub extern "C" fn MMDB_lib_version() -> *const c_char {
    // Return matchy version with "-compat" suffix
    concat!(env!("CARGO_PKG_VERSION"), "-compat\0").as_ptr() as *const c_char
}

/// Convert error code to string
#[no_mangle]
pub extern "C" fn MMDB_strerror(error_code: c_int) -> *const c_char {
    let msg = match error_code {
        MMDB_SUCCESS => "Success\0",
        MMDB_FILE_OPEN_ERROR => "Error opening database file\0",
        MMDB_IO_ERROR => "IO error\0",
        MMDB_OUT_OF_MEMORY_ERROR => "Out of memory\0",
        MMDB_INVALID_DATA_ERROR => "Invalid or corrupt data\0",
        MMDB_INVALID_LOOKUP_PATH_ERROR => "Invalid lookup path\0",
        MMDB_INVALID_NODE_NUMBER_ERROR => "Invalid node number\0",
        _ => "Unknown error\0",
    };
    msg.as_ptr() as *const c_char
}

// ============================================================================
// STUB FUNCTIONS (Not implemented)
// ============================================================================

/// Read node (not implemented)
///
/// # Safety
/// This function is a stub and is not implemented. Always returns an error.
#[no_mangle]
pub unsafe extern "C" fn MMDB_read_node(
    _mmdb: *const MMDB_s,
    _node_number: u32,
    _node: *mut c_void,
) -> c_int {
    MMDB_INVALID_NODE_NUMBER_ERROR
}

/// Dump entry data list (not implemented)
///
/// # Safety
/// This function is a stub and is not implemented. Always returns an error.
#[no_mangle]
pub unsafe extern "C" fn MMDB_dump_entry_data_list(
    _stream: *mut libc::FILE,
    _entry_data_list: *const MMDB_entry_data_list_s,
    _indent: c_int,
) -> c_int {
    MMDB_INVALID_DATA_ERROR
}

/// Get metadata as entry data list (not implemented)
///
/// # Safety
/// This function is a stub and is not implemented. Always returns an error.
#[no_mangle]
pub unsafe extern "C" fn MMDB_get_metadata_as_entry_data_list(
    _mmdb: *const MMDB_s,
    _entry_data_list: *mut *mut MMDB_entry_data_list_s,
) -> c_int {
    MMDB_INVALID_DATA_ERROR
}
