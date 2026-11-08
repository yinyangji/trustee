use core::ffi::{c_char, c_int, c_void};

pub type File = *mut c_void;

unsafe extern "C" {
    pub fn sgx_fopen_auto_key(filename: *const c_char, mode: *const c_char) -> File;
    pub fn sgx_fwrite(ptr: *const c_void, size: usize, count: usize, stream: File) -> usize;
    pub fn sgx_fread(ptr: *mut c_void, size: usize, count: usize, stream: File) -> usize;
    pub fn sgx_fclose(stream: File) -> c_int;
    pub fn sgx_ferror(stream: File) -> c_int;
    pub fn sgx_feof(stream: File) -> c_int;
    pub fn sgx_fexport_auto_key(filename: *const c_char, key: *mut u8) -> c_int;
    pub fn sgx_fimport_auto_key(filename: *const c_char, key: *const u8) -> c_int;
    pub fn __errno() -> *mut c_int;
}

pub fn last_error() -> c_int {
    let err = unsafe { *__errno() };
    if err == 0 {
        -1
    } else {
        -err
    }
}
