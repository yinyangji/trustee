//! Enclave side of the AAP protected file.
//!
//! `file` is the small subset of Teaclave `sgxfs` this service needs.
//! The functions below are the ECALL boundary used by the host.

#![no_std]

mod ffi;
mod file;

use core::ffi::{c_char, c_int};
use core::ptr;

use file::{export_auto_key, import_auto_key, SgxFile};

#[no_mangle]
pub extern "C" fn ecall_create(path: *const c_char, data: *const u8, len: usize) -> c_int {
    let result = (|| {
        let protected = SgxFile::create(path)?;
        protected.write_all(unsafe { core::slice::from_raw_parts(data, len) })?;
        protected.close()
    })();
    result.err().unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn ecall_read(
    path: *const c_char,
    buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let result = (|| {
        let protected = SgxFile::open(path)?;
        let got = protected.read_to_end(unsafe { core::slice::from_raw_parts_mut(buf, cap) })?;
        protected.close()?;
        Ok(got)
    })();
    match result {
        Ok(got) => {
            unsafe { *out_len = got };
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn ecall_export_key(path: *const c_char, key: *mut u8) -> c_int {
    let mut file_key = [0u8; 16];
    if let Err(err) = export_auto_key(path, &mut file_key) {
        return err;
    }
    unsafe { ptr::copy_nonoverlapping(file_key.as_ptr(), key, file_key.len()) };
    file_key.fill(0);
    0
}

#[no_mangle]
pub extern "C" fn ecall_import_key(path: *const c_char, key: *const u8) -> c_int {
    let mut file_key = [0u8; 16];
    unsafe { ptr::copy_nonoverlapping(key, file_key.as_mut_ptr(), file_key.len()) };
    let result = import_auto_key(path, &file_key);
    file_key.fill(0);
    result.err().unwrap_or(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
