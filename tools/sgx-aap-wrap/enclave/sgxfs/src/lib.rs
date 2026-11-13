//! Enclave side of the AAP protected file.
//!
//! `file` is the small subset of Teaclave `sgxfs` this service needs.
//! The functions below are the ECALL boundary used by the host.

#![no_std]

mod ffi;
mod file;
mod quote;

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

#[no_mangle]
pub extern "C" fn ecall_accept_quote(
    quote: *const u8,
    quote_len: usize,
    qve_report: *const core::ffi::c_void,
    expiration_check_date: i64,
    collateral_expiration_status: u32,
    quote_verification_result: u32,
    supplemental: *const u8,
    supplemental_data_size: u32,
    expected_report_data: *const u8,
) -> c_int {
    let quote = unsafe { core::slice::from_raw_parts(quote, quote_len) };
    let supplemental = if supplemental.is_null() || supplemental_data_size == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(supplemental, supplemental_data_size as usize) }
    };
    let expected = unsafe { core::slice::from_raw_parts(expected_report_data, 64) };
    match quote::accept(
        quote,
        qve_report,
        expiration_check_date,
        collateral_expiration_status,
        quote_verification_result,
        supplemental,
        expected,
    ) {
        Ok(()) => 0,
        Err(err) => err,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
