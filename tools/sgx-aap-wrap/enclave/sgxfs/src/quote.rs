use core::ffi::c_void;
use core::ptr;

use crate::ffi;

const QUOTE_HEADER_LEN: usize = 48;
const TDX_REPORT_DATA_OFFSET: usize = QUOTE_HEADER_LEN + 520;
const TDX_TEE_TYPE: u32 = 0x81;

pub fn accept(
    quote: &[u8],
    qve_report: *const c_void,
    expiration_check_date: i64,
    collateral_expiration_status: u32,
    quote_verification_result: u32,
    supplemental: &[u8],
    expected_report_data: &[u8],
) -> Result<(), i32> {
    if quote.len() > u32::MAX as usize || expected_report_data.len() != 64 {
        return Err(-1);
    }
    let status = unsafe {
        ffi::sgx_tvl_verify_qve_report_and_identity(
            quote.as_ptr(),
            quote.len() as u32,
            qve_report,
            expiration_check_date,
            collateral_expiration_status,
            quote_verification_result,
            if supplemental.is_empty() {
                ptr::null()
            } else {
                supplemental.as_ptr()
            },
            supplemental.len() as u32,
            0,
        )
    };
    if status != 0 {
        return Err(-(status as i32));
    }
    if collateral_expiration_status != 0 || quote_verification_result != 0 {
        return Err(-2);
    }
    if quote.len() < TDX_REPORT_DATA_OFFSET + 64 {
        return Err(-1);
    }
    let version = u16::from_le_bytes([quote[0], quote[1]]);
    let tee_type = u32::from_le_bytes(quote[4..8].try_into().unwrap());
    if version != 4 || tee_type != TDX_TEE_TYPE {
        return Err(-3);
    }
    if &quote[TDX_REPORT_DATA_OFFSET..TDX_REPORT_DATA_OFFSET + 64] != expected_report_data {
        return Err(-4);
    }
    Ok(())
}
