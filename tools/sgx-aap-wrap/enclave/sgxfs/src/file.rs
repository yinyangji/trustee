use core::ffi::{c_char, c_int};
use core::ptr;

use crate::ffi::{self, File};

pub struct SgxFile(File);

impl SgxFile {
    pub fn create(path: *const c_char) -> Result<Self, c_int> {
        Self::open_mode(path, c"wb".as_ptr())
    }

    pub fn open(path: *const c_char) -> Result<Self, c_int> {
        Self::open_mode(path, c"rb".as_ptr())
    }

    fn open_mode(path: *const c_char, mode: *const c_char) -> Result<Self, c_int> {
        let file = unsafe { ffi::sgx_fopen_auto_key(path, mode) };
        if file.is_null() {
            Err(ffi::last_error())
        } else {
            Ok(Self(file))
        }
    }

    pub fn write_all(&self, data: &[u8]) -> Result<(), c_int> {
        let written = unsafe { ffi::sgx_fwrite(data.as_ptr().cast(), 1, data.len(), self.0) };
        let err = unsafe { ffi::sgx_ferror(self.0) };
        if err != 0 || written != data.len() {
            return Err(if err != 0 { -err } else { -1 });
        }
        Ok(())
    }

    pub fn read_to_end(&self, buf: &mut [u8]) -> Result<usize, c_int> {
        let mut got = 0;
        while got < buf.len() {
            let n = unsafe {
                ffi::sgx_fread(buf[got..].as_mut_ptr().cast(), 1, buf.len() - got, self.0)
            };
            if n == 0 {
                break;
            }
            got += n;
        }
        let err = unsafe { ffi::sgx_ferror(self.0) };
        let eof = unsafe { ffi::sgx_feof(self.0) };
        if err != 0 || eof == 0 {
            return Err(if err != 0 { -err } else { -1 });
        }
        Ok(got)
    }

    pub fn close(mut self) -> Result<(), c_int> {
        let rc = unsafe { ffi::sgx_fclose(self.0) };
        self.0 = ptr::null_mut();
        if rc == 0 {
            Ok(())
        } else {
            Err(-1)
        }
    }
}

impl Drop for SgxFile {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { ffi::sgx_fclose(self.0) };
        }
    }
}

pub fn export_auto_key(path: *const c_char, key: &mut [u8; 16]) -> Result<(), c_int> {
    let rc = unsafe { ffi::sgx_fexport_auto_key(path, key.as_mut_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(ffi::last_error())
    }
}

pub fn import_auto_key(path: *const c_char, key: &[u8; 16]) -> Result<(), c_int> {
    let rc = unsafe { ffi::sgx_fimport_auto_key(path, key.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(ffi::last_error())
    }
}
