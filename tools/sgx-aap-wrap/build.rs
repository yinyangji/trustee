use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if env::var("SGX_MODE").is_ok_and(|mode| mode != "HW") {
        panic!("the hardware credential provider requires SGX_MODE=HW");
    }
    println!("cargo:rerun-if-env-changed=SGX_SDK");
    println!("cargo:rerun-if-env-changed=SGX_MODE");
    println!("cargo:rerun-if-changed=enclave/Enclave.config.xml");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let enclave = manifest.join("enclave");
    let sdk = env::var("SGX_SDK").unwrap_or_else(|_| "/home/chenpengyu/sgxsdk".to_string());
    println!("cargo:rerun-if-changed=enclave/sgxfs/src/lib.rs");
    println!("cargo:rerun-if-changed=enclave/sgxfs/src/file.rs");
    println!("cargo:rerun-if-changed=enclave/sgxfs/src/ffi.rs");
    println!("cargo:rerun-if-changed=enclave/sgxfs/src/quote.rs");
    println!("cargo:rerun-if-changed=enclave/sgxfs/Cargo.toml");
    println!("cargo:rerun-if-changed=enclave/Enclave.edl");
    println!("cargo:rerun-if-changed=enclave/host.c");
    println!("cargo:rerun-if-changed=enclave/Makefile");

    let status = Command::new("make")
        .arg("-C")
        .arg(&enclave)
        .env("SGX_SDK", &sdk)
        .status()
        .expect("run enclave makefile");
    if !status.success() {
        panic!("sgx enclave build failed");
    }

    let build = enclave.join("build");
    println!("cargo:rustc-link-search=native={}", build.display());
    println!("cargo:rustc-link-search=native={}/lib64", sdk);
    println!("cargo:rustc-link-lib=static=aap_fs_host");
    println!("cargo:rustc-link-lib=static=sgx_uprotected_fs");
    println!("cargo:rustc-link-lib=dylib=sgx_urts");
    println!("cargo:rustc-link-arg=/usr/lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so.1");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=dl");
}
