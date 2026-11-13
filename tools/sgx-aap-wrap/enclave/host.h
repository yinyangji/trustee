#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int aap_fs_init(const char* signed_enclave);
int aap_fs_create(const char* path, const uint8_t* data, size_t len);
int aap_fs_read(const char* path, uint8_t* buf, size_t cap, size_t* out_len);
int aap_fs_export_key(const char* path, uint8_t key[16]);
int aap_fs_import_key(const char* path, const uint8_t key[16]);
int aap_quote_verify(const uint8_t* quote, size_t quote_len, const uint8_t expected_report_data[64]);

#ifdef __cplusplus
}
#endif
