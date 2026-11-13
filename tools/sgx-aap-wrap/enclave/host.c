#include "host.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <pthread.h>
#include <sys/random.h>

#include "Enclave_u.h"
#include "sgx_ql_lib_common.h"
#include "sgx_ql_quote.h"
#include "sgx_qve_header.h"
#include "sgx_urts.h"

quote3_error_t tee_get_supplemental_data_version_and_size(
    const uint8_t* p_quote,
    uint32_t quote_size,
    uint32_t* p_version,
    uint32_t* p_data_size);

quote3_error_t tee_verify_quote(
    const uint8_t* p_quote,
    uint32_t quote_size,
    const uint8_t* p_quote_collateral,
    time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    sgx_ql_qv_result_t* p_quote_verification_result,
    sgx_ql_qe_report_info_t* p_qve_report_info,
    tee_supp_data_descriptor_t* p_supp_data_descriptor);

/* The enclave is built with one TCS, so every ECALL shares this lock. */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static sgx_enclave_id_t g_eid = 0;

static int call_status(sgx_status_t status, int fn)
{
    if (status != SGX_SUCCESS) {
        return -1000 - (int)status;
    }
    return fn;
}

int aap_fs_init(const char* signed_enclave)
{
    pthread_mutex_lock(&g_mu);
    int rc = 0;
    if (g_eid == 0) {
        sgx_launch_token_t token;
        memset(token, 0, sizeof(token));
        int updated = 0;
        sgx_status_t status = sgx_create_enclave(signed_enclave, SGX_DEBUG_FLAG, &token, &updated, &g_eid, NULL);
        rc = status == SGX_SUCCESS ? 0 : -1000 - (int)status;
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

int aap_fs_create(const char* path, const uint8_t* data, size_t len)
{
    pthread_mutex_lock(&g_mu);
    int fn = -1;
    sgx_status_t status = ecall_create(g_eid, &fn, path, data, len);
    int rc = call_status(status, fn);
    pthread_mutex_unlock(&g_mu);
    return rc;
}

int aap_fs_read(const char* path, uint8_t* buf, size_t cap, size_t* out_len)
{
    pthread_mutex_lock(&g_mu);
    int fn = -1;
    size_t got = 0;
    sgx_status_t status = ecall_read(g_eid, &fn, path, buf, cap, &got);
    if (status == SGX_SUCCESS && fn == 0) {
        *out_len = got;
    }
    int rc = call_status(status, fn);
    pthread_mutex_unlock(&g_mu);
    return rc;
}

int aap_fs_export_key(const char* path, uint8_t key[16])
{
    pthread_mutex_lock(&g_mu);
    int fn = -1;
    sgx_status_t status = ecall_export_key(g_eid, &fn, path, key);
    int rc = call_status(status, fn);
    pthread_mutex_unlock(&g_mu);
    return rc;
}

int aap_fs_import_key(const char* path, const uint8_t key[16])
{
    pthread_mutex_lock(&g_mu);
    int fn = -1;
    sgx_status_t status = ecall_import_key(g_eid, &fn, path, key);
    int rc = call_status(status, fn);
    pthread_mutex_unlock(&g_mu);
    return rc;
}

int aap_quote_verify(const uint8_t* quote, size_t quote_len, const uint8_t expected_report_data[64])
{
    if (quote == NULL || expected_report_data == NULL || quote_len > UINT32_MAX || g_eid == 0) {
        return -1;
    }

    pthread_mutex_lock(&g_mu);
    sgx_ql_qe_report_info_t info;
    memset(&info, 0, sizeof(info));
    sgx_status_t status = sgx_get_target_info(g_eid, &info.app_enclave_target_info);
    if (status != SGX_SUCCESS) {
        pthread_mutex_unlock(&g_mu);
        return -1000 - (int)status;
    }
    if (getentropy(info.nonce.rand, sizeof(info.nonce.rand)) != 0) {
        pthread_mutex_unlock(&g_mu);
        return -1;
    }

    uint32_t supplemental_size = 0;
    quote3_error_t qv = tee_get_supplemental_data_version_and_size(
        quote, (uint32_t)quote_len, NULL, &supplemental_size);
    if (qv != SGX_QL_SUCCESS) {
        pthread_mutex_unlock(&g_mu);
        return -(int)qv;
    }
    uint8_t* supplemental = calloc(1, supplemental_size == 0 ? 1 : supplemental_size);
    if (supplemental == NULL) {
        pthread_mutex_unlock(&g_mu);
        return -1;
    }
    tee_supp_data_descriptor_t supplemental_desc;
    memset(&supplemental_desc, 0, sizeof(supplemental_desc));
    supplemental_desc.major_version = 0;
    supplemental_desc.data_size = supplemental_size;
    supplemental_desc.p_data = supplemental_size == 0 ? NULL : supplemental;

    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    time_t now = time(NULL);
    qv = tee_verify_quote(
        quote,
        (uint32_t)quote_len,
        NULL,
        now,
        &collateral_expiration_status,
        &quote_result,
        &info,
        supplemental_size == 0 ? NULL : &supplemental_desc);
    int rc = -(int)qv;
    if (qv == SGX_QL_SUCCESS) {
        int fn = -1;
        status = ecall_accept_quote(
            g_eid,
            &fn,
            quote,
            quote_len,
            &info,
            (int64_t)now,
            collateral_expiration_status,
            (uint32_t)quote_result,
            supplemental,
            supplemental_size,
            expected_report_data);
        rc = call_status(status, fn);
    }
    free(supplemental);
    pthread_mutex_unlock(&g_mu);
    return rc;
}
