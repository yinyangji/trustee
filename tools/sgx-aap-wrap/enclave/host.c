#include "host.h"

#include <pthread.h>
#include <string.h>

#include "Enclave_u.h"
#include "sgx_urts.h"

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
