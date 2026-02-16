#include "fido2_credential.h"
#include "fido2_app.h"
#include <furi.h>
#include <furi_hal_random.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ecp.h>
#include <string.h>

#define TAG "FIDO2_CRED"

/**
 * @brief Complete definition of credential store
 * This is only in the .c file, not in the header
 */
struct Fido2CredentialStore {
    Fido2Credential credentials[FIDO2_MAX_CREDENTIALS];
};

/**
 * @brief Random number generator callback for mbedTLS
 */
static int rng_callback(void* ctx, unsigned char* buf, size_t len) {
    UNUSED(ctx);
    furi_hal_random_fill_buf(buf, len);
    return 0;
}

Fido2CredentialStore* fido2_credential_store_alloc() {
    Fido2CredentialStore* store = malloc(sizeof(struct Fido2CredentialStore));
    memset(store, 0, sizeof(struct Fido2CredentialStore));
    FURI_LOG_I(TAG, "Credential store initialized");
    return store;
}

void fido2_credential_store_free(Fido2CredentialStore* store) {
    if(!store) return;
    // Zero out sensitive data
    memset(store, 0, sizeof(struct Fido2CredentialStore));
    free(store);
}

Fido2Credential* fido2_credential_create(
    Fido2CredentialStore* store,
    const char* rp_id,
    const uint8_t* user_id,
    size_t user_id_len,
    const char* user_name,
    const char* user_display_name) {
    
    if(!store || !rp_id || !user_id) return NULL;

    // Find empty slot
    Fido2Credential* cred = NULL;
    for(size_t i = 0; i < FIDO2_MAX_CREDENTIALS; i++) {
        if(!store->credentials[i].valid) {
            cred = &store->credentials[i];
            break;
        }
    }

    if(!cred) {
        FURI_LOG_W(TAG, "No free credential slots");
        return NULL;
    }

    // Clear credential
    memset(cred, 0, sizeof(Fido2Credential));

    // Generate credential ID (random)
    furi_hal_random_fill_buf(cred->credential_id, sizeof(cred->credential_id));

    // Generate ECDSA key pair (P-256)
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    int ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, rng_callback, store);
    if(ret != 0) {
        FURI_LOG_E(TAG, "Failed to generate key pair: %d", ret);
        mbedtls_ecdsa_free(&ctx);
        return NULL;
    }

    // Extract private key
    ret = mbedtls_mpi_write_binary(&ctx.MBEDTLS_PRIVATE(d), cred->private_key, 32);
    if(ret != 0) {
        FURI_LOG_E(TAG, "Failed to extract private key: %d", ret);
        mbedtls_ecdsa_free(&ctx);
        return NULL;
    }

    // Extract public key coordinates
    ret = mbedtls_mpi_write_binary(
        &ctx.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X),
        cred->public_key_x,
        32);
    if(ret != 0) {
        FURI_LOG_E(TAG, "Failed to extract public key X: %d", ret);
        mbedtls_ecdsa_free(&ctx);
        return NULL;
    }

    ret = mbedtls_mpi_write_binary(
        &ctx.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y),
        cred->public_key_y,
        32);
    if(ret != 0) {
        FURI_LOG_E(TAG, "Failed to extract public key Y: %d", ret);
        mbedtls_ecdsa_free(&ctx);
        return NULL;
    }

    mbedtls_ecdsa_free(&ctx);

    // Copy metadata
    strncpy(cred->rp_id, rp_id, sizeof(cred->rp_id) - 1);
    cred->rp_id[sizeof(cred->rp_id) - 1] = '\0';

    memcpy(cred->user_id, user_id, user_id_len > 64 ? 64 : user_id_len);
    cred->user_id_len = user_id_len > 64 ? 64 : user_id_len;

    if(user_name) {
        strncpy(cred->user_name, user_name, sizeof(cred->user_name) - 1);
        cred->user_name[sizeof(cred->user_name) - 1] = '\0';
    }

    if(user_display_name) {
        strncpy(cred->user_display_name, user_display_name, sizeof(cred->user_display_name) - 1);
        cred->user_display_name[sizeof(cred->user_display_name) - 1] = '\0';
    }

    cred->sign_count = 0;
    cred->valid = true;

    FURI_LOG_I(TAG, "Created credential for RP: %s", rp_id);
    return cred;
}

Fido2Credential* fido2_credential_find_by_rp(Fido2CredentialStore* store, const char* rp_id) {
    if(!store || !rp_id) return NULL;

    for(size_t i = 0; i < FIDO2_MAX_CREDENTIALS; i++) {
        if(store->credentials[i].valid && strcmp(store->credentials[i].rp_id, rp_id) == 0) {
            return &store->credentials[i];
        }
    }

    return NULL;
}

Fido2Credential* fido2_credential_find_by_id(
    Fido2CredentialStore* store,
    const uint8_t* credential_id,
    size_t credential_id_len) {
    
    if(!store || !credential_id || credential_id_len != 32) return NULL;

    for(size_t i = 0; i < FIDO2_MAX_CREDENTIALS; i++) {
        if(store->credentials[i].valid &&
           memcmp(store->credentials[i].credential_id, credential_id, 32) == 0) {
            return &store->credentials[i];
        }
    }

    return NULL;
}

bool fido2_credential_sign(
    Fido2Credential* cred,
    const uint8_t* data,
    size_t data_len,
    uint8_t* signature,
    size_t* signature_len) {
    
    if(!cred || !data || !signature || !signature_len) return false;

    // Hash the data with SHA-256
    uint8_t hash[32];
    mbedtls_sha256(data, data_len, hash, 0);

    // Initialize ECDSA context and load private key
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    int ret = mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    if(ret != 0) {
        FURI_LOG_E(TAG, "Failed to load curve: %d", ret);
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    ret = mbedtls_mpi_read_binary(&ctx.MBEDTLS_PRIVATE(d), cred->private_key, 32);
    if(ret != 0) {
        FURI_LOG_E(TAG, "Failed to load private key: %d", ret);
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    // Sign the hash
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    ret = mbedtls_ecdsa_sign(
        &ctx.MBEDTLS_PRIVATE(grp),
        &r,
        &s,
        &ctx.MBEDTLS_PRIVATE(d),
        hash,
        32,
        rng_callback,
        NULL);

    if(ret != 0) {
        FURI_LOG_E(TAG, "Failed to sign: %d", ret);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    // Encode signature in DER format
    size_t offset = 0;
    
    // Get signature size
    size_t r_len = mbedtls_mpi_size(&r);
    size_t s_len = mbedtls_mpi_size(&s);
    
    // Build DER signature: 30 <len> 02 <r_len> <r> 02 <s_len> <s>
    signature[offset++] = 0x30; // SEQUENCE
    signature[offset++] = 2 + r_len + 2 + s_len; // Total length
    signature[offset++] = 0x02; // INTEGER
    signature[offset++] = r_len;
    
    // Write r
    ret = mbedtls_mpi_write_binary(&r, signature + offset, r_len);
    if(ret != 0) {
        FURI_LOG_E(TAG, "Failed to write r");
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecdsa_free(&ctx);
        return false;
    }
    offset += r_len;
    
    signature[offset++] = 0x02; // INTEGER
    signature[offset++] = s_len;
    
    // Write s
    ret = mbedtls_mpi_write_binary(&s, signature + offset, s_len);
    if(ret != 0) {
        FURI_LOG_E(TAG, "Failed to write s");
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecdsa_free(&ctx);
        return false;
    }
    offset += s_len;

    *signature_len = offset;

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ctx);

    // Increment signature counter
    cred->sign_count++;

    FURI_LOG_D(TAG, "Signed data, signature length: %d", *signature_len);
    return true;
}

size_t fido2_credential_count(Fido2CredentialStore* store) {
    if(!store) return 0;

    size_t count = 0;
    for(size_t i = 0; i < FIDO2_MAX_CREDENTIALS; i++) {
        if(store->credentials[i].valid) {
            count++;
        }
    }
    return count;
}

void fido2_credential_reset(Fido2CredentialStore* store) {
    if(!store) return;

    for(size_t i = 0; i < FIDO2_MAX_CREDENTIALS; i++) {
        memset(&store->credentials[i], 0, sizeof(Fido2Credential));
    }

    FURI_LOG_I(TAG, "All credentials reset");
}