#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FIDO2_MAX_CREDENTIALS 10
#define FIDO2_CREDENTIAL_ID_SIZE 32
#define FIDO2_RP_ID_MAX_SIZE 128
#define FIDO2_USER_ID_MAX_SIZE 64
#define FIDO2_USER_NAME_MAX_SIZE 64
#define FIDO2_DISPLAY_NAME_MAX_SIZE 64

/**
 * @brief FIDO2 credential structure
 */
typedef struct {
    uint8_t credential_id[32];
    uint8_t private_key[32];
    uint8_t public_key_x[32];
    uint8_t public_key_y[32];
    char rp_id[128];
    uint8_t user_id[64];
    size_t user_id_len;
    char user_name[64];
    char user_display_name[64];
    uint32_t sign_count;
    bool valid;
} Fido2Credential;

/**
 * @brief Opaque credential store type - forward declaration only
 */
typedef struct Fido2CredentialStore Fido2CredentialStore;

Fido2CredentialStore* fido2_credential_store_alloc(void);
void fido2_credential_store_free(Fido2CredentialStore* store);

Fido2Credential* fido2_credential_create(
    Fido2CredentialStore* store,
    const char* rp_id,
    const uint8_t* user_id,
    size_t user_id_len,
    const char* user_name,
    const char* user_display_name);

Fido2Credential* fido2_credential_find_by_rp(Fido2CredentialStore* store, const char* rp_id);

Fido2Credential* fido2_credential_find_by_id(
    Fido2CredentialStore* store,
    const uint8_t* credential_id,
    size_t credential_id_len);

bool fido2_credential_sign(
    Fido2Credential* cred,
    const uint8_t* data,
    size_t data_len,
    uint8_t* signature,
    size_t* signature_len);

size_t fido2_credential_count(Fido2CredentialStore* store);
void fido2_credential_reset(Fido2CredentialStore* store);

#ifdef __cplusplus
}
#endif