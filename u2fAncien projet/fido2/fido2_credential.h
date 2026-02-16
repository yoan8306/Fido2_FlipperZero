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

/**
 * @brief FIDO2 credential structure
 * 
 * Contains all data for a single credential including
 * private key, public key, and metadata.
 */
typedef struct {
    uint8_t credential_id[32];      /**< Unique credential ID */
    uint8_t private_key[32];        /**< ECDSA private key */
    uint8_t public_key_x[32];       /**< ECDSA public key X coordinate */
    uint8_t public_key_y[32];       /**< ECDSA public key Y coordinate */
    char rp_id[128];                /**< Relying Party ID */
    uint8_t user_id[64];            /**< User ID */
    size_t user_id_len;             /**< Length of user ID */
    char user_name[64];             /**< User name */
    char user_display_name[64];     /**< User display name */
    uint32_t sign_count;            /**< Signature counter */
    bool valid;                     /**< Is this slot used? */
} Fido2Credential;

/**
 * @brief Opaque credential store type
 */
typedef struct Fido2CredentialStore Fido2CredentialStore;

/**
 * @brief Create a new credential store
 * 
 * @return Fido2CredentialStore* New store instance or NULL on failure
 */
Fido2CredentialStore* fido2_credential_store_alloc();

/**
 * @brief Free credential store
 * 
 * @param store Store instance to free
 */
void fido2_credential_store_free(Fido2CredentialStore* store);

/**
 * @brief Create a new credential
 * 
 * @param store Credential store
 * @param rp_id Relying Party ID
 * @param user_id User ID
 * @param user_id_len User ID length
 * @param user_name User name (optional)
 * @param user_display_name User display name (optional)
 * @return Fido2Credential* New credential or NULL on failure
 */
Fido2Credential* fido2_credential_create(
    Fido2CredentialStore* store,
    const char* rp_id,
    const uint8_t* user_id,
    size_t user_id_len,
    const char* user_name,
    const char* user_display_name);

/**
 * @brief Find credential by RP ID
 * 
 * @param store Credential store
 * @param rp_id RP ID to search for
 * @return Fido2Credential* Found credential or NULL
 */
Fido2Credential* fido2_credential_find_by_rp(Fido2CredentialStore* store, const char* rp_id);

/**
 * @brief Find credential by credential ID
 * 
 * @param store Credential store
 * @param credential_id Credential ID
 * @param credential_id_len Credential ID length
 * @return Fido2Credential* Found credential or NULL
 */
Fido2Credential* fido2_credential_find_by_id(
    Fido2CredentialStore* store,
    const uint8_t* credential_id,
    size_t credential_id_len);

/**
 * @brief Sign data with credential
 * 
 * @param cred Credential to use
 * @param data Data to sign
 * @param data_len Data length
 * @param signature Output signature buffer
 * @param signature_len Output signature length
 * @return bool true on success
 */
bool fido2_credential_sign(
    Fido2Credential* cred,
    const uint8_t* data,
    size_t data_len,
    uint8_t* signature,
    size_t* signature_len);

/**
 * @brief Get number of stored credentials
 * 
 * @param store Credential store
 * @return size_t Number of credentials
 */
size_t fido2_credential_count(Fido2CredentialStore* store);

/**
 * @brief Reset/delete all credentials
 * 
 * @param store Credential store
 */
void fido2_credential_reset(Fido2CredentialStore* store);

#ifdef __cplusplus
}
#endif