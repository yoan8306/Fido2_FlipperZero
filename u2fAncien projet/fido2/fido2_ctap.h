#pragma once

#include <stdint.h>
#include <stddef.h>
#include "fido2_credential.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Fido2Ctap Fido2Ctap;

/**
 * @brief User presence callback type
 * 
 * Called when user presence confirmation is needed.
 * Should return true if user confirmed presence.
 */
typedef bool (*Fido2UserPresenceCallback)(void* context);

/**
 * @brief Create a new CTAP2 module instance
 * 
 * @param store Credential store to use
 * @return Fido2Ctap* New instance or NULL on failure
 */
Fido2Ctap* fido2_ctap_alloc(Fido2CredentialStore* store);

/**
 * @brief Free CTAP2 module instance
 * 
 * @param ctap Instance to free
 */
void fido2_ctap_free(Fido2Ctap* ctap);

/**
 * @brief Set user presence callback
 * 
 * @param ctap CTAP instance
 * @param callback Callback function
 * @param context Context to pass to callback
 */
void fido2_ctap_set_user_presence_callback(
    Fido2Ctap* ctap,
    Fido2UserPresenceCallback callback,
    void* context);

/**
 * @brief Process a CTAP2 command
 * 
 * @param ctap CTAP instance
 * @param request Request buffer (includes command byte)
 * @param req_len Request length
 * @param response Output buffer
 * @param max_len Maximum response buffer size
 * @return size_t Response length in bytes
 */
size_t fido2_ctap_process(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len);

/**
 * @brief Get authenticator AAGUID
 * 
 * @param ctap CTAP instance
 * @param aaguid Output buffer (must be 16 bytes)
 */
void fido2_ctap_get_aaguid(Fido2Ctap* ctap, uint8_t* aaguid);

#ifdef __cplusplus
}
#endif