#pragma once

#include <stdint.h>
#include <stddef.h>
#include "fido2_credential.h"

typedef struct Fido2Ctap Fido2Ctap;

// User presence callback
typedef bool (*Fido2UserPresenceCallback)(void* context);

// Create CTAP module
Fido2Ctap* fido2_ctap_alloc(Fido2CredentialStore* store);

// Free CTAP module
void fido2_ctap_free(Fido2Ctap* ctap);

// Set user presence callback
void fido2_ctap_set_user_presence_callback(
    Fido2Ctap* ctap,
    Fido2UserPresenceCallback callback,
    void* context);

// Process CTAP2 command
size_t fido2_ctap_process(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len);

// Get AAGUID
void fido2_ctap_get_aaguid(Fido2Ctap* ctap, uint8_t* aaguid);
