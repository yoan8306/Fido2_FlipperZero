#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Credential structure
typedef struct {
    uint8_t credential_id[32]; // Unique credential ID
    uint8_t private_key[32]; // ECDSA private key
    uint8_t public_key_x[32]; // ECDSA public key X coordinate
    uint8_t public_key_y[32]; // ECDSA public key Y coordinate
    char rp_id[128]; // Relying Party ID
    uint8_t user_id[64]; // User ID
    size_t user_id_len;
    char user_name[64]; // User name
    char user_display_name[64]; // User display name
    uint32_t sign_count; // Signature counter
    bool valid; // Is this slot used?
} Fido2Credential;

// Credential storage
typedef struct Fido2CredentialStore Fido2CredentialStore;

// Create credential store
Fido2CredentialStore* fido2_credential_store_alloc();

// Free credential store
void fido2_credential_store_free(Fido2CredentialStore* store);

// Create a new credential
Fido2Credential* fido2_credential_create(
    Fido2CredentialStore* store,
    const char* rp_id,
    const uint8_t* user_id,
    size_t user_id_len,
    const char* user_name,
    const char* user_display_name);

// Find credential by RP ID
Fido2Credential* fido2_credential_find_by_rp(Fido2CredentialStore* store, const char* rp_id);

// Find credential by credential ID
Fido2Credential* fido2_credential_find_by_id(
    Fido2CredentialStore* store,
    const uint8_t* credential_id,
    size_t credential_id_len);

// Sign data with credential
bool fido2_credential_sign(
    Fido2Credential* cred,
    const uint8_t* data,
    size_t data_len,
    uint8_t* signature,
    size_t* signature_len);

// Get number of stored credentials
size_t fido2_credential_count(Fido2CredentialStore* store);

// Reset all credentials
void fido2_credential_reset(Fido2CredentialStore* store);
