#pragma once

#include <stdint.h>
#include <stddef.h>
#include "fido2_credential.h"

#ifdef __cplusplus
extern "C" {
#endif

// CTAP2 command codes
#define CTAP2_CMD_MAKE_CREDENTIAL 0x01
#define CTAP2_CMD_GET_ASSERTION   0x02
#define CTAP2_CMD_GET_INFO         0x04
#define CTAP2_CMD_CLIENT_PIN       0x06
#define CTAP2_CMD_RESET            0x07
#define CTAP2_CMD_GET_NEXT_ASSERTION 0x08

// CTAP2 status codes (CTAP1 compatibility)
#define CTAP2_OK                    0x00
#define CTAP1_ERR_INVALID_COMMAND   0x01
#define CTAP1_ERR_INVALID_PARAMETER 0x02
#define CTAP1_ERR_INVALID_LENGTH    0x03
#define CTAP1_ERR_INVALID_SEQ       0x04
#define CTAP1_ERR_TIMEOUT            0x05
#define CTAP1_ERR_CHANNEL_BUSY       0x06
#define CTAP1_ERR_LOCK_REQUIRED      0x0A
#define CTAP1_ERR_INVALID_CHANNEL    0x0B

// CTAP2 specific errors
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE 0x11
#define CTAP2_ERR_INVALID_CBOR       0x12
#define CTAP2_ERR_MISSING_PARAMETER  0x14
#define CTAP2_ERR_LIMIT_EXCEEDED     0x15
#define CTAP2_ERR_UNSUPPORTED_EXTENSION 0x16
#define CTAP2_ERR_CREDENTIAL_EXCLUDED 0x19
#define CTAP2_ERR_PROCESSING         0x21
#define CTAP2_ERR_INVALID_CREDENTIAL 0x22
#define CTAP2_ERR_USER_ACTION_PENDING 0x23
#define CTAP2_ERR_OPERATION_PENDING  0x24
#define CTAP2_ERR_NO_OPERATIONS      0x25
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26
#define CTAP2_ERR_OPERATION_DENIED   0x27
#define CTAP2_ERR_KEY_STORE_FULL     0x28
#define CTAP2_ERR_NO_CREDENTIALS     0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT 0x2F
#define CTAP2_ERR_NOT_ALLOWED        0x30
#define CTAP2_ERR_PIN_INVALID        0x31
#define CTAP2_ERR_PIN_BLOCKED        0x32
#define CTAP2_ERR_PIN_AUTH_INVALID   0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED   0x34
#define CTAP2_ERR_PIN_NOT_SET        0x35
#define CTAP2_ERR_PIN_REQUIRED       0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION 0x37
#define CTAP2_ERR_PIN_TOKEN_EXPIRED  0x38
#define CTAP2_ERR_REQUEST_TOO_LARGE  0x39
#define CTAP2_ERR_ACTION_TIMEOUT     0x3A
#define CTAP2_ERR_UP_REQUIRED        0x3B
#define CTAP2_ERR_UV_BLOCKED         0x3C
#define CTAP2_ERR_UV_INVALID         0x3D
#define CTAP2_ERR_UNSUPPORTED_OPTION 0x3E

// COSE algorithm identifiers
#define COSE_ALG_ECDSA_WITH_SHA256  -7
#define COSE_ALG_EDDSA              -8
#define COSE_ALG_RSASSA_PSS_SHA256  -37
#define COSE_ALG_RSASSA_PKCS1_SHA256 -257

// COSE key type
#define COSE_KTY_OKP      1
#define COSE_KTY_EC2      2
#define COSE_KTY_RSA      3

// COSE EC2 parameters
#define COSE_KEY_CRV      -1
#define COSE_KEY_X        -2
#define COSE_KEY_Y        -3

// COSE curves
#define COSE_CRV_P256     1
#define COSE_CRV_P384     2
#define COSE_CRV_P521     3
#define COSE_CRV_X25519   4
#define COSE_CRV_X448     5
#define COSE_CRV_ED25519  6
#define COSE_CRV_ED448    7

// Authenticator data flags
#define CTAP_AUTH_DATA_FLAG_UP     0x01  // User Present
#define CTAP_AUTH_DATA_FLAG_UV     0x04  // User Verified
#define CTAP_AUTH_DATA_FLAG_AT     0x40  // Attested credential data present
#define CTAP_AUTH_DATA_FLAG_ED     0x80  // Extension data present

typedef struct Fido2Ctap Fido2Ctap;

typedef bool (*Fido2UserPresenceCallback)(void* context);

/**
 * @brief Allocate CTAP2 instance
 */
Fido2Ctap* fido2_ctap_alloc(Fido2CredentialStore* store);

/**
 * @brief Free CTAP2 instance
 */
void fido2_ctap_free(Fido2Ctap* ctap);

/**
 * @brief Set user presence callback
 */
void fido2_ctap_set_user_presence_callback(
    Fido2Ctap* ctap,
    Fido2UserPresenceCallback callback,
    void* context);

/**
 * @brief Process CTAP2 command
 */
size_t fido2_ctap_process(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len);

/**
 * @brief Get AAGUID
 */
void fido2_ctap_get_aaguid(Fido2Ctap* ctap, uint8_t* aaguid);

#ifdef __cplusplus
}
#endif