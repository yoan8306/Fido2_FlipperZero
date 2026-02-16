#include "fido2_ctap.h"
#include "fido2_app.h"
#include "fido2_cbor.h"
#include "fido2_credential.h"
#include <furi.h>
#include <furi_hal_random.h>
#include <string.h>

#define TAG "FIDO2_CTAP"

struct Fido2Ctap {
    uint8_t aaguid[16];
    Fido2CredentialStore* credential_store;
    Fido2UserPresenceCallback up_callback;
    void* up_context;
};

Fido2Ctap* fido2_ctap_alloc(Fido2CredentialStore* store) {
    Fido2Ctap* ctap = malloc(sizeof(Fido2Ctap));
    memset(ctap, 0, sizeof(Fido2Ctap));
    furi_hal_random_fill_buf(ctap->aaguid, 16);
    ctap->credential_store = store;
    ctap->up_callback = NULL;
    ctap->up_context = NULL;
    FURI_LOG_I(TAG, "CTAP2 module initialized");
    return ctap;
}

void fido2_ctap_free(Fido2Ctap* ctap) {
    if(!ctap) return;
    free(ctap);
}

void fido2_ctap_set_user_presence_callback(
    Fido2Ctap* ctap,
    Fido2UserPresenceCallback callback,
    void* context) {
    if(!ctap) return;
    ctap->up_callback = callback;
    ctap->up_context = context;
}

void fido2_ctap_get_aaguid(Fido2Ctap* ctap, uint8_t* aaguid) {
    if(!ctap || !aaguid) return;
    memcpy(aaguid, ctap->aaguid, 16);
}

/**
 * @brief CTAP2 GetInfo command handler
 * 
 * Returns authenticator information including supported versions,
 * extensions, AAGUID, options, and max message size.
 * 
 * @param ctap CTAP instance
 * @param response Output buffer for response
 * @param max_len Maximum response buffer size
 * @return Response length in bytes
 */
static size_t ctap2_get_info(Fido2Ctap* ctap, uint8_t* response, size_t max_len) {
    if(!ctap || !response || max_len < 200) {
        FURI_LOG_E(TAG, "GetInfo: invalid params or buffer too small");
        if(response && max_len > 0) response[0] = CTAP2_ERR_INVALID_PARAMETER;
        return 1;
    }

    FURI_LOG_I(TAG, "GetInfo");
    size_t offset = 0;
    
    // Status code OK
    response[offset++] = CTAP2_OK;
    
    // Map with 6 entries - keys must be in order: 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
    offset += cbor_encode_map_header(response + offset, 6);
    
    // 0x01: versions (array)
    offset += cbor_encode_uint(response + offset, 0x01);
    offset += cbor_encode_array_header(response + offset, 2);
    offset += cbor_encode_text(response + offset, "FIDO_2_0");
    offset += cbor_encode_text(response + offset, "U2F_V2");
    
    // 0x02: extensions (empty array)
    offset += cbor_encode_uint(response + offset, 0x02);
    offset += cbor_encode_array_header(response + offset, 0);
    
    // 0x03: aaguid (byte string)
    offset += cbor_encode_uint(response + offset, 0x03);
    offset += cbor_encode_bytes(response + offset, ctap->aaguid, 16);
    
    // 0x04: options (map)
    offset += cbor_encode_uint(response + offset, 0x04);
    offset += cbor_encode_map_header(response + offset, 3);
    offset += cbor_encode_text(response + offset, "rk");
    offset += cbor_encode_bool(response + offset, false);  // Resident keys not supported
    offset += cbor_encode_text(response + offset, "up");
    offset += cbor_encode_bool(response + offset, true);   // User presence supported
    offset += cbor_encode_text(response + offset, "uv");
    offset += cbor_encode_bool(response + offset, false);  // User verification not supported
    
    // 0x05: maxMsgSize (unsigned)
    offset += cbor_encode_uint(response + offset, 0x05);
    offset += cbor_encode_uint(response + offset, 1200);
    
    // 0x06: pinProtocols (empty array)
    offset += cbor_encode_uint(response + offset, 0x06);
    offset += cbor_encode_array_header(response + offset, 0);
    
    if(offset > max_len) {
        FURI_LOG_E(TAG, "GetInfo: response too large!");
        response[0] = CTAP2_ERR_REQUEST_TOO_LARGE;
        return 1;
    }
    
    FURI_LOG_I(TAG, "GetInfo done, %u bytes", offset);
    
    // Debug: print first few bytes
    FURI_LOG_I(TAG, "Response first bytes: %02x %02x %02x %02x %02x",
               response[0], response[1], response[2], response[3], response[4]);
    
    return offset;
}

/**
 * @brief CTAP2 MakeCredential command handler (stub)
 * 
 * Creates a new credential for the specified relying party.
 * Currently not implemented - returns unsupported error.
 * 
 * @param ctap CTAP instance
 * @param request Request buffer
 * @param req_len Request length
 * @param response Output buffer
 * @param max_len Maximum response size
 * @return Response length
 */
static size_t ctap2_make_credential(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len) {
    
    UNUSED(ctap);
    UNUSED(request);
    UNUSED(req_len);
    UNUSED(max_len);
    
    FURI_LOG_W(TAG, "MakeCredential: NOT IMPLEMENTED YET (stub)");
    
    if(response && max_len >= 1) {
        response[0] = CTAP2_ERR_UNSUPPORTED_OPTION;
        return 1;
    }
    return 0;
}

/**
 * @brief CTAP2 GetAssertion command handler (stub)
 * 
 * Generates an assertion for authentication.
 * Currently not implemented - returns no credentials error.
 * 
 * @param ctap CTAP instance
 * @param request Request buffer
 * @param req_len Request length
 * @param response Output buffer
 * @param max_len Maximum response size
 * @return Response length
 */
static size_t ctap2_get_assertion(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len) {
    
    UNUSED(ctap);
    UNUSED(request);
    UNUSED(req_len);
    UNUSED(max_len);
    
    FURI_LOG_W(TAG, "GetAssertion: NOT IMPLEMENTED YET (stub)");
    
    if(response && max_len >= 1) {
        response[0] = CTAP2_ERR_NO_CREDENTIALS;
        return 1;
    }
    return 0;
}

/**
 * @brief CTAP2 Reset command handler
 * 
 * Resets the authenticator, deleting all credentials.
 * 
 * @param ctap CTAP instance
 * @param response Output buffer
 * @param max_len Maximum response size
 * @return Response length
 */
static size_t ctap2_reset(Fido2Ctap* ctap, uint8_t* response, size_t max_len) {
    UNUSED(max_len);
    
    FURI_LOG_I(TAG, "Reset");
    fido2_credential_reset(ctap->credential_store);
    
    if(response && max_len >= 1) {
        response[0] = CTAP2_OK;
        return 1;
    }
    return 0;
}

/**
 * @brief Process CTAP2 command
 * 
 * Main entry point for CTAP2 command processing. Routes commands to
 * appropriate handlers based on command byte.
 * 
 * @param ctap CTAP instance
 * @param request Request buffer
 * @param req_len Request length
 * @param response Output buffer
 * @param max_len Maximum response size
 * @return Response length in bytes
 */
size_t fido2_ctap_process(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len) {
    
    // Strict parameter validation
    if(!ctap || !request || !response) {
        FURI_LOG_E(TAG, "NULL params");
        if(response && max_len > 0) {
            response[0] = CTAP2_ERR_INVALID_PARAMETER;
            return 1;
        }
        return 0;
    }
    
    if(req_len < 1) {
        FURI_LOG_E(TAG, "Request too short");
        if(max_len >= 1) {
            response[0] = CTAP2_ERR_INVALID_CBOR;
            return 1;
        }
        return 0;
    }
    
    if(max_len < 1) {
        FURI_LOG_E(TAG, "Response buffer too small");
        return 0;
    }
    
    uint8_t cmd = request[0];
    FURI_LOG_I(TAG, "CTAP2 cmd=0x%02X len=%u", cmd, req_len);
    
    // Print first few bytes of request for debugging
    if(req_len > 1) {
        FURI_LOG_I(TAG, "Request first bytes: %02x %02x %02x", 
                   request[1], request[2], request[3]);
    }
    
    // Route command to appropriate handler
    switch(cmd) {
    case CTAP2_CMD_GET_INFO:
        return ctap2_get_info(ctap, response, max_len);
        
    case CTAP2_CMD_MAKE_CREDENTIAL:
        return ctap2_make_credential(ctap, request + 1, req_len - 1, response, max_len);
        
    case CTAP2_CMD_GET_ASSERTION:
        return ctap2_get_assertion(ctap, request + 1, req_len - 1, response, max_len);
        
    case CTAP2_CMD_RESET:
        return ctap2_reset(ctap, response, max_len);
        
    default:
        FURI_LOG_W(TAG, "Unsupported cmd: 0x%02X", cmd);
        response[0] = CTAP2_ERR_INVALID_COMMAND;
        return 1;
    }
}