#include "fido2_ctap.h"
#include "fido2_app.h"
#include "fido2_cbor.h"
#include "fido2_credential.h"
#include <furi.h>
#include <furi_hal_random.h>
#include <mbedtls/sha256.h>
#include <string.h>

#define TAG "FIDO2_CTAP"
#define AAGUID_SIZE 16
#define MAX_CREDENTIAL_ID_SIZE 32

struct Fido2Ctap {
    uint8_t aaguid[16];
    Fido2CredentialStore* credential_store;
    Fido2UserPresenceCallback up_callback;
    void* up_context;
};

/**
 * @brief Wait for user presence with timeout
 */
static bool wait_for_user_presence(Fido2Ctap* ctap, uint32_t timeout_ms) {
    (void)timeout_ms; // Mark as unused to avoid warning
    if(!ctap->up_callback) return false;
    
    // Simple implementation - in real world, this would be async
    // For now, we just call the callback which should block until user responds
    return ctap->up_callback(ctap->up_context);
}

/**
 * @brief Build authenticator data for MakeCredential
 */
static size_t build_make_credential_auth_data(
    Fido2Ctap* ctap,
    const uint8_t* rp_id_hash,
    uint8_t flags,
    uint32_t sign_count,
    const Fido2Credential* cred,
    uint8_t* output,
    size_t max_len) {
    
    (void)max_len; // Mark as unused to avoid warning
    size_t offset = 0;
    
    // RP ID hash (32 bytes)
    memcpy(output + offset, rp_id_hash, 32);
    offset += 32;
    
    // Flags (1 byte)
    output[offset++] = flags;
    
    // Signature counter (4 bytes, big endian)
    output[offset++] = (sign_count >> 24) & 0xFF;
    output[offset++] = (sign_count >> 16) & 0xFF;
    output[offset++] = (sign_count >> 8) & 0xFF;
    output[offset++] = sign_count & 0xFF;
    
    // Attested credential data (if AT flag set)
    if(flags & CTAP_AUTH_DATA_FLAG_AT) {
        if(!cred) return offset;
        
        // AAGUID (16 bytes)
        memcpy(output + offset, ctap->aaguid, 16);
        offset += 16;
        
        // Credential ID length (2 bytes) - always 32 for now
        output[offset++] = 0;
        output[offset++] = MAX_CREDENTIAL_ID_SIZE;
        
        // Credential ID (32 bytes)
        memcpy(output + offset, cred->credential_id, MAX_CREDENTIAL_ID_SIZE);
        offset += MAX_CREDENTIAL_ID_SIZE;
        
        // COSE Key (public key in COSE format)
        // Map with 5 entries: kty, alg, crv, x, y
        offset += cbor_encode_map_header(output + offset, 5);
        
        // kty (key type) = 2 (EC2)
        offset += cbor_encode_int(output + offset, 1);  // key 1
        offset += cbor_encode_int(output + offset, COSE_KTY_EC2);
        
        // alg (algorithm) = -7 (ES256)
        offset += cbor_encode_int(output + offset, 3);  // key 3
        offset += cbor_encode_int(output + offset, COSE_ALG_ECDSA_WITH_SHA256);
        
        // crv (curve) = 1 (P-256)
        offset += cbor_encode_int(output + offset, -1); // key -1
        offset += cbor_encode_int(output + offset, COSE_CRV_P256);
        
        // x coordinate (32 bytes)
        offset += cbor_encode_int(output + offset, -2); // key -2
        offset += cbor_encode_bytes(output + offset, cred->public_key_x, 32);
        
        // y coordinate (32 bytes)
        offset += cbor_encode_int(output + offset, -3); // key -3
        offset += cbor_encode_bytes(output + offset, cred->public_key_y, 32);
    }
    
    return offset;
}

/**
 * @brief Build authenticator data for GetAssertion
 */
static size_t build_get_assertion_auth_data(
    const uint8_t* rp_id_hash,
    uint8_t flags,
    uint32_t sign_count,
    uint8_t* output) {
    
    size_t offset = 0;
    
    // RP ID hash (32 bytes)
    memcpy(output + offset, rp_id_hash, 32);
    offset += 32;
    
    // Flags (1 byte)
    output[offset++] = flags;
    
    // Signature counter (4 bytes, big endian)
    output[offset++] = (sign_count >> 24) & 0xFF;
    output[offset++] = (sign_count >> 16) & 0xFF;
    output[offset++] = (sign_count >> 8) & 0xFF;
    output[offset++] = sign_count & 0xFF;
    
    return offset;
}

/**
 * @brief CTAP2 GetInfo command handler
 * 
 * Returns authenticator information including supported versions,
 * extensions, AAGUID, options, and max message size.
 */
static size_t ctap2_get_info(Fido2Ctap* ctap, uint8_t* response, size_t max_len) {
    if(!ctap || !response || max_len < 200) {
        FURI_LOG_E(TAG, "GetInfo: invalid params");
        if(response && max_len > 0) response[0] = CTAP1_ERR_INVALID_PARAMETER;
        return 1;
    }

    FURI_LOG_I(TAG, "GetInfo");
    size_t offset = 0;
    
    // Status code OK
    response[offset++] = CTAP2_OK;
    
    // Map with 7 entries
    offset += cbor_encode_map_header(response + offset, 7);
    
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
    offset += cbor_encode_bool(response + offset, true);   // Resident keys supported
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
    
    // 0x07: algorithms (array of supported algorithms)
    offset += cbor_encode_uint(response + offset, 0x07);
    offset += cbor_encode_array_header(response + offset, 1);
    
    // Algorithm entry (map with 2 entries)
    offset += cbor_encode_map_header(response + offset, 2);
    offset += cbor_encode_text(response + offset, "alg");
    offset += cbor_encode_int(response + offset, COSE_ALG_ECDSA_WITH_SHA256);
    offset += cbor_encode_text(response + offset, "type");
    offset += cbor_encode_text(response + offset, "public-key");
    
    if(offset > max_len) {
        FURI_LOG_E(TAG, "GetInfo: response too large");
        response[0] = CTAP2_ERR_REQUEST_TOO_LARGE;
        return 1;
    }
    
    FURI_LOG_I(TAG, "GetInfo done, %u bytes", offset);
    return offset;
}

/**
 * @brief CTAP2 MakeCredential command handler
 * 
 * Creates a new credential for the specified relying party.
 */
static size_t ctap2_make_credential(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len) {
    
    FURI_LOG_I(TAG, "MakeCredential");
    
    if(!ctap || !request || !response || max_len < 300) {
        FURI_LOG_E(TAG, "Invalid parameters");
        if(response && max_len > 0) response[0] = CTAP1_ERR_INVALID_PARAMETER;
        return 1;
    }
    
    CborDecoder decoder;
    cbor_decoder_init(&decoder, request, req_len);
    
    // Parse request parameters
    const uint8_t* client_data_hash = NULL;
    size_t client_data_hash_len = 0;
    const uint8_t* rp_id = NULL;
    size_t rp_id_len = 0;
    const uint8_t* rp_name = NULL;
    size_t rp_name_len = 0;
    const uint8_t* user_id = NULL;
    size_t user_id_len = 0;
    const uint8_t* user_name = NULL;
    size_t user_name_len = 0;
    const uint8_t* user_display_name = NULL;
    size_t user_display_name_len = 0;
    bool resident_key = false;
    bool user_verification = false;
    
    // Mark unused variables to avoid warnings
    (void)resident_key;
    (void)user_verification;
    (void)rp_name;
    (void)rp_name_len;
    
    // Parse map
    size_t map_size;
    if(!cbor_decode_map_size(&decoder, &map_size)) {
        FURI_LOG_E(TAG, "Invalid CBOR map");
        response[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }
    
    for(size_t i = 0; i < map_size; i++) {
        uint64_t key;
        if(!cbor_decode_uint(&decoder, &key)) {
            FURI_LOG_E(TAG, "Invalid map key");
            response[0] = CTAP2_ERR_INVALID_CBOR;
            return 1;
        }
        
        switch(key) {
        case 1: // clientDataHash
            if(!cbor_decode_bytes(&decoder, &client_data_hash, &client_data_hash_len) ||
               client_data_hash_len != 32) {
                FURI_LOG_E(TAG, "Invalid clientDataHash");
                response[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            break;
            
        case 2: // rp
            {
                size_t rp_map_size;
                if(!cbor_decode_map_size(&decoder, &rp_map_size)) {
                    FURI_LOG_E(TAG, "Invalid rp map");
                    response[0] = CTAP2_ERR_INVALID_CBOR;
                    return 1;
                }
                
                for(size_t j = 0; j < rp_map_size; j++) {
                    uint64_t rp_key;
                    if(!cbor_decode_uint(&decoder, &rp_key)) {
                        FURI_LOG_E(TAG, "Invalid rp map key");
                        response[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                    
                    switch(rp_key) {
                    case 1: // id
                        if(!cbor_decode_text(&decoder, (const char**)&rp_id, &rp_id_len)) {
                            FURI_LOG_E(TAG, "Invalid rp id");
                            response[0] = CTAP2_ERR_INVALID_CBOR;
                            return 1;
                        }
                        break;
                    case 2: // name
                        if(!cbor_decode_text(&decoder, (const char**)&rp_name, &rp_name_len)) {
                            FURI_LOG_E(TAG, "Invalid rp name");
                            response[0] = CTAP2_ERR_INVALID_CBOR;
                            return 1;
                        }
                        break;
                    default:
                        if(!cbor_skip_value(&decoder)) {
                            response[0] = CTAP2_ERR_INVALID_CBOR;
                            return 1;
                        }
                        break;
                    }
                }
            }
            break;
            
        case 3: // user
            {
                size_t user_map_size;
                if(!cbor_decode_map_size(&decoder, &user_map_size)) {
                    FURI_LOG_E(TAG, "Invalid user map");
                    response[0] = CTAP2_ERR_INVALID_CBOR;
                    return 1;
                }
                
                for(size_t j = 0; j < user_map_size; j++) {
                    uint64_t user_key;
                    if(!cbor_decode_uint(&decoder, &user_key)) {
                        FURI_LOG_E(TAG, "Invalid user map key");
                        response[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                    
                    switch(user_key) {
                    case 1: // id
                        if(!cbor_decode_bytes(&decoder, &user_id, &user_id_len) ||
                           user_id_len > 64) {
                            FURI_LOG_E(TAG, "Invalid user id");
                            response[0] = CTAP2_ERR_INVALID_CBOR;
                            return 1;
                        }
                        break;
                    case 2: // name
                        if(!cbor_decode_text(&decoder, (const char**)&user_name, &user_name_len)) {
                            FURI_LOG_E(TAG, "Invalid user name");
                            response[0] = CTAP2_ERR_INVALID_CBOR;
                            return 1;
                        }
                        break;
                    case 3: // displayName
                        if(!cbor_decode_text(&decoder, (const char**)&user_display_name, &user_display_name_len)) {
                            FURI_LOG_E(TAG, "Invalid user display name");
                            response[0] = CTAP2_ERR_INVALID_CBOR;
                            return 1;
                        }
                        break;
                    default:
                        if(!cbor_skip_value(&decoder)) {
                            response[0] = CTAP2_ERR_INVALID_CBOR;
                            return 1;
                        }
                        break;
                    }
                }
            }
            break;
            
        case 4: // pubKeyCredParams
            {
                size_t array_size;
                if(!cbor_decode_array_size(&decoder, &array_size)) {
                    FURI_LOG_E(TAG, "Invalid pubKeyCredParams");
                    response[0] = CTAP2_ERR_INVALID_CBOR;
                    return 1;
                }
                
                // Skip for now - we only support ES256
                for(size_t j = 0; j < array_size; j++) {
                    if(!cbor_skip_value(&decoder)) {
                        response[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                }
            }
            break;
            
        case 5: // excludeList
            {
                size_t array_size;
                if(!cbor_decode_array_size(&decoder, &array_size)) {
                    FURI_LOG_E(TAG, "Invalid excludeList");
                    response[0] = CTAP2_ERR_INVALID_CBOR;
                    return 1;
                }
                
                // Check if credential already exists
                for(size_t j = 0; j < array_size; j++) {
                    size_t cred_map_size;
                    if(!cbor_decode_map_size(&decoder, &cred_map_size)) {
                        response[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                    
                    const uint8_t* cred_id = NULL;
                    size_t cred_id_len = 0;
                    
                    for(size_t k = 0; k < cred_map_size; k++) {
                        uint64_t cred_key;
                        if(!cbor_decode_uint(&decoder, &cred_key)) {
                            response[0] = CTAP2_ERR_INVALID_CBOR;
                            return 1;
                        }
                        
                        if(cred_key == 2) { // id
                            if(!cbor_decode_bytes(&decoder, &cred_id, &cred_id_len)) {
                                response[0] = CTAP2_ERR_INVALID_CBOR;
                                return 1;
                            }
                        } else {
                            if(!cbor_skip_value(&decoder)) {
                                response[0] = CTAP2_ERR_INVALID_CBOR;
                                return 1;
                            }
                        }
                    }
                    
                    // Check if credential exists
                    if(cred_id && cred_id_len == 32) {
                        Fido2Credential* existing = fido2_credential_find_by_id(
                            ctap->credential_store, cred_id, cred_id_len);
                        if(existing) {
                            FURI_LOG_W(TAG, "Credential excluded");
                            response[0] = CTAP2_ERR_CREDENTIAL_EXCLUDED;
                            return 1;
                        }
                    }
                }
            }
            break;
            
        case 6: // extensions
            if(!cbor_skip_value(&decoder)) {
                response[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            break;
            
        case 7: // options
            {
                size_t options_map_size;
                if(!cbor_decode_map_size(&decoder, &options_map_size)) {
                    response[0] = CTAP2_ERR_INVALID_CBOR;
                    return 1;
                }
                
                for(size_t j = 0; j < options_map_size; j++) {
                    const char* option_key;
                    size_t option_key_len;
                    if(!cbor_decode_text(&decoder, &option_key, &option_key_len)) {
                        response[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                    
                    bool value;
                    if(!cbor_decode_bool(&decoder, &value)) {
                        response[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                    
                    if(option_key_len == 2 && memcmp(option_key, "rk", 2) == 0) {
                        resident_key = value;
                    } else if(option_key_len == 2 && memcmp(option_key, "uv", 2) == 0) {
                        user_verification = value;
                    }
                }
            }
            break;
            
        default:
            if(!cbor_skip_value(&decoder)) {
                response[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            break;
        }
    }
    
    // Validate required parameters
    if(!client_data_hash || !rp_id || !user_id) {
        FURI_LOG_E(TAG, "Missing required parameter");
        response[0] = CTAP2_ERR_MISSING_PARAMETER;
        return 1;
    }
    
    // Check if credential already exists for this RP and user
    char rp_id_str[128];
    size_t copy_len = rp_id_len < 127 ? rp_id_len : 127;
    memcpy(rp_id_str, rp_id, copy_len);
    rp_id_str[copy_len] = '\0';
    
    Fido2Credential* existing = fido2_credential_find_by_rp(ctap->credential_store, rp_id_str);
    if(existing) {
        FURI_LOG_W(TAG, "Credential already exists for this RP");
        // In a real implementation, we might want to allow multiple credentials per RP
    }
    
    // Wait for user presence
    if(!wait_for_user_presence(ctap, 30000)) { // 30 second timeout
        FURI_LOG_W(TAG, "User presence timeout");
        response[0] = CTAP2_ERR_USER_ACTION_TIMEOUT;
        return 1;
    }
    
    // Create user ID string
    char user_name_str[64] = {0};
    if(user_name) {
        copy_len = user_name_len < 63 ? user_name_len : 63;
        memcpy(user_name_str, user_name, copy_len);
    }
    
    char user_display_str[64] = {0};
    if(user_display_name) {
        copy_len = user_display_name_len < 63 ? user_display_name_len : 63;
        memcpy(user_display_str, user_display_name, copy_len);
    }
    
    // Create new credential
    Fido2Credential* cred = fido2_credential_create(
        ctap->credential_store,
        rp_id_str,
        user_id,
        user_id_len,
        user_name_str,
        user_display_str);
    
    if(!cred) {
        FURI_LOG_E(TAG, "Failed to create credential");
        response[0] = CTAP2_ERR_KEY_STORE_FULL;
        return 1;
    }
    
    // Compute RP ID hash
    uint8_t rp_id_hash[32];
    mbedtls_sha256((const uint8_t*)rp_id_str, strlen(rp_id_str), rp_id_hash, 0);
    
    // Build authenticator data
    uint8_t auth_data[512];
    size_t auth_data_len = build_make_credential_auth_data(
        ctap,
        rp_id_hash,
        CTAP_AUTH_DATA_FLAG_UP | CTAP_AUTH_DATA_FLAG_AT,
        1, // Initial signature count
        cred,
        auth_data,
        sizeof(auth_data));
    
    // Build signature data (authData + clientDataHash)
    uint8_t signature_data[512 + 32];
    memcpy(signature_data, auth_data, auth_data_len);
    memcpy(signature_data + auth_data_len, client_data_hash, 32);
    
    // Sign
    uint8_t signature[128];
    size_t signature_len = 0;
    if(!fido2_credential_sign(cred, signature_data, auth_data_len + 32, signature, &signature_len)) {
        FURI_LOG_E(TAG, "Failed to sign");
        response[0] = CTAP2_ERR_PROCESSING;
        return 1;
    }
    
    // Build response
    size_t offset = 0;
    response[offset++] = CTAP2_OK;
    
    // Map with 3 entries
    offset += cbor_encode_map_header(response + offset, 3);
    
    // 1: fmt (string)
    offset += cbor_encode_uint(response + offset, 1);
    offset += cbor_encode_text(response + offset, "packed");
    
    // 2: authData (byte string)
    offset += cbor_encode_uint(response + offset, 2);
    offset += cbor_encode_bytes(response + offset, auth_data, auth_data_len);
    
    // 3: attStmt (map with signature)
    offset += cbor_encode_uint(response + offset, 3);
    offset += cbor_encode_map_header(response + offset, 1);
    offset += cbor_encode_text(response + offset, "sig");
    offset += cbor_encode_bytes(response + offset, signature, signature_len);
    
    if(offset > max_len) {
        FURI_LOG_E(TAG, "Response too large");
        response[0] = CTAP2_ERR_REQUEST_TOO_LARGE;
        return 1;
    }
    
    FURI_LOG_I(TAG, "MakeCredential success, credential ID: %02x%02x...",
               cred->credential_id[0], cred->credential_id[1]);
    
    return offset;
}

/**
 * @brief CTAP2 GetAssertion command handler
 * 
 * Generates an assertion for authentication.
 */
static size_t ctap2_get_assertion(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len) {
    
    FURI_LOG_I(TAG, "GetAssertion");
    
    if(!ctap || !request || !response || max_len < 300) {
        FURI_LOG_E(TAG, "Invalid parameters");
        if(response && max_len > 0) response[0] = CTAP1_ERR_INVALID_PARAMETER;
        return 1;
    }
    
    CborDecoder decoder;
    cbor_decoder_init(&decoder, request, req_len);
    
    // Parse request parameters
    const uint8_t* rp_id = NULL;
    size_t rp_id_len = 0;
    const uint8_t* client_data_hash = NULL;
    size_t client_data_hash_len = 0;
    const uint8_t* allow_list = NULL;
    size_t allow_list_len = 0;
    bool user_presence = true; // Default to true
    
    // Mark unused variables to avoid warnings
    (void)allow_list;
    (void)allow_list_len;
    
    size_t map_size;
    if(!cbor_decode_map_size(&decoder, &map_size)) {
        FURI_LOG_E(TAG, "Invalid CBOR map");
        response[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }
    
    for(size_t i = 0; i < map_size; i++) {
        uint64_t key;
        if(!cbor_decode_uint(&decoder, &key)) {
            FURI_LOG_E(TAG, "Invalid map key");
            response[0] = CTAP2_ERR_INVALID_CBOR;
            return 1;
        }
        
        switch(key) {
        case 1: // rpId
            if(!cbor_decode_text(&decoder, (const char**)&rp_id, &rp_id_len)) {
                FURI_LOG_E(TAG, "Invalid rpId");
                response[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            break;
            
        case 2: // clientDataHash
            if(!cbor_decode_bytes(&decoder, &client_data_hash, &client_data_hash_len) ||
               client_data_hash_len != 32) {
                FURI_LOG_E(TAG, "Invalid clientDataHash");
                response[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            break;
            
        case 3: // allowList
            {
                size_t array_size;
                if(!cbor_decode_array_size(&decoder, &array_size)) {
                    FURI_LOG_E(TAG, "Invalid allowList");
                    response[0] = CTAP2_ERR_INVALID_CBOR;
                    return 1;
                }
                // We'll just skip for now and find by RP ID
                for(size_t j = 0; j < array_size; j++) {
                    if(!cbor_skip_value(&decoder)) {
                        response[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                }
            }
            break;
            
        case 4: // extensions
            if(!cbor_skip_value(&decoder)) {
                response[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            break;
            
        case 5: // options
            {
                size_t options_map_size;
                if(!cbor_decode_map_size(&decoder, &options_map_size)) {
                    response[0] = CTAP2_ERR_INVALID_CBOR;
                    return 1;
                }
                
                for(size_t j = 0; j < options_map_size; j++) {
                    const char* option_key;
                    size_t option_key_len;
                    if(!cbor_decode_text(&decoder, &option_key, &option_key_len)) {
                        response[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                    
                    bool value;
                    if(!cbor_decode_bool(&decoder, &value)) {
                        response[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                    
                    if(option_key_len == 2 && memcmp(option_key, "up", 2) == 0) {
                        user_presence = value;
                    }
                }
            }
            break;
            
        case 6: // pinAuth
            if(!cbor_skip_value(&decoder)) {
                response[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            break;
            
        default:
            if(!cbor_skip_value(&decoder)) {
                response[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            break;
        }
    }
    
    // Validate required parameters
    if(!rp_id || !client_data_hash) {
        FURI_LOG_E(TAG, "Missing required parameter");
        response[0] = CTAP2_ERR_MISSING_PARAMETER;
        return 1;
    }
    
    char rp_id_str[128];
    size_t copy_len = rp_id_len < 127 ? rp_id_len : 127;
    memcpy(rp_id_str, rp_id, copy_len);
    rp_id_str[copy_len] = '\0';
    
    // Find credential for this RP
    Fido2Credential* cred = fido2_credential_find_by_rp(ctap->credential_store, rp_id_str);
    if(!cred) {
        FURI_LOG_W(TAG, "No credential found for RP: %s", rp_id_str);
        response[0] = CTAP2_ERR_NO_CREDENTIALS;
        return 1;
    }
    
    // Wait for user presence if required
    if(user_presence) {
        if(!wait_for_user_presence(ctap, 30000)) {
            FURI_LOG_W(TAG, "User presence timeout");
            response[0] = CTAP2_ERR_USER_ACTION_TIMEOUT;
            return 1;
        }
    }
    
    // Compute RP ID hash
    uint8_t rp_id_hash[32];
    mbedtls_sha256((const uint8_t*)rp_id_str, strlen(rp_id_str), rp_id_hash, 0);
    
    // Build authenticator data
    uint8_t auth_data[512];
    size_t auth_data_len = build_get_assertion_auth_data(
        rp_id_hash,
        CTAP_AUTH_DATA_FLAG_UP,
        cred->sign_count + 1,
        auth_data);
    
    // Build signature data (authData + clientDataHash)
    uint8_t signature_data[512 + 32];
    memcpy(signature_data, auth_data, auth_data_len);
    memcpy(signature_data + auth_data_len, client_data_hash, 32);
    
    // Sign
    uint8_t signature[128];
    size_t signature_len = 0;
    if(!fido2_credential_sign(cred, signature_data, auth_data_len + 32, signature, &signature_len)) {
        FURI_LOG_E(TAG, "Failed to sign");
        response[0] = CTAP2_ERR_PROCESSING;
        return 1;
    }
    
    // Build response
    size_t offset = 0;
    response[offset++] = CTAP2_OK;
    
    // Map with 3 entries
    offset += cbor_encode_map_header(response + offset, 3);
    
    // 1: credential (optional)
    offset += cbor_encode_uint(response + offset, 1);
    offset += cbor_encode_map_header(response + offset, 1);
    offset += cbor_encode_text(response + offset, "id");
    offset += cbor_encode_bytes(response + offset, cred->credential_id, 32);
    
    // 2: authData
    offset += cbor_encode_uint(response + offset, 2);
    offset += cbor_encode_bytes(response + offset, auth_data, auth_data_len);
    
    // 3: signature
    offset += cbor_encode_uint(response + offset, 3);
    offset += cbor_encode_bytes(response + offset, signature, signature_len);
    
    if(offset > max_len) {
        FURI_LOG_E(TAG, "Response too large");
        response[0] = CTAP2_ERR_REQUEST_TOO_LARGE;
        return 1;
    }
    
    // Increment signature counter
    cred->sign_count++;
    
    FURI_LOG_I(TAG, "GetAssertion success, RP: %s, counter: %lu", rp_id_str, cred->sign_count);
    
    return offset;
}

/**
 * @brief CTAP2 Reset command handler
 * 
 * Resets the authenticator, deleting all credentials.
 */
static size_t ctap2_reset(Fido2Ctap* ctap, uint8_t* response, size_t max_len) {
    (void)max_len;
    
    FURI_LOG_I(TAG, "Reset");
    fido2_credential_reset(ctap->credential_store);
    
    if(response && max_len >= 1) {
        response[0] = CTAP2_OK;
        return 1;
    }
    return 0;
}

Fido2Ctap* fido2_ctap_alloc(Fido2CredentialStore* store) {
    Fido2Ctap* ctap = malloc(sizeof(Fido2Ctap));
    if(!ctap) return NULL;
    
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

size_t fido2_ctap_process(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len) {
    
    if(!ctap || !request || !response) {
        FURI_LOG_E(TAG, "NULL params");
        if(response && max_len > 0) {
            response[0] = CTAP1_ERR_INVALID_PARAMETER;
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
    
    switch(cmd) {
    case CTAP2_CMD_GET_INFO:
        return ctap2_get_info(ctap, response, max_len);
        
    case CTAP2_CMD_MAKE_CREDENTIAL:
        if(req_len < 2) {
            response[0] = CTAP2_ERR_INVALID_CBOR;
            return 1;
        }
        return ctap2_make_credential(ctap, request + 1, req_len - 1, response, max_len);
        
    case CTAP2_CMD_GET_ASSERTION:
        if(req_len < 2) {
            response[0] = CTAP2_ERR_INVALID_CBOR;
            return 1;
        }
        return ctap2_get_assertion(ctap, request + 1, req_len - 1, response, max_len);
        
    case CTAP2_CMD_RESET:
        return ctap2_reset(ctap, response, max_len);
        
    default:
        FURI_LOG_W(TAG, "Unsupported cmd: 0x%02X", cmd);
        response[0] = CTAP1_ERR_INVALID_COMMAND;
        return 1;
    }
}

void fido2_ctap_get_aaguid(Fido2Ctap* ctap, uint8_t* aaguid) {
    if(!ctap || !aaguid) return;
    memcpy(aaguid, ctap->aaguid, 16);
}