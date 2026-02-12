#include "fido2_ctap.h"
#include "fido2_app.h"
#include "fido2_cbor.h"
#include "fido2_credential.h"
#include <furi.h>
#include <furi_hal_random.h>
#include <mbedtls/sha256.h>
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

// GetInfo Command
static size_t ctap2_get_info(Fido2Ctap* ctap, uint8_t* response, size_t max_len) {
    UNUSED(max_len);
    size_t offset = 0;
    FURI_LOG_I(TAG, "Processing GetInfo");
    response[offset++] = CTAP2_OK;
    offset += cbor_encode_map_header(response + offset, 6);
    offset += cbor_encode_uint(response + offset, 0x01);
    offset += cbor_encode_array_header(response + offset, 2);
    offset += cbor_encode_text(response + offset, "FIDO_2_0");
    offset += cbor_encode_text(response + offset, "U2F_V2");
    offset += cbor_encode_uint(response + offset, 0x02);
    offset += cbor_encode_array_header(response + offset, 0);
    offset += cbor_encode_uint(response + offset, 0x03);
    offset += cbor_encode_bytes(response + offset, ctap->aaguid, 16);
    offset += cbor_encode_uint(response + offset, 0x04);
    offset += cbor_encode_map_header(response + offset, 3);
    offset += cbor_encode_text(response + offset, "rk");
    offset += cbor_encode_bool(response + offset, false);
    offset += cbor_encode_text(response + offset, "up");
    offset += cbor_encode_bool(response + offset, true);
    offset += cbor_encode_text(response + offset, "plat");
    offset += cbor_encode_bool(response + offset, false);
    offset += cbor_encode_uint(response + offset, 0x05);
    offset += cbor_encode_uint(response + offset, 1200);
    offset += cbor_encode_uint(response + offset, 0x06);
    offset += cbor_encode_array_header(response + offset, 0);
    return offset;
}

// Build authenticatorData
static size_t build_authenticator_data(
    uint8_t* auth_data,
    const char* rp_id,
    bool user_present,
    bool user_verified,
    Fido2Credential* cred,
    const uint8_t* aaguid,
    uint32_t sign_count) {
    size_t offset = 0;
    uint8_t rp_id_hash[32];
    mbedtls_sha256((const uint8_t*)rp_id, strlen(rp_id), rp_id_hash, 0);
    memcpy(auth_data + offset, rp_id_hash, 32);
    offset += 32;
    uint8_t flags = 0;
    if(user_present) flags |= 0x01;
    if(user_verified) flags |= 0x04;
    if(cred) flags |= 0x40;
    auth_data[offset++] = flags;
    auth_data[offset++] = (sign_count >> 24) & 0xFF;
    auth_data[offset++] = (sign_count >> 16) & 0xFF;
    auth_data[offset++] = (sign_count >> 8) & 0xFF;
    auth_data[offset++] = sign_count & 0xFF;
    if(cred) {
        memcpy(auth_data + offset, aaguid, 16);
        offset += 16;
        auth_data[offset++] = 0;
        auth_data[offset++] = 32;
        memcpy(auth_data + offset, cred->credential_id, 32);
        offset += 32;
        offset += cbor_encode_map_header(auth_data + offset, 5);
        offset += cbor_encode_int(auth_data + offset, 1);
        offset += cbor_encode_int(auth_data + offset, 2);
        offset += cbor_encode_int(auth_data + offset, 3);
        offset += cbor_encode_int(auth_data + offset, -7);
        offset += cbor_encode_int(auth_data + offset, -1);
        offset += cbor_encode_int(auth_data + offset, 1);
        offset += cbor_encode_int(auth_data + offset, -2);
        offset += cbor_encode_bytes(auth_data + offset, cred->public_key_x, 32);
        offset += cbor_encode_int(auth_data + offset, -3);
        offset += cbor_encode_bytes(auth_data + offset, cred->public_key_y, 32);
    }
    return offset;
}

// MakeCredential Command
static size_t ctap2_make_credential(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len) {
    UNUSED(max_len);
    FURI_LOG_I(TAG, "Processing MakeCredential");
    CborDecoder decoder;
    cbor_decoder_init(&decoder, request, req_len);
    size_t map_size;
    if(!cbor_decode_map_size(&decoder, &map_size)) {
        response[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }
    uint8_t client_data_hash[32];
    char rp_id[128] = {0};
    uint8_t user_id[64];
    size_t user_id_len = 0;
    char user_name[64] = {0};
    char user_display_name[64] = {0};
    bool found_required = false;
    for(size_t i = 0; i < map_size; i++) {
        uint64_t key;
        if(!cbor_decode_uint(&decoder, &key)) {
            response[0] = CTAP2_ERR_INVALID_CBOR;
            return 1;
        }
        if(key == 0x01) {
            const uint8_t* hash_data;
            size_t hash_len;
            if(!cbor_decode_bytes(&decoder, &hash_data, &hash_len) || hash_len != 32) {
                response[0] = CTAP2_ERR_INVALID_PARAMETER;
                return 1;
            }
            memcpy(client_data_hash, hash_data, 32);
            found_required = true;
        } else if(key == 0x02) {
            size_t rp_map_size;
            if(!cbor_decode_map_size(&decoder, &rp_map_size)) {
                response[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            for(size_t j = 0; j < rp_map_size; j++) {
                const char* rp_key;
                size_t rp_key_len;
                if(!cbor_decode_text(&decoder, &rp_key, &rp_key_len)) {
                    cbor_skip_value(&decoder);
                    continue;
                }
                if(rp_key_len == 2 && memcmp(rp_key, "id", 2) == 0) {
                    const char* id;
                    size_t id_len;
                    if(cbor_decode_text(&decoder, &id, &id_len)) {
                        strncpy(rp_id, id, id_len < 127 ? id_len : 127);
                        rp_id[id_len < 127 ? id_len : 127] = '\0';
                    }
                } else {
                    cbor_skip_value(&decoder);
                }
            }
        } else if(key == 0x03) {
            size_t user_map_size;
            if(!cbor_decode_map_size(&decoder, &user_map_size)) {
                response[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            for(size_t j = 0; j < user_map_size; j++) {
                const char* user_key;
                size_t user_key_len;
                if(!cbor_decode_text(&decoder, &user_key, &user_key_len)) {
                    cbor_skip_value(&decoder);
                    continue;
                }
                if(user_key_len == 2 && memcmp(user_key, "id", 2) == 0) {
                    const uint8_t* id;
                    size_t id_len;
                    if(cbor_decode_bytes(&decoder, &id, &id_len)) {
                        memcpy(user_id, id, id_len < 64 ? id_len : 64);
                        user_id_len = id_len < 64 ? id_len : 64;
                    }
                } else if(user_key_len == 4 && memcmp(user_key, "name", 4) == 0) {
                    const char* name;
                    size_t name_len;
                    if(cbor_decode_text(&decoder, &name, &name_len)) {
                        strncpy(user_name, name, name_len < 63 ? name_len : 63);
                        user_name[name_len < 63 ? name_len : 63] = '\0';
                    }
                } else if(user_key_len == 11 && memcmp(user_key, "displayName", 11) == 0) {
                    const char* dname;
                    size_t dname_len;
                    if(cbor_decode_text(&decoder, &dname, &dname_len)) {
                        strncpy(user_display_name, dname, dname_len < 63 ? dname_len : 63);
                        user_display_name[dname_len < 63 ? dname_len : 63] = '\0';
                    }
                } else {
                    cbor_skip_value(&decoder);
                }
            }
        } else {
            cbor_skip_value(&decoder);
        }
    }
    if(!found_required || strlen(rp_id) == 0 || user_id_len == 0) {
        response[0] = CTAP2_ERR_MISSING_PARAMETER;
        return 1;
    }
    if(ctap->up_callback && !ctap->up_callback(ctap->up_context)) {
        response[0] = CTAP2_ERR_OPERATION_DENIED;
        return 1;
    }
    Fido2Credential* cred = fido2_credential_create(
        ctap->credential_store,
        rp_id,
        user_id,
        user_id_len,
        user_name,
        user_display_name);
    if(!cred) {
        response[0] = CTAP2_ERR_KEY_STORE_FULL;
        return 1;
    }
    uint8_t auth_data[512];
    size_t auth_data_len = build_authenticator_data(
        auth_data,
        rp_id,
        true,
        false,
        cred,
        ctap->aaguid,
        cred->sign_count);
    size_t offset = 0;
    response[offset++] = CTAP2_OK;
    offset += cbor_encode_map_header(response + offset, 3);
    offset += cbor_encode_uint(response + offset, 0x01);
    offset += cbor_encode_text(response + offset, "none");
    offset += cbor_encode_uint(response + offset, 0x02);
    offset += cbor_encode_bytes(response + offset, auth_data, auth_data_len);
    offset += cbor_encode_uint(response + offset, 0x03);
    offset += cbor_encode_map_header(response + offset, 2);
    offset += cbor_encode_text(response + offset, "alg");
    offset += cbor_encode_int(response + offset, -7);
    offset += cbor_encode_text(response + offset, "sig");
    offset += cbor_encode_bytes(response + offset, (uint8_t*)"", 0);
    FURI_LOG_I(TAG, "MakeCredential OK, response size: %d", offset);
    return offset;
}

// GetAssertion Command
static size_t ctap2_get_assertion(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len) {
    UNUSED(max_len);
    FURI_LOG_I(TAG, "Processing GetAssertion");
    CborDecoder decoder;
    cbor_decoder_init(&decoder, request, req_len);
    size_t map_size;
    if(!cbor_decode_map_size(&decoder, &map_size)) {
        response[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }
    char rp_id[128] = {0};
    uint8_t client_data_hash[32];
    uint8_t credential_id[32];
    size_t credential_id_len = 0;
    bool found_required = false;
    for(size_t i = 0; i < map_size; i++) {
        uint64_t key;
        if(!cbor_decode_uint(&decoder, &key)) {
            response[0] = CTAP2_ERR_INVALID_CBOR;
            return 1;
        }
        if(key == 0x01) {
            const char* rp;
            size_t rp_len;
            if(!cbor_decode_text(&decoder, &rp, &rp_len)) {
                response[0] = CTAP2_ERR_INVALID_PARAMETER;
                return 1;
            }
            strncpy(rp_id, rp, rp_len < 127 ? rp_len : 127);
            rp_id[rp_len < 127 ? rp_len : 127] = '\0';
            found_required = true;
        } else if(key == 0x02) {
            const uint8_t* hash;
            size_t hash_len;
            if(!cbor_decode_bytes(&decoder, &hash, &hash_len) || hash_len != 32) {
                response[0] = CTAP2_ERR_INVALID_PARAMETER;
                return 1;
            }
            memcpy(client_data_hash, hash, 32);
        } else if(key == 0x03) {
            size_t allow_list_size;
            if(cbor_decode_array_size(&decoder, &allow_list_size)) {
                for(size_t j = 0; j < allow_list_size; j++) {
                    size_t desc_size;
                    if(!cbor_decode_map_size(&decoder, &desc_size)) {
                        cbor_skip_value(&decoder);
                        continue;
                    }
                    for(size_t k = 0; k < desc_size; k++) {
                        const char* desc_key;
                        size_t desc_key_len;
                        if(!cbor_decode_text(&decoder, &desc_key, &desc_key_len)) {
                            cbor_skip_value(&decoder);
                            continue;
                        }
                        if(desc_key_len == 2 && memcmp(desc_key, "id", 2) == 0) {
                            const uint8_t* id;
                            size_t id_len;
                            if(cbor_decode_bytes(&decoder, &id, &id_len) && id_len == 32) {
                                memcpy(credential_id, id, 32);
                                credential_id_len = 32;
                            }
                        } else {
                            cbor_skip_value(&decoder);
                        }
                    }
                }
            }
        } else {
            cbor_skip_value(&decoder);
        }
    }
    if(!found_required) {
        response[0] = CTAP2_ERR_MISSING_PARAMETER;
        return 1;
    }
    Fido2Credential* cred = NULL;
    if(credential_id_len == 32) {
        cred = fido2_credential_find_by_id(ctap->credential_store, credential_id, credential_id_len);
    }
    if(!cred) {
        cred = fido2_credential_find_by_rp(ctap->credential_store, rp_id);
    }
    if(!cred) {
        response[0] = CTAP2_ERR_NO_CREDENTIALS;
        return 1;
    }
    if(ctap->up_callback && !ctap->up_callback(ctap->up_context)) {
        response[0] = CTAP2_ERR_OPERATION_DENIED;
        return 1;
    }
    uint8_t auth_data[256];
    size_t auth_data_len = build_authenticator_data(
        auth_data,
        rp_id,
        true,
        false,
        NULL,
        ctap->aaguid,
        cred->sign_count);
    uint8_t data_to_sign[512];
    memcpy(data_to_sign, auth_data, auth_data_len);
    memcpy(data_to_sign + auth_data_len, client_data_hash, 32);
    uint8_t signature[72];
    size_t signature_len;
    if(!fido2_credential_sign(cred, data_to_sign, auth_data_len + 32, signature, &signature_len)) {
        response[0] = CTAP2_ERR_INVALID_CREDENTIAL;
        return 1;
    }
    size_t offset = 0;
    response[offset++] = CTAP2_OK;
    offset += cbor_encode_map_header(response + offset, 3);
    offset += cbor_encode_uint(response + offset, 0x01);
    offset += cbor_encode_map_header(response + offset, 2);
    offset += cbor_encode_text(response + offset, "id");
    offset += cbor_encode_bytes(response + offset, cred->credential_id, 32);
    offset += cbor_encode_text(response + offset, "type");
    offset += cbor_encode_text(response + offset, "public-key");
    offset += cbor_encode_uint(response + offset, 0x02);
    offset += cbor_encode_bytes(response + offset, auth_data, auth_data_len);
    offset += cbor_encode_uint(response + offset, 0x03);
    offset += cbor_encode_bytes(response + offset, signature, signature_len);
    FURI_LOG_I(TAG, "GetAssertion OK, response size: %d", offset);
    return offset;
}

// Main CTAP processing
size_t fido2_ctap_process(
    Fido2Ctap* ctap,
    const uint8_t* request,
    size_t req_len,
    uint8_t* response,
    size_t max_len) {
    if(!ctap || !request || !response || req_len < 1) {
        response[0] = CTAP2_ERR_INVALID_LENGTH;
        return 1;
    }
    uint8_t cmd = request[0];
    FURI_LOG_D(TAG, "CTAP2 command: 0x%02X", cmd);
    switch(cmd) {
    case CTAP2_CMD_GET_INFO:
        return ctap2_get_info(ctap, response, max_len);
    case CTAP2_CMD_MAKE_CREDENTIAL:
        return ctap2_make_credential(ctap, request + 1, req_len - 1, response, max_len);
    case CTAP2_CMD_GET_ASSERTION:
        return ctap2_get_assertion(ctap, request + 1, req_len - 1, response, max_len);
    case CTAP2_CMD_RESET:
        fido2_credential_reset(ctap->credential_store);
        response[0] = CTAP2_OK;
        return 1;
    default:
        FURI_LOG_W(TAG, "Unsupported command: 0x%02X", cmd);
        response[0] = CTAP2_ERR_INVALID_COMMAND;
        return 1;
    }
}
