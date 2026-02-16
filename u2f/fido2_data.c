#include "fido2_data.h"
#include "fido2_credential.h"
#include <furi.h>
#include <storage/storage.h>
#include <flipper_format/flipper_format.h>

#define TAG "FIDO2_DATA"
#define FIDO2_CRED_FILE_TYPE "Flipper FIDO2 Credential File"
#define FIDO2_CRED_VERSION   1

/**
 * @brief Complete definition of credential store
 * This matches the definition in fido2_credential.c
 */
struct Fido2CredentialStore {
    Fido2Credential credentials[FIDO2_MAX_CREDENTIALS];
};

bool fido2_data_init(void) {
    Storage* storage = furi_record_open(RECORD_STORAGE);

    // Create data directory if it doesn't exist
    if(!storage_dir_exists(storage, FIDO2_DATA_FOLDER)) {
        FURI_LOG_I(TAG, "Creating FIDO2 data directory");
        if(!storage_simply_mkdir(storage, FIDO2_DATA_FOLDER)) {
            FURI_LOG_E(TAG, "Failed to create directory");
            furi_record_close(RECORD_STORAGE);
            return false;
        }
    }

    furi_record_close(RECORD_STORAGE);
    return true;
}

bool fido2_data_check(bool cert_only) {
    UNUSED(cert_only);
    Storage* storage = furi_record_open(RECORD_STORAGE);
    bool exists = storage_common_stat(storage, FIDO2_CRED_FILE, NULL) == FSE_OK;
    furi_record_close(RECORD_STORAGE);
    return exists;
}

bool fido2_data_save_credentials(void* credentials) {
    struct Fido2CredentialStore* store = (struct Fido2CredentialStore*)credentials;
    if(!store) return false;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat* flipper_format = flipper_format_file_alloc(storage);

    bool success = false;
    uint32_t count = 0;

    // Count valid credentials
    for(size_t i = 0; i < FIDO2_MAX_CREDENTIALS; i++) {
        if(store->credentials[i].valid) {
            count++;
        }
    }

    if(flipper_format_file_open_always(flipper_format, FIDO2_CRED_FILE)) {
        do {
            // Write header
            if(!flipper_format_write_header_cstr(
                   flipper_format, FIDO2_CRED_FILE_TYPE, FIDO2_CRED_VERSION)) {
                FURI_LOG_E(TAG, "Failed to write header");
                break;
            }

            // Write credential count
            if(!flipper_format_write_uint32(flipper_format, "Count", &count, 1)) {
                FURI_LOG_E(TAG, "Failed to write count");
                break;
            }

            // Write each credential
            uint32_t saved = 0;
            for(size_t i = 0; i < FIDO2_MAX_CREDENTIALS; i++) {
                Fido2Credential* cred = &store->credentials[i];
                if(!cred->valid) continue;

                char key[32];

                // Credential ID
                snprintf(key, sizeof(key), "CredID_%u", (unsigned)saved);
                if(!flipper_format_write_hex(flipper_format, key, cred->credential_id, 32)) {
                    FURI_LOG_E(TAG, "Failed to write credential ID");
                    break;
                }

                // Private key
                snprintf(key, sizeof(key), "PrivKey_%u", (unsigned)saved);
                if(!flipper_format_write_hex(flipper_format, key, cred->private_key, 32)) {
                    FURI_LOG_E(TAG, "Failed to write private key");
                    break;
                }

                // Public key X
                snprintf(key, sizeof(key), "PubKeyX_%u", (unsigned)saved);
                if(!flipper_format_write_hex(flipper_format, key, cred->public_key_x, 32)) {
                    FURI_LOG_E(TAG, "Failed to write public key X");
                    break;
                }

                // Public key Y
                snprintf(key, sizeof(key), "PubKeyY_%u", (unsigned)saved);
                if(!flipper_format_write_hex(flipper_format, key, cred->public_key_y, 32)) {
                    FURI_LOG_E(TAG, "Failed to write public key Y");
                    break;
                }

                // RP ID
                snprintf(key, sizeof(key), "RPID_%u", (unsigned)saved);
                if(!flipper_format_write_string_cstr(flipper_format, key, cred->rp_id)) {
                    FURI_LOG_E(TAG, "Failed to write RP ID");
                    break;
                }

                // User ID
                snprintf(key, sizeof(key), "UserID_%u", (unsigned)saved);
                if(!flipper_format_write_hex(flipper_format, key, cred->user_id, cred->user_id_len)) {
                    FURI_LOG_E(TAG, "Failed to write user ID");
                    break;
                }

                // User ID length
                snprintf(key, sizeof(key), "UserIDLen_%u", (unsigned)saved);
                uint32_t len = cred->user_id_len;
                if(!flipper_format_write_uint32(flipper_format, key, &len, 1)) {
                    FURI_LOG_E(TAG, "Failed to write user ID length");
                    break;
                }

                // User name
                snprintf(key, sizeof(key), "UserName_%u", (unsigned)saved);
                if(!flipper_format_write_string_cstr(flipper_format, key, cred->user_name)) {
                    FURI_LOG_E(TAG, "Failed to write user name");
                    break;
                }

                // User display name
                snprintf(key, sizeof(key), "UserDisplay_%u", (unsigned)saved);
                if(!flipper_format_write_string_cstr(flipper_format, key, cred->user_display_name)) {
                    FURI_LOG_E(TAG, "Failed to write user display name");
                    break;
                }

                // Signature counter
                snprintf(key, sizeof(key), "SignCount_%u", (unsigned)saved);
                if(!flipper_format_write_uint32(flipper_format, key, &cred->sign_count, 1)) {
                    FURI_LOG_E(TAG, "Failed to write signature counter");
                    break;
                }

                saved++;
            }

            success = (saved == count);
        } while(0);
    }

    flipper_format_free(flipper_format);
    furi_record_close(RECORD_STORAGE);

    if(success) {
        FURI_LOG_I(TAG, "Saved %lu credentials", count);
    } else {
        FURI_LOG_E(TAG, "Failed to save credentials");
    }

    return success;
}

bool fido2_data_load_credentials(void* credentials) {
    struct Fido2CredentialStore* store = (struct Fido2CredentialStore*)credentials;
    if(!store) return false;

    // Clear existing credentials
    for(size_t i = 0; i < FIDO2_MAX_CREDENTIALS; i++) {
        memset(&store->credentials[i], 0, sizeof(Fido2Credential));
    }

    Storage* storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat* flipper_format = flipper_format_file_alloc(storage);
    FuriString* filetype = furi_string_alloc();

    bool success = false;
    uint32_t version = 0;
    uint32_t count = 0;

    if(flipper_format_file_open_existing(flipper_format, FIDO2_CRED_FILE)) {
        do {
            // Read header
            if(!flipper_format_read_header(flipper_format, filetype, &version)) {
                FURI_LOG_E(TAG, "Missing or incorrect header");
                break;
            }

            if(strcmp(furi_string_get_cstr(filetype), FIDO2_CRED_FILE_TYPE) != 0 ||
               version != FIDO2_CRED_VERSION) {
                FURI_LOG_E(TAG, "Type or version mismatch");
                break;
            }

            // Read credential count
            if(!flipper_format_read_uint32(flipper_format, "Count", &count, 1)) {
                FURI_LOG_E(TAG, "Missing count");
                break;
            }

            if(count > FIDO2_MAX_CREDENTIALS) {
                FURI_LOG_W(TAG, "Count %lu exceeds max, truncating", count);
                count = FIDO2_MAX_CREDENTIALS;
            }

            // Read each credential
            uint32_t loaded = 0;
            for(uint32_t i = 0; i < count; i++) {
                Fido2Credential* cred = &store->credentials[i];
                char key[32];

                // Credential ID
                snprintf(key, sizeof(key), "CredID_%u", (unsigned)i);
                if(!flipper_format_read_hex(flipper_format, key, cred->credential_id, 32)) {
                    FURI_LOG_E(TAG, "Failed to read credential ID");
                    break;
                }

                // Private key
                snprintf(key, sizeof(key), "PrivKey_%u", (unsigned)i);
                if(!flipper_format_read_hex(flipper_format, key, cred->private_key, 32)) {
                    FURI_LOG_E(TAG, "Failed to read private key");
                    break;
                }

                // Public key X
                snprintf(key, sizeof(key), "PubKeyX_%u", (unsigned)i);
                if(!flipper_format_read_hex(flipper_format, key, cred->public_key_x, 32)) {
                    FURI_LOG_E(TAG, "Failed to read public key X");
                    break;
                }

                // Public key Y
                snprintf(key, sizeof(key), "PubKeyY_%u", (unsigned)i);
                if(!flipper_format_read_hex(flipper_format, key, cred->public_key_y, 32)) {
                    FURI_LOG_E(TAG, "Failed to read public key Y");
                    break;
                }

                // RP ID
                snprintf(key, sizeof(key), "RPID_%u", (unsigned)i);
                if(!flipper_format_read_string(flipper_format, key, filetype)) {
                    FURI_LOG_E(TAG, "Failed to read RP ID");
                    break;
                }
                strncpy(cred->rp_id, furi_string_get_cstr(filetype), sizeof(cred->rp_id) - 1);
                cred->rp_id[sizeof(cred->rp_id) - 1] = '\0';

                // User ID
                snprintf(key, sizeof(key), "UserID_%u", (unsigned)i);
                uint8_t user_id_buf[64];
                if(!flipper_format_read_hex(flipper_format, key, user_id_buf, 64)) {
                    FURI_LOG_E(TAG, "Failed to read user ID");
                    break;
                }

                // User ID length
                snprintf(key, sizeof(key), "UserIDLen_%u", (unsigned)i);
                uint32_t len = 0;
                if(!flipper_format_read_uint32(flipper_format, key, &len, 1)) {
                    FURI_LOG_E(TAG, "Failed to read user ID length");
                    break;
                }
                cred->user_id_len = (len <= 64) ? len : 64;
                memcpy(cred->user_id, user_id_buf, cred->user_id_len);

                // User name
                snprintf(key, sizeof(key), "UserName_%u", (unsigned)i);
                if(!flipper_format_read_string(flipper_format, key, filetype)) {
                    FURI_LOG_E(TAG, "Failed to read user name");
                    break;
                }
                strncpy(cred->user_name, furi_string_get_cstr(filetype), sizeof(cred->user_name) - 1);
                cred->user_name[sizeof(cred->user_name) - 1] = '\0';

                // User display name
                snprintf(key, sizeof(key), "UserDisplay_%u", (unsigned)i);
                if(!flipper_format_read_string(flipper_format, key, filetype)) {
                    FURI_LOG_E(TAG, "Failed to read user display name");
                    break;
                }
                strncpy(cred->user_display_name, furi_string_get_cstr(filetype),
                       sizeof(cred->user_display_name) - 1);
                cred->user_display_name[sizeof(cred->user_display_name) - 1] = '\0';

                // Signature counter
                snprintf(key, sizeof(key), "SignCount_%u", (unsigned)i);
                if(!flipper_format_read_uint32(flipper_format, key, &cred->sign_count, 1)) {
                    FURI_LOG_E(TAG, "Failed to read signature counter");
                    break;
                }

                cred->valid = true;
                loaded++;
            }

            success = (loaded == count);
            FURI_LOG_I(TAG, "Loaded %lu credentials", loaded);
        } while(0);
    }

    furi_string_free(filetype);
    flipper_format_free(flipper_format);
    furi_record_close(RECORD_STORAGE);

    return success;
}