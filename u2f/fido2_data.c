#include "fido2_data.h"
#include "fido2_credential.h"
#include <furi.h>
#include <storage/storage.h>
#include <flipper_format/flipper_format.h>

#define TAG "FIDO2_DATA"
#define FIDO2_CRED_FILE_TYPE "Flipper FIDO2 Credential File"
#define FIDO2_CRED_VERSION   1

/**
 * @brief Write debug message to SD card
 */
static void debug_log(const char* msg) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    
    if(storage_file_open(file, EXT_PATH("fido2_debug.txt"), FSAM_WRITE, FSOM_OPEN_APPEND)) {
        storage_file_write(file, msg, strlen(msg));
        storage_file_write(file, "\r\n", 2);
        storage_file_close(file);
    }
    
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/**
 * @brief Convert FS_Error to string for debugging
 */
static const char* fs_error_to_string(FS_Error error) {
    switch(error) {
    case FSE_OK:
        return "OK";
    case FSE_NOT_READY:
        return "NOT_READY";
    case FSE_EXIST:
        return "EXIST";
    case FSE_NOT_EXIST:
        return "NOT_EXIST";
    case FSE_INVALID_NAME:
        return "INVALID_NAME";
    case FSE_INVALID_PARAMETER:
        return "INVALID_PARAMETER";
    case FSE_DENIED:
        return "DENIED";
    case FSE_ALREADY_OPEN:
        return "ALREADY_OPEN";
    case FSE_INTERNAL:
        return "INTERNAL";
    default:
        return "UNKNOWN";
    }
}

/**
 * @brief Complete definition of credential store
 */
struct Fido2CredentialStore {
    Fido2Credential credentials[FIDO2_MAX_CREDENTIALS];
};

bool fido2_data_init(void) {
    FURI_LOG_I(TAG, "fido2_data_init - START");
    debug_log("fido2_data_init - START");
    
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) {
        FURI_LOG_E(TAG, "Failed to open storage record");
        debug_log("Failed to open storage record");
        return false;
    }
    debug_log("Storage record opened");

    // Test if SD card is writable - FIDO2 needs write access for credentials
    FURI_LOG_I(TAG, "Testing SD card write access...");
    debug_log("Testing SD card write access");
    
    File* test_file = storage_file_alloc(storage);
    bool write_test_passed = false;
    
    // Try to create a test file
    if(storage_file_open(test_file, EXT_PATH("fido2_write_test.tmp"), FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        // Write something
        const char* test_data = "FIDO2 write test";
        if(storage_file_write(test_file, test_data, strlen(test_data)) == strlen(test_data)) {
            storage_file_close(test_file);
            
            // Try to delete it
            if(storage_simply_remove(storage, EXT_PATH("fido2_write_test.tmp"))) {
                write_test_passed = true;
                FURI_LOG_I(TAG, "SD card write test PASSED");
                debug_log("SD card write test PASSED");
            } else {
                FURI_LOG_E(TAG, "Failed to delete test file");
                debug_log("Failed to delete test file");
            }
        } else {
            FURI_LOG_E(TAG, "Failed to write to test file");
            debug_log("Failed to write to test file");
            storage_file_close(test_file);
        }
    } else {
        FURI_LOG_E(TAG, "Failed to create test file");
        debug_log("Failed to create test file");
    }
    
    storage_file_free(test_file);
    
    if(!write_test_passed) {
        FURI_LOG_E(TAG, "SD card is not writable - FIDO2 cannot function without write access!");
        debug_log("SD card NOT writable - FIDO2 cannot function");
        furi_record_close(RECORD_STORAGE);
        return false;
    }

    // Check if directory exists
    bool dir_exists = storage_dir_exists(storage, FIDO2_DATA_FOLDER);
    FURI_LOG_I(TAG, "Directory %s: %s", FIDO2_DATA_FOLDER, dir_exists ? "exists" : "does not exist");
    debug_log(dir_exists ? "Directory exists" : "Directory does not exist");

    if(!dir_exists) {
        FURI_LOG_I(TAG, "Creating FIDO2 data directory: %s", FIDO2_DATA_FOLDER);
        debug_log("Creating directory");
        
        // Use storage_common_mkdir for better error information
        FS_Error error = storage_common_mkdir(storage, FIDO2_DATA_FOLDER);
        const char* error_str = fs_error_to_string(error);
        
        FURI_LOG_I(TAG, "storage_common_mkdir returned: %d (%s)", error, error_str);
        
        // Create a detailed log message
        char log_msg[64];
        snprintf(log_msg, sizeof(log_msg), "mkdir returned: %s", error_str);
        debug_log(log_msg);
        
        if(error == FSE_OK) {
            debug_log("Directory created successfully");
            FURI_LOG_I(TAG, "Directory created successfully");
        } else if(error == FSE_EXIST) {
            debug_log("Directory already exists (created by another process?)");
            FURI_LOG_I(TAG, "Directory already exists");
        } else {
            FURI_LOG_E(TAG, "Failed to create directory, error: %d (%s)", error, error_str);
            debug_log("Failed to create directory");
            
            // Log more details about the error
            char error_detail[64];
            snprintf(error_detail, sizeof(error_detail), "mkdir error: %s", error_str);
            debug_log(error_detail);
            
            // Don't fail immediately - try to continue anyway
            // Maybe the directory was created by another process
            FURI_LOG_W(TAG, "Continuing despite mkdir error - directory might already exist");
            debug_log("Continuing despite mkdir error");
        }
    } else {
        FURI_LOG_I(TAG, "Directory already exists, no need to create");
        debug_log("Directory already exists");
    }

    // Verify directory exists (or try to proceed anyway)
    if(!storage_dir_exists(storage, FIDO2_DATA_FOLDER)) {
        FURI_LOG_W(TAG, "Directory does not exist after creation attempt, but continuing");
        debug_log("Directory missing but continuing");
        // Don't fail - maybe we can still write files
    } else {
        debug_log("Directory verified");
    }

    furi_record_close(RECORD_STORAGE);
    FURI_LOG_I(TAG, "fido2_data_init - SUCCESS (continuing)");
    debug_log("fido2_data_init - SUCCESS");
    return true;
}

bool fido2_data_check(bool cert_only) {
    UNUSED(cert_only);
    Storage* storage = furi_record_open(RECORD_STORAGE);
    bool exists = storage_common_stat(storage, FIDO2_CRED_FILE, NULL) == FSE_OK;
    furi_record_close(RECORD_STORAGE);
    FURI_LOG_I(TAG, "fido2_data_check: credentials file exists = %d", exists);
    return exists;
}

bool fido2_data_save_credentials(void* credentials) {
    struct Fido2CredentialStore* store = (struct Fido2CredentialStore*)credentials;
    if(!store) {
        FURI_LOG_E(TAG, "fido2_data_save_credentials: store is NULL");
        return false;
    }

    FURI_LOG_I(TAG, "fido2_data_save_credentials - START");
    debug_log("fido2_data_save_credentials - START");

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
    FURI_LOG_I(TAG, "Saving %lu credentials", count);
    
    char count_msg[32];
    snprintf(count_msg, sizeof(count_msg), "Saving %lu credentials", count);
    debug_log(count_msg);

    if(flipper_format_file_open_always(flipper_format, FIDO2_CRED_FILE)) {
        // Write header
        if(!flipper_format_write_header_cstr(
               flipper_format, FIDO2_CRED_FILE_TYPE, FIDO2_CRED_VERSION)) {
            FURI_LOG_E(TAG, "Failed to write header");
            debug_log("Failed to write header");
            goto cleanup;
        }

        // Write credential count
        if(!flipper_format_write_uint32(flipper_format, "Count", &count, 1)) {
            FURI_LOG_E(TAG, "Failed to write count");
            debug_log("Failed to write count");
            goto cleanup;
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
                goto cleanup;
            }

            // Private key
            snprintf(key, sizeof(key), "PrivKey_%u", (unsigned)saved);
            if(!flipper_format_write_hex(flipper_format, key, cred->private_key, 32)) {
                FURI_LOG_E(TAG, "Failed to write private key");
                goto cleanup;
            }

            // Public key X
            snprintf(key, sizeof(key), "PubKeyX_%u", (unsigned)saved);
            if(!flipper_format_write_hex(flipper_format, key, cred->public_key_x, 32)) {
                FURI_LOG_E(TAG, "Failed to write public key X");
                goto cleanup;
            }

            // Public key Y
            snprintf(key, sizeof(key), "PubKeyY_%u", (unsigned)saved);
            if(!flipper_format_write_hex(flipper_format, key, cred->public_key_y, 32)) {
                FURI_LOG_E(TAG, "Failed to write public key Y");
                goto cleanup;
            }

            // RP ID
            snprintf(key, sizeof(key), "RPID_%u", (unsigned)saved);
            if(!flipper_format_write_string_cstr(flipper_format, key, cred->rp_id)) {
                FURI_LOG_E(TAG, "Failed to write RP ID");
                goto cleanup;
            }

            // User ID
            snprintf(key, sizeof(key), "UserID_%u", (unsigned)saved);
            if(!flipper_format_write_hex(flipper_format, key, cred->user_id, cred->user_id_len)) {
                FURI_LOG_E(TAG, "Failed to write user ID");
                goto cleanup;
            }

            // User ID length
            snprintf(key, sizeof(key), "UserIDLen_%u", (unsigned)saved);
            uint32_t len = cred->user_id_len;
            if(!flipper_format_write_uint32(flipper_format, key, &len, 1)) {
                FURI_LOG_E(TAG, "Failed to write user ID length");
                goto cleanup;
            }

            // User name
            snprintf(key, sizeof(key), "UserName_%u", (unsigned)saved);
            if(!flipper_format_write_string_cstr(flipper_format, key, cred->user_name)) {
                FURI_LOG_E(TAG, "Failed to write user name");
                goto cleanup;
            }

            // User display name
            snprintf(key, sizeof(key), "UserDisplay_%u", (unsigned)saved);
            if(!flipper_format_write_string_cstr(flipper_format, key, cred->user_display_name)) {
                FURI_LOG_E(TAG, "Failed to write user display name");
                goto cleanup;
            }

            // Signature counter
            snprintf(key, sizeof(key), "SignCount_%u", (unsigned)saved);
            if(!flipper_format_write_uint32(flipper_format, key, &cred->sign_count, 1)) {
                FURI_LOG_E(TAG, "Failed to write signature counter");
                goto cleanup;
            }

            saved++;
        }

        success = (saved == count);
        FURI_LOG_I(TAG, "Saved %lu/%lu credentials", saved, count);
        
        snprintf(count_msg, sizeof(count_msg), "Saved %lu/%lu", saved, count);
        debug_log(count_msg);
    } else {
        FURI_LOG_E(TAG, "Failed to open file for writing");
        debug_log("Failed to open file for writing");
    }

cleanup:
    flipper_format_free(flipper_format);
    furi_record_close(RECORD_STORAGE);

    if(success) {
        FURI_LOG_I(TAG, "fido2_data_save_credentials - SUCCESS");
        debug_log("fido2_data_save_credentials - SUCCESS");
    } else {
        FURI_LOG_E(TAG, "fido2_data_save_credentials - FAILED");
        debug_log("fido2_data_save_credentials - FAILED");
    }

    return success;
}

bool fido2_data_load_credentials(void* credentials) {
    struct Fido2CredentialStore* store = (struct Fido2CredentialStore*)credentials;
    if(!store) return false;

    FURI_LOG_I(TAG, "fido2_data_load_credentials - START");
    debug_log("fido2_data_load_credentials - START");

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
        // Read header
        if(!flipper_format_read_header(flipper_format, filetype, &version)) {
            FURI_LOG_E(TAG, "Missing or incorrect header");
            debug_log("Missing or incorrect header");
            goto cleanup;
        }

        if(strcmp(furi_string_get_cstr(filetype), FIDO2_CRED_FILE_TYPE) != 0 ||
           version != FIDO2_CRED_VERSION) {
            FURI_LOG_E(TAG, "Type or version mismatch");
            debug_log("Type or version mismatch");
            goto cleanup;
        }

        // Read credential count
        if(!flipper_format_read_uint32(flipper_format, "Count", &count, 1)) {
            FURI_LOG_E(TAG, "Missing count");
            debug_log("Missing count");
            goto cleanup;
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
                goto cleanup;
            }

            // Private key
            snprintf(key, sizeof(key), "PrivKey_%u", (unsigned)i);
            if(!flipper_format_read_hex(flipper_format, key, cred->private_key, 32)) {
                FURI_LOG_E(TAG, "Failed to read private key");
                goto cleanup;
            }

            // Public key X
            snprintf(key, sizeof(key), "PubKeyX_%u", (unsigned)i);
            if(!flipper_format_read_hex(flipper_format, key, cred->public_key_x, 32)) {
                FURI_LOG_E(TAG, "Failed to read public key X");
                goto cleanup;
            }

            // Public key Y
            snprintf(key, sizeof(key), "PubKeyY_%u", (unsigned)i);
            if(!flipper_format_read_hex(flipper_format, key, cred->public_key_y, 32)) {
                FURI_LOG_E(TAG, "Failed to read public key Y");
                goto cleanup;
            }

            // RP ID
            snprintf(key, sizeof(key), "RPID_%u", (unsigned)i);
            if(!flipper_format_read_string(flipper_format, key, filetype)) {
                FURI_LOG_E(TAG, "Failed to read RP ID");
                goto cleanup;
            }
            strncpy(cred->rp_id, furi_string_get_cstr(filetype), sizeof(cred->rp_id) - 1);
            cred->rp_id[sizeof(cred->rp_id) - 1] = '\0';

            // User ID
            snprintf(key, sizeof(key), "UserID_%u", (unsigned)i);
            uint8_t user_id_buf[64];
            if(!flipper_format_read_hex(flipper_format, key, user_id_buf, 64)) {
                FURI_LOG_E(TAG, "Failed to read user ID");
                goto cleanup;
            }

            // User ID length
            snprintf(key, sizeof(key), "UserIDLen_%u", (unsigned)i);
            uint32_t len = 0;
            if(!flipper_format_read_uint32(flipper_format, key, &len, 1)) {
                FURI_LOG_E(TAG, "Failed to read user ID length");
                goto cleanup;
            }
            cred->user_id_len = (len <= 64) ? len : 64;
            memcpy(cred->user_id, user_id_buf, cred->user_id_len);

            // User name
            snprintf(key, sizeof(key), "UserName_%u", (unsigned)i);
            if(!flipper_format_read_string(flipper_format, key, filetype)) {
                FURI_LOG_E(TAG, "Failed to read user name");
                goto cleanup;
            }
            strncpy(cred->user_name, furi_string_get_cstr(filetype), sizeof(cred->user_name) - 1);
            cred->user_name[sizeof(cred->user_name) - 1] = '\0';

            // User display name
            snprintf(key, sizeof(key), "UserDisplay_%u", (unsigned)i);
            if(!flipper_format_read_string(flipper_format, key, filetype)) {
                FURI_LOG_E(TAG, "Failed to read user display name");
                goto cleanup;
            }
            strncpy(cred->user_display_name, furi_string_get_cstr(filetype),
                   sizeof(cred->user_display_name) - 1);
            cred->user_display_name[sizeof(cred->user_display_name) - 1] = '\0';

            // Signature counter
            snprintf(key, sizeof(key), "SignCount_%u", (unsigned)i);
            if(!flipper_format_read_uint32(flipper_format, key, &cred->sign_count, 1)) {
                FURI_LOG_E(TAG, "Failed to read signature counter");
                goto cleanup;
            }

            cred->valid = true;
            loaded++;
        }

        success = (loaded == count);
        FURI_LOG_I(TAG, "Loaded %lu credentials", loaded);
        
        char load_msg[32];
        snprintf(load_msg, sizeof(load_msg), "Loaded %lu credentials", loaded);
        debug_log(load_msg);
    } else {
        FURI_LOG_I(TAG, "No existing credentials file, starting fresh");
        debug_log("No existing credentials, starting fresh");
        success = true; // Not an error if file doesn't exist
    }

cleanup:
    furi_string_free(filetype);
    flipper_format_free(flipper_format);
    furi_record_close(RECORD_STORAGE);

    if(success) {
        FURI_LOG_I(TAG, "fido2_data_load_credentials - SUCCESS");
        debug_log("fido2_data_load_credentials - SUCCESS");
    } else {
        FURI_LOG_E(TAG, "fido2_data_load_credentials - FAILED");
        debug_log("fido2_data_load_credentials - FAILED");
    }

    return success;
}