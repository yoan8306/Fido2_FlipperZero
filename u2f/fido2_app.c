#include "fido2_app.h"
#include "fido2_credential.h"
#include "fido2_ctap.h"
#include "fido2_hid.h"
#include "fido2_data.h"
#include <furi.h>
#include <storage/storage.h>

#define TAG "FIDO2_APP"

struct Fido2App {
    Fido2CredentialStore* credential_store;
    Fido2Ctap* ctap;
    Fido2Hid* hid;
    Fido2UserPresenceCallback up_callback;
    void* up_context;
    Fido2AppEventCallback event_callback;
    void* event_context;
    bool user_present;
    bool initialized;
};

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
 * @brief User presence check callback for CTAP2
 */
static bool fido2_app_user_presence_callback(void* context) {
    Fido2App* app = (Fido2App*)context;
    if(!app) return false;

    FURI_LOG_I(TAG, "User presence requested");
    debug_log("User presence requested");

    app->user_present = false;

    if(app->up_callback) {
        return app->up_callback(app->up_context);
    }

    return true;
}

Fido2App* fido2_app_alloc(void) {
    Fido2App* app = malloc(sizeof(Fido2App));
    if(!app) return NULL;
    
    memset(app, 0, sizeof(Fido2App));
    FURI_LOG_I(TAG, "FIDO2 app allocated");
    debug_log("FIDO2 app allocated");
    return app;
}

bool fido2_app_init(Fido2App* app) {
    if(!app) {
        FURI_LOG_E(TAG, "fido2_app_init: app is NULL");
        debug_log("fido2_app_init: app is NULL");
        return false;
    }

    FURI_LOG_I(TAG, "Initializing FIDO2 app - STEP A");
    debug_log("fido2_app_init - STEP A");

    // Initialize data storage
    FURI_LOG_I(TAG, "fido2_data_init - STEP B");
    debug_log("fido2_data_init - STEP B");
    
    if(!fido2_data_init()) {
        FURI_LOG_E(TAG, "fido2_data_init FAILED - SD card not writable");
        debug_log("fido2_data_init FAILED - SD card not writable");
        return false;
    }
    debug_log("fido2_data_init SUCCESS");

    // Allocate credential store
    FURI_LOG_I(TAG, "fido2_credential_store_alloc - STEP C");
    debug_log("fido2_credential_store_alloc - STEP C");
    
    app->credential_store = fido2_credential_store_alloc();
    if(!app->credential_store) {
        FURI_LOG_E(TAG, "fido2_credential_store_alloc FAILED");
        debug_log("fido2_credential_store_alloc FAILED");
        return false;
    }
    debug_log("fido2_credential_store_alloc SUCCESS");

    // Try to load existing credentials
    FURI_LOG_I(TAG, "fido2_data_check - STEP D");
    debug_log("fido2_data_check - STEP D");
    
    if(fido2_data_check(false)) {
        FURI_LOG_I(TAG, "Credentials exist, loading...");
        debug_log("Credentials exist, loading...");
        
        if(!fido2_data_load_credentials(app->credential_store)) {
            FURI_LOG_W(TAG, "Failed to load credentials, starting fresh");
            debug_log("Failed to load credentials, starting fresh");
        } else {
            FURI_LOG_I(TAG, "Loaded existing credentials");
            debug_log("Loaded existing credentials");
        }
    } else {
        FURI_LOG_I(TAG, "No existing credentials, starting fresh");
        debug_log("No existing credentials, starting fresh");
    }

    // Allocate CTAP2 module
    FURI_LOG_I(TAG, "fido2_ctap_alloc - STEP E");
    debug_log("fido2_ctap_alloc - STEP E");
    
    app->ctap = fido2_ctap_alloc(app->credential_store);
    if(!app->ctap) {
        FURI_LOG_E(TAG, "fido2_ctap_alloc FAILED");
        debug_log("fido2_ctap_alloc FAILED");
        fido2_credential_store_free(app->credential_store);
        return false;
    }
    debug_log("fido2_ctap_alloc SUCCESS");

    // Set user presence callback
    fido2_ctap_set_user_presence_callback(
        app->ctap,
        fido2_app_user_presence_callback,
        app);
    debug_log("User presence callback set");

    app->initialized = true;
    FURI_LOG_I(TAG, "FIDO2 app initialized successfully - STEP F");
    debug_log("FIDO2 app initialized successfully - STEP F");

    return true;
}

void fido2_app_free(Fido2App* app) {
    if(!app) return;

    FURI_LOG_I(TAG, "fido2_app_free");
    debug_log("fido2_app_free");

    if(app->hid) {
        fido2_hid_stop(app->hid);
        app->hid = NULL;
    }

    if(app->credential_store) {
        size_t count = fido2_credential_count(app->credential_store);
        if(count > 0) {
            FURI_LOG_I(TAG, "Saving %u credentials", count);
            debug_log("Saving credentials");
            fido2_data_save_credentials(app->credential_store);
        }
        fido2_credential_store_free(app->credential_store);
    }

    if(app->ctap) {
        fido2_ctap_free(app->ctap);
    }

    free(app);
    FURI_LOG_I(TAG, "FIDO2 app freed");
    debug_log("FIDO2 app freed");
}

void fido2_app_set_user_presence_callback(
    Fido2App* app,
    Fido2UserPresenceCallback callback,
    void* context) {
    if(!app) return;
    app->up_callback = callback;
    app->up_context = context;
    debug_log("User presence callback registered");
}

void fido2_app_set_event_callback(
    Fido2App* app,
    Fido2AppEventCallback callback,
    void* context) {
    if(!app) return;
    app->event_callback = callback;
    app->event_context = context;
    debug_log("Event callback registered");
}

void fido2_app_confirm_user_present(Fido2App* app) {
    if(!app) return;
    FURI_LOG_I(TAG, "User presence confirmed");
    debug_log("User presence confirmed");
    app->user_present = true;
}

Fido2Ctap* fido2_app_get_ctap(Fido2App* app) {
    if(!app) return NULL;
    return app->ctap;
}