#include "fido2_app.h"
#include "fido2_credential.h"
#include "fido2_ctap.h"
#include "fido2_hid.h"
#include "fido2_data.h"
#include <furi.h>

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
 * @brief User presence check callback for CTAP2
 */
static bool fido2_app_user_presence_callback(void* context) {
    Fido2App* app = (Fido2App*)context;
    if(!app) return false;

    FURI_LOG_I(TAG, "User presence requested");

    // Reset user presence flag
    app->user_present = false;

    // Call UI callback if registered
    if(app->up_callback) {
        return app->up_callback(app->up_context);
    }

    // If no UI callback, assume presence for testing
    return true;
}

Fido2App* fido2_app_alloc(void) {
    Fido2App* app = malloc(sizeof(Fido2App));
    if(!app) return NULL;
    
    memset(app, 0, sizeof(Fido2App));
    FURI_LOG_I(TAG, "FIDO2 app allocated");
    return app;
}

bool fido2_app_init(Fido2App* app) {
    if(!app) return false;

    FURI_LOG_I(TAG, "Initializing FIDO2 app");

    // Initialize data storage
    if(!fido2_data_init()) {
        FURI_LOG_E(TAG, "Failed to initialize data storage");
        return false;
    }

    // Allocate credential store
    app->credential_store = fido2_credential_store_alloc();
    if(!app->credential_store) {
        FURI_LOG_E(TAG, "Failed to allocate credential store");
        return false;
    }

    // Try to load existing credentials
    if(fido2_data_check(false)) {
        if(!fido2_data_load_credentials(app->credential_store)) {
            FURI_LOG_W(TAG, "Failed to load credentials, starting fresh");
        } else {
            FURI_LOG_I(TAG, "Loaded existing credentials");
        }
    }

    // Allocate CTAP2 module
    app->ctap = fido2_ctap_alloc(app->credential_store);
    if(!app->ctap) {
        FURI_LOG_E(TAG, "Failed to allocate CTAP2 module");
        fido2_credential_store_free(app->credential_store);
        return false;
    }

    // Set user presence callback
    fido2_ctap_set_user_presence_callback(
        app->ctap,
        fido2_app_user_presence_callback,
        app);

    app->initialized = true;
    FURI_LOG_I(TAG, "FIDO2 app initialized successfully");

    return true;
}

void fido2_app_free(Fido2App* app) {
    if(!app) return;

    // Stop HID if running
    if(app->hid) {
        fido2_hid_stop(app->hid);
        app->hid = NULL;
    }

    // Save credentials before freeing
    if(app->credential_store) {
        size_t count = fido2_credential_count(app->credential_store);
        if(count > 0) {
            FURI_LOG_I(TAG, "Saving %u credentials", count);
            fido2_data_save_credentials(app->credential_store);
        }
        fido2_credential_store_free(app->credential_store);
    }

    // Free CTAP2 module
    if(app->ctap) {
        fido2_ctap_free(app->ctap);
    }

    free(app);
    FURI_LOG_I(TAG, "FIDO2 app freed");
}

void fido2_app_set_user_presence_callback(
    Fido2App* app,
    Fido2UserPresenceCallback callback,
    void* context) {
    if(!app) return;
    app->up_callback = callback;
    app->up_context = context;
}

void fido2_app_set_event_callback(
    Fido2App* app,
    Fido2AppEventCallback callback,
    void* context) {
    if(!app) return;
    app->event_callback = callback;
    app->event_context = context;
}

void fido2_app_confirm_user_present(Fido2App* app) {
    if(!app) return;
    FURI_LOG_I(TAG, "User presence confirmed");
    app->user_present = true;
}

Fido2Ctap* fido2_app_get_ctap(Fido2App* app) {
    if(!app) return NULL;
    return app->ctap;
}