#pragma once

#include "fido2_credential.h"
#include "fido2_ctap.h"
#include "fido2_hid.h"
#include "fido2_data.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief FIDO2 notification events for UI
 */
typedef enum {
    Fido2AppNotifyConnect,     /**< Device connected */
    Fido2AppNotifyDisconnect,  /**< Device disconnected */
    Fido2AppNotifyError,       /**< Error occurred */
} Fido2AppNotifyEvent;

/**
 * @brief Event callback type for UI updates
 */
typedef void (*Fido2AppEventCallback)(Fido2AppNotifyEvent evt, void* context);

/**
 * @brief FIDO2 application instance (opaque)
 */
typedef struct Fido2App Fido2App;

/**
 * @brief Allocate a new FIDO2 application instance
 * 
 * @return Fido2App* New instance or NULL on failure
 */
Fido2App* fido2_app_alloc(void);

/**
 * @brief Free FIDO2 application instance
 * 
 * @param app Instance to free
 */
void fido2_app_free(Fido2App* app);

/**
 * @brief Initialize FIDO2 application
 * 
 * @param app FIDO2 app instance
 * @return true if successful
 */
bool fido2_app_init(Fido2App* app);

/**
 * @brief Set user presence callback
 * 
 * @param app FIDO2 app instance
 * @param callback Callback function
 * @param context Context to pass to callback
 */
void fido2_app_set_user_presence_callback(
    Fido2App* app,
    Fido2UserPresenceCallback callback,
    void* context);

/**
 * @brief Set event callback for UI updates
 * 
 * @param app FIDO2 app instance
 * @param callback Callback function
 * @param context Context to pass to callback
 */
void fido2_app_set_event_callback(
    Fido2App* app,
    Fido2AppEventCallback callback,
    void* context);

/**
 * @brief Confirm user presence (called from UI)
 * 
 * @param app FIDO2 app instance
 */
void fido2_app_confirm_user_present(Fido2App* app);

/**
 * @brief Get the CTAP2 instance
 * 
 * @param app FIDO2 app instance
 * @return Fido2Ctap* CTAP2 instance
 */
Fido2Ctap* fido2_app_get_ctap(Fido2App* app);

#ifdef __cplusplus
}
#endif