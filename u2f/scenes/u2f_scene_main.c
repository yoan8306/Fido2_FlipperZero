#include "../u2f_app_i.h"
#include "../views/u2f_view.h"
#include <dolphin/dolphin.h>
#include <furi_hal.h>
#include "../u2f.h"
#include "../fido2_app.h"
#include "../fido2_hid.h"

#define U2F_REQUEST_TIMEOUT 500
#define U2F_SUCCESS_TIMEOUT 3000
#define TAG "U2fMain"

static void u2f_scene_main_ok_callback(InputType type, void* context) {
    UNUSED(type);
    furi_assert(context);
    U2fApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventConfirm);
}

static void u2f_scene_main_event_callback(U2fNotifyEvent evt, void* context) {
    furi_assert(context);
    U2fApp* app = context;
    switch(evt) {
    case U2fNotifyRegister:
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventRegister);
        break;
    case U2fNotifyAuth:
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventAuth);
        break;
    case U2fNotifyAuthSuccess:
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventAuthSuccess);
        break;
    case U2fNotifyWink:
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventWink);
        break;
    case U2fNotifyConnect:
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventConnect);
        break;
    case U2fNotifyDisconnect:
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventDisconnect);
        break;
    case U2fNotifyError:
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventDataError);
        break;
    }
}

/**
 * @brief User presence callback for FIDO2 UI integration
 */
static bool fido2_scene_user_presence_callback(void* context) {
    furi_assert(context);
    U2fApp* app = context;

    FURI_LOG_I(TAG, "FIDO2 requesting user presence");
    view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventRegister);
    return true;
}

/**
 * @brief FIDO2 event callback for UI updates
 */
static void fido2_scene_main_event_callback(Fido2AppNotifyEvent evt, void* context) {
    furi_assert(context);
    U2fApp* app = context;
    
    switch(evt) {
    case Fido2AppNotifyConnect:
        FURI_LOG_I(TAG, "FIDO2 Connect event");
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventConnect);
        break;
    case Fido2AppNotifyDisconnect:
        FURI_LOG_I(TAG, "FIDO2 Disconnect event");
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventDisconnect);
        break;
    case Fido2AppNotifyError:
        FURI_LOG_E(TAG, "FIDO2 Error event");
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventDataError);
        break;
    }
}

static void u2f_scene_main_timer_callback(void* context) {
    furi_assert(context);
    U2fApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventTimeout);
}

bool u2f_scene_main_on_event(void* context, SceneManagerEvent event) {
    furi_assert(context);
    U2fApp* app = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == U2fCustomEventConnect) {
            furi_timer_stop(app->timer);
            u2f_view_set_state(app->u2f_view, U2fMsgIdle);
        } else if(event.event == U2fCustomEventDisconnect) {
            furi_timer_stop(app->timer);
            app->event_cur = U2fCustomEventNone;
            u2f_view_set_state(app->u2f_view, U2fMsgNotConnected);
        } else if((event.event == U2fCustomEventRegister) || (event.event == U2fCustomEventAuth)) {
            furi_timer_start(app->timer, U2F_REQUEST_TIMEOUT);
            if(app->event_cur == U2fCustomEventNone) {
                app->event_cur = event.event;
                if(event.event == U2fCustomEventRegister)
                    u2f_view_set_state(app->u2f_view, U2fMsgRegister);
                else if(event.event == U2fCustomEventAuth)
                    u2f_view_set_state(app->u2f_view, U2fMsgAuth);
                notification_message(app->notifications, &sequence_display_backlight_on);
                notification_message(app->notifications, &sequence_single_vibro);
            }
            notification_message(app->notifications, &sequence_blink_magenta_10);
        } else if(event.event == U2fCustomEventWink) {
            notification_message(app->notifications, &sequence_blink_magenta_10);
        } else if(event.event == U2fCustomEventAuthSuccess) {
            notification_message_block(app->notifications, &sequence_set_green_255);
            dolphin_deed(DolphinDeedU2fAuthorized);
            furi_timer_start(app->timer, U2F_SUCCESS_TIMEOUT);
            app->event_cur = U2fCustomEventNone;
            u2f_view_set_state(app->u2f_view, U2fMsgSuccess);
        } else if(event.event == U2fCustomEventTimeout) {
            notification_message_block(app->notifications, &sequence_reset_rgb);
            app->event_cur = U2fCustomEventNone;
            u2f_view_set_state(app->u2f_view, U2fMsgIdle);
        } else if(event.event == U2fCustomEventConfirm) {
            if(app->event_cur != U2fCustomEventNone) {
                if(app->fido_mode == FidoModeU2F && app->u2f_instance) {
                    u2f_confirm_user_present(app->u2f_instance);
                } else if(app->fido_mode == FidoModeFIDO2 && app->fido2_instance) {
                    fido2_app_confirm_user_present((Fido2App*)app->fido2_instance);
                }
            }
        } else if(event.event == U2fCustomEventDataError) {
            notification_message(app->notifications, &sequence_set_red_255);
            furi_timer_stop(app->timer);
            u2f_view_set_state(app->u2f_view, U2fMsgError);
        }
        consumed = true;
    }

    return consumed;
}

void u2f_scene_main_on_enter(void* context) {
    U2fApp* app = context;

    app->timer = furi_timer_alloc(u2f_scene_main_timer_callback, FuriTimerTypeOnce, app);
    app->usb_initialized = false;

    if(app->fido_mode == FidoModeU2F) {
        FURI_LOG_I(TAG, "Initializing U2F (FIDO1) mode");
        app->u2f_instance = u2f_alloc();
        app->u2f_ready = u2f_init(app->u2f_instance);
        if(app->u2f_ready == true) {
            u2f_set_event_callback(app->u2f_instance, u2f_scene_main_event_callback, app);
            app->u2f_hid = u2f_hid_start(app->u2f_instance);
            app->usb_initialized = true;
            u2f_view_set_ok_callback(app->u2f_view, u2f_scene_main_ok_callback, app);
            u2f_view_set_state(app->u2f_view, U2fMsgNotConnected);
        } else {
            u2f_free(app->u2f_instance);
            app->u2f_instance = NULL;
            u2f_view_set_state(app->u2f_view, U2fMsgError);
        }
    } else if(app->fido_mode == FidoModeFIDO2) {
        FURI_LOG_I(TAG, "Initializing FIDO2 mode");

        // Allocate FIDO2 app
        app->fido2_instance = fido2_app_alloc();
        if(!app->fido2_instance) {
            FURI_LOG_E(TAG, "Failed to allocate FIDO2 app");
            u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
        } else {
            // Initialize FIDO2 app
            if(!fido2_app_init((Fido2App*)app->fido2_instance)) {
                FURI_LOG_E(TAG, "Failed to initialize FIDO2 app");
                fido2_app_free((Fido2App*)app->fido2_instance);
                app->fido2_instance = NULL;
                u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
            } else {
                // Set user presence callback for UI integration
                fido2_app_set_user_presence_callback(
                    (Fido2App*)app->fido2_instance,
                    fido2_scene_user_presence_callback,
                    app);

                // Set event callback for UI updates
                fido2_app_set_event_callback(
                    (Fido2App*)app->fido2_instance,
                    fido2_scene_main_event_callback,
                    app);

                // Get CTAP instance and start HID
                Fido2Ctap* ctap = fido2_app_get_ctap((Fido2App*)app->fido2_instance);
                if(ctap) {
                    // Start FIDO2 HID transport
                    app->fido2_hid = fido2_hid_start(ctap);
                    app->usb_initialized = true;
                    
                    // Set OK callback for user presence
                    u2f_view_set_ok_callback(app->u2f_view, u2f_scene_main_ok_callback, app);
                    
                    // FIDO2 doesn't need certificate - show appropriate message
                    u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
                    
                    FURI_LOG_I(TAG, "FIDO2 mode initialized successfully");
                } else {
                    FURI_LOG_E(TAG, "Failed to get CTAP instance");
                    fido2_app_free((Fido2App*)app->fido2_instance);
                    app->fido2_instance = NULL;
                    u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
                }
            }
        }
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, U2fAppViewMain);
}

void u2f_scene_main_on_exit(void* context) {
    U2fApp* app = context;
    notification_message_block(app->notifications, &sequence_reset_rgb);
    furi_timer_stop(app->timer);
    furi_timer_free(app->timer);

    // Clean up USB and instances
    if(app->usb_initialized) {
        if(app->fido_mode == FidoModeU2F && app->u2f_instance) {
            u2f_hid_stop(app->u2f_hid);
            u2f_free(app->u2f_instance);
            app->u2f_instance = NULL;
            app->u2f_hid = NULL;
        } else if(app->fido_mode == FidoModeFIDO2 && app->fido2_instance) {
            // Stop FIDO2 HID and free app
            if(app->fido2_hid) {
                fido2_hid_stop(app->fido2_hid);
                app->fido2_hid = NULL;
            }
            fido2_app_free((Fido2App*)app->fido2_instance);
            app->fido2_instance = NULL;
        }
        app->usb_initialized = false;
    }

    // Reset mode for next launch
    app->fido_mode = FidoModeNone;
}