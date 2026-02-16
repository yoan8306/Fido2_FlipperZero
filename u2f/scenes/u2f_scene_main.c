#include "../u2f_app_i.h"
#include "../views/u2f_view.h"
#include <dolphin/dolphin.h>
#include <furi_hal.h>
#include "../u2f.h"
#include "../fido2_app.h"
#include "../fido2_hid.h"
#include <storage/storage.h>

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

/**
 * @brief Wrapper function for FIDO2 connection state changes
 */
static void fido2_connection_state_callback(void* context, bool connected) {
    furi_assert(context);
    U2fApp* app = context;
    
    if(connected) {
        FURI_LOG_I(TAG, "FIDO2 device connected");
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventConnect);
    } else {
        FURI_LOG_I(TAG, "FIDO2 device disconnected");
        view_dispatcher_send_custom_event(app->view_dispatcher, U2fCustomEventDisconnect);
    }
}

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

    // Write initial debug log
    debug_log("=== U2F Scene Main On Enter ===");

    app->timer = furi_timer_alloc(u2f_scene_main_timer_callback, FuriTimerTypeOnce, app);
    app->usb_initialized = false;

    if(app->fido_mode == FidoModeU2F) {
        FURI_LOG_I(TAG, "Initializing U2F (FIDO1) mode");
        debug_log("U2F mode selected");
        
        app->u2f_instance = u2f_alloc();
        app->u2f_ready = u2f_init(app->u2f_instance);
        if(app->u2f_ready == true) {
            u2f_set_event_callback(app->u2f_instance, u2f_scene_main_event_callback, app);
            app->u2f_hid = u2f_hid_start(app->u2f_instance);
            app->usb_initialized = true;
            u2f_view_set_ok_callback(app->u2f_view, u2f_scene_main_ok_callback, app);
            u2f_view_set_state(app->u2f_view, U2fMsgNotConnected);
            debug_log("U2F initialized successfully");
        } else {
            u2f_free(app->u2f_instance);
            app->u2f_instance = NULL;
            u2f_view_set_state(app->u2f_view, U2fMsgError);
            debug_log("U2F initialization FAILED");
        }
    } else if(app->fido_mode == FidoModeFIDO2) {
        FURI_LOG_I(TAG, "========== FIDO2 MODE SELECTED ==========");
        debug_log("FIDO2 mode selected - STEP 0");
        
        FURI_LOG_I(TAG, "Step 1: Allocating FIDO2 app");
        debug_log("Step 1: fido2_app_alloc");
        
        app->fido2_instance = fido2_app_alloc();
        if(!app->fido2_instance) {
            FURI_LOG_E(TAG, "Step 1 FAILED: fido2_app_alloc returned NULL");
            debug_log("Step 1 FAILED: fido2_app_alloc returned NULL");
            u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
        } else {
            FURI_LOG_I(TAG, "Step 2: fido2_app_alloc SUCCESS");
            debug_log("Step 2: fido2_app_alloc SUCCESS");
            
            FURI_LOG_I(TAG, "Step 3: Initializing FIDO2 app");
            debug_log("Step 3: fido2_app_init");
            
            if(!fido2_app_init((Fido2App*)app->fido2_instance)) {
                FURI_LOG_E(TAG, "Step 3 FAILED: fido2_app_init returned false");
                debug_log("Step 3 FAILED: fido2_app_init returned false");
                fido2_app_free((Fido2App*)app->fido2_instance);
                app->fido2_instance = NULL;
                u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
            } else {
                FURI_LOG_I(TAG, "Step 4: fido2_app_init SUCCESS");
                debug_log("Step 4: fido2_app_init SUCCESS");
                
                // Set user presence callback
                fido2_app_set_user_presence_callback(
                    (Fido2App*)app->fido2_instance,
                    fido2_scene_user_presence_callback,
                    app);
                FURI_LOG_I(TAG, "Step 5: User presence callback set");
                debug_log("Step 5: User presence callback set");
                
                // Set event callback
                fido2_app_set_event_callback(
                    (Fido2App*)app->fido2_instance,
                    fido2_scene_main_event_callback,
                    app);
                FURI_LOG_I(TAG, "Step 6: Event callback set");
                debug_log("Step 6: Event callback set");
                
                // Get CTAP instance
                FURI_LOG_I(TAG, "Step 7: Getting CTAP instance");
                debug_log("Step 7: fido2_app_get_ctap");
                
                Fido2Ctap* ctap = fido2_app_get_ctap((Fido2App*)app->fido2_instance);
                if(!ctap) {
                    FURI_LOG_E(TAG, "Step 7 FAILED: fido2_app_get_ctap returned NULL");
                    debug_log("Step 7 FAILED: fido2_app_get_ctap returned NULL");
                    fido2_app_free((Fido2App*)app->fido2_instance);
                    app->fido2_instance = NULL;
                    u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
                } else {
                    FURI_LOG_I(TAG, "Step 8: CTAP instance OK, calling fido2_hid_start");
                    debug_log("Step 8: Calling fido2_hid_start");
                    
                    // Start HID transport
                    app->fido2_hid = fido2_hid_start(ctap);
                    
                    if(app->fido2_hid) {
                        FURI_LOG_I(TAG, "Step 9: fido2_hid_start SUCCESS");
                        debug_log("Step 9: fido2_hid_start SUCCESS");
                        app->usb_initialized = true;
                        
                        // Set connection callback
                        fido2_hid_set_connection_callback(
                            app->fido2_hid,
                            fido2_connection_state_callback,
                            app);
                        FURI_LOG_I(TAG, "Step 10: Connection callback set");
                        debug_log("Step 10: Connection callback set");
                        
                        // Set OK callback
                        u2f_view_set_ok_callback(app->u2f_view, u2f_scene_main_ok_callback, app);
                        
                        // Show ready message
                        u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
                        
                        FURI_LOG_I(TAG, "========== FIDO2 INITIALIZATION COMPLETE ==========");
                        debug_log("FIDO2 initialization COMPLETE");
                    } else {
                        FURI_LOG_E(TAG, "Step 9 FAILED: fido2_hid_start returned NULL");
                        debug_log("Step 9 FAILED: fido2_hid_start returned NULL");
                        fido2_app_free((Fido2App*)app->fido2_instance);
                        app->fido2_instance = NULL;
                        u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
                    }
                }
            }
        }
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, U2fAppViewMain);
}

void u2f_scene_main_on_exit(void* context) {
    U2fApp* app = context;
    
    debug_log("U2F scene main on exit");
    
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
            debug_log("U2F cleaned up");
        } else if(app->fido_mode == FidoModeFIDO2 && app->fido2_instance) {
            if(app->fido2_hid) {
                fido2_hid_stop(app->fido2_hid);
                app->fido2_hid = NULL;
                debug_log("FIDO2 HID stopped");
            }
            fido2_app_free((Fido2App*)app->fido2_instance);
            app->fido2_instance = NULL;
            debug_log("FIDO2 app freed");
        }
        app->usb_initialized = false;
    }

    // Reset mode for next launch
    app->fido_mode = FidoModeNone;
    debug_log("=== U2F Scene Main On Exit ===");
}