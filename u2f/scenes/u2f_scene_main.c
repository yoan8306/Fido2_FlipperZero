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
    
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    bool exiting = app->exiting;
    furi_mutex_release(app->data_mutex);
    
    if(exiting) return;
    
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
    
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    bool exiting = app->exiting;
    furi_mutex_release(app->data_mutex);
    
    if(exiting) return;
    
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
 * @brief Thread-safe connection state callback for FIDO2
 */
static void fido2_connection_state_callback(void* context, bool connected) {
    furi_assert(context);
    U2fApp* app = (U2fApp*)context;
    
    // Check if app is still valid with mutex protection
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    
    bool exiting = app->exiting;
    bool view_valid = app->view_dispatcher_valid;
    ViewDispatcher* view_dispatcher = app->view_dispatcher;
    
    furi_mutex_release(app->data_mutex);
    
    // Log for debugging
    char log_msg[64];
    snprintf(log_msg, sizeof(log_msg), "conn cb: %d, exit=%d, view=%d", 
             connected, exiting, view_valid);
    debug_log(log_msg);
    
    // Safety checks
    if(exiting) {
        FURI_LOG_W(TAG, "App exiting, ignoring connection event");
        return;
    }
    
    if(!view_valid || !view_dispatcher) {
        FURI_LOG_E(TAG, "View dispatcher invalid, cannot send event");
        return;
    }
    
    // Send event through view_dispatcher (thread-safe)
    if(connected) {
        FURI_LOG_I(TAG, "FIDO2 device connected - sending event");
        view_dispatcher_send_custom_event(view_dispatcher, U2fCustomEventConnect);
    } else {
        FURI_LOG_I(TAG, "FIDO2 device disconnected - sending event");
        view_dispatcher_send_custom_event(view_dispatcher, U2fCustomEventDisconnect);
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

    // Check if app is exiting
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    bool exiting = app->exiting;
    furi_mutex_release(app->data_mutex);
    
    if(exiting) return false;

    if(event.type == SceneManagerEventTypeCustom) {
        // Use %lu for uint32_t event.event
        FURI_LOG_I(TAG, "Custom event: %lu", event.event);
        
        switch(event.event) {
        case U2fCustomEventConnect:
            furi_timer_stop(app->timer);
            u2f_view_set_state(app->u2f_view, U2fMsgIdle);
            consumed = true;
            break;
            
        case U2fCustomEventDisconnect:
            furi_timer_stop(app->timer);
            app->event_cur = U2fCustomEventNone;
            u2f_view_set_state(app->u2f_view, U2fMsgNotConnected);
            consumed = true;
            break;
            
        case U2fCustomEventRegister:
        case U2fCustomEventAuth:
            furi_timer_start(app->timer, U2F_REQUEST_TIMEOUT);
            if(app->event_cur == U2fCustomEventNone) {
                app->event_cur = event.event;
                if(event.event == U2fCustomEventRegister) {
                    u2f_view_set_state(app->u2f_view, U2fMsgRegister);
                } else {
                    u2f_view_set_state(app->u2f_view, U2fMsgAuth);
                }
                notification_message(app->notifications, &sequence_display_backlight_on);
                notification_message(app->notifications, &sequence_single_vibro);
            }
            notification_message(app->notifications, &sequence_blink_magenta_10);
            consumed = true;
            break;
            
        case U2fCustomEventWink:
            notification_message(app->notifications, &sequence_blink_magenta_10);
            consumed = true;
            break;
            
        case U2fCustomEventAuthSuccess:
            notification_message_block(app->notifications, &sequence_set_green_255);
            dolphin_deed(DolphinDeedU2fAuthorized);
            furi_timer_start(app->timer, U2F_SUCCESS_TIMEOUT);
            app->event_cur = U2fCustomEventNone;
            u2f_view_set_state(app->u2f_view, U2fMsgSuccess);
            consumed = true;
            break;
            
        case U2fCustomEventTimeout:
            notification_message_block(app->notifications, &sequence_reset_rgb);
            app->event_cur = U2fCustomEventNone;
            u2f_view_set_state(app->u2f_view, U2fMsgIdle);
            consumed = true;
            break;
            
        case U2fCustomEventConfirm:
            if(app->event_cur != U2fCustomEventNone) {
                if(app->fido_mode == FidoModeU2F && app->u2f_instance) {
                    u2f_confirm_user_present(app->u2f_instance);
                } else if(app->fido_mode == FidoModeFIDO2 && app->fido2_instance) {
                    fido2_app_confirm_user_present((Fido2App*)app->fido2_instance);
                }
            }
            consumed = true;
            break;
            
        case U2fCustomEventDataError:
            notification_message(app->notifications, &sequence_set_red_255);
            furi_timer_stop(app->timer);
            u2f_view_set_state(app->u2f_view, U2fMsgError);
            consumed = true;
            break;
            
        default:
            break;
        }
    }

    return consumed;
}

void u2f_scene_main_on_enter(void* context) {
    U2fApp* app = context;

    // Reset exiting flag when entering
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    app->exiting = false;
    furi_mutex_release(app->data_mutex);
    
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
        debug_log("FIDO2 mode selected");
        
        app->fido2_instance = fido2_app_alloc();
        if(!app->fido2_instance) {
            FURI_LOG_E(TAG, "Failed to allocate FIDO2 app");
            debug_log("FIDO2 alloc FAILED");
            u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
        } else {
            debug_log("FIDO2 app allocated");
            
            if(!fido2_app_init((Fido2App*)app->fido2_instance)) {
                FURI_LOG_E(TAG, "Failed to initialize FIDO2 app");
                debug_log("FIDO2 init FAILED");
                fido2_app_free((Fido2App*)app->fido2_instance);
                app->fido2_instance = NULL;
                u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
            } else {
                debug_log("FIDO2 init SUCCESS");
                
                // Set callbacks
                fido2_app_set_user_presence_callback(
                    (Fido2App*)app->fido2_instance,
                    fido2_scene_user_presence_callback,
                    app);
                
                fido2_app_set_event_callback(
                    (Fido2App*)app->fido2_instance,
                    fido2_scene_main_event_callback,
                    app);
                
                // Get CTAP instance
                Fido2Ctap* ctap = fido2_app_get_ctap((Fido2App*)app->fido2_instance);
                if(ctap) {
                    debug_log("Starting FIDO2 HID");
                    
                    app->fido2_hid = fido2_hid_start(ctap);
                    
                    if(app->fido2_hid) {
                        debug_log("FIDO2 HID started");
                        app->usb_initialized = true;
                        
                        // Set connection callback with thread-safe wrapper
                        fido2_hid_set_connection_callback(
                            app->fido2_hid,
                            fido2_connection_state_callback,
                            app);
                        
                        u2f_view_set_ok_callback(app->u2f_view, u2f_scene_main_ok_callback, app);
                        u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
                        
                        FURI_LOG_I(TAG, "FIDO2 initialization complete");
                        debug_log("FIDO2 ready");
                    } else {
                        FURI_LOG_E(TAG, "FIDO2 HID start failed");
                        debug_log("HID start FAILED");
                        fido2_app_free((Fido2App*)app->fido2_instance);
                        app->fido2_instance = NULL;
                        u2f_view_set_state(app->u2f_view, U2fMsgFido2Ready);
                    }
                } else {
                    FURI_LOG_E(TAG, "Failed to get CTAP instance");
                    debug_log("CTAP instance FAILED");
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
    
    FURI_LOG_I(TAG, "u2f_scene_main_on_exit");
    debug_log("Scene main on exit");
    
    // Set exiting flag to prevent callbacks during cleanup
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    app->exiting = true;
    furi_mutex_release(app->data_mutex);
    
    notification_message_block(app->notifications, &sequence_reset_rgb);
    
    if(app->timer) {
        furi_timer_stop(app->timer);
        furi_timer_free(app->timer);
        app->timer = NULL;
    }

    // Clean up USB and instances
    if(app->usb_initialized) {
        if(app->fido_mode == FidoModeU2F && app->u2f_instance) {
            if(app->u2f_hid) {
                u2f_hid_stop(app->u2f_hid);
                app->u2f_hid = NULL;
            }
            u2f_free(app->u2f_instance);
            app->u2f_instance = NULL;
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

    // Reset mode
    app->fido_mode = FidoModeNone;
    
    debug_log("Scene main on exit complete");
}