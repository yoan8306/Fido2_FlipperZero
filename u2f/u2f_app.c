#include "u2f_app_i.h"
#include "u2f_data.h"
#include "fido2_app.h"
#include "fido2_hid.h"
#include <furi.h>
#include <furi_hal.h>
#include <storage/storage.h>

#define TAG "U2fApp"

static bool u2f_app_custom_event_callback(void* context, uint32_t event) {
    furi_assert(context);
    U2fApp* app = context;
    return scene_manager_handle_custom_event(app->scene_manager, event);
}

static bool u2f_app_back_event_callback(void* context) {
    furi_assert(context);
    U2fApp* app = context;
    return scene_manager_handle_back_event(app->scene_manager);
}

static void u2f_app_tick_event_callback(void* context) {
    furi_assert(context);
    U2fApp* app = context;
    scene_manager_handle_tick_event(app->scene_manager);
}

U2fApp* u2f_app_alloc(void) {
    U2fApp* app = malloc(sizeof(U2fApp));
    
    // Initialize thread safety
    app->data_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->exiting = false;
    app->view_dispatcher_valid = false;

    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    app->view_dispatcher = view_dispatcher_alloc();
    app->view_dispatcher_valid = true;
    
    app->scene_manager = scene_manager_alloc(&u2f_scene_handlers, app);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_tick_event_callback(
        app->view_dispatcher, u2f_app_tick_event_callback, 500);

    view_dispatcher_set_custom_event_callback(app->view_dispatcher, u2f_app_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, u2f_app_back_event_callback);

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    // Submenu for mode selection
    app->submenu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, U2fAppViewSelectMode, submenu_get_view(app->submenu));

    // Custom Widget
    app->widget = widget_alloc();
    view_dispatcher_add_view(app->view_dispatcher, U2fAppViewError, widget_get_view(app->widget));

    // Main U2F/FIDO2 view
    app->u2f_view = u2f_view_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, U2fAppViewMain, u2f_view_get_view(app->u2f_view));

    // Initialize state
    app->fido_mode = FidoModeNone;
    app->usb_initialized = false;
    app->u2f_instance = NULL;
    app->fido2_instance = NULL;
    app->u2f_hid = NULL;
    app->fido2_hid = NULL;

    // Unlock USB but don't initialize
    furi_hal_usb_unlock();
    
    FURI_LOG_I(TAG, "USB unlocked, waiting for mode selection");

    // Check if U2F files exist
    if(u2f_data_check(true)) {
        FURI_LOG_I(TAG, "U2F data found, showing mode selection");
        scene_manager_next_scene(app->scene_manager, U2fSceneSelectMode);
    } else {
        FURI_LOG_E(TAG, "U2F data not found");
        app->error = U2fAppErrorNoFiles;
        scene_manager_next_scene(app->scene_manager, U2fSceneError);
    }

    return app;
}

void u2f_app_free(U2fApp* app) {
    furi_assert(app);

    FURI_LOG_I(TAG, "Freeing U2F app resources");
    
    // Set exiting flag to prevent callbacks
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    app->exiting = true;
    furi_mutex_release(app->data_mutex);

    // Clean up USB and instances
    if(app->usb_initialized) {
        if(app->fido_mode == FidoModeU2F && app->u2f_instance) {
            if(app->u2f_hid) {
                u2f_hid_stop(app->u2f_hid);
                app->u2f_hid = NULL;
            }
            u2f_free(app->u2f_instance);
            app->u2f_instance = NULL;
        } else if(app->fido_mode == FidoModeFIDO2 && app->fido2_instance) {
            if(app->fido2_hid) {
                fido2_hid_stop(app->fido2_hid);
                app->fido2_hid = NULL;
            }
            fido2_app_free((Fido2App*)app->fido2_instance);
            app->fido2_instance = NULL;
        }
        app->usb_initialized = false;
    }

    // Mark view_dispatcher as invalid before removing views
    app->view_dispatcher_valid = false;

    // Remove and free views
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewSelectMode);
    submenu_free(app->submenu);
    
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewMain);
    u2f_view_free(app->u2f_view);

    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewError);
    widget_free(app->widget);

    // Free view dispatcher and scene manager
    view_dispatcher_free(app->view_dispatcher);
    scene_manager_free(app->scene_manager);

    // Close records
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);

    // Free mutex
    furi_mutex_free(app->data_mutex);

    free(app);
    
    FURI_LOG_I(TAG, "U2F app freed");
}

int32_t u2f_app(void* p) {
    UNUSED(p);
    U2fApp* u2f_app = u2f_app_alloc();

    view_dispatcher_run(u2f_app->view_dispatcher);

    u2f_app_free(u2f_app);

    return 0;
}