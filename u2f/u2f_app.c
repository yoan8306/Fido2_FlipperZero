#include "u2f_app_i.h"
#include "u2f_data.h"
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

    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    app->view_dispatcher = view_dispatcher_alloc();
    app->scene_manager = scene_manager_alloc(&u2f_scene_handlers, app);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_tick_event_callback(
        app->view_dispatcher, u2f_app_tick_event_callback, 500);

    view_dispatcher_set_custom_event_callback(app->view_dispatcher, u2f_app_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, u2f_app_back_event_callback);

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    // Submenu for mode selection (NOUVEAU)
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

    // Initialisation des états
    app->fido_mode = FidoModeNone;
    app->usb_initialized = false;
    app->u2f_instance = NULL;
    app->fido2_instance = NULL;
    app->u2f_hid = NULL;

    // Déverrouiller l'USB mais NE PAS l'initialiser
    furi_hal_usb_unlock();
    
    FURI_LOG_I(TAG, "USB unlocked, waiting for mode selection");

    // Vérifier si les fichiers U2F existent
    if(u2f_data_check(true)) {
        // Aller au menu de sélection au lieu de Main directement
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

    // S'assurer que l'USB est arrêté proprement
    if(app->usb_initialized) {
        if(app->fido_mode == FidoModeU2F && app->u2f_instance) {
            u2f_hid_stop(app->u2f_hid);
            u2f_free(app->u2f_instance);
        } else if(app->fido_mode == FidoModeFIDO2 && app->fido2_instance) {
            // À implémenter : libération des ressources FIDO2
            // fido2_hid_stop(app->fido2_hid);
            // fido2_free((Fido2Data*)app->fido2_instance);
        }
    }

    // Views
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewSelectMode);
    submenu_free(app->submenu);
    
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewMain);
    u2f_view_free(app->u2f_view);

    // Custom Widget
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewError);
    widget_free(app->widget);

    // View dispatcher
    view_dispatcher_free(app->view_dispatcher);
    scene_manager_free(app->scene_manager);

    // Close records
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);

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