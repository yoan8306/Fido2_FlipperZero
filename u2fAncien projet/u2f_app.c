#include "u2f_app_i.h"
#include "u2f_hid.h"
#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_usb.h>

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

U2fApp* u2f_app_alloc() {
    U2fApp* app = malloc(sizeof(U2fApp));

    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, u2f_app_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, u2f_app_back_event_callback);
    view_dispatcher_set_tick_event_callback(app->view_dispatcher, u2f_app_tick_event_callback, 500);

    app->scene_manager = scene_manager_alloc(&u2f_scene_handlers, app);

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    // Menu de sélection
    app->submenu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, U2fAppViewMenu, submenu_get_view(app->submenu));

    // Vue U2F principale
    app->u2f_view = u2f_view_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, U2fAppViewMain, u2f_view_get_view(app->u2f_view));

    // Widget pour erreurs et FIDO2
    app->widget = widget_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, U2fAppViewError, widget_get_view(app->widget));
    view_dispatcher_add_view(
        app->view_dispatcher, U2fAppViewWidget, widget_get_view(app->widget));

    // Initialisation U2F
    app->u2f_instance = u2f_alloc();
    app->u2f_hid = NULL;
    
    // Mode par défaut
    app->mode = U2fModeU2F;
    FURI_LOG_I("U2F", "Created U2F app, default mode: %s", 
               app->mode == U2fModeU2F ? "U2F" : "FIDO2");
    // État initial
    app->event_cur = U2fCustomEventNone;
    app->u2f_ready = false;
    app->timer = NULL;

    // Commencer par le menu
    scene_manager_next_scene(app->scene_manager, U2fSceneMenu);

    return app;
}
void u2f_app_free(U2fApp* app) {
    furi_assert(app);

    FURI_LOG_I("U2F", "Freeing U2F app, restoring USB to normal mode");

    // Libérer les ressources U2F
    if(app->u2f_instance) {
        u2f_free(app->u2f_instance);
    }

    if(app->u2f_hid) {
        u2f_hid_stop(app->u2f_hid);
    }
    
    // CRITIQUE: Restaurer la configuration USB par défaut (CDC/série)
    // Cela permet de reconnecter le Flipper normalement sans reboot
    FURI_LOG_I("U2F", "Restoring default USB CDC configuration");
    
    // Déconnecter d'abord pour forcer la déconnexion
    furi_hal_usb_set_config(NULL, NULL);
    furi_delay_ms(100);
    
    // Restaurer la configuration CDC par défaut
    // usb_cdc_single est déjà déclaré dans furi_hal_usb.h
    if(!furi_hal_usb_set_config(&usb_cdc_single, NULL)) {
        FURI_LOG_E("U2F", "Failed to restore USB CDC config");
    } else {
        FURI_LOG_I("U2F", "USB CDC config restored successfully");
    }
    
    furi_delay_ms(100); // Laisser le temps à l'USB de se réinitialiser

    // Retirer les vues
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewMain);
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewError);
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewWidget);

    // Libérer les vues
    if(app->submenu) submenu_free(app->submenu);
    if(app->u2f_view) u2f_view_free(app->u2f_view);
    if(app->widget) widget_free(app->widget);

    // Libérer view dispatcher et scene manager
    view_dispatcher_free(app->view_dispatcher);
    scene_manager_free(app->scene_manager);

    // Fermer les records
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);

    free(app);
    
    FURI_LOG_I("U2F", "U2F app freed, USB should be back to normal");
}

int32_t u2f_app(void* p) {
    UNUSED(p);
    U2fApp* app = u2f_app_alloc();

    view_dispatcher_run(app->view_dispatcher);

    u2f_app_free(app);

    return 0;
}