#include "u2f_app_i.h"
#include "u2f_hid.h"
#include <furi.h>
#include <furi_hal.h>

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

    // NOUVEAU - Submenu pour le menu de sélection
    app->submenu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, U2fAppViewMenu, submenu_get_view(app->submenu));

    // ORIGINAL - Vue U2F principale
    app->u2f_view = u2f_view_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, U2fAppViewMain, u2f_view_get_view(app->u2f_view));

    // ORIGINAL - Widget pour erreurs
    app->widget = widget_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, U2fAppViewError, widget_get_view(app->widget));

    // NOUVEAU - Widget pour FIDO2 (réutilise le même widget)
    view_dispatcher_add_view(
        app->view_dispatcher, U2fAppViewWidget, widget_get_view(app->widget));

    // ORIGINAL - Initialisation U2F
    app->u2f_instance = u2f_alloc();
    app->u2f_hid = NULL;  // USB sera démarré dans les scènes
    
    // NOUVEAU - Mode par défaut
    app->mode = U2fModeU2F;
    
    // ORIGINAL - État initial
    app->event_cur = U2fCustomEventNone;
    app->u2f_ready = false;

    // MODIFIÉ - Commencer par le menu au lieu de Main
    scene_manager_next_scene(app->scene_manager, U2fSceneMenu);

    return app;
}

void u2f_app_free(U2fApp* app) {
    furi_assert(app);

    // ORIGINAL - Libérer les ressources U2F
    if(app->u2f_instance) {
        u2f_free(app->u2f_instance);
    }

	if(app->u2f_hid) {
    	   u2f_hid_stop(app->u2f_hid);  // Essayez u2f_hid_stop au lieu de free
	}
  //  if(app->u2f_hid) {
   //     u2f_hid_free(app->u2f_hid);
   // }

    // Retirer les vues
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewMain);
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewError);
    view_dispatcher_remove_view(app->view_dispatcher, U2fAppViewWidget);

    // Libérer les vues
    submenu_free(app->submenu);
    u2f_view_free(app->u2f_view);
    widget_free(app->widget);

    // Libérer view dispatcher et scene manager
    view_dispatcher_free(app->view_dispatcher);
    scene_manager_free(app->scene_manager);

    // Fermer les records
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);

    free(app);
}

int32_t u2f_app(void* p) {
    UNUSED(p);
    U2fApp* app = u2f_app_alloc();

    view_dispatcher_run(app->view_dispatcher);

    u2f_app_free(app);

    return 0;
}
