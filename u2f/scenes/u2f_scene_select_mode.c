#include "../u2f_app_i.h"
#include "../fido_mode.h"
#include <gui/modules/submenu.h>

static void u2f_scene_select_mode_submenu_callback(void* context, uint32_t index) {
    furi_assert(context);
    U2fApp* app = context;
    
    if(index == 0) {
        view_dispatcher_send_custom_event(app->view_dispatcher, FidoCustomEventSelectU2F);
    } else if(index == 1) {
        view_dispatcher_send_custom_event(app->view_dispatcher, FidoCustomEventSelectFIDO2);
    }
}

void u2f_scene_select_mode_on_enter(void* context) {
    U2fApp* app = context;
    Submenu* submenu = app->submenu;
    
    submenu_reset(submenu);
    submenu_set_header(submenu, "Select FIDO Mode");
    submenu_add_item(submenu, "U2F (FIDO1)", 0, u2f_scene_select_mode_submenu_callback, app);
    submenu_add_item(submenu, "FIDO2", 1, u2f_scene_select_mode_submenu_callback, app);
    
    view_dispatcher_switch_to_view(app->view_dispatcher, U2fAppViewSelectMode);
}

bool u2f_scene_select_mode_on_event(void* context, SceneManagerEvent event) {
    furi_assert(context);
    U2fApp* app = context;
    bool consumed = false;
    
    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == FidoCustomEventSelectU2F) {
            app->fido_mode = FidoModeU2F;
            scene_manager_next_scene(app->scene_manager, U2fSceneMain);
            consumed = true;
        } else if(event.event == FidoCustomEventSelectFIDO2) {
            app->fido_mode = FidoModeFIDO2;
            scene_manager_next_scene(app->scene_manager, U2fSceneMain);
            consumed = true;
        }
    } else if(event.type == SceneManagerEventTypeBack) {
        // Exit app if back pressed in mode selection
        view_dispatcher_stop(app->view_dispatcher);
        consumed = true;
    }
    
    return consumed;
}

void u2f_scene_select_mode_on_exit(void* context) {
    U2fApp* app = context;
    submenu_reset(app->submenu);
}