#include "../u2f_app_i.h"

enum SubmenuIndex {
    SubmenuIndexU2F,
    SubmenuIndexFIDO2,
};

void u2f_scene_menu_submenu_callback(void* context, uint32_t index) {
    U2fApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void u2f_scene_menu_on_enter(void* context) {
    U2fApp* app = context;
    Submenu* submenu = app->submenu;

    submenu_add_item(
        submenu,
        "U2F (FIDO1)",
        SubmenuIndexU2F,
        u2f_scene_menu_submenu_callback,
        app);
    
    submenu_add_item(
        submenu,
        "FIDO2",
        SubmenuIndexFIDO2,
        u2f_scene_menu_submenu_callback,
        app);

    submenu_set_selected_item(
        submenu, scene_manager_get_scene_state(app->scene_manager, U2fSceneMenu));

    view_dispatcher_switch_to_view(app->view_dispatcher, U2fAppViewMenu);
}

bool u2f_scene_menu_on_event(void* context, SceneManagerEvent event) {
    U2fApp* app = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == SubmenuIndexU2F) {
            scene_manager_set_scene_state(app->scene_manager, U2fSceneMenu, SubmenuIndexU2F);
            app->mode = U2fModeU2F;
            scene_manager_next_scene(app->scene_manager, U2fSceneMain);
            consumed = true;
        } else if(event.event == SubmenuIndexFIDO2) {
            scene_manager_set_scene_state(app->scene_manager, U2fSceneMenu, SubmenuIndexFIDO2);
            app->mode = U2fModeFIDO2;
            scene_manager_next_scene(app->scene_manager, U2fSceneFido2);
            consumed = true;
        }
    }

    return consumed;
}

void u2f_scene_menu_on_exit(void* context) {
    U2fApp* app = context;
    submenu_reset(app->submenu);
}
