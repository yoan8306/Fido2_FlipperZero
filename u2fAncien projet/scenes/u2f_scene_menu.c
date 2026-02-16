#include "../u2f_app_i.h"
#include <furi_hal_usb.h>

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
            
            FURI_LOG_I("U2F", "Switching to U2F mode");
            
            // Force USB disconnection
            if(app->u2f_hid) {
                FURI_LOG_I("U2F", "Stopping HID for mode switch");
                u2f_hid_stop(app->u2f_hid);
                app->u2f_hid = NULL;
            }
            
            // Set U2F mode AVANT de redémarrer
            app->mode = U2fModeU2F;
            FURI_LOG_I("U2F", "Mode set to: U2F");
            
            // Restart HID with correct mode
            FURI_LOG_I("U2F", "Starting HID in U2F mode");
            app->u2f_hid = u2f_hid_start(app->u2f_instance, app);
            
            if(app->u2f_hid) {
                FURI_LOG_I("U2F", "HID started successfully");
                scene_manager_next_scene(app->scene_manager, U2fSceneMain);
            } else {
                FURI_LOG_E("U2F", "Failed to start HID");
            }
            consumed = true;
            
        } else if(event.event == SubmenuIndexFIDO2) {
            scene_manager_set_scene_state(app->scene_manager, U2fSceneMenu, SubmenuIndexFIDO2);
            
            FURI_LOG_I("U2F", "Switching to FIDO2 mode");
            
            // Force USB disconnection
            if(app->u2f_hid) {
                FURI_LOG_I("U2F", "Stopping HID for mode switch");
                u2f_hid_stop(app->u2f_hid);
                app->u2f_hid = NULL;
            }
            
            // Set FIDO2 mode AVANT de redémarrer
            app->mode = U2fModeFIDO2;
            FURI_LOG_I("U2F", "Mode set to: FIDO2");
            
            // Restart HID with correct mode
            FURI_LOG_I("U2F", "Starting HID in FIDO2 mode");
            app->u2f_hid = u2f_hid_start(app->u2f_instance, app);
            
            if(app->u2f_hid) {
                FURI_LOG_I("U2F", "HID started successfully");
                scene_manager_next_scene(app->scene_manager, U2fSceneFido2);
            } else {
                FURI_LOG_E("U2F", "Failed to start HID");
            }
            consumed = true;
        }
    }

    return consumed;
}

void u2f_scene_menu_on_exit(void* context) {
    U2fApp* app = context;
    submenu_reset(app->submenu);
}