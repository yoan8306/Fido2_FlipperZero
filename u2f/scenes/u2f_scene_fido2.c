#include "../u2f_app_i.h"

void u2f_scene_fido2_on_enter(void* context) {
    U2fApp* app = context;
    
    // ✅ INITIALISER LE HID EN MODE FIDO2
    if(!app->u2f_hid) {
        app->u2f_hid = u2f_hid_start(app->u2f_instance, app);
    }
    
    // Réutiliser le widget pour afficher le statut
    widget_reset(app->widget);
    
    widget_add_string_element(
        app->widget,
        64,
        10,
        AlignCenter,
        AlignCenter,
        FontPrimary,
        "FIDO2 Authenticator");
    
    widget_add_string_element(
        app->widget,
        64,
        30,
        AlignCenter,
        AlignCenter,
        FontPrimary,
        "USB Connected");
    
    widget_add_string_element(
        app->widget,
        64,
        42,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        "FIDO2 mode active");
    
    widget_add_string_element(
        app->widget,
        64,
        54,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        "Press Back to return");
    
    view_dispatcher_switch_to_view(app->view_dispatcher, U2fAppViewWidget);
}

bool u2f_scene_fido2_on_event(void* context, SceneManagerEvent event) {
    U2fApp* app = context;
    UNUSED(app);
    // Permettre de revenir au menu
    if(event.type == SceneManagerEventTypeBack) {
        return true;  // Consume l'événement
    }
    
    return false;
}



void u2f_scene_fido2_on_exit(void* context) {
    U2fApp* app = context;
    widget_reset(app->widget);
    
    // ✅ Arrêter le HID en quittant la scène FIDO2
    if(app->u2f_hid) {
        u2f_hid_stop(app->u2f_hid);
        app->u2f_hid = NULL;
    }
}