#include "../u2f_app_i.h"

void u2f_scene_fido2_on_enter(void* context) {
    U2fApp* app = context;
    
    // Réutiliser le widget
    widget_reset(app->widget);
    
    widget_add_string_element(
        app->widget,
        64,
        10,
        AlignCenter,
        AlignCenter,
        FontPrimary,
        "FIDO2 Authenticator");
    
    // Pour l'instant, juste afficher "Connected" par défaut
    // La détection USB réelle viendra plus tard
    widget_add_string_element(
        app->widget,
        64,
        30,
        AlignCenter,
        AlignCenter,
        FontPrimary,
        "Ready");
    
    widget_add_string_element(
        app->widget,
        64,
        42,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        "FIDO2 mode");
    
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
    UNUSED(context);
    UNUSED(event);
    return false;
}

void u2f_scene_fido2_on_exit(void* context) {
    U2fApp* app = context;
    widget_reset(app->widget);
}
