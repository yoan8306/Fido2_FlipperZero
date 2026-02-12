#include "../u2f_app_i.h"

void u2f_scene_fido2_on_enter(void* context) {
    U2fApp* app = context;
    
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
        "Connected");
    
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
    UNUSED(context);
    UNUSED(event);
    return false;
}

void u2f_scene_fido2_on_exit(void* context) {
    U2fApp* app = context;
    widget_reset(app->widget);
}
