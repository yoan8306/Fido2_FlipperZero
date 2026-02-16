#include "../u2f_app_i.h"
#include <furi_hal_usb.h>

static void u2f_scene_fido2_timer_callback(void* context) {
    U2fApp* app = context;
    
    bool usb_connected = furi_hal_usb_is_locked();
    
    widget_reset(app->widget);
    
    widget_add_string_element(
        app->widget, 64, 10,
        AlignCenter, AlignCenter, FontPrimary,
        "FIDO2 Authenticator");
    
    if(usb_connected) {
        widget_add_string_element(
            app->widget, 64, 30,
            AlignCenter, AlignCenter, FontPrimary,
            "Connected");
        widget_add_string_element(
            app->widget, 64, 42,
            AlignCenter, AlignCenter, FontSecondary,
            "FIDO2 mode active");
    } else {
        widget_add_string_element(
            app->widget, 64, 30,
            AlignCenter, AlignCenter, FontSecondary,
            "Not Connected");
        widget_add_string_element(
            app->widget, 64, 42,
            AlignCenter, AlignCenter, FontSecondary,
            "Plug USB cable");
    }
    
    widget_add_string_element(
        app->widget, 64, 54,
        AlignCenter, AlignCenter, FontSecondary,
        "Press Back to return");
}

void u2f_scene_fido2_on_enter(void* context) {
    U2fApp* app = context;
    
    app->timer = furi_timer_alloc(u2f_scene_fido2_timer_callback, FuriTimerTypePeriodic, app);
    furi_timer_start(app->timer, 500);
    
    u2f_scene_fido2_timer_callback(app);
    
    view_dispatcher_switch_to_view(app->view_dispatcher, U2fAppViewWidget);
}

bool u2f_scene_fido2_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void u2f_scene_fido2_on_exit(void* context) {
    U2fApp* app = context;
    
    if(app->timer) {
        furi_timer_stop(app->timer);
        furi_timer_free(app->timer);
        app->timer = NULL;
    }
    
    widget_reset(app->widget);
}
