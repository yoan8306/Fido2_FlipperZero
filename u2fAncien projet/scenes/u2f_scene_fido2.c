#include "../u2f_app_i.h"
#include "../u2f_hid.h"
#include <furi_hal_usb.h>

static void u2f_scene_fido2_timer_callback(void* context) {
    U2fApp* app = context;
    
    bool usb_connected = furi_hal_usb_is_locked();
    bool hid_ready = (app->u2f_hid != NULL);
    bool fido2_ready = u2f_hid_is_fido2_ready(app->u2f_hid);
    
    // Log pour debug
    static int counter = 0;
    if(counter++ % 10 == 0) { // Log toutes les 5 secondes
        FURI_LOG_I("FIDO2", "USB: %d, HID: %d, FIDO2: %d", 
                   usb_connected, hid_ready, fido2_ready);
    }
    
    widget_reset(app->widget);
    
    widget_add_string_element(
        app->widget,
        64,
        10,
        AlignCenter,
        AlignCenter,
        FontPrimary,
        "FIDO2 Authenticator");
    
    if(usb_connected && hid_ready) {
        widget_add_string_element(
            app->widget,
            64,
            30,
            AlignCenter,
            AlignCenter,
            FontPrimary,
            "Connected");
        
        if(fido2_ready) {
            widget_add_string_element(
                app->widget,
                64,
                42,
                AlignCenter,
                AlignCenter,
                FontSecondary,
                "FIDO2 mode active");
        } else {
            widget_add_string_element(
                app->widget,
                64,
                42,
                AlignCenter,
                AlignCenter,
                FontSecondary,
                "FIDO2 init error");
        }
    } else {
        widget_add_string_element(
            app->widget,
            64,
            30,
            AlignCenter,
            AlignCenter,
            FontSecondary,
            "Not Connected");
        
        if(!usb_connected) {
            widget_add_string_element(
                app->widget,
                64,
                42,
                AlignCenter,
                AlignCenter,
                FontSecondary,
                "Plug USB cable");
        } else if(!hid_ready) {
            widget_add_string_element(
                app->widget,
                64,
                42,
                AlignCenter,
                AlignCenter,
                FontSecondary,
                "HID not ready");
        }
    }
    
    widget_add_string_element(
        app->widget,
        64,
        54,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        "Press Back to return");
}

void u2f_scene_fido2_on_enter(void* context) {
    U2fApp* app = context;
    
    FURI_LOG_I("FIDO2", "Entering FIDO2 scene");
    
    // S'assurer que le HID est démarré
    if(!app->u2f_hid) {
        FURI_LOG_I("FIDO2", "Starting HID from FIDO2 scene");
        app->u2f_hid = u2f_hid_start(app->u2f_instance, app);
    }
    
    app->timer = furi_timer_alloc(u2f_scene_fido2_timer_callback, FuriTimerTypePeriodic, app);
    furi_timer_start(app->timer, 500); // Vérifier toutes les 500ms
    
    // Affichage initial
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
    
    FURI_LOG_I("FIDO2", "Exiting FIDO2 scene");
    
    if(app->timer) {
        furi_timer_stop(app->timer);
        furi_timer_free(app->timer);
        app->timer = NULL;
    }
    
    widget_reset(app->widget);
}