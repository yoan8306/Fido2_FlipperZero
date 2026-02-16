#pragma once

#include "u2f_app.h"
#include "scenes/u2f_scene.h"
#include "fido_mode.h"

#include <gui/gui.h>
#include <assets_icons.h>
#include <gui/view_dispatcher.h>
#include <gui/scene_manager.h>
#include <gui/modules/submenu.h>
#include <dialogs/dialogs.h>
#include <notification/notification_messages.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/widget.h>
#include "views/u2f_view.h"
#include "u2f_hid.h"
#include "u2f.h"

typedef enum {
    U2fAppErrorNoFiles,
} U2fAppError;

typedef enum {
    U2fCustomEventNone = 0,
    U2fCustomEventConnect,
    U2fCustomEventDisconnect,
    U2fCustomEventDataError,
    U2fCustomEventRegister,
    U2fCustomEventAuth,
    U2fCustomEventAuthSuccess,
    U2fCustomEventWink,
    U2fCustomEventTimeout,
    U2fCustomEventConfirm,
    U2fCustomEventErrorBack,
} GpioCustomEvent;

typedef enum {
    U2fAppViewSelectMode = 0,
    U2fAppViewError,
    U2fAppViewMain,
} U2fAppView;

/**
 * @brief Main application structure with thread-safe guards
 */
struct U2fApp {
    // Core system
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    SceneManager* scene_manager;
    NotificationApp* notifications;
    
    // UI components
    Widget* widget;
    Submenu* submenu;
    U2fView* u2f_view;
    
    // Timers
    FuriTimer* timer;
    
    // U2F (FIDO1) components
    U2fHid* u2f_hid;
    U2fData* u2f_instance;
    bool u2f_ready;
    
    // FIDO2 components
    void* fido2_instance;
    void* fido2_hid;
    
    // State management
    GpioCustomEvent event_cur;
    bool usb_initialized;
    FidoMode fido_mode;
    U2fAppError error;
    
    // Thread safety guards
    volatile bool exiting;           // Set when app is shutting down
    volatile bool view_dispatcher_valid;  // Set while view_dispatcher is alive
    FuriMutex* data_mutex;           // Mutex for thread-safe data access
};