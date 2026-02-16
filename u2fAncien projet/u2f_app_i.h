#pragma once

#include "u2f_app.h"
#include "u2f_data.h"
#include "u2f_hid.h"
#include "u2f.h"
#include "views/u2f_view.h"

#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/scene_manager.h>
#include <gui/modules/submenu.h>
#include <gui/modules/widget.h>
#include <notification/notification_messages.h>

#define TAG "U2F"

// Mode de fonctionnement
typedef enum {
    U2fModeU2F,    // Mode U2F classique (FIDO1)
    U2fModeFIDO2,  // Mode FIDO2
} U2fMode;

// Scènes
typedef enum {
    U2fSceneMenu,    // Menu de sélection
    U2fSceneMain,    // Scène U2F principale
    U2fSceneError,   // Scène d'erreur
    U2fSceneFido2,   // Scène FIDO2
    U2fSceneNum,
} U2fScene;

// Custom events
typedef enum {
    U2fCustomEventNone,
    U2fCustomEventRegister,
    U2fCustomEventAuth,
    U2fCustomEventAuthSuccess,
    U2fCustomEventWink,
    U2fCustomEventConnect,
    U2fCustomEventDisconnect,
    U2fCustomEventTimeout,
    U2fCustomEventConfirm,
    U2fCustomEventDataError,
    U2fCustomEventErrorBack,
} U2fCustomEvent;

// App views
typedef enum {
    U2fAppViewMenu,     // Menu
    U2fAppViewMain,     // Vue U2F principale
    U2fAppViewError,    // Vue d'erreur
    U2fAppViewWidget,   // Vue widget pour FIDO2
} U2fAppView;

// App errors
typedef enum {
    U2fAppErrorNoFiles,
} U2fAppError;

// Structure de l'application
struct U2fApp {
    Gui* gui;
    NotificationApp* notifications;
    ViewDispatcher* view_dispatcher;
    SceneManager* scene_manager;
    
    Submenu* submenu;
    Widget* widget;
    
    U2fMode mode;           // Mode actuel
    
    // Champs U2F
    U2fView* u2f_view;
    U2fData* u2f_instance;
    U2fHid* u2f_hid;
    FuriTimer* timer;
    U2fCustomEvent event_cur;
    bool u2f_ready;
    
    U2fAppError error;
};

extern const SceneManagerHandlers u2f_scene_handlers;