#pragma once

#include "u2f_app.h"
#include "u2f_data.h"
#include "u2f_hid.h"

#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/scene_manager.h>
#include <gui/modules/submenu.h>
#include <gui/modules/widget.h>
#include <notification/notification_messages.h>

#include <gui/modules/variable_item_list.h>
#include <gui/view.h>

#include "views/u2f_view.h"

#define TAG "U2F"

// Mode de fonctionnement (NOUVEAU)
typedef enum {
    U2fModeU2F,    // Mode U2F classique (FIDO1)
    U2fModeFIDO2,  // Mode FIDO2
} U2fMode;

// Scènes (MODIFIÉ - ajout menu et fido2)
typedef enum {
    U2fSceneMenu,    // NOUVEAU - Menu de sélection
    U2fSceneMain,    // Existant - Scène U2F principale
    U2fSceneError,   // Existant - Scène d'erreur
    U2fSceneFido2,   // NOUVEAU - Scène FIDO2
    U2fSceneNum,
} U2fScene;

// Custom events (GARDÉ DE L'ORIGINAL)
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

// App views (MODIFIÉ - gardé compatibilité mais renommé)
typedef enum {
    U2fAppViewMenu,     // NOUVEAU
    U2fAppViewMain,     // Existant (garde le nom U2fAppViewMain)
    U2fAppViewError,    // Existant (garde le nom U2fAppViewError)  
    U2fAppViewWidget,   // NOUVEAU - pour FIDO2
} U2fAppView;

// App errors (GARDÉ DE L'ORIGINAL)
typedef enum {
    U2fAppErrorNoFiles,
} U2fAppError;

// Structure de l'application (MODIFIÉ - tous les champs gardés)
struct U2fApp {
    Gui* gui;
    NotificationApp* notifications;
    ViewDispatcher* view_dispatcher;
    SceneManager* scene_manager;
    
    Submenu* submenu;        // NOUVEAU
    Widget* widget;          // NOUVEAU (en plus de celui d'erreur)
    
    U2fMode mode;            // NOUVEAU - Mode actuel
    
    // GARDÉ - Champs originaux de U2F
    U2fView* u2f_view;       // Vue U2F principale
    U2fData* u2f_instance;   // Instance U2F
    U2fHid* u2f_hid;         // HID U2F
    FuriTimer* timer;        // Timer U2F
    U2fCustomEvent event_cur;// Event courant
    bool u2f_ready;          // U2F prêt
    
    U2fAppError error;       // Erreur
};

extern const SceneManagerHandlers u2f_scene_handlers;
