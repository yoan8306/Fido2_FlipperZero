#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <furi.h>

// Structure opaque pour l'instance FIDO2
typedef struct Fido2Data Fido2Data;

// Type de callback pour les événements FIDO2
typedef enum {
    Fido2NotifyRegister,
    Fido2NotifyAuth,
    Fido2NotifyAuthSuccess,
    Fido2NotifyWink,
    Fido2NotifyConnect,
    Fido2NotifyDisconnect,
    Fido2NotifyError,
} Fido2NotifyEvent;

typedef void (*Fido2EvtCallback)(Fido2NotifyEvent evt, void* context);

// Allocation et libération
Fido2Data* fido2_alloc(void);

// Initialisation
bool fido2_init(Fido2Data* instance);

// Libération
void fido2_free(Fido2Data* instance);

// Définir le callback d'événement
void fido2_set_event_callback(Fido2Data* instance, Fido2EvtCallback callback, void* context);

// Confirmer la présence utilisateur
void fido2_confirm_user_present(Fido2Data* instance);

// Parse un message CTAP2
uint16_t fido2_msg_parse(Fido2Data* instance, uint8_t* buf, uint16_t len);

// Wink (clignotement)
void fido2_wink(Fido2Data* instance);

// Définir l'état de connexion
void fido2_set_state(Fido2Data* instance, uint8_t state);

#ifdef __cplusplus
}
#endif