#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FidoModeU2F = 0,    // FIDO1 (CTAP1)
    FidoModeFIDO2,      // FIDO2 (CTAP2)
    FidoModeNone,       // No mode selected
} FidoMode;

typedef enum {
    FidoCustomEventSelectU2F = 100,  // Événements personnalisés
    FidoCustomEventSelectFIDO2,
    FidoCustomEventModeSelected,
    FidoCustomEventExit,
} FidoCustomEvent;

#ifdef __cplusplus
}
#endif