#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <furi.h>
#include "fido2_ctap.h"

typedef struct Fido2Hid Fido2Hid;

/**
 * @brief Connection state callback type
 */
typedef void (*Fido2HidConnectionCallback)(void* context, bool connected);

/**
 * @brief Start FIDO2 HID transport
 * 
 * @param ctap CTAP2 instance
 * @return Fido2Hid* New HID instance or NULL on failure
 */
Fido2Hid* fido2_hid_start(Fido2Ctap* ctap);

/**
 * @brief Stop FIDO2 HID transport
 * 
 * @param fido2_hid HID instance to stop
 */
void fido2_hid_stop(Fido2Hid* fido2_hid);

/**
 * @brief Set connection state callback
 * 
 * @param fido2_hid HID instance
 * @param callback Callback function
 * @param context Context to pass to callback
 */
void fido2_hid_set_connection_callback(
    Fido2Hid* fido2_hid,
    Fido2HidConnectionCallback callback,
    void* context);

#ifdef __cplusplus
}
#endif