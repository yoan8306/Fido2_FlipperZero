#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <furi.h>
#include "fido2_ctap.h"

typedef struct Fido2Hid Fido2Hid;

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

#ifdef __cplusplus
}
#endif