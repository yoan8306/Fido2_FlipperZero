#pragma once

#include "u2f.h"

typedef struct U2fApp U2fApp;
typedef struct U2fHid U2fHid;

U2fHid* u2f_hid_start(U2fData* u2f_inst, U2fApp* app);
void u2f_hid_stop(U2fHid* u2f_hid);

// NOUVELLE FONCTION : vérifier si FIDO2 est prêt
bool u2f_hid_is_fido2_ready(U2fHid* u2f_hid);