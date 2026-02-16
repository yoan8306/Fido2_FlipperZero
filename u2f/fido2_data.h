#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Use existing U2F folder instead of creating a new one
#define FIDO2_DATA_FOLDER EXT_PATH("u2f/")
#define FIDO2_CRED_FILE   FIDO2_DATA_FOLDER "fido2_credentials.dat"
#define FIDO2_CNT_FILE    FIDO2_DATA_FOLDER "fido2_counters.dat"

/**
 * @brief Initialize FIDO2 data storage
 * 
 * @return true if successful
 */
bool fido2_data_init(void);

/**
 * @brief Save credentials to persistent storage
 * 
 * @param credentials Credential store
 * @return true if successful
 */
bool fido2_data_save_credentials(void* credentials);

/**
 * @brief Load credentials from persistent storage
 * 
 * @param credentials Credential store to fill
 * @return true if successful
 */
bool fido2_data_load_credentials(void* credentials);

/**
 * @brief Check if FIDO2 data files exist
 * 
 * @param cert_only Only check certificate files
 * @return true if files exist
 */
bool fido2_data_check(bool cert_only);

#ifdef __cplusplus
}
#endif