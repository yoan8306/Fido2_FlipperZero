#include <furi.h>
#include "u2f_hid.h"
#include "u2f.h"
#include "u2f_app_i.h"
#include "fido2/fido2_ctap.h"
#include "fido2/fido2_credential.h"
#include <furi_hal.h>
#include <gui/gui.h>
#include <input/input.h>
#include <lib/toolbox/args.h>
#include <furi_hal_usb_hid_u2f.h>
#include <storage/storage.h>

#undef TAG
#define TAG "U2fHid"

#define WORKER_TAG TAG "Worker"

#define U2F_HID_MAX_PAYLOAD_LEN ((HID_U2F_PACKET_LEN - 7) + 128 * (HID_U2F_PACKET_LEN - 5))

#define U2F_HID_TYPE_MASK 0x80
#define U2F_HID_TYPE_INIT 0x80
#define U2F_HID_TYPE_CONT 0x00

#define U2F_HID_PING  (U2F_HID_TYPE_INIT | 0x01)
#define U2F_HID_MSG   (U2F_HID_TYPE_INIT | 0x03)
#define U2F_HID_LOCK  (U2F_HID_TYPE_INIT | 0x04)
#define U2F_HID_INIT  (U2F_HID_TYPE_INIT | 0x06)
#define U2F_HID_WINK  (U2F_HID_TYPE_INIT | 0x08)
#define U2F_HID_ERROR (U2F_HID_TYPE_INIT | 0x3f)
#define U2F_HID_CBOR  (U2F_HID_TYPE_INIT | 0x10)

#define U2F_HID_ERR_NONE          0x00
#define U2F_HID_ERR_INVALID_CMD   0x01
#define U2F_HID_ERR_INVALID_PAR   0x02
#define U2F_HID_ERR_INVALID_LEN   0x03
#define U2F_HID_ERR_INVALID_SEQ   0x04
#define U2F_HID_ERR_MSG_TIMEOUT   0x05
#define U2F_HID_ERR_CHANNEL_BUSY  0x06
#define U2F_HID_ERR_LOCK_REQUIRED 0x0a
#define U2F_HID_ERR_SYNC_FAIL     0x0b
#define U2F_HID_ERR_OTHER         0x7f

#define U2F_HID_BROADCAST_CID 0xFFFFFFFF

typedef enum {
    WorkerEvtReserved = (1 << 0),
    WorkerEvtStop = (1 << 1),
    WorkerEvtConnect = (1 << 2),
    WorkerEvtDisconnect = (1 << 3),
    WorkerEvtRequest = (1 << 4),
    WorkerEvtUnlock = (1 << 5),
} WorkerEvtFlags;

struct U2fHid_packet {
    uint32_t cid;
    uint16_t len;
    uint8_t cmd;
    uint8_t payload[U2F_HID_MAX_PAYLOAD_LEN];
};

struct U2fHid {
    FuriThread* thread;
    FuriTimer* lock_timer;
    uint8_t seq_id_last;
    uint16_t req_buf_ptr;
    uint32_t req_len_left;
    uint32_t lock_cid;
    bool lock;
    U2fData* u2f_instance;
    struct U2fHid_packet packet;
    
    // FIDO2 support
    U2fApp* app;
    Fido2Ctap* fido2_ctap;
    Fido2CredentialStore* fido2_store;
};

// Forward declarations
static void u2f_hid_event_callback(HidU2fEvent ev, void* context);
static void u2f_hid_lock_timeout_callback(void* context);
static void u2f_hid_send_response(U2fHid* u2f_hid);
static void u2f_hid_send_error(U2fHid* u2f_hid, uint8_t error);
static bool u2f_hid_parse_fido2(U2fHid* u2f_hid);
static bool u2f_hid_parse_request(U2fHid* u2f_hid);
static int32_t u2f_hid_worker(void* context);

/**
 * @brief HID event callback from USB stack
 */
static void u2f_hid_event_callback(HidU2fEvent ev, void* context) {
    furi_assert(context);
    U2fHid* u2f_hid = context;

    if(ev == HidU2fDisconnected)
        furi_thread_flags_set(furi_thread_get_id(u2f_hid->thread), WorkerEvtDisconnect);
    else if(ev == HidU2fConnected)
        furi_thread_flags_set(furi_thread_get_id(u2f_hid->thread), WorkerEvtConnect);
    else if(ev == HidU2fRequest)
        furi_thread_flags_set(furi_thread_get_id(u2f_hid->thread), WorkerEvtRequest);
}

/**
 * @brief Lock timeout callback
 */
static void u2f_hid_lock_timeout_callback(void* context) {
    furi_assert(context);
    U2fHid* u2f_hid = context;
    furi_thread_flags_set(furi_thread_get_id(u2f_hid->thread), WorkerEvtUnlock);
}

/**
 * @brief Send HID response packet
 */
static void u2f_hid_send_response(U2fHid* u2f_hid) {
    uint8_t packet_buf[HID_U2F_PACKET_LEN];
    uint16_t len_remain = u2f_hid->packet.len;
    uint8_t len_cur = 0;
    uint8_t seq_cnt = 0;
    uint16_t data_ptr = 0;

    memset(packet_buf, 0, HID_U2F_PACKET_LEN);
    memcpy(packet_buf, &(u2f_hid->packet.cid), sizeof(uint32_t));

    // Init packet
    packet_buf[4] = u2f_hid->packet.cmd;
    packet_buf[5] = u2f_hid->packet.len >> 8;
    packet_buf[6] = (u2f_hid->packet.len & 0xFF);
    len_cur = (len_remain < (HID_U2F_PACKET_LEN - 7)) ? (len_remain) : (HID_U2F_PACKET_LEN - 7);
    if(len_cur > 0) memcpy(&packet_buf[7], u2f_hid->packet.payload, len_cur);
    furi_hal_hid_u2f_send_response(packet_buf, HID_U2F_PACKET_LEN);
    data_ptr = len_cur;
    len_remain -= len_cur;

    // Continuation packets
    while(len_remain > 0) {
        memset(&packet_buf[4], 0, HID_U2F_PACKET_LEN - 4);
        packet_buf[4] = seq_cnt;
        len_cur = (len_remain < (HID_U2F_PACKET_LEN - 5)) ? (len_remain) : (HID_U2F_PACKET_LEN - 5);
        memcpy(&packet_buf[5], &(u2f_hid->packet.payload[data_ptr]), len_cur);
        furi_hal_hid_u2f_send_response(packet_buf, HID_U2F_PACKET_LEN);
        seq_cnt++;
        len_remain -= len_cur;
        data_ptr += len_cur;
    }
}

/**
 * @brief Send HID error response
 */
static void u2f_hid_send_error(U2fHid* u2f_hid, uint8_t error) {
    u2f_hid->packet.len = 1;
    u2f_hid->packet.cmd = U2F_HID_ERROR;
    u2f_hid->packet.payload[0] = error;
    u2f_hid_send_response(u2f_hid);
}

/**
 * @brief Parse FIDO2/CTAP2 commands
 */
static bool u2f_hid_parse_fido2(U2fHid* u2f_hid) {
    FURI_LOG_I(TAG, "=== u2f_hid_parse_fido2 ===");
    FURI_LOG_I(TAG, "cmd=0x%02x, len=%u", u2f_hid->packet.cmd, u2f_hid->packet.len);

    if(u2f_hid->packet.cmd == U2F_HID_CBOR) {
        FURI_LOG_I(TAG, "FIDO2 CBOR command received, len=%u", u2f_hid->packet.len);
        
        if(u2f_hid->packet.len > 0) {
            FURI_LOG_I(TAG, "CBOR first byte: 0x%02x", u2f_hid->packet.payload[0]);
            FURI_LOG_I(TAG, "CTAP2 command: 0x%02x", u2f_hid->packet.payload[0]);
        }
        
        // Check if fido2_ctap is initialized
        if(!u2f_hid->fido2_ctap) {
            FURI_LOG_E(TAG, "fido2_ctap is NULL!");
            u2f_hid_send_error(u2f_hid, U2F_HID_ERR_INVALID_CMD);
            return false;
        }
        
        uint8_t response[1024];
        size_t response_len = fido2_ctap_process(
            u2f_hid->fido2_ctap,
            u2f_hid->packet.payload,
            u2f_hid->packet.len,
            response,
            sizeof(response));
        
        if(response_len > 0) {
            FURI_LOG_I(TAG, "FIDO2 response generated, len=%u", response_len);
            FURI_LOG_I(TAG, "Response first byte: 0x%02x", response[0]);
            
            u2f_hid->packet.len = response_len;
            memcpy(u2f_hid->packet.payload, response, response_len);
            u2f_hid_send_response(u2f_hid);
            return true;
        } else {
            FURI_LOG_E(TAG, "FIDO2 processing failed (0 length response)");
            u2f_hid_send_error(u2f_hid, U2F_HID_ERR_INVALID_CMD);
            return false;
        }
    }
    
    FURI_LOG_W(TAG, "FIDO2 ignoring non-CBOR command: 0x%02x", u2f_hid->packet.cmd);
    return false;
}

/**
 * @brief Parse incoming HID request
 */
static bool u2f_hid_parse_request(U2fHid* u2f_hid) {
    FURI_LOG_D(
        WORKER_TAG,
        "Req cid=%lX cmd=%x len=%u mode=%s",
        u2f_hid->packet.cid,
        u2f_hid->packet.cmd,
        u2f_hid->packet.len,
        (u2f_hid->app && u2f_hid->app->mode == U2fModeFIDO2) ? "FIDO2" : "U2F");

    // FIDO2 MODE
    if(u2f_hid->app && u2f_hid->app->mode == U2fModeFIDO2) {
        
        FURI_LOG_I(TAG, "Processing in FIDO2 mode");
        
        // Common commands (PING, INIT, WINK)
        if(u2f_hid->packet.cmd == U2F_HID_PING) {
            FURI_LOG_I(TAG, "FIDO2 PING command");
            u2f_hid_send_response(u2f_hid);
            return true;
        }
        
        else if(u2f_hid->packet.cmd == U2F_HID_INIT) {
            FURI_LOG_I(TAG, "FIDO2 INIT request");
            
            if((u2f_hid->packet.len != 8) || (u2f_hid->packet.cid != U2F_HID_BROADCAST_CID)) {
                FURI_LOG_E(TAG, "FIDO2 INIT invalid params");
                return false;
            }
            
            u2f_hid->packet.len = 17;
            uint32_t random_cid = furi_hal_random_get();
            memcpy(&(u2f_hid->packet.payload[8]), &random_cid, sizeof(uint32_t));
            u2f_hid->packet.payload[12] = 2;           // Protocol version
            u2f_hid->packet.payload[13] = 2;           // Device version major (FIDO2)
            u2f_hid->packet.payload[14] = 0;           // Device version minor
            u2f_hid->packet.payload[15] = 1;           // Device build version
            u2f_hid->packet.payload[16] = 0x05;        // Capabilities: wink (0x01) + CBOR (0x04) = 0x05
            u2f_hid_send_response(u2f_hid);
            return true;
        }
        
        else if(u2f_hid->packet.cmd == U2F_HID_WINK) {
            FURI_LOG_I(TAG, "FIDO2 WINK command");
            if(u2f_hid->packet.len != 0) return false;
            u2f_wink(u2f_hid->u2f_instance);
            u2f_hid->packet.len = 0;
            u2f_hid_send_response(u2f_hid);
            return true;
        }
        
        // FIDO2 specific commands
        else if(u2f_hid->packet.cmd == U2F_HID_CBOR) {
            FURI_LOG_I(TAG, "FIDO2 CBOR command received");
            
            if(u2f_hid->fido2_ctap) {
                return u2f_hid_parse_fido2(u2f_hid);
            } else {
                FURI_LOG_E(TAG, "FIDO2 CBOR command but CTAP not initialized");
                u2f_hid_send_error(u2f_hid, U2F_HID_ERR_INVALID_CMD);
                return false;
            }
        }
        
        else if(u2f_hid->packet.cmd == U2F_HID_MSG) {
            FURI_LOG_I(TAG, "FIDO2 MSG command received");
            
            if(u2f_hid->packet.len > 0) {
                if(u2f_hid->packet.payload[0] == 0x00) {
                    FURI_LOG_D(TAG, "FIDO2 mode: routing to U2F legacy handler");
                    goto u2f_processing;
                } else {
                    FURI_LOG_D(TAG, "FIDO2 mode: treating MSG as CTAP2 command, cmd=0x%02x", 
                               u2f_hid->packet.payload[0]);
                    
                    if(u2f_hid->fido2_ctap) {
                        uint8_t ctap_cmd = u2f_hid->packet.payload[0];
                        UNUSED(ctap_cmd);
                        
                        u2f_hid->packet.cmd = U2F_HID_CBOR;
                        u2f_hid->packet.len--;
                        memmove(u2f_hid->packet.payload, 
                                u2f_hid->packet.payload + 1, 
                                u2f_hid->packet.len);
                        return u2f_hid_parse_fido2(u2f_hid);
                    }
                }
            }
        }
        
        else if(u2f_hid->packet.cmd == U2F_HID_LOCK) {
            FURI_LOG_I(TAG, "FIDO2 LOCK command");
            if(u2f_hid->packet.len != 1) return false;
            uint8_t lock_timeout = u2f_hid->packet.payload[0];
            if(lock_timeout == 0) {
                u2f_hid->lock = false;
                u2f_hid->lock_cid = 0;
            } else {
                u2f_hid->lock = true;
                u2f_hid->lock_cid = u2f_hid->packet.cid;
                furi_timer_start(u2f_hid->lock_timer, lock_timeout * 1000);
            }
            u2f_hid_send_response(u2f_hid);
            return true;
        }
        
        else {
            FURI_LOG_W(TAG, "Unknown FIDO2 command: 0x%02x", u2f_hid->packet.cmd);
            u2f_hid_send_error(u2f_hid, U2F_HID_ERR_INVALID_CMD);
            return false;
        }
    }

    // U2F CLASSIC MODE
u2f_processing:
    
    FURI_LOG_I(TAG, "Processing in U2F mode");
    
    if(u2f_hid->packet.cmd == U2F_HID_PING) {
        u2f_hid_send_response(u2f_hid);
    }
    
    else if(u2f_hid->packet.cmd == U2F_HID_MSG) {
        if((u2f_hid->lock == true) && (u2f_hid->packet.cid != u2f_hid->lock_cid)) {
            return false;
        }
        
        uint16_t resp_len = u2f_msg_parse(
            u2f_hid->u2f_instance, 
            u2f_hid->packet.payload, 
            u2f_hid->packet.len);
            
        if(resp_len > 0) {
            u2f_hid->packet.len = resp_len;
            u2f_hid_send_response(u2f_hid);
        } else {
            return false;
        }
    }
    
    else if(u2f_hid->packet.cmd == U2F_HID_LOCK) {
        if(u2f_hid->packet.len != 1) return false;
        
        uint8_t lock_timeout = u2f_hid->packet.payload[0];
        if(lock_timeout == 0) {
            u2f_hid->lock = false;
            u2f_hid->lock_cid = 0;
        } else {
            u2f_hid->lock = true;
            u2f_hid->lock_cid = u2f_hid->packet.cid;
            furi_timer_start(u2f_hid->lock_timer, lock_timeout * 1000);
        }
        u2f_hid_send_response(u2f_hid);
    }
    
    else if(u2f_hid->packet.cmd == U2F_HID_INIT) {
        if((u2f_hid->packet.len != 8) || 
           (u2f_hid->packet.cid != U2F_HID_BROADCAST_CID) ||
           (u2f_hid->lock == true)) {
            return false;
        }
        
        u2f_hid->packet.len = 17;
        uint32_t random_cid = furi_hal_random_get();
        memcpy(&(u2f_hid->packet.payload[8]), &random_cid, sizeof(uint32_t));
        u2f_hid->packet.payload[12] = 2;           // Protocol version
        u2f_hid->packet.payload[13] = 1;           // Device version major (U2F)
        u2f_hid->packet.payload[14] = 0;           // Device version minor
        u2f_hid->packet.payload[15] = 1;           // Device build version
        u2f_hid->packet.payload[16] = 1;           // Capabilities: wink only
        u2f_hid_send_response(u2f_hid);
    }
    
    else if(u2f_hid->packet.cmd == U2F_HID_WINK) {
        if(u2f_hid->packet.len != 0) return false;
        u2f_wink(u2f_hid->u2f_instance);
        u2f_hid->packet.len = 0;
        u2f_hid_send_response(u2f_hid);
    }
    
    else {
        FURI_LOG_W(TAG, "Unknown U2F command: 0x%02x", u2f_hid->packet.cmd);
        u2f_hid_send_error(u2f_hid, U2F_HID_ERR_INVALID_CMD);
        return false;
    }
    
    return true;
}

/**
 * @brief HID worker thread
 */
static int32_t u2f_hid_worker(void* context) {
    U2fHid* u2f_hid = context;
    uint8_t packet_buf[HID_U2F_PACKET_LEN];

    FURI_LOG_I(WORKER_TAG, "HID Worker starting");

    u2f_hid->lock_timer =
        furi_timer_alloc(u2f_hid_lock_timeout_callback, FuriTimerTypeOnce, u2f_hid);

    furi_hal_hid_u2f_set_callback(u2f_hid_event_callback, u2f_hid);
    
    FURI_LOG_I(WORKER_TAG, "HID Worker initialized, waiting for events");

    while(1) {
        uint32_t flags = furi_thread_flags_wait(
            WorkerEvtStop | WorkerEvtConnect | WorkerEvtDisconnect | WorkerEvtRequest,
            FuriFlagWaitAny,
            FuriWaitForever);
            
        if(flags & FuriFlagError) {
            FURI_LOG_E(WORKER_TAG, "Flag error: %lu", flags);
            continue;
        }
        
        if(flags & WorkerEvtStop) {
            FURI_LOG_I(WORKER_TAG, "Stop event received");
            break;
        }
        
        if(flags & WorkerEvtConnect) {
            FURI_LOG_I(WORKER_TAG, "USB Connected");
            u2f_set_state(u2f_hid->u2f_instance, 1);
        }
        
        if(flags & WorkerEvtDisconnect) {
            FURI_LOG_I(WORKER_TAG, "USB Disconnected");
            u2f_set_state(u2f_hid->u2f_instance, 0);
        }
        
        if(flags & WorkerEvtRequest) {
            uint32_t len_cur = furi_hal_hid_u2f_get_request(packet_buf);
            
            if(len_cur == 0) {
                continue;
            }
            
            FURI_LOG_D(WORKER_TAG, "USB Request received, len=%lu", len_cur);
            
            if((packet_buf[4] & U2F_HID_TYPE_MASK) == U2F_HID_TYPE_INIT) {
                if(len_cur < 7) {
                    u2f_hid->req_len_left = 0;
                    continue;
                }
                
                u2f_hid->packet.len = (packet_buf[5] << 8) | (packet_buf[6]);
                
                if(u2f_hid->packet.len > U2F_HID_MAX_PAYLOAD_LEN) {
                    u2f_hid->req_len_left = 0;
                    continue;
                }
                
                if(u2f_hid->packet.len > (len_cur - 7)) {
                    u2f_hid->req_len_left = u2f_hid->packet.len - (len_cur - 7);
                    len_cur = len_cur - 7;
                } else {
                    u2f_hid->req_len_left = 0;
                    len_cur = u2f_hid->packet.len;
                }
                
                memcpy(&(u2f_hid->packet.cid), packet_buf, 4);
                u2f_hid->packet.cmd = packet_buf[4];
                u2f_hid->seq_id_last = 0;
                u2f_hid->req_buf_ptr = len_cur;
                
                if(len_cur > 0) {
                    memcpy(u2f_hid->packet.payload, &packet_buf[7], len_cur);
                }
            } else {
                if(len_cur < 5) {
                    u2f_hid->req_len_left = 0;
                    continue;
                }
                
                if(u2f_hid->req_len_left > 0) {
                    uint32_t cid_temp = 0;
                    memcpy(&cid_temp, packet_buf, 4);
                    uint8_t seq_temp = packet_buf[4];
                    
                    if((cid_temp == u2f_hid->packet.cid) && (seq_temp == u2f_hid->seq_id_last)) {
                        if(u2f_hid->req_len_left > (len_cur - 5)) {
                            len_cur = len_cur - 5;
                            u2f_hid->req_len_left -= len_cur;
                        } else {
                            len_cur = u2f_hid->req_len_left;
                            u2f_hid->req_len_left = 0;
                        }
                        
                        memcpy(&(u2f_hid->packet.payload[u2f_hid->req_buf_ptr]), 
                               &packet_buf[5], len_cur);
                        u2f_hid->req_buf_ptr += len_cur;
                        u2f_hid->seq_id_last++;
                    }
                }
            }
            
            if(u2f_hid->req_len_left == 0 && u2f_hid->packet.len > 0) {
                if(u2f_hid_parse_request(u2f_hid) == false) {
                    FURI_LOG_W(WORKER_TAG, "Failed to parse request, sending error");
                    u2f_hid_send_error(u2f_hid, U2F_HID_ERR_INVALID_CMD);
                }
                u2f_hid->packet.len = 0;
            }
        }
        
        if(flags & WorkerEvtUnlock) {
            FURI_LOG_D(WORKER_TAG, "Unlock event");
            u2f_hid->lock = false;
            u2f_hid->lock_cid = 0;
        }
    }
    
    FURI_LOG_I(WORKER_TAG, "Stopping HID worker");
    furi_timer_stop(u2f_hid->lock_timer);
    furi_timer_free(u2f_hid->lock_timer);
    furi_hal_hid_u2f_set_callback(NULL, NULL);
    
    FURI_LOG_I(WORKER_TAG, "HID Worker stopped");
    return 0;
}

/**
 * @brief Start HID U2F/FIDO2 worker
 */
U2fHid* u2f_hid_start(U2fData* u2f_inst, U2fApp* app) {
    U2fHid* u2f_hid = malloc(sizeof(U2fHid));
    memset(u2f_hid, 0, sizeof(U2fHid));

    u2f_hid->u2f_instance = u2f_inst;
    u2f_hid->app = app;
    
    // Always initialize FIDO2 components
    FURI_LOG_I(TAG, "Initializing FIDO2 components");
    u2f_hid->fido2_store = fido2_credential_store_alloc();
    u2f_hid->fido2_ctap = fido2_ctap_alloc(u2f_hid->fido2_store);
    
    if(!u2f_hid->fido2_ctap) {
        FURI_LOG_E(TAG, "Failed to initialize FIDO2 ctap");
    } else {
        FURI_LOG_I(TAG, "FIDO2 ctap initialized: %p", u2f_hid->fido2_ctap);
    }
    
    if(!u2f_hid->fido2_store) {
        FURI_LOG_E(TAG, "Failed to initialize FIDO2 store");
    } else {
        FURI_LOG_I(TAG, "FIDO2 store initialized: %p", u2f_hid->fido2_store);
    }

    // Configure USB before starting worker
    FURI_LOG_I(TAG, "Configuring USB before starting worker");
    
    furi_hal_usb_set_config(NULL, NULL);
    furi_delay_ms(100);
    
    if(!furi_hal_usb_set_config(&usb_hid_u2f, NULL)) {
        FURI_LOG_E(TAG, "Failed to set USB config!");
        free(u2f_hid);
        return NULL;
    }
    
    furi_delay_ms(100);
    
    FURI_LOG_I(TAG, "USB configured successfully, starting worker thread");

    u2f_hid->thread = furi_thread_alloc_ex("U2fHidWorker", 2048, u2f_hid_worker, u2f_hid);
    furi_thread_start(u2f_hid->thread);
    return u2f_hid;
}

/**
 * @brief Stop HID worker and free resources
 */
void u2f_hid_stop(U2fHid* u2f_hid) {
    furi_assert(u2f_hid);
    
    if(u2f_hid->thread) {
        furi_thread_flags_set(furi_thread_get_id(u2f_hid->thread), WorkerEvtStop);
        furi_thread_join(u2f_hid->thread);
        furi_thread_free(u2f_hid->thread);
    }
    
    // Free FIDO2 components
    if(u2f_hid->fido2_ctap) {
        fido2_ctap_free(u2f_hid->fido2_ctap);
        u2f_hid->fido2_ctap = NULL;
    }
    if(u2f_hid->fido2_store) {
        fido2_credential_store_free(u2f_hid->fido2_store);
        u2f_hid->fido2_store = NULL;
    }
    
    free(u2f_hid);
}

/**
 * @brief Check if FIDO2 is ready
 */
bool u2f_hid_is_fido2_ready(U2fHid* u2f_hid) {
    if(!u2f_hid) return false;
    return (u2f_hid->fido2_ctap != NULL);
}