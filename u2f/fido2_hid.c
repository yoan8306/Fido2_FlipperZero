#include "fido2_hid.h"
#include "fido2_ctap.h"
#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_usb_hid_u2f.h>
#include <storage/storage.h>

#define TAG "FIDO2_HID"
#define WORKER_TAG TAG "Worker"

// CTAPHID protocol constants
#define CTAPHID_TYPE_MASK 0x80
#define CTAPHID_TYPE_INIT 0x80
#define CTAPHID_TYPE_CONT 0x00

// CTAPHID commands
#define CTAPHID_PING      (CTAPHID_TYPE_INIT | 0x01)
#define CTAPHID_MSG       (CTAPHID_TYPE_INIT | 0x03)
#define CTAPHID_LOCK      (CTAPHID_TYPE_INIT | 0x04)
#define CTAPHID_INIT      (CTAPHID_TYPE_INIT | 0x06)
#define CTAPHID_WINK      (CTAPHID_TYPE_INIT | 0x08)
#define CTAPHID_CBOR      (CTAPHID_TYPE_INIT | 0x10)
#define CTAPHID_ERROR     (CTAPHID_TYPE_INIT | 0x3f)

// CTAPHID error codes
#define CTAPHID_ERR_NONE          0x00
#define CTAPHID_ERR_INVALID_CMD   0x01
#define CTAPHID_ERR_INVALID_PAR   0x02
#define CTAPHID_ERR_INVALID_LEN   0x03
#define CTAPHID_ERR_INVALID_SEQ   0x04
#define CTAPHID_ERR_MSG_TIMEOUT   0x05
#define CTAPHID_ERR_CHANNEL_BUSY  0x06
#define CTAPHID_ERR_LOCK_REQUIRED 0x0a
#define CTAPHID_ERR_SYNC_FAIL     0x0b
#define CTAPHID_ERR_OTHER         0x7f

#define CTAPHID_BROADCAST_CID 0xFFFFFFFF
#define HID_PACKET_LEN        64
#define CTAPHID_MAX_PAYLOAD_LEN  ((HID_PACKET_LEN - 7) + 128 * (HID_PACKET_LEN - 5))

typedef enum {
    WorkerEvtReserved = (1 << 0),
    WorkerEvtStop = (1 << 1),
    WorkerEvtConnect = (1 << 2),
    WorkerEvtDisconnect = (1 << 3),
    WorkerEvtRequest = (1 << 4),
    WorkerEvtUnlock = (1 << 5),
} WorkerEvtFlags;

typedef struct {
    uint32_t cid;
    uint16_t len;
    uint8_t cmd;
    uint8_t payload[CTAPHID_MAX_PAYLOAD_LEN];
} Fido2HidPacket;

struct Fido2Hid {
    FuriThread* thread;
    FuriTimer* lock_timer;
    uint8_t seq_id_last;
    uint16_t req_buf_ptr;
    uint32_t req_len_left;
    uint32_t lock_cid;
    bool lock;
    Fido2Ctap* ctap;
    Fido2HidPacket packet;
    Fido2HidConnectionCallback connection_callback;
    void* connection_context;
};

/**
 * @brief Write debug message to SD card
 */
static void debug_log(const char* msg) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    
    if(storage_file_open(file, EXT_PATH("fido2_debug.txt"), FSAM_WRITE, FSOM_OPEN_APPEND)) {
        storage_file_write(file, msg, strlen(msg));
        storage_file_write(file, "\r\n", 2);
        storage_file_close(file);
    }
    
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/**
 * @brief HID event callback from USB stack
 */
static void fido2_hid_event_callback(HidU2fEvent ev, void* context) {
    furi_assert(context);
    Fido2Hid* fido2_hid = context;

    FURI_LOG_I(TAG, "HID EVENT: %d", ev);
    
    if(ev == HidU2fDisconnected) {
        FURI_LOG_I(TAG, "HID event: Disconnected");
        debug_log("HID EVENT: Disconnected");
        furi_thread_flags_set(furi_thread_get_id(fido2_hid->thread), WorkerEvtDisconnect);
    } else if(ev == HidU2fConnected) {
        FURI_LOG_I(TAG, "HID event: Connected");
        debug_log("HID EVENT: Connected");
        furi_thread_flags_set(furi_thread_get_id(fido2_hid->thread), WorkerEvtConnect);
    } else if(ev == HidU2fRequest) {
        FURI_LOG_I(TAG, "HID event: Request");
        debug_log("HID EVENT: Request");
        furi_thread_flags_set(furi_thread_get_id(fido2_hid->thread), WorkerEvtRequest);
    }
}

/**
 * @brief Lock timeout callback
 */
static void fido2_hid_lock_timeout_callback(void* context) {
    furi_assert(context);
    Fido2Hid* fido2_hid = context;
    FURI_LOG_D(TAG, "Lock timeout");
    furi_thread_flags_set(furi_thread_get_id(fido2_hid->thread), WorkerEvtUnlock);
}

/**
 * @brief Send response packet via HID
 */
static void fido2_hid_send_response(Fido2Hid* fido2_hid) {
    uint8_t packet_buf[HID_PACKET_LEN];
    uint16_t len_remain = fido2_hid->packet.len;
    uint8_t len_cur = 0;
    uint8_t seq_cnt = 0;
    uint16_t data_ptr = 0;

    memset(packet_buf, 0, HID_PACKET_LEN);
    memcpy(packet_buf, &(fido2_hid->packet.cid), sizeof(uint32_t));

    // Init packet
    packet_buf[4] = fido2_hid->packet.cmd;
    packet_buf[5] = fido2_hid->packet.len >> 8;
    packet_buf[6] = (fido2_hid->packet.len & 0xFF);
    len_cur = (len_remain < (HID_PACKET_LEN - 7)) ? (len_remain) : (HID_PACKET_LEN - 7);
    if(len_cur > 0) memcpy(&packet_buf[7], fido2_hid->packet.payload, len_cur);
    furi_hal_hid_u2f_send_response(packet_buf, HID_PACKET_LEN);
    data_ptr = len_cur;
    len_remain -= len_cur;

    // Continuation packets
    while(len_remain > 0) {
        memset(&packet_buf[4], 0, HID_PACKET_LEN - 4);
        packet_buf[4] = seq_cnt;
        len_cur = (len_remain < (HID_PACKET_LEN - 5)) ? (len_remain) : (HID_PACKET_LEN - 5);
        memcpy(&packet_buf[5], &(fido2_hid->packet.payload[data_ptr]), len_cur);
        furi_hal_hid_u2f_send_response(packet_buf, HID_PACKET_LEN);
        seq_cnt++;
        len_remain -= len_cur;
        data_ptr += len_cur;
    }
}

/**
 * @brief Send error response
 */
static void fido2_hid_send_error(Fido2Hid* fido2_hid, uint8_t error) {
    FURI_LOG_W(TAG, "Sending error: %02x", error);
    debug_log("Sending error");
    fido2_hid->packet.len = 1;
    fido2_hid->packet.cmd = CTAPHID_ERROR;
    fido2_hid->packet.payload[0] = error;
    fido2_hid_send_response(fido2_hid);
}

/**
 * @brief Parse and handle HID request
 */
static bool fido2_hid_parse_request(Fido2Hid* fido2_hid) {
    FURI_LOG_I(
        WORKER_TAG,
        "Req cid=%08lX cmd=%02x len=%u",
        fido2_hid->packet.cid,
        fido2_hid->packet.cmd,
        fido2_hid->packet.len);

    // Check lock
    if((fido2_hid->lock == true) && (fido2_hid->packet.cid != fido2_hid->lock_cid)) {
        FURI_LOG_W(TAG, "Lock check failed");
        return false;
    }

    switch(fido2_hid->packet.cmd) {
    case CTAPHID_PING: {
        FURI_LOG_I(TAG, "CTAPHID_PING received");
        fido2_hid_send_response(fido2_hid);
        break;
    }

    case CTAPHID_MSG:
    case CTAPHID_CBOR: {
        FURI_LOG_I(TAG, "CTAPHID_CBOR received");
        debug_log("CTAPHID_CBOR received");
        
        size_t resp_len = fido2_ctap_process(
            fido2_hid->ctap,
            fido2_hid->packet.payload,
            fido2_hid->packet.len,
            fido2_hid->packet.payload,
            sizeof(fido2_hid->packet.payload));

        if(resp_len > 0) {
            FURI_LOG_I(TAG, "CTAP2 response length: %u", resp_len);
            fido2_hid->packet.len = resp_len;
            fido2_hid->packet.cmd = CTAPHID_CBOR;
            fido2_hid_send_response(fido2_hid);
        } else {
            FURI_LOG_E(TAG, "CTAP2 process returned 0");
            fido2_hid_send_error(fido2_hid, CTAPHID_ERR_INVALID_CMD);
        }
        break;
    }

    case CTAPHID_LOCK: {
        FURI_LOG_I(TAG, "CTAPHID_LOCK received");
        if(fido2_hid->packet.len != 1) {
            fido2_hid_send_error(fido2_hid, CTAPHID_ERR_INVALID_LEN);
            break;
        }
        uint8_t lock_timeout = fido2_hid->packet.payload[0];
        if(lock_timeout == 0) {
            fido2_hid->lock = false;
            fido2_hid->lock_cid = 0;
            FURI_LOG_I(TAG, "Lock disabled");
        } else {
            fido2_hid->lock = true;
            fido2_hid->lock_cid = fido2_hid->packet.cid;
            furi_timer_start(fido2_hid->lock_timer, lock_timeout * 1000);
            FURI_LOG_I(TAG, "Lock enabled for CID %08lX, timeout %us", 
                       fido2_hid->lock_cid, lock_timeout);
        }
        fido2_hid->packet.len = 0;
        fido2_hid_send_response(fido2_hid);
        break;
    }

    case CTAPHID_INIT: {
        FURI_LOG_I(TAG, "========== CTAPHID INIT RECEIVED ==========");
        debug_log("CTAPHID INIT RECEIVED");
        
        if((fido2_hid->packet.len != 8) || (fido2_hid->packet.cid != CTAPHID_BROADCAST_CID) ||
           (fido2_hid->lock == true)) {
            FURI_LOG_E(TAG, "INIT validation failed");
            fido2_hid_send_error(fido2_hid, CTAPHID_ERR_INVALID_PAR);
            break;
        }

        // Generate new channel ID
        uint32_t random_cid = furi_hal_random_get();
        FURI_LOG_I(TAG, "Generated new CID: %08lX", random_cid);

        fido2_hid->packet.len = 17;
        memcpy(&(fido2_hid->packet.payload[8]), &random_cid, sizeof(uint32_t));
        fido2_hid->packet.payload[12] = 2;  // Protocol version (CTAP2)
        fido2_hid->packet.payload[13] = 1;  // Major version
        fido2_hid->packet.payload[14] = 0;  // Minor version
        fido2_hid->packet.payload[15] = 1;  // Build version
        fido2_hid->packet.payload[16] = 2;  // Capabilities: wink + CBOR
        
        fido2_hid_send_response(fido2_hid);
        break;
    }

    case CTAPHID_WINK: {
        FURI_LOG_I(TAG, "CTAPHID_WINK received");
        fido2_hid->packet.len = 0;
        fido2_hid_send_response(fido2_hid);
        break;
    }

    default:
        FURI_LOG_W(WORKER_TAG, "Unknown command: 0x%02x", fido2_hid->packet.cmd);
        fido2_hid_send_error(fido2_hid, CTAPHID_ERR_INVALID_CMD);
        return false;
    }

    return true;
}

/**
 * @brief HID worker thread
 */
static int32_t fido2_hid_worker(void* context) {
    Fido2Hid* fido2_hid = context;
    uint8_t packet_buf[HID_PACKET_LEN];

    FURI_LOG_I(WORKER_TAG, "========== FIDO2 HID Worker Started ==========");
    debug_log("FIDO2 HID Worker Started");

    // Save current USB config
    FuriHalUsbInterface* usb_mode_prev = furi_hal_usb_get_config();
    FURI_LOG_I(TAG, "Current USB mode: %p", usb_mode_prev);
    FURI_LOG_I(TAG, "Switching USB to HID U2F mode");
    debug_log("Switching USB to HID U2F");
    
    bool usb_ok = furi_hal_usb_set_config(&usb_hid_u2f, NULL);
    if(usb_ok) {
        FURI_LOG_I(TAG, "USB switch SUCCESS - New mode: HID U2F (VID=0x0483, PID=0x5740)");
        debug_log("USB switch SUCCESS");
    } else {
        FURI_LOG_E(TAG, "USB switch FAILED!");
        debug_log("USB switch FAILED");
    }

    fido2_hid->lock_timer = furi_timer_alloc(
        fido2_hid_lock_timeout_callback, FuriTimerTypeOnce, fido2_hid);

    furi_hal_hid_u2f_set_callback(fido2_hid_event_callback, fido2_hid);

    // Check initial connection state
    bool connected = furi_hal_hid_u2f_is_connected();
    FURI_LOG_I(TAG, "Initial connection state: %s", connected ? "CONNECTED" : "DISCONNECTED");
    debug_log(connected ? "Initial state: CONNECTED" : "Initial state: DISCONNECTED");
    
    if(connected && fido2_hid->connection_callback) {
        fido2_hid->connection_callback(fido2_hid->connection_context, true);
    }

    while(1) {
        FURI_LOG_D(TAG, "Worker waiting for events...");
        
        uint32_t flags = furi_thread_flags_wait(
            WorkerEvtStop | WorkerEvtConnect | WorkerEvtDisconnect | WorkerEvtRequest,
            FuriFlagWaitAny,
            FuriWaitForever);

        if(flags & FuriFlagError) {
            FURI_LOG_E(TAG, "Thread flags error: %lu", flags);
            break;
        }

        FURI_LOG_I(TAG, "Events received: flags=%lu", flags);

        if(flags & WorkerEvtStop) {
            FURI_LOG_I(TAG, "Stop event received");
            debug_log("Stop event received");
            break;
        }

        if(flags & WorkerEvtConnect) {
            FURI_LOG_I(TAG, "!!! DEVICE CONNECTED !!!");
            debug_log("DEVICE CONNECTED");
            if(fido2_hid->connection_callback) {
                fido2_hid->connection_callback(fido2_hid->connection_context, true);
            }
        }

        if(flags & WorkerEvtDisconnect) {
            FURI_LOG_I(TAG, "!!! DEVICE DISCONNECTED !!!");
            debug_log("DEVICE DISCONNECTED");
            if(fido2_hid->connection_callback) {
                fido2_hid->connection_callback(fido2_hid->connection_context, false);
            }
        }

        if(flags & WorkerEvtRequest) {
            FURI_LOG_I(TAG, "Request event received");
            uint32_t len_cur = furi_hal_hid_u2f_get_request(packet_buf);

            if(len_cur == 0) {
                FURI_LOG_W(TAG, "Empty request received");
                continue;
            }

            FURI_LOG_I(TAG, "Received packet length: %lu", len_cur);

            if((packet_buf[4] & CTAPHID_TYPE_MASK) == CTAPHID_TYPE_INIT) {
                // Init packet
                if(len_cur < 7) {
                    FURI_LOG_W(TAG, "Init packet too short");
                    fido2_hid->req_len_left = 0;
                    continue;
                }

                fido2_hid->packet.len = (packet_buf[5] << 8) | packet_buf[6];
                FURI_LOG_I(TAG, "Init packet, total length: %u", fido2_hid->packet.len);
                
                if(fido2_hid->packet.len > CTAPHID_MAX_PAYLOAD_LEN) {
                    FURI_LOG_W(TAG, "Packet length too large: %u", fido2_hid->packet.len);
                    fido2_hid->req_len_left = 0;
                    continue;
                }

                memcpy(&(fido2_hid->packet.cid), packet_buf, 4);
                fido2_hid->packet.cmd = packet_buf[4];
                fido2_hid->seq_id_last = 0;

                size_t data_len = (len_cur > 7) ? len_cur - 7 : 0;
                FURI_LOG_I(TAG, "Init packet data length: %u", data_len);
                
                if(fido2_hid->packet.len > data_len) {
                    fido2_hid->req_len_left = fido2_hid->packet.len - data_len;
                    memcpy(fido2_hid->packet.payload, &packet_buf[7], data_len);
                    fido2_hid->req_buf_ptr = data_len;
                    FURI_LOG_I(TAG, "Waiting for %lu continuation bytes", fido2_hid->req_len_left);
                } else {
                    fido2_hid->req_len_left = 0;
                    memcpy(fido2_hid->packet.payload, &packet_buf[7], fido2_hid->packet.len);
                    FURI_LOG_I(TAG, "Complete packet received");
                }
            } else {
                // Continuation packet
                if(fido2_hid->req_len_left == 0) {
                    FURI_LOG_W(TAG, "Unexpected continuation packet");
                    continue;
                }

                if(len_cur < 5) {
                    FURI_LOG_W(TAG, "Continuation packet too short");
                    continue;
                }

                uint32_t cid_temp = 0;
                memcpy(&cid_temp, packet_buf, 4);
                uint8_t seq_temp = packet_buf[4];

                if((cid_temp == fido2_hid->packet.cid) &&
                   (seq_temp == fido2_hid->seq_id_last)) {
                    size_t data_len = (len_cur > 5) ? len_cur - 5 : 0;
                    size_t copy_len = (data_len < fido2_hid->req_len_left) ?
                                      data_len : fido2_hid->req_len_left;

                    FURI_LOG_I(TAG, "Continuation seq=%u, copying %u bytes", seq_temp, copy_len);
                    
                    memcpy(
                        &(fido2_hid->packet.payload[fido2_hid->req_buf_ptr]),
                        &packet_buf[5],
                        copy_len);

                    fido2_hid->req_buf_ptr += copy_len;
                    fido2_hid->req_len_left -= copy_len;
                    fido2_hid->seq_id_last++;
                } else {
                    FURI_LOG_W(TAG, "Continuation packet mismatch");
                }
            }

            if(fido2_hid->req_len_left == 0) {
                FURI_LOG_I(TAG, "Complete request ready, parsing...");
                fido2_hid_parse_request(fido2_hid);
            }
        }

        if(flags & WorkerEvtUnlock) {
            FURI_LOG_I(TAG, "Unlock event received");
            fido2_hid->lock = false;
            fido2_hid->lock_cid = 0;
        }
    }

    FURI_LOG_I(TAG, "Stopping FIDO2 HID worker");
    debug_log("Stopping FIDO2 HID worker");
    
    furi_timer_stop(fido2_hid->lock_timer);
    furi_timer_free(fido2_hid->lock_timer);
    furi_hal_hid_u2f_set_callback(NULL, NULL);
    
    FURI_LOG_I(TAG, "Restoring previous USB mode");
    furi_hal_usb_set_config(usb_mode_prev, NULL);

    FURI_LOG_I(WORKER_TAG, "========== FIDO2 HID Worker Stopped ==========");
    debug_log("FIDO2 HID Worker Stopped");
    return 0;
}

Fido2Hid* fido2_hid_start(Fido2Ctap* ctap) {
    // LOG URGENT - write directly to SD
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, EXT_PATH("fido2_debug.txt"), FSAM_WRITE, FSOM_OPEN_APPEND)) {
        const char* msg = "*** fido2_hid_start CALLED ***\r\n";
        storage_file_write(file, msg, strlen(msg));
        storage_file_close(file);
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    
    FURI_LOG_I(TAG, "========== FIDO2 HID START ==========");
    debug_log("FIDO2 HID START");
    
    Fido2Hid* fido2_hid = malloc(sizeof(Fido2Hid));
    if(!fido2_hid) {
        FURI_LOG_E(TAG, "Failed to allocate Fido2Hid");
        debug_log("Allocation FAILED");
        return NULL;
    }
    
    memset(fido2_hid, 0, sizeof(Fido2Hid));

    fido2_hid->ctap = ctap;
    fido2_hid->connection_callback = NULL;
    fido2_hid->connection_context = NULL;

    fido2_hid->thread = furi_thread_alloc_ex(
        "Fido2HidWorker", 2048, fido2_hid_worker, fido2_hid);
    
    if(!fido2_hid->thread) {
        FURI_LOG_E(TAG, "Failed to allocate thread");
        debug_log("Thread allocation FAILED");
        free(fido2_hid);
        return NULL;
    }
    
    furi_thread_start(fido2_hid->thread);

    FURI_LOG_I(TAG, "FIDO2 HID started successfully");
    debug_log("FIDO2 HID started successfully");
    return fido2_hid;
}

void fido2_hid_stop(Fido2Hid* fido2_hid) {
    furi_assert(fido2_hid);
    FURI_LOG_I(TAG, "fido2_hid_stop called");
    debug_log("FIDO2 HID stop called");

    if(fido2_hid->thread) {
        furi_thread_flags_set(furi_thread_get_id(fido2_hid->thread), WorkerEvtStop);
        furi_thread_join(fido2_hid->thread);
        furi_thread_free(fido2_hid->thread);
    }

    free(fido2_hid);
    FURI_LOG_I(TAG, "FIDO2 HID stopped");
    debug_log("FIDO2 HID stopped");
}

void fido2_hid_set_connection_callback(
    Fido2Hid* fido2_hid,
    Fido2HidConnectionCallback callback,
    void* context) {
    furi_assert(fido2_hid);
    fido2_hid->connection_callback = callback;
    fido2_hid->connection_context = context;
    FURI_LOG_I(TAG, "Connection callback registered");
    debug_log("Connection callback registered");
}