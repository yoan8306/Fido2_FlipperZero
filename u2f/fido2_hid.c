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
    volatile bool running;
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

    if(!fido2_hid->running) return;

    if(ev == HidU2fDisconnected) {
        furi_thread_flags_set(furi_thread_get_id(fido2_hid->thread), WorkerEvtDisconnect);
    } else if(ev == HidU2fConnected) {
        furi_thread_flags_set(furi_thread_get_id(fido2_hid->thread), WorkerEvtConnect);
    } else if(ev == HidU2fRequest) {
        furi_thread_flags_set(furi_thread_get_id(fido2_hid->thread), WorkerEvtRequest);
    }
}

/**
 * @brief Lock timeout callback
 */
static void fido2_hid_lock_timeout_callback(void* context) {
    furi_assert(context);
    Fido2Hid* fido2_hid = context;
    if(fido2_hid->running) {
        furi_thread_flags_set(furi_thread_get_id(fido2_hid->thread), WorkerEvtUnlock);
    }
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
    while(len_remain > 0 && fido2_hid->running) {
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
    fido2_hid->packet.len = 1;
    fido2_hid->packet.cmd = CTAPHID_ERROR;
    fido2_hid->packet.payload[0] = error;
    fido2_hid_send_response(fido2_hid);
}

/**
 * @brief Parse and handle HID request
 */
static bool fido2_hid_parse_request(Fido2Hid* fido2_hid) {
    if(!fido2_hid->running) return false;

    // Check lock
    if((fido2_hid->lock == true) && (fido2_hid->packet.cid != fido2_hid->lock_cid)) {
        return false;
    }

    switch(fido2_hid->packet.cmd) {
    case CTAPHID_PING:
        fido2_hid_send_response(fido2_hid);
        break;

    case CTAPHID_MSG:
    case CTAPHID_CBOR: {
        size_t resp_len = fido2_ctap_process(
            fido2_hid->ctap,
            fido2_hid->packet.payload,
            fido2_hid->packet.len,
            fido2_hid->packet.payload,
            sizeof(fido2_hid->packet.payload));

        if(resp_len > 0 && fido2_hid->running) {
            fido2_hid->packet.len = resp_len;
            fido2_hid->packet.cmd = CTAPHID_CBOR;
            fido2_hid_send_response(fido2_hid);
        } else if(fido2_hid->running) {
            fido2_hid_send_error(fido2_hid, CTAPHID_ERR_INVALID_CMD);
        }
        break;
    }

    case CTAPHID_LOCK: {
        if(fido2_hid->packet.len != 1) {
            fido2_hid_send_error(fido2_hid, CTAPHID_ERR_INVALID_LEN);
            break;
        }
        uint8_t lock_timeout = fido2_hid->packet.payload[0];
        if(lock_timeout == 0) {
            fido2_hid->lock = false;
            fido2_hid->lock_cid = 0;
        } else {
            fido2_hid->lock = true;
            fido2_hid->lock_cid = fido2_hid->packet.cid;
            furi_timer_start(fido2_hid->lock_timer, lock_timeout * 1000);
        }
        fido2_hid->packet.len = 0;
        fido2_hid_send_response(fido2_hid);
        break;
    }

    case CTAPHID_INIT: {
        if((fido2_hid->packet.len != 8) || (fido2_hid->packet.cid != CTAPHID_BROADCAST_CID) ||
           (fido2_hid->lock == true)) {
            fido2_hid_send_error(fido2_hid, CTAPHID_ERR_INVALID_PAR);
            break;
        }

        uint32_t random_cid = furi_hal_random_get();

        fido2_hid->packet.len = 17;
        memcpy(&(fido2_hid->packet.payload[8]), &random_cid, sizeof(uint32_t));
        fido2_hid->packet.payload[12] = 2;
        fido2_hid->packet.payload[13] = 1;
        fido2_hid->packet.payload[14] = 0;
        fido2_hid->packet.payload[15] = 1;
        fido2_hid->packet.payload[16] = 2;
        
        fido2_hid_send_response(fido2_hid);
        break;
    }

    case CTAPHID_WINK:
        fido2_hid->packet.len = 0;
        fido2_hid_send_response(fido2_hid);
        break;

    default:
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

    fido2_hid->running = true;
    
    debug_log("FIDO2 HID Worker Started");

    // Save current USB config
    FuriHalUsbInterface* usb_mode_prev = furi_hal_usb_get_config();
    
    bool usb_ok = furi_hal_usb_set_config(&usb_hid_u2f, NULL);
    if(usb_ok) {
        debug_log("USB switch SUCCESS");
    } else {
        debug_log("USB switch FAILED");
    }

    fido2_hid->lock_timer = furi_timer_alloc(
        fido2_hid_lock_timeout_callback, FuriTimerTypeOnce, fido2_hid);

    furi_hal_hid_u2f_set_callback(fido2_hid_event_callback, fido2_hid);

    // Check initial connection state
    bool connected = furi_hal_hid_u2f_is_connected();
    debug_log(connected ? "Initial state: CONNECTED" : "Initial state: DISCONNECTED");
    
    if(connected && fido2_hid->connection_callback && fido2_hid->running) {
        fido2_hid->connection_callback(fido2_hid->connection_context, true);
    }

    while(fido2_hid->running) {
        uint32_t flags = furi_thread_flags_wait(
            WorkerEvtStop | WorkerEvtConnect | WorkerEvtDisconnect | WorkerEvtRequest,
            FuriFlagWaitAny,
            100); // Timeout to check running flag

        if(flags & FuriFlagError) {
            continue;
        }

        if(flags & WorkerEvtStop) {
            break;
        }

        if(!fido2_hid->running) break;

        if(flags & WorkerEvtConnect) {
            debug_log("DEVICE CONNECTED");
            if(fido2_hid->connection_callback && fido2_hid->running) {
                fido2_hid->connection_callback(fido2_hid->connection_context, true);
            }
        }

        if(flags & WorkerEvtDisconnect) {
            debug_log("DEVICE DISCONNECTED");
            if(fido2_hid->connection_callback && fido2_hid->running) {
                fido2_hid->connection_callback(fido2_hid->connection_context, false);
            }
        }

        if(flags & WorkerEvtRequest) {
            uint32_t len_cur = furi_hal_hid_u2f_get_request(packet_buf);
            if(len_cur == 0) continue;

            if((packet_buf[4] & CTAPHID_TYPE_MASK) == CTAPHID_TYPE_INIT) {
                // Init packet
                if(len_cur < 7) {
                    fido2_hid->req_len_left = 0;
                    continue;
                }

                fido2_hid->packet.len = (packet_buf[5] << 8) | packet_buf[6];
                if(fido2_hid->packet.len > CTAPHID_MAX_PAYLOAD_LEN) {
                    fido2_hid->req_len_left = 0;
                    continue;
                }

                memcpy(&(fido2_hid->packet.cid), packet_buf, 4);
                fido2_hid->packet.cmd = packet_buf[4];
                fido2_hid->seq_id_last = 0;

                size_t data_len = (len_cur > 7) ? len_cur - 7 : 0;
                if(fido2_hid->packet.len > data_len) {
                    fido2_hid->req_len_left = fido2_hid->packet.len - data_len;
                    memcpy(fido2_hid->packet.payload, &packet_buf[7], data_len);
                    fido2_hid->req_buf_ptr = data_len;
                } else {
                    fido2_hid->req_len_left = 0;
                    memcpy(fido2_hid->packet.payload, &packet_buf[7], fido2_hid->packet.len);
                }
            } else {
                // Continuation packet
                if(fido2_hid->req_len_left == 0) continue;
                if(len_cur < 5) continue;

                uint32_t cid_temp = 0;
                memcpy(&cid_temp, packet_buf, 4);
                uint8_t seq_temp = packet_buf[4];

                if((cid_temp == fido2_hid->packet.cid) &&
                   (seq_temp == fido2_hid->seq_id_last)) {
                    size_t data_len = (len_cur > 5) ? len_cur - 5 : 0;
                    size_t copy_len = (data_len < fido2_hid->req_len_left) ?
                                      data_len : fido2_hid->req_len_left;

                    memcpy(
                        &(fido2_hid->packet.payload[fido2_hid->req_buf_ptr]),
                        &packet_buf[5],
                        copy_len);

                    fido2_hid->req_buf_ptr += copy_len;
                    fido2_hid->req_len_left -= copy_len;
                    fido2_hid->seq_id_last++;
                }
            }

            if(fido2_hid->req_len_left == 0 && fido2_hid->running) {
                fido2_hid_parse_request(fido2_hid);
            }
        }

        if(flags & WorkerEvtUnlock) {
            fido2_hid->lock = false;
            fido2_hid->lock_cid = 0;
        }
    }

    fido2_hid->running = false;
    debug_log("Stopping FIDO2 HID worker");
    
    if(fido2_hid->lock_timer) {
        furi_timer_stop(fido2_hid->lock_timer);
        furi_timer_free(fido2_hid->lock_timer);
    }
    
    furi_hal_hid_u2f_set_callback(NULL, NULL);
    furi_hal_usb_set_config(usb_mode_prev, NULL);

    debug_log("FIDO2 HID Worker Stopped");
    return 0;
}

Fido2Hid* fido2_hid_start(Fido2Ctap* ctap) {
    debug_log("fido2_hid_start CALLED");
    
    Fido2Hid* fido2_hid = malloc(sizeof(Fido2Hid));
    if(!fido2_hid) {
        debug_log("Allocation FAILED");
        return NULL;
    }
    
    memset(fido2_hid, 0, sizeof(Fido2Hid));

    fido2_hid->ctap = ctap;
    fido2_hid->connection_callback = NULL;
    fido2_hid->connection_context = NULL;
    fido2_hid->running = false;

    fido2_hid->thread = furi_thread_alloc_ex(
        "Fido2HidWorker", 2048, fido2_hid_worker, fido2_hid);
    
    if(!fido2_hid->thread) {
        debug_log("Thread allocation FAILED");
        free(fido2_hid);
        return NULL;
    }
    
    furi_thread_start(fido2_hid->thread);
    debug_log("FIDO2 HID started successfully");
    
    return fido2_hid;
}

void fido2_hid_stop(Fido2Hid* fido2_hid) {
    furi_assert(fido2_hid);
    debug_log("FIDO2 HID stop called");

    fido2_hid->running = false;
    
    if(fido2_hid->thread) {
        furi_thread_flags_set(furi_thread_get_id(fido2_hid->thread), WorkerEvtStop);
        furi_thread_join(fido2_hid->thread);
        furi_thread_free(fido2_hid->thread);
    }

    free(fido2_hid);
    debug_log("FIDO2 HID stopped");
}

void fido2_hid_set_connection_callback(
    Fido2Hid* fido2_hid,
    Fido2HidConnectionCallback callback,
    void* context) {
    furi_assert(fido2_hid);
    fido2_hid->connection_callback = callback;
    fido2_hid->connection_context = context;
    debug_log("Connection callback registered");
}