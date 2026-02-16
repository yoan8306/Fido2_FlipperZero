#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// CBOR major types
#define CBOR_MAJOR_UNSIGNED 0
#define CBOR_MAJOR_NEGATIVE 1
#define CBOR_MAJOR_BYTES    2
#define CBOR_MAJOR_TEXT     3
#define CBOR_MAJOR_ARRAY    4
#define CBOR_MAJOR_MAP      5
#define CBOR_MAJOR_TAG      6
#define CBOR_MAJOR_SIMPLE   7

// Simple values
#define CBOR_FALSE 20
#define CBOR_TRUE  21
#define CBOR_NULL  22
#define CBOR_UNDEF 23

// CBOR encoding functions
size_t cbor_encode_uint(uint8_t* buf, uint64_t value);
size_t cbor_encode_int(uint8_t* buf, int64_t value);
size_t cbor_encode_bytes(uint8_t* buf, const uint8_t* data, size_t len);
size_t cbor_encode_text(uint8_t* buf, const char* text);
size_t cbor_encode_map_header(uint8_t* buf, size_t num_pairs);
size_t cbor_encode_array_header(uint8_t* buf, size_t num_items);
size_t cbor_encode_bool(uint8_t* buf, bool value);
size_t cbor_encode_null(uint8_t* buf);

// CBOR decoding functions
typedef struct {
    const uint8_t* data;
    size_t size;
    size_t offset;
} CborDecoder;

void cbor_decoder_init(CborDecoder* decoder, const uint8_t* data, size_t size);
bool cbor_decode_uint(CborDecoder* decoder, uint64_t* value);
bool cbor_decode_int(CborDecoder* decoder, int64_t* value);
bool cbor_decode_bytes(CborDecoder* decoder, const uint8_t** data, size_t* len);
bool cbor_decode_text(CborDecoder* decoder, const char** text, size_t* len);
bool cbor_decode_map_size(CborDecoder* decoder, size_t* size);
bool cbor_decode_array_size(CborDecoder* decoder, size_t* size);
bool cbor_decode_bool(CborDecoder* decoder, bool* value);
bool cbor_skip_value(CborDecoder* decoder);
uint8_t cbor_peek_type(CborDecoder* decoder);

#ifdef __cplusplus
}
#endif