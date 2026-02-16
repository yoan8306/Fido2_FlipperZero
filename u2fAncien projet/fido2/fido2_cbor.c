#include "fido2_cbor.h"
#include "fido2_app.h"
#include <string.h>

// ============================================================================
// CBOR ENCODING FUNCTIONS
// ============================================================================
size_t cbor_encode_uint(uint8_t* buf, uint64_t value) {
    if(value < 24) {
        buf[0] = (CBOR_MAJOR_UNSIGNED << 5) | (uint8_t)value;
        return 1;
    } else if(value < 256) {
        buf[0] = (CBOR_MAJOR_UNSIGNED << 5) | 24;
        buf[1] = (uint8_t)value;
        return 2;
    } else if(value < 65536) {
        buf[0] = (CBOR_MAJOR_UNSIGNED << 5) | 25;
        buf[1] = (uint8_t)(value >> 8);
        buf[2] = (uint8_t)value;
        return 3;
    } else if(value < 4294967296ULL) {
        buf[0] = (CBOR_MAJOR_UNSIGNED << 5) | 26;
        buf[1] = (uint8_t)(value >> 24);
        buf[2] = (uint8_t)(value >> 16);
        buf[3] = (uint8_t)(value >> 8);
        buf[4] = (uint8_t)value;
        return 5;
    } else {
        buf[0] = (CBOR_MAJOR_UNSIGNED << 5) | 27;
        buf[1] = (uint8_t)(value >> 56);
        buf[2] = (uint8_t)(value >> 48);
        buf[3] = (uint8_t)(value >> 40);
        buf[4] = (uint8_t)(value >> 32);
        buf[5] = (uint8_t)(value >> 24);
        buf[6] = (uint8_t)(value >> 16);
        buf[7] = (uint8_t)(value >> 8);
        buf[8] = (uint8_t)value;
        return 9;
    }
}

size_t cbor_encode_int(uint8_t* buf, int64_t value) {
    if(value >= 0) {
        return cbor_encode_uint(buf, (uint64_t)value);
    } else {
        uint64_t abs_value = (uint64_t)(-(value + 1));
        if(abs_value < 24) {
            buf[0] = (CBOR_MAJOR_NEGATIVE << 5) | (uint8_t)abs_value;
            return 1;
        } else if(abs_value < 256) {
            buf[0] = (CBOR_MAJOR_NEGATIVE << 5) | 24;
            buf[1] = (uint8_t)abs_value;
            return 2;
        } else if(abs_value < 65536) {
            buf[0] = (CBOR_MAJOR_NEGATIVE << 5) | 25;
            buf[1] = (uint8_t)(abs_value >> 8);
            buf[2] = (uint8_t)abs_value;
            return 3;
        } else {
            buf[0] = (CBOR_MAJOR_NEGATIVE << 5) | 26;
            buf[1] = (uint8_t)(abs_value >> 24);
            buf[2] = (uint8_t)(abs_value >> 16);
            buf[3] = (uint8_t)(abs_value >> 8);
            buf[4] = (uint8_t)abs_value;
            return 5;
        }
    }
}

size_t cbor_encode_bytes(uint8_t* buf, const uint8_t* data, size_t len) {
    size_t offset = 0;

    if(len < 24) {
        buf[offset++] = (CBOR_MAJOR_BYTES << 5) | (uint8_t)len;
    } else if(len < 256) {
        buf[offset++] = (CBOR_MAJOR_BYTES << 5) | 24;
        buf[offset++] = (uint8_t)len;
    } else if(len < 65536) {
        buf[offset++] = (CBOR_MAJOR_BYTES << 5) | 25;
        buf[offset++] = (uint8_t)(len >> 8);
        buf[offset++] = (uint8_t)len;
    } else {
        buf[offset++] = (CBOR_MAJOR_BYTES << 5) | 26;
        buf[offset++] = (uint8_t)(len >> 24);
        buf[offset++] = (uint8_t)(len >> 16);
        buf[offset++] = (uint8_t)(len >> 8);
        buf[offset++] = (uint8_t)len;
    }

    memcpy(buf + offset, data, len);
    return offset + len;
}

size_t cbor_encode_text(uint8_t* buf, const char* text) {
    size_t len = strlen(text);
    size_t offset = 0;

    if(len < 24) {
        buf[offset++] = (CBOR_MAJOR_TEXT << 5) | (uint8_t)len;
    } else if(len < 256) {
        buf[offset++] = (CBOR_MAJOR_TEXT << 5) | 24;
        buf[offset++] = (uint8_t)len;
    } else if(len < 65536) {
        buf[offset++] = (CBOR_MAJOR_TEXT << 5) | 25;
        buf[offset++] = (uint8_t)(len >> 8);
        buf[offset++] = (uint8_t)len;
    }

    memcpy(buf + offset, text, len);
    return offset + len;
}

size_t cbor_encode_map_header(uint8_t* buf, size_t num_pairs) {
    if(num_pairs < 24) {
        buf[0] = (CBOR_MAJOR_MAP << 5) | (uint8_t)num_pairs;
        return 1;
    } else if(num_pairs < 256) {
        buf[0] = (CBOR_MAJOR_MAP << 5) | 24;
        buf[1] = (uint8_t)num_pairs;
        return 2;
    } else {
        buf[0] = (CBOR_MAJOR_MAP << 5) | 25;
        buf[1] = (uint8_t)(num_pairs >> 8);
        buf[2] = (uint8_t)num_pairs;
        return 3;
    }
}

size_t cbor_encode_array_header(uint8_t* buf, size_t num_items) {
    if(num_items < 24) {
        buf[0] = (CBOR_MAJOR_ARRAY << 5) | (uint8_t)num_items;
        return 1;
    } else if(num_items < 256) {
        buf[0] = (CBOR_MAJOR_ARRAY << 5) | 24;
        buf[1] = (uint8_t)num_items;
        return 2;
    } else {
        buf[0] = (CBOR_MAJOR_ARRAY << 5) | 25;
        buf[1] = (uint8_t)(num_items >> 8);
        buf[2] = (uint8_t)num_items;
        return 3;
    }
}

size_t cbor_encode_bool(uint8_t* buf, bool value) {
    buf[0] = (CBOR_MAJOR_SIMPLE << 5) | (value ? CBOR_TRUE : CBOR_FALSE);
    return 1;
}

size_t cbor_encode_null(uint8_t* buf) {
    buf[0] = (CBOR_MAJOR_SIMPLE << 5) | CBOR_NULL;
    return 1;
}

// ============================================================================
// CBOR DECODING FUNCTIONS
// ============================================================================

void cbor_decoder_init(CborDecoder* decoder, const uint8_t* data, size_t size) {
    decoder->data = data;
    decoder->size = size;
    decoder->offset = 0;
}

static bool cbor_read_byte(CborDecoder* decoder, uint8_t* byte) {
    if(decoder->offset >= decoder->size) {
        return false;
    }
    *byte = decoder->data[decoder->offset++];
    return true;
}

static bool cbor_read_uint_internal(CborDecoder* decoder, uint8_t additional_info, uint64_t* value) {
    if(additional_info < 24) {
        *value = additional_info;
        return true;
    } else if(additional_info == 24) {
        uint8_t byte;
        if(!cbor_read_byte(decoder, &byte)) return false;
        *value = byte;
        return true;
    } else if(additional_info == 25) {
        if(decoder->offset + 2 > decoder->size) return false;
        *value = ((uint64_t)decoder->data[decoder->offset] << 8) |
                 ((uint64_t)decoder->data[decoder->offset + 1]);
        decoder->offset += 2;
        return true;
    } else if(additional_info == 26) {
        if(decoder->offset + 4 > decoder->size) return false;
        *value = ((uint64_t)decoder->data[decoder->offset] << 24) |
                 ((uint64_t)decoder->data[decoder->offset + 1] << 16) |
                 ((uint64_t)decoder->data[decoder->offset + 2] << 8) |
                 ((uint64_t)decoder->data[decoder->offset + 3]);
        decoder->offset += 4;
        return true;
    } else if(additional_info == 27) {
        if(decoder->offset + 8 > decoder->size) return false;
        *value = ((uint64_t)decoder->data[decoder->offset] << 56) |
                 ((uint64_t)decoder->data[decoder->offset + 1] << 48) |
                 ((uint64_t)decoder->data[decoder->offset + 2] << 40) |
                 ((uint64_t)decoder->data[decoder->offset + 3] << 32) |
                 ((uint64_t)decoder->data[decoder->offset + 4] << 24) |
                 ((uint64_t)decoder->data[decoder->offset + 5] << 16) |
                 ((uint64_t)decoder->data[decoder->offset + 6] << 8) |
                 ((uint64_t)decoder->data[decoder->offset + 7]);
        decoder->offset += 8;
        return true;
    }
    return false;
}

uint8_t cbor_peek_type(CborDecoder* decoder) {
    if(decoder->offset >= decoder->size) {
        return 0xFF;
    }
    return (decoder->data[decoder->offset] >> 5) & 0x07;
}

bool cbor_decode_uint(CborDecoder* decoder, uint64_t* value) {
    uint8_t initial_byte;
    if(!cbor_read_byte(decoder, &initial_byte)) return false;

    uint8_t major_type = (initial_byte >> 5) & 0x07;
    uint8_t additional_info = initial_byte & 0x1F;

    if(major_type != CBOR_MAJOR_UNSIGNED) return false;

    return cbor_read_uint_internal(decoder, additional_info, value);
}

bool cbor_decode_int(CborDecoder* decoder, int64_t* value) {
    uint8_t initial_byte;
    if(!cbor_read_byte(decoder, &initial_byte)) return false;

    uint8_t major_type = (initial_byte >> 5) & 0x07;
    uint8_t additional_info = initial_byte & 0x1F;

    if(major_type == CBOR_MAJOR_UNSIGNED) {
        uint64_t uvalue;
        if(!cbor_read_uint_internal(decoder, additional_info, &uvalue)) return false;
        *value = (int64_t)uvalue;
        return true;
    } else if(major_type == CBOR_MAJOR_NEGATIVE) {
        uint64_t uvalue;
        if(!cbor_read_uint_internal(decoder, additional_info, &uvalue)) return false;
        *value = -1 - (int64_t)uvalue;
        return true;
    }
    return false;
}

bool cbor_decode_bytes(CborDecoder* decoder, const uint8_t** data, size_t* len) {
    uint8_t initial_byte;
    if(!cbor_read_byte(decoder, &initial_byte)) return false;

    uint8_t major_type = (initial_byte >> 5) & 0x07;
    uint8_t additional_info = initial_byte & 0x1F;

    if(major_type != CBOR_MAJOR_BYTES) return false;

    uint64_t length;
    if(!cbor_read_uint_internal(decoder, additional_info, &length)) return false;

    if(decoder->offset + length > decoder->size) return false;

    *data = &decoder->data[decoder->offset];
    *len = (size_t)length;
    decoder->offset += length;

    return true;
}

bool cbor_decode_text(CborDecoder* decoder, const char** text, size_t* len) {
    uint8_t initial_byte;
    if(!cbor_read_byte(decoder, &initial_byte)) return false;

    uint8_t major_type = (initial_byte >> 5) & 0x07;
    uint8_t additional_info = initial_byte & 0x1F;

    if(major_type != CBOR_MAJOR_TEXT) return false;

    uint64_t length;
    if(!cbor_read_uint_internal(decoder, additional_info, &length)) return false;

    if(decoder->offset + length > decoder->size) return false;

    *text = (const char*)&decoder->data[decoder->offset];
    *len = (size_t)length;
    decoder->offset += length;

    return true;
}

bool cbor_decode_map_size(CborDecoder* decoder, size_t* size) {
    uint8_t initial_byte;
    if(!cbor_read_byte(decoder, &initial_byte)) return false;

    uint8_t major_type = (initial_byte >> 5) & 0x07;
    uint8_t additional_info = initial_byte & 0x1F;

    if(major_type != CBOR_MAJOR_MAP) return false;

    uint64_t map_size;
    if(!cbor_read_uint_internal(decoder, additional_info, &map_size)) return false;

    *size = (size_t)map_size;
    return true;
}

bool cbor_decode_array_size(CborDecoder* decoder, size_t* size) {
    uint8_t initial_byte;
    if(!cbor_read_byte(decoder, &initial_byte)) return false;

    uint8_t major_type = (initial_byte >> 5) & 0x07;
    uint8_t additional_info = initial_byte & 0x1F;

    if(major_type != CBOR_MAJOR_ARRAY) return false;

    uint64_t array_size;
    if(!cbor_read_uint_internal(decoder, additional_info, &array_size)) return false;

    *size = (size_t)array_size;
    return true;
}

bool cbor_decode_bool(CborDecoder* decoder, bool* value) {
    uint8_t initial_byte;
    if(!cbor_read_byte(decoder, &initial_byte)) return false;

    uint8_t major_type = (initial_byte >> 5) & 0x07;
    uint8_t additional_info = initial_byte & 0x1F;

    if(major_type != CBOR_MAJOR_SIMPLE) return false;

    if(additional_info == CBOR_FALSE) {
        *value = false;
        return true;
    } else if(additional_info == CBOR_TRUE) {
        *value = true;
        return true;
    }

    return false;
}

bool cbor_skip_value(CborDecoder* decoder) {
    uint8_t initial_byte;
    if(!cbor_read_byte(decoder, &initial_byte)) return false;

    uint8_t major_type = (initial_byte >> 5) & 0x07;
    uint8_t additional_info = initial_byte & 0x1F;

    uint64_t value;
    if(!cbor_read_uint_internal(decoder, additional_info, &value)) return false;

    switch(major_type) {
    case CBOR_MAJOR_UNSIGNED:
    case CBOR_MAJOR_NEGATIVE:
    case CBOR_MAJOR_SIMPLE:
        // Already consumed
        return true;

    case CBOR_MAJOR_BYTES:
    case CBOR_MAJOR_TEXT:
        // Skip the data
        if(decoder->offset + value > decoder->size) return false;
        decoder->offset += value;
        return true;

    case CBOR_MAJOR_ARRAY:
        // Skip each element
        for(uint64_t i = 0; i < value; i++) {
            if(!cbor_skip_value(decoder)) return false;
        }
        return true;

    case CBOR_MAJOR_MAP:
        // Skip key-value pairs
        for(uint64_t i = 0; i < value * 2; i++) {
            if(!cbor_skip_value(decoder)) return false;
        }
        return true;

    default:
        return false;
    }
}
