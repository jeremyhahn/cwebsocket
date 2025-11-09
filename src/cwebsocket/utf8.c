#include "utf8.h"

int utf8_count_code_points(uint8_t* s, size_t* count) {

	uint32_t codepoint;
	uint32_t state = 0;
	uint8_t first_byte = 0;

	for(*count = 0; *s; ++s) {
		uint32_t prev_state = state;
		if(prev_state == UTF8_ACCEPT) {
			first_byte = *s;
		}
		if(!utf8_decode(&state, &codepoint, *s)) {
			// Check for overlong encodings when we complete a codepoint
			if(utf8_is_overlong(first_byte, codepoint)) {
				return 1; // Reject overlong encoding
			}
			*count += 1;
		}
	}

	return state != UTF8_ACCEPT;
}

uint32_t utf8_decode(uint32_t* state, uint32_t* codep, uint32_t byte) {

	uint32_t type = utf8d[byte];
	*codep = (*state != UTF8_ACCEPT) ?
			(byte & 0x3fu) | (*codep << 6) :
			(0xff >> type) & (byte);

	*state = utf8d[256 + *state*16 + type];
	return *state;
}

int utf8_is_overlong(uint8_t first_byte, uint32_t codepoint) {
	// Check for overlong 2-byte sequences (0xC0, 0xC1)
	// These encode codepoints 0x00-0x7F which should use 1 byte
	if((first_byte & 0xFE) == 0xC0) {
		return 1; // 0xC0 or 0xC1 always indicates overlong
	}

	// Check for overlong 3-byte sequences starting with 0xE0
	// Valid 3-byte sequences should encode codepoints >= 0x800
	if(first_byte == 0xE0 && codepoint < 0x800) {
		return 1;
	}

	// Check for overlong 4-byte sequences starting with 0xF0
	// Valid 4-byte sequences should encode codepoints >= 0x10000
	if(first_byte == 0xF0 && codepoint < 0x10000) {
		return 1;
	}

	return 0;
}
