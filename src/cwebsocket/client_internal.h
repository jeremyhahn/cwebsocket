/**
 * Internal functions exposed for unit testing only.
 * DO NOT include this in production code!
 */

#ifndef CWEBSOCKET_CLIENT_INTERNAL_H
#define CWEBSOCKET_CLIENT_INTERNAL_H

#include "client.h"

#ifdef UNIT_TESTING

// Expose static functions for testing
int cwebsocket_client_is_control_frame(opcode frame_opcode);
void cwebsocket_client_reset_fragments(cwebsocket_client *websocket);
int cwebsocket_client_ensure_fragment_capacity(cwebsocket_client *websocket, size_t required);
int cwebsocket_is_valid_close_code(uint16_t code);
int cwebsocket_header_contains_token(const char *header_value, const char *token);
void cwebsocket_trim(char *value);
int cwebsocket_client_random_bytes(uint8_t *buffer, size_t length);

#endif // UNIT_TESTING

#endif // CWEBSOCKET_CLIENT_INTERNAL_H
