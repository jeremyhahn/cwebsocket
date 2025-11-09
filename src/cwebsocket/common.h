/**
 *  Copyright 2014 Jeremy Hahn
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef CWEBSOCKET_H_
#define CWEBSOCKET_H_

// Define GNU_SOURCE for strcasestr and other GNU extensions
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "utf8.h"

#ifdef HAVE_CONFIG_H
    #include "../../config.h"
#endif

#ifdef ENABLE_SSL
	#include <openssl/rand.h>
	#include <openssl/ssl.h>
	#include <openssl/err.h>
#endif

#if defined(__linux__)
	#include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
	#include <sys/endian.h>
#elif defined(__OpenBSD__)
	#define be16toh(x) betoh16(x)
	#define be32toh(x) betoh32(x)
	#define be64toh(x) betoh64(x)
#endif

#define htonl64(p) {\
	(char)(((p) >> 56) & 0xff), (char)(((p) >> 48) & 0xff), \
	(char)(((p) >> 40) & 0xff), (char)(((p) >> 32) & 0xff), \
	(char)(((p) >> 24) & 0xff), (char)(((p) >> 16) & 0xff), \
	(char)(((p) >> 8) & 0xff),  (char)((p) & 0xff) }

#ifndef CWS_HANDSHAKE_BUFFER_MAX
    #define CWS_HANDSHAKE_BUFFER_MAX 4096  // bytes
#endif

#ifndef CWS_DATA_BUFFER_MAX
    // Allow large Autobahn test payloads and fragmented assemblies (32 MiB)
    #define CWS_DATA_BUFFER_MAX (32 * 1024 * 1024)     // bytes
#endif

#ifndef CWS_STACK_SIZE_MIN
	#define CWS_STACK_SIZE_MIN 8          // MB
#endif

#define CWS_VERSION "1.0"

#define WEBSOCKET_STATE_CONNECTING   (1 << 0)
#define WEBSOCKET_STATE_CONNECTED    (1 << 1)
#define WEBSOCKET_STATE_OPEN         (1 << 2)
#define WEBSOCKET_STATE_CLOSING      (1 << 3)
#define WEBSOCKET_STATE_CLOSED       (1 << 4)

#define WEBSOCKET_FLAG_SSL           (1 << 0)

#define CWS_HANDSHAKE_HAS_UPGRADE    (1 << 0)
#define CWS_HANDSHAKE_HAS_CONNECTION (1 << 1)
#define CWS_HANDSHAKE_HAS_KEY        (1 << 2)
#define CWS_HANDSHAKE_HAS_VERSION    (1 << 3)
#define CWS_HANDSHAKE_HAS_ACCEPT     (1 << 4)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	TRUE,
	FALSE
} bool;

typedef enum {
	CONTINUATION = 0x00,
	TEXT_FRAME = 0x01,
	BINARY_FRAME = 0x02,
	CLOSE = 0x08,
	PING = 0x09,
	PONG = 0x0A,
} opcode;

typedef struct {
	bool fin;
	bool rsv1;
	bool rsv2;
	bool rsv3;
	opcode opcode;
	bool mask;
	uint64_t payload_len;
	uint32_t masking_key[4];
} cwebsocket_frame;

typedef struct {
	uint32_t opcode;
	uint64_t payload_len;
	char *payload;
} cwebsocket_message;

typedef struct {
	char *name;
	void (*onopen)(void *arg);
	void (*onmessage)(void *arg, cwebsocket_message *message);
	void (*onclose)(void *arg, int code, const char *message);
	void (*onerror)(void *arg, const char *error);
} cwebsocket_subprotocol;

char* cwebsocket_create_key_challenge_response(const char *seckey);
char* cwebsocket_base64_encode(const unsigned char *input, int length);
void cwebsocket_print_frame(cwebsocket_frame *frame);

#ifdef __cplusplus
}
#endif

#endif
