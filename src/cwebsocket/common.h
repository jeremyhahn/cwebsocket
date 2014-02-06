/**
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2014 Jeremy Hahn
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

#ifndef CWEBSOCKET_H_
#define CWEBSOCKET_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "utf8.h"

#ifndef HANDSHAKE_BUFFER_MAX
	#define HANDSHAKE_BUFFER_MAX 256  // bytes
#endif

#ifndef DATA_BUFFER_MAX
	#define DATA_BUFFER_MAX 65536     // bytes
#endif

#ifndef STACK_SIZE_MIN
	#define STACK_SIZE_MIN 2          // MB
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
	uint32_t opcode;
	uint64_t payload_len;
	char *payload;
} cwebsocket_message;

typedef struct {
	bool fin;
	bool rsv1;
	bool rsv2;
	bool rsv3;
	opcode opcode;
	bool mask;
	int payload_len;
	uint32_t masking_key[4];
} cwebsocket_frame;

char* cwebsocket_base64_encode(const unsigned char *input, int length);
void cwebsocket_print_frame(cwebsocket_frame *frame);

#endif
