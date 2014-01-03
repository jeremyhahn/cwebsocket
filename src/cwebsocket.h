/**
 *  cwebsocket: A fast, lightweight websocket client/server
 *
 *  Copyright (c) 2014 Jeremy Hahn
 *
 *  This file is part of cwebsocket.
 *
 *  cwebsocket is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  cwebsocket is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with cwebsocket.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WEBSOCKET_CLIENT_H
#define WEBSOCKET_CLIENT_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "base64.h"

#define HANDSHAKE_BUFFER_MAX 255
#define DATA_BUFFER_MAX 65536

typedef enum {
	TRUE,
	FALSE
} bool;

typedef enum opcode_type {
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
	int payload_len;
	uint32_t masking_key[4];
} websocket_frame;

/*
typedef struct {
	int code;
	char *message;
	int line;
	char *filename;
} websocket_error;*/

// Global callbacks - TODO: Make re-entrant/thread-safe
void (*on_connect_callback_ptr)(int fd);
int (*on_message_callback_ptr)(int fd, const char *message);
void (*on_close_callback_ptr)(int fd, const char *message);
//void (*on_error_callback_ptr)(websocket_error *error);
int (*on_error_callback_ptr)(const char *message);

// Provided for client/server implementations
int cwebsocket_connect(const char *hostname, const char *port, const char *path);
int cwebsocket_read_data(int fd);
ssize_t cwebsocket_write_data(int fd, char *data, int len);
void cwebsocket_close(int fd, const char *message);

// Used internally by cwebsocket
int cwebsocket_read_handshake(int fd, char *seckey);
int cwebsocket_handshake_handler(const char *message, char *seckey);
void cwebsocket_print_frame(websocket_frame *frame);

#endif
