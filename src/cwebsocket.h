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

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/time.h>

#define HANDSHAKE_BUFFER_MAX 1024
#define DATA_BUFFER_MAX 65536

typedef enum {
	TRUE,
	FALSE
} bool;

/*
	WebSocket Framing Protocol:
	http://tools.ietf.org/html/rfc6455#section-5.2

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-------+-+-------------+-------------------------------+
	|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
	|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
	|N|V|V|V|       |S|             |   (if payload len==126/127)   |
	| |1|2|3|       |K|             |                               |
	+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	|     Extended payload length continued, if payload len == 127  |
	+ - - - - - - - - - - - - - - - +-------------------------------+
	|                               |Masking-key, if MASK set to 1  |
	+-------------------------------+-------------------------------+
	| Masking-key (continued)       |          Payload Data         |
	+-------------------------------- - - - - - - - - - - - - - - - +
	:                     Payload Data continued ...                :
	+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
	|                     Payload Data continued ...                |
	+---------------------------------------------------------------+
*/
typedef enum opcode_type {
	CONTINUATION = 0x00,
	TEXT_FRAME = 0x01,
	BINARY_FRAME = 0x02,
	CLOSE = 0x08,
	PING = 0x09,
	PONG = 0x0A,
} opcode_t;

typedef struct {
	bool fin;
	bool rsv1;
	bool rsv2;
	bool rsv3;
	opcode_t opcode;
	bool mask;
	int payload_len;
	uint32_t masking_key[4];
} websocket_frame;

void (*on_connect_callback_ptr)(int fd);
int (*on_message_callback_ptr)(int fd, const char *message);
void (*on_close_callback_ptr)(int fd, const char *message);

int cwebsocket_connect(const char *hostname, const char *port, const char *path);
int cwebsocket_read_handshake(int fd);
int cwebsocket_handshake_handler(const char *message);
int cwebsocket_read_data(int fd);
ssize_t cwebsocket_write_data(int fd, char *data, int len);
void cwebsocket_print_frame(websocket_frame *frame);
void cwebsocket_close(int fd, const char *message);

#endif
