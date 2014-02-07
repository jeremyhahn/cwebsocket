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

#ifndef WEBSOCKET_CLIENT_H
#define WEBSOCKET_CLIENT_H

#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "common.h"

#define WEBSOCKET_STATE_CONNECTING   (1 << 0)
#define WEBSOCKET_STATE_CONNECTED    (1 << 1)
#define WEBSOCKET_STATE_OPEN         (1 << 2)
#define WEBSOCKET_STATE_CLOSING      (1 << 3)
#define WEBSOCKET_STATE_CLOSED       (1 << 4)

#define WEBSOCKET_FLAG_SSL           (1 << 0)
#define WEBSOCKET_FLAG_AUTORECONNECT (1 << 1)

typedef struct _cwebsocket {
	int socket;
	int retry;
	char *uri;
	uint8_t flags;
#ifdef USESSL
	SSL_CTX *sslctx;
	SSL *ssl;
#endif
#ifdef THREADED
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_mutex_t write_lock;
#endif
	uint8_t state;
	void (*onopen)(struct _cwebsocket *);
	void (*onmessage)(struct _cwebsocket *, cwebsocket_message *message);
	void (*onclose)(struct _cwebsocket *, const char *message);
	void (*onerror)(struct _cwebsocket *, const char *error);
} cwebsocket_client;

typedef struct {
	cwebsocket_client *socket;
	cwebsocket_message *message;
} cwebsocket_thread_args;

// "public"
void cwebsocket_init();
int cwebsocket_connect(cwebsocket_client *websocket);
int cwebsocket_read_data(cwebsocket_client *websocket);
ssize_t cwebsocket_write_data(cwebsocket_client *websocket, const char *data, int len);
void cwebsocket_run(cwebsocket_client *websocket);
void cwebsocket_close(cwebsocket_client *websocket, const char *message);
void cwebsocket_listen(cwebsocket_client *websocket);

// "private"
void cwebsocket_parse_uri(cwebsocket_client *websocket, const char *uri, char *hostname, char *port, char *resource, char *querystring);
int cwebsocket_handshake_handler(cwebsocket_client *websocket, const char *handshake_response, char *seckey);
int cwebsocket_read_handshake(cwebsocket_client *websocket, char *seckey);
int cwebsocket_send_control_frame(cwebsocket_client *websocket, opcode opcode, const char *frame_type, const char *payload);
ssize_t inline cwebsocket_read(cwebsocket_client *websocket, void *buf, int len);
ssize_t inline cwebsocket_write(cwebsocket_client *websocket, void *buf, int len);

#endif
