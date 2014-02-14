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

#ifndef cwebsocket_server_SERVER_H_
#define cwebsocket_server_SERVER_H_

#include <ev.h>
#include "common.h"

#ifndef CWS_MAX_CONNECTIONS
	#define CWS_MAX_CONNECTIONS 1024
#endif

#ifndef CWS_MAX_QUEUED_CONNECTIONS
	#define CWS_MAX_QUEUED_CONNECTIONS 100
#endif

#ifndef CWS_MAX_CONNECTIONS
	#define CWS_MAX_CONNECTIONS 1000000
#endif

typedef struct {
	int websocket;
	uint8_t state;
	pthread_t thread;
	pthread_mutex_t write_lock;
} cwebsocket_connection;

typedef struct {
	int socket;
	int port;
	uint8_t flags;
	int cores;                       // logical
	struct ev_loop *ev_accept_loop;
	struct ev_io ev_accept;
	int connections;
	pthread_mutex_t lock;
	//cwebsocket_protocol protocols[];
} cwebsocket_server;

cwebsocket_server *websocket_server;

cwebsocket_server* cwebsocket_server_new();
int cwebsocket_server_connect(cwebsocket_server *websocket);
int cwebsocket_server_accept(struct ev_loop *loop, struct ev_io *watcher, int revents);
void* cwebsocket_server_accept_thread(void *ptr);
int cwebsocket_server_read_handshake(cwebsocket_connection *connection);
int cwebsocket_server_read_handshake_handler(cwebsocket_connection *connection, const char *handshake);
int cwebsocket_server_send_handshake_response(cwebsocket_connection *connection, const char *seckey);
int cwebsocket_server_close(cwebsocket_server *websocket);

#endif
