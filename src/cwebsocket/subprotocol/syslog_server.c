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

#include "syslog_server.h"

void cwebsocket_subprotocol_syslog_server_onopen(void *websocket) {
	cwebsocket_server *client = (cwebsocket_server *)websocket;
	syslog(LOG_DEBUG, "cwebsocket_subprotocol_syslog_server_onopen: websocket file descriptor: %i", client->socket);
}

void cwebsocket_subprotocol_syslog_server_onmessage(void *websocket, cwebsocket_message *message) {
	cwebsocket_server *client = (cwebsocket_server *)websocket;
	syslog(LOG_DEBUG, "cwebsocket_subprotocol_syslog_server_onmessage: socket=%i, opcode=%#04x, payload_len=%zu, payload=%s\n",
			client->socket, message->opcode, message->payload_len, message->payload);
}

void cwebsocket_subprotocol_syslog_server_onclose(void *websocket, const char *message) {
	cwebsocket_server *client = (cwebsocket_server *)websocket;
	syslog(LOG_DEBUG, "cwebsocket_subprotocol_syslog_server_onclose: websocket file descriptor: %i, message: %s", client->socket, message);
}

void cwebsocket_subprotocol_syslog_server_onerror(void *websocket, const char *message) {
	cwebsocket_server *client = (cwebsocket_server *)websocket;
	syslog(LOG_DEBUG, "cwebsocket_subprotocol_syslog_server_onerror: websocket file descriptor: %i, message=%s", client->socket, message);
}

cwebsocket_subprotocol* cwebsocket_subprotocol_syslog_server_new() {
	cwebsocket_subprotocol *protocol = malloc(sizeof(cwebsocket_subprotocol));
	memset(protocol, 0, sizeof(cwebsocket_subprotocol));
	protocol->name = "syslog.cwebsocket\0";
	protocol->onopen = &cwebsocket_subprotocol_syslog_server_onopen;
	protocol->onmessage = &cwebsocket_subprotocol_syslog_server_onmessage;
	protocol->onclose = &cwebsocket_subprotocol_syslog_server_onclose;
	protocol->onerror = &cwebsocket_subprotocol_syslog_server_onerror;
	return protocol;
}
