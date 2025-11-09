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

#include "echo_client.h"

void cwebsocket_subprotocol_echo_client_onopen(void *websocket) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;
	syslog(LOG_DEBUG, "cwebsocket_subprotocol_echo_client_onopen: fd=%i", client->fd);
}

void cwebsocket_subprotocol_echo_client_onmessage(void *websocket, cwebsocket_message *message) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;

	// Print received message to stdout
	if(message->opcode == TEXT_FRAME) {
		printf("<<< RECEIVED: \"%.*s\"\n", (int)message->payload_len, (char*)message->payload);
		fflush(stdout);
	} else if(message->opcode == BINARY_FRAME) {
		printf("<<< RECEIVED: %lu bytes of binary data\n", (unsigned long)message->payload_len);
		fflush(stdout);
	}

	syslog(LOG_DEBUG, "cwebsocket_subprotocol_echo_client_onmessage: fd=%i, opcode=%#04x, payload_len=%llu, payload=%s\n",
            client->fd, message->opcode, message->payload_len, message->payload);

	// Echo back exactly what we received (text or binary)
	if(client->state & WEBSOCKET_STATE_OPEN) {
		opcode op = message->opcode;
		if(op == TEXT_FRAME || op == BINARY_FRAME) {
			uint64_t len = message->payload_len;
			if(len > 0 && message->payload != NULL) {
				cwebsocket_client_write_data(client, message->payload, len, op);
			} else {
				// Echo empty payload frame of same type
				cwebsocket_client_write_data(client, "", 0, op);
			}
		}
	}
}

void cwebsocket_subprotocol_echo_client_onclose(void *websocket, int code, const char *reason) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;
	syslog(LOG_DEBUG, "cwebsocket_subprotocol_echo_client_onclose: fd=%i, code=%i, reason=%s", client->fd, code, reason);
}

void cwebsocket_subprotocol_echo_client_onerror(void *websocket, const char *message) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;
	syslog(LOG_DEBUG, "cwebsocket_subprotocol_echo_client_onerror: fd=%i, message=%s", client->fd, message);
}

cwebsocket_subprotocol* cwebsocket_subprotocol_echo_client_new() {
	cwebsocket_subprotocol *protocol = malloc(sizeof(cwebsocket_subprotocol));
	memset(protocol, 0, sizeof(cwebsocket_subprotocol));
	protocol->name = "echo.cwebsocket\0";
	protocol->onopen = &cwebsocket_subprotocol_echo_client_onopen;
	protocol->onmessage = &cwebsocket_subprotocol_echo_client_onmessage;
	protocol->onclose = &cwebsocket_subprotocol_echo_client_onclose;
	protocol->onerror = &cwebsocket_subprotocol_echo_client_onerror;
	return protocol;
}
