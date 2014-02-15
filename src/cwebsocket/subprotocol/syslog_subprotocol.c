#include "syslog_subprotocol.h"

void cwebsocket_subprotocol_syslog_onopen(void *websocket) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;
	syslog(LOG_DEBUG, "onconnect: websocket file descriptor: %i", client->socket);
}

void cwebsocket_subprotocol_syslog_onmessage(void *websocket, cwebsocket_message *message) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;
	syslog(LOG_DEBUG, "onmessage: socket=%i, opcode=%#04x, payload_len=%zu, payload=%s\n",
			client->socket, message->opcode, message->payload_len, message->payload);
}

void cwebsocket_subprotocol_syslog_onclose(void *websocket, const char *message) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;
	syslog(LOG_DEBUG, "onclose: websocket file descriptor: %i, message: %s", client->socket, message);
}

void cwebsocket_subprotocol_syslog_onerror(void *websocket, const char *message) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;
	syslog(LOG_DEBUG, "onerror: websocket file descriptor: %i, message=%s", client->socket, message);
}

cwebsocket_subprotocol* cwebsocket_subprotocol_syslog_new() {
	cwebsocket_subprotocol *syslog_subprotocol = malloc(sizeof(cwebsocket_subprotocol));
	memset(syslog_subprotocol, 0, sizeof(cwebsocket_subprotocol));
	syslog_subprotocol->name = "syslog.cwebsocket";
	syslog_subprotocol->onopen = &cwebsocket_subprotocol_syslog_onopen;
	syslog_subprotocol->onmessage = &cwebsocket_subprotocol_syslog_onmessage;
	syslog_subprotocol->onclose = &cwebsocket_subprotocol_syslog_onclose;
	syslog_subprotocol->onerror = &cwebsocket_subprotocol_syslog_onerror;
	return syslog_subprotocol;
}
