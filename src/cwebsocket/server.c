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

#include "server.h"

int cwebsocket_server_setnonblocking(int fd) {
	int flags;
	flags = fcntl(fd, F_GETFL);
	if (flags < 0) return flags;
	flags |= O_NONBLOCK;
	if(fcntl(fd, F_SETFL, flags) < 0) return -1;
	return 0;
}

void cwebsocket_server_init(int port, cwebsocket_subprotocol *subprotocols[], int subprotocol_len) {
	websocket_server = malloc(sizeof(cwebsocket_server) + (sizeof(cwebsocket_subprotocol) * subprotocol_len));
	memset(websocket_server, 0, sizeof(cwebsocket_server));
	websocket_server->port = port;
	websocket_server->subprotocol_len = subprotocol_len;
	int i;
	for(i=0; i<subprotocol_len; i++) {
		syslog(LOG_DEBUG, "cwebsocket_server_init: initializing subprotocol %s", subprotocols[i]->name);
	    websocket_server->subprotocols[i] = subprotocols[i];
	}
	if(websocket_server->cores <= 0) {
		websocket_server->cores = sysconf(_SC_NPROCESSORS_ONLN);
	}
	syslog(LOG_DEBUG, "cwebsocket_server_init: port=%i, cores=%i", websocket_server->port, websocket_server->cores);
}

int cwebsocket_server_listen() {

	int reuseaddr = 1;
	struct sockaddr_in srvaddr;
	memset(&srvaddr, 0, sizeof(srvaddr));

	websocket_server->socket = socket(AF_INET, SOCK_STREAM, 0);
	if(websocket_server->socket == -1) {
		syslog(LOG_CRIT, "cwebsocket_server_listen: unable to connect: %s", strerror(errno));
		return -1;
	}

	if(websocket_server->port < 0 || websocket_server->port > 65535) {
		syslog(LOG_CRIT, "cwebsocket_server_listen: invalid port %i", websocket_server->port);
		return -1;
	}

	srvaddr.sin_family = AF_INET;
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	srvaddr.sin_port = htons(websocket_server->port);

	if(bind(websocket_server->socket, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) == -1) {
		syslog(LOG_CRIT, "cwebsocket_server_listen: unable to bind to socket: %s", strerror(errno));
		return -1;
	}

	if(listen(websocket_server->socket, CWS_MAX_QUEUED_CONNECTIONS) == -1) {
		syslog(LOG_CRIT, "cwebsocket_server_listen: unable to set maximum queued connections: %s", strerror(errno));
		return -1;
	}

	if(setsockopt(websocket_server->socket, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
	   syslog(LOG_CRIT, "cwebsocket_server_listen: failed to set SO_REUSEADDR sockopt: %s", strerror(errno));
	   return -1;
	}

	if(cwebsocket_server_setnonblocking(websocket_server->socket) == -1) {
		syslog(LOG_CRIT, "cwebsocket_server_listen: unable to set socket to non-blocking mode: %s", strerror(errno));
		return -1;
	}

	syslog(LOG_DEBUG, "cwebsocket_server_listen: starting libev accept loop");

	struct ev_loop *loop = ev_default_loop(0);
	ev_io_init(&websocket_server->ev_accept, cwebsocket_server_accept, websocket_server->socket, EV_READ);
	ev_io_start(loop, &websocket_server->ev_accept);
	ev_loop(loop, 0);

	syslog(LOG_DEBUG, "cwebsocket_server_listen: completed libev event loop");

	return 0;
}

int cwebsocket_server_accept(struct ev_loop *loop, struct ev_io *watcher, int revents) {

	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	cwebsocket_connection *connection = malloc(sizeof(cwebsocket_connection));
	memset(connection, 0, sizeof(cwebsocket_connection));
	connection->state |= WEBSOCKET_STATE_CONNECTING;

	if(EV_ERROR & revents) {
		syslog(LOG_ERR, "cwebsocket_server_accept: received invalid event");
		return -1;
	}

	connection->websocket = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);
	if(connection->websocket == -1) {
		syslog(LOG_CRIT, "cwebsocket_server_accept: %s", strerror(errno));
		return -1;
	}

	if(cwebsocket_server_setnonblocking(connection->websocket) == -1) {
		syslog(LOG_CRIT, "cwebsocket_server_accept: %s", strerror(errno));
		return -1;
	}

	pthread_mutex_lock(&websocket_server->lock);
	websocket_server->connections++;
	pthread_mutex_unlock(&websocket_server->lock);

	connection->state |= WEBSOCKET_STATE_CONNECTED;
	syslog(LOG_DEBUG, "cwebsocket_server_accept: connection #%i accepted on fd %i", websocket_server->connections, connection->websocket);

	if(pthread_create(&connection->thread, NULL, cwebsocket_server_accept_thread, (void *)connection) == -1) {
		syslog(LOG_ERR, "cwebsocket_server_accept: %s", strerror(errno));
		return -1;
	}

	return 0;
}

void* cwebsocket_server_accept_thread(void *ptr) {
	cwebsocket_connection *connection = (cwebsocket_connection *)ptr;
	if(cwebsocket_server_read_handshake(connection) == -1) {
		syslog(LOG_ERR, "cwebsocket_server_accept_thread: unable to read handshake");
		return NULL;
	}
	free(connection);
	return NULL;
}

int cwebsocket_server_read_handshake(cwebsocket_connection *connection) {

	char buffer[CWS_HANDSHAKE_BUFFER_MAX] = {0};

	ssize_t bytes_read = read(connection->websocket, buffer, CWS_HANDSHAKE_BUFFER_MAX);
	if(bytes_read == -1) {
		syslog(LOG_ERR, "cwebsocket_server_read_handshake: %s", strerror(errno));
		return -1;
	}

	if(bytes_read == 0) {
		syslog(LOG_ERR, "cwebsocket_server_read_handshake: client closed the connection");
		pthread_mutex_lock(&websocket_server->lock);
		websocket_server->connections--;
		pthread_mutex_unlock(&websocket_server->lock);
		return -1;
	}

	syslog(LOG_DEBUG, "cwebsocket_server_read_handshake:\n%s", buffer);

	if(cwebsocket_server_read_handshake_handler(connection, buffer) == -1) {
		syslog(LOG_CRIT, "cwebsocket_server_read_handshake: unable to parse handshake: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int cwebsocket_server_read_handshake_handler(cwebsocket_connection *connection, const char *handshake) {
	char *ptr = NULL, *token = NULL, *seckey_response = NULL;
	for(token = strtok((char *)handshake, "\r\n"); token != NULL; token = strtok(NULL, "\r\n")) {
		if(*token == 'G' && *(token+1) == 'E' && *(token+2) == 'T' && *(token+3) == ' ') {
			if(strstr(token, "HTTP/1.1") == NULL && strstr(token, "HTTP/1.0") == NULL) {
				syslog(LOG_ERR, "cwebsocket_server_read_handshake_handler: invalid HTTP version header: %s", token);
				return -1;
			}
		} else {
			ptr = strchr(token, ' ');
			*ptr = '\0';
			if(strcasecmp(token, "Upgrade:") == 0) {
				if(strcasecmp(ptr+1, "websocket") != 0) {
					syslog(LOG_ERR, "cwebsocket_server_read_handshake_handler: invalid upgrade header");
					return -1;
				}
			}
			if(strcasecmp(token, "Connection:") == 0) {
				if(strcasecmp(ptr+1, "upgrade") != 0) {
					syslog(LOG_ERR, "cwebsocket_server_read_handshake_handler: invalid connection header");
					return -1;
				}
			}
			if(strcasecmp(token, "Sec-WebSocket-Protocol:") == 0) {
				char *client_subprotocol, *client_subprotocols = ptr+1;
				for(client_subprotocol = strtok(client_subprotocols, " "); client_subprotocol != NULL; client_subprotocol = strtok(NULL, " ")) {
					int i;
					for(i=0; i<websocket_server->subprotocol_len; i++) {
						if(strcasecmp(websocket_server->subprotocols[i]->name, client_subprotocol) == 0) {
							connection->subprotocol = websocket_server->subprotocols[i];
							syslog(LOG_DEBUG, "cwebsocket_server_read_handshake_handler: negotiated subprotocol %s", connection->subprotocol->name);
						}
					}
				}
			}
			if(strcasecmp(token, "Sec-WebSocket-Key:") == 0) {
				int key_len = strlen(ptr+1);
				char seckey[key_len];
				strcpy(seckey, ptr+1);
			    seckey_response = cwebsocket_create_key_challenge_response(seckey);
			    syslog(LOG_DEBUG, "cwebsocket_server_read_handshake_handler: generated Sec-WebSocket-Accept key %s", seckey);
			}
			if(strcasecmp(token, "Sec-WebSocket-Version:") == 0) {
				if(strcmp(ptr+1, "13") != 0) {
					syslog(LOG_ERR, "cwebsocket_server_read_handshake_handler: invalid Sec-WebSocket-Version header");
					return -1;
				}
			}
		}
	}
	if(cwebsocket_server_send_handshake_response(connection, seckey_response) == -1) {
		free(seckey_response);
		return -1;
	}
	free(seckey_response);
	return 0;
}

int cwebsocket_server_send_handshake_response(cwebsocket_connection *connection, const char *seckey) {
	char buf[512];
	snprintf(buf, 512,
	      "HTTP/1.1 101 Switching Protocols\r\n"
	      "Server: cwebsocket/%s\r\n"
	      "Upgrade: websocket\r\n"
	      "Connection: Upgrade\r\n"
	      "Sec-WebSocket-Accept: %s\r\n"
		  , CWS_VERSION, seckey);

	if(connection->subprotocol != NULL) {
		strcat(buf, "Sec-WebSocket-Protocol: ");
		strcat(buf, connection->subprotocol->name);
		strcat(buf, "\r\n");
	}

	strcat(buf, "\r\n\r\n");

	if(write(connection->websocket, buf, strlen(buf)) == -1) {
		syslog(LOG_ERR, "cwebsocket_server_send_handshake_response: %s", strerror(errno));
		return -1;
	}
	connection->state |= WEBSOCKET_STATE_OPEN;

	return 0;
}

int cwebsocket_server_close_connection(cwebsocket_connection *connection) {
	if(connection->websocket > 0) {
		if(close(connection->websocket) == -1) {
			syslog(LOG_ERR, "cwebsocket_server_close_connection: unable to close connection");
			return -1;
		}
	}
	free(connection);
	syslog(LOG_DEBUG, "cwebsocket_server_close_connection: connection closed");
	return 0;
}

int cwebsocket_server_shutdown() {
	if(websocket_server->socket > 0) {
		if(close(websocket_server->socket) == -1) {
			syslog(LOG_ERR, "cwebsocket_server_shutdown: unable to close connection");
			return -1;
		}
	}
	free(websocket_server);
	syslog(LOG_DEBUG, "cwebsocket_server_shutdown: connection closed");
	return 0;
}
