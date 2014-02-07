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

int cwebsocket_connect(cwebsocket_server *websocket) {

	struct sockaddr_in srvaddr;
	memset(&srvaddr, 0, sizeof(srvaddr));

	websocket->socket = socket(AF_INET, SOCK_STREAM, 0);
	if(websocket->socket == -1) {
		syslog(LOG_CRIT, "cwebsocket_connect: unable to connect: %s", strerror(errno));
		return -1;
	}

	if(websocket->port < 0 || websocket->port > 65535) {
		syslog(LOG_CRIT, "cwebsocket_connect: invalid port %i", websocket->port);
		return -1;
	}

	srvaddr.sin_family = AF_INET;
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	srvaddr.sin_port = htons(websocket->port);

	if(bind(websocket->socket, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) == -1) {
		syslog(LOG_CRIT, "cwebsocket_connect: unable to bind to socket: %s", strerror(errno));
		return -1;
	}

	if(listen(websocket->socket, CWS_MAX_QUEUED_CONNECTIONS) == -1) {
		syslog(LOG_ERR, "cwebsocket_connect: unable to set maximum queued connections: %s", strerror(errno));
		return -1;
	}

	struct ev_io w_accept;
	struct ev_loop *loop = ev_default_loop(0);
	ev_io_init(&w_accept, cwebsocket_accept, websocket->socket, EV_READ);
	ev_io_start(loop, &w_accept);

	while(1) {
		ev_loop(loop, 0);
	}

	syslog(LOG_DEBUG, "cwebsocket_connect: connected");

	return 0;
}

int cwebsocket_accept(struct ev_loop *loop, struct ev_io *watcher, int revents) {

	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	struct ev_io *w_client = (struct ev_io*) malloc (sizeof(struct ev_io));

	if(EV_ERROR & revents) {
		syslog(LOG_ERR, "cwebsocket_accept: received invalid event");
		return -1;
	}

	int fd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);
	if(fd == -1) {
		syslog(LOG_ERR, "cwebsocket_accept: %s", strerror(errno));
		return -1;
	}

	syslog(LOG_DEBUG, "cwebsocket_accept: connection accepted");

	ev_io_init(w_client, cwebsocket_read_handshake, fd, EV_READ);
	ev_io_start(loop, w_client);

	return 0;
}

int cwebsocket_read_handshake(struct ev_loop *loop, struct ev_io *watcher, int revents){

	char buffer[HANDSHAKE_BUFFER_MAX] = {0};

	if(EV_ERROR & revents) {
		syslog(LOG_ERR, "cwebsocket_accept: received invalid event");
		return -1;
	}

	ssize_t bytes_read = read(watcher->fd, buffer, HANDSHAKE_BUFFER_MAX);
	if(bytes_read == -1) {
		perror("read error");
		return -1;
	}
	if(bytes_read == 0) {
		ev_io_stop(loop, watcher);
		free(watcher);
		syslog(LOG_ERR, "cwebsocket_read_handshake: client closed the connection");
		return -1;
	}

	syslog(LOG_DEBUG, "cwebsocket_read_handshake: %s", buffer);
	return 0;
}

int cwebsocket_close(cwebsocket_server *websocket) {
	if(websocket->socket > 0) {
		if(close(websocket->socket) == -1) {
			syslog(LOG_ERR, "cwebsocket_close: unable to close connection");
			return -1;
		}
	}
	syslog(LOG_DEBUG, "cwebsocket_close: connection closed");
	return 0;
}
