/**
 *  cwebsocket - A fast, lightweight ANSI C WebSocket
 *  RFC6455 - The WebSocket Protocol - http://tools.ietf.org/html/rfc6455
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

#include "client.h"

void websocket_generate_seckey(char *key) {

	static const char alphanum[] =
	        "0123456789"
	        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	        "abcdefghijklmnopqrstuvwxyz";

	int i;
	for(i = 0; i < 16; i++) {
		key[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	//key = base64_encode(key);

	key[16] = 0;

	// Hard coded for now
	key = "dGhlIHNhbXBsZSBub25jZQ==";
}

int websocket_connect(char *hostname, char *port) {

	if(websocket_fd > 0) {
		const char *errmsg = "WebSocket already connected";
		//fprintf(stderr, errmsg);
		syslog(LOG_ERR, "%s", errmsg);
		return -1;
	}

	char handshake[1024];
    struct addrinfo hints, *res;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	// Generate security key
	//const char *sec_key = "dGhlIHNhbXBsZSBub25jZQ==";
	char seckey[50];
	websocket_generate_seckey(seckey);
	const char *line_break = "\r\n";

	strcpy(handshake, "GET /udsflash/tune/dashboard HTTP/1.1\r\n");
	strcat(handshake, "Host: ");strcat(handshake, hostname);strcat(handshake, line_break);
	strcat(handshake, "Upgrade: websocket\r\n");
	strcat(handshake, "Connection: Upgrade\r\n");
	strcat(handshake, "Sec-WebSocket-Key: ");strcat(handshake, seckey);strcat(handshake, line_break);
	strcat(handshake, "Sec-WebSocket-Version: 13\r\n");
	//strcat(handshake, "Sec-WebSocket-Protocol: chat");
	strcat(handshake, "X-Auth-Token: abc123\r\n");
	strcat(handshake, "\r\n");

	if(getaddrinfo(hostname, port, &hints, &res) != 0 ) {
		const char *errmsg = "Host or IP not valid";
		//fprintf(stderr, errmsg);
		syslog(LOG_ERR, "%s", errmsg);
		return -1;
	}

	websocket_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(websocket_fd < 0) {
		syslog(LOG_ERR, "%s", "Unable to create local socket");
		return -1;
	}

	if(connect(websocket_fd, res->ai_addr, res->ai_addrlen) != 0 ) {
		syslog(LOG_ERR, "%s", "Unable to connect to remote server");
		return -1;
	}

    int optval = 1; //is
    setsockopt(websocket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
	if(write(websocket_fd, handshake, strlen(handshake)) == -1) {
		const char *errmsg_piece1 = "Unable to send handshake: ";
		const char *errmsg_piece2 = strerror(errno);
		char errmsg[strlen(errmsg_piece1) + strlen(errmsg_piece2)];
		strcpy(errmsg, errmsg_piece1);
		strcat(errmsg, errmsg_piece2);
		syslog(LOG_ERR, "%s", errmsg);
		return -1;
	}

	if(websocket_read_handshake(websocket_fd) == -1) {
		syslog(LOG_ERR, "Handshake read error");
		return -1;
	}

	return websocket_fd;
}

int websocket_handshake_handler(const char *message) {
	if(strstr(message, "HTTP/1.1 101 Switching Protocols") == NULL) {
		syslog(LOG_CRIT, "%s", "Unable to establish websocket connection");
		websocket_close();
		return -1;
	}
	syslog(LOG_DEBUG, "Websocket connected!\n%s", message);
	return 0;
}

int websocket_read_handshake(int fd) {

	int i = 0;
	unsigned int buffer_size = 1024;
	char data[buffer_size];

	while(read(fd, data+i, 1) > 0) {

		if(i == buffer_size) {
			// TODO http://stackoverflow.com/questions/2937409/resizing-an-array-with-c
			syslog(LOG_ERR, "Max message size reached. Remaining data will be truncated.");
		}
		if(i > buffer_size) continue; // Ignore overflow data for now

		if((data[i] == '\n' && data[i-1] == '\r' && data[i-2] == '\n' && data[i-3] == '\r')) {

			int len = i-3;
			char buf[len+1];
			strncpy(buf, data, len);
			buf[len+1] = '\0';
			return websocket_handshake_handler(buf);
		}
		i++;
	}
	return -1;
}

int websocket_read(int fd, int (*websocket_message_handler_ptr)(const char *message)) {

	//syslog(LOG_DEBUG, "websocket_read fired");

	int i = 0;
	unsigned int header_size = 0;
	int buffer_size = 1024;
	char data[buffer_size];
	opcode_t TEXT_FRAME = 0x01;
	websocket_frame frame;

	while(read(fd, data+i, 1) > 0) {

		if(i == buffer_size) {
			syslog(LOG_ERR, "Max message size reached. Remaining data will be truncated."); // sizeof(int)*buffer_size);
		}
		if(i > buffer_size) continue; // Ignore overflow data for now

		if(i == 0) {

			// First byte
			//  0 1 2 3 4 5 6 7
			// +-+-+-+-+-------+
			// |F|R|R|R| opcode|
			// |I|S|S|S|  (4)  |
			// |N|V|V|V|       |
			// | |1|2|3|       |
			// +-+-+-+-+--------
			frame.fin = (data[0] & 0x80) == 0x80;
			frame.opcode = ((data[0] & 0x08) | (data[0] & 0x04) | (data[0] & 0x02) | (data[0] & 0x01));
	 }
	 else if(i == 1) { // Second byte

		 // Second byte
		 //  0 1 2 3 4 5 6 7
		 // +-+-------------+
		 // |M| Payload len |
		 // |A|     (7)     |
		 // |S|             |
		 // |K|             |
		 // +-+-+-+-+-------+
		 frame.mask = (data[1] & 0x80) == 0x80;
		 frame.payload_len = (data[1] & 0x7f);

		 header_size = 2 + (frame.payload_len == 126 ? 2 : 0)
						 + (frame.payload_len == 127 ? 6 : 0)
						 + (frame.mask ? 4 : 0);
	 }

	 unsigned int data_length = frame.payload_len + header_size - 1;
	 if(frame.opcode == TEXT_FRAME && frame.fin && (i == data_length || i == buffer_size)) {

		 char *payload[frame.payload_len];
		 memcpy(payload, &data[header_size], data_length);

		 // websocket_print_frame(&frame);

		 //i=0;
		 //frame.fin = 0;
		 //frame.opcode = 0;
		 //frame.mask = 0;
		 //frame.payload_len = 0;
		 //memset(data, 0, buffer_size);
		 return (*websocket_message_handler_ptr)(payload);
	  }

	  //websocket_print_frame(&frame);

	  i++;
	}

	syslog(LOG_ERR, "Unhandled websocket_read. Closing connection.");
	return -1;
}

void websocket_print_frame(websocket_frame *frame) {
	printf("websocket_frame: fin=%x, opcode=%x, mask=%x, payload_len=%i\n", frame->fin, frame->opcode, frame->mask, frame->payload_len);
}

int websocket_message_print_handler(const char *message) {
	syslog(LOG_DEBUG, "websocket_message_print_handler: %s", message);
	return 0;
}

void websocket_close() {
	syslog(LOG_DEBUG, "Closing WebSocket");
	if(websocket_fd > 0) {
		close(websocket_fd);
		websocket_fd = 0;
	}
}
