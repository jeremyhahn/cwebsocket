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
#include "bitutil.c"

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

int websocket_connect(const char *hostname, const char *port, const char *resource, void (*on_connect_callback)(int fd)) {

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

	strcpy(handshake, "GET ");strcat(handshake, resource);strcat(handshake, " HTTP/1.1\r\n");
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
		const char *errmsg_piece1 = "Unable to create socket: ";
		const char *errmsg_piece2 = strerror(errno);
		char errmsg[strlen(errmsg_piece1) + strlen(errmsg_piece2)];
		strcpy(errmsg, errmsg_piece1);
		strcat(errmsg, errmsg_piece2);
		syslog(LOG_ERR, "%s", errmsg);
		return -1;
	}

	if(connect(websocket_fd, res->ai_addr, res->ai_addrlen) != 0 ) {
		const char *errmsg_piece1 = "Unable to connect: ";
		const char *errmsg_piece2 = strerror(errno);
		char errmsg[strlen(errmsg_piece1) + strlen(errmsg_piece2)];
		strcpy(errmsg, errmsg_piece1);
		strcat(errmsg, errmsg_piece2);
		syslog(LOG_ERR, "%s", errmsg);
		return -1;
	}

    int optval = 1;
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
		const char *errmsg_piece1 = "Handshake read error: ";
		const char *errmsg_piece2 = strerror(errno);
		char errmsg[strlen(errmsg_piece1) + strlen(errmsg_piece2)];
		strcpy(errmsg, errmsg_piece1);
		strcat(errmsg, errmsg_piece2);
		syslog(LOG_ERR, "%s", errmsg);
		return -1;
	}

	if((*on_connect_callback) != NULL) {
		(*on_connect_callback)(websocket_fd);
	}

	return websocket_fd;
}

int websocket_handshake_handler(const char *message) {
	if(strstr(message, "HTTP/1.1 101 Switching Protocols") == NULL) {
		syslog(LOG_CRIT, "%s%s", "Unexpected handshake response: ", message);
		websocket_close();
		return -1;
	}
	syslog(LOG_DEBUG, "Websocket connected!\n%s", message);
	return 0;
}

int websocket_read_handshake(int fd) {

	uint32_t byte = 0;
	char data[RECEIVE_BUFFER_MAX];
	uint8_t buffer_full = 0;

	while(read(fd, data+byte, 1) > 0 && !buffer_full) {

		if(byte == RECEIVE_BUFFER_MAX) {
			syslog(LOG_ERR, "Receive buffer full. Data will be truncated to %i bytes", RECEIVE_BUFFER_MAX);
			buffer_full = 1;
		}

		if((data[byte] == '\n' && data[byte-1] == '\r' && data[byte-2] == '\n' && data[byte-3] == '\r') || buffer_full) {

			int len = byte-3;
			char buf[len+1];
			strncpy(buf, data, len);
			buf[len+1] = '\0';
			return websocket_handshake_handler(buf);
		}
		byte++;
	}
	return -1;
}

int websocket_read_data(int fd, int (*on_message_callback_ptr)(const char *message)) {

	websocket_frame frame;
	uint8_t data[RECEIVE_BUFFER_MAX];
	int frame_byte_pointer = 2;                 // Used to extract masking-key if present
	int header_length = 2;                      // The default/smallest possible header size
	const int header_length_offset = 2;         // The byte which starts the 2 byte header
	const int extended_payload16_end_byte = 4;  // The byte which completes the extended 16-bit payload length bits
	const int extended_payload64_end_byte = 10; // The byte which completes the extended 64-bit payload length bits
	int bytes_read = 0;                         // Current byte counter
	int payload_length = 0;                     // Total length of the payload/data (minus the variable length header)
	uint64_t extended_payload_length;           // Stores the extended payload length bits, if present

	while(bytes_read < header_length + payload_length) {

		int bytes = read(fd, data+bytes_read, 1);
		if(bytes == -1) {
			syslog(LOG_ERR, "Error reading data frame: %s", strerror(errno));
			return -1;
		}
		bytes_read++;

		if(bytes_read == header_length_offset ||
				bytes_read == extended_payload16_end_byte || bytes_read == extended_payload64_end_byte) {

			if(bytes_read == header_length_offset) {
syslog(LOG_DEBUG, "inside bytes_read == header_length_offset");
				// 0                   1                   2                   3
				// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				// +-+-+-+-+-------+-+-------------+-------------------------------+
				// |F|R|R|R| opcode|                                               |
				// |I|S|S|S|  (4)  |                                               |
				// |N|V|V|V|       |                                               |
				// | |1|2|3|       |                                               |
				// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
				frame.fin = (data[0] & 0x80) == 0x80;
				frame.rsv1 = (data[0] & 0x40) == 0x40;
				frame.rsv2 = (data[0] & 0x20) == 0x20;
				frame.rsv3 = (data[0] & 0x10) == 0x10;
				frame.opcode = ((data[0] & 0x08) | (data[0] & 0x04) | (data[0] & 0x02) | (data[0] & 0x01));

				// 0                   1                   2                   3
				// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				// +-+-+-+-+-------+-+-------------+-------------------------------+
				// |               |M| Payload len |                               |
				// |               |A|     (7)     |                               |
				// |               |S|             |                               |
				// |               |K|             |                               |
				// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
				frame.mask = (data[1] & 0x80) == 0x80;
				frame.payload_len = (data[1] & 0x7F);

				header_length = 2;
				payload_length = frame.payload_len;
			}

			// 0                   1                   2                   3
			// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//                                 +-------------------------------+
			//                                 |    Extended payload length    |
			//                                 |             (16/64)           |
			//                                 |   (if payload len==126/127)   |
			//                                 |                               |
			//                                 + - - - - - - - - - - - - - - - +
			if(frame.payload_len == 126 && bytes_read == extended_payload16_end_byte) {
syslog(LOG_DEBUG, "inside frame.layload_len == 126");
				extended_payload_length = 0;
				extended_payload_length |= ((uint64_t) data[2]) << 8;
				extended_payload_length |= ((uint64_t) data[3]) << 0;

				frame_byte_pointer = 4;
				header_length += 2;
				payload_length = extended_payload_length;
			}
			// 0                   1                   2                   3
			// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
			// |     Extended payload length continued, if payload len == 127  |
			// + - - - - - - - - - - - - - - - +-------------------------------+
			// |                               |                               |
			// +-------------------------------+-------------------------------+
			else if(frame.payload_len == 127 && bytes_read == extended_payload64_end_byte) {
syslog(LOG_DEBUG, "inside frame.layload_len == 127");
				extended_payload_length = 0;
				extended_payload_length |= ((uint64_t) data[2]) << 56;
				extended_payload_length |= ((uint64_t) data[3]) << 48;
				extended_payload_length |= ((uint64_t) data[4]) << 40;
				extended_payload_length |= ((uint64_t) data[5]) << 32;
				extended_payload_length |= ((uint64_t) data[6]) << 24;
				extended_payload_length |= ((uint64_t) data[7]) << 16;
				extended_payload_length |= ((uint64_t) data[8]) << 8;
				extended_payload_length |= ((uint64_t) data[9]) << 0;

				frame_byte_pointer = 10;
				header_length += 6;
				payload_length = extended_payload_length;
			}

			// 0                   1                   2                   3
			// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			// + - - - - - - - - - - - - - - - +-------------------------------+
			// |                               |Masking-key, if MASK set to 1  |
			// +-------------------------------+-------------------------------+
			// | Masking-key (continued)       |                               |
			// +-------------------------------- - - - - - - - - - - - - - - - +
			if(frame.mask) {

				//if(payload_length < 14) continue;

				frame.masking_key[0] = ((uint8_t) data[frame_byte_pointer+0]) << 0;
				frame.masking_key[1] = ((uint8_t) data[frame_byte_pointer+1]) << 0;
				frame.masking_key[2] = ((uint8_t) data[frame_byte_pointer+2]) << 0;
				frame.masking_key[3] = ((uint8_t) data[frame_byte_pointer+3]) << 0;

				frame_byte_pointer = 14;
				header_length += 4;
			}
			else {

				frame.masking_key[0] = 0;
				frame.masking_key[1] = 0;
				frame.masking_key[2] = 0;
				frame.masking_key[3] = 0;
			}
		}
	}
	if(bytes_read == -1) {
		syslog(LOG_ERR, "Error reading data frame: %s", strerror(errno));
		return -1;
	}
	if(!sizeof(data) == header_length + payload_length) {
		syslog(LOG_ERR, "Unexpected data frame checksum: sizeof(payload)=%ld, header_length+payload_length=%i", sizeof(data), header_length + payload_length);
		return -1;
	}

websocket_print_frame(&frame);
syslog(LOG_DEBUG, "header_length: %i", header_length);
syslog(LOG_DEBUG, "payload_length: %i", payload_length);
syslog(LOG_DEBUG, "extended_payload_length: %ld", extended_payload_length);
syslog(LOG_DEBUG, "frame_byte_pointer: %i", frame_byte_pointer);
syslog(LOG_DEBUG, "bytes_read=%i", bytes_read);
syslog(LOG_DEBUG, "data=%s", data);

	if(frame.fin && frame.opcode == TEXT_FRAME) {

		char payload[payload_length+1];
		memcpy(payload, &data[header_length], payload_length);
		payload[payload_length+1] = '\0';

		if((*on_message_callback_ptr) != NULL)
		    return (*on_message_callback_ptr)(payload);

		syslog(LOG_DEBUG, "No callback defined for data: %s", payload);
		return 0; // no callback defined
	}
	else {

		syslog(LOG_DEBUG, "->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>found frame.fin = false!");

		if(!frame.fin && frame.opcode == CONTINUATION) {
			syslog(LOG_DEBUG, "->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>found continuation frame!");
		}
	}

	return -1;
}

void websocket_print_frame(websocket_frame *frame) {
	syslog(LOG_DEBUG, "websocket_frame: fin=%x, rsv1=%x, rsv2=%x, rsv3=%x, opcode=%x, mask=%x, payload_len=%i\n",
			frame->fin, frame->rsv1, frame->rsv2, frame->rsv3, frame->opcode, frame->mask, frame->payload_len);
}

int websocket_data_print_handler(const char *message) {
	syslog(LOG_DEBUG, "websocket_data_print_handler: %s", message);
	return 0;
}

int websocket_data_print_size(const char *message) {
	syslog(LOG_DEBUG, "websocket_data_print_size: data= %s", message);
	return 0;
}

void websocket_close() {
	if(websocket_fd > 0) {
	    syslog(LOG_DEBUG, "Closing WebSocket");
		close(websocket_fd);
		websocket_fd = 0;
	}
}
