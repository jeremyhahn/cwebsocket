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

#include "cwebsocket.h"

char *cwebsocket_base64_encode(const unsigned char *input, int length) {

	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buff = (char *)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = 0;

	BIO_free_all(b64);

	return buff;
}

int cwebsocket_connect(const char *hostname, const char *port, const char *path) {

	syslog(LOG_DEBUG, "Connecting to ws://%s:%s%s", hostname, port, path);

	int websocket_fd;
	char handshake[1024];
    struct addrinfo hints, *res;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	// Generate Sec-WebSocket-Key
	srand(time(NULL));
	char nonce[16];
	static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz";
	int i;
	for(i = 0; i < 16; i++) {
		nonce[i] = alphanum[rand() % 61];
	}
	char* seckey = (char*)malloc(100);
	seckey = cwebsocket_base64_encode((const unsigned char *)nonce, sizeof(nonce));

	snprintf(handshake, 1024,
		      "GET %s HTTP/1.1\r\n"
		      "Host: %s\r\n"
		      "Upgrade: websocket\r\n"
		      "Connection: Upgrade\r\n"
		      "Sec-WebSocket-Key: %s\r\n"
		      "Sec-WebSocket-Version: 13\r\n"
			  //"Sec-WebSocket-Protocol: chat, superchat\r\n"
			  "\r\n", path, hostname, seckey);

	if(getaddrinfo(hostname, port, &hints, &res) != 0 ) {
		const char *errmsg = "Host or IP not valid";
		syslog(LOG_ERR, "%s", errmsg);
		return -1;
	}

	websocket_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(websocket_fd < 0) {
		syslog(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

	if(connect(websocket_fd, res->ai_addr, res->ai_addrlen) != 0 ) {
		syslog(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

    int optval = 1;
    setsockopt(websocket_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof optval);
	if(write(websocket_fd, handshake, strlen(handshake)) == -1) {
		syslog(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

	//if(fcntl(websocket_fd, F_SETFL, O_NONBLOCK) == -1) {
	//	syslog(LOG_ERR, "%s", strerror(errno));
	//}

	if(cwebsocket_read_handshake(websocket_fd, seckey) == -1) {
		syslog(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

	if(on_connect_callback_ptr != NULL) {
	   (*on_connect_callback_ptr)(websocket_fd);
	}

	return websocket_fd;
}

int cwebsocket_handshake_handler(const char *handshake_response, char *seckey) {

	syslog(LOG_DEBUG, "%s\n", handshake_response);

	char *ptr = NULL, *token = NULL;
	for(token = strtok((char *)handshake_response, "\r\n"); token != NULL; token = strtok(NULL, "\r\n")) {
		if(*token == 'H' && *(token+1) == 'T' && *(token+2) == 'T' && *(token+3) == 'P') {
			ptr = strchr(token, ' ');
			ptr = strchr(ptr+1, ' ');
			*ptr = '\0';
			if(strcmp(token, "HTTP/1.1 101") != 0 && strcmp(token, "HTTP/1.0 101") != 0) {
				if(on_error_callback_ptr != NULL) {
				   return on_error_callback_ptr("Invalid HTTP status response");
				}
				return -1;
			}
		} else {
			ptr = strchr(token, ' ');
			*ptr = '\0';
			if(strcmp(token, "Upgrade:") == 0) {
				if(strcmp(ptr+1, "websocket") != 0 && strcmp(ptr+1, "Websocket") != 0) {
					if(on_error_callback_ptr != NULL) {
					   return on_error_callback_ptr("Invalid Upgrade header. Expected 'websocket'.");
					}
					return -1;
				}
			}
			if(strcmp(token, "Connection:") == 0) {
				if(strcmp(ptr+1, "upgrade") != 0 && strcmp(ptr+1, "Upgrade") != 0) {
					if(on_error_callback_ptr != NULL) {
					   return on_error_callback_ptr("Invalid Connection header. Expected 'upgrade'.");
					}
					return -1;
				}
			}
			if(strcmp(token, "Sec-WebSocket-Accept:") == 0) {

				const char *GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
				const int seckey_len = strlen(seckey);
				const int total_len = seckey_len + 36;

				char sha1buf[total_len];
				memcpy(sha1buf, seckey, seckey_len);
				memcpy(&sha1buf[seckey_len], GUID, 36);

		        unsigned char sha1_bytes[20];
		        SHA1((const unsigned char *)sha1buf, total_len, sha1_bytes);

			    char* base64_encoded = (char*)malloc(512);
			    base64_encoded = cwebsocket_base64_encode((const unsigned char *)sha1_bytes, sizeof(sha1_bytes));

				if(strcmp(ptr+1, base64_encoded) != 0) {
					free(base64_encoded);
					free(seckey);
					if(on_error_callback_ptr != NULL) {
						return on_error_callback_ptr("Invalid Sec-WebSocket-Accept header. Does not match computed sha1/base64 checksum.");
					}
					return -1;
				}
				free(base64_encoded);
				free(seckey);
			}
		}
	}

	syslog(LOG_DEBUG, "Handshake successful\n%s", handshake_response);
	return 0;
}

int cwebsocket_read_handshake(int fd, char *seckey) {

	uint32_t byte = 0;
	char data[HANDSHAKE_BUFFER_MAX];

	while(read(fd, data+byte, 1) > 0) {

		if(byte == HANDSHAKE_BUFFER_MAX) {
			syslog(LOG_ERR, "Handshake response too large. HANDSHAKE_BUFFER_MAX = %i bytes.", HANDSHAKE_BUFFER_MAX);
			return -1;
		}

		if((data[byte] == '\n' && data[byte-1] == '\r' && data[byte-2] == '\n' && data[byte-3] == '\r')) {

			int len = byte-3;
			char buf[len+1];
			strncpy(buf, data, len);
			buf[len+1] = '\0';
			return cwebsocket_handshake_handler(buf, seckey);
		}
		byte++;
	}
	return -1;
}

int cwebsocket_read_data(int fd) {

	websocket_frame frame;                      // WebSocket Data Frame - RFC 6455 Section 5.2
	uint8_t data[DATA_BUFFER_MAX];              // Data stream buffer
	int frame_byte_pointer = 2;                 // Used to extract masking-key if present
	int header_length = 2;                      // The size of the header (header = everything up until the start of the payload)
	const int header_length_offset = 2;         // The byte which starts the 2 byte header
	const int extended_payload16_end_byte = 4;  // The byte which completes the extended 16-bit payload length bits
	const int extended_payload64_end_byte = 10; // The byte which completes the extended 64-bit payload length bits
	int bytes_read = 0;                         // Current byte counter
	int payload_length = 0;                     // Total length of the payload/data (minus the variable length header)
	uint64_t extended_payload_length;           // Stores the extended payload length bits, if present

	frame.fin = 0;
	frame.rsv1 = 0;
	frame.rsv2 = 0;
	frame.rsv3 = 0;
	frame.opcode = 0;
	frame.mask = 0;
	frame.payload_len = 0;

	while(bytes_read < header_length + payload_length) {

		if(bytes_read == DATA_BUFFER_MAX) {
			syslog(LOG_ERR, "Data frame too large. RECEIVE_BUFFER_MAX = %i bytes. header_length=%i", DATA_BUFFER_MAX, header_length);
			// TODO Buffer large frames to the heap/filesystem...
			return -1;
		}

		int bytes = read(fd, data+bytes_read, 1);
		if(bytes == 0) {
			syslog(LOG_ERR, "The remote host has closed the connection");
			return -1;
		}
		if(bytes == -1) {
			syslog(LOG_ERR, "Error reading data frame: %s", strerror(errno));
			return -1;
		}
		bytes_read++;

		if(bytes_read == header_length_offset) {

			frame.fin = (data[0] & 0x80) == 0x80;
			frame.rsv1 = (data[0] & 0x40) == 0x40;
			frame.rsv2 = (data[0] & 0x20) == 0x20;
			frame.rsv3 = (data[0] & 0x10) == 0x10;
			frame.opcode = ((data[0] & 0x08) | (data[0] & 0x04) | (data[0] & 0x02) | (data[0] & 0x01));
			frame.mask = (data[1] & 0x80) == 0x80;
			frame.payload_len = (data[1] & 0x7F);

			header_length = 2 + (frame.payload_len == 126 ? 2 : 0) + (frame.payload_len == 127 ? 6 : 0) + (frame.mask ? 4 : 0);
			payload_length = frame.payload_len;
			extended_payload_length = 0;
		}

		if(payload_length == 126 && bytes_read == extended_payload16_end_byte) {

			extended_payload_length = 0;
			extended_payload_length |= ((uint64_t) data[2]) << 8;
			extended_payload_length |= ((uint64_t) data[3]) << 0;

			frame_byte_pointer = 4;
			payload_length = extended_payload_length;
		}
		else if(payload_length == 127 && bytes_read == extended_payload64_end_byte) {

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
			payload_length = extended_payload_length;
		}

		if(frame.mask) {

			frame.masking_key[0] = ((uint32_t) data[frame_byte_pointer+0]) << 0;
			frame.masking_key[1] = ((uint32_t) data[frame_byte_pointer+1]) << 0;
			frame.masking_key[2] = ((uint32_t) data[frame_byte_pointer+2]) << 0;
			frame.masking_key[3] = ((uint32_t) data[frame_byte_pointer+3]) << 0;

			frame_byte_pointer = 14;
		}
		else {

			frame.masking_key[0] = 0;
			frame.masking_key[1] = 0;
			frame.masking_key[2] = 0;
			frame.masking_key[3] = 0;
		}
	}

	if(frame.fin && frame.opcode == TEXT_FRAME) {

		char payload[payload_length];
		memcpy(payload, &data[header_length], payload_length);
		payload[payload_length] = '\0';

		if(on_message_callback_ptr != NULL) {
		   return (*on_message_callback_ptr)(fd, payload);
		}

		syslog(LOG_WARNING, "No on_message callback defined to handle data: %s", payload);
		return 0;
	}
	else if(frame.opcode == BINARY_FRAME) {
		syslog(LOG_DEBUG, "Received unsupported BINARY_FRAME opcode");
	}
	else if(frame.opcode == CONTINUATION) {
		syslog(LOG_DEBUG, "Received unsupported CONTINUATION opcode");
	}
	else if(frame.opcode == PING) {
		syslog(LOG_DEBUG, "Received PING control frame");
	}
	else if(frame.opcode == PONG) {
		syslog(LOG_DEBUG, "Received PONG control frame");
	}
	else if(frame.opcode == CLOSE) {
		syslog(LOG_DEBUG, "Received CLOSE control frame");
		cwebsocket_close(fd, "hard_coded_close_message_for_now");
	}
	else {
		syslog(LOG_ERR, "Unsupported data frame opcode: %x", frame.opcode);
		cwebsocket_print_frame(&frame);
		cwebsocket_close(fd, NULL);
	}

	return -1;
}

ssize_t cwebsocket_write_data(int fd, char *data, int len) {

	//websocket_frame frame;
	uint32_t header_length = 6;           // 4 = first two bytes of header plus masking key
	uint64_t payload_len = len;
	uint8_t header[header_length];

	// create random 4 byte masking key
	unsigned char masking_key[4];
	uint8_t mask_bit;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec * tv.tv_sec);
    mask_bit = rand();
    memcpy(masking_key, &mask_bit, 4);

    // Assemble first two bytes - 1000001 10000001
	header[0] = 0x81;
	/*
	frame.fin = ((uint8_t) 1) << 0;
	frame.mask = ((uint8_t) 1) << 0;
	frame.rsv1 = 0;
	frame.rsv2 = 0;
	frame.rsv3 = 0;
	frame.opcode = TEXT_FRAME;
	frame.mask = 1 << 0;
	frame.payload_len = payload_len;
	*/

	if(payload_len < 126) {
		header[1] = payload_len | 0x80;
		header[2] = masking_key[0];
		header[3] = masking_key[1];
		header[4] = masking_key[2];
		header[5] = masking_key[3];
	}
	else if(payload_len == 126) {
		//frame.payload_len = 126;
		header[1] = 126 | 0x80;
		header[2] = (payload_len >> 8) & 0xff;
		header[3] = (payload_len >> 0) & 0xff;
		header[4] = masking_key[0];
		header[5] = masking_key[1];
		header[6] = masking_key[2];
		header[7] = masking_key[3];

		header_length += 2;
	}
	else {
		//frame.payload_len = 127;
		header[1] = 127;
		header[2] = (payload_len >> 56) & 0xff;
		header[3] = (payload_len >> 48) & 0xff;
		header[4] = (payload_len >> 40) & 0xff;
		header[5] = (payload_len >> 32) & 0xff;
		header[6] = (payload_len >> 24) & 0xff;
		header[7] = (payload_len >> 16) & 0xff;
		header[8] = (payload_len >>  8) & 0xff;
		header[9] = (payload_len >>  0) & 0xff;
		header[10] = masking_key[0];
		header[11] = masking_key[1];
		header[12] = masking_key[2];
		header[13] = masking_key[3];

		header_length += 8;
	}

	int frame_length = header_length + payload_len;

	char framebuf[frame_length];
	memcpy(framebuf, header, header_length);
	memcpy(&framebuf[header_length], data, payload_len);

	int i;
	for(i=0; i<payload_len; i++) {
		framebuf[header_length+i] ^= masking_key[i % 4] & 0xff;
	}

	ssize_t bytes_written = write(fd, framebuf, frame_length);
	if(bytes_written == -1) {
		syslog(LOG_ERR, "Error writing data: %s", strerror(errno));
		return -1;
	}

	return bytes_written;
}

void cwebsocket_print_frame(websocket_frame *frame) {
	syslog(LOG_DEBUG, "websocket_frame: fin=%x, rsv1=%x, rsv2=%x, rsv3=%x, opcode=%x, mask=%x, payload_len=%i\n",
			frame->fin, frame->rsv1, frame->rsv2, frame->rsv3, frame->opcode, frame->mask, frame->payload_len);
}

void cwebsocket_close(int fd, const char *message) {
	syslog(LOG_DEBUG, "Closing WebSocket: %s", message);
	if(fd > 0) {
		if(close(fd) == -1) {
			syslog(LOG_ERR, "Error closing websocket: %s", strerror(errno));
		}
	}
	if(on_close_callback_ptr != NULL) {
	   (*on_close_callback_ptr)(fd, message);
	}
}
