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

void cwebsocket_init() {

	const rlim_t kStackSize = STACK_SIZE_MIN * 1024 * 1024;
	struct rlimit rl;
	int result;
	result = getrlimit(RLIMIT_STACK, &rl);
	if (result == 0) {
		if (rl.rlim_cur < kStackSize) {
			rl.rlim_cur = kStackSize;
			result = setrlimit(RLIMIT_STACK, &rl);
			if(result != 0) {
			   perror("Unable to set stack space.");
			   exit(1);
			}
		}
	}
	getrlimit(RLIMIT_STACK, &rl);
	syslog(LOG_DEBUG, "stack limit min=%ld, max=%ld\n", rl.rlim_cur, rl.rlim_max);
}

char* cwebsocket_base64_encode(const unsigned char *input, int length) {

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

void cwebsocket_parse_uri(const char *uri, char *hostname, char *port, char *resource) {

	if(sscanf(uri, "ws://%[^:]:%[^/]%s", hostname, port, resource) == 3) {
	}
	else if(sscanf(uri, "ws://%[^:]:%[^/]%s", hostname, port, resource) == 2) {
		strcpy(resource, "/");
	}
	else if(sscanf(uri, "ws://%[^/]%s", hostname, resource) == 2) {
		strcpy(port, "80");
	}
	else if(sscanf(uri, "ws://%[^/]", hostname) == 1) {
		strcpy(port, "80");
		strcpy(resource, "/");
	}
	else if(sscanf(uri, "ws://%[^/]", hostname) == 0) {
		printf("Invalid URL\n");
		exit(1);
	}
}

void cwebsocket_print_frame(cwebsocket_frame *frame) {
	syslog(LOG_DEBUG, "cwebsocket_print_frame: fin=%i, rsv1=%i, rsv2=%i, rsv3=%i, opcode=%#04x, mask=%i, payload_len=%i\n",
			frame->fin, frame->rsv1, frame->rsv2, frame->rsv3, frame->opcode, frame->mask, frame->payload_len);
}

int cwebsocket_connect(cwebsocket_client *websocket, const char *uri) {

	if(websocket->sock_fd > 0) {
		syslog(LOG_ERR, "socket already connected");
		return -1;
	}

	websocket->state = WEBSOCKET_STATE_CONNECTING;

	char hostname[100];
	char port[5];
	char resource[256];
	cwebsocket_parse_uri(uri, hostname, port, resource);
	cwebsocket_init();

#ifdef THREADED
	if(pthread_mutex_init(&websocket->lock, NULL) != 0) {
		syslog(LOG_ERR, "unable to initialize mutex: %s\n", strerror(errno));
		return -1;
	}
#endif

	syslog(LOG_DEBUG, "connecting to ws://%s:%s%s", hostname, port, resource);

	char handshake[1024];
    struct addrinfo hints, *servinfo;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	srand(time(NULL));
	char nonce[16];
	static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz";
	int i;
	for(i = 0; i < 16; i++) {
		nonce[i] = alphanum[rand() % 61];
	}
	char *seckey = cwebsocket_base64_encode((const unsigned char *)nonce, sizeof(nonce));

	snprintf(handshake, 1024,
		      "GET %s HTTP/1.1\r\n"
		      "Host: %s\r\n"
		      "Upgrade: websocket\r\n"
		      "Connection: Upgrade\r\n"
		      "Sec-WebSocket-Key: %s\r\n"
		      "Sec-WebSocket-Version: 13\r\n"
			  //"Sec-WebSocket-Protocol: chat, superchat\r\n"
			  "\r\n", resource, hostname, seckey);

	if(getaddrinfo(hostname, port, &hints, &servinfo) != 0 ) {
		freeaddrinfo(servinfo);
		syslog(LOG_ERR, "%s", "Host or IP not valid");
		return -1;
	}

	websocket->sock_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if(websocket->sock_fd < 0) {
		freeaddrinfo(servinfo);
		syslog(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

	if(connect(websocket->sock_fd, servinfo->ai_addr, servinfo->ai_addrlen) != 0 ) {
		freeaddrinfo(servinfo);
		syslog(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

	freeaddrinfo(servinfo);

    int optval = 1;
    setsockopt(websocket->sock_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof optval);
	if(write(websocket->sock_fd, handshake, strlen(handshake)) == -1) {
		syslog(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

	websocket->state = WEBSOCKET_STATE_CONNECTED;

	if(cwebsocket_read_handshake(websocket, seckey) == -1) {
		syslog(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

	if(websocket->onopen != NULL) {
	   websocket->onopen(websocket);
	}

	websocket->state = WEBSOCKET_STATE_OPEN;

	return 0;
}

int cwebsocket_handshake_handler(cwebsocket_client *websocket, const char *handshake_response, char *seckey) {

	syslog(LOG_DEBUG, "%s\n", handshake_response);

	char *ptr = NULL, *token = NULL;
	for(token = strtok((char *)handshake_response, "\r\n"); token != NULL; token = strtok(NULL, "\r\n")) {
		if(*token == 'H' && *(token+1) == 'T' && *(token+2) == 'T' && *(token+3) == 'P') {
			ptr = strchr(token, ' ');
			ptr = strchr(ptr+1, ' ');
			*ptr = '\0';
			if(strcmp(token, "HTTP/1.1 101") != 0 && strcmp(token, "HTTP/1.0 101") != 0) {
				if(websocket->onerror != NULL) {
				   websocket->onerror(websocket, "invalid status response code");
				   return -1;
				}
				return -1;
			}
		} else {
			ptr = strchr(token, ' ');
			*ptr = '\0';
			if(strcasecmp(token, "Upgrade:") == 0) {
				if(strcasecmp(ptr+1, "websocket") != 0) {
					if(websocket->onerror != NULL) {
					   websocket->onerror(websocket, "invalid upgrade header; expected 'websocket'.");
					   return -1;
					}
					return -1;
				}
			}
			if(strcasecmp(token, "Connection:") == 0) {
				if(strcasecmp(ptr+1, "upgrade") != 0) {
					if(websocket->onerror != NULL) {
					   websocket->onerror(websocket, "invalid connection header. expected 'upgrade'.");
					   return -1;
					}
					return -1;
				}
			}
			if(strcasecmp(token, "Sec-WebSocket-Accept:") == 0) {
				const char *GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
				const int seckey_len = strlen(seckey);
				const int total_len = seckey_len + 36;
				char sha1buf[total_len];
				memcpy(sha1buf, seckey, seckey_len);
				memcpy(&sha1buf[seckey_len], GUID, 36);
		        unsigned char sha1_bytes[20];
		        SHA1((const unsigned char *)sha1buf, total_len, sha1_bytes);
			    char *base64_encoded = cwebsocket_base64_encode((const unsigned char *)sha1_bytes, sizeof(sha1_bytes));
				if(strcmp(ptr+1, base64_encoded) != 0) {
					free(base64_encoded);
					free(seckey);
					if(websocket->onerror != NULL) {
				       websocket->onerror(websocket, "Sec-WebSocket-Accept header does not match computed sha1/base64 checksum");
					   return -1;
					}
					return -1;
				}
				free(base64_encoded);
				free(seckey);
			}
		}
	}

	syslog(LOG_DEBUG, "handshake successful");
	return 0;
}

int cwebsocket_read_handshake(cwebsocket_client *websocket, char *seckey) {

#ifdef THREADED
	pthread_mutex_lock(&websocket->lock);
#endif

	int tmplen;
	uint32_t bytes_read = 0;
	char data[HANDSHAKE_BUFFER_MAX];
	memset(&data, 0, HANDSHAKE_BUFFER_MAX);

	while(read(websocket->sock_fd, data+bytes_read, 1) > 0) {
		if(bytes_read == HANDSHAKE_BUFFER_MAX) {
			syslog(LOG_ERR, "handshake response too large. HANDSHAKE_BUFFER_MAX = %i bytes.", HANDSHAKE_BUFFER_MAX);
			return -1;
		}
		if((data[bytes_read] == '\n' && data[bytes_read-1] == '\r' && data[bytes_read-2] == '\n' && data[bytes_read-3] == '\r')) {
			break;
		}
		bytes_read++;
	}

#ifdef THREADED
	pthread_mutex_unlock(&websocket->lock);
#endif

	tmplen = bytes_read - 3;
	char buf[tmplen+1];
	strncpy(buf, data, tmplen);
	buf[tmplen+1] = '\0';

	return cwebsocket_handshake_handler(websocket, buf, seckey);
}

void cwebsocket_listen(cwebsocket_client *websocket) {
	do {
		syslog(LOG_DEBUG, "cwebsocket_listen: calling cwebsocket_read_data");
		cwebsocket_read_data(websocket);
	}
	while(websocket->state & WEBSOCKET_STATE_OPEN);
}

#ifdef THREADED
void *cwebsocket_onmessage_thread(void *ptr) {
	cwebsocket_thread_args *args = (cwebsocket_thread_args *)ptr;
	args->socket->onmessage(args->socket, args->message);
	free(args->message->payload);
	free(args->message);
	free(ptr);
	return NULL;
}
#endif

int cwebsocket_read_data(cwebsocket_client *websocket) {

        int frame_byte_pointer = 2;                 // Used to extract masking-key if present
        int header_length = 2;                      // The size of the header (header = everything up until the start of the payload)
        const int header_length_offset = 2;         // The byte which starts the 2 byte header
        const int extended_payload16_end_byte = 4;  // The byte which completes the extended 16-bit payload length bits
        const int extended_payload64_end_byte = 10; // The byte which completes the extended 64-bit payload length bits
        int bytes_read = 0;                         // Current byte counter
        int payload_length = 0;                     // Total length of the payload/data (minus the variable length header)
        int extended_payload_length;                // Stores the extended payload length bits, if present
        uint8_t data[DATA_BUFFER_MAX];              // Data stream buffer
        cwebsocket_frame frame;                     // WebSocket Data Frame - RFC 6455 Section 5.2
        memset(&frame, 0, sizeof frame);

#ifdef THREADED
        pthread_mutex_lock(&websocket->lock);
#endif

        while(bytes_read < header_length + payload_length) {

			if(bytes_read == DATA_BUFFER_MAX) {
					syslog(LOG_ERR, "cwebsocket_read_data: frame too large. RECEIVE_BUFFER_MAX = %i bytes. bytes_read=%i, header_length=%i",
							DATA_BUFFER_MAX, bytes_read, header_length);
					return -1;
			}

			int bytes = read(websocket->sock_fd, data+bytes_read, 1);

			if(bytes == 0) {
			   syslog(LOG_ERR, "cwebsocket_read_data: socket read returned 0 bytes");
			   return -1;
			}
			if(bytes == -1) {
			   syslog(LOG_ERR, "cwebsocket_read_data: error reading frame: %s", strerror(errno));
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

			if(frame.payload_len == 126 && bytes_read == extended_payload16_end_byte) {

					extended_payload_length = 0;
					extended_payload_length |= ((uint8_t) data[2]) << 8;
					extended_payload_length |= ((uint8_t) data[3]) << 0;

					frame_byte_pointer = 4;
					payload_length = extended_payload_length;
			}
			else if(frame.payload_len == 127 && bytes_read == extended_payload64_end_byte) {

#if defined(__arm__ ) || defined(__i386__)
					syslog(LOG_CRIT, "cwebsocket_read_data: payload larger than 32-bit system can handle (65536 bytes). aborting to prevent a crash...");
					return -1;
#endif

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

#ifdef THREADED
        pthread_mutex_unlock(&websocket->lock);
#endif

        char payload[payload_length];
		memcpy(payload, &data[header_length], payload_length);
		payload[payload_length] = '\0';

        if(frame.fin && frame.opcode == TEXT_FRAME) {

        	size_t count;
        	if(utf8_count_code_points((uint8_t *)payload, &count)) {
        		syslog(LOG_ERR, "received malformed utf-8 payload\n");
        		return -1;
        	}

			if(websocket->onmessage != NULL) {

			   cwebsocket_message *message = malloc(sizeof(cwebsocket_message));
			   message->opcode = frame.opcode;
			   message->payload_len = frame.payload_len;
			   message->payload = malloc(sizeof(char) * payload_length);
			   memcpy(message->payload, payload, payload_length);

#ifdef THREADED

			   cwebsocket_thread_args *args = malloc(sizeof(cwebsocket_thread_args));
			   args->socket = websocket;
			   args->message = message;

			   pthread_create(&websocket->thread, NULL, cwebsocket_onmessage_thread, (void *)args);
			   return bytes_read;
#else
			   websocket->onmessage(websocket, message);
			   free(message->payload);
			   free(message);
			   return bytes_read;
#endif
			}

			syslog(LOG_WARNING, "No on_message callback defined to handle data: %s", payload);
			return bytes_read;
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
            cwebsocket_close(websocket, "Received CLOSE control frame");
        }

        syslog(LOG_ERR, "Unsupported data frame opcode: %#04x", frame.opcode);
        cwebsocket_print_frame(&frame);
        cwebsocket_close(websocket, NULL);
        return -1;
}

ssize_t cwebsocket_write_data(cwebsocket_client *websocket, const char *data, int len) {

	//websocket_frame frame;
	uint32_t header_length = 6;           // 4 = first two bytes of header plus masking key
	unsigned long long payload_len = len;
	uint8_t header[header_length];

	// create random 4 byte masking key
	unsigned char masking_key[4];
	uint8_t mask_bit;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec * tv.tv_sec);
    mask_bit = rand();
    memcpy(masking_key, &mask_bit, 4);

    // Assemble first two bytes - 10000001 10000001
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
		header[1] = 126;
		header[2] = (payload_len >> 8) & 0xff;
		header[3] = (payload_len >> 0) & 0xff;
		header[4] = masking_key[0];
		header[5] = masking_key[1];
		header[6] = masking_key[2];
		header[7] = masking_key[3];

		header_length += 2;
	}
	else if(payload_len >= 127) {

#if defined(__arm__ ) || defined(__i386__)
		syslog(LOG_CRIT, "cwebsocket_write_data: discarding payload larger than this 32-bit system is able to handle (65536 bytes).");
		// TODO: try to chunk the data into unit32_t?
		return -1;
#endif

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
	else {
		syslog(LOG_CRIT, "cwebsocket_send_data: data too large");
		if(websocket->onerror != NULL) {
			websocket->onerror(websocket, "too much data");
		}
		return -1;
	}

	int frame_length;
	frame_length = header_length + payload_len;
	char framebuf[frame_length];
	memset(framebuf, 0, frame_length);
	memcpy(framebuf, header, header_length);
	memcpy(&framebuf[header_length], data, payload_len);

	int i;
	for(i=0; i<payload_len; i++) {
		framebuf[header_length+i] ^= masking_key[i % 4] & 0xff;
	}

#ifdef THREADED
	pthread_mutex_lock(&websocket->lock);
	ssize_t bytes_written = write(websocket->sock_fd, framebuf, frame_length);
	pthread_mutex_unlock(&websocket->lock);
#else
	ssize_t bytes_written = write(websocket->sock_fd, framebuf, frame_length);
#endif

	if(bytes_written == -1) {
		syslog(LOG_ERR, "cwebsocket_write_data: error: %s", strerror(errno));
		return -1;
	}

	syslog(LOG_DEBUG, "cwebsocket_write_data: wrote %zd bytes. data=%s\n", bytes_written, data);

	return bytes_written;
}

void cwebsocket_close(cwebsocket_client *websocket, const char *message) {

#ifdef THREADED
	// Kludge: SIGINT/SIGTERM causes a deadlock if the lock is already acquired
	if(websocket->state & WEBSOCKET_STATE_OPEN) {
		pthread_mutex_unlock(&websocket->lock);
	}
#endif
	websocket->state = WEBSOCKET_STATE_CLOSING;
	syslog(LOG_DEBUG, "cwebsocket_close: closing websocket: %s", message);
	// close the socket
	if(websocket->sock_fd > 0) {
		// Send close frame
		char close_frame[6];
		int mask_int;
		struct timeval tv;
		gettimeofday(&tv, NULL);
		srand(tv.tv_sec * tv.tv_usec);
		mask_int = rand();
		memcpy(close_frame+2, &mask_int, 4);
		close_frame[0] = 0x88;
		close_frame[1] = 0x80;
#ifdef THREADED
		pthread_mutex_lock(&websocket->lock);
		if(write(websocket->sock_fd, close_frame, 6)) {
			syslog(LOG_DEBUG, "cwebsocket_close: sent CLOSE control frame");
		}
		pthread_mutex_unlock(&websocket->lock);
#else
		if(write(websocket->sock_fd, close_frame, 6)) {
			syslog(LOG_DEBUG, "cwebsocket_close: sent CLOSE control frame");
		}
#endif
		if(close(websocket->sock_fd) == -1) {
			syslog(LOG_ERR, "cwebsocket_close: error closing websocket: %s", strerror(errno));
		}
	}
	if(websocket->onclose != NULL) {
	   websocket->onclose(websocket, message);
	}
	websocket->state = WEBSOCKET_STATE_CLOSED;
}
