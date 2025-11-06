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

// Define _GNU_SOURCE before any includes to enable strcasestr and other GNU extensions
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "client.h"

// For unit testing, make static functions visible
#ifdef UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

STATIC int cwebsocket_client_random_bytes(uint8_t *buffer, size_t length);
STATIC void cwebsocket_client_reset_fragments(cwebsocket_client *websocket);
STATIC int cwebsocket_client_ensure_fragment_capacity(cwebsocket_client *websocket, size_t required);
static int cwebsocket_client_dispatch_message(cwebsocket_client *websocket, opcode frame_opcode, uint8_t *payload, uint64_t payload_len, int fin);
static int cwebsocket_client_handle_control_frame(cwebsocket_client *websocket, opcode frame_opcode, const uint8_t *payload, uint64_t payload_len);
STATIC int cwebsocket_client_is_control_frame(opcode frame_opcode);
static int cwebsocket_client_read_exact(cwebsocket_client *websocket, uint8_t *buffer, size_t length);
STATIC int cwebsocket_header_contains_token(const char *header_value, const char *token);
STATIC void cwebsocket_trim(char *value);
static ssize_t cwebsocket_client_write_all(cwebsocket_client *websocket, const uint8_t *buffer, size_t length);
STATIC int cwebsocket_is_valid_close_code(uint16_t code);
static void cwebsocket_client_drop(cwebsocket_client *websocket, const char *reason);

void cwebsocket_client_init(cwebsocket_client *websocket, cwebsocket_subprotocol *subprotocols[], int subprotocol_len) {
	websocket->fd = 0;
	websocket->retry = 0;
	websocket->uri = '\0';
	websocket->flags = 0;
	websocket->state = WEBSOCKET_STATE_CLOSED;
	websocket->subprotocol_len = subprotocol_len;
	websocket->subprotocol = NULL;
	websocket->fragment_buffer = NULL;
	websocket->fragment_length = 0;
	websocket->fragment_capacity = 0;
	websocket->fragment_opcode = CONTINUATION;
	websocket->fragment_in_progress = 0;
	websocket->close_sent = 0;
	websocket->close_received = 0;
	websocket->protocol_error = 0;
	websocket->pmdeflate_client_window_bits = 15; // Default: maximum window size
	websocket->pmdeflate_server_window_bits = 15; // Default: maximum window size
#ifdef ENABLE_THREADS
	websocket->thread = 0;
#endif
	int i;
	for(i=0; i<subprotocol_len; i++) {
		syslog(LOG_DEBUG, "cwebsocket_client_init: loading subprotocol %s", subprotocols[i]->name);
		websocket->subprotocols[i] = subprotocols[i];
	}
	const rlim_t kStackSize = CWS_STACK_SIZE_MIN * 1024 * 1024;
	struct rlimit rl;
	int result;
	result = getrlimit(RLIMIT_STACK, &rl);
	if (result == 0) {
		if (rl.rlim_cur < kStackSize) {
			rl.rlim_cur = kStackSize;
			result = setrlimit(RLIMIT_STACK, &rl);
			if(result != 0) {
			   syslog(LOG_CRIT, "cwebsocket_client_init: unable to set stack space");
			   exit(1);
			}
		}
	}
	getrlimit(RLIMIT_STACK, &rl);
	syslog(LOG_DEBUG, "cwebsocket_client_init: stack limit min=%ld, max=%ld\n", rl.rlim_cur, rl.rlim_max);
}

void cwebsocket_client_parse_uri(cwebsocket_client *websocket, const char *uri,
		char *hostname, char *port, char *resource, char *querystring) {

	(void)websocket;

	if(sscanf(uri, "ws://%[^:]:%[^/]%[^?]%s", hostname, port, resource, querystring) == 4) {
		return;
	}
	else if(sscanf(uri, "ws://%[^:]:%[^/]%s", hostname, port, resource) == 3) {
		strcpy(querystring, "");
		return;
	}
	else if(sscanf(uri, "ws://%[^:]:%[^/]%s", hostname, port, resource) == 2) {
		strcpy(resource, "/");
		strcpy(querystring, "");
		return;
	}
	else if(sscanf(uri, "ws://%[^/]%s", hostname, resource) == 2) {
		strcpy(port, "80");
		strcpy(querystring, "");
		return;
	}
	else if(sscanf(uri, "ws://%[^/]", hostname) == 1) {
		strcpy(port, "80");
		strcpy(resource, "/");
		strcpy(querystring, "");
		return;
	}
#ifdef ENABLE_SSL
	else if(sscanf(uri, "wss://%[^:]:%[^/]%[^?]%s", hostname, port, resource, querystring) == 4) {
		websocket->flags |= WEBSOCKET_FLAG_SSL;
		return;
	}
	else if(sscanf(uri, "wss://%[^:]:%[^/]%s", hostname, port, resource) == 3) {
		strcpy(querystring, "");
		websocket->flags |= WEBSOCKET_FLAG_SSL;
		return;
	}
	else if(sscanf(uri, "wss://%[^:]:%[^/]%s", hostname, port, resource) == 2) {
		strcpy(resource, "/");
		strcpy(querystring, "");
		websocket->flags |= WEBSOCKET_FLAG_SSL;
		return;
	}
	else if(sscanf(uri, "wss://%[^/]%s", hostname, resource) == 2) {
		strcpy(port, "443");
		strcpy(querystring, "");
		websocket->flags |= WEBSOCKET_FLAG_SSL;
		return;
	}
	else if(sscanf(uri, "wss://%[^/]", hostname) == 1) {
		strcpy(port, "443");
		strcpy(resource, "/");
		strcpy(querystring, "");
		websocket->flags |= WEBSOCKET_FLAG_SSL;
		return;
	}
#endif
	else if(strstr(uri, "wss://") != NULL) {
		syslog(LOG_CRIT, "cwebsocket_client_parse_uri: recompile with SSL support to use a secure connection");
		exit(1);
	}
	else {
		syslog(LOG_CRIT, "cwebsocket_client_parse_uri: invalid websocket URL\n");
		exit(1);
	}
}

int cwebsocket_client_connect(cwebsocket_client *websocket) {

	if(websocket->state & WEBSOCKET_STATE_CONNECTED) {
		syslog(LOG_CRIT, "cwebsocket_client_connect: socket already connected");
		return -1;
	}

	if(websocket->state & WEBSOCKET_STATE_CONNECTING) {
		syslog(LOG_CRIT, "cwebsocket_client_connect: socket already connecting");
		return -1;
	}

	if(websocket->state & WEBSOCKET_STATE_OPEN) {
		syslog(LOG_CRIT, "cwebsocket_client_connect: socket already open");
		return -1;
	}

#ifdef ENABLE_THREADS
	if(pthread_mutex_init(&websocket->lock, NULL) != 0) {
		syslog(LOG_ERR, "cwebsocket_client_connect: unable to initialize websocket mutex: %s\n", strerror(errno));
		cwebsocket_client_onerror(websocket, strerror(errno));
		return -1;
	}
	if(pthread_mutex_init(&websocket->write_lock, NULL) != 0) {
		syslog(LOG_ERR, "cwebsocket_client_connect: unable to initialize websocket write mutex: %s\n", strerror(errno));
		cwebsocket_client_onerror(websocket, strerror(errno));
		return -1;
	}
	pthread_mutex_lock(&websocket->lock);
	websocket->state = WEBSOCKET_STATE_CONNECTING;
	pthread_mutex_unlock(&websocket->lock);
#else
	websocket->state = WEBSOCKET_STATE_CONNECTING;
#endif

	cwebsocket_client_reset_fragments(websocket);
	websocket->close_sent = 0;
	websocket->close_received = 0;
	if(websocket->subprotocol_len > 0) {
		websocket->subprotocol = NULL;
	}

	char hostname[100];
	char port[6];
	char resource[256];
	char querystring[256];
	cwebsocket_client_parse_uri(websocket, websocket->uri, hostname, port, resource, querystring);

	syslog(LOG_DEBUG, "cwebsocket_client_connect: hostname=%s, port=%s, resource=%s, querystring=%s, secure=%i\n",
			hostname, port, resource, querystring, (websocket->flags & WEBSOCKET_FLAG_SSL));

	char handshake[1024];
	struct addrinfo hints, *servinfo = NULL;
	memset(handshake, 0, sizeof(handshake));

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	uint8_t nonce[16];
	if(cwebsocket_client_random_bytes(nonce, sizeof(nonce)) != 0) {
		syslog(LOG_CRIT, "cwebsocket_client_connect: unable to generate nonce");
		cwebsocket_client_onerror(websocket, "unable to generate nonce");
		return -1;
	}
	char *seckey = cwebsocket_base64_encode((const unsigned char *)nonce, sizeof(nonce));
	if(seckey == NULL) {
		syslog(LOG_CRIT, "cwebsocket_client_connect: unable to base64 encode nonce");
		cwebsocket_client_onerror(websocket, "unable to encode nonce");
		return -1;
	}

    int written = snprintf(handshake, sizeof(handshake),
              "GET %s%s HTTP/1.1\r\n"
              "Host: %s:%s\r\n"
              "Upgrade: websocket\r\n"
              "Connection: Upgrade\r\n"
              "Sec-WebSocket-Key: %s\r\n"
              "Sec-WebSocket-Version: 13\r\n",
              resource, querystring, hostname, port, seckey);
    if(written < 0 || (size_t)written >= sizeof(handshake)) {
        syslog(LOG_CRIT, "cwebsocket_client_connect: handshake buffer too small");
        cwebsocket_client_onerror(websocket, "handshake buffer too small");
        free(seckey);
        return -1;
    }
    // Offer permessage-deflate to support Autobahn compression cases.
    // Include client_max_window_bits (no value = support 8-15, server chooses)
    // and server_max_window_bits=15 for maximum compression ratio.
    // Also request both client/server_no_context_takeover for simplicity.
    {
        size_t offset = (size_t)written;
        size_t remaining = sizeof(handshake) - offset;
        int need = snprintf(handshake + offset, remaining,
                            "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits; server_max_window_bits=15; client_no_context_takeover; server_no_context_takeover\r\n");
        if(need < 0 || (size_t)need >= remaining) {
            syslog(LOG_CRIT, "cwebsocket_client_connect: handshake buffer too small for extensions header");
            cwebsocket_client_onerror(websocket, "handshake buffer too small");
            free(seckey);
            return -1;
        }
        written += need;
    }

    if(websocket->subprotocol_len > 0) {
		size_t offset = (size_t)written;
		size_t remaining = sizeof(handshake) - offset;
		size_t i;
		int need = snprintf(handshake + offset, remaining, "Sec-WebSocket-Protocol: ");
		if(need < 0 || (size_t)need >= remaining) {
			syslog(LOG_CRIT, "cwebsocket_client_connect: handshake buffer too small for subprotocol header");
			cwebsocket_client_onerror(websocket, "handshake buffer too small");
			free(seckey);
			return -1;
		}
		offset += (size_t)need;
		remaining = sizeof(handshake) - offset;
		for(i = 0; i < websocket->subprotocol_len; i++) {
			const char *sep = (i == websocket->subprotocol_len - 1) ? "\r\n" : ", ";
			need = snprintf(handshake + offset, remaining, "%s%s", websocket->subprotocols[i]->name, sep);
			if(need < 0 || (size_t)need >= remaining) {
				syslog(LOG_CRIT, "cwebsocket_client_connect: handshake buffer too small for subprotocol value");
				cwebsocket_client_onerror(websocket, "handshake buffer too small");
				free(seckey);
				return -1;
			}
			offset += (size_t)need;
			remaining = sizeof(handshake) - offset;
		}
		written = (int)offset;
	}

    if((size_t)written + 2 >= sizeof(handshake)) {
        syslog(LOG_CRIT, "cwebsocket_client_connect: handshake buffer too small for terminator");
        cwebsocket_client_onerror(websocket, "handshake buffer too small");
        free(seckey);
        return -1;
    }
    strcat(handshake, "\r\n");

	int gai_err = getaddrinfo(hostname, port, &hints, &servinfo);
	if(gai_err != 0 ) {
		syslog(LOG_ERR, "cwebsocket_client_connect: %s", gai_strerror(gai_err));
		cwebsocket_client_onerror(websocket, gai_strerror(gai_err));
		free(seckey);
		return -1;
	}

	websocket->fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if(websocket->fd < 0) {
		freeaddrinfo(servinfo);
		syslog(LOG_ERR, "cwebsocket_client_connect: %s", strerror(errno));
		cwebsocket_client_onerror(websocket, strerror(errno));
		free(seckey);
		return -1;
	}

	if(connect(websocket->fd, servinfo->ai_addr, servinfo->ai_addrlen) != 0 ) {
		syslog(LOG_ERR, "cwebsocket_client_connect: %s", strerror(errno));
		cwebsocket_client_onerror(websocket, strerror(errno));
		websocket->state = WEBSOCKET_STATE_CLOSED;
		free(seckey);
		if(websocket->retry > 0) {
			sleep(websocket->retry);
			cwebsocket_client_connect(websocket);
		}
		return -1;
	}
	freeaddrinfo(servinfo);

    int optval = 1;
    if(setsockopt(websocket->fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof optval) == -1) {
        syslog(LOG_ERR, "cwebsocket_client_connect: %s", strerror(errno));
        cwebsocket_client_onerror(websocket, strerror(errno));
        free(seckey);
        return -1;
    }

    // Optimize socket buffer sizes for performance (256KB each)
    int bufsize = 262144; // 256KB
    if(setsockopt(websocket->fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof bufsize) == -1) {
        syslog(LOG_WARNING, "cwebsocket_client_connect: unable to set SO_RCVBUF: %s", strerror(errno));
    }
    if(setsockopt(websocket->fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof bufsize) == -1) {
        syslog(LOG_WARNING, "cwebsocket_client_connect: unable to set SO_SNDBUF: %s", strerror(errno));
    }

    // Disable Nagle to reduce small-frame latency during Autobahn echo tests
#ifdef TCP_NODELAY
    optval = 1;
    if(setsockopt(websocket->fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof optval) == -1) {
        syslog(LOG_WARNING, "cwebsocket_client_connect: unable to set TCP_NODELAY: %s", strerror(errno));
    }
#endif
    // Avoid per-socket timeouts: Autobahn cases may run long

#ifdef ENABLE_SSL

    websocket->ssl = NULL;
    websocket->sslctx = NULL;

	if(websocket->flags & WEBSOCKET_FLAG_SSL) {

	   syslog(LOG_DEBUG, "cwebsocket_client_connect: using secure (TLS) connection");

	   // Modern OpenSSL initialization (1.1.0+)
	   #if OPENSSL_VERSION_NUMBER < 0x10100000L
	   SSL_load_error_strings();
	   SSL_library_init();
	   #endif

	   // Use modern TLS method instead of deprecated SSLv23_client_method()
	   #if OPENSSL_VERSION_NUMBER >= 0x10100000L
	   websocket->sslctx = SSL_CTX_new(TLS_client_method());
	   #else
	   websocket->sslctx = SSL_CTX_new(SSLv23_client_method());
	   #endif
	   if(websocket->sslctx == NULL) {
		  ERR_print_errors_fp(stderr);
		  return -1;
	   }

	   // Set security options: disable old protocols, enable modern TLS
	   #if OPENSSL_VERSION_NUMBER >= 0x10100000L
	   SSL_CTX_set_min_proto_version(websocket->sslctx, TLS1_2_VERSION);
	   #else
	   SSL_CTX_set_options(websocket->sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	   #endif

	   // Enable certificate verification
	   SSL_CTX_set_verify(websocket->sslctx, SSL_VERIFY_PEER, NULL);

	   // Load system default trusted CA certificates
	   if(SSL_CTX_set_default_verify_paths(websocket->sslctx) != 1) {
		  syslog(LOG_WARNING, "cwebsocket_client_connect: unable to load default CA certificates");
	   }

	   // Set modern cipher suites for better performance and security
	   const char *cipher_list = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
	   if(SSL_CTX_set_cipher_list(websocket->sslctx, cipher_list) != 1) {
		  syslog(LOG_WARNING, "cwebsocket_client_connect: unable to set cipher list");
	   }

	   websocket->ssl = SSL_new(websocket->sslctx);
	   if(websocket->ssl == NULL) {
		  ERR_print_errors_fp(stderr);
		  return -1;
	   }

	   // Enable SNI (Server Name Indication) for proper certificate validation
	   if(SSL_set_tlsext_host_name(websocket->ssl, hostname) != 1) {
		  syslog(LOG_WARNING, "cwebsocket_client_connect: unable to set SNI hostname");
	   }

	   if(!SSL_set_fd(websocket->ssl, websocket->fd)) {
		  ERR_print_errors_fp(stderr);
		  return -1;
	   }

	   if(SSL_connect(websocket->ssl) != 1) {
		  ERR_print_errors_fp(stderr);
		  int ssl_err = SSL_get_error(websocket->ssl, -1);
		  syslog(LOG_ERR, "cwebsocket_client_connect: SSL_connect failed with error %d", ssl_err);
		  return -1;
	   }

	   // Verify the certificate
	   long verify_result = SSL_get_verify_result(websocket->ssl);
	   if(verify_result != X509_V_OK) {
		  syslog(LOG_WARNING, "cwebsocket_client_connect: certificate verification failed: %ld", verify_result);
		  // Note: We log but don't fail here to maintain backward compatibility
		  // In production, you may want to fail on cert verification errors
	   }
	}
#endif

#ifdef ENABLE_THREADS
	pthread_mutex_lock(&websocket->lock);
	websocket->state = WEBSOCKET_STATE_CONNECTED;
	pthread_mutex_unlock(&websocket->lock);
#else
	websocket->state = WEBSOCKET_STATE_CONNECTED;
#endif

	if(cwebsocket_client_write(websocket, handshake, strlen(handshake)) == -1) {
		syslog(LOG_ERR, "cwebsocket_client_connect: %s", strerror(errno));
		cwebsocket_client_onerror(websocket, strerror(errno));
		free(seckey);
		return -1;
	}

    if(cwebsocket_client_read_handshake(websocket, seckey) == -1) {
        syslog(LOG_ERR, "cwebsocket_client_connect: handshake failed");
        cwebsocket_client_onerror(websocket, "handshake failed");
        // ensure socket is torn down so caller can retry cleanly
        cwebsocket_client_close(websocket, 1006, "handshake failed");
        return -1;
    }
	seckey = NULL;

#ifdef ENABLE_THREADS
	pthread_mutex_lock(&websocket->lock);
	websocket->state = WEBSOCKET_STATE_OPEN;
	pthread_mutex_unlock(&websocket->lock);
#else
	websocket->state = WEBSOCKET_STATE_OPEN;
#endif

	cwebsocket_client_onopen(websocket);

	return 0;
}

int cwebsocket_client_handshake_handler(cwebsocket_client *websocket, const char *handshake_response, char *seckey) {
	uint8_t flags = 0;
    int status_verified = 0;
	syslog(LOG_DEBUG, "cwebsocket_client_handshake_handler: handshake response: \n%s\n", handshake_response);
	char *mutable = (char *)malloc(strlen(handshake_response) + 1);
	if(mutable == NULL) {
		cwebsocket_client_onerror(websocket, "out of memory");
		free(seckey);
		return -1;
	}
	strcpy(mutable, handshake_response);
	char *saveptr = NULL;
	for(char *line = strtok_r(mutable, "\r\n", &saveptr); line != NULL; line = strtok_r(NULL, "\r\n", &saveptr)) {
		if(strncasecmp(line, "HTTP/", 5) == 0) {
			char *status_ptr = strchr(line, ' ');
			if(status_ptr == NULL) {
				cwebsocket_client_onerror(websocket, "invalid HTTP status line");
				free(seckey);
				free(mutable);
				return -1;
			}
			status_ptr++;
			while(*status_ptr == ' ') status_ptr++;
			int status_code = atoi(status_ptr);
			if(status_code != 101) {
				cwebsocket_client_onerror(websocket, "unexpected HTTP status code");
				free(seckey);
				free(mutable);
				return -1;
			}
			status_verified = 1;
			continue;
		}

		char *value = strchr(line, ':');
		if(value == NULL) {
			syslog(LOG_ERR, "cwebsocket_client_handshake_handler: invalid HTTP header sent: %s", line);
			cwebsocket_client_onerror(websocket, "invalid HTTP header sent");
			free(seckey);
			free(mutable);
			return -1;
		}
		*value = '\0';
		value++;
		cwebsocket_trim(line);
		cwebsocket_trim(value);

		if(strcasecmp(line, "Upgrade") == 0) {
			if(!cwebsocket_header_contains_token(value, "websocket")) {
				cwebsocket_client_onerror(websocket, "invalid Upgrade header");
				free(seckey);
				free(mutable);
				return -1;
			}
			flags |= CWS_HANDSHAKE_HAS_UPGRADE;
			continue;
		}
		if(strcasecmp(line, "Connection") == 0) {
			if(!cwebsocket_header_contains_token(value, "upgrade")) {
				cwebsocket_client_onerror(websocket, "invalid Connection header");
				free(seckey);
				free(mutable);
				return -1;
			}
			flags |= CWS_HANDSHAKE_HAS_CONNECTION;
			continue;
		}
        if(strcasecmp(line, "Sec-WebSocket-Protocol") == 0) {
            // Only enforce subprotocol validation if we actually offered any
            if(websocket->subprotocol_len > 0) {
                int matched = 0;
                for(size_t i = 0; i < websocket->subprotocol_len; i++) {
                    if(strcasecmp(value, websocket->subprotocols[i]->name) == 0) {
                        websocket->subprotocol = websocket->subprotocols[i];
                        syslog(LOG_DEBUG, "cwebsocket_client_handshake_handler: negotiated subprotocol %s", websocket->subprotocol->name);
                        matched = 1;
                        break;
                    }
                }
                if(!matched) {
                    cwebsocket_client_onerror(websocket, "server replied with unknown subprotocol");
                    free(seckey);
                    free(mutable);
                    return -1;
                }
            } else {
                // No subprotocol was offered by client; accept server's header but do not bind callbacks here
                syslog(LOG_DEBUG, "cwebsocket_client_handshake_handler: ignoring Sec-WebSocket-Protocol from server (none offered)");
            }
            continue;
        }
		if(strcasecmp(line, "Sec-WebSocket-Accept") == 0) {
			char *response = cwebsocket_create_key_challenge_response(seckey);
			if(response == NULL) {
				cwebsocket_client_onerror(websocket, "unable to compute challenge response");
				free(seckey);
				free(mutable);
				return -1;
			}
			if(strcmp(value, response) != 0) {
				char errmsg[512];
				snprintf(errmsg, sizeof(errmsg), "Sec-WebSocket-Accept mismatch. expected=%s, actual=%s", response, value);
				cwebsocket_client_onerror(websocket, errmsg);
				free(response);
				free(seckey);
				free(mutable);
				return -1;
			}
			free(response);
			flags |= CWS_HANDSHAKE_HAS_ACCEPT;
			continue;
		}
        if(strcasecmp(line, "Sec-WebSocket-Extensions") == 0) {
            // Parse permessage-deflate negotiation and window bits parameters
            if(strcasestr(value, "permessage-deflate") != NULL) {
                websocket->ext_pmdeflate_enabled = 1;
                syslog(LOG_DEBUG, "cwebsocket_client_handshake_handler: negotiated permessage-deflate");

                // Parse client_max_window_bits parameter
                const char *client_wb = strcasestr(value, "client_max_window_bits");
                if(client_wb) {
                    const char *eq = strchr(client_wb, '=');
                    if(eq) {
                        int bits = atoi(eq + 1);
                        if(bits >= 8 && bits <= 15) {
                            websocket->pmdeflate_client_window_bits = bits;
                            syslog(LOG_DEBUG, "cwebsocket_client_handshake_handler: client_max_window_bits=%d", bits);
                        }
                    }
                }

                // Parse server_max_window_bits parameter
                const char *server_wb = strcasestr(value, "server_max_window_bits");
                if(server_wb) {
                    const char *eq = strchr(server_wb, '=');
                    if(eq) {
                        int bits = atoi(eq + 1);
                        if(bits >= 8 && bits <= 15) {
                            websocket->pmdeflate_server_window_bits = bits;
                            syslog(LOG_DEBUG, "cwebsocket_client_handshake_handler: server_max_window_bits=%d", bits);
                        }
                    }
                }
            }
            continue;
        }
	}

	free(seckey);
	free(mutable);

	if(!status_verified || ((flags & CWS_HANDSHAKE_HAS_UPGRADE) == 0) ||
	   ((flags & CWS_HANDSHAKE_HAS_CONNECTION) == 0) ||
	   ((flags & CWS_HANDSHAKE_HAS_ACCEPT) == 0)) {
		cwebsocket_client_close(websocket, 1002, "invalid websocket HTTP headers");
		return -1;
	}

    // If server negotiated permessage-deflate, we'll honor it (others are ignored)

	syslog(LOG_DEBUG, "cwebsocket_client_handshake_handler: handshake successful");
	return 0;
}

// permessage-deflate helpers
static int cws_inflate_append(cwebsocket_client *websocket, const uint8_t *in, size_t in_len, uint8_t **out_buf, size_t *out_len) {
    if(!websocket->pmdeflate_in_progress) {
        memset(&websocket->zin, 0, sizeof(websocket->zin));
        // Use negotiated server window bits (negative = raw DEFLATE without zlib wrapper)
        int window_bits = -websocket->pmdeflate_server_window_bits;
        if(inflateInit2(&websocket->zin, window_bits) != Z_OK) {
            return -1;
        }
        websocket->pmdeflate_in_progress = 1;
    }
    size_t cap = (*out_buf ? *out_len : 0) + in_len * 4 + 128;
    if(*out_buf == NULL) {
        *out_len = 0;
        *out_buf = (uint8_t*)malloc(cap);
        if(!*out_buf) return -1;
    }
    websocket->zin.next_in = (Bytef*)in;
    websocket->zin.avail_in = (uInt)in_len;
    while(websocket->zin.avail_in > 0) {
        if(cap - *out_len < 512) {
            cap *= 2;
            uint8_t *tmp = (uint8_t*)realloc(*out_buf, cap);
            if(!tmp) return -1;
            *out_buf = tmp;
        }
        websocket->zin.next_out = *out_buf + *out_len;
        websocket->zin.avail_out = (uInt)(cap - *out_len);
        int ret = inflate(&websocket->zin, Z_NO_FLUSH);
        if(ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) return -1;
        *out_len = cap - websocket->zin.avail_out;
        if(ret == Z_STREAM_END) break;
        if(ret == Z_BUF_ERROR && websocket->zin.avail_in == 0) break;
    }
    return 0;
}

static int cws_inflate_finish(cwebsocket_client *websocket, uint8_t **out_buf, size_t *out_len) {
    static const uint8_t trailer[4] = {0x00,0x00,0xff,0xff};
    if(cws_inflate_append(websocket, trailer, sizeof(trailer), out_buf, out_len) != 0) {
        inflateEnd(&websocket->zin);
        websocket->pmdeflate_in_progress = 0;
        return -1;
    }
    inflateEnd(&websocket->zin);
    websocket->pmdeflate_in_progress = 0;
    return 0;
}

// permessage-deflate: compress a whole message once. We use no context takeover
// and raw DEFLATE blocks with negotiated window bits. Caller must free *out on success.
static int cws_deflate_message(cwebsocket_client *websocket, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    z_stream *zs = &websocket->zout;
    memset(zs, 0, sizeof(*zs));
    // Use negotiated client window bits (negative = raw DEFLATE without zlib wrapper)
    int window_bits = -websocket->pmdeflate_client_window_bits;
    if(deflateInit2(zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }
    size_t cap = in_len + (in_len / 10) + 64; // rough headroom
    uint8_t *buf = (uint8_t*)malloc(cap);
    if(!buf) {
        deflateEnd(zs);
        return -1;
    }
    zs->next_in = (Bytef*)in;
    zs->avail_in = (uInt)in_len;
    zs->next_out = buf;
    zs->avail_out = (uInt)cap;
    int ret = deflate(zs, Z_SYNC_FLUSH);
    if(ret != Z_OK) {
        free(buf);
        deflateEnd(zs);
        return -1;
    }
    size_t produced = cap - zs->avail_out;
    // Remove 4-byte tail 0x00 00 ff ff added by Z_SYNC_FLUSH as per RFC
    if(produced >= 4) {
        produced -= 4;
    }
    *out = buf;
    *out_len = produced;
    deflateEnd(zs);
    return 0;
}

int cwebsocket_client_read_handshake(cwebsocket_client *websocket, char *seckey) {

	int byte, tmplen = 0;
	uint32_t bytes_read = 0;
	uint8_t data[CWS_HANDSHAKE_BUFFER_MAX];
	memset(data, 0, CWS_HANDSHAKE_BUFFER_MAX);

	while(bytes_read <= CWS_HANDSHAKE_BUFFER_MAX) {

		byte = cwebsocket_client_read(websocket, data+bytes_read, 1);

		if(byte == 0) return -1;
		if(byte == -1) {
			syslog(LOG_ERR, "cwebsocket_client_read_handshake: %s", strerror(errno));
			cwebsocket_client_onerror(websocket, strerror(errno));
			return -1;
		}
		if(bytes_read == CWS_HANDSHAKE_BUFFER_MAX) {
			syslog(LOG_ERR, "cwebsocket_client_read_handshake: handshake response too large. CWS_HANDSHAKE_BUFFER_MAX = %i bytes.", CWS_HANDSHAKE_BUFFER_MAX);
			cwebsocket_client_onerror(websocket, "handshake response too large");
			return -1;
		}
		if((data[bytes_read] == '\n' && data[bytes_read-1] == '\r' && data[bytes_read-2] == '\n' && data[bytes_read-3] == '\r')) {
			break;
		}
		bytes_read++;
	}

	if(bytes_read < 4) {
		syslog(LOG_ERR, "cwebsocket_client_read_handshake: incomplete handshake response");
		cwebsocket_client_onerror(websocket, "incomplete handshake response");
		free(seckey);
		return -1;
	}

	tmplen = bytes_read - 3;
	char *buf = (char *)malloc(tmplen + 1);
	if(buf == NULL) {
		cwebsocket_client_onerror(websocket, "out of memory");
		free(seckey);
		return -1;
	}
	memcpy(buf, data, tmplen);
	buf[tmplen] = '\0';

	int rc = cwebsocket_client_handshake_handler(websocket, buf, seckey);
	free(buf);
	return rc;
}

void cwebsocket_client_listen(cwebsocket_client *websocket) {
	while(websocket->state & WEBSOCKET_STATE_OPEN) {
		syslog(LOG_DEBUG, "cwebsocket_client_listen: calling cwebsocket_client_read_data");
		cwebsocket_client_read_data(websocket);
	}
	syslog(LOG_DEBUG, "cwebsocket_client_listen: shutting down");
}

#ifdef ENABLE_THREADS
void *cwebsocket_client_onmessage_thread(void *ptr) {
    cwebsocket_client_thread_args *args = (cwebsocket_client_thread_args *)ptr;
    cwebsocket_client_onmessage(args->socket, args->message);
    // Free payload after callback to avoid leaks
    if(args->message && args->message->payload) {
        free(args->message->payload);
        args->message->payload = NULL;
    }
    free(args->message);
    free(ptr);
    return NULL;
}
#endif

int cwebsocket_client_send_control_frame(cwebsocket_client *websocket, opcode code, const char *frame_type, uint8_t *payload, int payload_len) {
    if(websocket->fd <= 0 || websocket->protocol_error) {
        return -1;
    }
	if(payload_len > 125) {
		syslog(LOG_ERR, "cwebsocket_client_send_control_frame: control payload too large");
		return -1;
	}

	uint8_t masking_key[4];
	cwebsocket_client_create_masking_key(masking_key);

	size_t header_len = 6;
	size_t frame_len = header_len + (size_t)payload_len;
	uint8_t *control_frame = (uint8_t *)malloc(frame_len);
	if(control_frame == NULL) {
		syslog(LOG_CRIT, "cwebsocket_client_send_control_frame: out of memory");
		cwebsocket_client_onerror(websocket, "out of memory");
		return -1;
	}
	memset(control_frame, 0, frame_len);

	control_frame[0] = (uint8_t)(code | 0x80);
	control_frame[1] = (uint8_t)(payload_len | 0x80);
	memcpy(control_frame + 2, masking_key, sizeof(masking_key));

	if(payload_len > 0 && payload != NULL) {
		for(int i = 0; i < payload_len; i++) {
			control_frame[header_len + i] = (uint8_t)(payload[i] ^ masking_key[i % 4]);
		}
	}

	ssize_t bytes_written = cwebsocket_client_write(websocket, control_frame, (int)frame_len);
	free(control_frame);

	if(bytes_written == 0) {
		syslog(LOG_DEBUG, "cwebsocket_client_send_control_frame: remote host closed the connection");
		return 0;
	}
	if(bytes_written == -1) {
		syslog(LOG_CRIT, "cwebsocket_client_send_control_frame: error sending %s control frame. %s", frame_type, strerror(errno));
		cwebsocket_client_onerror(websocket, strerror(errno));
		return -1;
	}

	syslog(LOG_DEBUG, "cwebsocket_client_send_control_frame: wrote %zd byte %s frame", bytes_written, frame_type);
	return bytes_written;
}

int cwebsocket_client_read_data(cwebsocket_client *websocket) {
	uint8_t header[2];
	int result = cwebsocket_client_read_exact(websocket, header, sizeof(header));
    if(result <= 0) {
        const char *errmsg = (result == 0) ? "server closed the connection" : strerror(errno);
        syslog(LOG_ERR, "cwebsocket_client_read_data: %s", errmsg);
        cwebsocket_client_onerror(websocket, errmsg);
        cwebsocket_client_close(websocket, 1006, errmsg);
        return -1;
    }

	int total_bytes = sizeof(header);

	cwebsocket_frame frame;
	memset(&frame, 0, sizeof(frame));
	frame.fin = (header[0] & 0x80) != 0;
	frame.rsv1 = (header[0] & 0x40) != 0;
	frame.rsv2 = (header[0] & 0x20) != 0;
	frame.rsv3 = (header[0] & 0x10) != 0;
	frame.opcode = (opcode)(header[0] & 0x0F);
	frame.mask = (header[1] & 0x80) != 0;
	frame.payload_len = (header[1] & 0x7F);

    // Control frames MUST have FIN set and payload <= 125
    if(cwebsocket_client_is_control_frame(frame.opcode)) {
        if(!frame.fin || frame.payload_len > 125) {
            syslog(LOG_ERR, "cwebsocket_client_read_data: invalid control frame (fin=%d, len=%llu)", frame.fin, (unsigned long long)frame.payload_len);
            cwebsocket_client_drop(websocket, "protocol error: invalid control frame");
            return -1;
        }
    }

    if(frame.rsv2 || frame.rsv3) {
        syslog(LOG_ERR, "cwebsocket_client_read_data: received frame with RSV2/RSV3 set");
        cwebsocket_client_drop(websocket, "protocol error: RSV2/RSV3 set");
        return -1;
    }
    if(frame.rsv1) {
        // RSV1 allowed only on first data frame of a compressed message when permessage-deflate negotiated
        if(!(websocket->ext_pmdeflate_enabled && !websocket->fragment_in_progress && (frame.opcode == TEXT_FRAME || frame.opcode == BINARY_FRAME))) {
            syslog(LOG_ERR, "cwebsocket_client_read_data: received frame with invalid RSV1 usage");
            cwebsocket_client_drop(websocket, "protocol error: RSV1 invalid");
            return -1;
        }
    }

    if(frame.mask) {
        syslog(LOG_ERR, "cwebsocket_client_read_data: received masked frame from server");
        cwebsocket_client_drop(websocket, "protocol error: masked frame from server");
        return -1;
    }

	if((frame.opcode >= 0x03 && frame.opcode <= 0x07) || frame.opcode >= 0x0B) {
		char errmsg[80];
		snprintf(errmsg, sizeof(errmsg), "received unsupported opcode: %#04x", frame.opcode);
		syslog(LOG_ERR, "cwebsocket_client_read_data: %s", errmsg);
        cwebsocket_client_drop(websocket, errmsg);
        return -1;
    }

	uint64_t payload_len = frame.payload_len;
	if(frame.payload_len == 126) {
		uint8_t extended[2];
        if(cwebsocket_client_read_exact(websocket, extended, sizeof(extended)) <= 0) {
            syslog(LOG_ERR, "cwebsocket_client_read_data: failed to read extended payload length");
            cwebsocket_client_onerror(websocket, "failed to read extended payload length");
            cwebsocket_client_close(websocket, 1006, "failed to read extended payload length");
            return -1;
        }
		total_bytes += sizeof(extended);
		payload_len = ((uint64_t)extended[0] << 8) | ((uint64_t)extended[1]);
	}
	else if(frame.payload_len == 127) {
		uint8_t extended[8];
        if(cwebsocket_client_read_exact(websocket, extended, sizeof(extended)) <= 0) {
            syslog(LOG_ERR, "cwebsocket_client_read_data: failed to read extended payload length");
            cwebsocket_client_onerror(websocket, "failed to read extended payload length");
            cwebsocket_client_close(websocket, 1006, "failed to read extended payload length");
            return -1;
        }
		total_bytes += sizeof(extended);
		if(extended[0] & 0x80) {
			syslog(LOG_ERR, "cwebsocket_client_read_data: invalid 64-bit payload length");
            cwebsocket_client_drop(websocket, "protocol error: invalid 64-bit payload length");
            return -1;
        }
		payload_len =
			((uint64_t)extended[0] << 56) |
			((uint64_t)extended[1] << 48) |
			((uint64_t)extended[2] << 40) |
			((uint64_t)extended[3] << 32) |
			((uint64_t)extended[4] << 24) |
			((uint64_t)extended[5] << 16) |
			((uint64_t)extended[6] << 8)  |
			((uint64_t)extended[7]);
	}

    if(payload_len > CWS_DATA_BUFFER_MAX) {
        syslog(LOG_ERR, "cwebsocket_client_read_data: payload too large (%llu)", (unsigned long long)payload_len);
        cwebsocket_client_close(websocket, 1009, "payload too large");
        return -1;
    }

	if(cwebsocket_client_is_control_frame(frame.opcode)) {
        if(!frame.fin) {
            cwebsocket_client_drop(websocket, "protocol error: fragmented control frame");
            return -1;
        }
        if(payload_len > 125) {
            cwebsocket_client_drop(websocket, "protocol error: control payload too large");
            return -1;
        }
	}
	else {
		if(websocket->fragment_in_progress && frame.opcode != CONTINUATION) {
            cwebsocket_client_drop(websocket, "protocol error: continuation expected");
            return -1;
        }
        if(!websocket->fragment_in_progress && frame.opcode == CONTINUATION) {
            cwebsocket_client_drop(websocket, "protocol error: unexpected continuation frame");
            return -1;
        }
	}

    if(payload_len > 0 && payload_len > SIZE_MAX) {
        syslog(LOG_ERR, "cwebsocket_client_read_data: payload length exceeds addressable memory");
        cwebsocket_client_close(websocket, 1009, "payload too large");
        return -1;
    }

	uint8_t *payload = NULL;
	if(payload_len > 0) {
		payload = (uint8_t *)malloc((size_t)payload_len);
		if(payload == NULL) {
			cwebsocket_client_onerror(websocket, "out of memory allocating payload");
			cwebsocket_client_close(websocket, 1011, "out of memory");
			return -1;
		}
        if(cwebsocket_client_read_exact(websocket, payload, (size_t)payload_len) <= 0) {
            syslog(LOG_ERR, "cwebsocket_client_read_data: failed to read payload");
            free(payload);
            cwebsocket_client_onerror(websocket, "failed to read payload");
            cwebsocket_client_close(websocket, 1006, "failed to read payload");
            return -1;
        }
		total_bytes += (int)payload_len;
	}

    if(cwebsocket_client_is_control_frame(frame.opcode)) {
        int rc = cwebsocket_client_handle_control_frame(websocket, frame.opcode, payload, payload_len);
        free(payload);
        return (rc < 0) ? -1 : total_bytes;
    }

    // Handle permessage-deflate decompression if negotiated and RSV1 set on the first data frame
    if(websocket->ext_pmdeflate_enabled && (frame.opcode == TEXT_FRAME || frame.opcode == BINARY_FRAME || frame.opcode == CONTINUATION)) {
        static uint8_t *decomp_buf = NULL; // reused across calls in same thread
        static size_t decomp_len = 0;
        int is_first = (frame.opcode == TEXT_FRAME || frame.opcode == BINARY_FRAME);
        if(is_first && frame.rsv1) {
            // start/continue inflating across fragments
            decomp_len = 0;
            free(decomp_buf); decomp_buf = NULL;
            websocket->pmdeflate_opcode = frame.opcode;
            // Always initialize decompression stream even if payload_len is 0
            // This ensures pmdeflate_in_progress is set for subsequent continuation frames
            if(cws_inflate_append(websocket, payload, (size_t)payload_len, &decomp_buf, &decomp_len) != 0) {
                free(payload);
                cwebsocket_client_drop(websocket, "inflate error");
                return -1;
            }
            free(payload);
            if(frame.fin) {
                if(cws_inflate_finish(websocket, &decomp_buf, &decomp_len) != 0) {
                    cwebsocket_client_drop(websocket, "inflate finish error");
                    return -1;
                }
                int rc = cwebsocket_client_dispatch_message(websocket, (opcode)websocket->pmdeflate_opcode, decomp_buf, decomp_len, 1);
                decomp_buf = NULL; decomp_len = 0;
                return (rc < 0) ? -1 : total_bytes;
            } else {
                // not fin, buffer stored in decomp_buf; next CONTINUATION with RSV1==0
                int rc = cwebsocket_client_dispatch_message(websocket, (opcode)websocket->pmdeflate_opcode, decomp_buf, decomp_len, 0);
                decomp_buf = NULL; decomp_len = 0;
                return (rc < 0) ? -1 : total_bytes;
            }
        } else if(websocket->pmdeflate_in_progress) {
            // continuation of compressed message
            // Always append to decompression stream even if payload_len is 0
            if(cws_inflate_append(websocket, payload, (size_t)payload_len, &decomp_buf, &decomp_len) != 0) {
                free(payload);
                cwebsocket_client_drop(websocket, "inflate error");
                return -1;
            }
            free(payload);
            if(frame.fin) {
                if(cws_inflate_finish(websocket, &decomp_buf, &decomp_len) != 0) {
                    cwebsocket_client_drop(websocket, "inflate finish error");
                    return -1;
                }
                int rc = cwebsocket_client_dispatch_message(websocket, CONTINUATION, decomp_buf, decomp_len, 1);
                decomp_buf = NULL; decomp_len = 0;
                return (rc < 0) ? -1 : total_bytes;
            } else {
                int rc = cwebsocket_client_dispatch_message(websocket, CONTINUATION, decomp_buf, decomp_len, 0);
                decomp_buf = NULL; decomp_len = 0;
                return (rc < 0) ? -1 : total_bytes;
            }
        }
    }

    int rc = cwebsocket_client_dispatch_message(websocket, frame.opcode, payload, payload_len, frame.fin);
    return (rc < 0) ? -1 : total_bytes;
}

STATIC int cwebsocket_client_is_control_frame(opcode frame_opcode) {
	return frame_opcode == CLOSE || frame_opcode == PING || frame_opcode == PONG;
}

STATIC void cwebsocket_client_reset_fragments(cwebsocket_client *websocket) {
    websocket->fragment_length = 0;
    websocket->fragment_opcode = CONTINUATION;
    websocket->fragment_in_progress = 0;
    websocket->utf8_state = UTF8_ACCEPT;
    websocket->utf8_codepoint = 0;
}

STATIC int cwebsocket_client_ensure_fragment_capacity(cwebsocket_client *websocket, size_t required) {
	if(required > CWS_DATA_BUFFER_MAX) {
		return -1;
	}
	if(required <= websocket->fragment_capacity) {
		return 0;
	}
	uint8_t *tmp = realloc(websocket->fragment_buffer, required);
	if(tmp == NULL) {
		return -1;
	}
	websocket->fragment_buffer = tmp;
	websocket->fragment_capacity = required;
	return 0;
}

static int cwebsocket_client_deliver_message(cwebsocket_client *websocket, opcode message_opcode, char *payload, uint64_t payload_len) {
    if(websocket->protocol_error) {
        // Suppress application delivery after protocol error
        free(payload);
        return 0;
    }
    if(websocket->subprotocol == NULL || websocket->subprotocol->onmessage == NULL) {
        syslog(LOG_WARNING, "cwebsocket_client_deliver_message: onmessage callback undefined");
        return 0;
    }

#ifdef ENABLE_THREADS
    // Allow switching to synchronous callbacks to avoid per-message thread overhead
    const char *sync_cb = getenv("CWS_SYNC_CALLBACKS");
    if(sync_cb && *sync_cb && strcmp(sync_cb, "0") != 0) {
        cwebsocket_message message = {0};
        message.opcode = message_opcode;
        message.payload_len = payload_len;
        message.payload = payload;
        if(!websocket->protocol_error) {
            cwebsocket_client_onmessage(websocket, &message);
        }
        if(message.payload) free(message.payload);
        return 0;
    } else {
        cwebsocket_message *message = malloc(sizeof(cwebsocket_message));
        if(message == NULL) {
            syslog(LOG_CRIT, "cwebsocket_client_deliver_message: out of memory allocating message");
            cwebsocket_client_onerror(websocket, "out of memory allocating message");
            free(payload);
            return -1;
        }
        memset(message, 0, sizeof(cwebsocket_message));
        message->opcode = message_opcode;
        message->payload_len = payload_len;
        message->payload = payload;

        cwebsocket_client_thread_args *args = malloc(sizeof(cwebsocket_client_thread_args));
        if(args == NULL) {
            syslog(LOG_CRIT, "cwebsocket_client_deliver_message: out of memory allocating thread args");
            free(message);
            free(payload);
            cwebsocket_client_onerror(websocket, "out of memory allocating thread args");
            return -1;
        }
        memset(args, 0, sizeof(cwebsocket_client_thread_args));
        args->socket = websocket;
        args->message = message;

        pthread_attr_t attr; memset(&attr, 0, sizeof(attr));
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        int perr = pthread_create(&websocket->thread, &attr, cwebsocket_client_onmessage_thread, (void *)args);
        pthread_attr_destroy(&attr);
        if(perr != 0) {
            syslog(LOG_ERR, "cwebsocket_client_deliver_message: %s", strerror(errno));
            free(args);
            free(message);
            free(payload);
            cwebsocket_client_onerror(websocket, strerror(errno));
            return -1;
        }
        return 0;
    }
#else
    cwebsocket_message message = {0};
    message.opcode = message_opcode;
    message.payload_len = payload_len;
    message.payload = payload;
    if(!websocket->protocol_error) {
        cwebsocket_client_onmessage(websocket, &message);
    }
    // In non-threaded mode, free payload after delivery
    if(message.payload) {
        free(message.payload);
        message.payload = NULL;
    }
    return 0;
#endif
}

static int cwebsocket_client_dispatch_message(cwebsocket_client *websocket, opcode frame_opcode, uint8_t *payload, uint64_t payload_len, int fin) {
    // Continuation without a fragmented message in progress is a protocol error
    if(frame_opcode == CONTINUATION && !websocket->fragment_in_progress) {
        free(payload);
        syslog(LOG_ERR, "cwebsocket_client_dispatch_message: unexpected CONTINUATION frame");
        cwebsocket_client_close(websocket, 1002, "unexpected continuation");
        return -1;
    }
    // While fragmented message is in progress, only CONTINUATION frames are allowed
    if(websocket->fragment_in_progress && frame_opcode != CONTINUATION && !cwebsocket_client_is_control_frame(frame_opcode)) {
        free(payload);
        syslog(LOG_ERR, "cwebsocket_client_dispatch_message: overlapping data frames during fragmentation");
        cwebsocket_client_close(websocket, 1002, "overlapping fragments");
        return -1;
    }
    if(frame_opcode == CONTINUATION) {
        if(payload_len > 0) {
            size_t required = websocket->fragment_length + (size_t)payload_len;
            if(cwebsocket_client_ensure_fragment_capacity(websocket, required) != 0) {
                free(payload);
                syslog(LOG_ERR, "cwebsocket_client_dispatch_message: unable to grow fragment buffer");
                cwebsocket_client_close(websocket, 1011, "unable to grow fragment buffer");
                return -1;
            }
            memcpy(websocket->fragment_buffer + websocket->fragment_length, payload, (size_t)payload_len);
            websocket->fragment_length += (size_t)payload_len;
            if(websocket->fragment_opcode == TEXT_FRAME) {
                // Incremental UTF-8 validation: fail fast on invalid sequences
                for(uint64_t i = 0; i < payload_len; i++) {
                    uint32_t s = utf8_decode(&websocket->utf8_state, &websocket->utf8_codepoint, ((uint8_t*)payload)[i]);
                    if(s == UTF8_REJECT) {
                        free(payload);
                        syslog(LOG_ERR, "cwebsocket_client_dispatch_message: received fragmented malformed utf8 payload");
                        cwebsocket_client_close(websocket, 1007, "received malformed utf8 payload");
                        cwebsocket_client_reset_fragments(websocket);
                        return -1;
                    }
                }
            }
        }
        free(payload);
        if(!fin) {
            return 0;
        }
        opcode final_opcode = websocket->fragment_opcode;
        size_t message_len = websocket->fragment_length;
		if(final_opcode != TEXT_FRAME && final_opcode != BINARY_FRAME) {
			syslog(LOG_ERR, "cwebsocket_client_dispatch_message: invalid fragment opcode");
			cwebsocket_client_close(websocket, 1002, "invalid fragment opcode");
			cwebsocket_client_reset_fragments(websocket);
			return -1;
		}
        if(final_opcode == TEXT_FRAME) {
            char *text_payload = (char *)malloc(message_len + 1);
            if(text_payload == NULL) {
                syslog(LOG_CRIT, "cwebsocket_client_dispatch_message: out of memory assembling text message");
                cwebsocket_client_close(websocket, 1011, "out of memory");
                cwebsocket_client_reset_fragments(websocket);
                return -1;
            }
            if(message_len > 0) {
                memcpy(text_payload, websocket->fragment_buffer, message_len);
            }
            text_payload[message_len] = '\0';
            // On FIN, utf8_state must be ACCEPT (complete sequence)
            if(websocket->utf8_state != UTF8_ACCEPT) {
                syslog(LOG_ERR, "cwebsocket_client_dispatch_message: received fragmented malformed utf8 payload");
                cwebsocket_client_close(websocket, 1007, "received malformed utf8 payload");
                free(text_payload);
                cwebsocket_client_reset_fragments(websocket);
                return -1;
            }
            syslog(LOG_DEBUG, "cwebsocket_client_dispatch_message: assembled fragmented text payload bytes=%zu", message_len);
            cwebsocket_client_reset_fragments(websocket);
            return cwebsocket_client_deliver_message(websocket, TEXT_FRAME, text_payload, message_len);
        }
		char *binary_payload = NULL;
		if(message_len > 0) {
			binary_payload = (char *)malloc(message_len);
			if(binary_payload == NULL) {
				syslog(LOG_CRIT, "cwebsocket_client_dispatch_message: out of memory assembling binary message");
				cwebsocket_client_close(websocket, 1011, "out of memory");
				cwebsocket_client_reset_fragments(websocket);
				return -1;
			}
			memcpy(binary_payload, websocket->fragment_buffer, message_len);
		} else {
			binary_payload = (char *)malloc(1);
			if(binary_payload == NULL) {
				syslog(LOG_CRIT, "cwebsocket_client_dispatch_message: out of memory assembling binary message");
				cwebsocket_client_close(websocket, 1011, "out of memory");
				cwebsocket_client_reset_fragments(websocket);
				return -1;
			}
			binary_payload[0] = '\0';
		}
		cwebsocket_client_reset_fragments(websocket);
		syslog(LOG_DEBUG, "cwebsocket_client_dispatch_message: assembled fragmented binary payload bytes=%zu", message_len);
		return cwebsocket_client_deliver_message(websocket, BINARY_FRAME, binary_payload, message_len);
	}

	if(frame_opcode == TEXT_FRAME || frame_opcode == BINARY_FRAME) {
        if(!fin) {
            if(websocket->fragment_in_progress) {
                free(payload);
                syslog(LOG_ERR, "cwebsocket_client_dispatch_message: received new fragmented message while previous in progress");
                cwebsocket_client_close(websocket, 1002, "overlapping fragments");
                return -1;
            }
            if(cwebsocket_client_ensure_fragment_capacity(websocket, (size_t)payload_len) != 0) {
                free(payload);
                syslog(LOG_CRIT, "cwebsocket_client_dispatch_message: unable to allocate fragment buffer");
                cwebsocket_client_close(websocket, 1011, "unable to allocate fragment buffer");
                return -1;
            }
            // Initialize UTF-8 state for TEXT frames even if payload_len is 0
            // This ensures proper validation of subsequent continuation frames
            if(frame_opcode == TEXT_FRAME) {
                websocket->utf8_state = UTF8_ACCEPT;
                websocket->utf8_codepoint = 0;
            }
            if(payload_len > 0) {
                memcpy(websocket->fragment_buffer, payload, (size_t)payload_len);
                if(frame_opcode == TEXT_FRAME) {
                    // Validate initial bytes of fragmented text
                    for(uint64_t i = 0; i < payload_len; i++) {
                        uint32_t s = utf8_decode(&websocket->utf8_state, &websocket->utf8_codepoint, ((uint8_t*)payload)[i]);
                        if(s == UTF8_REJECT) {
                            free(payload);
                            syslog(LOG_ERR, "cwebsocket_client_dispatch_message: received malformed utf8 payload (fragment start)");
                            cwebsocket_client_close(websocket, 1007, "received malformed utf8 payload");
                            cwebsocket_client_reset_fragments(websocket);
                            return -1;
                        }
                    }
                }
            }
            free(payload);
            websocket->fragment_length = (size_t)payload_len;
            websocket->fragment_opcode = frame_opcode;
            websocket->fragment_in_progress = 1;
            syslog(LOG_DEBUG, "cwebsocket_client_dispatch_message: started fragmented message opcode=%#04x", frame_opcode);
            return 0;
        }

		if(frame_opcode == TEXT_FRAME) {
			char *text_payload = (char *)malloc(payload_len + 1);
			if(text_payload == NULL) {
				free(payload);
				syslog(LOG_CRIT, "cwebsocket_client_dispatch_message: out of memory for text payload");
				cwebsocket_client_close(websocket, 1011, "out of memory");
				return -1;
			}
			if(payload_len > 0 && payload != NULL) {
				memcpy(text_payload, payload, (size_t)payload_len);
			}
			text_payload[payload_len] = '\0';
			free(payload);
			size_t utf8_code_points = 0;
			if(utf8_count_code_points((uint8_t *)text_payload, &utf8_code_points)) {
				syslog(LOG_ERR, "cwebsocket_client_dispatch_message: received malformed utf8 payload");
				cwebsocket_client_close(websocket, 1007, "received malformed utf8 payload");
				free(text_payload);
				return -1;
			}
			syslog(LOG_DEBUG, "cwebsocket_client_dispatch_message: received text payload bytes=%llu", (unsigned long long)payload_len);
			return cwebsocket_client_deliver_message(websocket, TEXT_FRAME, text_payload, payload_len);
		}

		char *binary_payload = NULL;
		if(payload_len > 0 && payload != NULL) {
			binary_payload = (char *)payload;
		} else {
			free(payload);
			binary_payload = (char *)malloc(1);
			if(binary_payload == NULL) {
				syslog(LOG_CRIT, "cwebsocket_client_dispatch_message: out of memory for binary payload");
				cwebsocket_client_close(websocket, 1011, "out of memory");
				return -1;
			}
			binary_payload[0] = '\0';
		}
		syslog(LOG_DEBUG, "cwebsocket_client_dispatch_message: received binary payload bytes=%llu", (unsigned long long)payload_len);
		return cwebsocket_client_deliver_message(websocket, BINARY_FRAME, binary_payload, payload_len);
	}

	free(payload);
	return -1;
}

static int cwebsocket_client_handle_control_frame(cwebsocket_client *websocket, opcode frame_opcode, const uint8_t *payload, uint64_t payload_len) {
    switch(frame_opcode) {
        case PING:
            syslog(LOG_DEBUG, "cwebsocket_client_handle_control_frame: received PING payload_len=%llu", (unsigned long long)payload_len);
            if((websocket->state & WEBSOCKET_STATE_CLOSING)) {
                // During closing handshake, ignore pings to fail fast per strict expectations
                return 0;
            }
            return cwebsocket_client_send_control_frame(websocket, PONG, "PONG", (uint8_t *)payload, (int)payload_len);
		case PONG:
			syslog(LOG_DEBUG, "cwebsocket_client_handle_control_frame: received PONG payload_len=%llu", (unsigned long long)payload_len);
			return 0;
        case CLOSE: {
        syslog(LOG_DEBUG, "cwebsocket_client_handle_control_frame: received CLOSE payload_len=%llu", (unsigned long long)payload_len);
        websocket->close_received = 1;
        uint16_t code = 1005;
            size_t reason_len = 0;
            if(payload_len == 1) {
                // Invalid close payload length per RFC
                cwebsocket_client_close(websocket, 1002, NULL);
                return -1;
            }
            if(payload_len == 0) {
                // Peer closed without a code: reply with 1000 (normal closure)
                cwebsocket_client_close(websocket, 1000, NULL);
                return 0;
            } else if(payload_len >= 2) {
                code = ((uint16_t)payload[0] << 8) | ((uint16_t)payload[1]);
                reason_len = (size_t)payload_len - 2;
            }
			char *reason = NULL;
			if(reason_len > 0) {
				reason = (char *)malloc(reason_len + 1);
				if(reason == NULL) {
					syslog(LOG_CRIT, "cwebsocket_client_handle_control_frame: out of memory allocating close reason");
					cwebsocket_client_close(websocket, 1011, "out of memory");
					return -1;
				}
				memcpy(reason, payload + 2, reason_len);
				reason[reason_len] = '\0';
				size_t utf8_code_points = 0;
				if(utf8_count_code_points((uint8_t *)reason, &utf8_code_points)) {
					syslog(LOG_ERR, "cwebsocket_client_handle_control_frame: received malformed close reason");
					cwebsocket_client_close(websocket, 1007, "received malformed close reason");
					free(reason);
					return -1;
				}
			}
            // If peer sent invalid close code, respond with protocol error (1002)
            uint16_t respond_code = code;
            if(!cwebsocket_is_valid_close_code(code)) {
                respond_code = 1002;
                if(reason != NULL) {
                    free(reason);
                    reason = NULL;
                }
            }
            cwebsocket_client_close(websocket, respond_code, reason);
            if(reason != NULL) {
                free(reason);
            }
            return 0;
        }
		default:
			break;
	}
	return -1;
}

STATIC int cwebsocket_is_valid_close_code(uint16_t code) {
    if(code < 1000) return 0;
    switch(code) {
        case 1000: case 1001: case 1002: case 1003:
        case 1007: case 1008: case 1009: case 1010:
        case 1011: case 1012: case 1013: case 1014:
            return 1;
        case 1004: case 1005: case 1006: case 1015:
            return 0;
        default:
            break;
    }
    if(code >= 1016 && code <= 1999) return 0;      // unassigned
    if(code >= 2000 && code <= 2999) return 0;      // reserved for extensions
    if(code >= 5000) return 0;                      // out of range
    // 3000-3999 and 4000-4999 are allowed (libraries/apps)
    return 1;
}

static int cwebsocket_client_read_exact(cwebsocket_client *websocket, uint8_t *buffer, size_t length) {
	size_t total = 0;
	while(total < length) {
		ssize_t rc = cwebsocket_client_read(websocket, buffer + total, (int)(length - total));
		if(rc == 0) {
			return 0;
		}
		if(rc < 0) {
			if(errno == EINTR) {
				continue;
			}
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				// transient; keep trying
				continue;
			}
			return -1;
		}
		total += (size_t)rc;
	}
	return 1;
}

STATIC int cwebsocket_client_random_bytes(uint8_t *buffer, size_t length) {
#ifdef ENABLE_SSL
	if(RAND_bytes(buffer, (int)length) == 1) {
		return 0;
	}
#endif
	int fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0) {
		return -1;
	}
	size_t total = 0;
	while(total < length) {
		ssize_t rc = read(fd, buffer + total, length - total);
		if(rc == 0) {
			close(fd);
			return -1;
		}
		if(rc < 0) {
			if(errno == EINTR) {
				continue;
			}
			close(fd);
			return -1;
		}
		total += (size_t)rc;
	}
	close(fd);
	return 0;
}

STATIC int cwebsocket_header_contains_token(const char *header_value, const char *token) {
	size_t len = strlen(header_value);
	char *copy = (char *)malloc(len + 1);
	if(copy == NULL) {
		return 0;
	}
	memcpy(copy, header_value, len + 1);
	char *saveptr = NULL;
	for(char *part = strtok_r(copy, ",", &saveptr); part != NULL; part = strtok_r(NULL, ",", &saveptr)) {
		cwebsocket_trim(part);
		if(strcasecmp(part, token) == 0) {
			free(copy);
			return 1;
		}
	}
	free(copy);
	return 0;
}

STATIC void cwebsocket_trim(char *value) {
	if(value == NULL) {
		return;
	}
	char *start = value;
	while(*start && isspace((unsigned char)*start)) {
		start++;
	}
	char *end = start + strlen(start);
	while(end > start && isspace((unsigned char)*(end - 1))) {
		end--;
	}
	size_t len = (size_t)(end - start);
	if(start != value) {
		memmove(value, start, len);
	}
	value[len] = '\0';
}

static ssize_t cwebsocket_client_write_all(cwebsocket_client *websocket, const uint8_t *buffer, size_t length) {
	size_t total = 0;
	while(total < length) {
		size_t remaining = length - total;
#ifdef ENABLE_SSL
		if(websocket->flags & WEBSOCKET_FLAG_SSL) {
			ssize_t written = SSL_write(websocket->ssl, buffer + total, (int)remaining);
			if(written <= 0) {
				int err = SSL_get_error(websocket->ssl, (int)written);
				if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
					continue;
				}
				return -1;
			}
			total += (size_t)written;
			continue;
		}
#endif
		// Use send() with MSG_NOSIGNAL to prevent SIGPIPE and improve performance
		ssize_t written = send(websocket->fd, buffer + total, remaining, MSG_NOSIGNAL);
		if(written < 0) {
			if(errno == EINTR) {
				continue;
			}
			return -1;
		}
		if(written == 0) {
			break;
		}
		total += (size_t)written;
	}
	return (ssize_t)total;
}

void cwebsocket_client_create_masking_key(uint8_t *masking_key) {
	if(cwebsocket_client_random_bytes(masking_key, 4) != 0) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		srand((unsigned int)(tv.tv_usec ^ tv.tv_sec));
		uint32_t fallback = (uint32_t)rand();
		memcpy(masking_key, &fallback, sizeof(fallback));
	}
}

ssize_t cwebsocket_client_write_data(cwebsocket_client *websocket, const char *data, uint64_t payload_len, opcode code) {

    if((websocket->state & WEBSOCKET_STATE_OPEN) == 0 || websocket->protocol_error) {
        syslog(LOG_DEBUG, "cwebsocket_client_write_data: websocket closed");
        cwebsocket_client_onerror(websocket, "websocket closed");
        return -1;
    }

    if(payload_len > SIZE_MAX) {
        syslog(LOG_CRIT, "cwebsocket_client_write_data: payload length too large");
        cwebsocket_client_onerror(websocket, "payload too large");
        return -1;
    }

    // If permessage-deflate negotiated and this is a data frame, compress message once.
    int use_compression = 0;
    uint8_t *comp_buf = NULL;
    size_t comp_len = 0;
    if(websocket->ext_pmdeflate_enabled && (code == TEXT_FRAME || code == BINARY_FRAME)) {
        if(cws_deflate_message(websocket, (const uint8_t*)data, (size_t)payload_len, &comp_buf, &comp_len) == 0) {
            use_compression = 1;
        } else {
            syslog(LOG_WARNING, "cwebsocket_client_write_data: compression failed, sending uncompressed");
        }
    }

    const uint8_t *send_data = use_compression ? comp_buf : (const uint8_t*)data;
    uint64_t send_len = use_compression ? (uint64_t)comp_len : payload_len;

    // Auto-fragment large data frames to improve interoperability and satisfy Autobahn cases.
    // Default fragment size can be overridden via env CWS_AUTO_FRAGMENT_SIZE.
    size_t frag_size = 1300; // sensible default to avoid IP fragmentation
    const char *env_frag = getenv("CWS_AUTO_FRAGMENT_SIZE");
    if(env_frag && *env_frag) {
        long v = strtol(env_frag, NULL, 10);
        if(v > 0 && v < (long)CWS_DATA_BUFFER_MAX) frag_size = (size_t)v;
    }

    // Only data frames (TEXT/BINARY) may be fragmented
    int allow_fragment = (code == TEXT_FRAME || code == BINARY_FRAME);

    if(allow_fragment && send_len > frag_size) {
        ssize_t total_written = 0;
        uint64_t offset = 0;
        opcode current_opcode = code;
        int first_fragment = 1;
        while(offset < send_len) {
            uint64_t remaining = send_len - offset;
            size_t chunk = (remaining > frag_size) ? frag_size : (size_t)remaining;

            // Build one fragment frame
            uint8_t masking_key[4];
            cwebsocket_client_create_masking_key(masking_key);

            size_t header_length = (chunk <= 125) ? 6 : (chunk <= 0xffff ? 8 : 14);
            size_t frame_length = header_length + chunk;
            uint8_t *framebuf = (uint8_t *)malloc(frame_length);
            if(!framebuf) {
                syslog(LOG_CRIT, "cwebsocket_client_write_data: out of memory (fragment)");
                cwebsocket_client_onerror(websocket, "out of memory");
                return -1;
            }
            memset(framebuf, 0, frame_length);

            int fin = (offset + chunk) >= send_len;
            framebuf[0] = (uint8_t)(current_opcode | (fin ? 0x80 : 0x00));
            if(use_compression && first_fragment) {
                framebuf[0] |= 0x40; // RSV1 set on first fragment only
            }

            if(chunk <= 125) {
                framebuf[1] = (uint8_t)(chunk | 0x80);
                memcpy(framebuf + 2, masking_key, sizeof(masking_key));
            } else if(chunk <= 0xffff) {
                uint16_t len16 = htons((uint16_t)chunk);
                framebuf[1] = (uint8_t)(126 | 0x80);
                memcpy(framebuf + 2, &len16, sizeof(len16));
                memcpy(framebuf + 4, masking_key, sizeof(masking_key));
            } else {
                uint8_t len64[8] = htonl64((uint64_t)chunk);
                framebuf[1] = (uint8_t)(127 | 0x80);
                memcpy(framebuf + 2, len64, sizeof(len64));
                memcpy(framebuf + 10, masking_key, sizeof(masking_key));
            }

            memcpy(framebuf + header_length, send_data + offset, chunk);
            for(size_t i = 0; i < chunk; i++) {
                framebuf[header_length + i] ^= masking_key[i % 4];
            }

            ssize_t written = cwebsocket_client_write(websocket, framebuf, (int)frame_length);
            free(framebuf);
            if(written < 0) {
                syslog(LOG_ERR, "cwebsocket_client_write_data: write error during fragmentation: %s", strerror(errno));
                cwebsocket_client_onerror(websocket, strerror(errno));
                return -1;
            }
            total_written += written;
            offset += chunk;
            current_opcode = CONTINUATION;
            first_fragment = 0;
        }
        if(use_compression) {
            free(comp_buf);
        }
        syslog(LOG_DEBUG, "cwebsocket_client_write_data: fragmented write total_bytes=%zd, payload_len=%llu, frag_size=%zu", total_written, (unsigned long long)send_len, frag_size);
        return total_written;
    }

    // Non-fragmented single frame path
    uint8_t masking_key[4];
    cwebsocket_client_create_masking_key(masking_key);

    size_t header_length = 6;
    if(send_len <= 125) {
        header_length = 6;
    }
    else if(send_len <= 0xffff) {
        header_length = 8;
    }
    else {
        header_length = 14;
    }

    size_t frame_length = header_length + (size_t)send_len;
    uint8_t *framebuf = (uint8_t *)malloc(frame_length);
    if(framebuf == NULL) {
        syslog(LOG_CRIT, "cwebsocket_client_write_data: out of memory");
        cwebsocket_client_onerror(websocket, "out of memory");
        return -1;
    }
    memset(framebuf, 0, frame_length);

    framebuf[0] = (uint8_t)(code | 0x80);
    if(send_len <= 125) {
        framebuf[1] = (uint8_t)(send_len | 0x80);
        memcpy(framebuf + 2, masking_key, sizeof(masking_key));
    }
    else if(send_len <= 0xffff) {
        uint16_t len16 = htons((uint16_t)send_len);
        framebuf[1] = (uint8_t)(126 | 0x80);
        memcpy(framebuf + 2, &len16, sizeof(len16));
        memcpy(framebuf + 4, masking_key, sizeof(masking_key));
    }
    else {
        uint8_t len64[8] = htonl64(send_len);
        framebuf[1] = (uint8_t)(127 | 0x80);
        memcpy(framebuf + 2, len64, sizeof(len64));
        memcpy(framebuf + 10, masking_key, sizeof(masking_key));
    }

    if(send_len > 0) {
        memcpy(framebuf + header_length, send_data, (size_t)send_len);
        for(uint64_t i = 0; i < send_len; i++) {
            framebuf[header_length + i] ^= masking_key[i % 4];
        }
    }
    if(use_compression) {
        // Set RSV1 on the single-frame compressed message
        framebuf[0] |= 0x40;
    }
    if(send_len > 125) {
        syslog(LOG_DEBUG, "cwebsocket_client_write_data: header bytes=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                framebuf[0], framebuf[1], framebuf[2], framebuf[3], framebuf[4], framebuf[5], framebuf[6], framebuf[7], framebuf[8], framebuf[9]);
    }

    ssize_t bytes_written = cwebsocket_client_write(websocket, framebuf, (int)frame_length);
    free(framebuf);

    if(bytes_written == -1) {
        syslog(LOG_ERR, "cwebsocket_client_write_data: error: %s", strerror(errno));
        cwebsocket_client_onerror(websocket, strerror(errno));
        return -1;
    }

    if(use_compression) {
        free(comp_buf);
    }
    syslog(LOG_DEBUG, "cwebsocket_client_write_data: bytes_written=%zu, frame_length=%zu, payload_len=%llu", (size_t)bytes_written, frame_length, (unsigned long long)send_len);

    return bytes_written;
}

void cwebsocket_client_close(cwebsocket_client *websocket, uint16_t code, const char *message) {

	if(websocket->fd < 1 && websocket->close_sent) {
		return;
	}

	syslog(LOG_DEBUG, "cwebsocket_client_close: code=%i, message=%s\n", code, message);

	uint16_t close_code = code;
	if(close_code == 0 && message != NULL) {
		close_code = 1000;
	}
	if(close_code > 0 && (close_code < 1000 || close_code == 1005 || close_code == 1006 || close_code == 1015)) {
		close_code = 1000;
	}

	size_t reason_len = (message == NULL) ? 0 : strlen(message);
	size_t payload_len = (close_code > 0 ? 2 : 0) + reason_len;
	uint8_t *close_payload = NULL;
	if(payload_len > 0) {
		close_payload = (uint8_t *)malloc(payload_len);
		if(close_payload == NULL) {
			syslog(LOG_CRIT, "cwebsocket_client_close: out of memory allocating close payload");
			payload_len = 0;
		}
	}

	if(close_payload != NULL) {
		close_payload[0] = (uint8_t)((close_code >> 8) & 0xFF);
		close_payload[1] = (uint8_t)(close_code & 0xFF);
		if(reason_len > 0) {
			memcpy(close_payload + 2, message, reason_len);
		}
	}

    // Send Close frame BEFORE changing state (if WebSocket handshake completed and we haven't sent it yet)
    if(!websocket->close_sent && websocket->fd > 0 && (websocket->state & WEBSOCKET_STATE_OPEN)) {
        cwebsocket_client_send_control_frame(websocket, CLOSE, "CLOSE", close_payload, (int)payload_len);
        websocket->close_sent = 1;
    }

#ifdef ENABLE_THREADS
	pthread_mutex_lock(&websocket->lock);
	websocket->state &= ~WEBSOCKET_STATE_OPEN;
	websocket->state |= WEBSOCKET_STATE_CLOSING;
	pthread_mutex_unlock(&websocket->lock);
#else
	websocket->state &= ~WEBSOCKET_STATE_OPEN;
	websocket->state |= WEBSOCKET_STATE_CLOSING;
#endif

	if(close_payload != NULL) {
		free(close_payload);
	}

#ifdef ENABLE_SSL
	if(websocket->ssl != NULL) {
		SSL_shutdown(websocket->ssl);
		SSL_free(websocket->ssl);
		websocket->ssl = NULL;
	}
	if(websocket->sslctx != NULL) {
		SSL_CTX_free(websocket->sslctx);
		websocket->sslctx = NULL;
	}
#endif

    if(websocket->fd >= 0) {
#ifndef ENABLE_SSL
        if(websocket->fd > 0) {
            // RFC 6455 7.1.1: Client should wait for server to close the TCP connection.
            // If server initiated close (close_received=1), wait for server to close TCP.
            // If we initiated close (!close_received), we can close TCP after a brief wait.
            if(!websocket->close_received) {
                // We initiated close: do half-close and wait briefly for server's close
                if(shutdown(websocket->fd, SHUT_WR) == -1) {
                    syslog(LOG_ERR, "cwebsocket_client_close: unable to shutdown websocket: %s", strerror(errno));
                }
            }
            // Wait for server to close TCP connection or timeout
            {
                fd_set rfds;
                struct timeval tv;
                FD_ZERO(&rfds);
                FD_SET(websocket->fd, &rfds);
                // Use short timeout (100ms) for protocol errors, normal timeout (1-2s) otherwise
                if(websocket->protocol_error) {
                    tv.tv_sec = 0;
                    tv.tv_usec = 100000; // 100ms for protocol errors
                } else {
                    tv.tv_sec = websocket->close_received ? 2 : 1; // wait longer when server initiated
                    tv.tv_usec = 0;
                }
                int sel = select(websocket->fd + 1, &rfds, NULL, NULL, &tv);
                if(sel > 0 && FD_ISSET(websocket->fd, &rfds)) {
                    // Drain to detect server's TCP close
                    char drainbuf[256];
                    ssize_t n = read(websocket->fd, drainbuf, sizeof(drainbuf));
                    if(n == 0) {
                        syslog(LOG_DEBUG, "cwebsocket_client_close: server closed TCP connection cleanly");
                    }
                }
            }
        }
#endif
        if(websocket->fd > 0 && close(websocket->fd) == -1) {
            syslog(LOG_ERR, "cwebsocket_client_close: error closing websocket: %s", strerror(errno));
        }
        websocket->fd = 0;
	}

	if(websocket->fragment_buffer != NULL) {
		free(websocket->fragment_buffer);
		websocket->fragment_buffer = NULL;
		websocket->fragment_capacity = 0;
	}
	cwebsocket_client_reset_fragments(websocket);

	int callback_code = (code > 0) ? code : close_code;
	char *callback_message = NULL;
	if(message != NULL) {
		size_t len = strlen(message);
		callback_message = (char *)malloc(len + 1);
		if(callback_message != NULL) {
			memcpy(callback_message, message, len + 1);
		}
	}

	cwebsocket_client_onclose(websocket, callback_code, callback_message ? callback_message : message);
	if(callback_message != NULL) {
		free(callback_message);
	}

#ifdef ENABLE_THREADS
    pthread_mutex_lock(&websocket->lock);
    websocket->state = WEBSOCKET_STATE_CLOSED;
    pthread_mutex_unlock(&websocket->lock);
#else
    websocket->state = WEBSOCKET_STATE_CLOSED;
#endif

	// Clear protocol_error flag so subsequent connections start fresh
	websocket->protocol_error = 0;
	websocket->close_sent = 0;
	websocket->close_received = 0;

	syslog(LOG_DEBUG, "cwebsocket_client_close: websocket closed\n");

	if(websocket->flags & WEBSOCKET_FLAG_AUTORECONNECT) {
		cwebsocket_client_connect(websocket);
	}
}

ssize_t cwebsocket_client_read(cwebsocket_client *websocket, void *buf, int len) {
#ifdef ENABLE_SSL
	if(websocket->flags & WEBSOCKET_FLAG_SSL) {
		return SSL_read(websocket->ssl, buf, len);
	}
#endif
	// Use recv() instead of read() for better socket performance
	return recv(websocket->fd, buf, len, 0);
}

ssize_t cwebsocket_client_write(cwebsocket_client *websocket, void *buf, int len) {
#ifdef ENABLE_THREADS
	ssize_t bytes_written;
	pthread_mutex_lock(&websocket->write_lock);
	bytes_written = cwebsocket_client_write_all(websocket, (const uint8_t *)buf, (size_t)len);
	pthread_mutex_unlock(&websocket->write_lock);
	return bytes_written;
#else
	return cwebsocket_client_write_all(websocket, (const uint8_t *)buf, (size_t)len);
#endif
}

void cwebsocket_client_onopen(cwebsocket_client *websocket) {
	if(websocket->subprotocol != NULL && websocket->subprotocol->onopen != NULL) {
		websocket->subprotocol->onopen(websocket);
	}
}

void cwebsocket_client_onmessage(cwebsocket_client *websocket, cwebsocket_message *message) {
	if(websocket->subprotocol != NULL && websocket->subprotocol->onmessage != NULL) {
		websocket->subprotocol->onmessage(websocket, message);
	}
}

void cwebsocket_client_onclose(cwebsocket_client *websocket, int code, const char *message) {
	if(websocket->subprotocol != NULL && websocket->subprotocol->onclose != NULL) {
		websocket->subprotocol->onclose(websocket, code, message);
	}
}

void cwebsocket_client_onerror(cwebsocket_client *websocket, const char *error) {
	if(websocket->subprotocol != NULL && websocket->subprotocol->onerror != NULL) {
		websocket->subprotocol->onerror(websocket, error);
	}
}
static void cwebsocket_client_drop(cwebsocket_client *websocket, const char *reason) {
    // Fail the connection cleanly per RFC: send Close(1002) when protocol error occurs
    syslog(LOG_DEBUG, "cwebsocket_client_drop: protocol error -> clean close (1002): %s", reason ? reason : "");
    websocket->protocol_error = 1;
    cwebsocket_client_close(websocket, 1002, reason);
}
    
