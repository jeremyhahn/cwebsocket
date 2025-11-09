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

#ifndef CWEBSOCKET_CLIENT_H
#define CWEBSOCKET_CLIENT_H

#include <time.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <zlib.h>
#include "common.h"

#define WEBSOCKET_FLAG_AUTORECONNECT (1 << 1)

// Performance optimization: buffer pooling
#define BUFFER_POOL_SIZE 64
#define BUFFER_POOL_SMALL 4096      // 4KB buffers
#define BUFFER_POOL_MEDIUM 65536    // 64KB buffers
#define BUFFER_POOL_LARGE 1048576   // 1MB buffers

// Thread pool for parallel message processing
// Note: Thread pool size is now dynamically determined at runtime based on CPU cores
// Allocation strategy:
//   - Multi-core (2+): 1 core for event loop, remaining cores for workers
//   - Single-core: 2 threads (1 for main, 1 for worker)
//   - No thread support: Falls back to synchronous processing
#define MESSAGE_QUEUE_SIZE 256      // Pending message queue

// Zero-copy API flag
#define WEBSOCKET_MSG_ZEROCOPY (1 << 0)

typedef struct {
	uint8_t *buffer;
	size_t capacity;
	uint8_t in_use;
	uint8_t size_class; // 0=small, 1=medium, 2=large
} buffer_pool_entry;

typedef struct {
	buffer_pool_entry entries[BUFFER_POOL_SIZE];
#ifdef ENABLE_THREADS
	pthread_mutex_t lock;
#endif
} buffer_pool;

// Forward declaration
typedef struct _cwebsocket cwebsocket_client;

#ifdef ENABLE_THREADS
// Thread pool for message processing
typedef struct {
	cwebsocket_client *socket;
	cwebsocket_message *message;
} thread_pool_task;

typedef struct {
	pthread_t *threads;         // Dynamically allocated based on CPU cores
	int num_threads;            // Actual number of worker threads
	thread_pool_task queue[MESSAGE_QUEUE_SIZE];
	size_t queue_head;
	size_t queue_tail;
	size_t queue_size;
	pthread_mutex_t queue_lock;
	pthread_cond_t queue_not_empty;
	pthread_cond_t queue_not_full;
	int shutdown;
} thread_pool;
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct _cwebsocket {
	int fd;
	int retry;
	char *uri;
	uint8_t flags;
	uint8_t state;
#ifdef ENABLE_SSL
	SSL_CTX *sslctx;
	SSL *ssl;
#endif
#ifdef ENABLE_THREADS
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_mutex_t write_lock;
#endif
	size_t subprotocol_len;
	cwebsocket_subprotocol *subprotocol;
	uint8_t *fragment_buffer;
	size_t fragment_length;
	size_t fragment_capacity;
	opcode fragment_opcode;
	int fragment_in_progress;
	int close_sent;
	int close_received;
	// UTF-8 validation state for fragmented text messages
	uint32_t utf8_state;
	uint32_t utf8_codepoint;
	int protocol_error;
    // permessage-deflate extension flags/state
    int ext_pmdeflate_enabled;
    int pmdeflate_in_progress;
    z_stream zin;
    z_stream zout;
	int pmdeflate_opcode; // opcode of current compressed message (TEXT or BINARY)
	int pmdeflate_client_window_bits; // Negotiated client window bits (8-15, default 15)
	int pmdeflate_server_window_bits; // Negotiated server window bits (8-15, default 15)
	// Performance optimizations
	buffer_pool *msg_buffer_pool;
#ifdef ENABLE_THREADS
	thread_pool *msg_thread_pool;
#endif
	uint8_t *user_buffer; // Zero-copy: user-provided buffer
	size_t user_buffer_size;
	cwebsocket_subprotocol *subprotocols[];
};

typedef struct {
	cwebsocket_client *socket;
	cwebsocket_message *message;
} cwebsocket_client_thread_args;

// "public"
void cwebsocket_client_init(cwebsocket_client *websocket, cwebsocket_subprotocol *subprotocols[], int subprotocol_len);
int cwebsocket_client_connect(cwebsocket_client *websocket);
int cwebsocket_client_read_data(cwebsocket_client *websocket);
ssize_t cwebsocket_client_write_data(cwebsocket_client *websocket, const char *data, uint64_t len, opcode code);
void cwebsocket_client_run(cwebsocket_client *websocket);
void cwebsocket_client_close(cwebsocket_client *websocket, uint16_t code, const char *reason);
void cwebsocket_client_listen(cwebsocket_client *websocket);

// Zero-copy API
void cwebsocket_client_set_user_buffer(cwebsocket_client *websocket, uint8_t *buffer, size_t size);

// Buffer pool management
buffer_pool* cwebsocket_buffer_pool_create(void);
void cwebsocket_buffer_pool_destroy(buffer_pool *pool);
uint8_t* cwebsocket_buffer_pool_acquire(buffer_pool *pool, size_t size);
void cwebsocket_buffer_pool_release(buffer_pool *pool, uint8_t *buffer);

#ifdef ENABLE_THREADS
// Thread pool management
thread_pool* cwebsocket_thread_pool_create(void);
void cwebsocket_thread_pool_destroy(thread_pool *pool);
int cwebsocket_thread_pool_submit(thread_pool *pool, cwebsocket_client *socket, cwebsocket_message *message);
#endif

// "private"
void cwebsocket_client_parse_uri(cwebsocket_client *websocket, const char *uri, char *hostname, char *port, char *resource, char *querystring);
int cwebsocket_client_handshake_handler(cwebsocket_client *websocket, const char *handshake_response, char *seckey);
int cwebsocket_client_read_handshake(cwebsocket_client *websocket, char *seckey);
int cwebsocket_client_send_control_frame(cwebsocket_client *websocket, opcode opcode, const char *frame_type, const uint8_t *payload, int payload_len);
void cwebsocket_client_create_masking_key(uint8_t *masking_key);
ssize_t cwebsocket_client_read(cwebsocket_client *websocket, void *buf, int len);
ssize_t cwebsocket_client_write(cwebsocket_client *websocket, void *buf, int len);
void cwebsocket_client_onopen(cwebsocket_client *websocket);
void cwebsocket_client_onmessage(cwebsocket_client *websocket, cwebsocket_message *message);
void cwebsocket_client_onclose(cwebsocket_client *websocket, int code, const char *message);
void cwebsocket_client_onerror(cwebsocket_client *websocket, const char *error);

#ifdef __cplusplus
}
#endif

#endif
