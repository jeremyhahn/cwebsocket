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

#ifndef STOMP_SUBPROTOCOL_H_
#define STOMP_SUBPROTOCOL_H_

#include "../../common.h"
#include "../../client.h"
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

// STOMP protocol versions
#define STOMP_VERSION_1_0 "1.0"
#define STOMP_VERSION_1_1 "1.1"
#define STOMP_VERSION_1_2 "1.2"
#define STOMP_VERSION_DEFAULT STOMP_VERSION_1_2

// STOMP frame types
typedef enum {
    STOMP_CONNECT,
    STOMP_STOMP,
    STOMP_CONNECTED,
    STOMP_SEND,
    STOMP_SUBSCRIBE,
    STOMP_UNSUBSCRIBE,
    STOMP_ACK,
    STOMP_NACK,
    STOMP_BEGIN,
    STOMP_COMMIT,
    STOMP_ABORT,
    STOMP_MESSAGE,
    STOMP_RECEIPT,
    STOMP_ERROR,
    STOMP_DISCONNECT,
    STOMP_UNKNOWN
} stomp_command;

// ACK modes
typedef enum {
    STOMP_ACK_AUTO,           // Server automatically acks
    STOMP_ACK_CLIENT,         // Client must ack received messages
    STOMP_ACK_CLIENT_INDIVIDUAL  // Client must ack each message individually
} stomp_ack_mode;

// Header structure (key-value pair)
typedef struct stomp_header {
    char *key;
    char *value;
    struct stomp_header *next;
} stomp_header;

// STOMP frame structure
typedef struct {
    stomp_command command;
    stomp_header *headers;     // Linked list of headers
    char *body;
    size_t body_len;
} stomp_frame;

// Subscription structure
typedef struct stomp_subscription {
    char *id;
    char *destination;
    stomp_ack_mode ack_mode;
    char *selector;  // Message selector for filtering
    struct stomp_subscription *next;
} stomp_subscription;

// Transaction structure
typedef struct stomp_transaction {
    char *id;
    int active;
    struct stomp_transaction *next;
} stomp_transaction;

// Receipt tracking
typedef struct stomp_receipt {
    char *receipt_id;
    stomp_command original_command;
    void (*callback)(void *user_data, const char *receipt_id);
    void *user_data;
    struct stomp_receipt *next;
} stomp_receipt;

// Heartbeat configuration
typedef struct {
    int outgoing_ms;  // Can send heartbeats every X ms (0 = cannot send)
    int incoming_ms;  // Want to receive heartbeats every X ms (0 = don't want)
    int negotiated_send_ms;    // Negotiated send interval
    int negotiated_receive_ms; // Negotiated receive interval
    struct timeval last_sent;
    struct timeval last_received;
} stomp_heartbeat;

// STOMP client state (per-connection)
typedef struct {
    char *session_id;
    char *server;
    char *version;           // Negotiated protocol version
    int connected;

    // Connection parameters
    char *host;
    char *login;
    char *passcode;

    // Heartbeat support
    stomp_heartbeat heartbeat;

    // Subscription management
    stomp_subscription *subscriptions;
    int subscription_counter;

    // Transaction management
    stomp_transaction *transactions;

    // Receipt tracking
    stomp_receipt *receipts;
    int receipt_counter;

    // Pending messages (for client/client-individual ack modes)
    struct {
        char **message_ids;
        char **subscription_ids;
        int count;
        int capacity;
    } pending_acks;
} stomp_client_state;

// Factory function to create STOMP subprotocol
cwebsocket_subprotocol* cwebsocket_subprotocol_stomp_client_new(
    const char *host,
    const char *login,
    const char *passcode
);

// Connection management
void stomp_send_connect(
    cwebsocket_client *client,
    const char *host,
    const char *login,
    const char *passcode,
    const char *version,
    int heartbeat_send_ms,
    int heartbeat_receive_ms
);

void stomp_send_disconnect(
    cwebsocket_client *client,
    const char *receipt_id
);

// Subscription management
void stomp_send_subscribe(
    cwebsocket_client *client,
    const char *destination,
    const char *id,
    stomp_ack_mode ack_mode,
    const char *selector
);

void stomp_send_unsubscribe(
    cwebsocket_client *client,
    const char *id,
    const char *receipt_id
);

// Message operations
void stomp_send_message(
    cwebsocket_client *client,
    const char *destination,
    const char *body,
    size_t body_len,
    const char *content_type,
    const char *receipt_id,
    const char *transaction_id
);

void stomp_send_ack(
    cwebsocket_client *client,
    const char *message_id,
    const char *subscription_id,
    const char *transaction_id
);

void stomp_send_nack(
    cwebsocket_client *client,
    const char *message_id,
    const char *subscription_id,
    const char *transaction_id
);

// Transaction operations
void stomp_begin_transaction(
    cwebsocket_client *client,
    const char *transaction_id
);

void stomp_commit_transaction(
    cwebsocket_client *client,
    const char *transaction_id,
    const char *receipt_id
);

void stomp_abort_transaction(
    cwebsocket_client *client,
    const char *transaction_id,
    const char *receipt_id
);

// Frame parsing and construction
stomp_frame* stomp_parse_frame(const char *data, size_t len);
void stomp_frame_free(stomp_frame *frame);
char* stomp_frame_serialize(stomp_frame *frame, size_t *out_len);

// Header management
void stomp_frame_add_header(stomp_frame *frame, const char *key, const char *value);
void stomp_frame_add_header_no_escape(stomp_frame *frame, const char *key, const char *value);
const char* stomp_frame_get_header(stomp_frame *frame, const char *key);
void stomp_headers_free(stomp_header *headers);

// String escaping per STOMP 1.2 spec
char* stomp_escape_header_value(const char *value);
char* stomp_unescape_header_value(const char *value);

// Heartbeat management
void stomp_heartbeat_send(cwebsocket_client *client);
int stomp_heartbeat_check(cwebsocket_client *client);  // Returns 1 if timeout detected

// Receipt management
void stomp_add_receipt_handler(
    cwebsocket_client *client,
    const char *receipt_id,
    stomp_command original_command,
    void (*callback)(void *user_data, const char *receipt_id),
    void *user_data
);

// Utility functions
const char* stomp_command_to_string(stomp_command cmd);
stomp_command stomp_string_to_command(const char *str);
const char* stomp_ack_mode_to_string(stomp_ack_mode mode);

// Get state from client (internal use)
stomp_client_state* stomp_get_client_state(cwebsocket_client *client);

#ifdef __cplusplus
}
#endif

#endif
