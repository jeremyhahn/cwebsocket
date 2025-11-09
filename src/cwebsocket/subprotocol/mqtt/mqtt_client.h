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

#ifndef MQTT_SUBPROTOCOL_H_
#define MQTT_SUBPROTOCOL_H_

#include "../../common.h"
#include "../../client.h"
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

// MQTT protocol versions
#define MQTT_VERSION_3_1_1 0x04
#define MQTT_VERSION_5_0   0x05
#define MQTT_VERSION_DEFAULT MQTT_VERSION_5_0

// MQTT Control Packet Types (4 bits)
typedef enum {
    MQTT_RESERVED_0     = 0,
    MQTT_CONNECT        = 1,
    MQTT_CONNACK        = 2,
    MQTT_PUBLISH        = 3,
    MQTT_PUBACK         = 4,
    MQTT_PUBREC         = 5,
    MQTT_PUBREL         = 6,
    MQTT_PUBCOMP        = 7,
    MQTT_SUBSCRIBE      = 8,
    MQTT_SUBACK         = 9,
    MQTT_UNSUBSCRIBE    = 10,
    MQTT_UNSUBACK       = 11,
    MQTT_PINGREQ        = 12,
    MQTT_PINGRESP       = 13,
    MQTT_DISCONNECT     = 14,
    MQTT_AUTH           = 15
} mqtt_packet_type;

// MQTT Quality of Service Levels
typedef enum {
    MQTT_QOS_0 = 0,  // At most once (fire and forget)
    MQTT_QOS_1 = 1,  // At least once (acknowledged delivery)
    MQTT_QOS_2 = 2   // Exactly once (assured delivery)
} mqtt_qos;

// MQTT Connection Return Codes (MQTT 5.0 Reason Codes)
typedef enum {
    MQTT_RC_SUCCESS                         = 0x00,
    MQTT_RC_NORMAL_DISCONNECTION            = 0x00,
    MQTT_RC_GRANTED_QOS_0                   = 0x00,
    MQTT_RC_GRANTED_QOS_1                   = 0x01,
    MQTT_RC_GRANTED_QOS_2                   = 0x02,
    MQTT_RC_DISCONNECT_WITH_WILL            = 0x04,
    MQTT_RC_NO_MATCHING_SUBSCRIBERS         = 0x10,
    MQTT_RC_NO_SUBSCRIPTION_EXISTED         = 0x11,
    MQTT_RC_CONTINUE_AUTHENTICATION         = 0x18,
    MQTT_RC_REAUTHENTICATE                  = 0x19,
    MQTT_RC_UNSPECIFIED_ERROR               = 0x80,
    MQTT_RC_MALFORMED_PACKET                = 0x81,
    MQTT_RC_PROTOCOL_ERROR                  = 0x82,
    MQTT_RC_IMPLEMENTATION_SPECIFIC_ERROR   = 0x83,
    MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION    = 0x84,
    MQTT_RC_CLIENT_ID_NOT_VALID             = 0x85,
    MQTT_RC_BAD_USERNAME_OR_PASSWORD        = 0x86,
    MQTT_RC_NOT_AUTHORIZED                  = 0x87,
    MQTT_RC_SERVER_UNAVAILABLE              = 0x88,
    MQTT_RC_SERVER_BUSY                     = 0x89,
    MQTT_RC_BANNED                          = 0x8A,
    MQTT_RC_SERVER_SHUTTING_DOWN            = 0x8B,
    MQTT_RC_BAD_AUTHENTICATION_METHOD       = 0x8C,
    MQTT_RC_KEEPALIVE_TIMEOUT               = 0x8D,
    MQTT_RC_SESSION_TAKEN_OVER              = 0x8E,
    MQTT_RC_TOPIC_FILTER_INVALID            = 0x8F,
    MQTT_RC_TOPIC_NAME_INVALID              = 0x90,
    MQTT_RC_PACKET_ID_IN_USE                = 0x91,
    MQTT_RC_PACKET_ID_NOT_FOUND             = 0x92,
    MQTT_RC_RECEIVE_MAXIMUM_EXCEEDED        = 0x93,
    MQTT_RC_TOPIC_ALIAS_INVALID             = 0x94,
    MQTT_RC_PACKET_TOO_LARGE                = 0x95,
    MQTT_RC_MESSAGE_RATE_TOO_HIGH           = 0x96,
    MQTT_RC_QUOTA_EXCEEDED                  = 0x97,
    MQTT_RC_ADMINISTRATIVE_ACTION           = 0x98,
    MQTT_RC_PAYLOAD_FORMAT_INVALID          = 0x99,
    MQTT_RC_RETAIN_NOT_SUPPORTED            = 0x9A,
    MQTT_RC_QOS_NOT_SUPPORTED               = 0x9B,
    MQTT_RC_USE_ANOTHER_SERVER              = 0x9C,
    MQTT_RC_SERVER_MOVED                    = 0x9D,
    MQTT_RC_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED = 0x9E,
    MQTT_RC_CONNECTION_RATE_EXCEEDED        = 0x9F,
    MQTT_RC_MAXIMUM_CONNECT_TIME            = 0xA0,
    MQTT_RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED = 0xA1,
    MQTT_RC_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED = 0xA2
} mqtt_reason_code;

// MQTT 5.0 Property Identifiers
typedef enum {
    MQTT_PROP_PAYLOAD_FORMAT_INDICATOR      = 0x01,
    MQTT_PROP_MESSAGE_EXPIRY_INTERVAL       = 0x02,
    MQTT_PROP_CONTENT_TYPE                  = 0x03,
    MQTT_PROP_RESPONSE_TOPIC                = 0x08,
    MQTT_PROP_CORRELATION_DATA              = 0x09,
    MQTT_PROP_SUBSCRIPTION_IDENTIFIER       = 0x0B,
    MQTT_PROP_SESSION_EXPIRY_INTERVAL       = 0x11,
    MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER    = 0x12,
    MQTT_PROP_SERVER_KEEP_ALIVE             = 0x13,
    MQTT_PROP_AUTHENTICATION_METHOD         = 0x15,
    MQTT_PROP_AUTHENTICATION_DATA           = 0x16,
    MQTT_PROP_REQUEST_PROBLEM_INFORMATION   = 0x17,
    MQTT_PROP_WILL_DELAY_INTERVAL           = 0x18,
    MQTT_PROP_REQUEST_RESPONSE_INFORMATION  = 0x19,
    MQTT_PROP_RESPONSE_INFORMATION          = 0x1A,
    MQTT_PROP_SERVER_REFERENCE              = 0x1C,
    MQTT_PROP_REASON_STRING                 = 0x1F,
    MQTT_PROP_RECEIVE_MAXIMUM               = 0x21,
    MQTT_PROP_TOPIC_ALIAS_MAXIMUM           = 0x22,
    MQTT_PROP_TOPIC_ALIAS                   = 0x23,
    MQTT_PROP_MAXIMUM_QOS                   = 0x24,
    MQTT_PROP_RETAIN_AVAILABLE              = 0x25,
    MQTT_PROP_USER_PROPERTY                 = 0x26,
    MQTT_PROP_MAXIMUM_PACKET_SIZE           = 0x27,
    MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE = 0x28,
    MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE = 0x29,
    MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE = 0x2A
} mqtt_property_id;

// MQTT Property structure
typedef struct mqtt_property {
    mqtt_property_id id;
    union {
        uint8_t byte;
        uint16_t u16;
        uint32_t u32;
        char *string;
        struct {
            uint8_t *data;
            uint16_t len;
        } binary;
        struct {
            char *key;
            char *value;
        } user_property;
    } value;
    struct mqtt_property *next;
} mqtt_property;

// MQTT Fixed Header
typedef struct {
    mqtt_packet_type type;
    uint8_t flags;      // DUP, QoS, RETAIN flags
    uint32_t remaining_length;
} mqtt_fixed_header;

// MQTT Packet structure
typedef struct {
    mqtt_fixed_header header;
    uint8_t *variable_header;
    size_t variable_header_len;
    uint8_t *payload;
    size_t payload_len;
} mqtt_packet;

// Forward declaration for persistence
typedef struct mqtt_persistence_strategy mqtt_persistence_strategy;

// MQTT Subscription structure
typedef struct mqtt_subscription {
    char *topic_filter;
    mqtt_qos qos;
    uint8_t no_local;
    uint8_t retain_as_published;
    uint8_t retain_handling;
    uint8_t is_shared_subscription;  // 1 if this is a shared subscription
    char *share_name;                 // Share name for shared subscriptions (NULL otherwise)
    struct mqtt_subscription *next;
} mqtt_subscription;

// Pending acknowledgment (for QoS 1 and 2)
typedef struct mqtt_pending_ack {
    uint16_t packet_id;
    mqtt_packet_type packet_type;
    mqtt_qos qos;
    char *topic;
    uint8_t *payload;
    size_t payload_len;
    struct timeval timestamp;
    int retry_count;
    struct mqtt_pending_ack *next;
} mqtt_pending_ack;

// Packet ID Pool - manages packet IDs from 1-65535
// Uses bitmap for efficient O(1) allocation and deallocation
#define MQTT_PACKET_ID_MAX 65535
#define MQTT_PACKET_ID_BITMAP_SIZE ((MQTT_PACKET_ID_MAX + 63) / 64)  // Round up to 64-bit chunks

typedef struct {
    uint64_t bitmap[MQTT_PACKET_ID_BITMAP_SIZE];  // Bitmap: 1 = in use, 0 = available
    uint16_t last_allocated;                       // Last allocated ID for round-robin
    uint16_t in_use_count;                         // Number of IDs currently in use
} mqtt_packet_id_pool;

// Topic Alias mapping entry
typedef struct mqtt_topic_alias {
    uint16_t alias;
    char *topic;
    struct mqtt_topic_alias *next;
} mqtt_topic_alias;

// MQTT Message structure - passed to application callbacks
// Contains all information from a received PUBLISH message
typedef struct mqtt_message {
    const char *topic;           // Topic name (NULL-terminated)
    const uint8_t *payload;      // Message payload (may contain binary data)
    size_t payload_len;          // Length of payload in bytes
    mqtt_qos qos;                // Quality of Service level
    uint8_t retain;              // Retain flag
    uint8_t dup;                 // Duplicate delivery flag
    uint16_t packet_id;          // Packet identifier (0 for QoS 0)
    mqtt_property *properties;   // MQTT 5.0 properties (NULL if none)
} mqtt_message;

// Forward declaration for authentication callback
typedef struct mqtt_client_state mqtt_client_state;

// MQTT message callback function signature
// Called when a PUBLISH message is received
// The application must free the mqtt_message and its properties after processing
typedef void (*mqtt_message_callback)(
    cwebsocket_client *client,
    mqtt_message *message
);

// Authentication callback function signature
// Parameters:
//   - state: mqtt client state
//   - method: authentication method string (e.g., "SCRAM-SHA-1", "OAUTH2")
//   - data: authentication challenge data from server (may be NULL)
//   - data_len: length of authentication data
//   - response_data: output parameter for response data (caller allocates)
//   - response_len: output parameter for response data length
// Returns: 0 on success to continue auth, -1 to abort, 1 to send AUTH with data
typedef int (*mqtt_auth_callback)(
    mqtt_client_state *state,
    const char *method,
    const uint8_t *data,
    size_t data_len,
    uint8_t **response_data,
    size_t *response_len
);

// MQTT Client State (per-connection)
struct mqtt_client_state {
    // Connection parameters
    char *client_id;
    char *username;
    char *password;
    uint8_t protocol_version;
    uint16_t keep_alive;
    uint8_t clean_start;

    // Persistence strategy
    mqtt_persistence_strategy *persistence;

    // Connection state
    int connected;
    uint32_t session_expiry_interval;
    uint16_t receive_maximum;
    uint8_t maximum_qos;
    uint8_t retain_available;
    uint32_t maximum_packet_size;
    uint16_t topic_alias_maximum;
    char *assigned_client_id;
    uint8_t wildcard_subscription_available;  // From CONNACK
    uint8_t subscription_identifier_available; // From CONNACK
    uint8_t shared_subscription_available;     // From CONNACK

    // Enhanced authentication (MQTT 5.0)
    char *authentication_method;           // Authentication method for enhanced auth
    mqtt_auth_callback auth_callback;      // Callback for authentication challenges
    void *auth_context;                    // User context for authentication
    uint8_t auth_in_progress;              // Flag indicating authentication is ongoing

    // Message callback
    mqtt_message_callback message_callback; // Callback for received PUBLISH messages
    void *message_context;                  // User context for message callback

    // Will message
    struct {
        char *topic;
        uint8_t *payload;
        size_t payload_len;
        mqtt_qos qos;
        uint8_t retain;
        uint32_t delay_interval;
        mqtt_property *properties;
    } will;

    // Keep-alive tracking
    struct timeval last_packet_sent;
    struct timeval last_packet_received;

    // Packet ID management
    uint16_t next_packet_id;  // Deprecated - kept for compatibility
    mqtt_packet_id_pool *packet_id_pool;  // New robust packet ID pool

    // Subscription management
    mqtt_subscription *subscriptions;

    // Pending acknowledgments (QoS 1 and 2)
    mqtt_pending_ack *pending_acks;

    // Flow control
    uint16_t in_flight_qos_count;          // Current count of in-flight QoS 1/2 messages
    uint16_t server_receive_maximum;       // Server's receive maximum from CONNACK
    uint32_t server_maximum_packet_size;   // Server's maximum packet size from CONNACK
    uint16_t server_topic_alias_maximum;   // Server's topic alias maximum from CONNACK
    mqtt_topic_alias *topic_aliases;       // Topic alias mappings
    uint16_t next_topic_alias;             // Next alias to assign

    // Properties
    mqtt_property *connect_properties;
};

// Factory function to create MQTT subprotocol
cwebsocket_subprotocol* cwebsocket_subprotocol_mqtt_client_new(
    const char *client_id,
    const char *username,
    const char *password,
    uint8_t clean_start,
    uint16_t keep_alive
);

// Connection management
void mqtt_set_will_message(
    cwebsocket_client *client,
    const char *will_topic,
    const uint8_t *will_payload,
    size_t will_payload_len,
    mqtt_qos will_qos,
    uint8_t will_retain,
    uint32_t will_delay_interval
);

void mqtt_send_connect(
    cwebsocket_client *client,
    const char *client_id,
    const char *username,
    const char *password,
    uint16_t keep_alive,
    uint8_t clean_start
);

void mqtt_send_disconnect(
    cwebsocket_client *client,
    mqtt_reason_code reason_code,
    const char *reason_string
);

void mqtt_send_pingreq(cwebsocket_client *client);

// Message callback
void mqtt_set_message_callback(
    cwebsocket_client *client,
    mqtt_message_callback callback,
    void *context
);

void mqtt_message_free(mqtt_message *message);

// Enhanced authentication (MQTT 5.0)
void mqtt_set_authentication(
    cwebsocket_client *client,
    const char *authentication_method,
    mqtt_auth_callback auth_callback,
    void *auth_context
);

void mqtt_send_auth(
    cwebsocket_client *client,
    mqtt_reason_code reason_code,
    const char *authentication_method,
    const uint8_t *authentication_data,
    size_t authentication_data_len
);

// Subscription management
void mqtt_send_subscribe(
    cwebsocket_client *client,
    const char *topic_filter,
    mqtt_qos qos,
    uint8_t no_local,
    uint8_t retain_as_published,
    uint8_t retain_handling
);

void mqtt_send_subscribe_ex(
    cwebsocket_client *client,
    const char *topic_filter,
    mqtt_qos qos,
    uint8_t no_local,
    uint8_t retain_as_published,
    uint8_t retain_handling,
    uint32_t subscription_identifier
);

void mqtt_send_unsubscribe(
    cwebsocket_client *client,
    const char *topic_filter
);

// Publishing
void mqtt_send_publish(
    cwebsocket_client *client,
    const char *topic,
    const uint8_t *payload,
    size_t payload_len,
    mqtt_qos qos,
    uint8_t retain,
    uint8_t dup
);

void mqtt_send_publish_ex(
    cwebsocket_client *client,
    const char *topic,
    const uint8_t *payload,
    size_t payload_len,
    mqtt_qos qos,
    uint8_t retain,
    uint8_t dup,
    mqtt_property *properties
);

void mqtt_send_puback(
    cwebsocket_client *client,
    uint16_t packet_id,
    mqtt_reason_code reason_code
);

void mqtt_send_pubrec(
    cwebsocket_client *client,
    uint16_t packet_id,
    mqtt_reason_code reason_code
);

void mqtt_send_pubrel(
    cwebsocket_client *client,
    uint16_t packet_id,
    mqtt_reason_code reason_code
);

void mqtt_send_pubcomp(
    cwebsocket_client *client,
    uint16_t packet_id,
    mqtt_reason_code reason_code
);

// Packet encoding/decoding
mqtt_packet* mqtt_packet_decode(const uint8_t *data, size_t len);
uint8_t* mqtt_packet_encode(mqtt_packet *packet, size_t *out_len);
void mqtt_packet_free(mqtt_packet *packet);

// Variable Byte Integer encoding/decoding (MQTT 5.0 spec)
int mqtt_encode_variable_byte_integer(uint32_t value, uint8_t *output);
int mqtt_decode_variable_byte_integer(const uint8_t *input, uint32_t *value, int *bytes_consumed);

// UTF-8 string encoding/decoding
int mqtt_encode_utf8_string(const char *str, uint8_t *output);
int mqtt_decode_utf8_string(const uint8_t *input, char **str, int *bytes_consumed);

// Binary data encoding/decoding
int mqtt_encode_binary_data(const uint8_t *data, uint16_t len, uint8_t *output);
int mqtt_decode_binary_data(const uint8_t *input, uint8_t **data, uint16_t *len, int *bytes_consumed);

// Property management
mqtt_property* mqtt_property_create(mqtt_property_id id);
void mqtt_property_free(mqtt_property *prop);
void mqtt_properties_free(mqtt_property *props);
int mqtt_encode_properties(mqtt_property *props, uint8_t *output);
int mqtt_decode_properties(const uint8_t *input, mqtt_property **props, int *bytes_consumed);

// Helper functions for creating common PUBLISH properties
mqtt_property* mqtt_property_create_payload_format_indicator(uint8_t is_utf8);
mqtt_property* mqtt_property_create_message_expiry(uint32_t seconds);
mqtt_property* mqtt_property_create_content_type(const char *content_type);
mqtt_property* mqtt_property_create_response_topic(const char *topic);
mqtt_property* mqtt_property_create_correlation_data(const uint8_t *data, uint16_t len);
mqtt_property* mqtt_property_create_user_property(const char *key, const char *value);

// Helper function to find a property by ID
mqtt_property* mqtt_property_find(mqtt_property *props, mqtt_property_id id);
const char* mqtt_property_get_string(mqtt_property *props, mqtt_property_id id);
uint32_t mqtt_property_get_u32(mqtt_property *props, mqtt_property_id id, uint32_t default_value);
uint8_t mqtt_property_get_byte(mqtt_property *props, mqtt_property_id id, uint8_t default_value);

// Keep-alive management
void mqtt_keepalive_check(cwebsocket_client *client);

// Packet ID management (legacy - deprecated)
uint16_t mqtt_get_next_packet_id(mqtt_client_state *state);

// Packet ID Pool management (robust implementation)
mqtt_packet_id_pool* mqtt_packet_id_pool_create(void);
void mqtt_packet_id_pool_destroy(mqtt_packet_id_pool *pool);
uint16_t mqtt_packet_id_pool_allocate(mqtt_packet_id_pool *pool);
int mqtt_packet_id_pool_release(mqtt_packet_id_pool *pool, uint16_t packet_id);
int mqtt_packet_id_pool_is_in_use(mqtt_packet_id_pool *pool, uint16_t packet_id);
uint16_t mqtt_packet_id_pool_get_in_use_count(mqtt_packet_id_pool *pool);

// Utility functions
const char* mqtt_packet_type_to_string(mqtt_packet_type type);
const char* mqtt_qos_to_string(mqtt_qos qos);
const char* mqtt_reason_code_to_string(mqtt_reason_code code);

// Shared subscription functions
int mqtt_parse_shared_subscription(const char *topic_filter,
                                    char **share_name_out,
                                    char **topic_filter_out);
int mqtt_validate_shared_subscription(const char *topic_filter);
int mqtt_is_shared_subscription(const char *topic_filter);

// Get state from client
mqtt_client_state* mqtt_get_client_state(cwebsocket_client *client);

// Flow control functions
int mqtt_can_send_qos_message(mqtt_client_state *state);
void mqtt_increment_in_flight(mqtt_client_state *state);
void mqtt_decrement_in_flight(mqtt_client_state *state);
int mqtt_validate_packet_size(mqtt_client_state *state, size_t packet_size);

// Topic alias functions
uint16_t mqtt_topic_alias_get(mqtt_client_state *state, const char *topic);
int mqtt_topic_alias_set(mqtt_client_state *state, uint16_t alias, const char *topic);
const char* mqtt_topic_alias_lookup(mqtt_client_state *state, uint16_t alias);
void mqtt_topic_alias_free_all(mqtt_client_state *state);


// Persistence API
void mqtt_client_set_persistence_strategy(
    cwebsocket_client *client,
    mqtt_persistence_strategy *strategy
);

mqtt_persistence_strategy* mqtt_client_get_persistence_strategy(
    cwebsocket_client *client
);

#ifdef __cplusplus
}
#endif

#endif
