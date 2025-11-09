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

// MQTT Property structure (simplified)
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

// MQTT Subscription structure
typedef struct mqtt_subscription {
    char *topic_filter;
    mqtt_qos qos;
    uint8_t no_local;
    uint8_t retain_as_published;
    uint8_t retain_handling;
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

// Forward declaration for persistence
typedef struct mqtt_persistence_strategy mqtt_persistence_strategy;

// MQTT Client State (per-connection)
typedef struct {
    // Connection parameters
    char *client_id;
    char *username;
    char *password;
    uint8_t protocol_version;
    uint16_t keep_alive;
    uint8_t clean_start;

    // Connection state
    int connected;
    uint32_t session_expiry_interval;
    uint16_t receive_maximum;
    uint8_t maximum_qos;
    uint8_t retain_available;
    uint32_t maximum_packet_size;
    uint16_t topic_alias_maximum;
    char *assigned_client_id;

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
    uint16_t next_packet_id;

    // Subscription management
    mqtt_subscription *subscriptions;

    // Pending acknowledgments (QoS 1 and 2)
    mqtt_pending_ack *pending_acks;

    // Properties
    mqtt_property *connect_properties;

    // Persistence strategy
    mqtt_persistence_strategy *persistence;
} mqtt_client_state;

// Factory function to create MQTT subprotocol
cwebsocket_subprotocol* cwebsocket_subprotocol_mqtt_client_new(
    const char *client_id,
    const char *username,
    const char *password,
    uint8_t clean_start,
    uint16_t keep_alive,
    mqtt_persistence_strategy *persistence
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

// Enhanced authentication (MQTT 5.0)
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

// Keep-alive management
void mqtt_keepalive_check(cwebsocket_client *client);

// Packet ID management
uint16_t mqtt_get_next_packet_id(mqtt_client_state *state);

// Utility functions
const char* mqtt_packet_type_to_string(mqtt_packet_type type);
const char* mqtt_qos_to_string(mqtt_qos qos);
const char* mqtt_reason_code_to_string(mqtt_reason_code code);

// Get state from client
mqtt_client_state* mqtt_get_client_state(cwebsocket_client *client);

#ifdef __cplusplus
}
#endif

#endif
