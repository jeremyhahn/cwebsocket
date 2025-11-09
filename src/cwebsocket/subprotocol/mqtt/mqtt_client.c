/**
 *  Production-Grade MQTT 5.0 Client Implementation
 *
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

#include "mqtt_client.h"
#include "mqtt_persistence.h"
#include "mqtt_scram.h"
#include "../../logging.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Global client state (simplified for single connection)
static mqtt_client_state *global_mqtt_state = NULL;

// Buffer size constants for overflow protection
#define MQTT_MAX_TOPIC_LENGTH 65535
#define MQTT_MAX_PAYLOAD_SIZE (256 * 1024 * 1024)  // 256 MB max
#define MQTT_VAR_HEADER_BUFFER_SIZE 2048
#define MQTT_PAYLOAD_BUFFER_SIZE 4096
#define MQTT_PROPS_BUFFER_SIZE 1024
#define MQTT_SMALL_BUFFER_SIZE 256

// =============================================================================
// Persistence Helper Functions
// =============================================================================

static int mqtt_persist_session(mqtt_client_state *state) {
    if (!state || !state->persistence || !state->persistence->save_session) {
        return 0;
    }

    mqtt_persisted_session session = {0};
    session.client_id = state->client_id;
    session.session_expiry_interval = state->session_expiry_interval;
    session.session_created = (uint32_t)time(NULL);
    session.session_last_accessed = (uint32_t)time(NULL);
    session.next_packet_id = state->next_packet_id;

    // Convert subscriptions
    mqtt_subscription *sub = state->subscriptions;
    mqtt_persisted_subscription *prev_psub = NULL;
    while (sub) {
        mqtt_persisted_subscription *psub = calloc(1, sizeof(mqtt_persisted_subscription));
        if (!psub) return -1;

        psub->topic_filter = sub->topic_filter ? strdup(sub->topic_filter) : NULL;
        if (sub->topic_filter && !psub->topic_filter) {
            MQTT_LOG_ERROR("mqtt_persist_session: failed to allocate topic_filter");
            free(psub);
            return -1;
        }
        psub->qos = sub->qos;
        psub->no_local = sub->no_local;
        psub->retain_as_published = sub->retain_as_published;
        psub->retain_handling = sub->retain_handling;

        if (prev_psub) {
            prev_psub->next = psub;
        } else {
            session.subscriptions = psub;
        }
        prev_psub = psub;
        sub = sub->next;
    }

    // Convert pending acks
    mqtt_pending_ack *ack = state->pending_acks;
    mqtt_persisted_message *prev_pmsg = NULL;
    while (ack) {
        mqtt_persisted_message *pmsg = mqtt_persisted_message_create(
            ack->packet_id, ack->packet_type, ack->qos, ack->topic,
            ack->payload, ack->payload_len, 0, 0
        );
        if (!pmsg) return -1;

        pmsg->retry_count = ack->retry_count;
        pmsg->timestamp = (uint32_t)ack->timestamp.tv_sec;

        if (prev_pmsg) {
            prev_pmsg->next = pmsg;
        } else {
            session.pending_publish = pmsg;
        }
        prev_pmsg = pmsg;
        ack = ack->next;
    }

    int result = state->persistence->save_session(state->persistence, &session);

    // Cleanup
    mqtt_persisted_subscription *psub = session.subscriptions;
    while (psub) {
        mqtt_persisted_subscription *next = psub->next;
        free(psub->topic_filter);
        free(psub);
        psub = next;
    }

    mqtt_persisted_message *pmsg = session.pending_publish;
    while (pmsg) {
        mqtt_persisted_message *next = pmsg->next;
        mqtt_persisted_message_free(pmsg);
        pmsg = next;
    }

    if (result < 0) {
        MQTT_LOG_ERROR( "mqtt_persist_session: failed to save session");
        return -1;
    }

    MQTT_LOG_DEBUG( "mqtt_persist_session: session saved");
    return 0;
}

static int mqtt_restore_session(mqtt_client_state *state) {
    if (!state || !state->persistence || !state->persistence->load_session) {
        return 0;
    }

    mqtt_persisted_session *session = state->persistence->load_session(
        state->persistence, state->client_id
    );

    if (!session) {
        MQTT_LOG_DEBUG( "mqtt_restore_session: no session found");
        return 0;
    }

    MQTT_LOG_INFO( "mqtt_restore_session: restoring session for %s", state->client_id);

    state->next_packet_id = session->next_packet_id;
    state->session_expiry_interval = session->session_expiry_interval;

    // Restore subscriptions
    mqtt_persisted_subscription *psub = session->subscriptions;
    while (psub) {
        mqtt_subscription *sub = calloc(1, sizeof(mqtt_subscription));
        if (!sub) {
            mqtt_persisted_session_free(session);
            return -1;
        }

        sub->topic_filter = psub->topic_filter ? strdup(psub->topic_filter) : NULL;
        if (psub->topic_filter && !sub->topic_filter) {
            MQTT_LOG_ERROR("mqtt_restore_session: failed to allocate topic_filter");
            free(sub);
            mqtt_persisted_session_free(session);
            return -1;
        }
        sub->qos = psub->qos;
        sub->no_local = psub->no_local;
        sub->retain_as_published = psub->retain_as_published;
        sub->retain_handling = psub->retain_handling;
        sub->next = state->subscriptions;
        state->subscriptions = sub;

        MQTT_LOG_DEBUG( "mqtt_restore_session: restored subscription to %s", sub->topic_filter);
        psub = psub->next;
    }

    // Restore pending messages
    mqtt_persisted_message *pmsg = session->pending_publish;
    while (pmsg) {
        mqtt_pending_ack *ack = calloc(1, sizeof(mqtt_pending_ack));
        if (!ack) {
            mqtt_persisted_session_free(session);
            return -1;
        }

        ack->packet_id = pmsg->packet_id;
        ack->packet_type = pmsg->packet_type;
        ack->qos = pmsg->qos;
        ack->topic = pmsg->topic ? strdup(pmsg->topic) : NULL;
        if (pmsg->topic && !ack->topic) {
            MQTT_LOG_ERROR("mqtt_restore_session: failed to allocate ack topic");
            free(ack);
            mqtt_persisted_session_free(session);
            return -1;
        }

        if (pmsg->payload && pmsg->payload_len > 0) {
            ack->payload = malloc(pmsg->payload_len);
            if (!ack->payload) {
                MQTT_LOG_ERROR("mqtt_restore_session: failed to allocate ack payload");
                free(ack->topic);
                free(ack);
                mqtt_persisted_session_free(session);
                return -1;
            }
            memcpy(ack->payload, pmsg->payload, pmsg->payload_len);
            ack->payload_len = pmsg->payload_len;
        }

        ack->retry_count = pmsg->retry_count;
        ack->timestamp.tv_sec = pmsg->timestamp;
        ack->timestamp.tv_usec = 0;
        ack->next = state->pending_acks;
        state->pending_acks = ack;

        MQTT_LOG_DEBUG( "mqtt_restore_session: restored pending message %u", ack->packet_id);
        pmsg = pmsg->next;
    }

    mqtt_persisted_session_free(session);
    MQTT_LOG_INFO( "mqtt_restore_session: session restored successfully");
    return 0;
}

static int mqtt_delete_persisted_session(mqtt_client_state *state) {
    if (!state || !state->persistence || !state->persistence->delete_session) {
        return 0;
    }
    return state->persistence->delete_session(state->persistence, state->client_id);
}

static int mqtt_persist_message(mqtt_client_state *state, uint16_t packet_id,
                                mqtt_packet_type packet_type, mqtt_qos qos,
                                const char *topic, const uint8_t *payload,
                                size_t payload_len, uint8_t retain, uint8_t dup) {
    if (!state || !state->persistence || !state->persistence->add_pending_message) {
        return 0;
    }

    mqtt_persisted_message *pmsg = mqtt_persisted_message_create(
        packet_id, packet_type, qos, topic, payload, payload_len, retain, dup
    );
    if (!pmsg) {
        MQTT_LOG_ERROR( "mqtt_persist_message: failed to create message");
        return -1;
    }

    int result = state->persistence->add_pending_message(
        state->persistence, state->client_id, pmsg
    );

    mqtt_persisted_message_free(pmsg);

    if (result < 0) {
        MQTT_LOG_ERROR( "mqtt_persist_message: failed to persist");
        return -1;
    }

    MQTT_LOG_DEBUG( "mqtt_persist_message: persisted message %u", packet_id);
    return 0;
}

static int mqtt_unpersist_message(mqtt_client_state *state, uint16_t packet_id) {
    if (!state || !state->persistence || !state->persistence->remove_pending_message) {
        return 0;
    }

    int result = state->persistence->remove_pending_message(
        state->persistence, state->client_id, packet_id
    );

    if (result >= 0) {
        MQTT_LOG_DEBUG( "mqtt_unpersist_message: removed message %u", packet_id);
    }
    return result;
}

// =============================================================================
// Utility Functions - Variable Byte Integer (MQTT 5.0 Spec)
// =============================================================================

int mqtt_encode_variable_byte_integer(uint32_t value, uint8_t *output) {
    // MQTT 5.0 spec [MQTT-1.5.5]: Maximum value is 268,435,455 (0x0FFFFFFF)
    // This is 4 bytes with continuation bit pattern: 0xFF 0xFF 0xFF 0x7F
    if (value > 268435455) {
        MQTT_LOG_ERROR( "mqtt_encode_variable_byte_integer: value %u exceeds maximum 268435455", value);
        return -1;
    }

    int bytes = 0;
    do {
        uint8_t encoded_byte = value % 128;
        value = value / 128;
        if (value > 0) {
            encoded_byte = encoded_byte | 128;
        }
        output[bytes++] = encoded_byte;
    } while (value > 0 && bytes < 4);

    return bytes;
}

int mqtt_decode_variable_byte_integer(const uint8_t *input, uint32_t *value, int *bytes_consumed) {
    // Add NULL pointer checks
    if (!input || !value || !bytes_consumed) {
        MQTT_LOG_ERROR("mqtt_decode_variable_byte_integer: NULL parameter");
        return -1;
    }

    int multiplier = 1;
    *value = 0;
    *bytes_consumed = 0;
    uint8_t encoded_byte;

    do {
        if (*bytes_consumed >= 4) {
            MQTT_LOG_ERROR( "mqtt_decode_variable_byte_integer: malformed variable byte integer");
            return -1;
        }
        encoded_byte = input[*bytes_consumed];
        *value += (encoded_byte & 127) * multiplier;
        multiplier *= 128;
        (*bytes_consumed)++;
    } while ((encoded_byte & 128) != 0);

    return 0;
}

// =============================================================================
// Utility Functions - UTF-8 String Encoding/Decoding
// =============================================================================

int mqtt_encode_utf8_string(const char *str, uint8_t *output) {
    if (!str || !output) return 0;

    uint16_t len = strlen(str);

    // MQTT 5.0 spec: UTF-8 string MUST NOT contain null character (U+0000)
    // or surrogate pairs (U+D800 to U+DFFF)
    for (uint16_t i = 0; i < len; i++) {
        // Check for null character [MQTT-1.5.4-2]
        if (str[i] == '\0') {
            MQTT_LOG_ERROR( "mqtt_encode_utf8_string: string contains null character");
            return 0;
        }

        // Check for UTF-8 surrogate pairs [MQTT-1.5.4-1]
        // Surrogates are encoded as: 0xED 0xA0-0xBF 0x80-0xBF (for U+D800-U+DFFF)
        if (i + 2 < len && (unsigned char)str[i] == 0xED &&
            ((unsigned char)str[i+1] >= 0xA0 && (unsigned char)str[i+1] <= 0xBF)) {
            MQTT_LOG_ERROR( "mqtt_encode_utf8_string: string contains UTF-8 surrogate pair");
            return 0;
        }
    }

    output[0] = (len >> 8) & 0xFF;
    output[1] = len & 0xFF;
    memcpy(output + 2, str, len);

    return len + 2;
}

int mqtt_decode_utf8_string(const uint8_t *input, char **str, int *bytes_consumed) {
    if (!input || !str || !bytes_consumed) return -1;

    uint16_t len = (input[0] << 8) | input[1];

    // Validate UTF-8 string per MQTT 5.0 spec
    const uint8_t *data = input + 2;
    for (uint16_t i = 0; i < len; i++) {
        // Check for null character [MQTT-1.5.4-2]
        if (data[i] == '\0') {
            MQTT_LOG_ERROR( "mqtt_decode_utf8_string: string contains null character");
            return -1;
        }

        // Check for UTF-8 surrogate pairs [MQTT-1.5.4-1]
        if (i + 2 < len && data[i] == 0xED &&
            (data[i+1] >= 0xA0 && data[i+1] <= 0xBF)) {
            MQTT_LOG_ERROR( "mqtt_decode_utf8_string: string contains UTF-8 surrogate pair");
            return -1;
        }
    }

    *str = malloc(len + 1);
    if (!*str) {
        MQTT_LOG_ERROR( "mqtt_decode_utf8_string: malloc failed");
        return -1;
    }

    memcpy(*str, data, len);
    (*str)[len] = '\0';
    *bytes_consumed = len + 2;

    return 0;
}

// =============================================================================
// Utility Functions - Binary Data Encoding/Decoding
// =============================================================================

int mqtt_encode_binary_data(const uint8_t *data, uint16_t len, uint8_t *output) {
    if (!data || !output) return 0;

    output[0] = (len >> 8) & 0xFF;
    output[1] = len & 0xFF;
    memcpy(output + 2, data, len);

    return len + 2;
}

int mqtt_decode_binary_data(const uint8_t *input, uint8_t **data, uint16_t *len, int *bytes_consumed) {
    if (!input || !data || !len || !bytes_consumed) return -1;

    *len = (input[0] << 8) | input[1];
    *data = malloc(*len);
    if (!*data) {
        MQTT_LOG_ERROR( "mqtt_decode_binary_data: malloc failed");
        return -1;
    }

    memcpy(*data, input + 2, *len);
    *bytes_consumed = *len + 2;

    return 0;
}

// =============================================================================
// Property Management
// =============================================================================

mqtt_property* mqtt_property_create(mqtt_property_id id) {
    mqtt_property *prop = calloc(1, sizeof(mqtt_property));
    if (!prop) return NULL;
    prop->id = id;
    return prop;
}

void mqtt_property_free(mqtt_property *prop) {
    if (!prop) return;

    // Free string or binary data based on property type
    switch (prop->id) {
        case MQTT_PROP_CONTENT_TYPE:
        case MQTT_PROP_RESPONSE_TOPIC:
        case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
        case MQTT_PROP_AUTHENTICATION_METHOD:
        case MQTT_PROP_RESPONSE_INFORMATION:
        case MQTT_PROP_SERVER_REFERENCE:
        case MQTT_PROP_REASON_STRING:
            free(prop->value.string);
            break;
        case MQTT_PROP_CORRELATION_DATA:
        case MQTT_PROP_AUTHENTICATION_DATA:
            free(prop->value.binary.data);
            break;
        case MQTT_PROP_USER_PROPERTY:
            free(prop->value.user_property.key);
            free(prop->value.user_property.value);
            break;
        default:
            break;
    }

    free(prop);
}

void mqtt_properties_free(mqtt_property *props) {
    while (props) {
        mqtt_property *next = props->next;
        mqtt_property_free(props);
        props = next;
    }
}

// Helper functions for creating common PUBLISH properties

mqtt_property* mqtt_property_create_payload_format_indicator(uint8_t is_utf8) {
    mqtt_property *prop = mqtt_property_create(MQTT_PROP_PAYLOAD_FORMAT_INDICATOR);
    if (prop) {
        prop->value.byte = is_utf8 ? 1 : 0;
    }
    return prop;
}

mqtt_property* mqtt_property_create_message_expiry(uint32_t seconds) {
    mqtt_property *prop = mqtt_property_create(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
    if (prop) {
        prop->value.u32 = seconds;
    }
    return prop;
}

mqtt_property* mqtt_property_create_content_type(const char *content_type) {
    if (!content_type) return NULL;

    mqtt_property *prop = mqtt_property_create(MQTT_PROP_CONTENT_TYPE);
    if (prop) {
        prop->value.string = strdup(content_type);
        if (!prop->value.string) {
            mqtt_property_free(prop);
            return NULL;
        }
    }
    return prop;
}

mqtt_property* mqtt_property_create_response_topic(const char *topic) {
    if (!topic) return NULL;

    mqtt_property *prop = mqtt_property_create(MQTT_PROP_RESPONSE_TOPIC);
    if (prop) {
        prop->value.string = strdup(topic);
        if (!prop->value.string) {
            mqtt_property_free(prop);
            return NULL;
        }
    }
    return prop;
}

mqtt_property* mqtt_property_create_correlation_data(const uint8_t *data, uint16_t len) {
    if (!data || len == 0) return NULL;

    mqtt_property *prop = mqtt_property_create(MQTT_PROP_CORRELATION_DATA);
    if (prop) {
        prop->value.binary.data = malloc(len);
        if (!prop->value.binary.data) {
            mqtt_property_free(prop);
            return NULL;
        }
        memcpy(prop->value.binary.data, data, len);
        prop->value.binary.len = len;
    }
    return prop;
}

mqtt_property* mqtt_property_create_user_property(const char *key, const char *value) {
    if (!key || !value) return NULL;

    mqtt_property *prop = mqtt_property_create(MQTT_PROP_USER_PROPERTY);
    if (prop) {
        prop->value.user_property.key = strdup(key);
        prop->value.user_property.value = strdup(value);

        if (!prop->value.user_property.key || !prop->value.user_property.value) {
            mqtt_property_free(prop);
            return NULL;
        }
    }
    return prop;
}

// Helper function to find a property by ID
mqtt_property* mqtt_property_find(mqtt_property *props, mqtt_property_id id) {
    mqtt_property *current = props;
    while (current) {
        if (current->id == id) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Helper function to get a string property value
const char* mqtt_property_get_string(mqtt_property *props, mqtt_property_id id) {
    mqtt_property *prop = mqtt_property_find(props, id);
    if (!prop) return NULL;

    // Verify this is a string property type
    switch (id) {
        case MQTT_PROP_CONTENT_TYPE:
        case MQTT_PROP_RESPONSE_TOPIC:
        case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
        case MQTT_PROP_AUTHENTICATION_METHOD:
        case MQTT_PROP_RESPONSE_INFORMATION:
        case MQTT_PROP_SERVER_REFERENCE:
        case MQTT_PROP_REASON_STRING:
            return prop->value.string;
        default:
            return NULL;
    }
}

// Helper function to get a uint32 property value
uint32_t mqtt_property_get_u32(mqtt_property *props, mqtt_property_id id, uint32_t default_value) {
    mqtt_property *prop = mqtt_property_find(props, id);
    if (!prop) return default_value;

    // Verify this is a uint32 property type
    switch (id) {
        case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
        case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
        case MQTT_PROP_WILL_DELAY_INTERVAL:
        case MQTT_PROP_MAXIMUM_PACKET_SIZE:
            return prop->value.u32;
        default:
            return default_value;
    }
}

// Helper function to get a byte property value
uint8_t mqtt_property_get_byte(mqtt_property *props, mqtt_property_id id, uint8_t default_value) {
    mqtt_property *prop = mqtt_property_find(props, id);
    if (!prop) return default_value;

    // Verify this is a byte property type
    switch (id) {
        case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
        case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
        case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
        case MQTT_PROP_MAXIMUM_QOS:
        case MQTT_PROP_RETAIN_AVAILABLE:
        case MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE:
        case MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
        case MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE:
            return prop->value.byte;
        default:
            return default_value;
    }
}

int mqtt_encode_properties(mqtt_property *props, uint8_t *output) {
    if (!output) return 0;

    // First pass: calculate total property length
    uint32_t total_prop_len = 0;
    mqtt_property *current = props;

    while (current) {
        // Property ID is always 1 byte (variable byte integer, but values are < 128)
        // NOTE: For USER_PROPERTY, we only add the ID if both key and value are valid

        switch (current->id) {
            // Byte properties (1 byte value)
            case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
            case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
            case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
            case MQTT_PROP_MAXIMUM_QOS:
            case MQTT_PROP_RETAIN_AVAILABLE:
            case MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE:
            case MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
            case MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE:
                total_prop_len += 1;  // Property ID
                total_prop_len += 1;  // Value
                break;

            // Two Byte Integer (u16)
            case MQTT_PROP_SERVER_KEEP_ALIVE:
            case MQTT_PROP_RECEIVE_MAXIMUM:
            case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
            case MQTT_PROP_TOPIC_ALIAS:
                total_prop_len += 1;  // Property ID
                total_prop_len += 2;  // Value
                break;

            // Four Byte Integer (u32)
            case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
            case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
            case MQTT_PROP_WILL_DELAY_INTERVAL:
            case MQTT_PROP_MAXIMUM_PACKET_SIZE:
                total_prop_len += 1;  // Property ID
                total_prop_len += 4;  // Value
                break;

            // Variable Byte Integer
            case MQTT_PROP_SUBSCRIPTION_IDENTIFIER: {
                uint8_t vbi_buf[4];
                total_prop_len += 1;  // Property ID
                total_prop_len += mqtt_encode_variable_byte_integer(current->value.u32, vbi_buf);
                break;
            }

            // UTF-8 Encoded String
            case MQTT_PROP_CONTENT_TYPE:
            case MQTT_PROP_RESPONSE_TOPIC:
            case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
            case MQTT_PROP_AUTHENTICATION_METHOD:
            case MQTT_PROP_RESPONSE_INFORMATION:
            case MQTT_PROP_SERVER_REFERENCE:
            case MQTT_PROP_REASON_STRING:
                if (current->value.string) {
                    total_prop_len += 1;  // Property ID
                    total_prop_len += 2 + strlen(current->value.string);
                }
                break;

            // Binary Data
            case MQTT_PROP_CORRELATION_DATA:
            case MQTT_PROP_AUTHENTICATION_DATA:
                total_prop_len += 1;  // Property ID
                total_prop_len += 2 + current->value.binary.len;
                break;

            // UTF-8 String Pair (User Property)
            case MQTT_PROP_USER_PROPERTY:
                if (current->value.user_property.key && current->value.user_property.value) {
                    total_prop_len += 1;  // Property ID
                    total_prop_len += 2 + strlen(current->value.user_property.key);
                    total_prop_len += 2 + strlen(current->value.user_property.value);
                }
                break;

            default:
                MQTT_LOG_WARN( "mqtt_encode_properties: unknown property ID 0x%02X", current->id);
                break;
        }

        current = current->next;
    }

    // Encode property length as variable byte integer
    uint8_t vbi_buf[4];
    int vbi_len = mqtt_encode_variable_byte_integer(total_prop_len, vbi_buf);
    memcpy(output, vbi_buf, vbi_len);

    size_t pos = vbi_len;

    // Second pass: encode each property
    current = props;
    while (current) {
        // Skip user properties with NULL key or value
        if (current->id == MQTT_PROP_USER_PROPERTY) {
            if (!current->value.user_property.key || !current->value.user_property.value) {
                current = current->next;
                continue;
            }
        }

        // Encode property ID (always 1 byte for current property IDs)
        output[pos++] = (uint8_t)current->id;

        switch (current->id) {
            // Byte properties
            case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
            case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
            case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
            case MQTT_PROP_MAXIMUM_QOS:
            case MQTT_PROP_RETAIN_AVAILABLE:
            case MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE:
            case MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
            case MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE:
                output[pos++] = current->value.byte;
                break;

            // Two Byte Integer
            case MQTT_PROP_SERVER_KEEP_ALIVE:
            case MQTT_PROP_RECEIVE_MAXIMUM:
            case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
            case MQTT_PROP_TOPIC_ALIAS:
                output[pos++] = (current->value.u16 >> 8) & 0xFF;
                output[pos++] = current->value.u16 & 0xFF;
                break;

            // Four Byte Integer
            case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
            case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
            case MQTT_PROP_WILL_DELAY_INTERVAL:
            case MQTT_PROP_MAXIMUM_PACKET_SIZE:
                output[pos++] = (current->value.u32 >> 24) & 0xFF;
                output[pos++] = (current->value.u32 >> 16) & 0xFF;
                output[pos++] = (current->value.u32 >> 8) & 0xFF;
                output[pos++] = current->value.u32 & 0xFF;
                break;

            // Variable Byte Integer
            case MQTT_PROP_SUBSCRIPTION_IDENTIFIER: {
                uint8_t vbi_buf_local[4];
                int vbi_len_local = mqtt_encode_variable_byte_integer(current->value.u32, vbi_buf_local);
                memcpy(output + pos, vbi_buf_local, vbi_len_local);
                pos += vbi_len_local;
                break;
            }

            // UTF-8 Encoded String
            case MQTT_PROP_CONTENT_TYPE:
            case MQTT_PROP_RESPONSE_TOPIC:
            case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
            case MQTT_PROP_AUTHENTICATION_METHOD:
            case MQTT_PROP_RESPONSE_INFORMATION:
            case MQTT_PROP_SERVER_REFERENCE:
            case MQTT_PROP_REASON_STRING:
                if (current->value.string) {
                    int encoded_len = mqtt_encode_utf8_string(current->value.string, output + pos);
                    pos += encoded_len;
                }
                break;

            // Binary Data
            case MQTT_PROP_CORRELATION_DATA:
            case MQTT_PROP_AUTHENTICATION_DATA:
                if (current->value.binary.data) {
                    int encoded_len = mqtt_encode_binary_data(
                        current->value.binary.data,
                        current->value.binary.len,
                        output + pos
                    );
                    pos += encoded_len;
                }
                break;

            case MQTT_PROP_USER_PROPERTY:
                if (current->value.user_property.key && current->value.user_property.value) {
                    int key_len = mqtt_encode_utf8_string(current->value.user_property.key, output + pos);
                    pos += key_len;
                    int val_len = mqtt_encode_utf8_string(current->value.user_property.value, output + pos);
                    pos += val_len;
                }
                break;

            default:
                break;
        }

        current = current->next;
    }

    return pos;
}

// Helper function to determine property type for any property ID
// This allows us to skip unknown properties according to MQTT 5.0 spec section 2.2.2.2:
// "A Client or Server MUST be able to skip over Properties that it does not recognize"
typedef enum {
    PROP_TYPE_BYTE,
    PROP_TYPE_U16,
    PROP_TYPE_U32,
    PROP_TYPE_VBI,
    PROP_TYPE_STRING,
    PROP_TYPE_BINARY,
    PROP_TYPE_STRING_PAIR,
    PROP_TYPE_UNKNOWN
} mqtt_property_type;

static mqtt_property_type mqtt_get_property_type(mqtt_property_id id) {
    switch (id) {
        // Byte properties
        case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
        case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
        case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
        case MQTT_PROP_MAXIMUM_QOS:
        case MQTT_PROP_RETAIN_AVAILABLE:
        case MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE:
        case MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
        case MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE:
            return PROP_TYPE_BYTE;

        // Two-byte integer properties
        case MQTT_PROP_SERVER_KEEP_ALIVE:
        case MQTT_PROP_RECEIVE_MAXIMUM:
        case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
        case MQTT_PROP_TOPIC_ALIAS:
            return PROP_TYPE_U16;

        // Four-byte integer properties
        case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
        case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
        case MQTT_PROP_WILL_DELAY_INTERVAL:
        case MQTT_PROP_MAXIMUM_PACKET_SIZE:
            return PROP_TYPE_U32;

        // Variable byte integer
        case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
            return PROP_TYPE_VBI;

        // UTF-8 string properties
        case MQTT_PROP_CONTENT_TYPE:
        case MQTT_PROP_RESPONSE_TOPIC:
        case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
        case MQTT_PROP_AUTHENTICATION_METHOD:
        case MQTT_PROP_RESPONSE_INFORMATION:
        case MQTT_PROP_SERVER_REFERENCE:
        case MQTT_PROP_REASON_STRING:
            return PROP_TYPE_STRING;

        // Binary data properties
        case MQTT_PROP_CORRELATION_DATA:
        case MQTT_PROP_AUTHENTICATION_DATA:
            return PROP_TYPE_BINARY;

        // String pair (User Property)
        case MQTT_PROP_USER_PROPERTY:
            return PROP_TYPE_STRING_PAIR;

        default:
            return PROP_TYPE_UNKNOWN;
    }
}

int mqtt_decode_properties(const uint8_t *input, mqtt_property **props, int *bytes_consumed) {
    if (!input || !props || !bytes_consumed) return -1;

    // Decode property length
    uint32_t prop_len;
    int vbi_len;

    if (mqtt_decode_variable_byte_integer(input, &prop_len, &vbi_len) < 0) {
        MQTT_LOG_ERROR( "mqtt_decode_properties: failed to decode property length");
        return -1;
    }

    *props = NULL;
    *bytes_consumed = vbi_len + prop_len;

    // No properties
    if (prop_len == 0) {
        return 0;
    }

    size_t pos = vbi_len;
    size_t end = vbi_len + prop_len;
    mqtt_property **current_ptr = props;

    while (pos < end) {
        // Read property ID
        if (pos >= end) {
            MQTT_LOG_ERROR( "mqtt_decode_properties: truncated property ID");
            mqtt_properties_free(*props);
            *props = NULL;
            return -1;
        }

        mqtt_property_id prop_id = (mqtt_property_id)input[pos++];

        // Create property
        mqtt_property *prop = mqtt_property_create(prop_id);
        if (!prop) {
            MQTT_LOG_ERROR( "mqtt_decode_properties: failed to allocate property");
            mqtt_properties_free(*props);
            *props = NULL;
            return -1;
        }

        // Add to linked list
        *current_ptr = prop;
        current_ptr = &prop->next;

        // Decode property value based on type
        switch (prop_id) {
            // Byte properties
            case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
            case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
            case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
            case MQTT_PROP_MAXIMUM_QOS:
            case MQTT_PROP_RETAIN_AVAILABLE:
            case MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE:
            case MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
            case MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE:
                if (pos >= end) {
                    MQTT_LOG_ERROR( "mqtt_decode_properties: truncated byte property");
                    mqtt_properties_free(*props);
                    *props = NULL;
                    return -1;
                }
                prop->value.byte = input[pos++];
                break;

            // Two Byte Integer
            case MQTT_PROP_SERVER_KEEP_ALIVE:
            case MQTT_PROP_RECEIVE_MAXIMUM:
            case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
            case MQTT_PROP_TOPIC_ALIAS:
                if (pos + 2 > end) {
                    MQTT_LOG_ERROR( "mqtt_decode_properties: truncated u16 property");
                    mqtt_properties_free(*props);
                    *props = NULL;
                    return -1;
                }
                prop->value.u16 = (input[pos] << 8) | input[pos + 1];
                pos += 2;
                break;

            // Four Byte Integer
            case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
            case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
            case MQTT_PROP_WILL_DELAY_INTERVAL:
            case MQTT_PROP_MAXIMUM_PACKET_SIZE:
                if (pos + 4 > end) {
                    MQTT_LOG_ERROR( "mqtt_decode_properties: truncated u32 property");
                    mqtt_properties_free(*props);
                    *props = NULL;
                    return -1;
                }
                prop->value.u32 = ((uint32_t)input[pos] << 24) |
                                  ((uint32_t)input[pos + 1] << 16) |
                                  ((uint32_t)input[pos + 2] << 8) |
                                  ((uint32_t)input[pos + 3]);
                pos += 4;
                break;

            // Variable Byte Integer
            case MQTT_PROP_SUBSCRIPTION_IDENTIFIER: {
                uint32_t vbi_value;
                int vbi_bytes;
                if (mqtt_decode_variable_byte_integer(input + pos, &vbi_value, &vbi_bytes) < 0) {
                    MQTT_LOG_ERROR( "mqtt_decode_properties: failed to decode VBI property");
                    mqtt_properties_free(*props);
                    *props = NULL;
                    return -1;
                }
                prop->value.u32 = vbi_value;
                pos += vbi_bytes;
                break;
            }

            // UTF-8 Encoded String
            case MQTT_PROP_CONTENT_TYPE:
            case MQTT_PROP_RESPONSE_TOPIC:
            case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
            case MQTT_PROP_AUTHENTICATION_METHOD:
            case MQTT_PROP_RESPONSE_INFORMATION:
            case MQTT_PROP_SERVER_REFERENCE:
            case MQTT_PROP_REASON_STRING: {
                char *str = NULL;
                int str_bytes;
                if (mqtt_decode_utf8_string(input + pos, &str, &str_bytes) < 0) {
                    MQTT_LOG_ERROR( "mqtt_decode_properties: failed to decode UTF-8 string property");
                    mqtt_properties_free(*props);
                    *props = NULL;
                    return -1;
                }
                prop->value.string = str;
                pos += str_bytes;
                break;
            }

            // Binary Data
            case MQTT_PROP_CORRELATION_DATA:
            case MQTT_PROP_AUTHENTICATION_DATA: {
                uint8_t *data = NULL;
                uint16_t data_len;
                int data_bytes;
                if (mqtt_decode_binary_data(input + pos, &data, &data_len, &data_bytes) < 0) {
                    MQTT_LOG_ERROR( "mqtt_decode_properties: failed to decode binary data property");
                    mqtt_properties_free(*props);
                    *props = NULL;
                    return -1;
                }
                prop->value.binary.data = data;
                prop->value.binary.len = data_len;
                pos += data_bytes;
                break;
            }

            // UTF-8 String Pair (User Property)
            case MQTT_PROP_USER_PROPERTY: {
                // User properties have two UTF-8 strings: key and value
                char *key = NULL;
                int key_bytes;
                if (mqtt_decode_utf8_string(input + pos, &key, &key_bytes) < 0) {
                    MQTT_LOG_ERROR( "mqtt_decode_properties: failed to decode user property key");
                    mqtt_properties_free(*props);
                    *props = NULL;
                    return -1;
                }
                pos += key_bytes;

                char *value = NULL;
                int value_bytes;
                if (mqtt_decode_utf8_string(input + pos, &value, &value_bytes) < 0) {
                    MQTT_LOG_ERROR( "mqtt_decode_properties: failed to decode user property value");
                    free(key);
                    mqtt_properties_free(*props);
                    *props = NULL;
                    return -1;
                }
                pos += value_bytes;

                // Store both key and value in the property structure
                prop->value.user_property.key = key;
                prop->value.user_property.value = value;
                break;
            }

            default: {
                // Unknown property - determine its type and skip it
                // MQTT 5.0 spec section 2.2.2.2: "A Client or Server MUST be able to skip over Properties that it does not recognize"
                mqtt_property_type type = mqtt_get_property_type(prop_id);

                MQTT_LOG_WARN( "mqtt_decode_properties: unknown property ID 0x%02X (type %d), skipping", prop_id, type);

                // Skip the property value based on its type
                switch (type) {
                    case PROP_TYPE_BYTE:
                        if (pos >= end) goto truncated_error;
                        pos += 1;
                        break;

                    case PROP_TYPE_U16:
                        if (pos + 2 > end) goto truncated_error;
                        pos += 2;
                        break;

                    case PROP_TYPE_U32:
                        if (pos + 4 > end) goto truncated_error;
                        pos += 4;
                        break;

                    case PROP_TYPE_VBI: {
                        uint32_t vbi_value;
                        int vbi_bytes;
                        if (mqtt_decode_variable_byte_integer(input + pos, &vbi_value, &vbi_bytes) < 0) {
                            goto truncated_error;
                        }
                        pos += vbi_bytes;
                        break;
                    }

                    case PROP_TYPE_STRING: {
                        // Skip UTF-8 string (2-byte length prefix + string data)
                        if (pos + 2 > end) goto truncated_error;
                        uint16_t str_len = (input[pos] << 8) | input[pos + 1];
                        pos += 2;
                        if (pos + str_len > end) goto truncated_error;
                        pos += str_len;
                        break;
                    }

                    case PROP_TYPE_BINARY: {
                        // Skip binary data (2-byte length prefix + binary data)
                        if (pos + 2 > end) goto truncated_error;
                        uint16_t bin_len = (input[pos] << 8) | input[pos + 1];
                        pos += 2;
                        if (pos + bin_len > end) goto truncated_error;
                        pos += bin_len;
                        break;
                    }

                    case PROP_TYPE_STRING_PAIR: {
                        // Skip two UTF-8 strings
                        for (int i = 0; i < 2; i++) {
                            if (pos + 2 > end) goto truncated_error;
                            uint16_t str_len = (input[pos] << 8) | input[pos + 1];
                            pos += 2;
                            if (pos + str_len > end) goto truncated_error;
                            pos += str_len;
                        }
                        break;
                    }

                    case PROP_TYPE_UNKNOWN:
                    default:
                        // Truly unknown property type - cannot skip safely
                        MQTT_LOG_ERROR( "mqtt_decode_properties: cannot skip property 0x%02X - unknown type", prop_id);
                        mqtt_properties_free(*props);
                        *props = NULL;
                        return -1;
                }

                // Remove the unknown property from the list since we didn't populate it
                // Find and remove prop from the list
                if (*props == prop) {
                    // It's the head
                    *props = prop->next;
                    current_ptr = props;
                } else {
                    // Find the previous property
                    mqtt_property *prev = *props;
                    while (prev && prev->next != prop) {
                        prev = prev->next;
                    }
                    if (prev) {
                        prev->next = prop->next;
                    }
                    current_ptr = &prev->next;
                }
                mqtt_property_free(prop);
                break;

            truncated_error:
                MQTT_LOG_ERROR( "mqtt_decode_properties: truncated unknown property 0x%02X", prop_id);
                mqtt_properties_free(*props);
                *props = NULL;
                return -1;
            }
        }
    }

    return 0;
}

// =============================================================================
// Packet ID Management
// =============================================================================

uint16_t mqtt_get_next_packet_id(mqtt_client_state *state) {
    if (!state) return 0;

    state->next_packet_id++;
    if (state->next_packet_id == 0) {
        state->next_packet_id = 1; // Packet ID 0 is reserved
    }

    return state->next_packet_id;
}

// =============================================================================
// State Management
// =============================================================================

mqtt_client_state* mqtt_get_client_state(cwebsocket_client *client) {
    return global_mqtt_state;
}

// =============================================================================
// Packet Encoding/Decoding
// =============================================================================

mqtt_packet* mqtt_packet_decode(const uint8_t *data, size_t len) {
    if (!data || len < 2) return NULL;

    mqtt_packet *packet = calloc(1, sizeof(mqtt_packet));
    if (!packet) {
        MQTT_LOG_ERROR( "mqtt_packet_decode: failed to allocate packet");
        return NULL;
    }

    // Parse fixed header
    packet->header.type = (data[0] >> 4) & 0x0F;
    packet->header.flags = data[0] & 0x0F;

    // MQTT 5.0 spec: Packet type 0 is reserved and forbidden
    if (packet->header.type == MQTT_RESERVED_0) {
        MQTT_LOG_ERROR( "mqtt_packet_decode: received reserved packet type 0");
        free(packet);
        return NULL;
    }

    // Parse remaining length
    int vbi_len;
    if (mqtt_decode_variable_byte_integer(data + 1, &packet->header.remaining_length, &vbi_len) < 0) {
        free(packet);
        return NULL;
    }

    size_t header_len = 1 + vbi_len;

    if (len < header_len + packet->header.remaining_length) {
        MQTT_LOG_ERROR( "mqtt_packet_decode: incomplete packet");
        free(packet);
        return NULL;
    }

    // Copy variable header and payload
    if (packet->header.remaining_length > 0) {
        uint8_t *combined = malloc(packet->header.remaining_length);
        if (!combined) {
            free(packet);
            return NULL;
        }
        memcpy(combined, data + header_len, packet->header.remaining_length);

        // For now, treat everything as payload
        // Proper implementation would parse variable header based on packet type
        packet->payload = combined;
        packet->payload_len = packet->header.remaining_length;
    }

    return packet;
}

uint8_t* mqtt_packet_encode(mqtt_packet *packet, size_t *out_len) {
    if (!packet || !out_len) return NULL;

    // Calculate total size
    uint8_t remaining_len_buf[4];
    int remaining_len_bytes = mqtt_encode_variable_byte_integer(
        packet->header.remaining_length, remaining_len_buf);

    *out_len = 1 + remaining_len_bytes + packet->header.remaining_length;

    uint8_t *buffer = malloc(*out_len);
    if (!buffer) {
        MQTT_LOG_ERROR( "mqtt_packet_encode: malloc failed");
        return NULL;
    }

    size_t pos = 0;

    // Fixed header byte 1
    buffer[pos++] = ((packet->header.type & 0x0F) << 4) | (packet->header.flags & 0x0F);

    // Remaining length
    memcpy(buffer + pos, remaining_len_buf, remaining_len_bytes);
    pos += remaining_len_bytes;

    // Variable header
    if (packet->variable_header && packet->variable_header_len > 0) {
        memcpy(buffer + pos, packet->variable_header, packet->variable_header_len);
        pos += packet->variable_header_len;
    }

    // Payload
    if (packet->payload && packet->payload_len > 0) {
        memcpy(buffer + pos, packet->payload, packet->payload_len);
        pos += packet->payload_len;
    }

    return buffer;
}

void mqtt_packet_free(mqtt_packet *packet) {
    if (!packet) return;
    free(packet->variable_header);
    free(packet->payload);
    free(packet);
}

// =============================================================================
// Connection Management
// =============================================================================

void mqtt_set_authentication(
    cwebsocket_client *client,
    const char *authentication_method,
    mqtt_auth_callback auth_callback,
    void *auth_context
) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state) {
        MQTT_LOG_ERROR( "mqtt_set_authentication: no client state");
        return;
    }

    // Free existing authentication method if any
    free(state->authentication_method);
    state->authentication_method = NULL;

    // Set new authentication parameters
    if (authentication_method) {
        state->authentication_method = strdup(authentication_method);
        if (!state->authentication_method) {
            MQTT_LOG_ERROR( "mqtt_set_authentication: failed to allocate authentication method");
            return;
        }
    }

    state->auth_callback = auth_callback;
    state->auth_context = auth_context;
    state->auth_in_progress = 0;

    MQTT_LOG_DEBUG( "mqtt_set_authentication: configured authentication method '%s' with %scallback",
           authentication_method ? authentication_method : "(none)",
           auth_callback ? "" : "no ");
}

void mqtt_set_will_message(
    cwebsocket_client *client,
    const char *will_topic,
    const uint8_t *will_payload,
    size_t will_payload_len,
    mqtt_qos will_qos,
    uint8_t will_retain,
    uint32_t will_delay_interval
) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state) {
        MQTT_LOG_ERROR( "mqtt_set_will_message: no client state");
        return;
    }

    // Free existing will message if any
    free(state->will.topic);
    free(state->will.payload);
    mqtt_properties_free(state->will.properties);
    memset(&state->will, 0, sizeof(state->will));

    // Set new will message
    if (will_topic) {
        state->will.topic = strdup(will_topic);
        if (!state->will.topic) {
            MQTT_LOG_ERROR( "mqtt_set_will_message: failed to allocate will topic");
            return;
        }
    }

    if (will_payload && will_payload_len > 0) {
        state->will.payload = malloc(will_payload_len);
        if (!state->will.payload) {
            MQTT_LOG_ERROR( "mqtt_set_will_message: failed to allocate will payload");
            free(state->will.topic);
            state->will.topic = NULL;
            return;
        }
        memcpy(state->will.payload, will_payload, will_payload_len);
        state->will.payload_len = will_payload_len;
    }

    state->will.qos = will_qos;
    state->will.retain = will_retain;
    state->will.delay_interval = will_delay_interval;

    // Create will delay interval property if specified
    if (will_delay_interval > 0) {
        mqtt_property *prop = mqtt_property_create(MQTT_PROP_WILL_DELAY_INTERVAL);
        if (prop) {
            prop->value.u32 = will_delay_interval;
            state->will.properties = prop;
        }
    }

    MQTT_LOG_DEBUG( "mqtt_set_will_message: configured will message for topic '%s' (QoS %d, retain %d, delay %u)",
           will_topic ? will_topic : "(null)", will_qos, will_retain, will_delay_interval);
}

// =============================================================================
// Session Restoration Functions
// =============================================================================

// Resubscribe to all persisted subscriptions
static int mqtt_resubscribe_all(cwebsocket_client *client, mqtt_client_state *state) {
    if (!client || !state) return 0;

    mqtt_subscription *sub = state->subscriptions;
    int count = 0;

    while (sub) {
        // Resubscribe with original options
        if (sub->no_local || sub->retain_as_published || sub->retain_handling) {
            // Use extended subscribe if advanced options are set
            mqtt_send_subscribe_ex(client, sub->topic_filter, sub->qos,
                                 sub->no_local, sub->retain_as_published,
                                 sub->retain_handling, 0);
        } else {
            // Use simple subscribe for basic subscriptions
            mqtt_send_subscribe(client, sub->topic_filter, sub->qos, 0, 0, 0);
        }
        count++;
        sub = sub->next;
    }

    MQTT_LOG_INFO("mqtt_resubscribe_all: resubscribed to %d topics", count);
    return count;
}

// Retransmit pending QoS 1/2 messages
static int mqtt_retransmit_pending_messages(cwebsocket_client *client, mqtt_client_state *state) {
    if (!client || !state) return 0;

    mqtt_pending_ack *pending = state->pending_acks;
    int count = 0;

    while (pending) {
        if (pending->packet_type == MQTT_PUBLISH) {
            // Retransmit with DUP=1, retain=0 per spec
            mqtt_send_publish(client, pending->topic, pending->payload,
                            pending->payload_len, pending->qos, 0, 1);
            count++;
        }
        pending = pending->next;
    }

    MQTT_LOG_INFO("mqtt_retransmit_pending_messages: retransmitted %d messages", count);
    return count;
}

// =============================================================================
// Message Callback Management
// =============================================================================

/**
 * Set the message callback for received PUBLISH messages
 * The callback will receive mqtt_message structs that must be freed with mqtt_message_free()
 */
void mqtt_set_message_callback(
    cwebsocket_client *client,
    mqtt_message_callback callback,
    void *context
) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state) return;

    state->message_callback = callback;
    state->message_context = context;
}

/**
 * Free an mqtt_message struct received from the message callback
 * This frees the message, topic, and all properties
 */
void mqtt_message_free(mqtt_message *message) {
    if (!message) return;

    // Free topic (was allocated with strdup)
    if (message->topic) {
        free((char *)message->topic);
    }

    // Note: payload is NOT freed - it points to internal buffer

    // Free properties if present
    if (message->properties) {
        mqtt_properties_free(message->properties);
    }

    // Free the message struct itself
    free(message);
}

// =============================================================================
// SCRAM-SHA-256 Authentication Callback
// =============================================================================

// SCRAM authentication callback for AUTH packet handling
static int mqtt_scram_auth_callback(
    mqtt_client_state *state,
    const char *method,
    const uint8_t *data,
    size_t data_len,
    uint8_t **response_data,
    size_t *response_len
) {
    if (!state || !method || strcmp(method, "SCRAM-SHA-256") != 0) {
        MQTT_LOG_ERROR("mqtt_scram_auth_callback: invalid parameters or unsupported method");
        return -1;
    }

    mqtt_scram_context *scram_ctx = (mqtt_scram_context *)state->auth_context;

    if (!scram_ctx) {
        MQTT_LOG_ERROR("mqtt_scram_auth_callback: no SCRAM context");
        return -1;
    }

    // Determine SCRAM state based on received data
    if (!data || data_len == 0) {
        // Initial AUTH challenge - send client-first-message
        MQTT_LOG_DEBUG("mqtt_scram_auth_callback: generating client-first-message");

        char *client_first = mqtt_scram_client_first(scram_ctx);
        if (!client_first) {
            MQTT_LOG_ERROR("mqtt_scram_auth_callback: failed to generate client-first-message");
            return -1;
        }

        // Return client-first as authentication data
        size_t msg_len = strlen(client_first);
        *response_data = (uint8_t *)malloc(msg_len);
        if (!*response_data) {
            free(client_first);
            return -1;
        }

        memcpy(*response_data, client_first, msg_len);
        *response_len = msg_len;
        free(client_first);

        MQTT_LOG_DEBUG("mqtt_scram_auth_callback: client-first-message sent (%zu bytes)", msg_len);
        return 1;
    }

    // Server sent authentication data - parse as server-first or server-final
    if (scram_ctx->state == SCRAM_STATE_CLIENT_FIRST_SENT) {
        // This is server-first-message - generate client-final
        MQTT_LOG_DEBUG("mqtt_scram_auth_callback: received server-first-message (%zu bytes)", data_len);

        // Convert binary data to null-terminated string
        char *server_first = malloc(data_len + 1);
        if (!server_first) {
            return -1;
        }
        memcpy(server_first, data, data_len);
        server_first[data_len] = '\0';

        char *client_final = mqtt_scram_client_final(scram_ctx, server_first);
        free(server_first);

        if (!client_final) {
            MQTT_LOG_ERROR("mqtt_scram_auth_callback: failed to generate client-final-message");
            return -1;
        }

        // Return client-final as authentication data
        size_t msg_len = strlen(client_final);
        *response_data = (uint8_t *)malloc(msg_len);
        if (!*response_data) {
            free(client_final);
            return -1;
        }

        memcpy(*response_data, client_final, msg_len);
        *response_len = msg_len;
        free(client_final);

        MQTT_LOG_DEBUG("mqtt_scram_auth_callback: client-final-message sent (%zu bytes)", msg_len);
        return 1;
    }

    if (scram_ctx->state == SCRAM_STATE_CLIENT_FINAL_SENT) {
        // This is server-final-message - verify server signature
        MQTT_LOG_DEBUG("mqtt_scram_auth_callback: received server-final-message (%zu bytes)", data_len);

        // Convert binary data to null-terminated string
        char *server_final = malloc(data_len + 1);
        if (!server_final) {
            return -1;
        }
        memcpy(server_final, data, data_len);
        server_final[data_len] = '\0';

        int result = mqtt_scram_verify_server_final(scram_ctx, server_final);
        free(server_final);

        if (result == 0) {
            MQTT_LOG_DEBUG("mqtt_scram_auth_callback: authentication successful");
            return 0;  // Success, no response needed
        } else {
            MQTT_LOG_ERROR("mqtt_scram_auth_callback: server verification failed");
            return -1;
        }
    }

    MQTT_LOG_WARN("mqtt_scram_auth_callback: unexpected SCRAM state %d", scram_ctx->state);
    return -1;
}

// =============================================================================
// MQTT Connection Management
// =============================================================================

void mqtt_send_connect(
    cwebsocket_client *client,
    const char *client_id,
    const char *username,
    const char *password,
    uint16_t keep_alive,
    uint8_t clean_start
) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state) {
        MQTT_LOG_ERROR( "mqtt_send_connect: no client state");
        return;
    }

    // Restore session if clean_start=0 and persistence enabled
    if (!clean_start && state->persistence) {
        mqtt_restore_session(state);
    }

    // Build CONNECT packet
    mqtt_packet packet = {0};
    packet.header.type = MQTT_CONNECT;
    packet.header.flags = 0;

    // Variable header: Protocol Name + Version + Connect Flags + Keep Alive
    uint8_t var_header[1024];
    size_t vh_pos = 0;

    // Protocol Name: "MQTT"
    vh_pos += mqtt_encode_utf8_string("MQTT", var_header + vh_pos);

    // Protocol Version (5 for MQTT 5.0)
    var_header[vh_pos++] = MQTT_VERSION_5_0;

    // Connect Flags
    uint8_t connect_flags = 0;
    if (clean_start) connect_flags |= 0x02;

    // Will flag and related flags (bit 2 = will flag, bits 3-4 = will QoS, bit 5 = will retain)
    if (state->will.topic) {
        connect_flags |= 0x04;  // Will flag
        connect_flags |= (state->will.qos & 0x03) << 3;  // Will QoS
        if (state->will.retain) connect_flags |= 0x20;  // Will retain
    }

    if (username) connect_flags |= 0x80;
    if (password) connect_flags |= 0x40;
    var_header[vh_pos++] = connect_flags;

    // Keep Alive
    var_header[vh_pos++] = (keep_alive >> 8) & 0xFF;
    var_header[vh_pos++] = keep_alive & 0xFF;

    // CONNECT Properties - Build comprehensive property list
    mqtt_property *connect_props = NULL;
    mqtt_property **props_tail = &connect_props;

    // Session Expiry Interval (default: 0 for session ends on disconnect)
    if (state->session_expiry_interval > 0) {
        mqtt_property *prop = mqtt_property_create(MQTT_PROP_SESSION_EXPIRY_INTERVAL);
        if (prop) {
            prop->value.u32 = state->session_expiry_interval;
            *props_tail = prop;
            props_tail = &prop->next;
        }
    }

    // Receive Maximum (max number of QoS 1 and 2 messages we can handle concurrently)
    if (state->receive_maximum > 0 && state->receive_maximum != 65535) {
        mqtt_property *prop = mqtt_property_create(MQTT_PROP_RECEIVE_MAXIMUM);
        if (prop) {
            prop->value.u16 = state->receive_maximum;
            *props_tail = prop;
            props_tail = &prop->next;
        }
    }

    // Maximum Packet Size (max packet size we can accept)
    if (state->maximum_packet_size > 0) {
        mqtt_property *prop = mqtt_property_create(MQTT_PROP_MAXIMUM_PACKET_SIZE);
        if (prop) {
            prop->value.u32 = state->maximum_packet_size;
            *props_tail = prop;
            props_tail = &prop->next;
        }
    }

    // Topic Alias Maximum (max topic aliases we support)
    if (state->topic_alias_maximum > 0) {
        mqtt_property *prop = mqtt_property_create(MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
        if (prop) {
            prop->value.u16 = state->topic_alias_maximum;
            *props_tail = prop;
            props_tail = &prop->next;
        }
    }

    // Request Response Information (request server to send response information)
    mqtt_property *prop_req_resp = mqtt_property_create(MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
    if (prop_req_resp) {
        prop_req_resp->value.byte = 1;  // Request response information
        *props_tail = prop_req_resp;
        props_tail = &prop_req_resp->next;
    }

    // Request Problem Information (request detailed error info)
    mqtt_property *prop_req_prob = mqtt_property_create(MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
    if (prop_req_prob) {
        prop_req_prob->value.byte = 1;  // Request problem information
        *props_tail = prop_req_prob;
        props_tail = &prop_req_prob->next;
    }

    // Authentication Method (for enhanced authentication)
    if (state->authentication_method) {
        mqtt_property *prop_auth_method = mqtt_property_create(MQTT_PROP_AUTHENTICATION_METHOD);
        if (prop_auth_method) {
            prop_auth_method->value.string = strdup(state->authentication_method);
            if (prop_auth_method->value.string) {
                *props_tail = prop_auth_method;
                props_tail = &prop_auth_method->next;
                // Mark authentication as in progress
                state->auth_in_progress = 1;
                MQTT_LOG_DEBUG( "mqtt_send_connect: including Authentication Method '%s'",
                       state->authentication_method);

                // Set up SCRAM-SHA-256 authentication if requested
                if (strcmp(state->authentication_method, "SCRAM-SHA-256") == 0) {
                    // Create SCRAM context if not already created
                    if (!state->auth_context && username && password) {
                        mqtt_scram_context *scram_ctx = mqtt_scram_create(username, password);
                        if (scram_ctx) {
                            state->auth_context = scram_ctx;
                            state->auth_callback = mqtt_scram_auth_callback;
                            MQTT_LOG_DEBUG("mqtt_send_connect: SCRAM-SHA-256 context created");
                        } else {
                            MQTT_LOG_ERROR("mqtt_send_connect: failed to create SCRAM-SHA-256 context");
                        }
                    }
                }
            } else {
                free(prop_auth_method);
            }
        }
    }

    // Encode CONNECT properties
    uint8_t props_buffer[1024];
    int props_len = mqtt_encode_properties(connect_props, props_buffer);
    memcpy(var_header + vh_pos, props_buffer, props_len);
    vh_pos += props_len;

    // Free property list
    mqtt_properties_free(connect_props);

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) return;
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;

    // Payload: Client ID + Will Properties + Will Topic + Will Payload + Username + Password
    uint8_t payload[4096];
    size_t payload_pos = 0;

    // Client ID
    payload_pos += mqtt_encode_utf8_string(client_id ? client_id : "", payload + payload_pos);

    // Will Properties, Topic, and Payload (if will flag is set)
    if (state->will.topic) {
        // Will Properties
        if (state->will.delay_interval > 0) {
            // Encode property length (1 byte for property ID + 4 bytes for uint32)
            payload[payload_pos++] = 5;

            // Will Delay Interval property
            payload[payload_pos++] = MQTT_PROP_WILL_DELAY_INTERVAL;
            payload[payload_pos++] = (state->will.delay_interval >> 24) & 0xFF;
            payload[payload_pos++] = (state->will.delay_interval >> 16) & 0xFF;
            payload[payload_pos++] = (state->will.delay_interval >> 8) & 0xFF;
            payload[payload_pos++] = state->will.delay_interval & 0xFF;
        } else {
            // No will properties
            payload[payload_pos++] = 0;
        }

        // Will Topic
        payload_pos += mqtt_encode_utf8_string(state->will.topic, payload + payload_pos);

        // Will Payload
        if (state->will.payload && state->will.payload_len > 0) {
            payload_pos += mqtt_encode_binary_data(state->will.payload,
                                                   state->will.payload_len,
                                                   payload + payload_pos);
        } else {
            // Empty payload (length = 0)
            payload[payload_pos++] = 0;
            payload[payload_pos++] = 0;
        }

        MQTT_LOG_DEBUG( "mqtt_send_connect: including will message (topic='%s', payload_len=%zu, QoS=%d, retain=%d)",
               state->will.topic, state->will.payload_len, state->will.qos, state->will.retain);
    }

    // Username (if present)
    if (username) {
        payload_pos += mqtt_encode_utf8_string(username, payload + payload_pos);
    }

    // Password (if present)
    if (password) {
        payload_pos += mqtt_encode_utf8_string(password, payload + payload_pos);
    }

    packet.payload = malloc(payload_pos);
    if (!packet.payload) {
        free(packet.variable_header);
        return;
    }
    memcpy(packet.payload, payload, payload_pos);
    packet.payload_len = payload_pos;

    // Set remaining length
    packet.header.remaining_length = packet.variable_header_len + packet.payload_len;

    // Encode and send
    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        // Validate packet size before sending
        if (!mqtt_validate_packet_size(state, encoded_len)) {
            MQTT_LOG_ERROR("mqtt_send_connect: packet size %zu exceeds server maximum %u",
                   encoded_len, state->server_maximum_packet_size);
            free(encoded);
            free(packet.variable_header);
            free(packet.payload);
            return;
        }

        MQTT_LOG_DEBUG( "mqtt_send_connect: sending CONNECT packet (%zu bytes)", encoded_len);
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);

        // Update timestamp
        gettimeofday(&state->last_packet_sent, NULL);
    }

    free(packet.variable_header);
    free(packet.payload);
}

void mqtt_send_disconnect(
    cwebsocket_client *client,
    mqtt_reason_code reason_code,
    const char *reason_string
) {
    // Add NULL check for client
    if (!client) {
        MQTT_LOG_ERROR("mqtt_send_disconnect: NULL client pointer");
        return;
    }

    // Persist session state before disconnecting (for clean reconnect)
    mqtt_client_state *state = global_mqtt_state;
    if (state && state->persistence && !state->clean_start) {
        mqtt_persist_session(state);
        MQTT_LOG_DEBUG( "mqtt_send_disconnect: session persisted before disconnect");
    }

    mqtt_packet packet = {0};
    packet.header.type = MQTT_DISCONNECT;
    packet.header.flags = 0;

    // Variable header: Reason Code + Properties
    uint8_t var_header[256];
    size_t vh_pos = 0;

    // Reason code (optional for success)
    if (reason_code != MQTT_RC_SUCCESS) {
        var_header[vh_pos++] = reason_code;
    }

    // Properties (simplified: length = 0)
    var_header[vh_pos++] = 0;

    if (vh_pos > 0) {
        packet.variable_header = malloc(vh_pos);
        if (!packet.variable_header) return;
        memcpy(packet.variable_header, var_header, vh_pos);
        packet.variable_header_len = vh_pos;
        packet.header.remaining_length = vh_pos;
    }

    // Encode and send
    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        // Validate packet size before sending
        if (!mqtt_validate_packet_size(state, encoded_len)) {
            MQTT_LOG_ERROR("mqtt_send_disconnect: packet size %zu exceeds server maximum %u",
                   encoded_len, state->server_maximum_packet_size ? state->server_maximum_packet_size : 0);
            free(encoded);
            free(packet.variable_header);
            return;
        }

        MQTT_LOG_DEBUG( "mqtt_send_disconnect: sending DISCONNECT packet");
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);
    }

    free(packet.variable_header);
}

void mqtt_send_pingreq(cwebsocket_client *client) {
    // Add NULL check for client
    if (!client) {
        MQTT_LOG_ERROR("mqtt_send_pingreq: NULL client pointer");
        return;
    }

    mqtt_packet packet = {0};
    packet.header.type = MQTT_PINGREQ;
    packet.header.flags = 0;
    packet.header.remaining_length = 0;

    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        MQTT_LOG_DEBUG( "mqtt_send_pingreq: sending PINGREQ");
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);

        mqtt_client_state *state = global_mqtt_state;
        if (state) {
            gettimeofday(&state->last_packet_sent, NULL);
        }
    }
}

void mqtt_send_auth(
    cwebsocket_client *client,
    mqtt_reason_code reason_code,
    const char *authentication_method,
    const uint8_t *authentication_data,
    size_t authentication_data_len
) {
    if (!authentication_method) {
        MQTT_LOG_ERROR( "mqtt_send_auth: authentication method is required");
        return;
    }

    mqtt_packet packet = {0};
    packet.header.type = MQTT_AUTH;
    packet.header.flags = 0;

    // Variable header: Reason Code + Properties
    uint8_t var_header[2048];
    size_t vh_pos = 0;

    // Reason code (optional for success, but we include it for clarity)
    var_header[vh_pos++] = reason_code;

    // Build properties section
    uint8_t properties[2048];
    size_t prop_pos = 0;

    // Authentication Method (0x15, UTF-8 String) - REQUIRED
    properties[prop_pos++] = MQTT_PROP_AUTHENTICATION_METHOD;
    prop_pos += mqtt_encode_utf8_string(authentication_method, properties + prop_pos);

    // Authentication Data (0x16, Binary Data) - optional
    if (authentication_data && authentication_data_len > 0) {
        properties[prop_pos++] = MQTT_PROP_AUTHENTICATION_DATA;
        prop_pos += mqtt_encode_binary_data(authentication_data, authentication_data_len, properties + prop_pos);
    }

    // Encode property length as variable byte integer
    uint8_t prop_len_buf[4];
    int prop_len_bytes = mqtt_encode_variable_byte_integer(prop_pos, prop_len_buf);

    // Add property length to variable header
    memcpy(var_header + vh_pos, prop_len_buf, prop_len_bytes);
    vh_pos += prop_len_bytes;

    // Add properties to variable header
    memcpy(var_header + vh_pos, properties, prop_pos);
    vh_pos += prop_pos;

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) {
        MQTT_LOG_ERROR( "mqtt_send_auth: malloc failed for variable header");
        return;
    }
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;
    packet.header.remaining_length = vh_pos;

    // Encode and send
    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        MQTT_LOG_DEBUG( "mqtt_send_auth: sending AUTH packet (reason=0x%02X, method=%s)",
               reason_code, authentication_method);
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);

        mqtt_client_state *state = global_mqtt_state;
        if (state) {
            gettimeofday(&state->last_packet_sent, NULL);
        }
    }

    free(packet.variable_header);
}

// =============================================================================
// Subscription Management
// =============================================================================

void mqtt_send_subscribe(
    cwebsocket_client *client,
    const char *topic_filter,
    mqtt_qos qos,
    uint8_t no_local,
    uint8_t retain_as_published,
    uint8_t retain_handling
) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state) return;

    // MQTT 5.0 Spec: Check subscription restrictions from CONNACK

    // Check for wildcards if server doesn't support them (MQTT-3.8.3-1)
    if (!state->wildcard_subscription_available &&
        (strchr(topic_filter, '#') || strchr(topic_filter, '+'))) {
        MQTT_LOG_ERROR("mqtt_send_subscribe: Server doesn't support wildcard subscriptions (topic: %s)", topic_filter);
        return;
    }

    // Check for shared subscription prefix if server doesn't support them (MQTT-3.8.3-2)
    if (!state->shared_subscription_available &&
        strncmp(topic_filter, "$share/", 7) == 0) {
        MQTT_LOG_ERROR("mqtt_send_subscribe: Server doesn't support shared subscriptions (topic: %s)", topic_filter);
        return;
    }

    mqtt_packet packet = {0};
    packet.header.type = MQTT_SUBSCRIBE;
    packet.header.flags = 0x02; // Reserved bits = 0010

    // Variable header: Packet ID + Properties
    uint8_t var_header[32];
    size_t vh_pos = 0;

    // Packet ID
    uint16_t packet_id = mqtt_packet_id_pool_allocate(state->packet_id_pool);
    if (packet_id == 0) {
        MQTT_LOG_ERROR( "mqtt_send_subscribe: packet ID pool exhausted - cannot send SUBSCRIBE");
        return;
    }
    var_header[vh_pos++] = (packet_id >> 8) & 0xFF;
    var_header[vh_pos++] = packet_id & 0xFF;

    // Properties (simplified)
    var_header[vh_pos++] = 0;

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) return;
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;

    // Payload: Topic Filter + Subscription Options
    uint8_t payload[1024];
    size_t payload_pos = 0;

    payload_pos += mqtt_encode_utf8_string(topic_filter, payload + payload_pos);

    // Subscription options byte
    uint8_t options = (qos & 0x03);
    if (no_local) options |= 0x04;
    if (retain_as_published) options |= 0x08;
    options |= (retain_handling & 0x03) << 4;
    payload[payload_pos++] = options;

    packet.payload = malloc(payload_pos);
    if (!packet.payload) {
        free(packet.variable_header);
        return;
    }
    memcpy(packet.payload, payload, payload_pos);
    packet.payload_len = payload_pos;

    packet.header.remaining_length = packet.variable_header_len + packet.payload_len;

    // Encode and send
    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        // Validate packet size before sending
        if (!mqtt_validate_packet_size(state, encoded_len)) {
            MQTT_LOG_ERROR("mqtt_send_subscribe: packet size %zu exceeds server maximum %u",
                   encoded_len, state->server_maximum_packet_size);
            free(encoded);
            free(packet.variable_header);
            free(packet.payload);
            return;
        }

        MQTT_LOG_DEBUG( "mqtt_send_subscribe: subscribing to %s (QoS %d)", topic_filter, qos);
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);

        gettimeofday(&state->last_packet_sent, NULL);
    }

    free(packet.variable_header);
    free(packet.payload);

    // Track subscription
    mqtt_subscription *sub = calloc(1, sizeof(mqtt_subscription));
    if (sub) {
        sub->topic_filter = strdup(topic_filter);
        if (!sub->topic_filter) {
            MQTT_LOG_ERROR("mqtt_send_subscribe: failed to allocate topic_filter");
            free(sub);
            return;
        }
        sub->qos = qos;
        sub->no_local = no_local;
        sub->retain_as_published = retain_as_published;
        sub->retain_handling = retain_handling;

        // Check if this is a shared subscription
        if (mqtt_is_shared_subscription(topic_filter)) {
            char *share_name = NULL;
            char *actual_topic = NULL;
            if (mqtt_parse_shared_subscription(topic_filter, &share_name, &actual_topic) == 0) {
                sub->is_shared_subscription = 1;
                sub->share_name = share_name;
                MQTT_LOG_DEBUG( "mqtt_send_subscribe: shared subscription (share=%s, topic=%s)",
                       share_name, actual_topic);
                free(actual_topic);
            } else {
                sub->is_shared_subscription = 0;
                sub->share_name = NULL;
            }
        } else {
            sub->is_shared_subscription = 0;
            sub->share_name = NULL;
        }

        sub->next = state->subscriptions;
        state->subscriptions = sub;
    }
}

void mqtt_send_subscribe_ex(
    cwebsocket_client *client,
    const char *topic_filter,
    mqtt_qos qos,
    uint8_t no_local,
    uint8_t retain_as_published,
    uint8_t retain_handling,
    uint32_t subscription_identifier
) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state) return;

    // MQTT 5.0 Spec: Check subscription restrictions from CONNACK

    // Check for wildcards if server doesn't support them (MQTT-3.8.3-1)
    if (!state->wildcard_subscription_available &&
        (strchr(topic_filter, '#') || strchr(topic_filter, '+'))) {
        MQTT_LOG_ERROR("mqtt_send_subscribe_ex: Server doesn't support wildcard subscriptions (topic: %s)", topic_filter);
        return;
    }

    // Check for shared subscription prefix if server doesn't support them (MQTT-3.8.3-2)
    if (!state->shared_subscription_available &&
        strncmp(topic_filter, "$share/", 7) == 0) {
        MQTT_LOG_ERROR("mqtt_send_subscribe_ex: Server doesn't support shared subscriptions (topic: %s)", topic_filter);
        return;
    }

    // Check subscription identifier usage if server doesn't support them (MQTT-3.8.3-3)
    if (subscription_identifier > 0 && !state->subscription_identifier_available) {
        MQTT_LOG_WARN("mqtt_send_subscribe_ex: Server doesn't support subscription identifiers, ignoring (ID: %u)", subscription_identifier);
        subscription_identifier = 0;  // Clear the subscription ID
    }

    mqtt_packet packet = {0};
    packet.header.type = MQTT_SUBSCRIBE;
    packet.header.flags = 0x02; // Reserved bits = 0010

    // Variable header: Packet ID + Properties
    uint8_t var_header[64];
    size_t vh_pos = 0;

    // Packet ID
    uint16_t packet_id = mqtt_get_next_packet_id(state);
    var_header[vh_pos++] = (packet_id >> 8) & 0xFF;
    var_header[vh_pos++] = packet_id & 0xFF;

    // Properties
    if (subscription_identifier > 0) {
        // Calculate property length
        uint8_t sub_id_vbi[4];
        int sub_id_len = mqtt_encode_variable_byte_integer(subscription_identifier, sub_id_vbi);

        // Property length (1 byte property ID + variable byte integer)
        uint8_t prop_len_vbi[4];
        int prop_len = mqtt_encode_variable_byte_integer(1 + sub_id_len, prop_len_vbi);

        // Write property length
        memcpy(var_header + vh_pos, prop_len_vbi, prop_len);
        vh_pos += prop_len;

        // Write Subscription Identifier property
        var_header[vh_pos++] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
        memcpy(var_header + vh_pos, sub_id_vbi, sub_id_len);
        vh_pos += sub_id_len;
    } else {
        // No properties
        var_header[vh_pos++] = 0;
    }

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) return;
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;

    // Payload: Topic Filter + Subscription Options
    uint8_t payload[1024];
    size_t payload_pos = 0;

    payload_pos += mqtt_encode_utf8_string(topic_filter, payload + payload_pos);

    // Subscription options byte
    uint8_t options = (qos & 0x03);
    if (no_local) options |= 0x04;
    if (retain_as_published) options |= 0x08;
    options |= (retain_handling & 0x03) << 4;
    payload[payload_pos++] = options;

    packet.payload = malloc(payload_pos);
    if (!packet.payload) {
        free(packet.variable_header);
        return;
    }
    memcpy(packet.payload, payload, payload_pos);
    packet.payload_len = payload_pos;

    packet.header.remaining_length = packet.variable_header_len + packet.payload_len;

    // Encode and send
    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        MQTT_LOG_DEBUG( "mqtt_send_subscribe_ex: subscribing to %s (QoS %d, SubID %u, NL=%d, RAP=%d, RH=%d)",
               topic_filter, qos, subscription_identifier, no_local, retain_as_published, retain_handling);
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);

        gettimeofday(&state->last_packet_sent, NULL);
    }

    free(packet.variable_header);
    free(packet.payload);

    // Track subscription
    mqtt_subscription *sub = calloc(1, sizeof(mqtt_subscription));
    if (sub) {
        sub->topic_filter = strdup(topic_filter);
        if (!sub->topic_filter) {
            MQTT_LOG_ERROR("mqtt_send_subscribe_ex: failed to allocate topic_filter");
            free(sub);
            return;
        }
        sub->qos = qos;
        sub->no_local = no_local;
        sub->retain_as_published = retain_as_published;
        sub->retain_handling = retain_handling;

        // Check if this is a shared subscription
        if (mqtt_is_shared_subscription(topic_filter)) {
            char *share_name = NULL;
            char *actual_topic = NULL;
            if (mqtt_parse_shared_subscription(topic_filter, &share_name, &actual_topic) == 0) {
                sub->is_shared_subscription = 1;
                sub->share_name = share_name;
                MQTT_LOG_DEBUG( "mqtt_send_subscribe_ex: shared subscription (share=%s, topic=%s)",
                       share_name, actual_topic);
                free(actual_topic);
            } else {
                sub->is_shared_subscription = 0;
                sub->share_name = NULL;
            }
        } else {
            sub->is_shared_subscription = 0;
            sub->share_name = NULL;
        }

        sub->next = state->subscriptions;
        state->subscriptions = sub;
    }
}

void mqtt_send_unsubscribe(
    cwebsocket_client *client,
    const char *topic_filter
) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state) return;

    mqtt_packet packet = {0};
    packet.header.type = MQTT_UNSUBSCRIBE;
    packet.header.flags = 0x02; // Reserved bits = 0010

    // Variable header: Packet ID + Properties
    uint8_t var_header[32];
    size_t vh_pos = 0;

    uint16_t packet_id = mqtt_get_next_packet_id(state);
    var_header[vh_pos++] = (packet_id >> 8) & 0xFF;
    var_header[vh_pos++] = packet_id & 0xFF;

    var_header[vh_pos++] = 0; // Properties

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) return;
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;

    // Payload: Topic Filter
    uint8_t payload[1024];
    size_t payload_pos = mqtt_encode_utf8_string(topic_filter, payload);

    packet.payload = malloc(payload_pos);
    if (!packet.payload) {
        free(packet.variable_header);
        return;
    }
    memcpy(packet.payload, payload, payload_pos);
    packet.payload_len = payload_pos;

    packet.header.remaining_length = packet.variable_header_len + packet.payload_len;

    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        // Validate packet size before sending
        if (!mqtt_validate_packet_size(state, encoded_len)) {
            MQTT_LOG_ERROR("mqtt_send_unsubscribe: packet size %zu exceeds server maximum %u",
                   encoded_len, state->server_maximum_packet_size);
            free(encoded);
            free(packet.variable_header);
            free(packet.payload);
            return;
        }

        MQTT_LOG_DEBUG( "mqtt_send_unsubscribe: unsubscribing from %s", topic_filter);
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);

        gettimeofday(&state->last_packet_sent, NULL);
    }

    free(packet.variable_header);
    free(packet.payload);

    // Remove from subscriptions list
    mqtt_subscription **current = &state->subscriptions;
    while (*current) {
        if (strcmp((*current)->topic_filter, topic_filter) == 0) {
            mqtt_subscription *to_remove = *current;
            *current = to_remove->next;
            free(to_remove->topic_filter);
            free(to_remove);
            break;
        }
        current = &(*current)->next;
    }
}

// =============================================================================
// Publishing
// =============================================================================

void mqtt_send_publish(
    cwebsocket_client *client,
    const char *topic,
    const uint8_t *payload,
    size_t payload_len,
    mqtt_qos qos,
    uint8_t retain,
    uint8_t dup
) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state) return;

    // Enforce Maximum QoS from server (MQTT 5.0 spec: CONNACK property 0x24)
    if (state->maximum_qos < 255 && qos > state->maximum_qos) {
        MQTT_LOG_WARN("mqtt_send_publish: Downgrading QoS from %d to %d (server maximum)", qos, state->maximum_qos);
        qos = state->maximum_qos;
    }

    // Enforce Retain Available from server (MQTT 5.0 spec: CONNACK property 0x25)
    if (!state->retain_available && retain) {
        MQTT_LOG_WARN("mqtt_send_publish: Clearing retain flag (server doesn't support retained messages)");
        retain = 0;
    }

    // FLOW CONTROL: Check if we can send QoS > 0 message
    if (qos > 0 && !mqtt_can_send_qos_message(state)) {
        MQTT_LOG_WARN( "mqtt_send_publish: cannot send QoS %d message, flow control limit reached (%u/%u in-flight)",
               qos, state->in_flight_qos_count, state->server_receive_maximum);
        // Return error - message is dropped (could implement queuing here)
        return;
    }

    mqtt_packet packet = {0};
    packet.header.type = MQTT_PUBLISH;

    // Flags: DUP, QoS, RETAIN
    packet.header.flags = 0;
    if (dup) packet.header.flags |= 0x08;
    packet.header.flags |= (qos & 0x03) << 1;
    if (retain) packet.header.flags |= 0x01;

    // Variable header: Topic Name + Packet ID (if QoS > 0) + Properties
    uint8_t var_header[1024];
    size_t vh_pos = 0;

    vh_pos += mqtt_encode_utf8_string(topic, var_header + vh_pos);

    // Packet ID (only for QoS 1 and 2)
    uint16_t packet_id = 0;
    if (qos > 0) {
        // Allocate packet ID from pool
        packet_id = mqtt_packet_id_pool_allocate(state->packet_id_pool);
        if (packet_id == 0) {
            MQTT_LOG_ERROR( "mqtt_send_publish: packet ID pool exhausted - cannot send QoS %d message", qos);
            return;
        }
        var_header[vh_pos++] = (packet_id >> 8) & 0xFF;
        var_header[vh_pos++] = packet_id & 0xFF;

        // Persist QoS 1/2 messages before sending
        mqtt_persist_message(state, packet_id, MQTT_PUBLISH, qos,
                            topic, payload, payload_len, retain, dup);
    }

    // Properties - empty for now (can be extended via mqtt_send_publish_ex)
    var_header[vh_pos++] = 0;

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) return;
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;

    // Payload
    if (payload && payload_len > 0) {
        packet.payload = malloc(payload_len);
        if (!packet.payload) {
            free(packet.variable_header);
            return;
        }
        memcpy(packet.payload, payload, payload_len);
        packet.payload_len = payload_len;
    }

    packet.header.remaining_length = packet.variable_header_len + packet.payload_len;

    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        // Validate packet size before sending
        if (!mqtt_validate_packet_size(state, encoded_len)) {
            MQTT_LOG_ERROR("mqtt_send_publish: packet size %zu exceeds server maximum %u",
                   encoded_len, state->server_maximum_packet_size);
            free(encoded);
            free(packet.variable_header);
            free(packet.payload);
            // Release packet ID if allocated
            if (qos > 0 && packet_id != 0) {
                mqtt_packet_id_pool_release(state->packet_id_pool, packet_id);
            }
            return;
        }

        MQTT_LOG_DEBUG( "mqtt_send_publish: publishing to %s (%zu bytes, QoS %d)",
               topic, payload_len, qos);
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);

        gettimeofday(&state->last_packet_sent, NULL);

        // FLOW CONTROL: Increment in-flight counter for QoS > 0 messages
        if (qos > 0) {
            mqtt_increment_in_flight(state);
        }
    }

    free(packet.variable_header);
    free(packet.payload);
}

void mqtt_send_publish_ex(
    cwebsocket_client *client,
    const char *topic,
    const uint8_t *payload,
    size_t payload_len,
    mqtt_qos qos,
    uint8_t retain,
    uint8_t dup,
    mqtt_property *properties
) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state) return;

    // Enforce Maximum QoS from server (MQTT 5.0 spec: CONNACK property 0x24)
    if (state->maximum_qos < 255 && qos > state->maximum_qos) {
        MQTT_LOG_WARN("mqtt_send_publish_ex: Downgrading QoS from %d to %d (server maximum)", qos, state->maximum_qos);
        qos = state->maximum_qos;
    }

    // Enforce Retain Available from server (MQTT 5.0 spec: CONNACK property 0x25)
    if (!state->retain_available && retain) {
        MQTT_LOG_WARN("mqtt_send_publish_ex: Clearing retain flag (server doesn't support retained messages)");
        retain = 0;
    }

    // FLOW CONTROL: Check if we can send QoS > 0 message
    if (qos > 0 && !mqtt_can_send_qos_message(state)) {
        MQTT_LOG_WARN( "mqtt_send_publish_ex: cannot send QoS %d message, flow control limit reached (%u/%u in-flight)",
               qos, state->in_flight_qos_count, state->server_receive_maximum);
        // Return error - message is dropped (could implement queuing here)
        return;
    }

    mqtt_packet packet = {0};
    packet.header.type = MQTT_PUBLISH;

    // Flags: DUP, QoS, RETAIN
    packet.header.flags = 0;
    if (dup) packet.header.flags |= 0x08;
    packet.header.flags |= (qos & 0x03) << 1;
    if (retain) packet.header.flags |= 0x01;

    // Topic alias handling
    uint16_t topic_alias = 0;
    const char *topic_to_send = topic;
    mqtt_property *topic_alias_prop = NULL;

    // Check if we should use topic alias (only if server supports it)
    if (state->server_topic_alias_maximum > 0 && topic && strlen(topic) > 0) {
        // Check if we already have an alias for this topic
        topic_alias = mqtt_topic_alias_get(state, topic);

        if (topic_alias > 0) {
            // We have an existing alias - use it with empty topic
            topic_to_send = "";
            MQTT_LOG_DEBUG( "mqtt_send_publish_ex: using existing alias %u for topic '%s'",
                   topic_alias, topic);
        } else {
            // No existing alias - check if we can create one
            if (state->next_topic_alias <= state->server_topic_alias_maximum) {
                // Assign a new alias
                topic_alias = state->next_topic_alias++;
                if (mqtt_topic_alias_set(state, topic_alias, topic) == 0) {
                    // Successfully created alias - send both topic and alias
                    topic_to_send = topic;
                    MQTT_LOG_DEBUG( "mqtt_send_publish_ex: assigned new alias %u for topic '%s'",
                           topic_alias, topic);
                } else {
                    // Failed to set alias - just send topic without alias
                    topic_alias = 0;
                }
            }
        }

        // Create topic alias property if we're using one
        if (topic_alias > 0) {
            topic_alias_prop = mqtt_property_create(MQTT_PROP_TOPIC_ALIAS);
            if (topic_alias_prop) {
                topic_alias_prop->value.u16 = topic_alias;
                // Add to properties list
                topic_alias_prop->next = properties;
                properties = topic_alias_prop;
            }
        }
    }

    // Variable header: Topic Name + Packet ID (if QoS > 0) + Properties
    uint8_t var_header[2048];
    size_t vh_pos = 0;

    vh_pos += mqtt_encode_utf8_string(topic_to_send, var_header + vh_pos);

    // Packet ID (only for QoS 1 and 2)
    uint16_t packet_id = 0;
    if (qos > 0) {
        // Allocate packet ID from pool
        packet_id = mqtt_packet_id_pool_allocate(state->packet_id_pool);
        if (packet_id == 0) {
            MQTT_LOG_ERROR( "mqtt_send_publish_ex: packet ID pool exhausted - cannot send QoS %d message", qos);
            if (topic_alias_prop) mqtt_property_free(topic_alias_prop);
            return;
        }
        var_header[vh_pos++] = (packet_id >> 8) & 0xFF;
        var_header[vh_pos++] = packet_id & 0xFF;

        // Persist QoS 1/2 messages before sending
        mqtt_persist_message(state, packet_id, MQTT_PUBLISH, qos,
                            topic, payload, payload_len, retain, dup);
    }

    // Encode properties
    uint8_t props_buffer[1024];
    int props_len = mqtt_encode_properties(properties, props_buffer);
    memcpy(var_header + vh_pos, props_buffer, props_len);
    vh_pos += props_len;

    // Clean up temporary topic alias property
    if (topic_alias_prop) {
        topic_alias_prop->next = NULL;
        mqtt_property_free(topic_alias_prop);
    }

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) return;
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;

    // Payload
    if (payload && payload_len > 0) {
        packet.payload = malloc(payload_len);
        if (!packet.payload) {
            free(packet.variable_header);
            return;
        }
        memcpy(packet.payload, payload, payload_len);
        packet.payload_len = payload_len;
    }

    packet.header.remaining_length = packet.variable_header_len + packet.payload_len;

    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        MQTT_LOG_DEBUG( "mqtt_send_publish_ex: publishing to %s (%zu bytes, QoS %d) with properties",
               topic, payload_len, qos);
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);

        gettimeofday(&state->last_packet_sent, NULL);

        // FLOW CONTROL: Increment in-flight counter for QoS > 0 messages
        if (qos > 0) {
            mqtt_increment_in_flight(state);
        }
    }

    free(packet.variable_header);
    free(packet.payload);
}

void mqtt_send_puback(
    cwebsocket_client *client,
    uint16_t packet_id,
    mqtt_reason_code reason_code
) {
    MQTT_LOG_DEBUG( "mqtt_send_puback: sending PUBACK for packet %u", packet_id);
    mqtt_packet packet = {0};
    packet.header.type = MQTT_PUBACK;
    packet.header.flags = 0;

    uint8_t var_header[16];
    size_t vh_pos = 0;

    // Packet ID (always present)
    var_header[vh_pos++] = (packet_id >> 8) & 0xFF;
    var_header[vh_pos++] = packet_id & 0xFF;

    // MQTT 5.0: For success (0x00) with no properties, send ONLY packet ID (2 bytes)
    // For non-success or with properties, include reason code and property length
    if (reason_code != MQTT_RC_SUCCESS) {
        // Non-success: include reason code (no properties for now)
        var_header[vh_pos++] = reason_code;
        // Note: Property length omitted if remaining length < 4 (spec allows this)
    }
    // For success, don't add anything - just 2 bytes total

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) return;
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;
    packet.header.remaining_length = vh_pos;

    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        // Validate packet size before sending
        mqtt_client_state *state = global_mqtt_state;
        if (state && !mqtt_validate_packet_size(state, encoded_len)) {
            MQTT_LOG_ERROR("mqtt_send_puback: packet size %zu exceeds server maximum %u",
                   encoded_len, state->server_maximum_packet_size);
            free(encoded);
            free(packet.variable_header);
            return;
        }

        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);
    }

    free(packet.variable_header);
}

void mqtt_send_pubrec(
    cwebsocket_client *client,
    uint16_t packet_id,
    mqtt_reason_code reason_code
) {
    MQTT_LOG_DEBUG( "mqtt_send_pubrec: sending PUBREC for packet %u", packet_id);
    mqtt_packet packet = {0};
    packet.header.type = MQTT_PUBREC;
    packet.header.flags = 0;

    uint8_t var_header[16];
    size_t vh_pos = 0;

    // Packet ID (always present)
    var_header[vh_pos++] = (packet_id >> 8) & 0xFF;
    var_header[vh_pos++] = packet_id & 0xFF;

    // MQTT 5.0: For success, send only packet ID (2 bytes)
    if (reason_code != MQTT_RC_SUCCESS) {
        var_header[vh_pos++] = reason_code;
    }

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) return;
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;
    packet.header.remaining_length = vh_pos;

    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        // Validate packet size before sending
        mqtt_client_state *state = global_mqtt_state;
        if (state && !mqtt_validate_packet_size(state, encoded_len)) {
            MQTT_LOG_ERROR("mqtt_send_pubrec: packet size %zu exceeds server maximum %u",
                   encoded_len, state->server_maximum_packet_size);
            free(encoded);
            free(packet.variable_header);
            return;
        }

        MQTT_LOG_DEBUG( "mqtt_send_pubrec: sending PUBREC for packet %u", packet_id);
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);
    }

    free(packet.variable_header);
}

void mqtt_send_pubrel(
    cwebsocket_client *client,
    uint16_t packet_id,
    mqtt_reason_code reason_code
) {
    MQTT_LOG_DEBUG( "mqtt_send_pubrel: sending PUBREL for packet %u", packet_id);
    mqtt_packet packet = {0};
    packet.header.type = MQTT_PUBREL;
    packet.header.flags = 0x02; // Reserved bits = 0010

    uint8_t var_header[16];
    size_t vh_pos = 0;

    // Packet ID (always present)
    var_header[vh_pos++] = (packet_id >> 8) & 0xFF;
    var_header[vh_pos++] = packet_id & 0xFF;

    // MQTT 5.0: For success, send only packet ID (2 bytes)
    if (reason_code != MQTT_RC_SUCCESS) {
        var_header[vh_pos++] = reason_code;
    }

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) return;
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;
    packet.header.remaining_length = vh_pos;

    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        // Validate packet size before sending
        mqtt_client_state *state = global_mqtt_state;
        if (state && !mqtt_validate_packet_size(state, encoded_len)) {
            MQTT_LOG_ERROR("mqtt_send_pubrel: packet size %zu exceeds server maximum %u",
                   encoded_len, state->server_maximum_packet_size);
            free(encoded);
            free(packet.variable_header);
            return;
        }

        MQTT_LOG_DEBUG( "mqtt_send_pubrel: sending PUBREL for packet %u", packet_id);
        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);
    }

    free(packet.variable_header);
}

void mqtt_send_pubcomp(
    cwebsocket_client *client,
    uint16_t packet_id,
    mqtt_reason_code reason_code
) {
    MQTT_LOG_DEBUG( "mqtt_send_pubcomp: sending PUBCOMP for packet %u", packet_id);
    mqtt_packet packet = {0};
    packet.header.type = MQTT_PUBCOMP;
    packet.header.flags = 0;

    uint8_t var_header[16];
    size_t vh_pos = 0;

    // Packet ID (always present)
    var_header[vh_pos++] = (packet_id >> 8) & 0xFF;
    var_header[vh_pos++] = packet_id & 0xFF;

    // MQTT 5.0: For success (0x00) with no properties, send ONLY packet ID (2 bytes)
    // For non-success or with properties, include reason code and property length
    if (reason_code != MQTT_RC_SUCCESS) {
        // Non-success: include reason code (no properties for now)
        var_header[vh_pos++] = reason_code;
        // Note: Property length omitted if remaining length < 4 (spec allows this)
    }
    // For success, don't add anything - just 2 bytes total

    packet.variable_header = malloc(vh_pos);
    if (!packet.variable_header) return;
    memcpy(packet.variable_header, var_header, vh_pos);
    packet.variable_header_len = vh_pos;
    packet.header.remaining_length = vh_pos;

    size_t encoded_len;
    uint8_t *encoded = mqtt_packet_encode(&packet, &encoded_len);

    if (encoded) {
        // Validate packet size before sending
        mqtt_client_state *state = global_mqtt_state;
        if (state && !mqtt_validate_packet_size(state, encoded_len)) {
            MQTT_LOG_ERROR("mqtt_send_pubcomp: packet size %zu exceeds server maximum %u",
                   encoded_len, state->server_maximum_packet_size);
            free(encoded);
            free(packet.variable_header);
            return;
        }

        cwebsocket_client_write_data(client, (const char *)encoded, encoded_len, BINARY_FRAME);
        free(encoded);
    }

    free(packet.variable_header);
}

// =============================================================================
// Keep-alive Management
// =============================================================================

void mqtt_keepalive_check(cwebsocket_client *client) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state || !state->connected || state->keep_alive == 0) return;

    struct timeval now;
    gettimeofday(&now, NULL);

    // Check if we need to send PINGREQ
    long elapsed_sec = now.tv_sec - state->last_packet_sent.tv_sec;

    if (elapsed_sec >= (state->keep_alive * 0.75)) {
        // Send PINGREQ when 75% of keep-alive interval has elapsed
        mqtt_send_pingreq(client);
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

const char* mqtt_packet_type_to_string(mqtt_packet_type type) {
    switch (type) {
        case MQTT_CONNECT: return "CONNECT";
        case MQTT_CONNACK: return "CONNACK";
        case MQTT_PUBLISH: return "PUBLISH";
        case MQTT_PUBACK: return "PUBACK";
        case MQTT_PUBREC: return "PUBREC";
        case MQTT_PUBREL: return "PUBREL";
        case MQTT_PUBCOMP: return "PUBCOMP";
        case MQTT_SUBSCRIBE: return "SUBSCRIBE";
        case MQTT_SUBACK: return "SUBACK";
        case MQTT_UNSUBSCRIBE: return "UNSUBSCRIBE";
        case MQTT_UNSUBACK: return "UNSUBACK";
        case MQTT_PINGREQ: return "PINGREQ";
        case MQTT_PINGRESP: return "PINGRESP";
        case MQTT_DISCONNECT: return "DISCONNECT";
        case MQTT_AUTH: return "AUTH";
        default: return "UNKNOWN";
    }
}

const char* mqtt_qos_to_string(mqtt_qos qos) {
    switch (qos) {
        case MQTT_QOS_0: return "QoS 0 (At most once)";
        case MQTT_QOS_1: return "QoS 1 (At least once)";
        case MQTT_QOS_2: return "QoS 2 (Exactly once)";
        default: return "Invalid QoS";
    }
}

const char* mqtt_reason_code_to_string(mqtt_reason_code code) {
    switch (code) {
        // Success & Subscription Grants
        case MQTT_RC_SUCCESS: return "Success";
        case MQTT_RC_GRANTED_QOS_1: return "Granted QoS 1";
        case MQTT_RC_GRANTED_QOS_2: return "Granted QoS 2";

        // Disconnect & PUBLISH Reasons
        case MQTT_RC_DISCONNECT_WITH_WILL: return "Disconnect with Will Message";
        case MQTT_RC_NO_MATCHING_SUBSCRIBERS: return "No matching subscribers";
        case MQTT_RC_NO_SUBSCRIPTION_EXISTED: return "No subscription existed";
        case MQTT_RC_CONTINUE_AUTHENTICATION: return "Continue authentication";
        case MQTT_RC_REAUTHENTICATE: return "Re-authenticate";

        // CONNACK Reasons
        case MQTT_RC_UNSPECIFIED_ERROR: return "Unspecified error";
        case MQTT_RC_MALFORMED_PACKET: return "Malformed packet";
        case MQTT_RC_PROTOCOL_ERROR: return "Protocol error";
        case MQTT_RC_IMPLEMENTATION_SPECIFIC_ERROR: return "Implementation specific error";
        case MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION: return "Unsupported protocol version";
        case MQTT_RC_CLIENT_ID_NOT_VALID: return "Client ID not valid";
        case MQTT_RC_BAD_USERNAME_OR_PASSWORD: return "Bad username or password";
        case MQTT_RC_NOT_AUTHORIZED: return "Not authorized";
        case MQTT_RC_SERVER_UNAVAILABLE: return "Server unavailable";
        case MQTT_RC_SERVER_BUSY: return "Server busy";
        case MQTT_RC_BANNED: return "Banned";
        case MQTT_RC_SERVER_SHUTTING_DOWN: return "Server shutting down";
        case MQTT_RC_BAD_AUTHENTICATION_METHOD: return "Bad authentication method";
        case MQTT_RC_KEEPALIVE_TIMEOUT: return "Keep Alive timeout";
        case MQTT_RC_SESSION_TAKEN_OVER: return "Session taken over";
        case MQTT_RC_TOPIC_FILTER_INVALID: return "Topic Filter invalid";
        case MQTT_RC_TOPIC_NAME_INVALID: return "Topic Name invalid";
        case MQTT_RC_PACKET_ID_IN_USE: return "Packet Identifier in use";
        case MQTT_RC_PACKET_ID_NOT_FOUND: return "Packet Identifier not found";
        case MQTT_RC_RECEIVE_MAXIMUM_EXCEEDED: return "Receive Maximum exceeded";
        case MQTT_RC_TOPIC_ALIAS_INVALID: return "Topic Alias invalid";
        case MQTT_RC_PACKET_TOO_LARGE: return "Packet too large";
        case MQTT_RC_MESSAGE_RATE_TOO_HIGH: return "Message rate too high";
        case MQTT_RC_QUOTA_EXCEEDED: return "Quota exceeded";
        case MQTT_RC_ADMINISTRATIVE_ACTION: return "Administrative action";
        case MQTT_RC_PAYLOAD_FORMAT_INVALID: return "Payload format invalid";
        case MQTT_RC_RETAIN_NOT_SUPPORTED: return "Retain not supported";
        case MQTT_RC_QOS_NOT_SUPPORTED: return "QoS not supported";
        case MQTT_RC_USE_ANOTHER_SERVER: return "Use another server";
        case MQTT_RC_SERVER_MOVED: return "Server moved";
        case MQTT_RC_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED: return "Shared Subscriptions not supported";
        case MQTT_RC_CONNECTION_RATE_EXCEEDED: return "Connection rate exceeded";
        case MQTT_RC_MAXIMUM_CONNECT_TIME: return "Maximum connect time";
        case MQTT_RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED: return "Subscription Identifiers not supported";
        case MQTT_RC_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED: return "Wildcard Subscriptions not supported";

        default: return "Unknown reason code";
    }
}

// =============================================================================
// Shared Subscription Support
// =============================================================================

// Check if a topic filter is a shared subscription
int mqtt_is_shared_subscription(const char *topic_filter) {
    return (topic_filter != NULL && strncmp(topic_filter, "$share/", 7) == 0);
}

// Parse shared subscription format: $share/ShareName/TopicFilter
// Returns 0 on success, -1 on failure
// Caller must free *share_name_out and *topic_filter_out on success
int mqtt_parse_shared_subscription(const char *topic_filter,
                                    char **share_name_out,
                                    char **topic_filter_out) {
    if (!topic_filter || !share_name_out || !topic_filter_out) {
        return -1;
    }

    // Check if it starts with "$share/"
    if (strncmp(topic_filter, "$share/", 7) != 0) {
        return -1;
    }

    // Find the next slash after "$share/"
    const char *share_name_start = topic_filter + 7;
    const char *slash_pos = strchr(share_name_start, '/');

    if (!slash_pos || slash_pos == share_name_start) {
        // No second slash or empty share name
        return -1;
    }

    // Extract share name
    size_t share_name_len = slash_pos - share_name_start;
    *share_name_out = malloc(share_name_len + 1);
    if (!*share_name_out) {
        return -1;
    }
    memcpy(*share_name_out, share_name_start, share_name_len);
    (*share_name_out)[share_name_len] = '\0';

    // Extract topic filter (everything after the second slash)
    const char *topic_start = slash_pos + 1;
    if (*topic_start == '\0') {
        // Empty topic filter
        free(*share_name_out);
        *share_name_out = NULL;
        return -1;
    }

    *topic_filter_out = strdup(topic_start);
    if (!*topic_filter_out) {
        free(*share_name_out);
        *share_name_out = NULL;
        return -1;
    }

    return 0;
}

// Validate shared subscription format
// Returns 1 if valid, 0 if invalid
int mqtt_validate_shared_subscription(const char *topic_filter) {
    if (!topic_filter) return 0;

    // Must start with "$share/"
    if (strncmp(topic_filter, "$share/", 7) != 0) {
        return 0;
    }

    // Find share name and topic filter parts
    const char *share_name_start = topic_filter + 7;
    const char *slash_pos = strchr(share_name_start, '/');

    if (!slash_pos) {
        return 0; // No second slash
    }

    if (slash_pos == share_name_start) {
        return 0; // Empty share name
    }

    if (*(slash_pos + 1) == '\0') {
        return 0; // Empty topic filter
    }

    // Check that share name doesn't contain wildcards
    for (const char *p = share_name_start; p < slash_pos; p++) {
        if (*p == '+' || *p == '#') {
            return 0; // Wildcards not allowed in share name
        }
    }

    return 1; // Valid
}

// =============================================================================
// MQTT Subprotocol Callbacks
// =============================================================================

void cwebsocket_subprotocol_mqtt_client_onopen(void *websocket) {
    cwebsocket_client *client = (cwebsocket_client *)websocket;
    mqtt_client_state *state = global_mqtt_state;

    MQTT_LOG_DEBUG( "cwebsocket_subprotocol_mqtt_client_onopen: fd=%i", client->fd);
    printf("WebSocket connected, sending MQTT CONNECT...\n");

    if (state) {
        mqtt_send_connect(
            client,
            state->client_id,
            state->username,
            state->password,
            state->keep_alive,
            state->clean_start
        );

        gettimeofday(&state->last_packet_sent, NULL);
        gettimeofday(&state->last_packet_received, NULL);
    }
}

void cwebsocket_subprotocol_mqtt_client_onmessage(void *websocket, cwebsocket_message *message) {
    cwebsocket_client *client = (cwebsocket_client *)websocket;
    mqtt_client_state *state = global_mqtt_state;

    if (message->opcode != BINARY_FRAME) {
        MQTT_LOG_WARN( "mqtt_client_onmessage: received non-binary frame, ignoring");
        return;
    }

    if (state) {
        gettimeofday(&state->last_packet_received, NULL);
    }

    // Decode MQTT packet
    mqtt_packet *packet = mqtt_packet_decode((const uint8_t *)message->payload, message->payload_len);
    if (!packet) {
        MQTT_LOG_ERROR( "mqtt_client_onmessage: failed to decode packet");
        return;
    }

    MQTT_LOG_DEBUG( "mqtt_client_onmessage: received %s packet",
           mqtt_packet_type_to_string(packet->header.type));

    switch (packet->header.type) {
        case MQTT_CONNACK: {
            if (packet->payload_len < 3) break;

            uint8_t connect_ack_flags = packet->payload[0];
            uint8_t reason_code = packet->payload[1];

            printf("\nMQTT CONNACK\n");
            printf("  Session Present: %s\n", (connect_ack_flags & 0x01) ? "yes" : "no");
            printf("  Reason Code: 0x%02X (%s)\n", reason_code, mqtt_reason_code_to_string(reason_code));

            // Parse CONNACK properties
            mqtt_property *connack_props = NULL;
            int props_consumed = 0;
            if (mqtt_decode_properties(packet->payload + 2, &connack_props, &props_consumed) == 0) {
                // Process each property and update client state
                mqtt_property *prop = connack_props;
                while (prop) {
                    switch (prop->id) {
                        case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
                            if (state) state->session_expiry_interval = prop->value.u32;
                            printf("  Session Expiry Interval: %u\n", prop->value.u32);
                            break;
                        case MQTT_PROP_RECEIVE_MAXIMUM:
                            if (state) state->server_receive_maximum = prop->value.u16;
                            printf("  Server Receive Maximum: %u\n", prop->value.u16);
                            break;
                        case MQTT_PROP_MAXIMUM_QOS:
                            if (state) state->maximum_qos = prop->value.byte;
                            printf("  Maximum QoS: %u\n", prop->value.byte);
                            break;
                        case MQTT_PROP_RETAIN_AVAILABLE:
                            if (state) state->retain_available = prop->value.byte;
                            printf("  Retain Available: %s\n", prop->value.byte ? "yes" : "no");
                            break;
                        case MQTT_PROP_MAXIMUM_PACKET_SIZE:
                            if (state) state->server_maximum_packet_size = prop->value.u32;
                            printf("  Maximum Packet Size: %u\n", prop->value.u32);
                            break;
                        case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
                            if (state) {
                                free(state->assigned_client_id);
                                state->assigned_client_id = strdup(prop->value.string);
                                if (!state->assigned_client_id) {
                                    MQTT_LOG_ERROR("mqtt_handle_connack: failed to allocate assigned_client_id");
                                }
                            }
                            printf("  Assigned Client ID: %s\n", prop->value.string);
                            break;
                        case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
                            if (state) state->server_topic_alias_maximum = prop->value.u16;
                            printf("  Server Topic Alias Maximum: %u\n", prop->value.u16);
                            break;
                        case MQTT_PROP_REASON_STRING:
                            printf("  Reason String: %s\n", prop->value.string);
                            break;
                        case MQTT_PROP_USER_PROPERTY:
                            printf("  User Property: %s = %s\n",
                                   prop->value.user_property.key,
                                   prop->value.user_property.value);
                            break;
                        case MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE:
                            if (state) state->wildcard_subscription_available = prop->value.byte;
                            printf("  Wildcard Subscriptions: %s\n", prop->value.byte ? "yes" : "no");
                            break;
                        case MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
                            if (state) state->subscription_identifier_available = prop->value.byte;
                            printf("  Subscription Identifiers: %s\n", prop->value.byte ? "yes" : "no");
                            break;
                        case MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE:
                            if (state) state->shared_subscription_available = prop->value.byte;
                            printf("  Shared Subscriptions: %s\n", prop->value.byte ? "yes" : "no");
                            break;
                        case MQTT_PROP_SERVER_KEEP_ALIVE:
                            if (state) state->keep_alive = prop->value.u16;
                            printf("  Server Keep Alive: %u\n", prop->value.u16);
                            break;
                        case MQTT_PROP_RESPONSE_INFORMATION:
                            printf("  Response Information: %s\n", prop->value.string);
                            break;
                        case MQTT_PROP_SERVER_REFERENCE:
                            printf("  Server Reference: %s\n", prop->value.string);
                            break;
                        case MQTT_PROP_AUTHENTICATION_METHOD:
                            printf("  Authentication Method: %s\n", prop->value.string);
                            break;
                        case MQTT_PROP_AUTHENTICATION_DATA:
                            printf("  Authentication Data: %u bytes\n", prop->value.binary.len);
                            break;
                    }
                    prop = prop->next;
                }
                mqtt_properties_free(connack_props);
            }

            if (reason_code == MQTT_RC_SUCCESS && state) {
                state->connected = 1;
                printf("  ✓ MQTT connection established\n");

                // Parse session_present flag
                uint8_t session_present = connect_ack_flags & 0x01;

                // Handle session restoration based on clean_start and session_present
                if (!state->clean_start && !session_present) {
                    // Server lost our session - restore from local persistence
                    MQTT_LOG_INFO("CONNACK: session not present, restoring from local persistence");

                    if (state->subscriptions) {
                        int resubscribed = mqtt_resubscribe_all(client, state);
                        if (resubscribed > 0) {
                            printf("  ↻ Resubscribed to %d topics\n", resubscribed);
                        }
                    }

                    if (state->pending_acks) {
                        int retransmitted = mqtt_retransmit_pending_messages(client, state);
                        if (retransmitted > 0) {
                            printf("  ↻ Retransmitted %d messages\n", retransmitted);
                        }
                    }
                } else if (!state->clean_start && session_present) {
                    // Server has our session - just retransmit our outgoing messages
                    MQTT_LOG_INFO("CONNACK: session present, resuming existing session");
                    printf("  ✓ Session resumed\n");

                    if (state->pending_acks) {
                        int retransmitted = mqtt_retransmit_pending_messages(client, state);
                        if (retransmitted > 0) {
                            printf("  ↻ Retransmitted %d pending messages\n", retransmitted);
                        }
                    }
                } else if (state->clean_start || !session_present) {
                    // Clean start or no session - delete old session
                    mqtt_delete_persisted_session(state);
                }

                // Save session state after successful CONNACK
                mqtt_persist_session(state);
            } else {
                printf("  ✗ Connection failed: %s\n", mqtt_reason_code_to_string(reason_code));
            }
            break;
        }

        case MQTT_PUBLISH: {
            // Parse topic and payload from packet
            if (packet->payload_len < 2) break;

            // Topic is at the start of payload
            uint16_t topic_len = (packet->payload[0] << 8) | packet->payload[1];
            if (packet->payload_len < 2 + topic_len) break;

            char *topic = malloc(topic_len + 1);
            if (!topic) break;
            memcpy(topic, packet->payload + 2, topic_len);
            topic[topic_len] = '\0';

            // QoS and flags
            uint8_t qos = (packet->header.flags >> 1) & 0x03;
            uint8_t retain = packet->header.flags & 0x01;
            uint8_t dup = (packet->header.flags >> 3) & 0x01;

            // Packet ID (if QoS > 0)
            uint16_t packet_id = 0;
            size_t payload_start = 2 + topic_len;

            if (qos > 0) {
                if (packet->payload_len < payload_start + 2) {
                    free(topic);
                    break;
                }
                packet_id = (packet->payload[payload_start] << 8) | packet->payload[payload_start + 1];
                payload_start += 2;
            }

            // Parse all PUBLISH properties
            uint16_t received_alias = 0;
            mqtt_property *publish_props = NULL;
            if (packet->payload_len > payload_start) {
                uint32_t prop_len;
                int vbi_len;
                if (mqtt_decode_variable_byte_integer(packet->payload + payload_start, &prop_len, &vbi_len) == 0) {
                    size_t props_start = payload_start + vbi_len;

                    // Decode all properties (will be passed to application)
                    int props_consumed = 0;
                    if (mqtt_decode_properties(packet->payload + props_start, &publish_props, &props_consumed) == 0) {
                        // Extract topic alias if present
                        mqtt_property *prop = publish_props;
                        while (prop) {
                            if (prop->id == MQTT_PROP_TOPIC_ALIAS) {
                                received_alias = prop->value.u16;
                                break;
                            }
                            prop = prop->next;
                        }
                    }

                    payload_start += vbi_len + prop_len;
                }
            }

            // If topic alias was received, resolve it
            const char *resolved_topic = topic;
            if (received_alias > 0) {
                if (topic_len > 0) {
                    // Topic + alias: server is establishing the mapping
                    if (state) {
                        mqtt_topic_alias_set(state, received_alias, topic);
                        MQTT_LOG_DEBUG( "mqtt_handle_publish: server set alias %u to topic '%s'",
                               received_alias, topic);
                    }
                } else {
                    // Empty topic + alias: server is using existing mapping
                    if (state) {
                        const char *aliased_topic = mqtt_topic_alias_lookup(state, received_alias);
                        if (aliased_topic) {
                            resolved_topic = aliased_topic;
                            MQTT_LOG_DEBUG( "mqtt_handle_publish: resolved alias %u to topic '%s'",
                                   received_alias, aliased_topic);
                        } else {
                            MQTT_LOG_ERROR( "mqtt_handle_publish: unknown topic alias %u", received_alias);
                            free(topic);
                            break;
                        }
                    }
                }
            }

            // Application payload
            size_t app_payload_len = packet->payload_len - payload_start;

            // Print debug information
            printf("\nMQTT PUBLISH\n");
            printf("  Topic: %s\n", resolved_topic);
            if (received_alias > 0) {
                printf("  Topic Alias: %u\n", received_alias);
            }
            if (packet_id > 0) printf("  Packet ID: %u\n", packet_id);
            if (app_payload_len > 0) {
                printf("  Payload (%zu bytes): %.*s\n", app_payload_len, (int)app_payload_len, packet->payload + payload_start);
            }

            // Call application callback if registered
            if (state && state->message_callback) {
                mqtt_message *msg = malloc(sizeof(mqtt_message));
                if (msg) {
                    msg->topic = strdup(resolved_topic);
                    msg->payload = packet->payload + payload_start;
                    msg->payload_len = app_payload_len;
                    msg->qos = qos;
                    msg->retain = retain;
                    msg->dup = dup;
                    msg->packet_id = packet_id;
                    msg->properties = publish_props;  // Transfer ownership to message
                    publish_props = NULL;  // Don't free below

                    // Invoke callback - application must free message and properties
                    state->message_callback(client, msg);
                }
            }

            // Send acknowledgment based on QoS
            if (qos == 1) {
                mqtt_send_puback(client, packet_id, MQTT_RC_SUCCESS);
            } else if (qos == 2) {
                mqtt_send_pubrec(client, packet_id, MQTT_RC_SUCCESS);
            }

            // Free properties if not transferred to callback
            if (publish_props) {
                mqtt_properties_free(publish_props);
            }
            free(topic);
            break;
        }

        case MQTT_PUBACK: {
            if (packet->payload_len >= 2) {
                uint16_t packet_id = (packet->payload[0] << 8) | packet->payload[1];
                uint8_t reason_code = packet->payload_len > 2 ? packet->payload[2] : MQTT_RC_SUCCESS;
                printf("\nMQTT PUBACK: packet_id=%u, reason=0x%02X\n", packet_id, reason_code);

                // Remove from persistence after successful acknowledgment
                if (reason_code == MQTT_RC_SUCCESS && state) {
                    mqtt_unpersist_message(state, packet_id);
                }
            }
            break;
        }

        case MQTT_PUBREC: {
            if (packet->payload_len >= 2) {
                uint16_t packet_id = (packet->payload[0] << 8) | packet->payload[1];
                uint8_t reason_code = packet->payload_len > 2 ? packet->payload[2] : MQTT_RC_SUCCESS;
                printf("\nMQTT PUBREC: packet_id=%u, reason=0x%02X\n", packet_id, reason_code);
                // Send PUBREL
                mqtt_send_pubrel(client, packet_id, MQTT_RC_SUCCESS);
            }
            break;
        }

        case MQTT_PUBREL: {
            if (packet->payload_len >= 2) {
                uint16_t packet_id = (packet->payload[0] << 8) | packet->payload[1];
                uint8_t reason_code = packet->payload_len > 2 ? packet->payload[2] : MQTT_RC_SUCCESS;
                printf("\nMQTT PUBREL: packet_id=%u, reason=0x%02X\n", packet_id, reason_code);
                // Send PUBCOMP
                mqtt_send_pubcomp(client, packet_id, MQTT_RC_SUCCESS);
            }
            break;
        }

        case MQTT_PUBCOMP: {
            if (packet->payload_len >= 2) {
                uint16_t packet_id = (packet->payload[0] << 8) | packet->payload[1];
                uint8_t reason_code = packet->payload_len > 2 ? packet->payload[2] : MQTT_RC_SUCCESS;
                printf("\nMQTT PUBCOMP: packet_id=%u, reason=0x%02X\n", packet_id, reason_code);

                // Remove from persistence after QoS 2 flow completes
                if (reason_code == MQTT_RC_SUCCESS && state) {
                    mqtt_unpersist_message(state, packet_id);
                }
            }
            break;
        }

        case MQTT_SUBACK: {
            if (packet->payload_len >= 3) {
                uint16_t packet_id = (packet->payload[0] << 8) | packet->payload[1];

                // Parse properties
                size_t pos = 2;
                uint32_t prop_len = 0;
                int vbi_len = 0;

                if (mqtt_decode_variable_byte_integer(packet->payload + pos, &prop_len, &vbi_len) == 0) {
                    pos += vbi_len + prop_len;
                }

                // Parse reason codes (one per subscription in the request)
                printf("\nMQTT SUBACK: packet_id=%u\n", packet_id);

                while (pos < packet->payload_len) {
                    uint8_t reason_code = packet->payload[pos++];

                    // Validate subscription result
                    if (reason_code <= MQTT_RC_GRANTED_QOS_2) {
                        // Success - QoS 0, 1, or 2 granted
                        printf("  ✓ Subscription granted: QoS %d\n", reason_code);
                    } else {
                        // Failure
                        printf("  ✗ Subscription failed: 0x%02X (%s)\n",
                               reason_code, mqtt_reason_code_to_string(reason_code));

                        // Remove failed subscription from list
                        mqtt_subscription *prev = NULL;
                        mqtt_subscription *curr = state ? state->subscriptions : NULL;
                        while (curr) {
                            mqtt_subscription *next = curr->next;
                            // In a real implementation, we would match by packet_id
                            // For now, we just log the failure
                            curr = next;
                        }
                    }
                }
            }

            // Persist updated subscription list
            if (state && state->persistence) {
                mqtt_persist_session(state);
            }
            break;
        }

        case MQTT_UNSUBACK: {
            if (packet->payload_len >= 3) {
                uint16_t packet_id = (packet->payload[0] << 8) | packet->payload[1];
                printf("\nMQTT UNSUBACK: packet_id=%u\n", packet_id);
            }
            break;
        }

        case MQTT_PINGRESP: {
            MQTT_LOG_DEBUG( "mqtt_client_onmessage: received PINGRESP");
            break;
        }

        case MQTT_DISCONNECT: {
            uint8_t reason_code = packet->payload_len > 0 ? packet->payload[0] : MQTT_RC_NORMAL_DISCONNECTION;
            printf("\nMQTT DISCONNECT: reason=0x%02X (%s)\n",
                   reason_code, mqtt_reason_code_to_string(reason_code));
            break;
        }

        case MQTT_AUTH: {
            // Parse AUTH packet
            if (packet->payload_len < 1) {
                MQTT_LOG_ERROR( "mqtt_client_onmessage: malformed AUTH packet");
                break;
            }

            size_t pos = 0;
            uint8_t reason_code = packet->payload[pos++];

            // Parse properties
            uint32_t prop_len = 0;
            int vbi_len = 0;
            if (pos < packet->payload_len) {
                if (mqtt_decode_variable_byte_integer(packet->payload + pos, &prop_len, &vbi_len) < 0) {
                    MQTT_LOG_ERROR( "mqtt_client_onmessage: failed to decode AUTH properties length");
                    break;
                }
                pos += vbi_len;
            }

            char *auth_method = NULL;
            uint8_t *auth_data = NULL;
            uint16_t auth_data_len = 0;
            char *reason_string = NULL;

            // Parse properties
            size_t prop_end = pos + prop_len;
            while (pos < prop_end && pos < packet->payload_len) {
                uint8_t prop_id = packet->payload[pos++];

                switch (prop_id) {
                    case MQTT_PROP_AUTHENTICATION_METHOD: {
                        int consumed = 0;
                        if (mqtt_decode_utf8_string(packet->payload + pos, &auth_method, &consumed) < 0) {
                            MQTT_LOG_ERROR( "mqtt_client_onmessage: failed to decode authentication method");
                        }
                        pos += consumed;
                        break;
                    }

                    case MQTT_PROP_AUTHENTICATION_DATA: {
                        int consumed = 0;
                        if (mqtt_decode_binary_data(packet->payload + pos, &auth_data, &auth_data_len, &consumed) < 0) {
                            MQTT_LOG_ERROR( "mqtt_client_onmessage: failed to decode authentication data");
                        }
                        pos += consumed;
                        break;
                    }

                    case MQTT_PROP_REASON_STRING: {
                        int consumed = 0;
                        if (mqtt_decode_utf8_string(packet->payload + pos, &reason_string, &consumed) < 0) {
                            MQTT_LOG_ERROR( "mqtt_client_onmessage: failed to decode reason string");
                        }
                        pos += consumed;
                        break;
                    }

                    case MQTT_PROP_USER_PROPERTY: {
                        // Skip user properties for now
                        char *key = NULL, *value = NULL;
                        int consumed = 0;
                        mqtt_decode_utf8_string(packet->payload + pos, &key, &consumed);
                        pos += consumed;
                        mqtt_decode_utf8_string(packet->payload + pos, &value, &consumed);
                        pos += consumed;
                        free(key);
                        free(value);
                        break;
                    }

                    default:
                        MQTT_LOG_WARN( "mqtt_client_onmessage: unknown AUTH property 0x%02X", prop_id);
                        // Skip unknown property - this is a simplified approach
                        // Production code should properly skip based on property type
                        break;
                }
            }

            printf("\nMQTT AUTH\n");
            printf("  Reason Code: 0x%02X (%s)\n", reason_code, mqtt_reason_code_to_string(reason_code));
            if (auth_method) {
                printf("  Authentication Method: %s\n", auth_method);
            }
            if (auth_data && auth_data_len > 0) {
                printf("  Authentication Data: %u bytes\n", auth_data_len);
            }
            if (reason_string) {
                printf("  Reason String: %s\n", reason_string);
            }

            // Handle authentication flow based on reason code
            if (reason_code == MQTT_RC_CONTINUE_AUTHENTICATION || reason_code == MQTT_RC_REAUTHENTICATE) {
                MQTT_LOG_DEBUG( "mqtt_client_onmessage: server requests %s",
                       reason_code == MQTT_RC_REAUTHENTICATE ? "re-authentication" : "continued authentication");

                // Invoke authentication callback if registered
                if (state && state->auth_callback) {
                    uint8_t *response_data = NULL;
                    size_t response_len = 0;

                    int result = state->auth_callback(
                        state,
                        auth_method ? auth_method : state->authentication_method,
                        auth_data,
                        auth_data_len,
                        &response_data,
                        &response_len
                    );

                    if (result > 0 && response_data) {
                        // Send AUTH response with authentication data
                        mqtt_send_auth(
                            client,
                            MQTT_RC_CONTINUE_AUTHENTICATION,
                            auth_method ? auth_method : state->authentication_method,
                            response_data,
                            response_len
                        );
                        free(response_data);
                    } else if (result == 0) {
                        // Continue authentication - callback handled it
                        MQTT_LOG_DEBUG( "mqtt_client_onmessage: authentication callback handled challenge");
                    } else {
                        // Authentication failed or aborted
                        MQTT_LOG_ERROR( "mqtt_client_onmessage: authentication callback failed");
                        mqtt_send_disconnect(client, MQTT_RC_NOT_AUTHORIZED, "Authentication failed");
                    }
                } else {
                    MQTT_LOG_WARN( "mqtt_client_onmessage: no authentication callback registered");
                    mqtt_send_disconnect(client, MQTT_RC_NOT_AUTHORIZED, "No authentication handler");
                }
            } else if (reason_code == MQTT_RC_SUCCESS) {
                MQTT_LOG_DEBUG( "mqtt_client_onmessage: authentication successful");
                if (state) {
                    state->auth_in_progress = 0;
                }
            } else {
                // Authentication failed
                MQTT_LOG_WARN( "mqtt_client_onmessage: authentication failed with reason 0x%02X (%s)",
                       reason_code, mqtt_reason_code_to_string(reason_code));
                if (state) {
                    state->auth_in_progress = 0;
                }
            }

            // Free allocated memory
            free(auth_method);
            free(auth_data);
            free(reason_string);
            break;
        }

        default:
            MQTT_LOG_WARN( "mqtt_client_onmessage: unhandled packet type %d", packet->header.type);
            break;
    }

    mqtt_packet_free(packet);
}

void cwebsocket_subprotocol_mqtt_client_onclose(void *websocket, int code, const char *reason) {
    cwebsocket_client *client = (cwebsocket_client *)websocket;
    mqtt_client_state *state = global_mqtt_state;

    MQTT_LOG_DEBUG( "cwebsocket_subprotocol_mqtt_client_onclose: fd=%i, code=%i", client->fd, code);
    printf("\nWebSocket closed: code=%d, reason=%s\n", code, reason ? reason : "none");

    // Persist final session state before closing
    if (state && state->persistence) {
        mqtt_persist_session(state);
    }

    // Cleanup persistence
    if (state && state->persistence) {
        if (state->persistence->cleanup) {
            state->persistence->cleanup(state->persistence);
        }
        free(state->persistence);
        state->persistence = NULL;
    }

    // Cleanup packet ID pool
    if (state && state->packet_id_pool) {
        mqtt_packet_id_pool_destroy(state->packet_id_pool);
        state->packet_id_pool = NULL;
    }

    // Clean up state
    if (state) {
        free(state->client_id);
        free(state->username);
        free(state->password);
        free(state->assigned_client_id);

        // Free will message
        free(state->will.topic);
        free(state->will.payload);
        mqtt_properties_free(state->will.properties);

        // Free subscriptions
        while (state->subscriptions) {
            mqtt_subscription *next = state->subscriptions->next;
            free(state->subscriptions->topic_filter);
            free(state->subscriptions->share_name);
            free(state->subscriptions);
            state->subscriptions = next;
        }

        // Free pending acks
        while (state->pending_acks) {
            mqtt_pending_ack *next = state->pending_acks->next;
            free(state->pending_acks->topic);
            free(state->pending_acks->payload);
            free(state->pending_acks);
            state->pending_acks = next;
        }

        // Free SCRAM authentication context if present
        if (state->auth_context && state->authentication_method &&
            strcmp(state->authentication_method, "SCRAM-SHA-256") == 0) {
            mqtt_scram_free((mqtt_scram_context *)state->auth_context);
            state->auth_context = NULL;
        }

        // Free authentication method
        free(state->authentication_method);

        mqtt_properties_free(state->connect_properties);

        free(state);
        global_mqtt_state = NULL;
    }
}

void cwebsocket_subprotocol_mqtt_client_onerror(void *websocket, const char *error) {
    cwebsocket_client *client = (cwebsocket_client *)websocket;
    MQTT_LOG_ERROR( "cwebsocket_subprotocol_mqtt_client_onerror: fd=%i, error=%s", client->fd, error);
    printf("WebSocket error: %s\n", error);
}


// =============================================================================
// Persistence API Implementation
// =============================================================================

void mqtt_client_set_persistence_strategy(
    cwebsocket_client *client,
    mqtt_persistence_strategy *strategy
) {
    mqtt_client_state *state = global_mqtt_state;
    if (!state) {
        MQTT_LOG_ERROR( "mqtt_client_set_persistence_strategy: no client state");
        return;
    }

    if (strategy && strategy->init) {
        if (strategy->init(strategy, state->client_id) < 0) {
            MQTT_LOG_ERROR( "mqtt_client_set_persistence_strategy: init failed");
            return;
        }
    }

    state->persistence = strategy;
    MQTT_LOG_INFO( "mqtt_client_set_persistence_strategy: strategy set to '%s'",
           strategy ? strategy->name : "none");
}

mqtt_persistence_strategy* mqtt_client_get_persistence_strategy(
    cwebsocket_client *client
) {
    mqtt_client_state *state = global_mqtt_state;
    return state ? state->persistence : NULL;
}

// =============================================================================
// Factory Function
// =============================================================================

cwebsocket_subprotocol* cwebsocket_subprotocol_mqtt_client_new(
    const char *client_id,
    const char *username,
    const char *password,
    uint8_t clean_start,
    uint16_t keep_alive
) {
    // Clean up any existing state
    if (global_mqtt_state) {
        MQTT_LOG_WARN( "Cleaning up existing MQTT state");
    }

    // Create new state
    global_mqtt_state = calloc(1, sizeof(mqtt_client_state));
    if (!global_mqtt_state) {
        MQTT_LOG_ERROR( "cwebsocket_subprotocol_mqtt_client_new: failed to allocate state");
        return NULL;
    }

    global_mqtt_state->client_id = client_id ? strdup(client_id) : strdup("cwebsocket_mqtt_client");
    if (!global_mqtt_state->client_id) {
        MQTT_LOG_ERROR("cwebsocket_subprotocol_mqtt_client_new: failed to allocate client_id");
        free(global_mqtt_state);
        global_mqtt_state = NULL;
        return NULL;
    }
    if (username) {
        global_mqtt_state->username = strdup(username);
        if (!global_mqtt_state->username) {
            MQTT_LOG_ERROR("cwebsocket_subprotocol_mqtt_client_new: failed to allocate username");
            free(global_mqtt_state->client_id);
            free(global_mqtt_state);
            global_mqtt_state = NULL;
            return NULL;
        }
    }
    if (password) {
        global_mqtt_state->password = strdup(password);
        if (!global_mqtt_state->password) {
            MQTT_LOG_ERROR("cwebsocket_subprotocol_mqtt_client_new: failed to allocate password");
            free(global_mqtt_state->username);
            free(global_mqtt_state->client_id);
            free(global_mqtt_state);
            global_mqtt_state = NULL;
            return NULL;
        }
    }
    global_mqtt_state->protocol_version = MQTT_VERSION_5_0;
    global_mqtt_state->keep_alive = keep_alive;
    global_mqtt_state->clean_start = clean_start;
    global_mqtt_state->connected = 0;
    global_mqtt_state->next_packet_id = 1;  // Deprecated - kept for compatibility

    // Initialize robust packet ID pool
    global_mqtt_state->packet_id_pool = mqtt_packet_id_pool_create();
    if (!global_mqtt_state->packet_id_pool) {
        MQTT_LOG_ERROR( "cwebsocket_subprotocol_mqtt_client_new: failed to create packet ID pool");
        free(global_mqtt_state->client_id);
        free(global_mqtt_state->username);
        free(global_mqtt_state->password);
        free(global_mqtt_state);
        global_mqtt_state = NULL;
        return NULL;
    }

    // Initialize default memory-based persistence
    global_mqtt_state->persistence = mqtt_persistence_memory_create();
    if (!global_mqtt_state->persistence) {
        MQTT_LOG_WARN( "Failed to create default persistence strategy");
    }

    // Set default MQTT 5.0 property values
    global_mqtt_state->session_expiry_interval = 0;  // Session ends on disconnect by default
    global_mqtt_state->receive_maximum = 65535;      // Default: unlimited
    global_mqtt_state->maximum_packet_size = 0;      // 0 = no limit (use server's limit)
    global_mqtt_state->topic_alias_maximum = 0;      // Default: no topic aliases
    global_mqtt_state->maximum_qos = 2;              // Support QoS 0, 1, 2
    global_mqtt_state->retain_available = 1;         // Assume retained messages supported

    // Set default subscription restriction values (MQTT 5.0 spec defaults to true if not specified)
    global_mqtt_state->wildcard_subscription_available = 1;      // Default: wildcards supported
    global_mqtt_state->subscription_identifier_available = 1;    // Default: subscription IDs supported
    global_mqtt_state->shared_subscription_available = 1;        // Default: shared subscriptions supported

    cwebsocket_subprotocol *protocol = malloc(sizeof(cwebsocket_subprotocol));
    if (!protocol) {
        MQTT_LOG_ERROR( "cwebsocket_subprotocol_mqtt_client_new: failed to allocate protocol");
        free(global_mqtt_state->client_id);
        free(global_mqtt_state->username);
        free(global_mqtt_state->password);
        free(global_mqtt_state);
        global_mqtt_state = NULL;
        return NULL;
    }

    memset(protocol, 0, sizeof(cwebsocket_subprotocol));
    protocol->name = "mqtt";  // MQTT 5.0 uses "mqtt" subprotocol
    protocol->onopen = &cwebsocket_subprotocol_mqtt_client_onopen;
    protocol->onmessage = &cwebsocket_subprotocol_mqtt_client_onmessage;
    protocol->onclose = &cwebsocket_subprotocol_mqtt_client_onclose;
    protocol->onerror = &cwebsocket_subprotocol_mqtt_client_onerror;

    return protocol;
}
// =============================================================================
// Flow Control Functions
// =============================================================================

// Check if we can send a QoS 1/2 message based on Receive Maximum
int mqtt_can_send_qos_message(mqtt_client_state *state) {
    if (!state) return 0;

    // If server_receive_maximum is 0, it means no limit was set (default: 65535)
    if (state->server_receive_maximum == 0) {
        return 1;
    }

    // Check if we have room for another in-flight message
    return state->in_flight_qos_count < state->server_receive_maximum;
}

// Increment in-flight QoS message counter
void mqtt_increment_in_flight(mqtt_client_state *state) {
    if (!state) return;
    state->in_flight_qos_count++;
    MQTT_LOG_DEBUG( "mqtt_increment_in_flight: in-flight count now %u (max %u)",
           state->in_flight_qos_count, state->server_receive_maximum);
}

// Decrement in-flight QoS message counter
void mqtt_decrement_in_flight(mqtt_client_state *state) {
    if (!state) return;
    if (state->in_flight_qos_count > 0) {
        state->in_flight_qos_count--;
        MQTT_LOG_DEBUG( "mqtt_decrement_in_flight: in-flight count now %u (max %u)",
               state->in_flight_qos_count, state->server_receive_maximum);
    }
}

// Validate packet size against server's maximum
int mqtt_validate_packet_size(mqtt_client_state *state, size_t packet_size) {
    if (!state) return 1;

    // If server_maximum_packet_size is 0, it means no limit was set
    if (state->server_maximum_packet_size == 0) {
        return 1;
    }

    // Check if packet size exceeds server limit
    if (packet_size > state->server_maximum_packet_size) {
        MQTT_LOG_ERROR( "mqtt_validate_packet_size: packet size %zu exceeds maximum %u",
               packet_size, state->server_maximum_packet_size);
        return 0;
    }

    return 1;
}

// =============================================================================
// Topic Alias Functions
// =============================================================================

// Get or create topic alias for a topic
uint16_t mqtt_topic_alias_get(mqtt_client_state *state, const char *topic) {
    if (!state || !topic) return 0;

    // Check if server supports topic aliases
    if (state->server_topic_alias_maximum == 0) {
        return 0;  // No alias support
    }

    // Search for existing alias
    mqtt_topic_alias *current = state->topic_aliases;
    while (current) {
        if (strcmp(current->topic, topic) == 0) {
            return current->alias;
        }
        current = current->next;
    }

    // If we haven't allocated maximum aliases yet, create a new one
    if (state->next_topic_alias <= state->server_topic_alias_maximum) {
        uint16_t new_alias = state->next_topic_alias++;
        if (mqtt_topic_alias_set(state, new_alias, topic) == 0) {
            return new_alias;
        }
    }

    return 0;  // No alias available
}

// Set topic alias mapping
int mqtt_topic_alias_set(mqtt_client_state *state, uint16_t alias, const char *topic) {
    if (!state || !topic || alias == 0) return -1;

    // Validate alias is within allowed range
    if (state->server_topic_alias_maximum > 0 && alias > state->server_topic_alias_maximum) {
        MQTT_LOG_ERROR( "mqtt_topic_alias_set: alias %u exceeds maximum %u",
               alias, state->server_topic_alias_maximum);
        return -1;
    }

    // Check if alias already exists - if so, update it
    mqtt_topic_alias *current = state->topic_aliases;
    while (current) {
        if (current->alias == alias) {
            free(current->topic);
            current->topic = strdup(topic);
            if (!current->topic) {
                MQTT_LOG_ERROR( "mqtt_topic_alias_set: failed to allocate topic");
                return -1;
            }
            return 0;
        }
        current = current->next;
    }

    // Create new alias entry
    mqtt_topic_alias *new_alias = calloc(1, sizeof(mqtt_topic_alias));
    if (!new_alias) {
        MQTT_LOG_ERROR( "mqtt_topic_alias_set: failed to allocate alias entry");
        return -1;
    }

    new_alias->alias = alias;
    new_alias->topic = strdup(topic);
    if (!new_alias->topic) {
        free(new_alias);
        MQTT_LOG_ERROR( "mqtt_topic_alias_set: failed to allocate topic");
        return -1;
    }

    // Add to front of list
    new_alias->next = state->topic_aliases;
    state->topic_aliases = new_alias;

    MQTT_LOG_DEBUG( "mqtt_topic_alias_set: mapped alias %u to topic '%s'", alias, topic);
    return 0;
}

// Lookup topic by alias
const char* mqtt_topic_alias_lookup(mqtt_client_state *state, uint16_t alias) {
    if (!state || alias == 0) return NULL;

    mqtt_topic_alias *current = state->topic_aliases;
    while (current) {
        if (current->alias == alias) {
            return current->topic;
        }
        current = current->next;
    }

    return NULL;
}

// Free all topic alias mappings
void mqtt_topic_alias_free_all(mqtt_client_state *state) {
    if (!state) return;

    while (state->topic_aliases) {
        mqtt_topic_alias *next = state->topic_aliases->next;
        free(state->topic_aliases->topic);
        free(state->topic_aliases);
        state->topic_aliases = next;
    }

    state->next_topic_alias = 1;
}
