/**
 *  MQTT Session Persistence Strategy Interface
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

#ifndef MQTT_PERSISTENCE_H_
#define MQTT_PERSISTENCE_H_

#include <stdint.h>
#include <stdlib.h>
#include "mqtt_client.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct mqtt_persistence_strategy mqtt_persistence_strategy;
typedef struct mqtt_persisted_session mqtt_persisted_session;

/**
 * Persisted message structure for QoS 1 and 2
 */
typedef struct mqtt_persisted_message {
    uint16_t packet_id;
    mqtt_packet_type packet_type;
    mqtt_qos qos;
    char *topic;
    uint8_t *payload;
    size_t payload_len;
    uint8_t retain;
    uint8_t dup;
    uint32_t timestamp;
    int retry_count;
    struct mqtt_persisted_message *next;
} mqtt_persisted_message;

/**
 * Persisted subscription structure
 */
typedef struct mqtt_persisted_subscription {
    char *topic_filter;
    mqtt_qos qos;
    uint8_t no_local;
    uint8_t retain_as_published;
    uint8_t retain_handling;
    struct mqtt_persisted_subscription *next;
} mqtt_persisted_subscription;

/**
 * Complete persisted session state
 */
typedef struct mqtt_persisted_session {
    // Session identifier
    char *client_id;

    // Session expiry
    uint32_t session_expiry_interval;
    uint32_t session_created;
    uint32_t session_last_accessed;

    // Subscriptions
    mqtt_persisted_subscription *subscriptions;

    // QoS 1 and 2 messages pending acknowledgment
    mqtt_persisted_message *pending_publish;     // Messages we sent, awaiting ack
    mqtt_persisted_message *pending_receive;     // Messages we received, need to ack

    // Packet ID state
    uint16_t next_packet_id;
} mqtt_persisted_session;

/**
 * Persistence strategy interface
 *
 * Implementations provide storage mechanisms for MQTT session state.
 * All methods return 0 on success, -1 on error.
 */
struct mqtt_persistence_strategy {
    const char *name;
    void *context;  // Strategy-specific context

    /**
     * Initialize the persistence strategy
     */
    int (*init)(mqtt_persistence_strategy *strategy, const char *client_id);

    /**
     * Save session state
     */
    int (*save_session)(mqtt_persistence_strategy *strategy,
                       const mqtt_persisted_session *session);

    /**
     * Load session state
     * Returns NULL if no session exists
     */
    mqtt_persisted_session* (*load_session)(mqtt_persistence_strategy *strategy,
                                           const char *client_id);

    /**
     * Delete session state
     */
    int (*delete_session)(mqtt_persistence_strategy *strategy,
                         const char *client_id);

    /**
     * Add a pending message (QoS 1/2)
     */
    int (*add_pending_message)(mqtt_persistence_strategy *strategy,
                              const char *client_id,
                              const mqtt_persisted_message *message);

    /**
     * Remove a pending message (after acknowledgment)
     */
    int (*remove_pending_message)(mqtt_persistence_strategy *strategy,
                                 const char *client_id,
                                 uint16_t packet_id);

    /**
     * Cleanup and shutdown
     */
    int (*cleanup)(mqtt_persistence_strategy *strategy);
};

// =============================================================================
// Memory-based Persistence (default, non-persistent across restarts)
// =============================================================================

/**
 * Create memory-based persistence strategy
 * Session state is kept in RAM only, lost on process termination
 */
mqtt_persistence_strategy* mqtt_persistence_memory_create(void);

// =============================================================================
// File-based Persistence (persists to local filesystem)
// =============================================================================

/**
 * Create file-based persistence strategy
 * Session state is persisted to files in the specified directory
 *
 * @param base_path Directory to store session files (e.g., "/var/lib/mqtt/sessions")
 */
mqtt_persistence_strategy* mqtt_persistence_file_create(const char *base_path);

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Free a persisted session structure
 */
void mqtt_persisted_session_free(mqtt_persisted_session *session);

/**
 * Create a persisted message from current state
 */
mqtt_persisted_message* mqtt_persisted_message_create(
    uint16_t packet_id,
    mqtt_packet_type packet_type,
    mqtt_qos qos,
    const char *topic,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t retain,
    uint8_t dup
);

/**
 * Free a persisted message
 */
void mqtt_persisted_message_free(mqtt_persisted_message *msg);

#ifdef __cplusplus
}
#endif

#endif // MQTT_PERSISTENCE_H_
