/**
 *  Robust MQTT Packet ID Pool Implementation
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// =============================================================================
// Packet ID Pool Management (Robust Implementation)
// =============================================================================

/**
 * Create a new packet ID pool
 * Initializes bitmap to all zeros (all IDs available)
 * Returns: newly allocated pool or NULL on error
 */
mqtt_packet_id_pool* mqtt_packet_id_pool_create(void) {
    mqtt_packet_id_pool *pool = calloc(1, sizeof(mqtt_packet_id_pool));
    if (!pool) {
        syslog(LOG_ERR, "mqtt_packet_id_pool_create: failed to allocate pool");
        return NULL;
    }

    // Initialize bitmap to all zeros (all IDs available)
    memset(pool->bitmap, 0, sizeof(pool->bitmap));
    pool->last_allocated = 0;
    pool->in_use_count = 0;

    syslog(LOG_DEBUG, "mqtt_packet_id_pool_create: created pool with capacity %d IDs", MQTT_PACKET_ID_MAX);
    return pool;
}

/**
 * Destroy a packet ID pool
 * Frees all resources
 */
void mqtt_packet_id_pool_destroy(mqtt_packet_id_pool *pool) {
    if (!pool) return;

    if (pool->in_use_count > 0) {
        syslog(LOG_WARNING, "mqtt_packet_id_pool_destroy: destroying pool with %u IDs still in use",
               pool->in_use_count);
    }

    free(pool);
}

/**
 * Allocate a packet ID from the pool
 * Uses round-robin search starting from last allocated ID to avoid hotspots
 * Returns: allocated packet ID (1-65535) or 0 if pool is exhausted
 */
uint16_t mqtt_packet_id_pool_allocate(mqtt_packet_id_pool *pool) {
    if (!pool) {
        syslog(LOG_ERR, "mqtt_packet_id_pool_allocate: NULL pool");
        return 0;
    }

    // Check if pool is exhausted
    if (pool->in_use_count >= MQTT_PACKET_ID_MAX) {
        syslog(LOG_ERR, "mqtt_packet_id_pool_allocate: pool exhausted (all %u IDs in use)",
               MQTT_PACKET_ID_MAX);
        return 0;
    }

    // Start search from next ID after last allocated (round-robin)
    uint16_t start_id = pool->last_allocated;
    uint16_t current_id = start_id;

    // Search for available ID
    do {
        current_id++;
        if (current_id == 0 || current_id > MQTT_PACKET_ID_MAX) {
            current_id = 1;  // Wrap around (ID 0 is reserved)
        }

        // Check if this ID is available
        uint16_t bitmap_index = (current_id - 1) / 64;  // Which 64-bit chunk
        uint16_t bit_offset = (current_id - 1) % 64;    // Which bit in chunk
        uint64_t mask = (uint64_t)1 << bit_offset;

        if (!(pool->bitmap[bitmap_index] & mask)) {
            // ID is available - allocate it
            pool->bitmap[bitmap_index] |= mask;
            pool->last_allocated = current_id;
            pool->in_use_count++;

            syslog(LOG_DEBUG, "mqtt_packet_id_pool_allocate: allocated ID %u (%u/%u in use)",
                   current_id, pool->in_use_count, MQTT_PACKET_ID_MAX);
            return current_id;
        }

        // ID is in use - continue search
    } while (current_id != start_id);

    // Should never reach here (we checked pool exhaustion above)
    syslog(LOG_ERR, "mqtt_packet_id_pool_allocate: unexpected exhaustion");
    return 0;
}

/**
 * Release a packet ID back to the pool
 * Makes the ID available for reuse
 * Returns: 0 on success, -1 on error
 */
int mqtt_packet_id_pool_release(mqtt_packet_id_pool *pool, uint16_t packet_id) {
    if (!pool) {
        syslog(LOG_ERR, "mqtt_packet_id_pool_release: NULL pool");
        return -1;
    }

    if (packet_id == 0 || packet_id > MQTT_PACKET_ID_MAX) {
        syslog(LOG_ERR, "mqtt_packet_id_pool_release: invalid packet ID %u", packet_id);
        return -1;
    }

    uint16_t bitmap_index = (packet_id - 1) / 64;
    uint16_t bit_offset = (packet_id - 1) % 64;
    uint64_t mask = (uint64_t)1 << bit_offset;

    // Check if ID was actually in use
    if (!(pool->bitmap[bitmap_index] & mask)) {
        syslog(LOG_WARNING, "mqtt_packet_id_pool_release: attempting to release ID %u that was not in use",
               packet_id);
        return -1;
    }

    // Release the ID
    pool->bitmap[bitmap_index] &= ~mask;
    pool->in_use_count--;

    syslog(LOG_DEBUG, "mqtt_packet_id_pool_release: released ID %u (%u/%u in use)",
           packet_id, pool->in_use_count, MQTT_PACKET_ID_MAX);
    return 0;
}

/**
 * Check if a packet ID is currently in use
 * Returns: 1 if in use, 0 if available, -1 on error
 */
int mqtt_packet_id_pool_is_in_use(mqtt_packet_id_pool *pool, uint16_t packet_id) {
    if (!pool) {
        syslog(LOG_ERR, "mqtt_packet_id_pool_is_in_use: NULL pool");
        return -1;
    }

    if (packet_id == 0 || packet_id > MQTT_PACKET_ID_MAX) {
        syslog(LOG_ERR, "mqtt_packet_id_pool_is_in_use: invalid packet ID %u", packet_id);
        return -1;
    }

    uint16_t bitmap_index = (packet_id - 1) / 64;
    uint16_t bit_offset = (packet_id - 1) % 64;
    uint64_t mask = (uint64_t)1 << bit_offset;

    return (pool->bitmap[bitmap_index] & mask) ? 1 : 0;
}

/**
 * Get the number of packet IDs currently in use
 * Returns: number of IDs in use
 */
uint16_t mqtt_packet_id_pool_get_in_use_count(mqtt_packet_id_pool *pool) {
    if (!pool) {
        syslog(LOG_ERR, "mqtt_packet_id_pool_get_in_use_count: NULL pool");
        return 0;
    }

    return pool->in_use_count;
}
