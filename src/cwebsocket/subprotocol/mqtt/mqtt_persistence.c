/**
 *  MQTT Session Persistence Strategy Implementations
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

#include "mqtt_persistence.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

// =============================================================================
// Utility Functions
// =============================================================================

mqtt_persisted_message* mqtt_persisted_message_create(
    uint16_t packet_id,
    mqtt_packet_type packet_type,
    mqtt_qos qos,
    const char *topic,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t retain,
    uint8_t dup
) {
    mqtt_persisted_message *msg = calloc(1, sizeof(mqtt_persisted_message));
    if (!msg) return NULL;

    msg->packet_id = packet_id;
    msg->packet_type = packet_type;
    msg->qos = qos;
    msg->retain = retain;
    msg->dup = dup;
    msg->timestamp = (uint32_t)time(NULL);
    msg->retry_count = 0;

    if (topic) {
        msg->topic = strdup(topic);
    }

    if (payload && payload_len > 0) {
        msg->payload = malloc(payload_len);
        if (msg->payload) {
            memcpy(msg->payload, payload, payload_len);
            msg->payload_len = payload_len;
        }
    }

    return msg;
}

void mqtt_persisted_message_free(mqtt_persisted_message *msg) {
    if (!msg) return;
    free(msg->topic);
    free(msg->payload);
    free(msg);
}

void mqtt_persisted_session_free(mqtt_persisted_session *session) {
    if (!session) return;

    free(session->client_id);

    // Free subscriptions
    while (session->subscriptions) {
        mqtt_persisted_subscription *next = session->subscriptions->next;
        free(session->subscriptions->topic_filter);
        free(session->subscriptions);
        session->subscriptions = next;
    }

    // Free pending publish messages
    while (session->pending_publish) {
        mqtt_persisted_message *next = session->pending_publish->next;
        mqtt_persisted_message_free(session->pending_publish);
        session->pending_publish = next;
    }

    // Free pending receive messages
    while (session->pending_receive) {
        mqtt_persisted_message *next = session->pending_receive->next;
        mqtt_persisted_message_free(session->pending_receive);
        session->pending_receive = next;
    }

    free(session);
}

// =============================================================================
// Memory-based Persistence Implementation
// =============================================================================

typedef struct memory_persistence_context {
    mqtt_persisted_session *session;
} memory_persistence_context;

static int memory_persistence_init(mqtt_persistence_strategy *strategy, const char *client_id) {
    memory_persistence_context *ctx = (memory_persistence_context *)strategy->context;
    if (!ctx) {
        ctx = calloc(1, sizeof(memory_persistence_context));
        if (!ctx) return -1;
        strategy->context = ctx;
    }
    return 0;
}

static int memory_persistence_save_session(
    mqtt_persistence_strategy *strategy,
    const mqtt_persisted_session *session
) {
    memory_persistence_context *ctx = (memory_persistence_context *)strategy->context;
    if (!ctx) return -1;

    // Free existing session
    if (ctx->session) {
        mqtt_persisted_session_free(ctx->session);
    }

    // Deep copy the session
    ctx->session = calloc(1, sizeof(mqtt_persisted_session));
    if (!ctx->session) return -1;

    ctx->session->client_id = session->client_id ? strdup(session->client_id) : NULL;
    ctx->session->session_expiry_interval = session->session_expiry_interval;
    ctx->session->session_created = session->session_created;
    ctx->session->session_last_accessed = session->session_last_accessed;
    ctx->session->next_packet_id = session->next_packet_id;

    // Copy subscriptions
    mqtt_persisted_subscription *sub_src = session->subscriptions;
    mqtt_persisted_subscription **sub_dst = &ctx->session->subscriptions;
    while (sub_src) {
        *sub_dst = calloc(1, sizeof(mqtt_persisted_subscription));
        if (!*sub_dst) return -1;

        (*sub_dst)->topic_filter = sub_src->topic_filter ? strdup(sub_src->topic_filter) : NULL;
        (*sub_dst)->qos = sub_src->qos;
        (*sub_dst)->no_local = sub_src->no_local;
        (*sub_dst)->retain_as_published = sub_src->retain_as_published;
        (*sub_dst)->retain_handling = sub_src->retain_handling;

        sub_dst = &(*sub_dst)->next;
        sub_src = sub_src->next;
    }

    // Copy pending publish messages
    mqtt_persisted_message *msg_src = session->pending_publish;
    mqtt_persisted_message **msg_dst = &ctx->session->pending_publish;
    while (msg_src) {
        *msg_dst = mqtt_persisted_message_create(
            msg_src->packet_id, msg_src->packet_type, msg_src->qos,
            msg_src->topic, msg_src->payload, msg_src->payload_len,
            msg_src->retain, msg_src->dup
        );
        if (!*msg_dst) return -1;
        (*msg_dst)->timestamp = msg_src->timestamp;
        (*msg_dst)->retry_count = msg_src->retry_count;

        msg_dst = &(*msg_dst)->next;
        msg_src = msg_src->next;
    }

    // Copy pending receive messages
    msg_src = session->pending_receive;
    msg_dst = &ctx->session->pending_receive;
    while (msg_src) {
        *msg_dst = mqtt_persisted_message_create(
            msg_src->packet_id, msg_src->packet_type, msg_src->qos,
            msg_src->topic, msg_src->payload, msg_src->payload_len,
            msg_src->retain, msg_src->dup
        );
        if (!*msg_dst) return -1;
        (*msg_dst)->timestamp = msg_src->timestamp;
        (*msg_dst)->retry_count = msg_src->retry_count;

        msg_dst = &(*msg_dst)->next;
        msg_src = msg_src->next;
    }

    syslog(LOG_DEBUG, "memory_persistence: saved session for client %s", session->client_id);
    return 0;
}

static mqtt_persisted_session* memory_persistence_load_session(
    mqtt_persistence_strategy *strategy,
    const char *client_id
) {
    memory_persistence_context *ctx = (memory_persistence_context *)strategy->context;
    if (!ctx || !ctx->session) return NULL;

    // Check if client_id matches
    if (!ctx->session->client_id || strcmp(ctx->session->client_id, client_id) != 0) {
        return NULL;
    }

    // Check session expiry
    uint32_t now = (uint32_t)time(NULL);
    if (ctx->session->session_expiry_interval > 0) {
        uint32_t elapsed = now - ctx->session->session_last_accessed;
        if (elapsed > ctx->session->session_expiry_interval) {
            syslog(LOG_INFO, "memory_persistence: session expired for client %s", client_id);
            mqtt_persisted_session_free(ctx->session);
            ctx->session = NULL;
            return NULL;
        }
    }

    // Update last accessed time
    ctx->session->session_last_accessed = now;

    syslog(LOG_DEBUG, "memory_persistence: loaded session for client %s", client_id);
    return ctx->session;
}

static int memory_persistence_delete_session(
    mqtt_persistence_strategy *strategy,
    const char *client_id
) {
    memory_persistence_context *ctx = (memory_persistence_context *)strategy->context;
    if (!ctx) return -1;

    if (ctx->session) {
        mqtt_persisted_session_free(ctx->session);
        ctx->session = NULL;
    }

    syslog(LOG_DEBUG, "memory_persistence: deleted session for client %s", client_id);
    return 0;
}

static int memory_persistence_add_pending_message(
    mqtt_persistence_strategy *strategy,
    const char *client_id,
    const mqtt_persisted_message *message
) {
    memory_persistence_context *ctx = (memory_persistence_context *)strategy->context;
    if (!ctx || !ctx->session) return -1;

    mqtt_persisted_message *new_msg = mqtt_persisted_message_create(
        message->packet_id, message->packet_type, message->qos,
        message->topic, message->payload, message->payload_len,
        message->retain, message->dup
    );
    if (!new_msg) return -1;

    // Add to pending_publish list
    new_msg->next = ctx->session->pending_publish;
    ctx->session->pending_publish = new_msg;

    return 0;
}

static int memory_persistence_remove_pending_message(
    mqtt_persistence_strategy *strategy,
    const char *client_id,
    uint16_t packet_id
) {
    memory_persistence_context *ctx = (memory_persistence_context *)strategy->context;
    if (!ctx || !ctx->session) return -1;

    // Remove from pending_publish
    mqtt_persisted_message **current = &ctx->session->pending_publish;
    while (*current) {
        if ((*current)->packet_id == packet_id) {
            mqtt_persisted_message *to_remove = *current;
            *current = to_remove->next;
            mqtt_persisted_message_free(to_remove);
            return 0;
        }
        current = &(*current)->next;
    }

    // Remove from pending_receive
    current = &ctx->session->pending_receive;
    while (*current) {
        if ((*current)->packet_id == packet_id) {
            mqtt_persisted_message *to_remove = *current;
            *current = to_remove->next;
            mqtt_persisted_message_free(to_remove);
            return 0;
        }
        current = &(*current)->next;
    }

    return -1;
}

static int memory_persistence_cleanup(mqtt_persistence_strategy *strategy) {
    memory_persistence_context *ctx = (memory_persistence_context *)strategy->context;
    if (ctx) {
        if (ctx->session) {
            mqtt_persisted_session_free(ctx->session);
        }
        free(ctx);
        strategy->context = NULL;
    }
    return 0;
}

mqtt_persistence_strategy* mqtt_persistence_memory_create(void) {
    mqtt_persistence_strategy *strategy = calloc(1, sizeof(mqtt_persistence_strategy));
    if (!strategy) return NULL;

    strategy->name = "memory";
    strategy->init = memory_persistence_init;
    strategy->save_session = memory_persistence_save_session;
    strategy->load_session = memory_persistence_load_session;
    strategy->delete_session = memory_persistence_delete_session;
    strategy->add_pending_message = memory_persistence_add_pending_message;
    strategy->remove_pending_message = memory_persistence_remove_pending_message;
    strategy->cleanup = memory_persistence_cleanup;

    return strategy;
}

// =============================================================================
// File-based Persistence Implementation
// =============================================================================

typedef struct file_persistence_context {
    char *base_path;
} file_persistence_context;

static char* file_persistence_get_session_path(const char *base_path, const char *client_id) {
    size_t path_len = strlen(base_path) + strlen(client_id) + 20;
    char *path = malloc(path_len);
    if (!path) return NULL;
    snprintf(path, path_len, "%s/%s.session", base_path, client_id);
    return path;
}

static int file_persistence_init(mqtt_persistence_strategy *strategy, const char *client_id) {
    file_persistence_context *ctx = (file_persistence_context *)strategy->context;
    if (!ctx) return -1;

    // Create base directory if it doesn't exist
    struct stat st = {0};
    if (stat(ctx->base_path, &st) == -1) {
        if (mkdir(ctx->base_path, 0700) == -1) {
            syslog(LOG_ERR, "file_persistence: failed to create directory %s: %s",
                   ctx->base_path, strerror(errno));
            return -1;
        }
    }

    return 0;
}

static int file_persistence_save_session(
    mqtt_persistence_strategy *strategy,
    const mqtt_persisted_session *session
) {
    file_persistence_context *ctx = (file_persistence_context *)strategy->context;
    if (!ctx || !session || !session->client_id) return -1;

    char *path = file_persistence_get_session_path(ctx->base_path, session->client_id);
    if (!path) return -1;

    FILE *fp = fopen(path, "wb");
    free(path);

    if (!fp) {
        syslog(LOG_ERR, "file_persistence: failed to open file for writing");
        return -1;
    }

    // Write session metadata
    fwrite(&session->session_expiry_interval, sizeof(uint32_t), 1, fp);
    fwrite(&session->session_created, sizeof(uint32_t), 1, fp);
    fwrite(&session->session_last_accessed, sizeof(uint32_t), 1, fp);
    fwrite(&session->next_packet_id, sizeof(uint16_t), 1, fp);

    // Write client ID
    uint16_t client_id_len = strlen(session->client_id);
    fwrite(&client_id_len, sizeof(uint16_t), 1, fp);
    fwrite(session->client_id, 1, client_id_len, fp);

    // Write subscriptions count and data
    uint16_t sub_count = 0;
    mqtt_persisted_subscription *sub = session->subscriptions;
    while (sub) {
        sub_count++;
        sub = sub->next;
    }
    fwrite(&sub_count, sizeof(uint16_t), 1, fp);

    sub = session->subscriptions;
    while (sub) {
        uint16_t topic_len = strlen(sub->topic_filter);
        fwrite(&topic_len, sizeof(uint16_t), 1, fp);
        fwrite(sub->topic_filter, 1, topic_len, fp);
        fwrite(&sub->qos, sizeof(uint8_t), 1, fp);
        fwrite(&sub->no_local, sizeof(uint8_t), 1, fp);
        fwrite(&sub->retain_as_published, sizeof(uint8_t), 1, fp);
        fwrite(&sub->retain_handling, sizeof(uint8_t), 1, fp);
        sub = sub->next;
    }

    // Write pending messages count and data
    uint16_t pending_count = 0;
    mqtt_persisted_message *msg = session->pending_publish;
    while (msg) {
        pending_count++;
        msg = msg->next;
    }
    fwrite(&pending_count, sizeof(uint16_t), 1, fp);

    msg = session->pending_publish;
    while (msg) {
        fwrite(&msg->packet_id, sizeof(uint16_t), 1, fp);
        fwrite(&msg->packet_type, sizeof(uint8_t), 1, fp);
        fwrite(&msg->qos, sizeof(uint8_t), 1, fp);
        fwrite(&msg->retain, sizeof(uint8_t), 1, fp);
        fwrite(&msg->dup, sizeof(uint8_t), 1, fp);
        fwrite(&msg->timestamp, sizeof(uint32_t), 1, fp);
        fwrite(&msg->retry_count, sizeof(int), 1, fp);

        uint16_t topic_len = msg->topic ? strlen(msg->topic) : 0;
        fwrite(&topic_len, sizeof(uint16_t), 1, fp);
        if (topic_len > 0) {
            fwrite(msg->topic, 1, topic_len, fp);
        }

        fwrite(&msg->payload_len, sizeof(size_t), 1, fp);
        if (msg->payload_len > 0) {
            fwrite(msg->payload, 1, msg->payload_len, fp);
        }

        msg = msg->next;
    }

    fclose(fp);
    syslog(LOG_DEBUG, "file_persistence: saved session for client %s", session->client_id);
    return 0;
}

static mqtt_persisted_session* file_persistence_load_session(
    mqtt_persistence_strategy *strategy,
    const char *client_id
) {
    file_persistence_context *ctx = (file_persistence_context *)strategy->context;
    if (!ctx || !client_id) return NULL;

    char *path = file_persistence_get_session_path(ctx->base_path, client_id);
    if (!path) return NULL;

    FILE *fp = fopen(path, "rb");
    free(path);

    if (!fp) {
        return NULL;  // No existing session
    }

    mqtt_persisted_session *session = calloc(1, sizeof(mqtt_persisted_session));
    if (!session) {
        fclose(fp);
        return NULL;
    }

    // Read session metadata
    fread(&session->session_expiry_interval, sizeof(uint32_t), 1, fp);
    fread(&session->session_created, sizeof(uint32_t), 1, fp);
    fread(&session->session_last_accessed, sizeof(uint32_t), 1, fp);
    fread(&session->next_packet_id, sizeof(uint16_t), 1, fp);

    // Check session expiry
    uint32_t now = (uint32_t)time(NULL);
    if (session->session_expiry_interval > 0) {
        uint32_t elapsed = now - session->session_last_accessed;
        if (elapsed > session->session_expiry_interval) {
            syslog(LOG_INFO, "file_persistence: session expired for client %s", client_id);
            free(session);
            fclose(fp);
            return NULL;
        }
    }

    // Read client ID
    uint16_t client_id_len;
    fread(&client_id_len, sizeof(uint16_t), 1, fp);
    session->client_id = malloc(client_id_len + 1);
    fread(session->client_id, 1, client_id_len, fp);
    session->client_id[client_id_len] = '\0';

    // Read subscriptions
    uint16_t sub_count;
    fread(&sub_count, sizeof(uint16_t), 1, fp);

    mqtt_persisted_subscription **sub_ptr = &session->subscriptions;
    for (uint16_t i = 0; i < sub_count; i++) {
        *sub_ptr = calloc(1, sizeof(mqtt_persisted_subscription));
        if (!*sub_ptr) {
            mqtt_persisted_session_free(session);
            fclose(fp);
            return NULL;
        }

        uint16_t topic_len;
        fread(&topic_len, sizeof(uint16_t), 1, fp);
        (*sub_ptr)->topic_filter = malloc(topic_len + 1);
        fread((*sub_ptr)->topic_filter, 1, topic_len, fp);
        (*sub_ptr)->topic_filter[topic_len] = '\0';
        fread(&(*sub_ptr)->qos, sizeof(uint8_t), 1, fp);
        fread(&(*sub_ptr)->no_local, sizeof(uint8_t), 1, fp);
        fread(&(*sub_ptr)->retain_as_published, sizeof(uint8_t), 1, fp);
        fread(&(*sub_ptr)->retain_handling, sizeof(uint8_t), 1, fp);

        sub_ptr = &(*sub_ptr)->next;
    }

    // Read pending messages
    uint16_t pending_count;
    fread(&pending_count, sizeof(uint16_t), 1, fp);

    mqtt_persisted_message **msg_ptr = &session->pending_publish;
    for (uint16_t i = 0; i < pending_count; i++) {
        *msg_ptr = calloc(1, sizeof(mqtt_persisted_message));
        if (!*msg_ptr) {
            mqtt_persisted_session_free(session);
            fclose(fp);
            return NULL;
        }

        fread(&(*msg_ptr)->packet_id, sizeof(uint16_t), 1, fp);
        fread(&(*msg_ptr)->packet_type, sizeof(uint8_t), 1, fp);
        fread(&(*msg_ptr)->qos, sizeof(uint8_t), 1, fp);
        fread(&(*msg_ptr)->retain, sizeof(uint8_t), 1, fp);
        fread(&(*msg_ptr)->dup, sizeof(uint8_t), 1, fp);
        fread(&(*msg_ptr)->timestamp, sizeof(uint32_t), 1, fp);
        fread(&(*msg_ptr)->retry_count, sizeof(int), 1, fp);

        uint16_t topic_len;
        fread(&topic_len, sizeof(uint16_t), 1, fp);
        if (topic_len > 0) {
            (*msg_ptr)->topic = malloc(topic_len + 1);
            fread((*msg_ptr)->topic, 1, topic_len, fp);
            (*msg_ptr)->topic[topic_len] = '\0';
        }

        fread(&(*msg_ptr)->payload_len, sizeof(size_t), 1, fp);
        if ((*msg_ptr)->payload_len > 0) {
            (*msg_ptr)->payload = malloc((*msg_ptr)->payload_len);
            fread((*msg_ptr)->payload, 1, (*msg_ptr)->payload_len, fp);
        }

        msg_ptr = &(*msg_ptr)->next;
    }

    fclose(fp);

    // Update last accessed time
    session->session_last_accessed = now;

    syslog(LOG_DEBUG, "file_persistence: loaded session for client %s", client_id);
    return session;
}

static int file_persistence_delete_session(
    mqtt_persistence_strategy *strategy,
    const char *client_id
) {
    file_persistence_context *ctx = (file_persistence_context *)strategy->context;
    if (!ctx || !client_id) return -1;

    char *path = file_persistence_get_session_path(ctx->base_path, client_id);
    if (!path) return -1;

    unlink(path);
    free(path);

    syslog(LOG_DEBUG, "file_persistence: deleted session for client %s", client_id);
    return 0;
}

static int file_persistence_add_pending_message(
    mqtt_persistence_strategy *strategy,
    const char *client_id,
    const mqtt_persisted_message *message
) {
    // Load session, add message, save session
    mqtt_persisted_session *session = file_persistence_load_session(strategy, client_id);
    if (!session) {
        session = calloc(1, sizeof(mqtt_persisted_session));
        if (!session) return -1;
        session->client_id = strdup(client_id);
        session->session_created = (uint32_t)time(NULL);
    }

    mqtt_persisted_message *new_msg = mqtt_persisted_message_create(
        message->packet_id, message->packet_type, message->qos,
        message->topic, message->payload, message->payload_len,
        message->retain, message->dup
    );
    if (!new_msg) {
        mqtt_persisted_session_free(session);
        return -1;
    }

    new_msg->next = session->pending_publish;
    session->pending_publish = new_msg;

    int result = file_persistence_save_session(strategy, session);
    mqtt_persisted_session_free(session);
    return result;
}

static int file_persistence_remove_pending_message(
    mqtt_persistence_strategy *strategy,
    const char *client_id,
    uint16_t packet_id
) {
    mqtt_persisted_session *session = file_persistence_load_session(strategy, client_id);
    if (!session) return -1;

    mqtt_persisted_message **current = &session->pending_publish;
    int found = 0;
    while (*current) {
        if ((*current)->packet_id == packet_id) {
            mqtt_persisted_message *to_remove = *current;
            *current = to_remove->next;
            mqtt_persisted_message_free(to_remove);
            found = 1;
            break;
        }
        current = &(*current)->next;
    }

    if (!found) {
        current = &session->pending_receive;
        while (*current) {
            if ((*current)->packet_id == packet_id) {
                mqtt_persisted_message *to_remove = *current;
                *current = to_remove->next;
                mqtt_persisted_message_free(to_remove);
                found = 1;
                break;
            }
            current = &(*current)->next;
        }
    }

    int result = file_persistence_save_session(strategy, session);
    mqtt_persisted_session_free(session);
    return found ? result : -1;
}

static int file_persistence_cleanup(mqtt_persistence_strategy *strategy) {
    file_persistence_context *ctx = (file_persistence_context *)strategy->context;
    if (ctx) {
        free(ctx->base_path);
        free(ctx);
        strategy->context = NULL;
    }
    return 0;
}

mqtt_persistence_strategy* mqtt_persistence_file_create(const char *base_path) {
    if (!base_path) return NULL;

    mqtt_persistence_strategy *strategy = calloc(1, sizeof(mqtt_persistence_strategy));
    if (!strategy) return NULL;

    file_persistence_context *ctx = calloc(1, sizeof(file_persistence_context));
    if (!ctx) {
        free(strategy);
        return NULL;
    }

    ctx->base_path = strdup(base_path);
    if (!ctx->base_path) {
        free(ctx);
        free(strategy);
        return NULL;
    }

    strategy->name = "file";
    strategy->context = ctx;
    strategy->init = file_persistence_init;
    strategy->save_session = file_persistence_save_session;
    strategy->load_session = file_persistence_load_session;
    strategy->delete_session = file_persistence_delete_session;
    strategy->add_pending_message = file_persistence_add_pending_message;
    strategy->remove_pending_message = file_persistence_remove_pending_message;
    strategy->cleanup = file_persistence_cleanup;

    return strategy;
}
