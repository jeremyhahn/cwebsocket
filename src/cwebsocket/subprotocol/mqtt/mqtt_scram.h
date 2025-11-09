/*
 * Copyright 2024 <NAME>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MQTT_SCRAM_H
#define MQTT_SCRAM_H

#include <stddef.h>
#include <stdint.h>

// SCRAM-SHA-256 authentication for MQTT 5.0
// RFC 5802: Salted Challenge Response Authentication Mechanism (SCRAM)
// RFC 7677: SCRAM-SHA-256 and SCRAM-SHA-256-PLUS

typedef enum {
    SCRAM_STATE_INITIAL,
    SCRAM_STATE_CLIENT_FIRST_SENT,
    SCRAM_STATE_CLIENT_FINAL_SENT,
    SCRAM_STATE_AUTHENTICATED,
    SCRAM_STATE_FAILED
} mqtt_scram_state;

typedef struct mqtt_scram_context {
    char *username;
    char *password;
    char *client_nonce;
    char *server_nonce;
    char *salt;
    char *client_first_bare;    // Saved for AuthMessage
    char *server_first;          // Saved for AuthMessage
    mqtt_scram_state state;
} mqtt_scram_context;

// Create SCRAM context for authentication
// Returns: context on success, NULL on failure
mqtt_scram_context *mqtt_scram_create(const char *username, const char *password);

// Free SCRAM context
void mqtt_scram_free(mqtt_scram_context *ctx);

// Generate client-first-message
// Format: n,,n=<username>,r=<client-nonce>
// Returns: allocated string (caller must free), NULL on failure
char *mqtt_scram_client_first(mqtt_scram_context *ctx);

// Generate client-final-message
// server_first: server's first message (r=<nonce>,s=<salt>,i=<iterations>)
// Returns: allocated string (caller must free), NULL on failure
char *mqtt_scram_client_final(mqtt_scram_context *ctx, const char *server_first);

// Verify server-final-message
// server_final: server's final message (v=<signature> or e=<error>)
// Returns: 0 on success, -1 on failure
int mqtt_scram_verify_server_final(mqtt_scram_context *ctx, const char *server_final);

#endif // MQTT_SCRAM_H
