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

#include "mqtt_scram.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Use printf for logging for now (SCRAM is self-contained)
#define SCRAM_LOG_DEBUG(fmt, ...) fprintf(stderr, "[DEBUG] SCRAM: " fmt "\n", ##__VA_ARGS__)
#define SCRAM_LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] SCRAM: " fmt "\n", ##__VA_ARGS__)

// Base64 encoding helper
static char *base64_encode(const unsigned char *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data, len);
    BIO_flush(b64);

    char *b64_data = NULL;
    long b64_len = BIO_get_mem_data(bmem, &b64_data);

    char *result = malloc(b64_len + 1);
    if (result && b64_data) {
        memcpy(result, b64_data, b64_len);
        result[b64_len] = '\0';
    }

    BIO_free_all(b64);
    return result;
}

// Base64 decoding helper
static unsigned char *base64_decode(const char *data, size_t *out_len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(data, -1);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_push(b64, bmem);

    size_t max_len = (strlen(data) * 3) / 4 + 1;
    unsigned char *result = malloc(max_len);
    if (!result) {
        BIO_free_all(bmem);
        return NULL;
    }

    *out_len = BIO_read(bmem, result, max_len);
    BIO_free_all(bmem);

    if (*out_len <= 0) {
        free(result);
        return NULL;
    }

    return result;
}

// Generate random nonce
static char *generate_nonce(void) {
    unsigned char random_bytes[24];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        SCRAM_LOG_ERROR("Failed to generate random bytes");
        return NULL;
    }
    return base64_encode(random_bytes, sizeof(random_bytes));
}

// XOR two byte arrays
static void xor_bytes(unsigned char *result, const unsigned char *a, const unsigned char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        result[i] = a[i] ^ b[i];
    }
}

// HMAC-SHA-256
static void hmac_sha256(const unsigned char *key, size_t key_len,
                        const unsigned char *data, size_t data_len,
                        unsigned char *output) {
    unsigned int out_len;
    HMAC(EVP_sha256(), key, key_len, data, data_len, output, &out_len);
}

// Hi function from SCRAM (PBKDF2 with HMAC-SHA-256)
static void scram_hi(const char *password, const unsigned char *salt, size_t salt_len,
                     int iterations, unsigned char *output) {
    PKCS5_PBKDF2_HMAC(password, strlen(password),
                      salt, salt_len,
                      iterations,
                      EVP_sha256(),
                      32, // SHA-256 output length
                      output);
}

// H function (SHA-256 hash)
static void scram_h(const unsigned char *data, size_t len, unsigned char *output) {
    SHA256(data, len, output);
}

// Parse server-first-message
static int parse_server_first(const char *message, char **nonce, char **salt, int *iterations) {
    // Expected format: r=<nonce>,s=<salt>,i=<iterations>

    *nonce = NULL;
    *salt = NULL;
    *iterations = 0;

    char *msg_copy = strdup(message);
    if (!msg_copy) return -1;

    char *ptr = msg_copy;
    char *token;

    while ((token = strsep(&ptr, ",")) != NULL) {
        if (token[0] == 'r' && token[1] == '=') {
            *nonce = strdup(token + 2);
        } else if (token[0] == 's' && token[1] == '=') {
            *salt = strdup(token + 2);
        } else if (token[0] == 'i' && token[1] == '=') {
            *iterations = atoi(token + 2);
        }
    }

    free(msg_copy);

    if (!*nonce || !*salt || *iterations == 0) {
        free(*nonce);
        free(*salt);
        return -1;
    }

    return 0;
}

mqtt_scram_context *mqtt_scram_create(const char *username, const char *password) {
    if (!username || !password) {
        return NULL;
    }

    mqtt_scram_context *ctx = calloc(1, sizeof(mqtt_scram_context));
    if (!ctx) {
        return NULL;
    }

    ctx->username = strdup(username);
    ctx->password = strdup(password);
    ctx->client_nonce = generate_nonce();

    if (!ctx->username || !ctx->password || !ctx->client_nonce) {
        mqtt_scram_free(ctx);
        return NULL;
    }

    ctx->state = SCRAM_STATE_INITIAL;
    return ctx;
}

void mqtt_scram_free(mqtt_scram_context *ctx) {
    if (!ctx) return;

    free(ctx->username);
    free(ctx->password);
    free(ctx->client_nonce);
    free(ctx->server_nonce);
    free(ctx->salt);
    free(ctx->client_first_bare);
    free(ctx->server_first);
    free(ctx);
}

char *mqtt_scram_client_first(mqtt_scram_context *ctx) {
    if (!ctx || ctx->state != SCRAM_STATE_INITIAL) {
        return NULL;
    }

    // GS2 header: n,, (no channel binding)
    // client-first-message-bare: n=<username>,r=<nonce>
    size_t msg_len = strlen("n=") + strlen(ctx->username) + strlen(",r=") +
                     strlen(ctx->client_nonce) + 1;

    ctx->client_first_bare = malloc(msg_len);
    if (!ctx->client_first_bare) {
        return NULL;
    }

    snprintf(ctx->client_first_bare, msg_len, "n=%s,r=%s",
             ctx->username, ctx->client_nonce);

    // Full message includes GS2 header
    size_t full_len = strlen("n,,") + strlen(ctx->client_first_bare) + 1;
    char *message = malloc(full_len);
    if (!message) {
        return NULL;
    }

    snprintf(message, full_len, "n,,%s", ctx->client_first_bare);

    ctx->state = SCRAM_STATE_CLIENT_FIRST_SENT;
    return message;
}

char *mqtt_scram_client_final(mqtt_scram_context *ctx, const char *server_first) {
    if (!ctx || ctx->state != SCRAM_STATE_CLIENT_FIRST_SENT || !server_first) {
        return NULL;
    }

    // Save server-first message
    ctx->server_first = strdup(server_first);
    if (!ctx->server_first) {
        return NULL;
    }

    // Parse server-first-message
    char *server_nonce = NULL;
    char *salt_b64 = NULL;
    int iterations = 0;

    if (parse_server_first(server_first, &server_nonce, &salt_b64, &iterations) < 0) {
        SCRAM_LOG_ERROR("Failed to parse server-first-message");
        return NULL;
    }

    // Verify server nonce starts with client nonce
    if (strncmp(server_nonce, ctx->client_nonce, strlen(ctx->client_nonce)) != 0) {
        SCRAM_LOG_ERROR("Server nonce doesn't start with client nonce");
        free(server_nonce);
        free(salt_b64);
        return NULL;
    }

    ctx->server_nonce = server_nonce;

    // Decode salt
    size_t salt_len;
    unsigned char *salt = base64_decode(salt_b64, &salt_len);
    free(salt_b64);
    if (!salt) {
        SCRAM_LOG_ERROR("Failed to decode salt");
        return NULL;
    }

    // Compute SaltedPassword = Hi(password, salt, iterations)
    unsigned char salted_password[32];
    scram_hi(ctx->password, salt, salt_len, iterations, salted_password);
    free(salt);

    // Compute ClientKey = HMAC(SaltedPassword, "Client Key")
    unsigned char client_key[32];
    hmac_sha256(salted_password, 32, (unsigned char *)"Client Key", 10, client_key);

    // Compute StoredKey = H(ClientKey)
    unsigned char stored_key[32];
    scram_h(client_key, 32, stored_key);

    // Build client-final-message-without-proof
    // Format: c=<base64(GS2 header)>,r=<nonce>
    char *gs2_header_b64 = base64_encode((unsigned char *)"n,,", 3);

    size_t cf_len = strlen("c=") + strlen(gs2_header_b64) + strlen(",r=") +
                    strlen(server_nonce) + 1;
    char *client_final_without_proof = malloc(cf_len);
    if (!client_final_without_proof) {
        free(gs2_header_b64);
        return NULL;
    }

    snprintf(client_final_without_proof, cf_len, "c=%s,r=%s",
             gs2_header_b64, server_nonce);
    free(gs2_header_b64);

    // Build AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof
    size_t auth_msg_len = strlen(ctx->client_first_bare) + 1 +
                          strlen(server_first) + 1 +
                          strlen(client_final_without_proof) + 1;
    char *auth_message = malloc(auth_msg_len);
    if (!auth_message) {
        free(client_final_without_proof);
        return NULL;
    }

    snprintf(auth_message, auth_msg_len, "%s,%s,%s",
             ctx->client_first_bare, server_first, client_final_without_proof);

    // Compute ClientSignature = HMAC(StoredKey, AuthMessage)
    unsigned char client_signature[32];
    hmac_sha256(stored_key, 32, (unsigned char *)auth_message, strlen(auth_message), client_signature);
    free(auth_message);

    // Compute ClientProof = ClientKey XOR ClientSignature
    unsigned char client_proof[32];
    xor_bytes(client_proof, client_key, client_signature, 32);

    // Encode proof
    char *proof_b64 = base64_encode(client_proof, 32);

    // Build final message: client-final-without-proof + ",p=" + proof
    size_t final_len = strlen(client_final_without_proof) + strlen(",p=") +
                       strlen(proof_b64) + 1;
    char *client_final = malloc(final_len);
    if (!client_final) {
        free(client_final_without_proof);
        free(proof_b64);
        return NULL;
    }

    snprintf(client_final, final_len, "%s,p=%s",
             client_final_without_proof, proof_b64);

    free(client_final_without_proof);
    free(proof_b64);

    ctx->state = SCRAM_STATE_CLIENT_FINAL_SENT;
    return client_final;
}

int mqtt_scram_verify_server_final(mqtt_scram_context *ctx, const char *server_final) {
    if (!ctx || ctx->state != SCRAM_STATE_CLIENT_FINAL_SENT || !server_final) {
        return -1;
    }

    // Expected format: v=<server-signature>
    if (server_final[0] == 'v' && server_final[1] == '=') {
        ctx->state = SCRAM_STATE_AUTHENTICATED;
        return 0;
    }

    // Check for error
    if (server_final[0] == 'e' && server_final[1] == '=') {
        SCRAM_LOG_ERROR("Server authentication error: %s", server_final + 2);
        ctx->state = SCRAM_STATE_FAILED;
        return -1;
    }

    ctx->state = SCRAM_STATE_FAILED;
    return -1;
}
